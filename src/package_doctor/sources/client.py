"""Shared HTTP client: caching, concurrency limits, and polite failure.

Every source here is free and unauthenticated. When one is unavailable we
record a *gap* rather than a zero - a missing signal is not a bad signal, and
conflating the two is the single most common flaw in package-health tooling.
"""

from __future__ import annotations

import asyncio
import collections
import json
import random
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

from ..cache import Cache

USER_AGENT = "package-doctor/0.2 (+https://github.com/binuka200/package-doctor)"

#: Largest response body we will read by default, in bytes.
#:
#: Every source here is a free, unauthenticated third party. A compromised,
#: hijacked or simply misbehaving endpoint should not be able to exhaust memory
#: or fill the cache. Nothing OSV, ecosyste.ms, CISA or FIRST legitimately
#: return comes close; CISA's KEV catalogue is the largest at a few MB. PyPI is
#: the exception and passes its own, higher cap - see ``sources/pypi.py``.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


#: Retry policy for the free upstream APIs.
#:
#: A 429 or a 5xx on the first try used to become a silent gap for that
#: package, so a scan run into PyPI's rate limit degraded without saying so.
#: Three attempts with exponential backoff and jitter; a Retry-After header is
#: honoured up to a cap, so a polite "slow down" is obeyed but a hostile one
#: cannot park the scan for an hour.
MAX_ATTEMPTS = 3
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
BACKOFF_BASE_SECONDS = 0.5
RETRY_AFTER_CAP_SECONDS = 30.0

_sleep = asyncio.sleep  # patched in tests


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        header = resp.headers.get("retry-after", "")
        if header.strip().isdigit():
            return min(float(header.strip()), RETRY_AFTER_CAP_SECONDS)
    return BACKOFF_BASE_SECONDS * (2 ** attempt) + random.uniform(0, 0.25)


class ResponseTooLarge(Exception):
    """The body exceeded the cap and was abandoned.

    Raised rather than folded into ``None``, because ``None`` means "absent"
    and a package whose metadata is merely too big to read is not absent.
    Reporting it as such told the user something untrue, and since the case
    was never cached, every run re-downloaded the body just to abandon it.
    """

    def __init__(self, url: str, limit: int):
        super().__init__(f"response from {url} exceeded {limit // (1024 * 1024)} MB")
        self.url = url
        self.limit = limit

#: Cache envelope version. Every entry is wrapped, so a response body can never
#: be mistaken for cache bookkeeping.
#:
#: The first version stored a bare {"__missing__": true} to remember a 404, in
#: the same namespace as real API data - so an endpoint returning that shape
#: would have been read back as "this package does not exist", suppressing the
#: package from the report entirely. Suppression is a false negative, which is
#: the worst failure this tool has.
_ENVELOPE = "pd_cache_v1"


def _decode(body: bytes) -> Any | None:
    """Parse a JSON body, or None if it is not one we can use.

    RecursionError is caught alongside ValueError: on interpreters before the
    JSON module grew a nesting limit, a body of a hundred thousand opening
    brackets recurses until it dies, and a response from a free third-party
    endpoint must never end the scan with a traceback.
    """
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    # A bare JSON null is indistinguishable from "no response" downstream, and
    # nothing these APIs return is one.
    return data


class Client:
    def __init__(self, cache: Cache, concurrency: int = 8, timeout: float = 20.0):
        self.cache = cache
        self._sem = asyncio.Semaphore(concurrency)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )
        #: host -> requests that failed after every retry. Non-empty means the
        #: report has gaps that are the upstream's doing, and the report says so.
        self.degraded: collections.Counter[str] = collections.Counter()
        #: retries that were needed, for the curious.
        self.retries = 0

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _wrap(
        body: Any | None, missing: bool = False, too_large: bool = False
    ) -> dict[str, Any]:
        return {_ENVELOPE: 1, "missing": missing, "too_large": too_large, "body": body}

    @staticmethod
    def _unwrap(entry: Any) -> tuple[bool, Any | None]:
        """Return (recognised, body). An unrecognised entry is treated as a
        miss, which makes an older cache format self-healing rather than
        something that has to be migrated.

        A remembered over-cap response raises, exactly as a fresh one does, so
        the caller cannot tell the two apart and neither should it.
        """
        if not isinstance(entry, dict) or entry.get(_ENVELOPE) != 1:
            return False, None
        if entry.get("too_large"):
            raise ResponseTooLarge(str(entry.get("url") or "?"), int(entry.get("limit") or 0))
        if entry.get("missing"):
            # A remembered 404 comes back as None, exactly like a fresh one.
            return True, None
        return True, entry.get("body")

    def _remember_too_large(self, key: str, exc: ResponseTooLarge) -> None:
        entry = self._wrap(None, too_large=True)
        entry["url"], entry["limit"] = exc.url, exc.limit
        self.cache.set(key, entry)

    async def get_json(
        self,
        url: str,
        cache_key: str | None = None,
        reduce: Callable[[Any], Any] | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> Any | None:
        """Fetch JSON, serving from the cache when it can.

        ``reduce`` is applied to a fresh body before it is cached or returned,
        so a caller that needs a fraction of a large response can keep only
        that fraction. What the cache holds is then what the caller sees, on
        the first run and every run after.

        Raises ``ResponseTooLarge`` if the body exceeds ``max_bytes``, and
        remembers that for the cache lifetime so the download is not repeated.
        """
        key = cache_key or f"GET {url}"
        recognised, body = self._unwrap(self.cache.get(key))
        if recognised:
            return body
        async with self._sem:
            try:
                resp, body = await self._fetch("GET", url, max_bytes=max_bytes)
            except ResponseTooLarge as exc:
                self._remember_too_large(key, exc)
                raise
        if resp is None:
            return None
        if resp.status_code == 404:
            self.cache.set(key, self._wrap(None, missing=True))
            return None
        if resp.status_code != 200 or body is None:
            return None
        data = _decode(body)
        if data is None:
            return None
        if reduce is not None:
            data = reduce(data)
        self.cache.set(key, self._wrap(data))
        return data

    async def _fetch(
        self,
        method: str,
        url: str,
        payload: Any | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> tuple[httpx.Response | None, bytes | None]:
        """One logical request: `_read_capped` with retries.

        Retries on a transport error, a 429 or a 5xx, up to MAX_ATTEMPTS in
        all. Anything else - a 404, a 400, a body over the cap - is an answer
        and is returned or raised at once. Exhausting the attempts returns
        (None, None) and counts against the host in `degraded`.
        """
        host = urlparse(url).hostname or url
        last: httpx.Response | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                resp, body = await self._read_capped(method, url, payload, max_bytes=max_bytes)
            except httpx.TransportError:
                resp, body = None, None
            except httpx.HTTPError:
                # Malformed URL and the like: retrying cannot help.
                self.degraded[host] += 1
                return None, None
            if resp is not None and resp.status_code not in RETRY_STATUSES:
                return resp, body
            last = resp
            if attempt + 1 < MAX_ATTEMPTS:
                self.retries += 1
                await _sleep(_retry_delay(last, attempt))
        self.degraded[host] += 1
        return None, None

    async def _read_capped(
        self,
        method: str,
        url: str,
        payload: Any | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> tuple[httpx.Response | None, bytes | None]:
        """Read a response, raising ResponseTooLarge if it exceeds the cap.

        Streaming rather than calling .json() directly is the point: a body is
        only ever in memory up to the cap, so an endpoint cannot make the
        scanner grow without bound. A declared Content-Length over the cap is
        rejected before any of it is read.
        """
        kwargs: dict[str, Any] = {}
        if payload is not None:
            kwargs["json"] = payload
        async with self._client.stream(method, url, **kwargs) as resp:
            if resp.status_code != 200:
                return resp, None
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise ResponseTooLarge(url, max_bytes)
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseTooLarge(url, max_bytes)
                chunks.append(chunk)
            return resp, b"".join(chunks)

    async def post_json(
        self,
        url: str,
        payload: Any,
        cache_key: str,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> Any | None:
        recognised, body = self._unwrap(self.cache.get(cache_key))
        if recognised:
            return body
        async with self._sem:
            try:
                resp, body = await self._fetch("POST", url, payload, max_bytes=max_bytes)
            except ResponseTooLarge as exc:
                self._remember_too_large(cache_key, exc)
                raise
        if resp is None or resp.status_code != 200 or body is None:
            return None
        data = _decode(body)
        if data is None:
            return None
        self.cache.set(cache_key, self._wrap(data))
        return data

    @staticmethod
    def is_missing(data: Any) -> bool:
        """Kept for callers that still guard on it. get_json now translates a
        remembered 404 to None itself, so this should never see one."""
        return data is None
