"""Shared HTTP client: caching, concurrency limits, and polite failure.

Every source here is free and unauthenticated. When one is unavailable we
record a *gap* rather than a zero - a missing signal is not a bad signal, and
conflating the two is the single most common flaw in package-health tooling.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx

from ..cache import Cache

USER_AGENT = "package-doctor/0.1 (+https://github.com/binuka200/package-doctor)"

#: Largest response body we will read by default, in bytes.
#:
#: Every source here is a free, unauthenticated third party. A compromised,
#: hijacked or simply misbehaving endpoint should not be able to exhaust memory
#: or fill the cache. Nothing OSV, ecosyste.ms, CISA or FIRST legitimately
#: return comes close; CISA's KEV catalogue is the largest at a few MB. PyPI is
#: the exception and passes its own, higher cap - see ``sources/pypi.py``.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


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
                resp, body = await self._read_capped("GET", url, max_bytes=max_bytes)
            except ResponseTooLarge as exc:
                self._remember_too_large(key, exc)
                raise
            except httpx.HTTPError:
                return None
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
                resp, body = await self._read_capped("POST", url, payload, max_bytes=max_bytes)
            except ResponseTooLarge as exc:
                self._remember_too_large(cache_key, exc)
                raise
            except httpx.HTTPError:
                return None
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
