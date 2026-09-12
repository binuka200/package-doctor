"""Shared HTTP client: caching, concurrency limits, and polite failure.

Every source here is free and unauthenticated. When one is unavailable we
record a *gap* rather than a zero - a missing signal is not a bad signal, and
conflating the two is the single most common flaw in package-health tooling.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from ..cache import Cache

USER_AGENT = "package-doctor/0.1 (+https://github.com/binuka200/package-doctor)"

#: Largest response body we will read, in bytes.
#:
#: Every source here is a free, unauthenticated third party. A compromised,
#: hijacked or simply misbehaving endpoint should not be able to exhaust memory
#: or fill the cache, and nothing these APIs legitimately return comes close -
#: the largest real response encountered is CISA's KEV catalogue at a few MB.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


class Client:
    def __init__(self, cache: Cache, concurrency: int = 8, timeout: float = 20.0):
        self.cache = cache
        self._sem = asyncio.Semaphore(concurrency)
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(self, url: str, cache_key: str | None = None) -> Any | None:
        key = cache_key or f"GET {url}"
        cached = self.cache.get(key)
        if cached is not None:
            # A remembered 404 must come back as None, exactly like a fresh one.
            # Returning the sentinel would hand callers a truthy dict for a
            # resource that does not exist.
            return None if self.is_missing(cached) else cached
        async with self._sem:
            try:
                resp, body = await self._read_capped("GET", url)
            except httpx.HTTPError:
                return None
        if resp is None:
            return None
        if resp.status_code == 404:
            self.cache.set(key, {"__missing__": True})
            return None
        if resp.status_code != 200 or body is None:
            return None
        try:
            data = json.loads(body)
        except ValueError:
            return None
        self.cache.set(key, data)
        return data

    async def _read_capped(
        self, method: str, url: str, payload: Any | None = None
    ) -> tuple[httpx.Response | None, bytes | None]:
        """Read a response, abandoning it if it exceeds MAX_RESPONSE_BYTES.

        Streaming rather than calling .json() directly is the point: a body is
        only ever in memory up to the cap, so an endpoint cannot make the
        scanner grow without bound. A declared Content-Length over the cap is
        rejected before any of it is read.
        """
        kwargs: dict[str, Any] = {}
        if payload is not None:
            kwargs["json"] = payload
        async with self._client.stream(method, url, **kwargs) as resp:
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                return resp, None
            if resp.status_code != 200:
                return resp, None
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    return resp, None
                chunks.append(chunk)
            return resp, b"".join(chunks)

    async def post_json(self, url: str, payload: Any, cache_key: str) -> Any | None:
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        async with self._sem:
            try:
                resp, body = await self._read_capped("POST", url, payload)
            except httpx.HTTPError:
                return None
        if resp is None or resp.status_code != 200 or body is None:
            return None
        try:
            data = json.loads(body)
        except ValueError:
            return None
        self.cache.set(cache_key, data)
        return data

    @staticmethod
    def is_missing(data: Any) -> bool:
        return isinstance(data, dict) and data.get("__missing__") is True
