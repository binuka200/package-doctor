"""Shared HTTP client: caching, concurrency limits, and polite failure.

Every source here is free and unauthenticated. When one is unavailable we
record a *gap* rather than a zero - a missing signal is not a bad signal, and
conflating the two is the single most common flaw in package-health tooling.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..cache import Cache

USER_AGENT = "package-doctor/0.1 (+https://github.com/binukajayaweera/package-doctor)"


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
                resp = await self._client.get(url)
            except httpx.HTTPError:
                return None
        if resp.status_code == 404:
            self.cache.set(key, {"__missing__": True})
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        self.cache.set(key, data)
        return data

    async def post_json(self, url: str, payload: Any, cache_key: str) -> Any | None:
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        async with self._sem:
            try:
                resp = await self._client.post(url, json=payload)
            except httpx.HTTPError:
                return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        self.cache.set(cache_key, data)
        return data

    @staticmethod
    def is_missing(data: Any) -> bool:
        return isinstance(data, dict) and data.get("__missing__") is True
