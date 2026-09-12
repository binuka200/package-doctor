"""HTTP behaviour under failure.

Every source here is free and unauthenticated, which means every one of them
can be down, rate-limited or malformed. None of that may turn into a finding.
"""

from __future__ import annotations

import httpx
import pytest

from package_doctor.sources.client import Client


def client_with(cache, handler, **kw) -> Client:
    c = Client(cache, **kw)
    c._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


async def test_successful_json_is_returned_and_cached(cache):
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(200, json={"ok": True})

    c = client_with(cache, handler)
    assert await c.get_json("https://x.invalid/a") == {"ok": True}
    assert await c.get_json("https://x.invalid/a") == {"ok": True}
    assert len(calls) == 1, "second call should have been served from cache"
    await c.aclose()


async def test_a_404_is_remembered_so_we_stop_asking(cache):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(404)

    c = client_with(cache, handler)
    assert await c.get_json("https://x.invalid/missing") is None
    assert await c.get_json("https://x.invalid/missing") is None
    assert len(calls) == 1
    await c.aclose()


@pytest.mark.parametrize("status", [429, 500, 502, 503])
async def test_server_errors_return_none_and_are_not_cached(cache, status):
    """A rate limit is temporary. Caching it would poison later runs."""
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(status)

    c = client_with(cache, handler)
    assert await c.get_json("https://x.invalid/a") is None
    assert await c.get_json("https://x.invalid/a") is None
    assert len(calls) == 2
    await c.aclose()


async def test_a_network_failure_returns_none(cache):
    def handler(request):
        raise httpx.ConnectError("no route to host")

    c = client_with(cache, handler)
    assert await c.get_json("https://x.invalid/a") is None
    await c.aclose()


async def test_a_malformed_body_returns_none(cache):
    def handler(request):
        return httpx.Response(200, content=b"<html>not json</html>")

    c = client_with(cache, handler)
    assert await c.get_json("https://x.invalid/a") is None
    await c.aclose()


async def test_post_json_round_trips_and_caches(cache):
    calls = []

    def handler(request):
        calls.append(request.content)
        return httpx.Response(200, json={"vulns": []})

    c = client_with(cache, handler)
    for _ in range(2):
        assert await c.post_json("https://x.invalid/q", {"a": 1}, "key") == {"vulns": []}
    assert len(calls) == 1
    await c.aclose()


async def test_post_failure_returns_none(cache):
    c = client_with(cache, lambda r: httpx.Response(500))
    assert await c.post_json("https://x.invalid/q", {}, "key") is None
    await c.aclose()


def test_missing_sentinel_is_recognised():
    assert Client.is_missing({"__missing__": True})
    assert not Client.is_missing({"real": "data"})
    assert not Client.is_missing(None)
