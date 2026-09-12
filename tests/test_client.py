"""HTTP behaviour under failure.

Every source here is free and unauthenticated, which means every one of them
can be down, rate-limited or malformed. None of that may turn into a finding.
"""

from __future__ import annotations

import httpx
import pytest

from package_doctor.sources.client import Client, ResponseTooLarge


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


async def test_a_response_body_cannot_impersonate_a_cached_404(cache, make_client):
    """The first version of this cache stored a bare {"__missing__": true} to
    remember a 404, in the same namespace as real API data. An endpoint
    returning that shape would have been read back as "this package does not
    exist", suppressing it from the report - which is a false negative, the
    worst failure this tool has."""
    hostile = {"__missing__": True, "pd_cache_v1": 1, "missing": True,
               "info": {"version": "9.9"}}
    c = client_with(cache, lambda r: httpx.Response(200, json=hostile))
    first = await c.get_json("https://x.invalid/a")
    assert first == hostile, "a 200 body must be returned as-is"
    second = await c.get_json("https://x.invalid/a")
    assert second == hostile, "and must survive the round trip through the cache"
    await c.aclose()


async def test_a_genuine_404_is_remembered_as_absent(cache, make_client):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(404)

    c = client_with(cache, handler)
    assert await c.get_json("https://x.invalid/gone") is None
    assert await c.get_json("https://x.invalid/gone") is None
    assert len(calls) == 1, "the absence should have been cached"
    await c.aclose()


def test_an_unrecognised_cache_entry_is_treated_as_a_miss():
    """Older cache formats self-heal rather than needing a migration."""
    assert Client._unwrap({"__missing__": True}) == (False, None)
    assert Client._unwrap("garbage") == (False, None)
    assert Client._unwrap(None) == (False, None)
    assert Client._unwrap(Client._wrap({"ok": 1})) == (True, {"ok": 1})
    assert Client._unwrap(Client._wrap(None, missing=True)) == (True, None)


async def test_a_pathologically_nested_body_is_treated_as_no_response(make_client):
    """json.loads recurses on interpreters without a nesting limit. A free
    endpoint must not be able to end the scan with a RecursionError."""
    client = make_client(lambda r: httpx.Response(200, content=b"[" * 200_000))
    assert await client.get_json("https://example.invalid/x") is None
    assert await client.post_json("https://example.invalid/y", {}, cache_key="k") is None
    await client.aclose()


async def test_reduce_is_applied_before_caching_and_on_the_way_out(cache):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"keep": 1, "drop": "x" * 1000})

    c = client_with(cache, handler)
    slim = lambda d: {"keep": d["keep"]}  # noqa: E731 - a one-line stub
    assert await c.get_json("https://x.invalid/a", cache_key="k", reduce=slim) == {"keep": 1}
    assert cache.get("k")["body"] == {"keep": 1}
    assert await c.get_json("https://x.invalid/a", cache_key="k", reduce=slim) == {"keep": 1}
    assert len(calls) == 1
    await c.aclose()


# --- a body over the cap is "too large", never "absent" ---------------------

async def test_an_undeclared_oversized_body_raises_and_is_remembered(cache):
    """Chunked responses carry no Content-Length, so the cap has to hold while
    streaming. And the outcome is cached: without that, every run downloaded
    the whole body again just to abandon it."""
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, content=b"[" + b"1," * 600 + b"1]")

    c = client_with(cache, handler)
    with pytest.raises(ResponseTooLarge):
        await c.get_json("https://x.invalid/big", cache_key="k", max_bytes=1000)
    with pytest.raises(ResponseTooLarge):
        await c.get_json("https://x.invalid/big", cache_key="k", max_bytes=1000)
    assert len(calls) == 1, "the second call is answered from the cache"
    await c.aclose()


async def test_a_declared_oversized_body_is_rejected_before_it_is_read(cache):
    read = []

    def handler(request):
        async def gen():
            read.append(1)
            yield b"x" * 10

        return httpx.Response(
            200, headers={"content-length": "999999"},
            stream=httpx.AsyncByteStream.__new__(type("S", (httpx.AsyncByteStream,), {
                "__aiter__": lambda self: gen(),
            })),
        )

    c = client_with(cache, handler)
    with pytest.raises(ResponseTooLarge):
        await c.get_json("https://x.invalid/big", cache_key="k", max_bytes=1000)
    assert not read
    await c.aclose()


async def test_the_cap_is_per_call(cache):
    body = {"n": list(range(300))}
    c = client_with(cache, lambda r: httpx.Response(200, json=body))
    with pytest.raises(ResponseTooLarge):
        await c.get_json("https://x.invalid/a", cache_key="small", max_bytes=100)
    assert await c.get_json("https://x.invalid/a", cache_key="large", max_bytes=10_000) == body
    await c.aclose()


async def test_post_json_honours_the_cap_too(cache):
    c = client_with(cache, lambda r: httpx.Response(200, content=b"x" * 2000))
    with pytest.raises(ResponseTooLarge):
        await c.post_json("https://x.invalid/q", {}, cache_key="k", max_bytes=1000)
    with pytest.raises(ResponseTooLarge):
        await c.post_json("https://x.invalid/q", {}, cache_key="k", max_bytes=1000)
    await c.aclose()


def test_a_response_body_cannot_impersonate_a_remembered_oversize():
    """Same principle as the 404 envelope: real API data lives under "body",
    so a body shaped like the marker is just data."""
    entry = Client._wrap({"too_large": True, "url": "x", "limit": 1})
    assert Client._unwrap(entry) == (True, {"too_large": True, "url": "x", "limit": 1})


async def test_a_non_200_is_not_mistaken_for_too_large_by_its_length(cache):
    """A server error with a large declared length is a server error."""
    c = client_with(cache, lambda r: httpx.Response(
        503, headers={"content-length": "999999999"}, content=b""
    ))
    assert await c.get_json("https://x.invalid/a", cache_key="k", max_bytes=10) is None
    await c.aclose()
