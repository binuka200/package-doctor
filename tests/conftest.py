"""Shared fixtures.

Offline by construction: no test in this suite makes a network request. HTTP is
served by httpx.MockTransport, so upstream outages and rate limits can never
turn into a failing build.
"""

from __future__ import annotations

import httpx
import pytest

from package_doctor.cache import Cache
from package_doctor.sources.client import Client


@pytest.fixture
def cache(tmp_path):
    """A throwaway cache whose SQLite connection is always closed."""
    c = Cache(path=tmp_path / "cache.sqlite3")
    yield c
    c.close()


@pytest.fixture
def make_client(cache):
    """Build a Client backed by a stub transport, closed on teardown."""
    def build(handler, **kwargs) -> Client:
        client = Client(cache, **kwargs)
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return client

    return build
