"""Shared fixtures.

Offline by construction: no test in this suite makes a network request. HTTP is
served by httpx.MockTransport, so upstream outages and rate limits can never
turn into a failing build.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from package_doctor.cache import Cache
from package_doctor.sources.client import Client


def test_suite_runs_against_this_checkout() -> None:
    """Fail loudly if the installed package resolves somewhere else.

    An editable install can be silently repointed - running `pip install -e .`
    from a temporary clone, for instance, rewrites the path in the venv - and a
    green suite testing a stale snapshot is worse than a red one.
    """
    import package_doctor
    here = Path(__file__).resolve().parents[1] / "src" / "package_doctor"
    imported = Path(package_doctor.__file__).resolve().parent
    if imported != here:
        pytest.exit(
            f"package_doctor resolves to {imported}, not {here}. "
            f"Run: pip install -e '.[dev]'",
            returncode=1,
        )


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
