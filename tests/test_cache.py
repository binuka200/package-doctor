"""The response cache. A stale or lost entry changes what the user is told."""

from __future__ import annotations

import time

from package_doctor.cache import Cache, default_cache_path


def test_roundtrip(tmp_path):
    c = Cache(path=tmp_path / "c.sqlite3")
    c.set("k", {"a": 1})
    assert c.get("k") == {"a": 1}
    c.close()


def test_missing_key_is_none(tmp_path):
    c = Cache(path=tmp_path / "c.sqlite3")
    assert c.get("nope") is None
    c.close()


def test_entries_expire(tmp_path):
    c = Cache(path=tmp_path / "c.sqlite3", ttl=0)
    c.set("k", {"a": 1})
    time.sleep(0.01)
    assert c.get("k") is None
    c.close()


def test_writing_the_same_key_twice_replaces_it(tmp_path):
    c = Cache(path=tmp_path / "c.sqlite3")
    c.set("k", {"v": 1})
    c.set("k", {"v": 2})
    assert c.get("k") == {"v": 2}
    c.close()


def test_survives_reopening(tmp_path):
    path = tmp_path / "c.sqlite3"
    a = Cache(path=path)
    a.set("k", ["persisted"])
    a.close()
    b = Cache(path=path)
    assert b.get("k") == ["persisted"]
    b.close()


def test_clear_reports_how_much_it_removed(tmp_path):
    c = Cache(path=tmp_path / "c.sqlite3")
    c.set("a", 1)
    c.set("b", 2)
    assert c.clear() == 2
    assert c.get("a") is None
    c.close()


def test_disabled_cache_is_a_no_op(tmp_path):
    """--no-cache must not silently keep using a previous answer."""
    c = Cache(path=tmp_path / "c.sqlite3", enabled=False)
    c.set("k", {"a": 1})
    assert c.get("k") is None
    assert c.clear() == 0
    c.close()


def test_disabled_cache_creates_no_file(tmp_path):
    path = tmp_path / "nested" / "c.sqlite3"
    Cache(path=path, enabled=False).close()
    assert not path.exists()


def test_corrupt_body_does_not_raise(tmp_path):
    c = Cache(path=tmp_path / "c.sqlite3")
    c.set("k", {"a": 1})
    c._conn.execute("UPDATE entries SET body = ? WHERE key = ?", ("{not json", "k"))
    c._conn.commit()
    assert c.get("k") is None
    c.close()


def test_default_path_is_under_a_cache_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_path().parent == tmp_path / "package-doctor"
