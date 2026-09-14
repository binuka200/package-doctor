"""The response cache. A stale or lost entry changes what the user is told."""

from __future__ import annotations

import sys
import time

import pytest

from package_doctor.cache import Cache, default_cache_path

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


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


@posix_only
def test_a_new_cache_is_not_world_readable(tmp_path):
    """The cache records which packages have been scanned, which says something
    about projects the user may not have published."""
    import stat
    path = tmp_path / "c.sqlite3"
    c = Cache(path=path)
    c.set("k", {"a": 1})
    c.close()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & stat.S_IRGRP, oct(mode)
    assert not mode & stat.S_IROTH, oct(mode)


def test_expired_rows_are_pruned_once_the_file_grows(tmp_path, monkeypatch):
    """Entries were only checked for expiry on read, so stale rows were never
    removed and a bulk scan grew the file past a gigabyte."""
    import package_doctor.cache as cache_mod

    path = tmp_path / "c.sqlite3"
    warm = Cache(path=path, ttl=0)
    for i in range(200):
        warm.set(f"k{i}", {"pad": "A" * 4000})
    warm.close()

    monkeypatch.setattr(cache_mod, "PRUNE_ABOVE_BYTES", 1)
    pruned = Cache(path=path, ttl=0)
    remaining = pruned._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    pruned.close()
    assert remaining == 0


def test_a_cache_under_the_limit_is_left_completely_alone(tmp_path):
    """Pruning is a response to size, not something that happens every run."""
    path = tmp_path / "c.sqlite3"
    warm = Cache(path=path)
    warm.set("keep", {"v": 1})
    warm.close()

    c = Cache(path=path)
    assert c.get("keep") == {"v": 1}
    c.close()


def test_an_oversized_cache_of_fresh_entries_still_sheds(tmp_path, monkeypatch):
    """A heavy user's cache can be large and entirely unexpired. If only stale
    rows were ever dropped, that cache would never recover any space."""
    import package_doctor.cache as cache_mod

    path = tmp_path / "c.sqlite3"
    warm = Cache(path=path)
    for i in range(40):
        warm.set(f"k{i}", {"pad": "A" * 500})
    warm.close()

    monkeypatch.setattr(cache_mod, "PRUNE_ABOVE_BYTES", 1)
    c = Cache(path=path)
    remaining = c._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    c.close()
    assert 0 < remaining < 40, remaining


def test_pruning_does_not_rewrite_the_file_when_nothing_was_removed(tmp_path, monkeypatch):
    """Vacuuming on every invocation because nothing had expired yet was the
    first version of this, and it made every run take seconds.

    VACUUM rewrites the whole database, so an unchanged mtime is the evidence
    that it did not run.
    """
    import os

    import package_doctor.cache as cache_mod

    path = tmp_path / "c.sqlite3"
    warm = Cache(path=path)
    warm.set("fresh", {"v": 1})
    warm.close()

    # Backdate the file so any rewrite is unmistakable.
    old_time = 1_000_000_000
    os.utime(path, (old_time, old_time))

    # Oversized by the threshold, but the single row is fresh and the table is
    # too small for the oldest-quarter sweep to find anything to drop.
    monkeypatch.setattr(cache_mod, "PRUNE_ABOVE_BYTES", 10**12)
    Cache(path=path).close()

    assert int(path.stat().st_mtime) == old_time, "the file was rewritten"


def test_clear_actually_returns_the_disk_space(tmp_path):
    """DELETE only frees pages for reuse inside the file. Someone running
    `cache clear` wants the disk back."""
    path = tmp_path / "c.sqlite3"
    c = Cache(path=path)
    for i in range(400):
        c.set(f"k{i}", {"pad": "A" * 2000})
    c._conn.commit()
    before = path.stat().st_size
    c.clear()
    c.close()
    assert path.stat().st_size < before / 2, (before, path.stat().st_size)


@posix_only
def test_an_existing_world_readable_cache_is_tightened(tmp_path):
    """Caches created before this existed are the ones most likely to be large
    and revealing, so opening one should fix it rather than only new files."""
    import stat as s
    path = tmp_path / "c.sqlite3"
    Cache(path=path).close()
    path.chmod(0o644)
    assert s.S_IMODE(path.stat().st_mode) & s.S_IROTH

    Cache(path=path).close()
    assert not s.S_IMODE(path.stat().st_mode) & s.S_IROTH


@posix_only
def test_the_cache_file_is_created_private_not_tightened_afterwards(tmp_path, monkeypatch):
    """SQLite creates the file with the umask, and chmod-ing afterwards leaves
    a window. The file is pre-created 0600 so there is no such window; this
    checks the pre-creation rather than the end state, which the test above
    already covers."""
    import os
    import sqlite3
    import stat as s

    path = tmp_path / "cache.sqlite3"
    modes_at_connect = []
    real_connect = sqlite3.connect

    def spy(target, *a, **kw):
        modes_at_connect.append(s.S_IMODE(os.stat(target).st_mode))
        return real_connect(target, *a, **kw)

    monkeypatch.setattr(sqlite3, "connect", spy)
    monkeypatch.setattr(os, "umask", lambda m: 0)  # not relied upon either way
    c = Cache(path=path)
    c.close()
    assert modes_at_connect == [0o600], "already private when SQLite first opens it"


@posix_only
def test_a_loose_existing_cache_is_tightened_before_sqlite_opens_it(tmp_path, monkeypatch):
    """Tightening after CREATE TABLE / commit left every row written in that
    run in a world-readable file for as long as the run took. The existing
    file must already be private by the time SQLite first opens it."""
    import os
    import sqlite3
    import stat as s

    path = tmp_path / "c.sqlite3"
    Cache(path=path).close()
    path.chmod(0o644)

    modes_at_connect = []
    real_connect = sqlite3.connect

    def spy(target, *a, **kw):
        modes_at_connect.append(s.S_IMODE(os.stat(target).st_mode))
        return real_connect(target, *a, **kw)

    monkeypatch.setattr(sqlite3, "connect", spy)
    Cache(path=path).close()
    assert modes_at_connect == [0o600]


@posix_only
def test_sqlite_is_opened_under_a_private_umask_that_is_then_restored(tmp_path, monkeypatch):
    """Whether journal, WAL and SHM sidecars inherit the main file's mode is a
    platform detail. A 0o077 umask for the life of the connection means
    anything SQLite creates is born private; the caller's umask must come
    back unchanged afterwards."""
    import os

    real = os.umask
    calls = []

    def spy(mask):
        calls.append(mask)
        return real(mask)

    before = real(0)
    real(before)
    monkeypatch.setattr(os, "umask", spy)
    Cache(path=tmp_path / "c.sqlite3").close()
    assert calls[0] == 0o077
    assert calls[-1] == before, "restored to what it was"
    after = real(0)
    real(after)
    assert after == before


@posix_only
def test_leftover_sidecar_files_are_tightened_too(tmp_path):
    """A journal, WAL or SHM file left behind by an older run, or by a
    platform that ignored the umask, carries the same contents."""
    import stat as s

    path = tmp_path / "c.sqlite3"
    c = Cache(path=path, enabled=False)  # nothing opened; exercise the tightening alone
    sidecars = [tmp_path / f"c.sqlite3{suffix}" for suffix in ("-journal", "-wal", "-shm")]
    for side in sidecars:
        side.write_bytes(b"x")
        side.chmod(0o644)
    c._restrict_permissions()
    for side in sidecars:
        assert not s.S_IMODE(side.stat().st_mode) & (s.S_IRWXG | s.S_IRWXO), side.name
    c.close()
