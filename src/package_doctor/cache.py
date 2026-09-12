"""SQLite-backed response cache.

Scanning a real lockfile means hundreds of API calls. Without a cache the tool
is unusable in a pre-commit hook and rude to the free services it depends on.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL = 24 * 60 * 60  # a day; maintenance signals do not move faster than that

#: Prune expired rows once the file grows past this, in bytes.
#:
#: Entries were previously only checked for expiry when read, so a stale row was
#: never removed and the file grew without bound - a bulk scan took one past a
#: gigabyte. Pruning on open keeps that in check without a background task.
PRUNE_ABOVE_BYTES = 256 * 1024 * 1024


def default_cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "package-doctor" / "http-cache.sqlite3"


class Cache:
    def __init__(self, path: Path | None = None, ttl: int = DEFAULT_TTL, enabled: bool = True):
        self.ttl = ttl
        self.enabled = enabled
        self.path = path or default_cache_path()
        self._conn: sqlite3.Connection | None = None
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            existed = self.path.exists()
            self._conn = sqlite3.connect(str(self.path))
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS entries "
                "(key TEXT PRIMARY KEY, fetched_at REAL NOT NULL, body TEXT NOT NULL)"
            )
            self._conn.commit()
            # The cache records which packages have been scanned, which says
            # something about projects the user may not have published. On a
            # shared machine that is nobody else's business. Applied to existing
            # files as well, since caches created before this existed are the
            # ones most likely to be large and revealing.
            self._restrict_permissions()
            self._prune_if_large()

    def _restrict_permissions(self) -> None:
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                self.path.chmod(0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass

    def _prune_if_large(self) -> None:
        """Keep the file bounded, cheaply.

        Entries were previously only checked for expiry when read, so a stale
        row was never removed and a bulk scan grew the file past a gigabyte.

        Two things matter here. Expired rows go first, since they are worthless.
        If the file is still oversized after that - a large cache of entirely
        fresh entries - the oldest are dropped until it is not, because
        otherwise a heavy user simply never recovers the space.

        VACUUM only runs when something was actually deleted. Vacuuming a
        gigabyte on every invocation because nothing had expired yet was the
        first version of this method, and it made every run take seconds.
        """
        if not self._conn:
            return
        try:
            if self.path.stat().st_size < PRUNE_ABOVE_BYTES:
                return
            cur = self._conn.execute(
                "DELETE FROM entries WHERE fetched_at < ?", (time.time() - self.ttl,)
            )
            removed = cur.rowcount or 0

            # Still oversized with nothing expired: drop the oldest quarter.
            if self.path.stat().st_size >= PRUNE_ABOVE_BYTES:
                total = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
                if total:
                    cur = self._conn.execute(
                        "DELETE FROM entries WHERE key IN ("
                        "  SELECT key FROM entries ORDER BY fetched_at ASC LIMIT ?"
                        ")",
                        (max(1, total // 4),),
                    )
                    removed += cur.rowcount or 0

            self._conn.commit()
            if removed:
                # Only VACUUM when there is space to reclaim; it rewrites the
                # whole file and is far too expensive to run speculatively.
                self._conn.execute("VACUUM")
        except (OSError, sqlite3.Error):  # pragma: no cover - best effort only
            pass

    def get(self, key: str) -> Any | None:
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT fetched_at, body FROM entries WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        fetched_at, body = row
        if time.time() - fetched_at > self.ttl:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Any) -> None:
        if not self._conn:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO entries (key, fetched_at, body) VALUES (?, ?, ?)",
            (key, time.time(), json.dumps(value)),
        )
        self._conn.commit()

    def clear(self) -> int:
        if not self._conn:
            return 0
        n = self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
        self._conn.execute("DELETE FROM entries")
        self._conn.commit()
        if n:
            # DELETE only frees pages for reuse inside the file; VACUUM is what
            # hands the space back. Someone running `cache clear` wants the
            # disk back, not a gigabyte of reusable pages.
            self._conn.execute("VACUUM")
        return int(n)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
