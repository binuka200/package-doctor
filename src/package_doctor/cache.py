"""SQLite-backed response cache.

Scanning a real lockfile means hundreds of API calls. Without a cache the tool
is unusable in a pre-commit hook and rude to the free services it depends on.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL = 24 * 60 * 60  # a day; maintenance signals do not move faster than that


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
            self._conn = sqlite3.connect(str(self.path))
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS entries "
                "(key TEXT PRIMARY KEY, fetched_at REAL NOT NULL, body TEXT NOT NULL)"
            )
            self._conn.commit()

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
        return int(n)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
