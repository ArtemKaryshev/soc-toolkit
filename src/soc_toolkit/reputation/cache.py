"""Кеш результатов репутации в SQLite с временем жизни записей."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .base import RepResult


class ReputationCache:
    def __init__(self, path: Path, ttl_hours: float = 24.0):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_hours * 3600
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS reputation (provider TEXT, indicator TEXT, ts REAL, data TEXT, "
            "PRIMARY KEY (provider, indicator))"
        )
        self._db.commit()

    def get(self, provider: str, indicator: str) -> RepResult | None:
        with self._lock:
            row = self._db.execute("SELECT ts, data FROM reputation WHERE provider=? AND indicator=?",
                                   (provider, indicator.lower())).fetchone()
        if not row or time.time() - row[0] > self.ttl:
            return None
        res = RepResult.from_dict(json.loads(row[1]))
        res.cached = True
        return res

    def put(self, res: RepResult) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO reputation VALUES (?, ?, ?, ?)",
                             (res.provider, res.indicator.lower(), time.time(),
                              json.dumps(res.to_dict(), ensure_ascii=False)))
            self._db.commit()

    def clear(self, expired_only: bool = False) -> int:
        with self._lock:
            if expired_only:
                cur = self._db.execute("DELETE FROM reputation WHERE ts < ?", (time.time() - self.ttl,))
            else:
                cur = self._db.execute("DELETE FROM reputation")
            self._db.commit()
            return cur.rowcount

    def stats(self) -> dict[str, int]:
        with self._lock:
            total = self._db.execute("SELECT count(*) FROM reputation").fetchone()[0]
            fresh = self._db.execute("SELECT count(*) FROM reputation WHERE ts >= ?",
                                     (time.time() - self.ttl,)).fetchone()[0]
        return {"total": total, "fresh": fresh}

    def close(self) -> None:
        self._db.close()
