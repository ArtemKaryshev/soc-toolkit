"""История разборов (кейсы) в SQLite.

Каждый сохранённый разбор хранит исходный алерт, вердикт, отчёт и индикаторы.
Таблица case_iocs позволяет быстро ответить на вопрос «встречался ли этот IOC раньше».
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..ioc import IOC

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT NOT NULL,
    updated TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT '',
    verdict TEXT DEFAULT '',
    category TEXT DEFAULT '',
    escalated INTEGER DEFAULT 0,
    status TEXT DEFAULT 'open',
    analyst TEXT DEFAULT '',
    source_format TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    alert_json TEXT DEFAULT '',
    report_md TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    tags TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS case_iocs (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    scope TEXT DEFAULT '',
    verdict TEXT DEFAULT '',
    PRIMARY KEY (case_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_case_iocs_value ON case_iocs(value);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created);
"""

STATUSES = ("open", "closed")


@dataclass
class Case:
    id: int | None = None
    title: str = ""
    severity: str = ""
    verdict: str = ""
    category: str = ""
    escalated: bool = False
    status: str = "open"
    analyst: str = ""
    source_format: str = ""
    first_seen: str = ""
    alert_json: str = ""
    report_md: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    created: str = ""
    updated: str = ""


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class CaseStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def _row_to_case(self, r: sqlite3.Row) -> Case:
        d = dict(r)
        d["escalated"] = bool(d["escalated"])
        d["tags"] = [t for t in d["tags"].split(",") if t]
        return Case(**d)

    def save(self, case: Case, iocs: Iterable[IOC] = (), verdicts: dict[str, str] | None = None) -> int:
        """Создать или обновить кейс. Возвращает id."""
        verdicts = verdicts or {}
        now = _now()
        values = (case.title, case.severity, case.verdict, case.category, int(case.escalated), case.status,
                  case.analyst, case.source_format, case.first_seen, case.alert_json, case.report_md, case.notes,
                  ",".join(case.tags))
        with self._lock, self.db:
            if case.id is None:
                cur = self.db.execute(
                    "INSERT INTO cases (title, severity, verdict, category, escalated, status, analyst, source_format,"
                    " first_seen, alert_json, report_md, notes, tags, created, updated)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (*values, now, now))
                case.id = int(cur.lastrowid or 0)
            else:
                self.db.execute(
                    "UPDATE cases SET title=?, severity=?, verdict=?, category=?, escalated=?, status=?, analyst=?,"
                    " source_format=?, first_seen=?, alert_json=?, report_md=?, notes=?, tags=?, updated=?"
                    " WHERE id=?", (*values, now, case.id))
            iocs = list(iocs)
            if iocs:
                self.db.execute("DELETE FROM case_iocs WHERE case_id=?", (case.id,))
                self.db.executemany(
                    "INSERT OR IGNORE INTO case_iocs VALUES (?,?,?,?,?)",
                    [(case.id, i.type.value, i.value.lower(), i.scope, verdicts.get(i.value, "")) for i in iocs])
        return case.id

    def get(self, case_id: int) -> Case | None:
        r = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return self._row_to_case(r) if r else None

    def iocs(self, case_id: int) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT type, value, scope, verdict FROM case_iocs WHERE case_id=? ORDER BY type, value", (case_id,))]

    def delete(self, case_id: int) -> bool:
        with self._lock, self.db:
            return self.db.execute("DELETE FROM cases WHERE id=?", (case_id,)).rowcount > 0

    def set_status(self, case_id: int, status: str) -> None:
        if status not in STATUSES:
            raise ValueError(f"Статус должен быть одним из {STATUSES}")
        with self._lock, self.db:
            self.db.execute("UPDATE cases SET status=?, updated=? WHERE id=?", (status, _now(), case_id))

    def search(self, text: str = "", verdict: str = "", status: str = "", category: str = "",
               date_from: str = "", date_to: str = "", limit: int = 200) -> list[Case]:
        sql = "SELECT * FROM cases WHERE 1=1"
        args: list[Any] = []
        if text:
            like = f"%{text}%"
            sql += (" AND (title LIKE ? OR notes LIKE ? OR report_md LIKE ? OR alert_json LIKE ?"
                    " OR id IN (SELECT case_id FROM case_iocs WHERE value LIKE ?))")
            args += [like, like, like, like, f"%{text.lower()}%"]
        for col, val in (("verdict", verdict), ("status", status), ("category", category)):
            if val:
                sql += f" AND {col} = ?"
                args.append(val)
        if date_from:
            sql += " AND created >= ?"
            args.append(date_from)
        if date_to:
            sql += " AND created <= ?"
            args.append(date_to + "T23:59:59")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [self._row_to_case(r) for r in self.db.execute(sql, args)]

    def sightings(self, values: Iterable[str], exclude_case: int | None = None) -> dict[str, list[int]]:
        """В каких кейсах раньше встречались эти индикаторы."""
        out: dict[str, list[int]] = {}
        for v in values:
            rows = self.db.execute("SELECT DISTINCT case_id FROM case_iocs WHERE value=? ORDER BY case_id",
                                   (v.lower(),)).fetchall()
            ids = [r[0] for r in rows if r[0] != exclude_case]
            if ids:
                out[v] = ids
        return out

    def stats(self) -> dict[str, Any]:
        q = self.db.execute
        return {
            "total": q("SELECT count(*) FROM cases").fetchone()[0],
            "open": q("SELECT count(*) FROM cases WHERE status='open'").fetchone()[0],
            "by_verdict": dict(q("SELECT verdict, count(*) FROM cases GROUP BY verdict").fetchall()),
            "by_category": dict(q("SELECT category, count(*) FROM cases GROUP BY category").fetchall()),
            "escalated": q("SELECT count(*) FROM cases WHERE escalated=1").fetchone()[0],
            "top_iocs": [dict(r) for r in q(
                "SELECT type, value, count(*) AS cases FROM case_iocs WHERE scope IN ('', 'public')"
                " GROUP BY type, value HAVING cases > 1 ORDER BY cases DESC LIMIT 20")],
        }

    def export_json(self) -> str:
        cases = [dict(r) for r in self.db.execute("SELECT * FROM cases ORDER BY id")]
        for c in cases:
            c["iocs"] = self.iocs(c["id"])
        return json.dumps(cases, ensure_ascii=False, indent=2)

    def close(self) -> None:
        self.db.close()
