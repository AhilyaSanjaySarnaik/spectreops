from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, title TEXT, severity TEXT,
  confidence TEXT, target TEXT, evidence TEXT, tool TEXT, status TEXT DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, host TEXT UNIQUE, info TEXT
);
"""


# columns added after the first release; applied to existing DBs on open
_MIGRATIONS = {"reproduction": "TEXT DEFAULT ''", "remediation": "TEXT DEFAULT ''"}
_FINDING_KEYS = ["id", "ts", "title", "severity", "confidence", "target",
                 "evidence", "tool", "status", "reproduction", "remediation"]


class Memory:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(findings)")}
        for col, decl in _MIGRATIONS.items():
            if col not in cols:
                self.conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
        self.conn.commit()

    def add_finding(self, title: str, severity: str, confidence: str,
                    target: str, evidence: dict, tool: str,
                    reproduction: str = "", remediation: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (ts,title,severity,confidence,target,evidence,tool,"
            "reproduction,remediation) VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), title, severity, confidence, target,
             json.dumps(evidence, default=str), tool, reproduction, remediation))
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def findings(self, severity: str | None = None) -> list[dict]:
        q = f"SELECT {','.join(_FINDING_KEYS)} FROM findings"
        args: tuple = ()
        if severity:
            q += " WHERE severity=?"
            args = (severity,)
        rows = self.conn.execute(q + " ORDER BY id", args).fetchall()
        out = []
        for r in rows:
            d = dict(zip(_FINDING_KEYS, r, strict=True))
            try:
                d["evidence"] = json.loads(d["evidence"] or "{}")
            except json.JSONDecodeError:
                pass
            out.append(d)
        return out

    def upsert_host(self, host: str, info: dict) -> None:
        self.conn.execute(
            "INSERT INTO hosts (ts,host,info) VALUES (?,?,?)"
            " ON CONFLICT(host) DO UPDATE SET info=excluded.info, ts=excluded.ts",
            (time.time(), host, json.dumps(info)))
        self.conn.commit()

    def log_event(self, kind: str, payload: dict) -> None:
        self.conn.execute("INSERT INTO events (ts,kind,payload) VALUES (?,?,?)",
                          (time.time(), kind, json.dumps(payload)))
        self.conn.commit()

    def events(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts,kind,payload FROM events ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [{"ts": r[0], "kind": r[1], "payload": json.loads(r[2])} for r in rows]
