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


class Memory:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)

    def add_finding(self, title: str, severity: str, confidence: str,
                    target: str, evidence: dict, tool: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings (ts,title,severity,confidence,target,evidence,tool)"
            " VALUES (?,?,?,?,?,?,?)",
            (time.time(), title, severity, confidence, target,
             json.dumps(evidence), tool))
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def findings(self, severity: str | None = None) -> list[dict]:
        q = "SELECT id,ts,title,severity,confidence,target,evidence,tool,status FROM findings"
        args: tuple = ()
        if severity:
            q += " WHERE severity=?"
            args = (severity,)
        rows = self.conn.execute(q, args).fetchall()
        keys = ["id", "ts", "title", "severity", "confidence", "target",
                "evidence", "tool", "status"]
        return [dict(zip(keys, r)) for r in rows]

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
