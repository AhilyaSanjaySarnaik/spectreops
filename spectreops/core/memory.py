from __future__ import annotations

import hashlib
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
CREATE TABLE IF NOT EXISTS surfaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, url TEXT UNIQUE, method TEXT,
  kind TEXT, source TEXT, status TEXT DEFAULT 'new', notes TEXT
);
"""


# columns added after the first release; applied to existing DBs on open
_MIGRATIONS = {"reproduction": "TEXT DEFAULT ''", "remediation": "TEXT DEFAULT ''",
               "last_seen": "REAL", "seen_count": "INTEGER DEFAULT 1"}
_FINDING_KEYS = ["id", "ts", "title", "severity", "confidence", "target",
                 "evidence", "tool", "status", "reproduction", "remediation",
                 "last_seen", "seen_count"]


class Memory:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(findings)")}
        for col, decl in _MIGRATIONS.items():
            if col not in cols:
                self.conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
        self.conn.execute(
            "UPDATE findings SET last_seen=ts WHERE last_seen IS NULL"
        )
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS finding_observations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              finding_id INTEGER NOT NULL,
              ts REAL NOT NULL,
              severity TEXT NOT NULL,
              confidence TEXT NOT NULL,
              evidence TEXT NOT NULL,
              tool TEXT NOT NULL,
              FOREIGN KEY(finding_id) REFERENCES findings(id)
            )
        """)
        # Backfill legacy findings once without losing original evidence.
        self.conn.execute("""
            INSERT INTO finding_observations
              (finding_id,ts,severity,confidence,evidence,tool)
            SELECT f.id,f.ts,f.severity,f.confidence,COALESCE(f.evidence,'{}'),
                   COALESCE(f.tool,'')
            FROM findings f
            WHERE NOT EXISTS (
                SELECT 1 FROM finding_observations o WHERE o.finding_id=f.id
            )
        """)
        self.conn.commit()

    @staticmethod
    def finding_fingerprint(title: str, target: str) -> str:
        """Stable identity for the same title and exact affected target."""
        identity = json.dumps(
            [title.strip().casefold(), target.strip()],
            ensure_ascii=False, separators=(",", ":"),
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def existing_finding_id(self, title: str, target: str) -> int | None:
        """Return an existing issue ID, including rows from older databases."""
        fingerprint = self.finding_fingerprint(title, target)
        rows = self.conn.execute(
            "SELECT id,title,target FROM findings ORDER BY id",
        ).fetchall()
        for row_id, previous_title, previous_target in rows:
            if self.finding_fingerprint(previous_title or "", previous_target or "") == fingerprint:
                return row_id
        return None

    def add_finding(self, title: str, severity: str, confidence: str,
                    target: str, evidence: dict, tool: str,
                    reproduction: str = "", remediation: str = "") -> int:
        existing = self.existing_finding_id(title, target)
        now = time.time()
        if existing is not None:
            with self.conn:
                self.conn.execute(
                    "UPDATE findings SET last_seen=?, seen_count=COALESCE(seen_count, 1)+1, "
                    "status=CASE WHEN status='resolved' THEN 'open' ELSE status END "
                    "WHERE id=?", (now, existing),
                )
                self.conn.execute(
                    "INSERT INTO finding_observations "
                    "(finding_id,ts,severity,confidence,evidence,tool) "
                    "VALUES (?,?,?,?,?,?)",
                    (existing, now, severity, confidence,
                     json.dumps(evidence, default=str), tool),
                )
            return existing
        cur = self.conn.execute(
            "INSERT INTO findings (ts,title,severity,confidence,target,evidence,tool,"
            "reproduction,remediation,last_seen,seen_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (now, title, severity, confidence, target,
             json.dumps(evidence, default=str), tool, reproduction, remediation,
             now, 1))
        with self.conn:
            self.conn.execute(
                "INSERT INTO finding_observations "
                "(finding_id,ts,severity,confidence,evidence,tool) VALUES (?,?,?,?,?,?)",
                (cur.lastrowid, now, severity, confidence,
                 json.dumps(evidence, default=str), tool),
            )
        return cur.lastrowid  # type: ignore[return-value]

    def finding_history(self, finding_id: int) -> list[dict]:
        """Every observation for one issue, without overwriting original evidence."""
        rows = self.conn.execute(
            "SELECT ts,severity,confidence,evidence,tool FROM finding_observations "
            "WHERE finding_id=? ORDER BY id", (finding_id,),
        ).fetchall()
        return [
            {"ts": ts, "severity": severity, "confidence": confidence,
             "evidence": json.loads(evidence), "tool": tool}
            for ts, severity, confidence, evidence, tool in rows
        ]

    def set_finding_status(self, finding_id: int, status: str) -> bool:
        """Explicit status change; absence from an incomplete scan is not a fix."""
        if status not in ("open", "resolved", "accepted_risk", "false_positive"):
            raise ValueError("invalid finding status")
        cur = self.conn.execute(
            "UPDATE findings SET status=? WHERE id=?", (status, finding_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

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

    # ---- attack surfaces (discovered endpoints worked through a queue) -------
    def add_surface(self, url: str, method: str = "GET", kind: str = "endpoint",
                    source: str = "", notes: str = "") -> bool:
        """Queue a discovered endpoint. Returns False if it was already known."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO surfaces (ts,url,method,kind,source,status,notes)"
            " VALUES (?,?,?,?,?,'new',?)",
            (time.time(), url, method.upper(), kind, source, notes))
        self.conn.commit()
        return cur.rowcount > 0

    def surfaces(self, status: str | None = None, limit: int = 500) -> list[dict]:
        q = "SELECT id,ts,url,method,kind,source,status,notes FROM surfaces"
        args: tuple = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        rows = self.conn.execute(q + " ORDER BY id LIMIT ?", (*args, limit)).fetchall()
        keys = ["id", "ts", "url", "method", "kind", "source", "status", "notes"]
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def next_surface(self) -> dict | None:
        """Claim the oldest untested surface, marking it in-progress (atomic)."""
        with self.conn:
            row = self.conn.execute(
                "SELECT id,url,method,kind,source FROM surfaces WHERE status='new'"
                " ORDER BY id LIMIT 1").fetchone()
            if row is None:
                return None
            self.conn.execute("UPDATE surfaces SET status='in_progress' WHERE id=?",
                              (row[0],))
        return {"id": row[0], "url": row[1], "method": row[2], "kind": row[3],
                "source": row[4]}

    def set_surface_status(self, surface_id: int, status: str) -> bool:
        if status not in ("new", "in_progress", "tested", "skipped"):
            raise ValueError(f"bad surface status: {status}")
        cur = self.conn.execute("UPDATE surfaces SET status=? WHERE id=?",
                                (status, surface_id))
        self.conn.commit()
        return cur.rowcount > 0

    def log_event(self, kind: str, payload: dict) -> None:
        self.conn.execute("INSERT INTO events (ts,kind,payload) VALUES (?,?,?)",
                          (time.time(), kind, json.dumps(payload)))
        self.conn.commit()

    def events(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts,kind,payload FROM events ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [{"ts": r[0], "kind": r[1], "payload": json.loads(r[2])} for r in rows]
