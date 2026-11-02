"""Named assessment snapshots with evidence-preserving comparison.

A missing observation is *unverified*, never proof of remediation.
Only an explicit resolved status event can classify a prior issue as resolved.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class AssessmentError(ValueError):
    pass


class Assessments:
    def __init__(self, memory):
        self.memory = memory
        self.conn = memory.conn
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS assessment_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              started_at REAL NOT NULL,
              finished_at REAL,
              state TEXT NOT NULL CHECK(state IN ('active','complete'))
            );
            CREATE TABLE IF NOT EXISTS assessment_observations (
              run_id INTEGER NOT NULL,
              finding_id INTEGER NOT NULL,
              ts REAL NOT NULL,
              severity TEXT NOT NULL,
              confidence TEXT NOT NULL,
              evidence TEXT NOT NULL,
              tool TEXT NOT NULL,
              PRIMARY KEY(run_id,finding_id),
              FOREIGN KEY(run_id) REFERENCES assessment_runs(id),
              FOREIGN KEY(finding_id) REFERENCES findings(id)
            );
        """)

    def start(self, name: str) -> int:
        name = name.strip()
        if not name or len(name) > 100:
            raise AssessmentError("assessment name must be 1–100 characters")
        if self.active() is not None:
            raise AssessmentError("complete the current assessment before starting another")
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO assessment_runs (name,started_at,state) "
                    "VALUES (?,?,'active')", (name, time.time()),
                )
            return int(cur.lastrowid)
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise AssessmentError("assessment name already exists") from exc
            raise

    def active(self) -> dict | None:
        row = self.conn.execute(
            "SELECT id,name,started_at FROM assessment_runs WHERE state='active'"
            " ORDER BY id LIMIT 1"
        ).fetchone()
        return ({"id": row[0], "name": row[1], "started_at": row[2]}
                if row else None)

    def complete(self, name: str) -> None:
        with self.conn:
            changed = self.conn.execute(
                "UPDATE assessment_runs SET state='complete',finished_at=? "
                "WHERE name=? AND state='active'", (time.time(), name),
            )
        if not changed.rowcount:
            raise AssessmentError("no active assessment with that name")

    def list_runs(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id,name,state,started_at,finished_at FROM assessment_runs ORDER BY id"
        ).fetchall()
        return [dict(zip(("id","name","state","started_at","finished_at"), r,
                         strict=True)) for r in rows]

    def record(self, finding_id: int, *, severity: str, confidence: str,
               evidence: dict, tool: str) -> None:
        active = self.active()
        if active is None:
            return
        with self.conn:
            self.conn.execute(
                "INSERT INTO assessment_observations "
                "(run_id,finding_id,ts,severity,confidence,evidence,tool) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(run_id,finding_id) DO UPDATE SET "
                "ts=excluded.ts,severity=excluded.severity,"
                "confidence=excluded.confidence,evidence=excluded.evidence,"
                "tool=excluded.tool",
                (active["id"], finding_id, time.time(), severity, confidence,
                 json.dumps(evidence, default=str), tool),
            )

    def _completed(self, name: str) -> dict:
        row = self.conn.execute(
            "SELECT id,name,started_at,finished_at FROM assessment_runs "
            "WHERE name=? AND state='complete'", (name,),
        ).fetchone()
        if row is None:
            raise AssessmentError(f"assessment {name!r} is missing or incomplete")
        return dict(zip(("id","name","started_at","finished_at"), row,
                        strict=True))

    def _observed(self, run_id: int) -> dict[int, dict]:
        rows = self.conn.execute(
            "SELECT o.finding_id,f.title,f.target,o.severity,o.confidence,"
            "o.evidence,o.tool,o.ts FROM assessment_observations o "
            "JOIN findings f ON f.id=o.finding_id WHERE o.run_id=?",
            (run_id,),
        ).fetchall()
        return {r[0]: {"id":r[0], "title":r[1], "target":r[2],
                       "severity":r[3], "confidence":r[4],
                       "evidence":json.loads(r[5]), "tool":r[6],
                       "observed_at":r[7]} for r in rows}

    def compare(self, before: str, after: str) -> dict:
        base = self._completed(before)
        newer = self._completed(after)
        if base["finished_at"] >= newer["started_at"]:
            raise AssessmentError("assessments must be sequential, not overlapping")
        a = self._observed(base["id"])
        b = self._observed(newer["id"])
        new_ids = b.keys() - a.keys()
        repeat_ids = b.keys() & a.keys()
        absent_ids = a.keys() - b.keys()
        resolved, unverified = [], []
        for finding_id in sorted(absent_ids):
            event = self.conn.execute(
                "SELECT status FROM finding_status_events "
                "WHERE finding_id=? AND ts>? AND ts<=? "
                "ORDER BY ts DESC,id DESC LIMIT 1",
                (finding_id, base["finished_at"], newer["finished_at"]),
            ).fetchone()
            if event is not None and event[0] == "resolved":
                resolved.append(a[finding_id])
            else:
                unverified.append(a[finding_id])
        return {
            "baseline":base["name"], "comparison":newer["name"],
            "new":[b[i] for i in sorted(new_ids)],
            "recurring":[b[i] for i in sorted(repeat_ids)],
            "explicitly_resolved":resolved,
            "not_observed_unverified":unverified,
        }


def export_comparison(comparison: dict, output: Path) -> None:
    """Export structured evidence and a readable Markdown difference summary."""
    if output.suffix.lower() == ".json":
        output.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
        return
    if output.suffix.lower() != ".md":
        raise AssessmentError("comparison export must be .json or .md")
    lines = [
        "# SpectreOps Assessment Comparison", "",
        f"Baseline: **{comparison['baseline']}**",
        f"Comparison: **{comparison['comparison']}**", "",
        "An absent finding is not classified as fixed unless explicitly resolved.", "",
    ]
    for key, label in (
        ("new", "New observations"),
        ("recurring", "Recurring observations"),
        ("explicitly_resolved", "Explicitly resolved"),
        ("not_observed_unverified", "Not observed (unverified)"),
    ):
        lines += [f"## {label} ({len(comparison[key])})", ""]
        for item in comparison[key]:
            lines.append(
                f"- Finding #{item['id']}: **{item['title']}** "
                f"at `{item['target']}` ({item['severity']})"
            )
        lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")
