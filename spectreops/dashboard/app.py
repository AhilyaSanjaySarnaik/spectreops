from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from ..core.assessments import AssessmentError, Assessments
from ..core.audit import AuditLog
from ..core.memory import Memory

app = FastAPI(title="SpectreOps Dashboard")

# The data directory is fixed when the server starts. It used to be a query
# parameter, which let any local page/process open an arbitrary path.
DATA_DIR = Path(os.environ.get("SPECTREOPS_DATA_DIR", "~/.spectreops")).expanduser()


def _memory() -> Memory:
    if not (DATA_DIR / "memory.db").exists():
        raise HTTPException(404, f"no memory.db under {DATA_DIR}")
    return Memory(DATA_DIR / "memory.db")


@app.get("/findings")
def findings(severity: str | None = None):
    return _memory().findings(severity)


@app.get("/events")
def events(limit: int = 50):
    return _memory().events(min(max(limit, 1), 1000))


@app.get("/surfaces")
def surfaces(status: str | None = None):
    return _memory().surfaces(status)


@app.get("/assessments")
def assessments():
    """List named assessment runs, including active/incomplete ones."""
    memory = _memory()
    try:
        return Assessments(memory).list_runs()
    finally:
        memory.conn.close()


@app.get("/assessments/compare")
def assessment_comparison(baseline: str, comparison: str):
    """Return full evidence-backed comparison for two completed runs."""
    memory = _memory()
    try:
        try:
            return Assessments(memory).compare(baseline, comparison)
        except AssessmentError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        memory.conn.close()


@app.get("/assessments/trends")
def assessment_trends():
    """Adjacent completed-run comparison counts; never infer fixes by absence."""
    memory = _memory()
    try:
        tracker = Assessments(memory)
        complete = [r for r in tracker.list_runs() if r["state"] == "complete"]
        trends = []
        for earlier, later in zip(complete, complete[1:], strict=False):
            diff = tracker.compare(earlier["name"], later["name"])
            trends.append({
                "baseline": earlier["name"],
                "comparison": later["name"],
                "completed_at": later["finished_at"],
                "new": len(diff["new"]),
                "recurring": len(diff["recurring"]),
                "explicitly_resolved": len(diff["explicitly_resolved"]),
                "not_observed_unverified": len(diff["not_observed_unverified"]),
            })
        return trends
    finally:
        memory.conn.close()


@app.get("/audit/verify")
def audit_verify():
    path = DATA_DIR / "audit.jsonl"
    if not path.exists():
        raise HTTPException(404, "no audit log yet")
    return {"chain_ok": AuditLog(path).verify()}


@app.get("/", response_class=HTMLResponse)
def index():
    """Render the local-only, read-only assessment trends dashboard."""
    return (Path(__file__).with_name("overview.html").read_text(encoding="utf-8"))



def serve(data_dir: str = "~/.spectreops", port: int = 8765) -> None:
    global DATA_DIR
    import uvicorn
    DATA_DIR = Path(data_dir).expanduser()
    # localhost-only by default; remote bind must be an explicit change
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    serve(os.environ.get("SPECTREOPS_DATA_DIR", "~/.spectreops"))
