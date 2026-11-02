from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from ..core.audit import AuditLog
from ..core.memory import Memory

app = FastAPI(title="SpectreOps Dashboard")


def _memory(data_dir: str) -> Memory:
    p = Path(data_dir).expanduser()
    if not (p / "memory.db").exists():
        raise HTTPException(404, f"no memory.db under {p}")
    return Memory(p / "memory.db")


@app.get("/findings")
def findings(data_dir: str, severity: str | None = None):
    return _memory(data_dir).findings(severity)


@app.get("/events")
def events(data_dir: str, limit: int = 50):
    return _memory(data_dir).events(limit)


@app.get("/audit/verify")
def audit_verify(data_dir: str):
    log = AuditLog(Path(data_dir).expanduser() / "audit.jsonl")
    return {"chain_ok": log.verify()}


@app.get("/", response_class=HTMLResponse)
def index():
    return ("<h1>SpectreOps</h1><p>Endpoints: <code>/findings</code>, "
            "<code>/events</code>, <code>/audit/verify</code> — append "
            "<code>?data_dir=~/.spectreops</code></p>")


def serve(data_dir: str = "~/.spectreops", port: int = 8765) -> None:
    import uvicorn
    # localhost-only by default; remote bind must be an explicit change
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    import typer
    typer.run(lambda data_dir: serve(data_dir or "~/.spectreops"))
