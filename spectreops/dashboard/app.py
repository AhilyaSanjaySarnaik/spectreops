from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

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


@app.get("/audit/verify")
def audit_verify():
    path = DATA_DIR / "audit.jsonl"
    if not path.exists():
        raise HTTPException(404, "no audit log yet")
    return {"chain_ok": AuditLog(path).verify()}


@app.get("/", response_class=HTMLResponse)
def index():
    return ("<h1>SpectreOps</h1><p>Endpoints: <a href='/findings'>/findings</a>, "
            "<a href='/events'>/events</a>, <a href='/audit/verify'>/audit/verify</a>"
            "</p>")


def serve(data_dir: str = "~/.spectreops", port: int = 8765) -> None:
    global DATA_DIR
    import uvicorn
    DATA_DIR = Path(data_dir).expanduser()
    # localhost-only by default; remote bind must be an explicit change
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    serve(os.environ.get("SPECTREOPS_DATA_DIR", "~/.spectreops"))
