from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from fastapi.responses import HTMLResponse

from ..core.assessments import AssessmentError, Assessments
from ..core.audit import AuditLog
from ..core.chat_sessions import ChatStore, reply_to_message
from ..core.config import LLMConfig
from ..llm.ollama import OllamaBackend
from ..llm.openai_compat import OpenAICompatBackend
from ..core.memory import Memory

app = FastAPI(title="SpectreOps Cybersecurity Chat")
CHAT_LLM_CONFIG = LLMConfig()

# The data directory is fixed when the server starts. It used to be a query
# parameter, which let any local page/process open an arbitrary path.
DATA_DIR = Path(os.environ.get("SPECTREOPS_DATA_DIR", "~/.spectreops")).expanduser()


def _chat_store() -> ChatStore:
    return ChatStore(DATA_DIR / "chat.sqlite")


def _chat_backend():
    cfg = CHAT_LLM_CONFIG
    backend = OllamaBackend if cfg.backend == "ollama" else OpenAICompatBackend
    return backend(cfg.base_url, cfg.model, cfg.api_key_env,
                   cfg.temperature, cfg.request_timeout)


class ChatRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=12000)


@app.get("/api/chats")
def list_chats():
    return _chat_store().list_sessions()


@app.post("/api/chats")
def create_chat(request: Request):
    _same_origin(request)
    session_id = _chat_store().create_session()
    return {"id": session_id}


@app.get("/api/chats/{session_id}")
def get_chat(session_id: str):
    store = _chat_store()
    if not store.exists(session_id):
        raise HTTPException(status_code=404, detail="conversation not found")
    return {"id": session_id, "messages": store.messages(session_id)}


def _same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin != str(request.base_url).rstrip("/"):
        raise HTTPException(status_code=403, detail="cross-origin request denied")


@app.post("/api/chat")
async def chat_message(body: ChatRequest, request: Request):
    _same_origin(request)
    store = _chat_store()
    if not store.exists(body.session_id):
        raise HTTPException(status_code=404, detail="conversation not found")
    backend = _chat_backend()
    try:
        reply = await reply_to_message(store, body.session_id, body.message,
                                       backend, CHAT_LLM_CONFIG.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        # Never return upstream response bodies: they can contain credentials.
        raise HTTPException(status_code=502, detail="model backend unavailable") from exc
    finally:
        await backend._client.aclose()
    return {"reply": reply, "session_id": body.session_id}


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
    """Chat-first assistant, with assessment dashboard still under /trends."""
    return Path(__file__).with_name("chat.html").read_text(encoding="utf-8")


@app.get("/trends", response_class=HTMLResponse)
def trend_page():
    return Path(__file__).with_name("overview.html").read_text(encoding="utf-8")



def serve(data_dir: str = "~/.spectreops", port: int = 8765,
          llm_config: LLMConfig | None = None) -> None:
    global DATA_DIR, CHAT_LLM_CONFIG
    import uvicorn
    DATA_DIR = Path(data_dir).expanduser()
    if llm_config is not None:
        CHAT_LLM_CONFIG = llm_config
    # localhost-only by default; remote bind must be an explicit change
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    serve(os.environ.get("SPECTREOPS_DATA_DIR", "~/.spectreops"))
