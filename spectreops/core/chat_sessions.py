"""Persistent, tool-free cybersecurity chat for the standalone web assistant."""
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path

from ..llm.base import Message

CHAT_SYSTEM_PROMPT = """You are SpectreOps, a knowledgeable cybersecurity and bug bounty research assistant.
Be direct, practical and technically precise. Discuss networking, vulnerabilities,
secure coding, cloud security, reverse engineering, pentesting and bug bounty methods
in depth. Use clear explanations, realistic examples, commands and code when useful.
Distinguish hypotheses from confirmed evidence. Do not invent scan results, CVEs,
sources or tool execution. You are in conversation mode; you have no terminal or
network scanning tools. Only describe actions; never claim to have performed them.
Keep safety and authorisation boundaries concise and relevant, not repetitive.
"""

MAX_MESSAGE_CHARS = 12000
MAX_HISTORY_MESSAGES = 40


class ChatStore:
    """SQLite conversations isolated from assessment tool execution."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self._db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                    content TEXT NOT NULL, ts REAL NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES chat_sessions(id)
                );
                CREATE INDEX IF NOT EXISTS chat_messages_session
                    ON chat_messages(session_id,id);
            """)

    def _db(self):
        return sqlite3.connect(self.path, timeout=15)

    def list_sessions(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT id,title,created_at,updated_at FROM chat_sessions "
                "ORDER BY updated_at DESC LIMIT 200",
            ).fetchall()
        return [dict(zip(("id", "title", "created_at", "updated_at"), row,
                         strict=True)) for row in rows]

    def create_session(self, title: str = "New conversation") -> str:
        now = time.time()
        session_id = str(uuid.uuid4())
        with self._db() as conn:
            conn.execute(
                "INSERT INTO chat_sessions VALUES (?,?,?,?)",
                (session_id, title[:100], now, now),
            )
        return session_id

    def messages(self, session_id: str, limit: int | None = None) -> list[dict]:
        with self._db() as conn:
            if limit is None:
                rows = conn.execute(
                    "SELECT role,content,ts FROM chat_messages "
                    "WHERE session_id=? ORDER BY id", (session_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT role,content,ts FROM (SELECT id,role,content,ts "
                    "FROM chat_messages WHERE session_id=? "
                    "ORDER BY id DESC LIMIT ?) ORDER BY id",
                    (session_id, limit),
                ).fetchall()
        return [dict(zip(("role", "content", "ts"), row, strict=True)) for row in rows]

    def exists(self, session_id: str) -> bool:
        with self._db() as conn:
            return conn.execute(
                "SELECT 1 FROM chat_sessions WHERE id=?", (session_id,),
            ).fetchone() is not None

    def add_message(self, session_id: str, role: str, content: str) -> None:
        if role not in ("user", "assistant"):
            raise ValueError("invalid chat role")
        with self._db() as conn:
            if not conn.execute(
                "SELECT 1 FROM chat_sessions WHERE id=?", (session_id,),
            ).fetchone():
                raise KeyError("unknown conversation")
            now = time.time()
            conn.execute(
                "INSERT INTO chat_messages (session_id,role,content,ts) "
                "VALUES (?,?,?,?)", (session_id, role, content, now),
            )
            conn.execute(
                "UPDATE chat_sessions SET updated_at=?, "
                "title=CASE WHEN title='New conversation' AND ?='user' "
                "THEN ? ELSE title END WHERE id=?",
                (now, role, content.strip().splitlines()[0][:75], session_id),
            )


async def reply_to_message(store: ChatStore, session_id: str, user_text: str,
                           llm, model: str) -> str:
    """Never pass tool schemas: this is Q&A, not the agent execution loop."""
    content = user_text.strip()
    if not content or len(content) > MAX_MESSAGE_CHARS:
        raise ValueError("message must contain 1–12000 characters")
    if not store.exists(session_id):
        raise KeyError("unknown conversation")
    prior = store.messages(session_id, limit=MAX_HISTORY_MESSAGES)
    messages = [Message(role="system", content=CHAT_SYSTEM_PROMPT)]
    messages.extend(Message(role=x["role"], content=x["content"]) for x in prior)
    messages.append(Message(role="user", content=content))
    answer = await llm.chat(messages, tools=None, model=model)
    response = (answer.content or "").strip()
    if not response:
        raise RuntimeError("model returned an empty reply")
    store.add_message(session_id, "user", content)
    store.add_message(session_id, "assistant", response)
    return response
