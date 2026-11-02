from __future__ import annotations

from ..llm.base import Message

SYSTEM_PRESERVE = 2          # keep first N messages (system prompt)
RECENT_KEEP = 10             # keep last N messages verbatim


def compact(messages: list[Message], summarizer, max_messages: int = 60) -> list[Message]:
    """Trim history: keep system prompt + recent turns, replace the middle with a summary."""
    if len(messages) <= max_messages:
        return messages
    head = messages[:SYSTEM_PRESERVE]
    middle = messages[SYSTEM_PRESERVE:-RECENT_KEEP]
    tail = messages[-RECENT_KEEP:]
    transcript = "\n".join(
        f"{m.role}: {(m.content or '[tool_call]')[:400]}" for m in middle)
    summary_text = f"[compacted context — summary of {len(middle)} earlier steps]\n{transcript[:4000]}"
    summary = Message(role="user",
                      content=f"Context summary of earlier assessment steps:\n{summary_text}")
    return head + [summary] + tail
