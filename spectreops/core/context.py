from __future__ import annotations

from collections.abc import Callable

from ..llm.base import Message

SYSTEM_PRESERVE = 2          # keep first N messages (system prompt + original task)
RECENT_KEEP = 10             # keep roughly the last N messages verbatim


def _default_summary(middle: list[Message]) -> str:
    transcript = "\n".join(
        f"{m.role}: {(m.content or '[tool_call]')[:400]}" for m in middle)
    return transcript[:4000]


def compact(messages: list[Message],
            summarizer: Callable[[list[Message]], str] | None = None,
            max_messages: int = 60) -> list[Message]:
    """Trim history: keep system prompt + recent turns, replace the middle with a summary.

    The cut point is moved backwards so the retained tail never starts with a
    ``tool`` message whose assistant ``tool_calls`` message was summarized away —
    OpenAI-compatible servers reject such orphaned tool results.
    """
    if len(messages) <= max_messages:
        return messages
    cut = len(messages) - RECENT_KEEP
    while cut > SYSTEM_PRESERVE and messages[cut].role == "tool":
        cut -= 1
    if cut <= SYSTEM_PRESERVE:
        return messages
    head = messages[:SYSTEM_PRESERVE]
    middle = messages[SYSTEM_PRESERVE:cut]
    tail = messages[cut:]
    text = (summarizer or _default_summary)(middle)
    summary = Message(
        role="user",
        content=(f"Context summary of {len(middle)} earlier assessment steps "
                 f"(compacted):\n{text}"))
    return head + [summary] + tail
