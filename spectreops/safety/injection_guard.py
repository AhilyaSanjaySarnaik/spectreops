# spectreops/safety/injection_guard.py
from __future__ import annotations

import re

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?(previous|prior) instructions", re.I),
    re.compile(r"disregard (the )?system prompt", re.I),
    re.compile(r"you are now (a|an) .{0,40}(agent|assistant|mode)", re.I),
    re.compile(r"(disable|bypass|turn off) (your )?(safety|security|filters)", re.I),
    re.compile(r"reveal (your )?(system )?prompt", re.I),
    re.compile(r"add .* to (your )?scope", re.I),
]


def scrub_tool_output(text: str, max_len: int = 200_000) -> tuple[str, list[str]]:
    """Neutralize prompt-injection attempts found in scanned content.
    Returns (clean_text, detected_patterns)."""
    detected = [p.pattern for p in _INJECTION_PATTERNS if p.search(text)]
    clean = text
    for p in _INJECTION_PATTERNS:
        clean = p.sub("[INJECTION-ATTEMPT-REDACTED]", clean)
    return clean[:max_len], detected
