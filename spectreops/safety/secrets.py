from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

_SECRET_FILE = Path(os.environ.get("SPECTREOPS_SECRETS",
                                   Path.home() / ".spectreops" / "secrets.json"))

_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|authorization)\s*[:=]\s*\S+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                      # AWS access key
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI-style key
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),                  # GitHub PAT
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\."), # JWT
]


def load_secrets() -> dict[str, str]:
    if not _SECRET_FILE.exists():
        return {}
    return json.loads(_SECRET_FILE.read_text())


def store_secret(name: str, value: str) -> Path:
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = load_secrets()
    data[name] = value
    _SECRET_FILE.write_text(json.dumps(data, indent=2))
    _SECRET_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)   # 0600, owner-only
    return _SECRET_FILE


def redact(text: str, extra_values: dict[str, str] | None = None) -> str:
    """Redact known secret values and common secret patterns from output."""
    for value in list((extra_values or {}).values()) + list(load_secrets().values()):
        if value:
            text = text.replace(value, "[REDACTED]")
    for pat in _PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text
