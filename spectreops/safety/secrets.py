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


_cache: tuple[Path, float, dict[str, str]] | None = None

# Secret values discovered at runtime (auth tokens resolved from env, etc.) that
# are never written to the secrets file but must still be redacted from output.
_RUNTIME_SECRETS: set[str] = set()


def register_runtime_secret(value: str) -> None:
    """Register a secret value (e.g. an auth token) so redact() masks it."""
    if value and len(value) >= 4:
        _RUNTIME_SECRETS.add(value)


def clear_runtime_secrets() -> None:
    _RUNTIME_SECRETS.clear()


def load_secrets() -> dict[str, str]:
    """Load stored secrets, re-reading the file only when it changes."""
    global _cache
    if not _SECRET_FILE.exists():
        return {}
    mtime = _SECRET_FILE.stat().st_mtime
    if _cache and _cache[0] == _SECRET_FILE and _cache[1] == mtime:
        return _cache[2]
    data = json.loads(_SECRET_FILE.read_text())
    _cache = (_SECRET_FILE, mtime, data)
    return data


def store_secret(name: str, value: str) -> Path:
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = load_secrets()
    data[name] = value
    # create with 0600 up front so the secret is never briefly world-readable
    fd = os.open(_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(data, indent=2))
    _SECRET_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return _SECRET_FILE


def redact(text: str, extra_values: dict[str, str] | None = None) -> str:
    """Redact known secret values and common secret patterns from output."""
    values = (list((extra_values or {}).values()) + list(load_secrets().values())
              + list(_RUNTIME_SECRETS))
    # longest first so a secret that contains another is fully replaced
    for value in sorted(values, key=len, reverse=True):
        if value and len(value) >= 4:
            text = text.replace(value, "[REDACTED]")
    for pat in _PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text
