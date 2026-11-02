# spectreops/tools/base.py
from __future__ import annotations

import shutil
from typing import Any

import httpx

from ..core.rate_limit import current_limiter


def require_binary(name: str) -> str:
    """Resolve an external security tool; raise with install hint if missing."""
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(
            f"required tool '{name}' not found on PATH. "
            f"Install it first (e.g. 'apt install {name}' or see project docs).")
    return path


async def http_request(method: str, url: str, **kw: Any) -> dict:
    async with httpx.AsyncClient(verify=False, timeout=30,
                                 follow_redirects=False) as client:
        async with current_limiter().slot():
            resp = await client.request(method, url, **kw)
        return {"status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:20000]}


TOOL_BINARIES = {"nmap_scan": "nmap", "nuclei_scan": "nuclei",
                 "subfinder_enum": "subfinder", "trivy_scan": "trivy"}


def missing_binary(tool_name: str) -> str | None:
    """Human-readable note if a tool's external binary is not installed."""
    binary = TOOL_BINARIES.get(tool_name)
    if binary and shutil.which(binary) is None:
        return f"'{binary}' not installed"
    return None
