# spectreops/tools/base.py
from __future__ import annotations

import shutil
from typing import Any

import httpx


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
        resp = await client.request(method, url, **kw)
        return {"status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:20000]}
