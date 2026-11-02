# spectreops/tools/base.py
from __future__ import annotations

import shutil
from typing import Any
from urllib.parse import urljoin

import httpx

from ..core.auth import current_auth
from ..core.egress import check_http_url
from ..core.rate_limit import current_limiter

BODY_CAP = 20000


def require_binary(name: str) -> str:
    """Resolve an external security tool; raise with install hint if missing."""
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(
            f"required tool '{name}' not found on PATH. "
            f"Install it first (e.g. 'apt install {name}' or see project docs).")
    return path


async def http_request(method: str, url: str, *, identity: str | None = None,
                       headers: dict[str, str] | None = None,
                       follow_redirects: bool = False, raw: bool = False,
                       **kw: Any) -> dict:
    """Make one rate-limited HTTP request, attaching the active identity's
    credential when the request host has one configured. `raw=True` also returns
    the request line and sent headers (with secrets still redacted downstream)
    so the result can be stored as finding evidence."""
    check_http_url(url)
    headers, cookies, params = current_auth().apply(url, headers or {}, identity)
    if cookies:
        kw["cookies"] = {**kw.get("cookies", {}), **cookies}
    if params:
        kw["params"] = {**kw.get("params", {}), **params}
    # Never let the HTTP client silently follow redirects: even a scoped URL
    # can redirect off-scope and leak authentication headers or request bodies.
    # Caller may inspect Location and explicitly authorize a second request.
    async with httpx.AsyncClient(verify=True, trust_env=False, timeout=30,
                                 follow_redirects=False) as client:
        async with current_limiter().slot():
            resp = await client.request(method, url, headers=headers, **kw)
        if follow_redirects and resp.is_redirect and resp.headers.get("location"):
            return {"error": "redirect not followed: explicit scope validation required",
                    "status": resp.status_code, "url": str(resp.url),
                    "location": urljoin(str(resp.url), resp.headers["location"])}
        out = {"status": resp.status_code,
               "url": str(resp.url),
               "headers": dict(resp.headers),
               "body": resp.text[:BODY_CAP]}
        if raw:
            out["request"] = {"method": method.upper(), "url": url,
                              "headers": dict(resp.request.headers),
                              "identity": identity or current_auth().active}
        return out


TOOL_BINARIES = {"nmap_scan": "nmap", "nuclei_scan": "nuclei",
                 "subfinder_enum": "subfinder", "trivy_scan": "trivy",
                 "ffuf_fuzz": "ffuf", "crawl": "katana", "param_discover": "arjun",
                 "archive_urls": "gau", "sqlmap_test": "sqlmap"}


def missing_binary(tool_name: str) -> str | None:
    """Human-readable note if a tool's external binary is not installed."""
    binary = TOOL_BINARIES.get(tool_name)
    if binary and shutil.which(binary) is None:
        return f"'{binary}' not installed"
    return None
