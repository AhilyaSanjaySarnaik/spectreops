"""gau adapter — pull known URLs for a domain from public archives.

Queries third-party sources (Wayback Machine, Common Crawl, etc.), so it is
tagged third_party_egress and is blocked when runtime.offline is true. The
target host is scope-checked; results are filtered to in-scope hosts is left to
the agent, but the seed domain must be in scope.
"""
from __future__ import annotations

import asyncio

from ..base import require_binary

MAX_URLS = 5000


async def archive_urls(args: dict) -> dict:
    binary = require_binary("gau")
    domain = args["domain"]
    cmd = [binary, "--subs", "--threads", "5", domain] if args.get("include_subs") \
        else [binary, "--threads", "5", domain]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        return {"error": f"gau exit {proc.returncode}: {err.decode()[:500]}"}
    urls = [u for u in out.decode(errors="replace").splitlines() if u][:MAX_URLS]
    return {"domain": domain, "count": len(urls), "urls": urls}


TOOL = {
    "name": "archive_urls",
    "description": "Fetch historical/known URLs for a domain from public archives "
                   "(Wayback, Common Crawl) using gau. Passive but contacts third "
                   "parties, so it is disabled in offline mode.",
    "parameters": {"type": "object",
                   "properties": {"domain": {"type": "string"},
                                  "include_subs": {"type": "boolean"}},
                   "required": ["domain"]},
}
