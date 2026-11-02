"""katana crawler adapter — discover endpoints and JS-referenced URLs.

Fixed argv (no raw flags). Depth and headless are the only knobs; rate and
concurrency come from the engagement policy. Crawling only follows links on the
target host; the Executor scope-checks the seed URL.
"""
from __future__ import annotations

import asyncio
import json

from ...core.rate_limit import current_limiter
from ..base import require_binary

MAX_DEPTH = 5


def build_command(binary: str, args: dict, rate: float, concurrency: int) -> list[str]:
    depth = int(args.get("depth", 2))
    if not 1 <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be 1..{MAX_DEPTH}")
    cmd = [binary, "-u", args["url"], "-jsonl", "-silent", "-nc",
           "-d", str(depth), "-c", str(max(1, min(concurrency, 50)))]
    if rate > 0:
        cmd += ["-rl", str(max(1, int(rate)))]
    if args.get("js_crawl"):
        cmd += ["-jc"]            # parse endpoints out of JavaScript
    # -fs fqdn: never stray off the seed host
    cmd += ["-fs", "fqdn"]
    return cmd


async def crawl(args: dict) -> dict:
    lim = current_limiter()
    cmd = build_command("katana", args, lim.rate, lim.concurrency)
    cmd[0] = require_binary("katana")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    urls = []
    for line in out.decode(errors="replace").splitlines():
        try:
            r = json.loads(line)
            u = r.get("request", {}).get("endpoint") or r.get("endpoint")
            if u:
                urls.append(u)
        except json.JSONDecodeError:
            continue
    return {"url": args["url"], "count": len(urls), "endpoints": sorted(set(urls))[:1000],
            "stderr": err.decode(errors="replace")[:500]}


TOOL = {
    "name": "crawl",
    "description": "Crawl a site with katana to discover endpoints (optionally "
                   "parsing JavaScript). Stays on the seed host.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"},
                                  "depth": {"type": "integer", "description": "1..5"},
                                  "js_crawl": {"type": "boolean"}},
                   "required": ["url"]},
}
