"""ffuf adapter: directory, parameter and vhost fuzzing.

ffuf is powerful and takes a free-form command line, so — like nmap — the model
never passes raw flags. It picks a mode and a wordlist (which must be a local
file), and this builds a fixed, safe argv. The FUZZ keyword must appear in the
URL (or in a header value for vhost mode); the target host is scope-checked by
the Executor via target_keys=("url",).
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from ...core.rate_limit import current_limiter
from ..base import require_binary

MODES = {"dir", "param", "vhost"}
STATUS_RE = re.compile(r"^[0-9,\-]+$|^all$")
MAX_WORDLIST_BYTES = 50 * 1024 * 1024


def resolve_wordlist(value: str | None) -> str:
    """Resolve a local wordlist path. Remote/URL wordlists are refused so ffuf
    cannot be pointed at attacker-controlled input."""
    if not value:
        # ship-safe default locations; fall back to the built-in small list
        for p in ("/usr/share/seclists/Discovery/Web-Content/common.txt",
                  "/usr/share/wordlists/dirb/common.txt"):
            if Path(p).is_file():
                return p
        raise ValueError("no wordlist given and no default found; pass 'wordlist' "
                         "as a path to a local file")
    if "://" in value:
        raise ValueError("wordlist must be a local file path, not a URL")
    p = Path(value).expanduser()
    if not p.is_file():
        raise ValueError(f"wordlist not found: {value}")
    if p.stat().st_size > MAX_WORDLIST_BYTES:
        raise ValueError(f"wordlist too large (>{MAX_WORDLIST_BYTES // 1_000_000}MB)")
    return str(p)


def build_command(binary: str, args: dict, rate: float, concurrency: int) -> list[str]:
    mode = str(args.get("mode", "dir")).lower()
    if mode not in MODES:
        raise ValueError(f"mode must be one of {sorted(MODES)}")
    url = args["url"]
    if "FUZZ" not in url and mode != "vhost":
        # default dir fuzzing point
        url = url.rstrip("/") + "/FUZZ"
    wordlist = resolve_wordlist(args.get("wordlist"))
    cmd = [binary, "-w", wordlist, "-u", url, "-json", "-s",
           "-t", str(max(1, min(concurrency, 100)))]
    if rate > 0:
        cmd += ["-rate", str(max(1, int(rate)))]
    if mode == "vhost":
        host = args.get("vhost_header") or "FUZZ"
        cmd += ["-H", f"Host: {host}"]
    mc = str(args.get("match_codes", "")).strip()
    if mc:
        if not STATUS_RE.match(mc):
            raise ValueError("match_codes must look like '200,301,403' or 'all'")
        cmd += ["-mc", mc]
    fc = str(args.get("filter_codes", "")).strip()
    if fc:
        if not STATUS_RE.match(fc):
            raise ValueError("filter_codes must look like '404'")
        cmd += ["-fc", fc]
    return cmd


async def ffuf_fuzz(args: dict) -> dict:
    lim = current_limiter()
    cmd = build_command("ffuf", args, lim.rate, lim.concurrency)   # validate first
    cmd[0] = require_binary("ffuf")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    hits = []
    try:
        report = json.loads(out or b"{}")
        for r in report.get("results", []):
            hits.append({"input": (r.get("input") or {}).get("FUZZ"),
                         "url": r.get("url"), "status": r.get("status"),
                         "length": r.get("length"), "words": r.get("words")})
    except json.JSONDecodeError:
        return {"error": "ffuf produced non-JSON output",
                "stderr": err.decode(errors="replace")[:1000]}
    return {"url": args["url"], "mode": args.get("mode", "dir"), "hits": hits}


TOOL = {
    "name": "ffuf_fuzz",
    "description": "Fuzz with ffuf. mode 'dir' (place FUZZ in the path or let it "
                   "append /FUZZ), 'param' (FUZZ in a query param), or 'vhost' "
                   "(fuzz the Host header). 'wordlist' must be a local file path.",
    "parameters": {"type": "object",
                   "properties": {
                       "url": {"type": "string",
                               "description": "target URL, with FUZZ where to fuzz"},
                       "mode": {"type": "string", "enum": sorted(MODES)},
                       "wordlist": {"type": "string",
                                    "description": "local path to a wordlist file"},
                       "match_codes": {"type": "string", "description": "e.g. 200,301,403"},
                       "filter_codes": {"type": "string", "description": "e.g. 404"},
                       "vhost_header": {"type": "string"}},
                   "required": ["url"]},
}
