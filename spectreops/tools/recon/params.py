"""arjun adapter — discover hidden HTTP parameters an endpoint accepts.

Hidden/undocumented parameters are a frequent source of API bugs (mass
assignment, debug flags, auth bypass toggles). Fixed argv; methods restricted to
ordinary verbs; rate/concurrency from policy.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from ...core.rate_limit import current_limiter
from ..base import require_binary

METHODS = {"GET", "POST", "JSON", "XML"}


def build_command(binary: str, url: str, method: str, out_path: str,
                  rate: float, concurrency: int) -> list[str]:
    method = method.upper()
    if method not in METHODS:
        raise ValueError(f"method must be one of {sorted(METHODS)}")
    cmd = [binary, "-u", url, "-m", method, "-oJ", out_path,
           "-t", str(max(1, min(concurrency, 50)))]
    if rate > 0:
        cmd += ["--rate-limit", str(max(1, int(rate)))]
    return cmd


async def param_discover(args: dict) -> dict:
    lim = current_limiter()
    with tempfile.TemporaryDirectory() as td:
        out_path = str(Path(td) / "arjun.json")
        cmd = build_command("arjun", args["url"], str(args.get("method", "GET")),
                            out_path, lim.rate, lim.concurrency)
        cmd[0] = require_binary("arjun")
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        params: list[str] = []
        p = Path(out_path)
        if p.is_file():
            try:
                data = json.loads(p.read_text() or "{}")
                for entry in (data.values() if isinstance(data, dict) else []):
                    params += entry.get("params", []) if isinstance(entry, dict) else []
            except json.JSONDecodeError:
                pass
    return {"url": args["url"], "parameters": sorted(set(params)),
            "stderr": err.decode(errors="replace")[:500]}


TOOL = {
    "name": "param_discover",
    "description": "Discover hidden HTTP parameters an endpoint accepts, using "
                   "arjun. Useful for finding undocumented/debug/mass-assignment "
                   "parameters.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"},
                                  "method": {"type": "string", "enum": sorted(METHODS)}},
                   "required": ["url"]},
}
