from __future__ import annotations

import asyncio

from ..base import require_binary


async def nmap_scan(args: dict) -> dict:
    binary = require_binary("nmap")
    target = args["target"]
    cmd = [binary, "-oX", "-", "-Pn"]
    if args.get("ports"):
        cmd += ["-p", str(args["ports"])]
    cmd += args.get("extra", "-sV --open").split() + [target]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        return {"error": f"nmap exit {proc.returncode}: {err.decode()[:2000]}"}
    return {"target": target, "xml": out.decode(errors="replace")[:200000],
            "summary": err.decode(errors="replace")[:2000]}


TOOL = {
    "name": "nmap_scan",
    "description": "Scan a target for open TCP ports and service versions using "
                   "nmap. Active scan — in-scope hosts only.",
    "parameters": {"type": "object",
                   "properties": {"target": {"type": "string"},
                                  "ports": {"type": "string"},
                                  "extra": {"type": "string"}},
                   "required": ["target"]},
}
