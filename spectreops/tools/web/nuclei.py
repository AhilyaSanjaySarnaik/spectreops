from __future__ import annotations

import asyncio
import json

from ..base import require_binary


async def nuclei_scan(args: dict) -> dict:
    binary = require_binary("nuclei")
    cmd = [binary, "-u", args["url"], "-json", "-silent"]
    if args.get("templates"):
        cmd += ["-t", args["templates"]]
    if args.get("severity"):
        cmd += ["-severity", args["severity"]]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    findings = []
    for line in out.decode().splitlines():
        try:
            r = json.loads(line)
            info = r.get("info", {})
            findings.append({"id": r.get("template-id"), "name": info.get("name"),
                             "severity": info.get("severity"),
                             "matched": r.get("matched-at"),
                             "extracted": r.get("extracted-results")})
        except json.JSONDecodeError:
            continue
    return {"url": args["url"], "findings": findings,
            "stderr": err.decode(errors="replace")[:1000]}


TOOL = {
    "name": "nuclei_scan",
    "description": "Run nuclei vulnerability templates against a URL and return "
                   "structured findings with severity.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"},
                                  "templates": {"type": "string"},
                                  "severity": {"type": "string"}},
                   "required": ["url"]},
}
