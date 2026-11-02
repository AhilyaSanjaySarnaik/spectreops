from __future__ import annotations

import asyncio
import json

from ..base import require_binary


async def subfinder_enum(args: dict) -> dict:
    binary = require_binary("subfinder")
    proc = await asyncio.create_subprocess_exec(
        binary, "-d", args["domain"], "-silent", "-json",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        return {"error": f"subfinder exit {proc.returncode}: {err.decode()[:1000]}"}
    subs = []
    for line in out.decode().splitlines():
        try:
            entry = json.loads(line)
            subs.append({"host": entry.get("host"), "source": entry.get("source")})
        except json.JSONDecodeError:
            continue
    return {"domain": args["domain"], "subdomains": subs}


TOOL = {
    "name": "subfinder_enum",
    "description": "Passive subdomain discovery for a domain using subfinder.",
    "parameters": {"type": "object",
                   "properties": {"domain": {"type": "string"}},
                   "required": ["domain"]},
}
