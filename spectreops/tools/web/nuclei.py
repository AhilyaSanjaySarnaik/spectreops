from __future__ import annotations

import asyncio
import json
import re
from pathlib import PurePosixPath

from ...core.rate_limit import current_limiter
from ..base import require_binary

SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
# template IDs / tags / relative paths inside the local templates directory
TEMPLATE_RE = re.compile(r"^[A-Za-z0-9_\-./]+$")


def validate_templates(value: str) -> list[str]:
    """Allow only local, relative template paths.

    Remote templates (-t https://...) or absolute paths could load
    attacker-controlled templates — including ones hosted *on the target* —
    whose requests go to arbitrary hosts the executor never validated.
    """
    out = []
    for item in (v.strip() for v in value.split(",")):
        if not item:
            continue
        p = PurePosixPath(item)
        if ("://" in item or p.is_absolute() or ".." in p.parts
                or item.startswith("~") or not TEMPLATE_RE.match(item)):
            raise ValueError(f"template must be a relative path in the local "
                             f"nuclei-templates directory: {item!r}")
        out.append(item)
    return out


def build_command(binary: str, args: dict, rate: float, concurrency: int) -> list[str]:
    # -duc: no update check. -ni: no interactsh — out-of-band callbacks go to
    # public oast.* servers, which is third-party egress outside the scope.
    cmd = [binary, "-u", args["url"], "-jsonl", "-silent", "-duc", "-ni",
           "-c", str(max(1, concurrency))]
    if rate > 0:
        cmd += ["-rl", str(max(1, int(rate)))]
    if args.get("templates"):
        for t in validate_templates(str(args["templates"])):
            cmd += ["-t", t]
    if args.get("severity"):
        sev = [s.strip().lower() for s in str(args["severity"]).split(",") if s.strip()]
        if not set(sev) <= SEVERITIES:
            raise ValueError(f"severity must be from {sorted(SEVERITIES)}")
        cmd += ["-severity", ",".join(sev)]
    return cmd


async def nuclei_scan(args: dict) -> dict:
    lim = current_limiter()
    cmd = build_command("nuclei", args, lim.rate, lim.concurrency)  # validate first
    cmd[0] = require_binary("nuclei")
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
                   "structured findings with severity. 'templates' accepts only "
                   "relative paths/IDs from the local nuclei-templates directory "
                   "(comma-separated), e.g. 'http/exposures,http/misconfiguration'.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"},
                                  "templates": {"type": "string"},
                                  "severity": {"type": "string",
                                               "description": "e.g. 'high,critical'"}},
                   "required": ["url"]},
}
