from __future__ import annotations

import asyncio
import json

from ..base import require_binary


async def trivy_scan(args: dict) -> dict:
    binary = require_binary("trivy")
    target = args["target"]
    sub = "image" if args.get("kind") == "image" else "fs"
    proc = await asyncio.create_subprocess_exec(
        binary, sub, "--format", "json", "--quiet", target,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if proc.returncode != 0:
        return {"error": f"trivy exit {proc.returncode}: {err.decode()[:1000]}"}
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        return {"error": "trivy produced non-JSON output", "raw": out.decode()[:2000]}
    vulns = [{"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
              "version": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"),
              "severity": v.get("Severity"), "title": v.get("Title")}
             for result in report.get("Results", [])
             for v in (result.get("Vulnerabilities") or [])]
    return {"target": target, "vulnerabilities": vulns}


TOOL = {
    "name": "trivy_scan",
    "description": "Scan a filesystem path or container image for vulnerable "
                   "dependencies using trivy.",
    "parameters": {"type": "object",
                   "properties": {"target": {"type": "string"},
                                  "kind": {"type": "string",
                                           "enum": ["fs", "image"]}},
                   "required": ["target"]},
}
