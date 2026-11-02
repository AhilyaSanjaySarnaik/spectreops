"""sqlmap adapter — SQL injection detection, locked down.

sqlmap can run OS commands, read/write files and open shells. None of that is
reachable here: the model picks from a small set of detection-only options and
this builds a fixed argv. Any attempt to pass an out-of-band or code-execution
option is refused. The tool is registered with danger="exploit", so it only runs
in the plan's exploit phase AND requires operator approval on every call.

sqlmap is also pinned to batch/non-interactive, forced to stay on the target
(no crawling to other hosts), and never allowed to auto-update.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path

from ...core.rate_limit import current_limiter
from ..base import require_binary

# Detection/enumeration options the model may toggle. Everything else is refused.
ALLOWED_ENUM = {"--banner", "--current-user", "--current-db", "--is-dba",
                "--dbs", "--tables", "--users", "--passwords", "--privileges"}
# Options that must NEVER appear — code execution, file access, OOB, tampering.
FORBIDDEN = ("--os-shell", "--os-cmd", "--os-pwn", "--sql-shell", "--sql-query",
             "--eval", "--file-read", "--file-write", "--file-dest", "--tamper",
             "--priv-esc", "--reg-read", "--reg-add", "--shell", "--udf-inject",
             "--crawl", "-c", "--configFile", "--load-cookies", "--proxy",
             "--second-url", "--second-req")
LEVEL_RE = re.compile(r"^[1-5]$")
RISK_RE = re.compile(r"^[1-3]$")


def build_command(binary: str, args: dict, out_dir: str, rate_delay: float) -> list[str]:
    url = args["url"]
    cmd = [binary, "-u", url, "--batch", "--disable-coloring", "--flush-session",
           "--answers=quit=N,crack=N,dict=N", "--output-dir", out_dir]
    level = str(args.get("level", "1"))
    risk = str(args.get("risk", "1"))
    if not LEVEL_RE.match(level):
        raise ValueError("level must be 1..5")
    if not RISK_RE.match(risk):
        raise ValueError("risk must be 1..3")
    cmd += ["--level", level, "--risk", risk]
    # keep sqlmap on the target host and off the network otherwise
    if args.get("data"):
        data = str(args["data"])
        # a body value can't introduce sqlmap options, but refuse one that looks
        # like it's trying to (e.g. smuggling --os-cmd= through the data field)
        if any(opt + "=" in data or opt + " " in data for opt in FORBIDDEN):
            raise ValueError("request body contains a forbidden sqlmap option")
        cmd += ["--data", data]
    for opt in (args.get("enumerate") or []):
        if opt not in ALLOWED_ENUM:
            raise ValueError(f"enumeration option not allowed: {opt!r}. "
                             f"Allowed: {sorted(ALLOWED_ENUM)}")
        cmd.append(opt)
    # throttle: translate the engagement rate into a per-request delay
    if rate_delay > 0:
        cmd += ["--delay", f"{rate_delay:g}"]
    # defence in depth: no built argv token may be a forbidden option
    forbidden = set(FORBIDDEN)
    for tok in cmd[1:]:
        head = tok.split("=", 1)[0]
        if head in forbidden:
            raise ValueError(f"refused: sqlmap option {head!r} is disabled")
    return cmd


async def sqlmap_test(args: dict) -> dict:
    lim = current_limiter()
    delay = 1.0 / lim.rate if lim.rate and lim.rate > 0 else 0.0
    with tempfile.TemporaryDirectory() as td:
        cmd = build_command("sqlmap", args, td, delay)     # validate before resolving
        cmd[0] = require_binary("sqlmap")
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        injectable = "is vulnerable" in out.decode(errors="replace").lower() or \
                     "sqlmap identified" in out.decode(errors="replace").lower()
        findings = _parse_logs(Path(td))
    return {"url": args["url"], "injectable": injectable,
            "detail": findings,
            "stdout_tail": out.decode(errors="replace")[-3000:],
            "stderr": err.decode(errors="replace")[:500]}


def _parse_logs(out_dir: Path) -> list[dict]:
    results = []
    for log in out_dir.rglob("log"):
        try:
            results.append({"target": log.parent.name,
                            "log_excerpt": log.read_text(errors="replace")[:2000]})
        except OSError:
            continue
    for target_json in out_dir.rglob("*.json"):
        try:
            results.append({"file": target_json.name,
                            "data": json.loads(target_json.read_text())})
        except (OSError, json.JSONDecodeError):
            continue
    return results


TOOL = {
    "name": "sqlmap_test",
    "description": "Test a URL (optionally with a request body) for SQL injection "
                   "using sqlmap, detection/enumeration only. OS/file/shell options "
                   "are disabled. Runs only in the exploit phase and needs approval.",
    "parameters": {"type": "object",
                   "properties": {
                       "url": {"type": "string"},
                       "data": {"type": "string", "description": "POST body to test"},
                       "level": {"type": "string", "description": "1..5"},
                       "risk": {"type": "string", "description": "1..3"},
                       "enumerate": {"type": "array", "items": {"type": "string"},
                                     "description": f"subset of {sorted(ALLOWED_ENUM)}"}},
                   "required": ["url"]},
}
