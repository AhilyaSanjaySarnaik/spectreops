from __future__ import annotations

import shlex

from ...safety.sandbox import Sandbox

# Scope and approval are enforced by the Executor (this tool is registered as
# `unscoped`, so it needs scope mode 'full' and explicit operator approval).
_sandbox: Sandbox | None = None


def configure(sandbox: Sandbox) -> None:
    global _sandbox
    _sandbox = sandbox


async def run_shell(args: dict) -> dict:
    if _sandbox is None:
        return {"error": "shell tool not configured (missing sandbox)"}
    cmd = args["command"]
    argv = shlex.split(cmd) if isinstance(cmd, str) else [str(c) for c in cmd]
    if not argv:
        return {"error": "empty command"}
    r = await _sandbox.run(argv)
    return {"returncode": r.returncode, "timed_out": r.timed_out,
            "sandbox": r.sandbox, "stdout": r.stdout, "stderr": r.stderr}


TOOL = {
    "name": "run_shell",
    "description": "Execute a single command (no shell pipes/redirection) inside "
                   "the configured sandbox. Requires scope mode 'full' and operator "
                   "approval for every call. Prefer a dedicated tool when one exists.",
    "parameters": {"type": "object",
                   "properties": {"command": {"type": "string"}},
                   "required": ["command"]},
}
