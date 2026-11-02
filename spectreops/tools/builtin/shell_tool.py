from __future__ import annotations

from ...safety.approval import ApprovalGate
from ...safety.sandbox import Sandbox

_gate = ApprovalGate()
_sandbox: Sandbox | None = None


def configure(approval: ApprovalGate, sandbox: Sandbox) -> None:
    global _gate, _sandbox
    _gate, _sandbox = approval, sandbox


async def run_shell(args: dict) -> dict:
    cmd = args["command"]
    if isinstance(cmd, str):
        cmd = cmd.split()
    if _gate.requires_approval({"shell"}, "active") and not _gate.confirm(
            f"shell: {cmd}"):
        return {"error": "operator denied shell execution"}
    if _sandbox is None:
        return {"error": "shell tool not configured (missing sandbox)"}
    r = await _sandbox.run(cmd)
    return {"returncode": r.returncode, "timed_out": r.timed_out,
            "stdout": r.stdout, "stderr": r.stderr}


TOOL = {
    "name": "run_shell",
    "description": "Execute a shell command inside the configured sandbox. "
                   "Destructive host commands are rejected.",
    "parameters": {"type": "object",
                   "properties": {"command": {"type": "string"}},
                   "required": ["command"]},
}
