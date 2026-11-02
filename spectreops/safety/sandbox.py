from __future__ import annotations

import asyncio
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxResult:
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False
    sandbox: str = "none"


FORBIDDEN_COMMAND_TOKENS = {
    "rm -rf /", "mkfs", "dd if=/dev/zero", ":(){:|:&};:",
    "shutdown", "reboot", "halt ", "chmod 777 /", "> /dev/sda",
}


def check_command(cmd: list[str] | str) -> list[str]:
    """Reject clearly destructive host-impacting commands before execution."""
    text = " ".join(cmd) if isinstance(cmd, list) else cmd
    low = text.lower()
    for token in FORBIDDEN_COMMAND_TOKENS:
        if token in low:
            raise PermissionError(f"command rejected by guard: contains '{token}'")
    return cmd if isinstance(cmd, list) else text.split()


class Sandbox:
    """Runs shell commands with decreasing levels of isolation.

    Resolution order (config: auto): docker -> bwrap -> none.
    'none' still enforces timeouts, output caps, and destructive-command guards.
    """

    def __init__(self, mode: str = "auto", timeout: int = 120, max_output: int = 100_000):
        self.mode = self._resolve(mode)
        self.timeout = timeout
        self.max_output = max_output

    @staticmethod
    def _resolve(mode: str) -> str:
        if mode != "auto":
            return mode
        if shutil.which("docker"):
            return "docker"
        if shutil.which("bwrap"):
            return "bwrap"
        return "none"

    def _wrap(self, cmd: list[str], workdir: Path | None) -> tuple[list[str], Path | None]:
        if self.mode == "docker":
            image = "spectreops/tools:latest"
            wrapped = ["docker", "run", "--rm", "--network", "host",
                       "-v", f"{workdir or Path.cwd()}:/work", "-w", "/work",
                       image] + cmd
            return wrapped, None
        if self.mode == "bwrap":
            w = workdir or Path.cwd()
            wrapped = ["bwrap", "--ro-bind", "/usr", "/usr", "--proc", "/proc",
                       "--dev", "/dev", "--bind", str(w), "/work",
                       "--chdir", "/work", "--unshare-all", "--share-net"] + cmd
            return wrapped, None
        return check_command(cmd), workdir

    async def run(self, cmd: list[str], workdir: Path | None = None,
                  env: dict[str, str] | None = None) -> SandboxResult:
        cmd = check_command(cmd)
        wrapped, _wd = self._wrap(cmd, workdir)
        proc = await asyncio.create_subprocess_exec(
            *wrapped,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir) if workdir else None,
            env={**(env or {})})
        timed_out = False
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            out, err = await proc.communicate()
            timed_out = True
        return SandboxResult(
            stdout=out.decode(errors="replace")[: self.max_output],
            stderr=err.decode(errors="replace")[: self.max_output],
            returncode=proc.returncode or 0, timed_out=timed_out, sandbox=self.mode)
