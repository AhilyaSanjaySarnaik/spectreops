from __future__ import annotations

import asyncio
import shlex
import shutil
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
    "mkfs", ":(){:|:&};:", "shutdown", "reboot", "halt", "poweroff",
    "chmod 777 /", "> /dev/sd", "of=/dev/sd", "of=/dev/nvme", "dd if=/dev/zero",
}
_FORBIDDEN_PROGRAMS = {"mkfs", "shutdown", "reboot", "halt", "poweroff", "init",
                       "systemctl", "fdisk", "parted", "wipefs", "shred"}
_ROOT_PATHS = {"/", "/*", "~", "~/", "~/*", "/home", "/etc", "/usr", "/var",
               "/boot", "/root", "$HOME", "${HOME}"}


def check_command(cmd: list[str] | str) -> list[str]:
    """Reject clearly destructive host-impacting commands before execution.

    This is a tripwire, not a security boundary — real isolation comes from the
    docker/bwrap sandbox. Commands are checked as argv so trivial spacing or
    flag-order changes ("rm -r -f /*") are still caught.
    """
    argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    text = " ".join(argv).lower()
    for token in FORBIDDEN_COMMAND_TOKENS:
        if token in text:
            raise PermissionError(f"command rejected by guard: contains '{token}'")
    for i, arg in enumerate(argv):
        prog = Path(arg).name.lower()
        if prog.split(".")[0] in _FORBIDDEN_PROGRAMS and (i == 0 or argv[i - 1] in
                                                         ("sudo", "env", "nohup")):
            raise PermissionError(f"command rejected by guard: '{prog}'")
        if prog == "rm":
            rest = argv[i + 1:]
            recursive = any(a.startswith("-") and not a.startswith("--")
                            and "r" in a.lower() for a in rest) or "--recursive" in rest
            if recursive and any(a.rstrip("/") in {p.rstrip("/") for p in _ROOT_PATHS}
                                 or a in _ROOT_PATHS for a in rest):
                raise PermissionError("command rejected by guard: recursive rm of "
                                      "a system path")
    return argv


SANDBOX_IMAGE = "spectreops/tools:latest"


class SandboxImageMissing(RuntimeError):
    pass


class Sandbox:
    """Runs shell commands with decreasing levels of isolation.

    Resolution order (config: auto): docker -> bwrap -> none.
    'none' still enforces timeouts, output caps, and destructive-command guards.
    """

    def __init__(self, mode: str = "auto", timeout: int = 120, max_output: int = 100_000,
                 network: str = "host", image: str = SANDBOX_IMAGE):
        if network not in ("host", "none"):
            raise ValueError("sandbox network must be 'host' or 'none'")
        self.mode = self._resolve(mode)
        self.timeout = timeout
        self.max_output = max_output
        # host: container shares the host network stack, so the scope validator is
        #       the only network boundary (needed to reach lab targets on 127.0.0.1).
        # none: no network at all — for local analysis.
        self.network = network
        self.image = image
        self._image_ok = False

    async def ensure_image(self) -> None:
        """Fail loudly if the docker image is missing, instead of letting
        `docker run` try to pull it mid-engagement."""
        if self.mode != "docker" or self._image_ok:
            return
        proc = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", self.image,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        if await proc.wait() != 0:
            raise SandboxImageMissing(
                f"sandbox image {self.image} not found — run docker/tools/build.sh "
                f"(or set runtime.sandbox to 'bwrap'/'none')")
        self._image_ok = True

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
            wrapped = ["docker", "run", "--rm", "--network", self.network,
                       "--cap-drop", "ALL", "--cap-add", "NET_RAW",
                       "--security-opt", "no-new-privileges",
                       "--pids-limit", "256", "--memory", "1g",
                       "-v", f"{workdir or Path.cwd()}:/work", "-w", "/work",
                       "--pull", "never", self.image] + cmd
            return wrapped, None
        if self.mode == "bwrap":
            w = workdir or Path.cwd()
            wrapped = ["bwrap", "--ro-bind", "/usr", "/usr", "--proc", "/proc",
                       "--dev", "/dev", "--bind", str(w), "/work",
                       "--chdir", "/work", "--unshare-all"]
            if self.network == "host":
                wrapped.append("--share-net")
            wrapped += cmd
            return wrapped, None
        return check_command(cmd), workdir

    async def run(self, cmd: list[str], workdir: Path | None = None,
                  env: dict[str, str] | None = None) -> SandboxResult:
        cmd = check_command(cmd)
        await self.ensure_image()
        wrapped, _wd = self._wrap(cmd, workdir)
        proc = await asyncio.create_subprocess_exec(
            *wrapped,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir) if workdir else None,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", **(env or {})})
        timed_out = False
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except TimeoutError:
            proc.kill()
            out, err = await proc.communicate()
            timed_out = True
        return SandboxResult(
            stdout=out.decode(errors="replace")[: self.max_output],
            stderr=err.decode(errors="replace")[: self.max_output],
            returncode=proc.returncode if proc.returncode is not None else -1,
            timed_out=timed_out, sandbox=self.mode)
