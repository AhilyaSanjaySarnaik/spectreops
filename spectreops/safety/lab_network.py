"""Docker-only scanner runner sharing a strictly offline lab target namespace.

This mode is intentionally limited to loopback services in a container launched
with Docker network mode 'none'. It is not a general remote-target firewall.
"""
from __future__ import annotations

import asyncio
import json
import re

LAB_SCANNER_IMAGE = "spectreops/lab-scanner:latest"

_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class LabIsolationError(RuntimeError):
    """A target cannot be established as an isolated Docker lab."""


async def verify_offline_container(container_id: str) -> str:
    if not _CONTAINER_ID.fullmatch(container_id):
        raise LabIsolationError("lab target must be a full or short Docker container ID")
    proc = await asyncio.create_subprocess_exec(
        "docker", "inspect", "--type", "container", container_id,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, _err = await asyncio.wait_for(proc.communicate(), timeout=10)
    if proc.returncode:
        raise LabIsolationError("lab target container not found")
    try:
        info = json.loads(out)[0]
        config = info["HostConfig"]
        state = info["State"]
        networks = info["NetworkSettings"]["Networks"]
        full_id = info["Id"]
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise LabIsolationError("unexpected Docker inspect response") from exc
    if (not state.get("Running")
            or config.get("NetworkMode") != "none"
            or config.get("Privileged")
            or (set(networks) - {"none"})):
        raise LabIsolationError("lab target must be running, unprivileged, network=none")
    if not _CONTAINER_ID.fullmatch(full_id):
        raise LabIsolationError("Docker returned an invalid container ID")
    return full_id


def lab_scanner_command(container_id: str, argv: list[str],
                        image: str = LAB_SCANNER_IMAGE) -> list[str]:
    """Construct a scanner without bind mounts, privileges, or outbound networking."""
    if not _CONTAINER_ID.fullmatch(container_id):
        raise LabIsolationError("invalid lab container ID")
    if not argv or argv[0] not in {"nmap"}:
        raise LabIsolationError("only approved scanner binaries are supported")
    return [
        "docker", "run", "--rm", "--network", f"container:{container_id}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "512m",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
        "--pull", "never", image, *argv,
    ]


async def nmap_lab(target: str, container_id: str, ports: str = "80,443") -> dict:
    """Scan a loopback service in an offline target namespace, never the host."""
    if target not in _LOOPBACK:
        raise LabIsolationError("offline lab scans are restricted to loopback")
    if not re.fullmatch(r"[0-9,-]{1,100}", ports):
        raise LabIsolationError("ports must be a numeric list or range")
    full_id = await verify_offline_container(container_id)
    cmd = lab_scanner_command(full_id, [
        "nmap", "-sT", "-Pn", "-n", "--open", "-p", ports,
        "-oX", "-", "--", target,
    ])
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
    except TimeoutError:
        proc.kill()
        await proc.communicate()
        raise LabIsolationError("lab scan timed out") from None
    if proc.returncode != 0:
        return {"error": "isolated lab nmap failed", "stderr": err.decode(errors="replace")[:800]}
    return {"target": target, "lab_container": full_id[:12],
            "xml": out.decode(errors="replace")[:200000],
            "stderr": err.decode(errors="replace")[:800]}
