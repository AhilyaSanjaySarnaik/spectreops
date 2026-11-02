"""Real Docker lab: a runner may reach loopback, never external IPs.

Runs only when SPECTREOPS_DOCKER_LAB=1, in a Linux Docker CI job.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from xml.etree import ElementTree

import pytest

from spectreops.safety.lab_network import (
    LabIsolationError,
    nmap_lab,
    verify_offline_container,
)


@pytest.mark.skipif(
    os.getenv("SPECTREOPS_DOCKER_LAB") != "1" or shutil.which("docker") is None,
    reason="requires explicitly enabled Docker network-isolation lab",
)
def test_offline_namespace_allows_loopback_but_denies_external():
    image = "python:3.12-alpine"
    start = subprocess.run(
        ["docker", "run", "-d", "--rm", "--network", "none",
         "--cap-drop", "ALL", image, "python", "-m", "http.server",
         "8765", "--bind", "127.0.0.1"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    container = start.stdout.strip()
    assert len(container) == 64

    def runner(source: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "run", "--rm", "--network", f"container:{container}",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--read-only", "--pull", "never", image, "python", "-c", source],
            capture_output=True, text=True, timeout=30,
        )

    try:
        assert asyncio.run(verify_offline_container(container)) == container
        allow_code = (
            "import urllib.request; "
            "print(urllib.request.urlopen('http://127.0.0.1:8765/', "
            "timeout=2).status)"
        )
        success = None
        for _ in range(15):
            success = runner(allow_code)
            if success.returncode == 0:
                break
            time.sleep(0.3)
        assert success is not None
        assert success.returncode == 0, success.stderr
        assert success.stdout.strip() == "200"

        deny_code = (
            "import socket,sys; s=socket.socket(); s.settimeout(2); "
            "rc=s.connect_ex(('192.0.2.1', 9)); "
            "print('DENIED' if rc else 'ESCAPED'); sys.exit(0 if rc else 1)"
        )
        denied = runner(deny_code)
        assert denied.returncode == 0, denied.stderr
        assert denied.stdout.strip() == "DENIED"
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                       timeout=15, check=False)


@pytest.mark.skipif(
    os.getenv("SPECTREOPS_DOCKER_LAB") != "1" or shutil.which("docker") is None,
    reason="requires explicitly enabled Docker network-isolation lab",
)
def test_real_nmap_only_scans_offline_lab():
    """Run the actual SpectreOps scanner backend rather than a socket mock."""
    image = "python:3.12-alpine"
    started = subprocess.run(
        ["docker", "run", "-d", "--rm", "--network", "none",
         "--cap-drop", "ALL", image, "python", "-m", "http.server",
         "8765", "--bind", "127.0.0.1"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    container = started.stdout.strip()
    try:
        result = None
        for _ in range(10):
            result = asyncio.run(nmap_lab("127.0.0.1", container, "8765"))
            if "error" not in result:
                root = ElementTree.fromstring(result["xml"])
                if root.find(".//port[@portid='8765']/state[@state='open']") is not None:
                    break
            time.sleep(0.3)
        assert result is not None
        assert "error" not in result, result
        root = ElementTree.fromstring(result["xml"])
        assert root.find(".//port[@portid='8765']/state[@state='open']") is not None

        with pytest.raises(LabIsolationError, match="loopback"):
            asyncio.run(nmap_lab("192.0.2.1", container, "8765"))
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                       timeout=15, check=False)
