"""Offline Docker lab scanner guard tests (no live network required)."""
from __future__ import annotations

import json

import pytest

from spectreops.safety import lab_network


def test_lab_command_has_no_host_network_mounts_or_privileges():
    cmd = lab_network.lab_scanner_command("a" * 64, [
        "nmap", "-sT", "-Pn", "127.0.0.1",
    ])
    assert ["--network", "container:" + "a" * 64] == cmd[3:5]
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "--read-only" in cmd and "--pull" in cmd
    assert "--privileged" not in cmd
    assert "-v" not in cmd and "--volume" not in cmd
    assert "--network=host" not in cmd


@pytest.mark.parametrize("bad", ["", "abc", "target", "x" * 64, "a" * 65])
def test_invalid_container_id_rejected(bad):
    with pytest.raises(lab_network.LabIsolationError):
        lab_network.lab_scanner_command(bad, ["nmap"])


def test_arbitrary_binary_cannot_run():
    with pytest.raises(lab_network.LabIsolationError):
        lab_network.lab_scanner_command("a" * 64, ["bash", "-c", "id"])


@pytest.mark.asyncio
async def test_reject_attached_network_without_scanning(monkeypatch):
    class FakeProc:
        returncode = 0

        async def communicate(self):
            info = [{
                "Id": "a" * 64,
                "State": {"Running": True},
                "HostConfig": {"NetworkMode": "none", "Privileged": False},
                "NetworkSettings": {"Networks": {"none": {}, "bridge": {}}},
            }]
            return json.dumps(info).encode(), b""

    async def fake_exec(*_args, **_kwargs):
        return FakeProc()

    monkeypatch.setattr(lab_network.asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(lab_network.LabIsolationError, match="network=none"):
        await lab_network.verify_offline_container("a" * 64)


@pytest.mark.asyncio
async def test_accept_offline_container_with_none_attachment(monkeypatch):
    class FakeProc:
        returncode = 0

        async def communicate(self):
            info = [{
                "Id": "a" * 64,
                "State": {"Running": True},
                "HostConfig": {"NetworkMode": "none", "Privileged": False},
                "NetworkSettings": {"Networks": {"none": {}}},
            }]
            return json.dumps(info).encode(), b""

    async def fake_exec(*_args, **_kwargs):
        return FakeProc()

    monkeypatch.setattr(lab_network.asyncio, "create_subprocess_exec", fake_exec)
    assert await lab_network.verify_offline_container("a" * 64) == "a" * 64
