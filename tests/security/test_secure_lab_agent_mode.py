"""The agent's supported secure lab mode fails closed outside isolated Nmap."""
from __future__ import annotations

import pytest

from spectreops.core.audit import AuditLog
from spectreops.core.executor import Executor
from spectreops.core.tool_registry import ToolRegistry
from spectreops.safety.approval import ApprovalGate
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator
from spectreops.tools.loader import register_all


def make_executor(tmp_path, approval):
    registry = ToolRegistry()
    register_all(registry)
    invoked = []

    async def isolated_handler(args):
        invoked.append(args)
        return {"isolated": True}

    nmap = registry.get("nmap_scan")
    nmap.handler = isolated_handler
    nmap.host_subprocess = False
    scope = ScopeValidator(
        Policy(mode="active", targets=["127.0.0.1"], offline=True)
    )
    executor = Executor(
        registry, scope, AuditLog(tmp_path / "audit.jsonl"),
        approval=approval, secure_lab_only=True,
    )
    return executor, invoked


@pytest.mark.asyncio
async def test_secure_lab_refuses_other_network_tools(tmp_path):
    executor, invoked = make_executor(tmp_path, ApprovalGate(always_yes=True))
    for name, args in (
        ("http_probe", {"url": "http://127.0.0.1/"}),
        ("nuclei_scan", {"url": "http://127.0.0.1/"}),
        ("run_shell", {"command": "echo hi"}),
        ("subfinder_enum", {"domain": "127.0.0.1"}),
    ):
        result = await executor.run(name, args)
        assert "scope violation" in result["error"]
    assert invoked == []


@pytest.mark.asyncio
async def test_secure_lab_rejects_other_destinations_and_flags(tmp_path):
    executor, invoked = make_executor(tmp_path, ApprovalGate(always_yes=True))
    for args in (
        {"target": "192.0.2.1"},
        {"target": "127.0.0.1", "extra": "-sV"},
        {"target": "127.0.0.1", "service_detection": True},
    ):
        result = await executor.run("nmap_scan", args)
        assert "scope violation" in result["error"]
    assert invoked == []


@pytest.mark.asyncio
async def test_secure_lab_needs_approval_for_nmap(tmp_path):
    executor, invoked = make_executor(tmp_path, ApprovalGate(always_deny=True))
    result = await executor.run("nmap_scan", {"target": "127.0.0.1"})
    assert "denied" in result["error"]
    assert invoked == []


@pytest.mark.asyncio
async def test_secure_lab_approved_loopback_runs(tmp_path):
    executor, invoked = make_executor(tmp_path, ApprovalGate(always_yes=True))
    result = await executor.run("nmap_scan", {"target": "127.0.0.1", "ports": "8765"})
    assert result == {"isolated": True}
    assert invoked == [{"target": "127.0.0.1", "ports": "8765"}]
