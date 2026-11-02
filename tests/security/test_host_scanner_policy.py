"""Host-launched scanner adapters require explicit unsafe opt-in and approval."""
from __future__ import annotations

import pytest

from spectreops.core.audit import AuditLog
from spectreops.core.executor import Executor
from spectreops.core.tool_registry import ToolRegistry
from spectreops.safety.approval import ApprovalGate
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator
from spectreops.tools.loader import register_all


def _scanner_executor(tmp_path, allow=False, approval=None):
    registry = ToolRegistry()
    register_all(registry)
    invoked = []

    async def fake_handler(args):
        invoked.append(args)
        return {"ok": True}

    registry.get("nmap_scan").handler = fake_handler
    validator = ScopeValidator(
        Policy(mode="active", targets=["127.0.0.1"], offline=True)
    )
    executor = Executor(
        registry, validator, AuditLog(tmp_path / "audit.jsonl"),
        allow_host_scanners=allow, approval=approval,
    )
    return executor, invoked


@pytest.mark.asyncio
async def test_host_scanner_blocked_by_default(tmp_path):
    executor, invoked = _scanner_executor(
        tmp_path, approval=ApprovalGate(always_yes=True)
    )
    result = await executor.run("nmap_scan", {"target": "127.0.0.1"})
    assert "allow_host_scanners" in result["error"]
    assert invoked == []


@pytest.mark.asyncio
async def test_opt_in_still_requires_approval(tmp_path):
    executor, invoked = _scanner_executor(
        tmp_path, allow=True, approval=ApprovalGate(always_deny=True)
    )
    result = await executor.run("nmap_scan", {"target": "127.0.0.1"})
    assert "denied" in result["error"]
    assert invoked == []


@pytest.mark.asyncio
async def test_explicit_opt_in_and_approval_allow_execution(tmp_path):
    executor, invoked = _scanner_executor(
        tmp_path, allow=True, approval=ApprovalGate(always_yes=True)
    )
    result = await executor.run("nmap_scan", {"target": "127.0.0.1"})
    assert result == {"ok": True}
    assert invoked == [{"target": "127.0.0.1"}]


def test_every_external_adapter_is_marked():
    registry = ToolRegistry()
    register_all(registry)
    names = {
        "nmap_scan", "nuclei_scan", "sqlmap_test", "crawl", "param_discover",
        "ffuf_fuzz", "subfinder_enum", "archive_urls", "trivy_scan",
    }
    assert all(registry.get(name).host_subprocess for name in names)
    assert not registry.get("http_probe").host_subprocess


def test_host_scanner_default_is_disabled():
    from spectreops.core.config import RuntimeConfig

    assert RuntimeConfig().allow_host_scanners is False
