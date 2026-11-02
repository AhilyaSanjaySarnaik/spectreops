"""Security regression tests for live DNS changes during HTTP tool execution."""
from __future__ import annotations

import socket

import pytest

from spectreops.core import egress
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator, ScopeViolation


def _dns(address):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]


def test_live_dns_change_outside_scope_is_rejected(monkeypatch):
    from spectreops.scope import validator as scope_mod

    monkeypatch.setattr(scope_mod.socket, "getaddrinfo", lambda *_args: _dns("192.0.2.10"))
    validator = ScopeValidator(Policy(mode="active", targets=["lab.example"]))
    validator.check_url("https://lab.example/")
    validator.check_live_dns("https://lab.example/")

    monkeypatch.setattr(scope_mod.socket, "getaddrinfo", lambda *_args: _dns("169.254.169.254"))
    with pytest.raises(ScopeViolation, match="outside approved scope"):
        validator.check_live_dns("https://lab.example/")


def test_dns_resolution_failure_fails_closed(monkeypatch):
    from spectreops.scope import validator as scope_mod

    monkeypatch.setattr(scope_mod.socket, "getaddrinfo", lambda *_args: _dns("192.0.2.10"))
    validator = ScopeValidator(Policy(mode="active", targets=["lab.example"]))

    def fail(*_args):
        raise socket.gaierror("DNS unavailable")

    monkeypatch.setattr(scope_mod.socket, "getaddrinfo", fail)
    with pytest.raises(ScopeViolation, match="DNS resolution failed"):
        validator.check_live_dns("https://lab.example/")


def test_executor_scope_context_checks_live_dns(monkeypatch):
    from spectreops.scope import validator as scope_mod

    monkeypatch.setattr(scope_mod.socket, "getaddrinfo", lambda *_args: _dns("192.0.2.10"))
    validator = ScopeValidator(Policy(mode="active", targets=["lab.example"]))
    token = egress.use_scope(validator)
    try:
        egress.check_http_url("https://lab.example/")
        monkeypatch.setattr(scope_mod.socket, "getaddrinfo", lambda *_args: _dns("169.254.169.254"))
        with pytest.raises(ScopeViolation):
            egress.check_http_url("https://lab.example/")
    finally:
        egress.reset_scope(token)


def test_literal_ip_does_not_require_dns_lookup():
    validator = ScopeValidator(Policy(mode="active", targets=["127.0.0.1"]))
    token = egress.use_scope(validator)
    try:
        egress.check_http_url("https://127.0.0.1/")
    finally:
        egress.reset_scope(token)


@pytest.mark.asyncio
async def test_executor_refuses_dns_switch_inside_handler(tmp_path, monkeypatch):
    from spectreops.core.audit import AuditLog
    from spectreops.core.executor import Executor
    from spectreops.core.tool_registry import Tool, ToolRegistry
    from spectreops.scope import validator as scope_mod

    monkeypatch.setattr(scope_mod.socket, "getaddrinfo", lambda *_args: _dns("192.0.2.10"))
    validator = ScopeValidator(Policy(mode="active", targets=["lab.example"]))

    async def do_http(_args):
        # Simulate a DNS answer changing after the executor's argument validation.
        monkeypatch.setattr(
            scope_mod.socket, "getaddrinfo",
            lambda *_args: _dns("169.254.169.254"),
        )
        egress.check_http_url("https://lab.example/path")
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(Tool(
        name="http_probe", description="probe", parameters={"type": "object"},
        handler=do_http, danger="active",
    ))
    executor = Executor(registry, validator, AuditLog(tmp_path / "audit.jsonl"))
    result = await executor.run("http_probe", {"url": "https://lab.example/path"})
    assert "scope violation" in result["error"]
    assert "169.254.169.254" in result["error"]
