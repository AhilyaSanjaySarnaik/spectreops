"""Adversarial / abuse-case tests — the guards that stop the agent (or a
prompt-injected model) from doing something out of scope or out of policy.

These are the cases that matter most if a guard silently regresses: SSRF to
cloud metadata, scope escape through tool arguments, noise/stealth caps, the
exploit-phase gate, and secret leakage.
"""
from __future__ import annotations

import pytest

from spectreops.core.audit import AuditLog
from spectreops.core.auth import AuthStore
from spectreops.core.config import AuthConfig
from spectreops.core.executor import Executor
from spectreops.core.planner import Plan
from spectreops.core.tool_registry import ToolRegistry
from spectreops.safety.approval import ApprovalGate
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator
from spectreops.tools.loader import register_all


def _real_executor(tmp_path, mode="active", targets=("127.0.0.1",), offline=True,
                   profile="normal", plan=None, approval=None, auth=None):
    reg = ToolRegistry()
    register_all(reg)

    async def ok(_args):
        return {"ok": True}
    for t in reg.all():
        t.handler = ok            # don't actually shell out; we test the guards
    pol = Policy(mode=mode, targets=list(targets), offline=offline, profile=profile)
    return reg, Executor(reg, ScopeValidator(pol), AuditLog(tmp_path / "a.jsonl"),
                         plan=plan, approval=approval, auth=auth)


# ---- SSRF / metadata -------------------------------------------------------
@pytest.mark.asyncio
async def test_cloud_metadata_ip_blocked(tmp_path):
    _, ex = _real_executor(tmp_path)
    for url in ("http://169.254.169.254/latest/meta-data/",
                "http://[fd00:ec2::254]/latest/meta-data/"):
        res = await ex.run("http_probe", {"url": url})
        assert "scope violation" in res["error"]


@pytest.mark.asyncio
async def test_scope_escape_via_second_url_arg_blocked(tmp_path):
    _, ex = _real_executor(tmp_path)
    res = await ex.run("http_send", {"url": "http://127.0.0.1/",
                                     "headers": {"X-Forwarded-For":
                                                 "see http://169.254.169.254/"}})
    assert "scope violation" in res["error"]


# ---- noise / stealth caps --------------------------------------------------
def test_stealth_profile_caps_rate_and_concurrency(tmp_path):
    _, ex = _real_executor(tmp_path, profile="stealth")
    assert ex.limiter.rate <= 2.0 and ex.limiter.concurrency == 1


def test_profile_cannot_raise_above_policy(tmp_path):
    # loud profile has no rate cap, but policy's explicit 3/s still wins
    reg = ToolRegistry()
    register_all(reg)
    pol = Policy(mode="active", targets=["127.0.0.1"], profile="loud",
                 rate_limit=3.0, concurrency=2)
    ex = Executor(reg, ScopeValidator(pol), AuditLog(tmp_path / "a.jsonl"))
    assert ex.limiter.rate == 3.0 and ex.limiter.concurrency == 2


def test_nmap_quiet_by_default():
    from spectreops.core.profile import get_profile
    from spectreops.tools.recon.nmap import default_extra
    extra = default_extra(get_profile("normal"), service_detection=False)
    assert "-sV" not in extra                     # no version detection by default
    assert get_profile("stealth").nmap_top_ports <= 50


# ---- exploit-phase gate ----------------------------------------------------
@pytest.mark.asyncio
async def test_exploit_tool_blocked_outside_exploit_phase(tmp_path):
    plan = Plan(objective="o")
    plan.current = plan.phases.index("test")
    _, ex = _real_executor(tmp_path, mode="full", plan=plan,
                           approval=ApprovalGate(always_yes=True))
    res = await ex.run("sqlmap_test", {"url": "http://127.0.0.1/?id=1"})
    assert "only allowed in the 'exploit' phase" in res["error"]


@pytest.mark.asyncio
async def test_shell_needs_full_mode(tmp_path):
    _, ex = _real_executor(tmp_path, mode="active",
                           approval=ApprovalGate(always_yes=True))
    res = await ex.run("run_shell", {"command": "id"})
    assert "scope mode 'full'" in res["error"]


# ---- secret leakage --------------------------------------------------------
@pytest.mark.asyncio
async def test_auth_token_never_in_audit_or_output(tmp_path, monkeypatch):
    monkeypatch.setenv("LEAKTOK", "supersecret-leaktoken-123")
    auth = AuthStore.from_config(AuthConfig(active="a", identities={
        "a": {"127.0.0.1": {"kind": "bearer", "token_env": "LEAKTOK"}}}))
    reg = ToolRegistry()
    register_all(reg)

    async def echo(_args):
        return {"body": "token=supersecret-leaktoken-123"}
    reg.get("http_probe").handler = echo
    pol = Policy(mode="active", targets=["127.0.0.1"])
    ex = Executor(reg, ScopeValidator(pol), AuditLog(tmp_path / "a.jsonl"), auth=auth)
    res = await ex.run("http_probe", {"url": "http://127.0.0.1/",
                                      "headers": {"Authorization": "Bearer x"}})
    assert "supersecret-leaktoken-123" not in str(res)
    assert "supersecret-leaktoken-123" not in (tmp_path / "a.jsonl").read_text()


# ---- offline egress --------------------------------------------------------
@pytest.mark.asyncio
async def test_offline_blocks_third_party_tools(tmp_path):
    _, ex = _real_executor(tmp_path, targets=("example.com",), offline=True)
    for tool, arg in (("subfinder_enum", {"domain": "example.com"}),
                      ("archive_urls", {"domain": "example.com"})):
        res = await ex.run(tool, arg)
        assert "third-party" in res["error"]
