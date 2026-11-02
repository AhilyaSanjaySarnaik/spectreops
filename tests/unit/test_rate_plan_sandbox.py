"""Tests for rate limiting, nuclei template lockdown, sandbox image check and planner gating."""
from __future__ import annotations

import asyncio
import shutil
import time

import pytest

from spectreops.core.audit import AuditLog
from spectreops.core.executor import Executor
from spectreops.core.planner import Plan
from spectreops.core.rate_limit import RateLimiter, current_limiter
from spectreops.core.tool_registry import Tool, ToolRegistry
from spectreops.safety.approval import ApprovalGate
from spectreops.safety.sandbox import Sandbox, SandboxImageMissing
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator
from spectreops.tools.builtin.plan_tools import make_plan_tools
from spectreops.tools.recon.nmap import apply_rate_ceiling
from spectreops.tools.web.nuclei import build_command, validate_templates


# ---- rate limiting ---------------------------------------------------------
@pytest.mark.asyncio
async def test_limiter_spaces_requests():
    lim = RateLimiter(rate=20, concurrency=5)          # 50 ms apart
    stamps = []

    async def req():
        async with lim.slot():
            stamps.append(time.monotonic())
    await asyncio.gather(*(req() for _ in range(6)))
    gaps = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    assert min(gaps) >= 0.045
    assert stamps[-1] - stamps[0] >= 0.24


@pytest.mark.asyncio
async def test_limiter_caps_concurrency():
    lim = RateLimiter(rate=0, concurrency=2)
    live = peak = 0

    async def req():
        nonlocal live, peak
        async with lim.slot():
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.02)
            live -= 1
    await asyncio.gather(*(req() for _ in range(8)))
    assert peak == 2


def _executor(tmp_path, tool, mode="active", rate=7.0, plan=None, approval=None):
    reg = ToolRegistry()
    reg.register(tool)
    v = ScopeValidator(Policy(mode=mode, targets=["127.0.0.1"], rate_limit=rate,
                              concurrency=3))
    return Executor(reg, v, AuditLog(tmp_path / "a.jsonl"), plan=plan, approval=approval)


@pytest.mark.asyncio
async def test_executor_installs_policy_limiter_for_network_tools(tmp_path):
    seen = {}

    async def h(_args):
        lim = current_limiter()
        seen["rate"], seen["conc"] = lim.rate, lim.concurrency
        return {}
    ex = _executor(tmp_path, Tool("t", "", {"type": "object"}, h, target_keys=("url",)))
    await ex.run("t", {"url": "http://127.0.0.1/"})
    assert seen == {"rate": 7.0, "conc": 3}
    assert current_limiter().rate == 0          # reset after the call


def test_nmap_rate_ceiling():
    assert apply_rate_ceiling(["-sV"], 10) == ["-sV", "--max-rate", "10"]
    assert apply_rate_ceiling(["--max-rate", "500"], 10) == ["--max-rate", "10"]
    assert apply_rate_ceiling(["--max-rate", "5"], 10) == ["--max-rate", "5"]
    assert apply_rate_ceiling(["-sV"], 0) == ["-sV"]


# ---- nuclei ----------------------------------------------------------------
def test_nuclei_flags_include_limits_and_no_oob():
    cmd = build_command("nuclei", {"url": "http://127.0.0.1"}, rate=10, concurrency=4)
    assert "-ni" in cmd and "-duc" in cmd
    assert cmd[cmd.index("-rl") + 1] == "10" and cmd[cmd.index("-c") + 1] == "4"


@pytest.mark.parametrize("bad", ["https://evil.example/t.yaml", "/etc/passwd",
                                 "../../x.yaml", "~/t.yaml", "http/a;rm -rf"])
def test_nuclei_rejects_non_local_templates(bad):
    with pytest.raises(ValueError):
        validate_templates(bad)


def test_nuclei_accepts_local_templates():
    assert validate_templates("http/exposures, cves/2024/") == ["http/exposures",
                                                                "cves/2024/"]


# ---- sandbox ---------------------------------------------------------------
@pytest.mark.asyncio
async def test_sandbox_missing_image_fails_loudly():
    if not shutil.which("docker"):
        pytest.skip("docker CLI not installed")
    sb = Sandbox(mode="docker", image="spectreops/definitely-not-built:never")
    with pytest.raises(SandboxImageMissing, match="build.sh"):
        await sb.run(["true"])


def test_sandbox_network_option():
    sb = Sandbox(mode="docker", network="none")
    wrapped, _ = sb._wrap(["id"], None)
    assert wrapped[wrapped.index("--network") + 1] == "none"
    assert "--pull" in wrapped and "never" in wrapped
    with pytest.raises(ValueError):
        Sandbox(mode="none", network="bridge")


# ---- planner -----------------------------------------------------------------
def _tools(plan, mode="full", answer="n"):
    gate = ApprovalGate(prompt=lambda _q: answer)
    return {t.name: t.handler for t in make_plan_tools(plan, gate, mode)}


def _at_test_phase() -> Plan:
    p = Plan(objective="o")
    p.current = p.phases.index("test")
    return p


@pytest.mark.asyncio
async def test_plan_tasks_block_advance_until_done():
    p = Plan(objective="o")
    t = _tools(p)
    await t["plan_task"]({"task": "enumerate ports"})
    assert "open task" in (await t["plan_next_phase"]({}))["error"]
    await t["plan_complete_task"]({"index": 0})
    assert (await t["plan_next_phase"]({}))["phase"] == "collect"


@pytest.mark.asyncio
async def test_entering_exploit_requires_approval():
    p = _at_test_phase()
    res = await _tools(p, mode="full", answer="n")["plan_next_phase"]({})
    assert "did not approve" in res["error"] and p.current_phase() == "test"
    res = await _tools(p, mode="full", answer="y")["plan_next_phase"]({})
    assert res["phase"] == "exploit"


@pytest.mark.asyncio
async def test_exploit_phase_skipped_outside_full_mode():
    p = _at_test_phase()
    res = await _tools(p, mode="active", answer="y")["plan_next_phase"]({})
    assert res["phase"] == "report" and "skipped 'exploit'" in res["note"]


@pytest.mark.asyncio
async def test_exploit_tools_only_run_in_exploit_phase(tmp_path):
    async def h(_a):
        return {"ok": True}
    tool = Tool("exp", "", {"type": "object"}, h, danger="exploit", target_keys=("url",))
    plan = _at_test_phase()
    ex = _executor(tmp_path, tool, mode="full", plan=plan,
                   approval=ApprovalGate(always_yes=True))
    res = await ex.run("exp", {"url": "http://127.0.0.1/"})
    assert "only allowed in the 'exploit' phase" in res["error"]
    plan.current = plan.phases.index("exploit")
    assert await ex.run("exp", {"url": "http://127.0.0.1/"}) == {"ok": True}


def test_plan_save_load_roundtrip(tmp_path):
    p = Plan(objective="assess lab")
    p.add_task("recon", "dns")
    p.advance()
    path = p.save(tmp_path / "plans" / "p.json")
    q = Plan.load(path)
    assert (q.objective, q.current_phase(), q.tasks) == ("assess lab", "collect",
                                                         {"recon": [{"task": "dns",
                                                                     "done": False}]})


@pytest.mark.asyncio
async def test_limiter_acquire_release_api():
    lim = RateLimiter(rate=0, concurrency=1)
    await lim.acquire()
    assert lim._sem.locked()
    lim.release()
    assert not lim._sem.locked()
