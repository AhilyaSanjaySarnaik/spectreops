import pytest

from spectreops.core.audit import AuditLog
from spectreops.core.executor import Executor
from spectreops.core.tool_registry import Tool, ToolRegistry
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator, ScopeViolation


def _setup(tmp_path, mode="active", offline=True):
    reg = ToolRegistry()

    async def probe(args):
        return {"ok": True}

    reg.register(Tool(name="http_probe", description="p",
                      parameters={"type": "object"}, handler=probe,
                      danger="active"))
    validator = ScopeValidator(Policy(mode=mode, targets=["127.0.0.1"],
                                      offline=offline))
    return reg, validator, Executor(reg, validator, AuditLog(tmp_path / "a.jsonl"))


@pytest.mark.asyncio
async def test_llm_cannot_bypass_scope_via_arguments(tmp_path):
    """Even if a prompt-injected LLM tries an out-of-scope URL, the executor blocks it."""
    _, _, ex = _setup(tmp_path)
    res = await ex.run("http_probe", {"url": "http://169.254.169.254/latest/meta-data"})
    assert "scope violation" in res["error"]


@pytest.mark.asyncio
async def test_exploit_blocked_in_active_mode(tmp_path):
    reg = ToolRegistry()

    async def exploit(args):
        return {"pwned": True}

    reg.register(Tool(name="exploit_tool", description="e",
                      parameters={"type": "object"}, handler=exploit,
                      danger="exploit"))
    validator = ScopeValidator(Policy(mode="active", targets=["127.0.0.1"]))
    ex = Executor(reg, validator, AuditLog(tmp_path / "a.jsonl"))
    res = await ex.run("exploit_tool", {"url": "http://127.0.0.1/"})
    assert "scope violation" in res["error"]


def test_metadata_ip_never_in_scope(tmp_path):
    _, validator, _ = _setup(tmp_path)
    assert not validator.check_host("169.254.169.254")
