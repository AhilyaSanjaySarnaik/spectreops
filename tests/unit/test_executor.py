import pytest

from spectreops.core.audit import AuditLog
from spectreops.core.executor import Executor
from spectreops.core.tool_registry import Tool, ToolRegistry
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator


@pytest.mark.asyncio
async def test_executor_blocks_out_of_scope(tmp_path):
    reg = ToolRegistry()

    async def probe(args):
        return {"ok": True}

    reg.register(Tool(name="http_probe", description="p",
                      parameters={"type": "object"}, handler=probe,
                      danger="active"))
    validator = ScopeValidator(Policy(mode="active", targets=["127.0.0.1"]))
    ex = Executor(reg, validator, AuditLog(tmp_path / "a.jsonl"))
    res = await ex.run("http_probe", {"url": "http://example.com/"})
    assert "scope violation" in res["error"]


@pytest.mark.asyncio
async def test_executor_allows_in_scope(tmp_path):
    reg = ToolRegistry()

    async def probe(args):
        return {"ok": True}

    reg.register(Tool(name="http_probe", description="p",
                      parameters={"type": "object"}, handler=probe,
                      danger="active"))
    validator = ScopeValidator(Policy(mode="active", targets=["127.0.0.1"]))
    ex = Executor(reg, validator, AuditLog(tmp_path / "a.jsonl"))
    res = await ex.run("http_probe", {"url": "http://127.0.0.1/x"})
    assert res == {"ok": True}
