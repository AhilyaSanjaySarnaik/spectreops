import pytest

from spectreops.core.agent import Agent
from spectreops.core.audit import AuditLog
from spectreops.core.executor import Executor
from spectreops.core.tool_registry import Tool, ToolRegistry
from spectreops.llm.base import Message
from spectreops.scope.policy import Policy
from spectreops.scope.validator import ScopeValidator


class FakeLLM:
    """Scripted LLM: first call requests a tool, second call answers."""

    def __init__(self):
        self.calls = 0

    async def chat(self, messages, tools=None, model=None, temperature=None):
        self.calls += 1
        if self.calls == 1:
            return Message(role="assistant", content=None, tool_calls=[{
                "id": "c1", "type": "function",
                "function": {"name": "http_probe",
                             "arguments": '{"url": "http://127.0.0.1/"}'}}])
        return Message(role="assistant", content="Done: probe returned ok.")

    async def stream(self, messages, **kw):
        yield "stub"


@pytest.mark.asyncio
async def test_agent_loop_executes_tool(tmp_path):
    reg = ToolRegistry()

    async def probe(args):
        return {"status": 200, "ok": True}

    reg.register(Tool(name="http_probe", description="p",
                      parameters={"type": "object"}, handler=probe,
                      danger="active"))
    validator = ScopeValidator(Policy(mode="active", targets=["127.0.0.1"]))
    ex = Executor(reg, validator, AuditLog(tmp_path / "a.jsonl"))
    agent = Agent(FakeLLM(), reg, ex, max_rounds=5)
    answer = await agent.run("probe the target")
    assert "Done" in answer
