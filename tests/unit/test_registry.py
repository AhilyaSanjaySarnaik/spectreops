# tests/unit/test_registry.py
import json
import pytest
from spectreops.core.tool_registry import Tool, ToolRegistry


@pytest.mark.asyncio
async def test_dispatch_and_errors():
    reg = ToolRegistry()

    async def handler(args):
        return {"echo": args["x"]}

    reg.register(Tool(name="echo", description="echo", parameters={"type": "object"},
                      handler=handler))
    assert (await reg.dispatch("echo", '{"x": 1}')) == {"echo": 1}
    assert "error" in await reg.dispatch("nope", "{}")
    assert "error" in await reg.dispatch("echo", "not json")
    assert reg.openai_schemas()[0]["function"]["name"] == "echo"
