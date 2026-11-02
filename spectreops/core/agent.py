from __future__ import annotations

import json

from ..llm.base import LLMBackend, Message
from .context import compact
from .executor import Executor
from .tool_registry import ToolRegistry

SYSTEM_PROMPT = """You are SpectreOps, an autonomous cybersecurity assessment agent \
operating strictly within the operator-configured scope of an authorized engagement.

Rules:
- Only act on in-scope targets. If a tool returns a scope violation, do not retry it.
- Distinguish verified findings (tool evidence) from hypotheses. Never claim a \
vulnerability is confirmed without tool output backing it.
- Plan before acting; explain technical reasoning; state uncertainty explicitly.
- Prefer passive checks before active ones. Respect rate limits.
"""


class Agent:
    def __init__(self, llm: LLMBackend, registry: ToolRegistry, executor: Executor,
                 max_rounds: int = 40, model: str | None = None):
        self.llm = llm
        self.registry = registry
        self.executor = executor
        self.max_rounds = max_rounds
        self.model = model
        self.history: list[Message] = [Message(role="system", content=SYSTEM_PROMPT)]

    async def run(self, user_task: str) -> str:
        self.history.append(Message(role="user", content=user_task))
        schemas = self.registry.openai_schemas()
        for _ in range(self.max_rounds):
            self.history = compact(self.history)
            reply = await self.llm.chat(self.history, tools=schemas, model=self.model)
            if reply.tool_calls:
                self.history.append(reply)
                for call in reply.tool_calls:
                    fn = call.get("function", {})
                    result = await self.executor.run(fn.get("name", ""),
                                                     fn.get("arguments", "{}"))
                    self.history.append(Message(role="tool",
                                                content=json.dumps(result)[:8000],
                                                tool_call_id=call.get("id"),
                                                name=fn.get("name")))
                continue
            self.history.append(reply)
            return reply.content or ""
        return "[max rounds reached without final answer]"

    async def step(self, user_message: str) -> str:
        """Single-turn chat (no tool loop) for the interactive REPL."""
        self.history.append(Message(role="user", content=user_message))
        reply = await self.llm.chat(self.history,
                                    tools=self.registry.openai_schemas(),
                                    model=self.model)
        self.history.append(reply)
        if reply.tool_calls:
            results = []
            for call in reply.tool_calls:
                fn = call.get("function", {})
                res = await self.executor.run(fn.get("name", ""), fn.get("arguments", "{}"))
                results.append(json.dumps(res)[:8000])
                self.history.append(Message(role="tool", content=json.dumps(res)[:8000],
                                            tool_call_id=call.get("id"),
                                            name=fn.get("name")))
            follow = await self.llm.chat(self.history, model=self.model)
            self.history.append(follow)
            return (follow.content or "") + "\n[tool results]\n" + "\n".join(results)
        return reply.content or ""
