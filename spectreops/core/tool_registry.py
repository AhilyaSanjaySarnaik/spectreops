from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict                       # JSON schema
    handler: Callable[[dict], Awaitable[dict]]
    tags: set[str] = field(default_factory=set)   # e.g. {"recon","active"}
    danger: str = "safe"                   # safe | active | exploit | destructive

    def openai_schema(self) -> dict:
        return {"type": "function",
                "function": {"name": self.name, "description": self.description,
                             "parameters": self.parameters}}


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def openai_schemas(self, allowed: set[str] | None = None) -> list[dict]:
        tools = [t for t in self._tools.values()
                 if allowed is None or t.name in allowed]
        return [t.openai_schema() for t in tools]

    async def dispatch(self, name: str, arguments: str | dict) -> dict:
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"unknown tool: {name}"}
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
        except json.JSONDecodeError as e:
            return {"error": f"invalid tool arguments JSON: {e}"}
        try:
            return await tool.handler(args)
        except Exception as e:                       # noqa: BLE001 - report to LLM
            return {"error": f"{type(e).__name__}: {e}"}
