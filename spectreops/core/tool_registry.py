from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

# Argument names that, by default, are treated as network targets and
# validated against scope before a tool runs.
DEFAULT_TARGET_KEYS: tuple[str, ...] = (
    "host", "target", "url", "domain", "hostname", "ip", "base_url")


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict                       # JSON schema
    handler: Callable[[dict], Awaitable[dict]]
    tags: set[str] = field(default_factory=set)   # e.g. {"recon","active"}
    danger: str = "safe"                   # safe | active | exploit | destructive
    # Which arguments name a network target. () = tool takes no network target.
    target_keys: tuple[str, ...] = DEFAULT_TARGET_KEYS
    # False for purely local tools (file scanners, finding recorders).
    network: bool = True
    # True when the executor cannot know where the tool will connect
    # (e.g. a shell). Such tools need scope mode 'full' plus operator approval.
    unscoped: bool = False
    # True when the tool contacts third-party services (not the target),
    # e.g. passive DNS/CT sources. Blocked when runtime.offline is true.
    third_party_egress: bool = False
    # Runs a standalone executable directly on the host, outside the Sandbox.
    host_subprocess: bool = False

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
        """Unchecked dispatch (no scope/approval). Use Executor.run for agent calls."""
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
