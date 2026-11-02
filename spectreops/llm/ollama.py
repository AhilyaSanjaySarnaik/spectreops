# spectreops/llm/base.py
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator


@dataclass
class Message:
    role: str                       # system | user | assistant | tool
    content: str | None = None
    tool_calls: list[dict] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_wire(self) -> dict:
        d: dict[str, Any] = {"role": self.role}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.name:
            d["name"] = self.name
        return d


class LLMError(Exception):
    pass


class LLMBackend(ABC):
    @abstractmethod
    async def chat(self, messages: list[Message], tools: list[dict] | None = None,
                   model: str | None = None, temperature: float | None = None,
                   ) -> Message:
        """One completion round. Tool calls returned in Message.tool_calls."""

    @abstractmethod
    async def stream(self, messages: list[Message], **kw) -> AsyncIterator[str]:
        ...
