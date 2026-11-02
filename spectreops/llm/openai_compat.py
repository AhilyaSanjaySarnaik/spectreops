# spectreops/llm/openai_compat.py — covers Ollama, llama.cpp, vLLM, LM Studio
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from .base import LLMBackend, LLMError, Message


class OpenAICompatBackend(LLMBackend):
    def __init__(self, base_url: str, model: str, api_key_env: str = "",
                 temperature: float = 0.2, timeout: int = 300):
        import os
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        headers = {"Content-Type": "application/json"}
        if api_key_env:
            key = os.environ.get(api_key_env, "")
            if key:
                headers["Authorization"] = f"Bearer {key}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url, headers=headers, timeout=timeout)

    async def chat(self, messages, tools=None, model=None, temperature=None):
        payload: dict[str, Any] = {
            "model": model or self.model,
            "messages": [m.to_wire() for m in messages],
            "temperature": temperature if temperature is not None else self.temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        resp = await self._client.post("/v1/chat/completions", json=payload)
        if resp.status_code != 200:
            raise LLMError(f"LLM backend {resp.status_code}: {resp.text[:500]}")
        choice = resp.json()["choices"][0]
        msg = choice["message"]
        return Message(
            role="assistant",
            content=msg.get("content"),
            tool_calls=msg.get("tool_calls") or [],
        )

    async def stream(self, messages, model=None, temperature=None) -> AsyncIterator[str]:
        payload = {
            "model": model or self.model,
            "messages": [m.to_wire() for m in messages],
            "temperature": temperature if temperature is not None else self.temperature,
            "stream": True,
        }
        async with self._client.stream("POST", "/v1/chat/completions", json=payload) as r:
            if r.status_code != 200:
                raise LLMError(f"stream error {r.status_code}")
            async for line in r.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data == "[DONE]":
                    break
                delta = json.loads(data)["choices"][0].get("delta", {})
                if delta.get("content"):
                    yield delta["content"]
