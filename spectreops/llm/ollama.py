# spectreops/llm/ollama.py
"""Ollama backend.

Ollama exposes an OpenAI-compatible ``/v1/chat/completions`` endpoint, so this
is a thin subclass that only changes defaults. Kept as its own class so
Ollama-specific options (keep_alive, num_ctx, ...) have an obvious home.
"""
from __future__ import annotations

from .openai_compat import OpenAICompatBackend


class OllamaBackend(OpenAICompatBackend):
    def __init__(self, base_url: str = "http://127.0.0.1:11434",
                 model: str = "qwen2.5-coder:7b", api_key_env: str = "",
                 temperature: float = 0.2, timeout: int = 300):
        super().__init__(base_url, model, api_key_env, temperature, timeout)
