from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class LLMConfig(BaseModel):
    backend: Literal["ollama", "openai_compat"] = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5-coder:14b"
    small_model: str = "qwen2.5:7b"
    api_key_env: str = ""          # read from env, never stored in config
    temperature: float = 0.2
    max_context_tokens: int = 32768
    request_timeout: int = 300


class AgentConfig(BaseModel):
    autonomy: Literal["advisory", "supervised", "authorized"] = "supervised"
    max_tool_rounds: int = 40
    max_tool_timeout: int = 600
    max_retries: int = 2


class ScopeConfig(BaseModel):
    mode: Literal["none", "passive_only", "active", "full"] = "none"
    targets: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)
    rate_limit: float = 10.0
    concurrency: int = 5
    require_approval_for: list[str] = Field(
        default_factory=lambda: ["exploit", "destructive", "auth_bypass"]
    )


class RuntimeConfig(BaseModel):
    data_dir: Path = Path.home() / ".spectreops"
    sandbox: Literal["auto", "docker", "bwrap", "none"] = "auto"
    offline: bool = True
    redact_secrets: bool = True


class AuditConfig(BaseModel):
    enabled: bool = True
    hash_chain: bool = True


class AppConfig(BaseModel):
    llm: LLMConfig = LLMConfig()
    agent: AgentConfig = AgentConfig()
    scope: ScopeConfig = ScopeConfig()
    runtime: RuntimeConfig = RuntimeConfig()
    audit: AuditConfig = AuditConfig()
    raw: dict = Field(default_factory=dict, exclude=True)

    @field_validator("runtime")
    @classmethod
    def _expand(cls, v: RuntimeConfig) -> RuntimeConfig:
        v.data_dir = Path(os.path.expanduser(str(v.data_dir)))
        return v


def load_config(path: Path | None = None) -> AppConfig:
    """Load config from YAML, then environment overrides (SPECTREOPS_*)."""
    data: dict = {}
    if path and path.exists():
        data = yaml.safe_load(path.read_text()) or {}
    cfg = AppConfig.model_validate(data)
    # env overrides: SPECTREOPS_LLM_MODEL, SPECTREOPS_SCOPE_MODE, etc.
    prefix = "SPECTREOPS_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("__")
        section = getattr(cfg, parts[0], None)
        if section is not None and isinstance(section, BaseModel) and len(parts) == 2:
            field = section.model_fields.get(parts[1])
            if field:
                cast = {bool: lambda x: x.lower() in ("1", "true", "yes"),
                        int: int, float: float}.get(field.annotation, str)
                setattr(section, parts[1], cast(value))
    cfg.raw = data
    return cfg
