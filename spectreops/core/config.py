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
    profile: Literal["stealth", "normal", "loud"] = "normal"  # noise/aggressiveness
    rate_limit: float = 10.0
    concurrency: int = 5
    require_approval_for: list[str] = Field(
        default_factory=lambda: ["exploit", "destructive", "auth_bypass"]
    )


class RuntimeConfig(BaseModel):
    data_dir: Path = Path.home() / ".spectreops"
    sandbox: Literal["auto", "docker", "bwrap", "none"] = "auto"
    sandbox_network: Literal["host", "none"] = "none"
    offline: bool = True
    redact_secrets: bool = True
    # Dangerous escape hatch: scanners have no network namespace containment yet.
    allow_host_scanners: bool = False


class AuditConfig(BaseModel):
    enabled: bool = True
    hash_chain: bool = True


class AuthConfig(BaseModel):
    # identities: name -> { "host[:port]": {kind, token_env|value_env|secret, header?} }
    # Raw secrets are NEVER stored here — only the env var / secret-store name.
    identities: dict[str, dict[str, dict]] = Field(default_factory=dict)
    active: str = ""           # default identity to use when a tool names none


class AppConfig(BaseModel):
    llm: LLMConfig = LLMConfig()
    agent: AgentConfig = AgentConfig()
    scope: ScopeConfig = ScopeConfig()
    runtime: RuntimeConfig = RuntimeConfig()
    audit: AuditConfig = AuditConfig()
    auth: AuthConfig = AuthConfig()
    raw: dict = Field(default_factory=dict, exclude=True)

    @field_validator("runtime")
    @classmethod
    def _expand(cls, v: RuntimeConfig) -> RuntimeConfig:
        v.data_dir = Path(os.path.expanduser(str(v.data_dir)))
        return v


def load_config(path: Path | None = None) -> AppConfig:
    """Load config from YAML, then environment overrides.

    Overrides use a double underscore between section and field, e.g.
    ``SPECTREOPS_LLM__MODEL=qwen2.5-coder:7b`` or ``SPECTREOPS_SCOPE__MODE=active``.
    They are merged *before* validation, so invalid values are rejected.
    """
    data: dict = {}
    if path is not None:
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        data = yaml.safe_load(path.read_text()) or {}
    merged = {k: dict(v) if isinstance(v, dict) else v for k, v in data.items()}
    prefix = "SPECTREOPS_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("__")
        if len(parts) != 2 or parts[0] not in AppConfig.model_fields:
            continue
        section = merged.setdefault(parts[0], {})
        if isinstance(section, dict):
            # lists (targets, exclusions) may be given as comma-separated values
            field = AppConfig.model_fields[parts[0]].annotation.model_fields.get(parts[1])
            if field is not None and getattr(field.annotation, "__origin__", None) is list:
                section[parts[1]] = [v.strip() for v in value.split(",") if v.strip()]
            else:
                section[parts[1]] = value
    cfg = AppConfig.model_validate(merged)
    cfg.raw = data
    return cfg
