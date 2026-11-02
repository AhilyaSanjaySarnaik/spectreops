# spectreops/cli/main.py
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console

from ..core.agent import Agent
from ..core.audit import AuditLog
from ..core.executor import Executor
from ..core.memory import Memory
from ..core.tool_registry import ToolRegistry
from ..llm.openai_compat import OpenAICompatBackend
from ..scope.policy import Policy
from ..scope.validator import ScopeValidator
from ..tools.builtin.http_probe import TOOL as HTTP_PROBE, http_probe

app = typer.Typer(help="SpectreOps — local-first AI red-team agent")
console = Console()


def build(config_path: Path | None):
    from ..core.config import load_config
    cfg = load_config(config_path)
    policy = Policy.from_config(cfg.scope, cfg.runtime)
    validator = ScopeValidator(policy)
    audit = AuditLog(cfg.runtime.data_dir / "audit.jsonl", cfg.audit.hash_chain)
    memory = Memory(cfg.runtime.data_dir / "memory.db")
    registry = ToolRegistry()
    registry.register(__import__("spectreops.core.tool_registry", fromlist=["Tool"])
                      .Tool(name=HTTP_PROBE["name"], description=HTTP_PROBE["description"],
                            parameters=HTTP_PROBE["parameters"], handler=http_probe,
                            tags={"recon", "web"}, danger="active"))
    llm = OpenAICompatBackend(cfg.llm.base_url, cfg.llm.model,
                              cfg.llm.api_key_env, cfg.llm.temperature,
                              cfg.llm.request_timeout)
    executor = Executor(registry, validator, audit,
                        cfg.agent.max_tool_timeout, cfg.agent.max_retries)
    agent = Agent(llm, registry, executor, cfg.agent.max_tool_rounds, cfg.llm.model)
    return cfg, policy, validator, audit, memory, agent


@app.command()
def chat(config: Path = typer.Option(None, "--config", "-c")):
    """Interactive session with the agent."""
    from .chat import repl
    _, policy, _, audit, memory, agent = build(config)
    audit.record("session_start", actor="cli", mode=policy.mode)
    repl(agent, memory)


@app.command()
def run(task: str, config: Path = typer.Option(None, "--config", "-c")):
    """Run a one-shot assessment task."""
    _, policy, _, audit, _, agent = build(config)
    audit.record("run_start", actor="cli", mode=policy.mode, task=task)
    result = asyncio.run(agent.run(task))
    console.print(result)


@app.command()
def scope(config: Path = typer.Option(None, "--config", "-c")):
    """Show the active scope policy."""
    _, policy, validator, _, _, _ = build(config)
    console.print_json(json.dumps({
        "mode": policy.mode, "targets": policy.targets,
        "exclusions": policy.exclusions, "offline": policy.offline,
        "allowed_hosts": sorted(validator._allowed),
    }))


@app.command()
def verify_audit(config: Path = typer.Option(None, "--config", "-c")):
    """Verify the tamper-evidence hash chain of the audit log."""
    from ..core.config import load_config
    cfg = load_config(config)
    audit = AuditLog(cfg.runtime.data_dir / "audit.jsonl", cfg.audit.hash_chain)
    ok = audit.verify()
    console.print("[green]audit chain OK[/green]" if ok else "[red]AUDIT CHAIN BROKEN[/red]")
    raise typer.Exit(0 if ok else 1)


if __name__ == "__main__":
    app()
