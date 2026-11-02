# spectreops/cli/main.py
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ..core.agent import Agent
from ..core.audit import AuditLog
from ..core.auth import AuthStore
from ..core.config import AppConfig, load_config
from ..core.executor import Executor
from ..core.memory import Memory
from ..core.planner import Plan
from ..core.tool_registry import Tool, ToolRegistry
from ..llm.base import LLMBackend
from ..llm.ollama import OllamaBackend
from ..llm.openai_compat import OpenAICompatBackend
from ..safety.approval import ApprovalGate
from ..safety.sandbox import Sandbox
from ..scope.policy import Policy
from ..scope.validator import ScopeValidator
from ..tools.builtin import shell_tool
from ..tools.builtin.findings_tool import TOOL as FINDING_TOOL
from ..tools.builtin.findings_tool import make_record_finding
from ..tools.builtin.plan_tools import make_plan_tools
from ..tools.builtin.surface_tools import make_surface_tools
from ..tools.loader import register_all

app = typer.Typer(help="SpectreOps — local-first AI red-team agent", no_args_is_help=True)
console = Console()

ConfigOpt = typer.Option(None, "--config", "-c", help="YAML config file",
                         exists=True, dir_okay=False)


@dataclass
class Runtime:
    cfg: AppConfig
    policy: Policy
    validator: ScopeValidator
    audit: AuditLog
    memory: Memory
    registry: ToolRegistry
    executor: Executor
    agent: Agent
    plan: Plan
    plan_path: Path


def make_llm(cfg: AppConfig) -> LLMBackend:
    cls = OllamaBackend if cfg.llm.backend == "ollama" else OpenAICompatBackend
    return cls(cfg.llm.base_url, cfg.llm.model, cfg.llm.api_key_env,
               cfg.llm.temperature, cfg.llm.request_timeout)


def make_approval(cfg: AppConfig, yes: bool) -> ApprovalGate:
    required = set(cfg.scope.require_approval_for) | {"shell"}
    if cfg.agent.autonomy == "authorized" or yes:
        return ApprovalGate(always_yes=True, required_tags=required)
    return ApprovalGate(required_tags=required,
                        prompt=lambda q: console.input(f"[bold yellow]{q}[/]"))


def load_or_create_plan(path: Path | None, data_dir: Path, objective: str) -> tuple[Plan, Path]:
    if path is not None and path.exists():
        return Plan.load(path), path
    path = path or data_dir / "plans" / f"plan-{time.strftime('%Y%m%d-%H%M%S')}.json"
    return Plan(objective=objective), path


def build(config_path: Path | None, yes: bool = False, plan_path: Path | None = None,
          objective: str = "interactive session") -> Runtime:
    cfg = load_config(config_path)
    policy = Policy.from_config(cfg.scope, cfg.runtime)
    validator = ScopeValidator(policy)
    audit = AuditLog(cfg.runtime.data_dir / "audit.jsonl", cfg.audit.hash_chain)
    memory = Memory(cfg.runtime.data_dir / "memory.db")

    registry = ToolRegistry()
    register_all(registry)
    registry.register(Tool(
        name=FINDING_TOOL["name"], description=FINDING_TOOL["description"],
        parameters=FINDING_TOOL["parameters"], handler=make_record_finding(memory),
        tags={"reporting"}, danger="safe", target_keys=(), network=False))
    for spec, handler in make_surface_tools(memory):
        registry.register(Tool(
            name=spec["name"], description=spec["description"],
            parameters=spec["parameters"], handler=handler,
            tags={"surface"}, danger="safe", target_keys=(), network=False))
    shell_tool.configure(Sandbox(cfg.runtime.sandbox, timeout=cfg.agent.max_tool_timeout,
                                 network=cfg.runtime.sandbox_network))

    approval = make_approval(cfg, yes)
    auth = AuthStore.from_config(cfg.auth)
    for w in auth.warnings:
        audit.record("auth_warning", actor="cli", detail=w)
    plan, plan_path = load_or_create_plan(plan_path, cfg.runtime.data_dir, objective)
    for tool in make_plan_tools(plan, approval, policy.mode,
                                on_change=lambda p: p.save(plan_path), audit=audit):
        registry.register(tool)

    executor = Executor(registry, validator, audit,
                        cfg.agent.max_tool_timeout, cfg.agent.max_retries,
                        approval=approval, autonomy=cfg.agent.autonomy,
                        redact_secrets=cfg.runtime.redact_secrets, plan=plan, auth=auth,
                        allow_host_scanners=cfg.runtime.allow_host_scanners)
    agent = Agent(make_llm(cfg), registry, executor, cfg.agent.max_tool_rounds,
                  cfg.llm.model, plan=plan)
    return Runtime(cfg, policy, validator, audit, memory, registry, executor, agent,
                   plan, plan_path)


@app.command()
def chat(config: Path = ConfigOpt,
         plan: Path = typer.Option(None, "--plan", help="resume/save plan JSON")):
    """Interactive session with the agent."""
    from .chat import repl
    rt = build(config, plan_path=plan)
    rt.audit.record("session_start", actor="cli", mode=rt.policy.mode)
    repl(rt.agent, rt.memory)


@app.command()
def run(task: str,
        config: Path = ConfigOpt,
        yes: bool = typer.Option(False, "--yes", "-y",
                                 help="pre-approve actions that need confirmation"),
        plan: Path = typer.Option(None, "--plan",
                                  help="plan JSON to resume (created if missing)")):
    """Run a one-shot assessment task."""
    rt = build(config, yes, plan_path=plan, objective=task)
    rt.audit.record("run_start", actor="cli", mode=rt.policy.mode, task=task,
                    plan=str(rt.plan_path), phase=rt.plan.current_phase())
    try:
        result = asyncio.run(rt.agent.run(task))
    finally:
        rt.plan.save(rt.plan_path)
        rt.audit.record("run_end", actor="cli", phase=rt.plan.current_phase())
    console.print(result)
    console.print(f"[dim]plan saved to {rt.plan_path} (phase: "
                  f"{rt.plan.current_phase()}) — resume with --plan {rt.plan_path}[/dim]")


@app.command()
def scope(config: Path = ConfigOpt):
    """Show the active scope policy."""
    rt = build(config)
    console.print_json(json.dumps({
        "mode": rt.policy.mode, "targets": rt.policy.targets,
        "exclusions": rt.policy.exclusions, "offline": rt.policy.offline,
        "autonomy": rt.cfg.agent.autonomy, "profile": rt.policy.profile,
        "effective_rate": rt.executor.limiter.rate,
        "effective_concurrency": rt.executor.limiter.concurrency,
        "allowed_hosts": sorted(rt.validator._allowed),
    }))


@app.command()
def surfaces(config: Path = ConfigOpt,
             status: str = typer.Option(None, "--status", "-s",
                                        help="new | in_progress | tested | skipped")):
    """List discovered attack surfaces (endpoints) and their queue status."""
    rt = build(config)
    rows = rt.memory.surfaces(status)
    if not rows:
        console.print("no surfaces recorded yet")
        return
    t = Table("id", "status", "method", "url", "source")
    for s in rows:
        t.add_row(str(s["id"]), s["status"], s["method"], s["url"], s["source"])
    console.print(t)


@app.command()
def auth(config: Path = ConfigOpt):
    """Show configured auth identities and the hosts they cover (never the values)."""
    rt = build(config)
    store = rt.executor.auth
    if not store.identities:
        console.print("no auth identities configured")
    else:
        t = Table("identity", "active", "hosts", "kinds")
        for name in store.names():
            ident = store.identities[name]
            hosts = sorted(ident._creds)
            kinds = sorted({c.kind for c in ident._creds.values()})
            t.add_row(name, "✓" if name == store.active else "",
                      ", ".join(hosts), ", ".join(kinds))
        console.print(t)
    for w in store.warnings:
        console.print(f"[yellow]warning:[/yellow] {w}")


@app.command()
def tools(config: Path = ConfigOpt):
    """List registered tools and whether each can run under the current scope."""
    from ..scope.validator import ScopeViolation
    from ..tools.base import missing_binary
    rt = build(config)
    t = Table("tool", "danger", "runs in this scope?", "notes")
    for tool in rt.registry.all():
        try:
            rt.executor._check_scope(tool, {})
            allowed = "[green]yes[/]"
        except ScopeViolation as e:
            allowed = f"[red]no[/] — {e}"
        note = missing_binary(tool.name) or ""
        if tool.unscoped:
            note = (note + " approval every call").strip()
        t.add_row(tool.name, tool.danger, allowed, note)
    console.print(t)


@app.command()
def findings(config: Path = ConfigOpt,
             severity: str = typer.Option(None, "--severity", "-s")):
    """List findings recorded during engagements."""
    rt = build(config)
    rows = rt.memory.findings(severity)
    if not rows:
        console.print("no findings recorded yet")
        return
    t = Table("id", "severity", "confidence", "title", "target")
    for f in rows:
        t.add_row(str(f["id"]), f["severity"], f["confidence"], f["title"], f["target"])
    console.print(t)


@app.command()
def report(output: Path = typer.Argument(..., help="report.md | .json | .sarif | .html"),
           config: Path = ConfigOpt):
    """Export recorded findings. Format is chosen from the file extension."""
    from ..reporting.exporters import export_html, export_json, export_sarif
    from ..reporting.findings import export_markdown, from_memory
    rt = build(config)
    items = from_memory(rt.memory.findings())
    exporters = {".md": export_markdown, ".json": export_json,
                 ".sarif": export_sarif, ".html": export_html}
    fn = exporters.get(output.suffix.lower())
    if fn is None:
        raise typer.BadParameter(f"unsupported extension; use one of {sorted(exporters)}")
    fn(items, str(output))
    rt.audit.record("report_export", actor="cli", path=str(output), count=len(items))
    console.print(f"[green]wrote {len(items)} finding(s) to {output}[/green]")


@app.command()
def verify_audit(config: Path = ConfigOpt):
    """Verify the tamper-evidence hash chain of the audit log."""
    cfg = load_config(config)
    audit = AuditLog(cfg.runtime.data_dir / "audit.jsonl", cfg.audit.hash_chain)
    ok = audit.verify()
    console.print("[green]audit chain OK[/green]" if ok else "[red]AUDIT CHAIN BROKEN[/red]")
    raise typer.Exit(0 if ok else 1)


@app.command()
def dashboard(config: Path = ConfigOpt, port: int = 8765):
    """Serve the read-only dashboard on 127.0.0.1."""
    from ..dashboard.app import serve
    cfg = load_config(config)
    serve(str(cfg.runtime.data_dir), port)


if __name__ == "__main__":
    app()
