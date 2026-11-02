# spectreops/cli/chat.py
from __future__ import annotations

from rich.console import Console

from ..core.memory import Memory

console = Console()


def repl(agent, memory: Memory) -> None:
    console.print("[bold cyan]SpectreOps REPL[/bold cyan] — type 'exit' to quit, "
                  "'findings' to list stored findings")
    while True:
        try:
            line = console.input("[bold green]spec> [/bold green]").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            break
        if line.lower() == "findings":
            for f in memory.findings():
                console.print(f"[{f['severity']}] {f['title']} ({f['confidence']}) — {f['target']}")
            continue
        reply = agent.step_sync(line) if hasattr(agent, "step_sync") else None
        if reply is None:
            import asyncio
            reply = asyncio.run(agent.step(line))
        console.print(reply)
