# spectreops/cli/chat.py
from __future__ import annotations

import asyncio

from rich.console import Console

from ..core.memory import Memory

console = Console()


def repl(agent, memory: Memory) -> None:
    console.print("[bold cyan]SpectreOps REPL[/bold cyan] — type 'exit' to quit, "
                  "'findings' to list stored findings")
    # One event loop for the whole session: the LLM's HTTP client is bound to
    # the loop it was first used on, so asyncio.run() per message breaks turn 2.
    with asyncio.Runner() as runner:
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
                    console.print(f"[{f['severity']}] {f['title']} "
                                  f"({f['confidence']}) — {f['target']}")
                continue
            try:
                reply = runner.run(agent.step(line))
            except Exception as e:   # noqa: BLE001 - keep the session alive
                console.print(f"[red]error:[/red] {e}")
                continue
            console.print(reply)
