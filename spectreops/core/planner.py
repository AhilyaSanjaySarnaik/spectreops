from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

PHASES = ["recon", "collect", "test", "exploit", "report"]


@dataclass
class Plan:
    objective: str
    phases: list[str] = field(default_factory=lambda: list(PHASES))
    current: int = 0
    tasks: dict[str, list[dict]] = field(default_factory=dict)

    def current_phase(self) -> str:
        return self.phases[self.current]

    def add_task(self, phase: str, description: str) -> None:
        self.tasks.setdefault(phase, []).append({"task": description, "done": False})

    def complete_task(self, phase: str, index: int) -> None:
        tasks = self.tasks.get(phase, [])
        if not 0 <= index < len(tasks):
            raise IndexError(f"no task #{index} in phase '{phase}'")
        tasks[index]["done"] = True

    def next_phase(self) -> str | None:
        return self.phases[self.current + 1] if self.current < len(self.phases) - 1 else None

    def open_tasks(self, phase: str | None = None) -> list[dict]:
        return [t for t in self.tasks.get(phase or self.current_phase(), []) if not t["done"]]

    def advance(self) -> str | None:
        if self.current < len(self.phases) - 1:
            self.current += 1
            return self.current_phase()
        return None

    def to_json(self) -> str:
        return json.dumps({"objective": self.objective, "phases": self.phases,
                           "current": self.current, "tasks": self.tasks})

    def save(self, path: Path | str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(self.to_json())
        tmp.replace(p)                 # atomic: a crash never leaves a half-written plan
        return p

    @classmethod
    def load(cls, path: Path | str) -> Plan:
        return cls.from_json(Path(path).read_text())

    @classmethod
    def from_json(cls, raw: str) -> Plan:
        d = json.loads(raw)
        p = cls(objective=d["objective"], phases=d["phases"], current=d["current"])
        p.tasks = d.get("tasks", {})
        return p
