from __future__ import annotations

import json
from dataclasses import dataclass, field

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
        self.tasks[phase][index]["done"] = True

    def advance(self) -> str | None:
        if self.current < len(self.phases) - 1:
            self.current += 1
            return self.current_phase()
        return None

    def to_json(self) -> str:
        return json.dumps({"objective": self.objective, "phases": self.phases,
                           "current": self.current, "tasks": self.tasks})

    @classmethod
    def from_json(cls, raw: str) -> "Plan":
        d = json.loads(raw)
        p = cls(objective=d["objective"], phases=d["phases"], current=d["current"])
        p.tasks = d.get("tasks", {})
        return p
