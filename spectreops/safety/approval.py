# spectreops/safety/approval.py
from __future__ import annotations

import sys


class ApprovalGate:
    """Confirmation gate for high-impact actions. `yes` flag = pre-authorized mode."""

    def __init__(self, always_yes: bool = False, required_tags: set[str] | None = None):
        self.always_yes = always_yes
        self.required_tags = required_tags or {"exploit", "destructive", "auth_bypass"}

    def requires_approval(self, tags: set[str], danger: str) -> bool:
        return danger in self.required_tags or bool(tags & self.required_tags)

    def confirm(self, description: str) -> bool:
        if self.always_yes:
            return True
        try:
            answer = input(f"\n[APPROVAL REQUIRED] {description}\nProceed? [y/N] ")
        except EOFError:
            print("non-interactive session: denying", file=sys.stderr)
            return False
        return answer.strip().lower() in ("y", "yes")
