# spectreops/safety/approval.py
from __future__ import annotations

import sys
from collections.abc import Callable

DEFAULT_REQUIRED = {"exploit", "destructive", "auth_bypass", "shell"}


class ApprovalGate:
    """Confirmation gate for high-impact actions.

    always_yes  -> pre-authorized mode (autonomy: authorized)
    always_deny -> no human available; anything needing approval is refused
    prompt      -> injectable for tests / alternative UIs (defaults to input())
    """

    def __init__(self, always_yes: bool = False, required_tags: set[str] | None = None,
                 always_deny: bool = False,
                 prompt: Callable[[str], str] | None = None):
        if always_yes and always_deny:
            raise ValueError("always_yes and always_deny are mutually exclusive")
        self.always_yes = always_yes
        self.always_deny = always_deny
        self.required_tags = set(required_tags) if required_tags else set(DEFAULT_REQUIRED)
        self._prompt = prompt or input

    def requires_approval(self, tags: set[str], danger: str) -> bool:
        return danger in self.required_tags or bool(tags & self.required_tags)

    def confirm(self, description: str) -> bool:
        if self.always_deny:
            return False
        if self.always_yes:
            return True
        try:
            answer = self._prompt(f"\n[APPROVAL REQUIRED] {description}\nProceed? [y/N] ")
        except EOFError:
            print("non-interactive session: denying", file=sys.stderr)
            return False
        return answer.strip().lower() in ("y", "yes")
