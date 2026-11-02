from __future__ import annotations

import asyncio
import json
from typing import Any

from ..core.audit import AuditLog
from ..core.tool_registry import ToolRegistry
from ..scope.validator import ScopeValidator, ScopeViolation

HOST_KEYS = ("host", "target", "url", "domain", "hostname", "ip", "base_url")
DANGEROUS_TOOLS = {"exploit", "destructive"}


class Executor:
    """Validates, executes, times out, and audits every tool call."""

    def __init__(self, registry: ToolRegistry, validator: ScopeValidator,
                 audit: AuditLog, max_timeout: int = 600, max_retries: int = 2):
        self.registry = registry
        self.validator = validator
        self.audit = audit
        self.max_timeout = max_timeout
        self.max_retries = max_retries

    def _check_scope(self, tool_name: str, args: dict) -> None:
        for key in HOST_KEYS:
            val = args.get(key)
            if isinstance(val, str) and val:
                self.validator.check_url(val if "://" in val else f"http://{val}")
                self.validator.check_network_action(val, tool.danger
                                                    if (tool := self.registry.get(tool_name)) else "safe")

    async def run(self, name: str, arguments: str | dict) -> dict[str, Any]:
        tool = self.registry.get(name)
        if tool is None:
            return {"error": f"unknown tool: {name}"}
        args = json.loads(arguments) if isinstance(arguments, str) else arguments
        try:
            self._check_scope(name, args)
        except ScopeViolation as e:
            self.audit.record("tool_blocked", actor="executor", tool=name,
                              args=args, reason=str(e))
            return {"error": f"scope violation: {e}"}

        self.audit.record("tool_start", actor="executor", tool=name, args=args)
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                result = await asyncio.wait_for(tool.handler(args),
                                                timeout=self.max_timeout)
                self.audit.record("tool_end", actor="executor", tool=name,
                                  ok=True, attempt=attempt)
                return result
            except (asyncio.TimeoutError, Exception) as e:   # noqa: BLE001
                last_err = e
        self.audit.record("tool_end", actor="executor", tool=name, ok=False,
                          error=str(last_err))
        return {"error": f"tool '{name}' failed after retries: {last_err}"}
