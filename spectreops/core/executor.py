from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from ..core.audit import AuditLog
from ..core.auth import AuthStore, reset_auth, use_auth
from ..core.egress import reset_scope, use_scope
from ..core.profile import get_profile, reset_profile, use_profile
from ..core.rate_limit import RateLimiter, reset_limiter, use_limiter
from ..core.tool_registry import Tool, ToolRegistry
from ..safety.approval import ApprovalGate
from ..safety.injection_guard import scrub_tool_output
from ..safety.secrets import redact
from ..scope.validator import ScopeValidator, ScopeViolation

# Only these are worth retrying; a timeout on a 10-minute scan or a tool bug is not.
TRANSIENT_ERRORS = (httpx.TransportError, ConnectionError)
NO_RETRY_DANGER = {"exploit", "destructive"}
_SENSITIVE_KEYS = {"authorization", "cookie", "password", "token", "api_key",
                   "apikey", "secret", "x-api-key"}


def _iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


class Executor:
    """Single choke point for every tool call the model makes.

    Order of checks: tool exists -> args parse -> autonomy -> scope mode vs
    danger -> every target argument and every embedded URL in scope ->
    operator approval -> run with timeout -> scrub + redact output -> audit.
    """

    def __init__(self, registry: ToolRegistry, validator: ScopeValidator,
                 audit: AuditLog, max_timeout: int = 600, max_retries: int = 2,
                 approval: ApprovalGate | None = None, autonomy: str = "supervised",
                 redact_secrets: bool = True, limiter: RateLimiter | None = None,
                 plan=None, auth: AuthStore | None = None,
                 allow_host_scanners: bool = False):
        self.registry = registry
        self.validator = validator
        self.audit = audit
        self.max_timeout = max_timeout
        self.max_retries = max_retries
        # No gate supplied = deny anything that would need approval.
        self.approval = approval or ApprovalGate(always_deny=True)
        self.autonomy = autonomy
        self.redact_secrets = redact_secrets
        # When a Plan is attached, exploit/destructive tools only run in its exploit phase.
        self.plan = plan
        pol = validator.policy
        self.profile = get_profile(getattr(pol, "profile", "normal"))
        # the noise profile can lower (never raise) the policy's rate/concurrency
        self.limiter = limiter or RateLimiter(
            self.profile.cap_rate(getattr(pol, "rate_limit", 10.0)),
            self.profile.cap_concurrency(getattr(pol, "concurrency", 5)))
        self.auth = auth or AuthStore.empty()
        self.allow_host_scanners = allow_host_scanners

    # ------------------------------------------------------------------ checks
    def _check_scope(self, tool: Tool, args: dict) -> None:
        if not tool.network:
            if tool.host_subprocess and not self.allow_host_scanners:
                raise ScopeViolation(
                    f"{tool.name} runs on the host: set runtime.allow_host_scanners "
                    "explicitly to accept unisolated execution"
                )
            return
        self.validator.check_action(tool.danger)
        if tool.third_party_egress and self.validator.policy.offline:
            raise ScopeViolation(f"'{tool.name}' contacts third-party services; "
                                 "disabled while runtime.offline is true")
        if tool.host_subprocess and not self.allow_host_scanners:
            raise ScopeViolation(
                f"{tool.name} runs on the host: set runtime.allow_host_scanners "
                "explicitly to accept unisolated execution"
            )
        if tool.unscoped:
            if self.validator.policy.mode != "full":
                raise ScopeViolation(
                    f"'{tool.name}' can reach arbitrary hosts; requires scope mode 'full'")
            return
        for key in tool.target_keys:
            val = args.get(key)
            if val is None:
                continue
            if not isinstance(val, str):
                raise ScopeViolation(f"argument '{key}' must be a string")
            self.validator.check_target(val)
        # Defence in depth: any URL smuggled into another argument must be in scope.
        for s in _iter_strings(args):
            if "://" in s:
                for token in s.split():
                    if "://" in token:
                        self.validator.check_url(token)

    def _check_phase(self, tool: Tool) -> None:
        if self.plan is None or tool.danger not in NO_RETRY_DANGER:
            return
        if self.plan.current_phase() != "exploit":
            raise ScopeViolation(
                f"'{tool.name}' is {tool.danger}-level; only allowed in the 'exploit' "
                f"phase (current: '{self.plan.current_phase()}')")

    def _needs_approval(self, tool: Tool) -> bool:
        return (tool.unscoped or tool.host_subprocess
                or self.approval.requires_approval(tool.tags, tool.danger))

    # --------------------------------------------------------------- sanitise
    def _sanitize(self, result: Any) -> Any:
        """Scrub prompt-injection text and redact secrets from tool output."""
        warnings: list[str] = []

        def clean(obj: Any) -> Any:
            if isinstance(obj, str):
                text, detected = scrub_tool_output(obj)
                warnings.extend(detected)
                return redact(text) if self.redact_secrets else text
            if isinstance(obj, dict):
                return {k: clean(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [clean(v) for v in obj]
            return obj

        out = clean(result)
        if warnings and isinstance(out, dict):
            out["_injection_warnings"] = sorted(set(warnings))
        return out

    def _audit_args(self, args: dict) -> Any:
        if not self.redact_secrets:
            return args

        def walk(obj: Any) -> Any:
            if isinstance(obj, str):
                return redact(obj)
            if isinstance(obj, dict):
                return {k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else walk(v))
                        for k, v in obj.items()}
            if isinstance(obj, list):
                return [walk(v) for v in obj]
            return obj
        return walk(args)

    # -------------------------------------------------------------------- run
    async def run(self, name: str, arguments: str | dict) -> dict[str, Any]:
        tool = self.registry.get(name)
        if tool is None:
            return {"error": f"unknown tool: {name}"}
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
        except json.JSONDecodeError as e:
            return {"error": f"invalid tool arguments JSON: {e}"}
        if not isinstance(args, dict):
            return {"error": "tool arguments must be a JSON object"}
        logged = self._audit_args(args)

        if self.autonomy == "advisory" and (tool.network and tool.danger != "safe"
                                            or tool.unscoped):
            self.audit.record("tool_blocked", actor="executor", tool=name,
                              args=logged, reason="advisory mode")
            return {"error": "advisory mode: only passive tools may run; "
                             "describe the next step for the operator instead"}
        try:
            self._check_scope(tool, args)
            self._check_phase(tool)
        except ScopeViolation as e:
            self.audit.record("tool_blocked", actor="executor", tool=name,
                              args=logged, reason=str(e))
            return {"error": f"scope violation: {e}"}

        if self._needs_approval(tool):
            ok = self.approval.confirm(
                f"{tool.name} [{tool.danger}] {json.dumps(logged)[:500]}")
            self.audit.record("approval", actor="operator", tool=name,
                              args=logged, granted=ok)
            if not ok:
                return {"error": "operator denied this action"}

        self.audit.record("tool_start", actor="executor", tool=name, args=logged)
        retries = 0 if tool.danger in NO_RETRY_DANGER else self.max_retries
        last_err: BaseException | None = None
        for attempt in range(retries + 1):
            try:
                tokens = ([use_limiter(self.limiter), use_auth(self.auth),
                           use_profile(self.profile), use_scope(self.validator)]
                          if tool.network else [])
                try:
                    result = await asyncio.wait_for(tool.handler(args),
                                                    timeout=self.max_timeout)
                finally:
                    if tokens:
                        reset_scope(tokens[3])
                        reset_profile(tokens[2])
                        reset_auth(tokens[1])
                        reset_limiter(tokens[0])
                self.audit.record("tool_end", actor="executor", tool=name,
                                  ok=True, attempt=attempt)
                return self._sanitize(result)
            except ScopeViolation as e:
                self.audit.record("tool_blocked", actor="executor", tool=name,
                                  args=logged, reason=str(e))
                return {"error": f"scope violation: {e}"}
            except TRANSIENT_ERRORS as e:
                last_err = e
                await asyncio.sleep(min(2 ** attempt, 10))
            except TimeoutError:
                last_err = TimeoutError(f"timed out after {self.max_timeout}s")
                break
            except Exception as e:   # noqa: BLE001 - surface tool bugs to the LLM
                last_err = e
                break
        err = f"{type(last_err).__name__}: {last_err}"
        self.audit.record("tool_end", actor="executor", tool=name, ok=False, error=err)
        return {"error": f"tool '{name}' failed: {self._sanitize(err)}"}
