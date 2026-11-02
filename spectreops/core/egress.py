"""Per-tool engagement scope context for outbound HTTP preflight checks.

This is an additional application-layer guard, not a connection firewall.
Network destinations must also be restricted at the socket/container boundary.
"""
from __future__ import annotations

from contextvars import ContextVar

from ..scope.validator import ScopeValidator

_scope: ContextVar[ScopeValidator | None] = ContextVar("spectreops_scope", default=None)


def use_scope(validator: ScopeValidator):
    return _scope.set(validator)


def reset_scope(token) -> None:
    _scope.reset(token)


def check_http_url(url: str) -> None:
    validator = _scope.get()
    if validator is None:
        # Direct tool helpers stay available, while Executor-managed calls are checked.
        return
    validator.check_url(url)
    validator.check_live_dns(url)
