from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Policy:
    mode: str = "none"              # none | passive_only | active | full
    targets: list[str] = field(default_factory=list)      # hosts, CIDRs, URLs
    exclusions: list[str] = field(default_factory=list)
    rate_limit: float = 10.0        # requests/sec
    concurrency: int = 5
    require_approval_for: list[str] = field(
        default_factory=lambda: ["exploit", "destructive", "auth_bypass"])
    offline: bool = True

    @classmethod
    def from_config(cls, scope_cfg, runtime_cfg) -> Policy:
        return cls(mode=scope_cfg.mode, targets=list(scope_cfg.targets),
                   exclusions=list(scope_cfg.exclusions),
                   rate_limit=scope_cfg.rate_limit, concurrency=scope_cfg.concurrency,
                   require_approval_for=list(scope_cfg.require_approval_for),
                   offline=runtime_cfg.offline)
