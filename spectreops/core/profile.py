"""Engagement noise profile — how loud/detectable the agent is allowed to be.

The default was criticised as too noisy (nmap in particular fired version
detection across 1000 ports on every scan). This introduces three profiles that
tune aggressiveness across tools from one setting:

- stealth: minimal footprint — low request rate, single-threaded, nmap top-50
  ports with slow timing and no version detection.
- normal (default): quiet-by-default — nmap top-100 ports, no version detection
  unless asked, modest concurrency. No artificial rate cap beyond scope.rate_limit.
- loud: full speed for lab/CTF use — faster timing, version detection on.

The active profile is installed into a ContextVar by the Executor (like the rate
limiter), so any tool can read it. nmap uses it today; others can adopt it.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class NoiseProfile:
    name: str
    nmap_timing: str            # -T0..-T5
    nmap_top_ports: int         # default port breadth when the model gives none
    service_detection: bool     # whether -sV is on by default
    max_rate: float             # requests/sec cap (0 = no extra cap)
    max_concurrency: int        # in-flight cap

    def cap_rate(self, policy_rate: float) -> float:
        if self.max_rate <= 0:
            return policy_rate
        if policy_rate <= 0:
            return self.max_rate
        return min(policy_rate, self.max_rate)

    def cap_concurrency(self, policy_concurrency: int) -> int:
        return max(1, min(policy_concurrency, self.max_concurrency))


PROFILES = {
    "stealth": NoiseProfile("stealth", nmap_timing="-T2", nmap_top_ports=50,
                            service_detection=False, max_rate=2.0, max_concurrency=1),
    "normal": NoiseProfile("normal", nmap_timing="-T3", nmap_top_ports=100,
                           service_detection=False, max_rate=0.0, max_concurrency=16),
    "loud": NoiseProfile("loud", nmap_timing="-T4", nmap_top_ports=1000,
                         service_detection=True, max_rate=0.0, max_concurrency=64),
}
DEFAULT = PROFILES["normal"]


def get_profile(name: str) -> NoiseProfile:
    return PROFILES.get(name, DEFAULT)


_current: ContextVar[NoiseProfile] = ContextVar("spectreops_profile", default=DEFAULT)


def current_profile() -> NoiseProfile:
    return _current.get()


def use_profile(profile: NoiseProfile):
    return _current.set(profile)


def reset_profile(token) -> None:
    _current.reset(token)
