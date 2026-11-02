from __future__ import annotations

import fnmatch
import ipaddress
import socket
from urllib.parse import urlparse


class ScopeViolation(Exception):
    pass


def _expand_to_hosts(target: str) -> set[str]:
    """Return the set of hostnames/IPs a target covers."""
    out: set[str] = set()
    t = target.strip()
    if "/" in t and not t.startswith("http"):
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses <= 4096:
                out.update(str(ip) for ip in net.hosts())
            return out
        except ValueError:
            pass
    host = urlparse(t).hostname if "://" in t else t.split("/")[0]
    if host:
        out.add(host.lower())
        try:
            out.update(a[4][0] for a in socket.getaddrinfo(host, None))
        except socket.gaierror:
            pass
    return out


class ScopeValidator:
    def __init__(self, policy):
        self.policy = policy
        self._allowed: set[str] = set()
        self._denied_patterns: list[str] = list(policy.exclusions)
        for t in policy.targets:
            self._allowed |= _expand_to_hosts(t)

    def check_host(self, host: str) -> bool:
        """True if host is in scope and not excluded."""
        h = host.lower().strip()
        if any(fnmatch.fnmatch(h, pat) for pat in self._denied_patterns):
            return False
        if h in self._allowed:
            return True
        # IP literal may be a resolved address of an allowed target
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            return False
        for allowed in self._allowed:
            try:
                if ipaddress.ip_address(allowed) == ip:
                    return True
            except ValueError:
                continue
        return False

    def check_url(self, url: str) -> None:
        host = urlparse(url).hostname
        if not host or not self.check_host(host):
            raise ScopeViolation(f"URL out of scope: {url}")

    def check_network_action(self, host: str, action: str) -> None:
        """Validate an outbound action against policy mode."""
        if self.policy.mode == "none":
            raise ScopeViolation("scope mode 'none': no network actions permitted")
        if self.policy.offline and host not in self._allowed:
            # offline mode forbids egress to anything but in-scope targets
            if not self.check_host(host):
                raise ScopeViolation(f"offline mode: egress to {host} denied")
        if action in ("exploit", "destructive") and self.policy.mode != "full":
            raise ScopeViolation(f"action '{action}' requires scope mode 'full'")
