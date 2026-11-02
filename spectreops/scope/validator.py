from __future__ import annotations

import fnmatch
import ipaddress
import socket
from urllib.parse import urlparse


class ScopeViolation(Exception):
    pass


# How intrusive a tool is, and the most intrusive level each scope mode permits.
DANGER_RANK = {"safe": 0, "active": 1, "exploit": 2, "destructive": 2}
MODE_CEILING = {"none": -1, "passive_only": 0, "active": 1, "full": 2}

MAX_CIDR_ADDRESSES = 4096


def _expand_to_hosts(target: str) -> set[str]:
    """Return the set of hostnames/IPs a target covers."""
    out: set[str] = set()
    t = target.strip()
    if "/" in t and "://" not in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses > MAX_CIDR_ADDRESSES:
                raise ValueError(f"scope target {t} is larger than "
                                 f"{MAX_CIDR_ADDRESSES} addresses; split it up")
            out.update(str(ip) for ip in net)
            return out
        except ValueError as e:
            if "larger than" in str(e):
                raise
    host = host_of(t)
    if host:
        out.add(host.lower())
        try:
            out.update(a[4][0] for a in socket.getaddrinfo(host, None))
        except socket.gaierror:
            pass
    return out


def host_of(value: str) -> str | None:
    """Extract the hostname/IP from a URL, host:port, or bare host string."""
    v = value.strip()
    try:                                  # bare IP literal, incl. IPv6 "::1"
        return str(ipaddress.ip_address(v.strip("[]")))
    except ValueError:
        pass
    try:
        if "://" in v:
            return urlparse(v).hostname
        return urlparse(f"//{v.split('/')[0]}").hostname
    except ValueError:
        return None


class ScopeValidator:
    def __init__(self, policy):
        self.policy = policy
        self._allowed: set[str] = set()
        self._denied_patterns: list[str] = list(policy.exclusions)
        for t in policy.targets:
            self._allowed |= _expand_to_hosts(t)

    # ---- host level -------------------------------------------------------
    def _excluded(self, h: str) -> bool:
        for pat in self._denied_patterns:
            if fnmatch.fnmatch(h, pat.lower()):
                return True
            try:   # CIDR exclusions, e.g. "10.0.0.0/28"
                if ipaddress.ip_address(h) in ipaddress.ip_network(pat, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def check_host(self, host: str) -> bool:
        """True if host is in scope and not excluded."""
        h = host.lower().strip().strip("[]")
        if not h or self._excluded(h):
            return False
        if h in self._allowed:
            return True
        try:   # normalise IP spellings (e.g. IPv6 forms) before comparing
            ip = ipaddress.ip_address(h)
        except ValueError:
            return False
        return any(_same_ip(a, ip) for a in self._allowed)

    # ---- argument level ---------------------------------------------------
    def check_target(self, value: str) -> None:
        """Validate a tool argument naming a network target (URL, host, IP or CIDR)."""
        v = value.strip()
        if not v or any(c.isspace() for c in v) or "," in v:
            raise ScopeViolation(f"target must be a single host/URL: {value!r}")
        if "/" in v and "://" not in v:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if net.num_addresses > MAX_CIDR_ADDRESSES:
                    raise ScopeViolation(f"CIDR too large: {v}")
                bad = [str(ip) for ip in net if not self.check_host(str(ip))]
                if bad:
                    raise ScopeViolation(f"CIDR {v} includes out-of-scope hosts "
                                         f"(e.g. {bad[0]})")
                return
        host = host_of(v)
        if not host or not self.check_host(host):
            raise ScopeViolation(f"target out of scope: {value}")

    def check_url(self, url: str) -> None:
        host = urlparse(url).hostname
        if not host or not self.check_host(host):
            raise ScopeViolation(f"URL out of scope: {url}")

    def check_live_dns(self, url: str) -> None:
        """Recheck current DNS answers before dispatch (not socket-level pinning)."""
        host = urlparse(url).hostname
        if not host:
            raise ScopeViolation("URL has no hostname")
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass
        try:
            answers = {entry[4][0] for entry in socket.getaddrinfo(host, None)}
        except socket.gaierror as exc:
            raise ScopeViolation(f"DNS resolution failed for {host}") from exc
        if not answers:
            raise ScopeViolation(f"DNS resolution returned no addresses for {host}")
        for ip in answers:
            if not self.check_host(ip):
                raise ScopeViolation(
                    f"DNS address {ip} for {host} is outside approved scope"
                )

    # ---- policy level -----------------------------------------------------
    def check_action(self, danger: str) -> None:
        """Validate a tool's intrusiveness against the scope mode."""
        mode = self.policy.mode
        if mode == "none":
            raise ScopeViolation("scope mode 'none': no network actions permitted")
        rank = DANGER_RANK.get(danger, 2)     # unknown danger = treat as exploit
        if rank > MODE_CEILING.get(mode, -1):
            raise ScopeViolation(
                f"'{danger}' action not permitted in scope mode '{mode}'")

    def check_network_action(self, target: str, action: str) -> None:
        """Validate an outbound action (host or URL) against policy mode."""
        self.check_action(action)
        host = host_of(target) or target
        if self.policy.offline and not self.check_host(host):
            raise ScopeViolation(f"offline mode: egress to {host} denied")


def _same_ip(allowed: str, ip) -> bool:
    try:
        return ipaddress.ip_address(allowed) == ip
    except ValueError:
        return False
