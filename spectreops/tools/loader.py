from __future__ import annotations

from ..core.tool_registry import Tool
from .api.openapi_ingest import TOOL as OPENAPI
from .api.openapi_ingest import openapi_endpoints
from .builtin.http_probe import TOOL as PROBE
from .builtin.http_probe import http_probe
from .builtin.shell_tool import TOOL as SHELL
from .builtin.shell_tool import run_shell
from .recon.dns_lookup import TOOL as DNS
from .recon.dns_lookup import dns_lookup
from .recon.nmap import TOOL as NMAP
from .recon.nmap import nmap_scan
from .recon.subfinder import TOOL as SUBF
from .recon.subfinder import subfinder_enum
from .vuln.trivy import TOOL as TRIVY
from .vuln.trivy import trivy_scan
from .web.dir_brute import TOOL as DIRB
from .web.dir_brute import dir_brute
from .web.nuclei import TOOL as NUCLEI
from .web.nuclei import nuclei_scan

# spec, handler, danger, tags, extra Tool kwargs
_ALL = [
    (PROBE, http_probe, "active", {"recon", "web"}, {"target_keys": ("url",)}),
    (DNS, dns_lookup, "safe", {"recon", "dns"}, {"target_keys": ("domain",)}),
    # subfinder queries third-party passive sources (crt.sh, etc.), not the target
    (SUBF, subfinder_enum, "safe", {"recon", "third_party"},
     {"target_keys": ("domain",), "third_party_egress": True}),
    (NMAP, nmap_scan, "active", {"recon", "network"}, {"target_keys": ("target",)}),
    (NUCLEI, nuclei_scan, "active", {"vuln", "web"}, {"target_keys": ("url",)}),
    (DIRB, dir_brute, "active", {"web", "content_discovery"},
     {"target_keys": ("base_url",)}),
    (OPENAPI, openapi_endpoints, "safe", {"api", "recon"}, {"target_keys": ("url",)}),
    # local filesystem / image scan: no target host
    (TRIVY, trivy_scan, "safe", {"vuln", "local"},
     {"target_keys": (), "network": False}),
    (SHELL, run_shell, "active", {"shell"}, {"target_keys": (), "unscoped": True}),
]


def register_all(registry) -> list[str]:
    registered = []
    for spec, handler, danger, tags, extra in _ALL:
        registry.register(Tool(name=spec["name"], description=spec["description"],
                               parameters=spec["parameters"], handler=handler,
                               tags={"builtin", *tags}, danger=danger, **extra))
        registered.append(spec["name"])
    return registered
