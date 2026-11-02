from __future__ import annotations

from ..core.tool_registry import Tool
from .api.openapi_ingest import TOOL as OPENAPI, openapi_endpoints
from .builtin.http_probe import TOOL as PROBE, http_probe
from .builtin.shell_tool import TOOL as SHELL, run_shell
from .recon.dns_lookup import TOOL as DNS, dns_lookup
from .recon.nmap import TOOL as NMAP, nmap_scan
from .recon.subfinder import TOOL as SUBF, subfinder_enum
from .vuln.trivy import TOOL as TRIVY, trivy_scan
from .web.dir_brute import TOOL as DIRB, dir_brute
from .web.nuclei import TOOL as NUCLEI, nuclei_scan

_ALL = [
    (PROBE, http_probe, "active"),
    (DNS, dns_lookup, "safe"),
    (SUBF, subfinder_enum, "safe"),
    (NMAP, nmap_scan, "active"),
    (NUCLEI, nuclei_scan, "active"),
    (DIRB, dir_brute, "active"),
    (OPENAPI, openapi_endpoints, "safe"),
    (TRIVY, trivy_scan, "safe"),
    (SHELL, run_shell, "active"),
]


def register_all(registry) -> list[str]:
    registered = []
    for spec, handler, danger in _ALL:
        registry.register(Tool(name=spec["name"], description=spec["description"],
                               parameters=spec["parameters"], handler=handler,
                               tags={"builtin"}, danger=danger))
        registered.append(spec["name"])
    return registered
