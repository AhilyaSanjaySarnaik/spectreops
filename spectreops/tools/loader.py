from __future__ import annotations

from ..core.tool_registry import Tool
from .api.graphql import TOOL as GRAPHQL
from .api.graphql import graphql_introspect
from .api.openapi_ingest import TOOL as OPENAPI
from .api.openapi_ingest import openapi_endpoints
from .builtin.http_probe import TOOL as PROBE
from .builtin.http_probe import http_probe
from .builtin.http_request_tool import REPLAY_TOOL, SEND_TOOL, http_replay, http_send
from .builtin.shell_tool import TOOL as SHELL
from .builtin.shell_tool import run_shell
from .recon.archive import TOOL as ARCHIVE
from .recon.archive import archive_urls
from .recon.crawl import TOOL as CRAWL
from .recon.crawl import crawl
from .recon.dns_lookup import TOOL as DNS
from .recon.dns_lookup import dns_lookup
from .recon.fingerprint import TOOL as FINGERPRINT
from .recon.fingerprint import fingerprint
from .recon.nmap import TOOL as NMAP
from .recon.nmap import nmap_scan
from .recon.params import TOOL as PARAMS
from .recon.params import param_discover
from .recon.subfinder import TOOL as SUBF
from .recon.subfinder import subfinder_enum
from .vuln.sqlmap import TOOL as SQLMAP
from .vuln.sqlmap import sqlmap_test
from .vuln.trivy import TOOL as TRIVY
from .vuln.trivy import trivy_scan
from .web.dir_brute import TOOL as DIRB
from .web.dir_brute import dir_brute
from .web.ffuf import TOOL as FFUF
from .web.ffuf import ffuf_fuzz
from .web.nuclei import TOOL as NUCLEI
from .web.nuclei import nuclei_scan

# spec, handler, danger, tags, extra Tool kwargs
_ALL = [
    # --- recon / discovery ---
    (DNS, dns_lookup, "safe", {"recon", "dns"}, {"target_keys": ("domain",)}),
    (SUBF, subfinder_enum, "safe", {"recon", "third_party"},
     {"target_keys": ("domain",), "third_party_egress": True, "host_subprocess": True}),
    (ARCHIVE, archive_urls, "safe", {"recon", "third_party"},
     {"target_keys": ("domain",), "third_party_egress": True, "host_subprocess": True}),
    (NMAP, nmap_scan, "active", {"recon", "network"}, {"target_keys": ("target",), "host_subprocess": True}),
    (PROBE, http_probe, "active", {"recon", "web"}, {"target_keys": ("url",)}),
    (FINGERPRINT, fingerprint, "active", {"recon", "web"}, {"target_keys": ("url",)}),
    (CRAWL, crawl, "active", {"recon", "web"}, {"target_keys": ("url",), "host_subprocess": True}),
    (PARAMS, param_discover, "active", {"recon", "web"}, {"target_keys": ("url",), "host_subprocess": True}),
    # --- API ---
    (OPENAPI, openapi_endpoints, "safe", {"api", "recon"}, {"target_keys": ("url",)}),
    (GRAPHQL, graphql_introspect, "active", {"api", "recon"}, {"target_keys": ("url",)}),
    # --- content/param fuzzing ---
    (DIRB, dir_brute, "active", {"web", "content_discovery"},
     {"target_keys": ("base_url",)}),
    (FFUF, ffuf_fuzz, "active", {"web", "content_discovery"}, {"target_keys": ("url",), "host_subprocess": True}),
    # --- manual request / replay ---
    (SEND_TOOL, http_send, "active", {"web", "manual"}, {"target_keys": ("url",)}),
    (REPLAY_TOOL, http_replay, "active", {"web", "manual", "authz"},
     {"target_keys": ("url",)}),
    # --- vuln scanning ---
    (NUCLEI, nuclei_scan, "active", {"vuln", "web"}, {"target_keys": ("url",), "host_subprocess": True}),
    (TRIVY, trivy_scan, "safe", {"vuln", "local"},
     {"target_keys": (), "network": False, "host_subprocess": True}),
    # --- active exploitation (phase-gated + approval) ---
    (SQLMAP, sqlmap_test, "exploit", {"vuln", "injection"}, {"target_keys": ("url",), "host_subprocess": True}),
    # --- shell (full mode + approval every call) ---
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
