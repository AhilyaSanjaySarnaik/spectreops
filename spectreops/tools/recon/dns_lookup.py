from __future__ import annotations

import dns.resolver

TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


async def dns_lookup(args: dict) -> dict:
    domain = args["domain"]
    out: dict[str, list[str]] = {}
    for rtype in TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            out[rtype] = sorted(r.to_text() for r in answers)
        except Exception:  # noqa: BLE001 — record as empty per type
            out[rtype] = []
    return {"domain": domain, "records": out}


TOOL = {
    "name": "dns_lookup",
    "description": "Passive DNS enumeration of a domain (A, AAAA, CNAME, MX, "
                   "NS, TXT, SOA).",
    "parameters": {"type": "object",
                   "properties": {"domain": {"type": "string"}},
                   "required": ["domain"]},
}
