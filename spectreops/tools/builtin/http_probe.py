# spectreops/tools/builtin/http_probe.py
from __future__ import annotations

from ..base import http_request


async def http_probe(args: dict) -> dict:
    """GET a URL and return status, headers, and a body snippet."""
    url = args["url"]
    return await http_request("GET", url, headers=args.get("headers", {}))


TOOL = {
    "name": "http_probe",
    "description": "Fetch a URL with GET and return status code, response headers, "
                   "and the first 20KB of the body. Use for HTTP reconnaissance.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL (must be in scope)"},
            "headers": {"type": "object", "description": "Optional request headers"},
        },
        "required": ["url"],
    },
}
