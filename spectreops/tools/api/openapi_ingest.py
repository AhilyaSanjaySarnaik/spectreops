from __future__ import annotations

import json

import yaml

from ..base import http_request


async def openapi_endpoints(args: dict) -> dict:
    url = args["url"]
    response = await http_request("GET", url)
    if "error" in response:
        return {"error": response["error"], "spec_url": url}
    raw = response["body"]
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError:
        spec = yaml.safe_load(raw)
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method.startswith("x-") or method == "parameters":
                continue
            endpoints.append({
                "method": method.upper(), "path": path,
                "operation_id": op.get("operationId"),
                "security": bool(op.get("security") or spec.get("security")),
                "parameters": [p.get("name") for p in op.get("parameters", [])]})
    server = (spec.get("servers") or [{}])[0].get("url", "")
    return {"spec_url": url, "title": spec.get("info", {}).get("title"),
            "server": server, "endpoints": endpoints}


TOOL = {
    "name": "openapi_endpoints",
    "description": "Fetch an OpenAPI/Swagger spec and enumerate all endpoints "
                   "with methods, auth requirements, and parameters.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"}},
                   "required": ["url"]},
}
