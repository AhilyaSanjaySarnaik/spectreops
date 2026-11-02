from __future__ import annotations

import json

import httpx
import yaml


async def openapi_endpoints(args: dict) -> dict:
    url = args["url"]
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        raw = (await client.get(url)).text
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
