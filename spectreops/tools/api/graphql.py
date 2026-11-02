"""GraphQL introspection and schema enumeration.

Runs the standard introspection query against a GraphQL endpoint (in-process, so
no extra binary) and summarises the types, queries, mutations and — importantly
for API testing — whether introspection is even enabled, which is itself a
finding on many production endpoints.
"""
from __future__ import annotations

from ..base import http_request

# Minimal introspection query — enough to enumerate the schema surface.
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name } }
  }
}
""".strip()


async def graphql_introspect(args: dict) -> dict:
    url = args["url"]
    res = await http_request("POST", url, headers={"Content-Type": "application/json"},
                             identity=args.get("identity"),
                             json={"query": INTROSPECTION_QUERY}, raw=True)
    if res.get("error"):
        return res
    body = res.get("body") or ""
    import json as _json
    try:
        data = _json.loads(body)
    except _json.JSONDecodeError:
        return {"url": url, "introspection_enabled": False,
                "note": "endpoint did not return JSON; may not be GraphQL",
                "status": res.get("status")}
    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        return {"url": url, "introspection_enabled": False,
                "status": res.get("status"),
                "errors": data.get("errors"),
                "note": "introspection appears disabled (good practice in prod)"}
    types = schema.get("types") or []
    user_types = [t for t in types if not (t.get("name") or "").startswith("__")]
    return {
        "url": url,
        "introspection_enabled": True,
        "note": "introspection is ENABLED — often undesirable on production APIs",
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "type_count": len(user_types),
        "queries": [f.get("name") for t in types
                    if t.get("name") == (schema.get("queryType") or {}).get("name")
                    for f in (t.get("fields") or [])],
        "mutations": [f.get("name") for t in types
                      if t.get("name") == (schema.get("mutationType") or {}).get("name")
                      for f in (t.get("fields") or [])],
        "types": [t.get("name") for t in user_types][:200],
    }


TOOL = {
    "name": "graphql_introspect",
    "description": "Run a GraphQL introspection query against an endpoint and "
                   "enumerate its queries, mutations and types. Reports whether "
                   "introspection is enabled. Set 'identity' to send authenticated.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"},
                                  "identity": {"type": "string"}},
                   "required": ["url"]},
}
