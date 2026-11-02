"""A general HTTP request tool the agent can use to send a crafted request and
replay it with changes.

This is the primitive behind most manual API testing: send a request, then
replay it with a tweaked header, body, method, or a *different auth identity*
and diff the responses. Identity-swapping (sending user A's request with user
B's credential) is how BOLA/IDOR is demonstrated — and because credentials are
bound to hosts in core/auth, swapping identities still can't leak a token to
another host.

Scope is enforced by the Executor (target_keys=("url",)). Request bodies are
capped and the method set is limited to ordinary HTTP verbs.
"""
from __future__ import annotations

import hashlib

from ..base import http_request

METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
MAX_BODY_IN = 100_000


async def http_send(args: dict) -> dict:
    method = str(args.get("method", "GET")).upper()
    if method not in METHODS:
        return {"error": f"method must be one of {sorted(METHODS)}"}
    url = args["url"]
    headers = args.get("headers") or {}
    if not isinstance(headers, dict):
        return {"error": "headers must be an object"}
    kw: dict = {}
    body = args.get("body")
    if body is not None:
        if isinstance(body, (dict, list)):
            kw["json"] = body
        else:
            text = str(body)
            if len(text) > MAX_BODY_IN:
                return {"error": f"body too large (>{MAX_BODY_IN} bytes)"}
            kw["content"] = text.encode()
    if args.get("json") is not None and body is None:
        kw["json"] = args["json"]
    return await http_request(method, url, headers=headers,
                              identity=args.get("identity"),
                              follow_redirects=bool(args.get("follow_redirects")),
                              raw=True, **kw)


async def http_replay(args: dict) -> dict:
    """Send the same request under two identities and diff the responses —
    the core check for broken object/function-level authorization."""
    identities = args.get("identities")
    if not isinstance(identities, list) or not identities:
        return {"error": "identities must be a non-empty list of identity names "
                         "(use \"\" for an unauthenticated request)"}
    base = {k: v for k, v in args.items() if k not in ("identities",)}
    runs = []
    for ident in identities:
        res = await http_send({**base, "identity": ident or None})
        runs.append({"identity": ident or "(none)", "status": res.get("status"),
                     "length": len(res.get("body") or ""),
                     "body_sha": _sha(res.get("body")), "error": res.get("error")})
    distinct = {(r["status"], r["body_sha"]) for r in runs if not r["error"]}
    return {"url": args.get("url"), "runs": runs,
            "identical_responses": len(distinct) <= 1,
            "note": "identical responses across identities on a protected resource "
                    "may indicate broken authorization — verify manually"}


def _sha(body: str | None) -> str:
    return hashlib.sha256((body or "").encode()).hexdigest()[:16]


SEND_TOOL = {
    "name": "http_send",
    "description": "Send a crafted HTTP request (method, headers, body, auth "
                   "identity) and return the response plus the request that was "
                   "sent (as evidence). Use for manual API probing and replay.",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": sorted(METHODS)},
            "headers": {"type": "object"},
            "body": {"description": "string, or object/array sent as JSON"},
            "identity": {"type": "string", "description": "auth identity name"},
            "follow_redirects": {"type": "boolean"},
        },
        "required": ["url"],
    },
}

REPLAY_TOOL = {
    "name": "http_replay",
    "description": "Send one request under several auth identities and diff the "
                   "responses — the primitive for BOLA/IDOR and broken "
                   "function-level authorization checks. List identity names in "
                   "'identities' (\"\" means unauthenticated).",
    "parameters": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": sorted(METHODS)},
            "headers": {"type": "object"},
            "body": {"description": "string, or object/array sent as JSON"},
            "identities": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["url", "identities"],
    },
}
