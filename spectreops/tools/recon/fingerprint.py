"""In-process HTTP technology fingerprinting — no external binary needed.

Fetches the target and infers server software, frameworks and notable security
headers from response headers and a few body markers. Also flags security
headers that are *missing*, which is a common low-severity finding.
"""
from __future__ import annotations

import re

from ..base import http_request

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]

_TECH_HEADER_HINTS = {
    "server": "server", "x-powered-by": "framework", "x-aspnet-version": "ASP.NET",
    "x-generator": "generator", "via": "proxy/cdn",
}
_BODY_HINTS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"/_next/|__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
    (re.compile(r"__VIEWSTATE", re.I), "ASP.NET WebForms"),
]


async def fingerprint(args: dict) -> dict:
    url = args["url"]
    res = await http_request("GET", url, identity=args.get("identity"),
                             follow_redirects=True)
    if res.get("error"):
        return res
    headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
    tech = {}
    for h, label in _TECH_HEADER_HINTS.items():
        if h in headers:
            tech[label] = headers[h]
    body = res.get("body") or ""
    detected = sorted({name for rx, name in _BODY_HINTS if rx.search(body)})
    present = [h for h in SECURITY_HEADERS if h in headers]
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    cookies = headers.get("set-cookie", "")
    cookie_flags = {
        "httponly": "httponly" in cookies.lower(),
        "secure": "secure" in cookies.lower(),
        "samesite": "samesite" in cookies.lower(),
    } if cookies else {}
    return {"url": res.get("url", url), "status": res.get("status"),
            "technologies": tech, "frameworks_detected": detected,
            "security_headers_present": present,
            "security_headers_missing": missing,
            "cookie_flags": cookie_flags}


TOOL = {
    "name": "http_fingerprint",
    "description": "Fetch a URL and fingerprint server/framework technologies from "
                   "headers and body, and report present/missing security headers "
                   "and cookie flags. Passive, single request.",
    "parameters": {"type": "object",
                   "properties": {"url": {"type": "string"},
                                  "identity": {"type": "string"}},
                   "required": ["url"]},
}
