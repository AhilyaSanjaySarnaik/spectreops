from __future__ import annotations

import asyncio

import httpx

DEFAULT_WORDS = ["admin", "login", "dashboard", "api", "backup", ".git",
                 "robots.txt", ".env", "wp-admin", "config", "test", "docs"]


async def dir_brute(args: dict) -> dict:
    base = args["base_url"].rstrip("/")
    words: list[str] = args.get("words") or DEFAULT_WORDS
    codes = set(args.get("interesting_codes", [200, 301, 302, 401, 403]))
    sem = asyncio.Semaphore(10)
    hits: list[dict] = []
    async with httpx.AsyncClient(verify=False, timeout=15,
                                 follow_redirects=False) as client:
        async def probe(path: str) -> None:
            try:
                async with sem:
                    r = await client.get(f"{base}/{path}")
                if r.status_code in codes:
                    hits.append({"path": f"/{path}", "status": r.status_code,
                                 "length": len(r.content)})
            except httpx.HTTPError:
                pass

        await asyncio.gather(*(probe(w) for w in words))
    return {"base_url": base, "hits": hits}


TOOL = {
    "name": "dir_brute",
    "description": "Probe common paths under a base URL and report interesting "
                   "responses (status and length).",
    "parameters": {"type": "object",
                   "properties": {"base_url": {"type": "string"},
                                  "words": {"type": "array",
                                            "items": {"type": "string"}}},
                   "required": ["base_url"]},
}
