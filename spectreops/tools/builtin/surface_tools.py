"""Attack-surface queue tools (inspired by RedteamAgent's case pipeline).

Discovery tools (crawl, openapi, ffuf, archive URLs) find endpoints; the agent
records them as surfaces and then works through the queue one at a time in the
test phase. This keeps coverage explicit — every discovered endpoint is either
tested or deliberately skipped — instead of relying on the model to remember
what it has seen.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from ...core.memory import Memory


def make_surface_tools(memory: Memory) -> list[tuple[dict, Callable[[dict], Awaitable[dict]]]]:
    async def surface_add(args: dict) -> dict:
        items = args.get("urls")
        if items is None and args.get("url"):
            items = [args["url"]]
        if not items:
            return {"error": "provide 'url' or 'urls'"}
        added = 0
        for url in items:
            if memory.add_surface(str(url), method=str(args.get("method", "GET")),
                                  kind=str(args.get("kind", "endpoint")),
                                  source=str(args.get("source", ""))):
                added += 1
        return {"added": added, "already_known": len(items) - added,
                "queued_total": len(memory.surfaces(status="new"))}

    async def surface_next(_args: dict) -> dict:
        nxt = memory.next_surface()
        if nxt is None:
            return {"surface": None, "note": "queue empty — all surfaces handled"}
        return {"surface": nxt,
                "remaining": len(memory.surfaces(status="new"))}

    async def surface_done(args: dict) -> dict:
        status = str(args.get("status", "tested"))
        try:
            ok = memory.set_surface_status(int(args["id"]), status)
        except (KeyError, ValueError) as e:
            return {"error": str(e)}
        return {"updated": ok, "id": args.get("id"), "status": status}

    add_tool = {
        "name": "surface_add",
        "description": "Add discovered endpoint(s) to the attack-surface queue so "
                       "they get worked through in the test phase. Pass 'url' or a "
                       "list in 'urls'. Duplicates are ignored.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "urls": {"type": "array", "items": {"type": "string"}},
            "method": {"type": "string"}, "kind": {"type": "string"},
            "source": {"type": "string", "description": "tool/phase that found it"}}},
    }
    next_tool = {
        "name": "surface_next",
        "description": "Claim the next untested endpoint from the attack-surface "
                       "queue (marks it in-progress). Returns none when the queue "
                       "is empty.",
        "parameters": {"type": "object", "properties": {}},
    }
    done_tool = {
        "name": "surface_done",
        "description": "Mark a surface as tested (or skipped) by its id.",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "integer"},
            "status": {"type": "string", "enum": ["tested", "skipped", "new"]}},
            "required": ["id"]},
    }
    return [(add_tool, surface_add), (next_tool, surface_next), (done_tool, surface_done)]
