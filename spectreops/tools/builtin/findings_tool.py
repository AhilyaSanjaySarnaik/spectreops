from __future__ import annotations

from collections.abc import Awaitable, Callable

from ...core.assessments import Assessments
from ...core.memory import Memory

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCES = ["verified", "likely", "possible"]


def make_record_finding(memory: Memory) -> Callable[[dict], Awaitable[dict]]:
    """Build a handler that lets the agent persist findings to the engagement DB.

    Without this the agent had no way to store anything, so `findings`, the
    dashboard and reports were always empty.
    """

    async def record_finding(args: dict) -> dict:
        sev = str(args.get("severity", "info")).lower()
        conf = str(args.get("confidence", "possible")).lower()
        if sev not in SEVERITIES:
            return {"error": f"severity must be one of {SEVERITIES}"}
        if conf not in CONFIDENCES:
            return {"error": f"confidence must be one of {CONFIDENCES}"}
        evidence = args.get("evidence") or {}
        if conf == "verified" and not evidence:
            return {"error": "a 'verified' finding needs tool evidence; "
                             "use 'likely' or 'possible' otherwise"}
        duplicate_id = memory.existing_finding_id(
            str(args["title"])[:200], str(args.get("target", "")),
        )
        fid = memory.add_finding(
            title=str(args["title"])[:200], severity=sev, confidence=conf,
            target=str(args.get("target", "")), evidence=evidence,
            tool=str(args.get("tool", "")),
            reproduction=str(args.get("reproduction", "")),
            remediation=str(args.get("remediation", "")))
        Assessments(memory).record(fid, severity=sev, confidence=conf,
                                   evidence=evidence, tool=str(args.get("tool", "")))
        return {"recorded": duplicate_id is None, "id": fid,
                "duplicate": duplicate_id is not None}

    return record_finding


TOOL = {
    "name": "record_finding",
    "description": "Persist a security finding to the engagement database. Call this "
                   "once per distinct issue. Use confidence 'verified' only when "
                   "tool output proves it, and include that output as evidence.",
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": SEVERITIES},
            "confidence": {"type": "string", "enum": CONFIDENCES},
            "target": {"type": "string", "description": "affected URL/host"},
            "tool": {"type": "string", "description": "tool that produced evidence"},
            "evidence": {"type": "object"},
            "reproduction": {"type": "string"},
            "remediation": {"type": "string"},
        },
        "required": ["title", "severity", "confidence", "target"],
    },
}
