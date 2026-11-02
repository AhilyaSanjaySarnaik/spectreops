"""Tools that let the model read and advance the engagement plan.

The phase machine lives in code (core/planner.py); the model only decides task
content and asks to move on. Entering the exploit phase needs operator
approval, and is skipped entirely unless scope mode is 'full' — otherwise the
model could walk itself from recon to exploitation with no human checkpoint.
"""
from __future__ import annotations

from collections.abc import Callable

from ...core.planner import Plan
from ...core.tool_registry import Tool
from ...safety.approval import ApprovalGate

GATED_PHASES = {"exploit"}


def make_plan_tools(plan: Plan, approval: ApprovalGate, scope_mode: str,
                    on_change: Callable[[Plan], None] | None = None,
                    audit=None) -> list[Tool]:
    def changed() -> None:
        if on_change:
            on_change(plan)

    def record(event: str, **fields) -> None:
        if audit is not None:
            audit.record(event, actor="planner", **fields)

    async def plan_status(_args: dict) -> dict:
        phase = plan.current_phase()
        return {"objective": plan.objective, "current_phase": phase,
                "tasks": plan.tasks.get(phase, []),
                "remaining_phases": plan.phases[plan.current + 1:]}

    async def plan_task(args: dict) -> dict:
        task = str(args["task"]).strip()[:300]
        if not task:
            return {"error": "task must not be empty"}
        plan.add_task(plan.current_phase(), task)
        changed()
        return {"queued": task, "phase": plan.current_phase(),
                "index": len(plan.tasks[plan.current_phase()]) - 1}

    async def plan_complete_task(args: dict) -> dict:
        try:
            plan.complete_task(plan.current_phase(), int(args["index"]))
        except (IndexError, ValueError, TypeError) as e:
            return {"error": str(e)}
        changed()
        return {"completed": int(args["index"]), "open": plan.open_tasks()}

    async def plan_next_phase(_args: dict) -> dict:
        nxt = plan.next_phase()
        if nxt is None:
            return {"phase": None, "note": "already at the final phase (report)"}
        if open_ := plan.open_tasks():
            return {"error": f"{len(open_)} open task(s) in '{plan.current_phase()}'; "
                             "complete them first", "open": open_}
        skipped = None
        if nxt in GATED_PHASES:
            if scope_mode != "full":
                skipped = nxt
                plan.advance()                      # step over the gated phase
                record("phase_skipped", phase=nxt, reason=f"scope mode {scope_mode}")
            else:
                ok = approval.confirm(f"Advance engagement into the '{nxt}' phase?")
                record("phase_approval", phase=nxt, granted=ok)
                if not ok:
                    return {"error": f"operator did not approve entering '{nxt}'; "
                                     "continue with the current phase or report"}
        phase = plan.advance()
        record("phase_advance", phase=phase)
        changed()
        out = {"phase": phase}
        if skipped:
            out["note"] = f"skipped '{skipped}' (requires scope mode 'full')"
        return out

    empty = {"type": "object", "properties": {}}
    common = {"danger": "safe", "target_keys": (), "network": False, "tags": {"planner"}}
    return [
        Tool("plan_status", "Get the engagement objective, current phase and its tasks.",
             empty, plan_status, **common),
        Tool("plan_task", "Queue a task in the current engagement phase.",
             {"type": "object", "properties": {"task": {"type": "string"}},
              "required": ["task"]}, plan_task, **common),
        Tool("plan_complete_task", "Mark a task in the current phase done (by index).",
             {"type": "object", "properties": {"index": {"type": "integer"}},
              "required": ["index"]}, plan_complete_task, **common),
        Tool("plan_next_phase", "Advance to the next phase (recon -> collect -> test -> "
             "exploit -> report) once the current phase's tasks are complete. Entering "
             "'exploit' needs operator approval and scope mode 'full'.",
             empty, plan_next_phase, **common),
    ]
