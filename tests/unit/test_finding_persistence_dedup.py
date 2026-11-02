"""Phase 2 persistent findings identity and duplicate detection."""
from __future__ import annotations

import pytest

from spectreops.core.memory import Memory
from spectreops.tools.builtin.findings_tool import make_record_finding


def test_persistent_duplicate_reuses_id(tmp_path):
    db = tmp_path / "engagement.db"
    memory = Memory(db)
    first = memory.add_finding("  EXPOSED API KEY  ", "high", "likely",
                               "http://127.0.0.1:8080/", {"first": True}, "http_probe")
    second = memory.add_finding("exposed api key", "critical", "verified",
                                "http://127.0.0.1:8080/", {"second": True}, "http_probe")
    assert first == second
    rows = memory.findings()
    assert len(rows) == 1
    assert rows[0]["evidence"] == {"first": True}
    memory.conn.close()
    reopened = Memory(db)
    assert reopened.existing_finding_id("Exposed Api Key", "http://127.0.0.1:8080/") == first
    assert len(reopened.findings()) == 1


def test_same_finding_different_target_not_merged(tmp_path):
    memory = Memory(tmp_path / "findings.db")
    first = memory.add_finding("Missing CSP", "low", "possible",
                               "http://127.0.0.1/a", {}, "http_probe")
    second = memory.add_finding("Missing CSP", "low", "possible",
                                "http://127.0.0.1/b", {}, "http_probe")
    assert first != second
    assert len(memory.findings()) == 2


@pytest.mark.asyncio
async def test_record_finding_reports_existing_issue(tmp_path):
    memory = Memory(tmp_path / "findings.db")
    handler = make_record_finding(memory)
    args = {"title": "Missing CSP", "target": "http://127.0.0.1/",
            "severity": "low", "confidence": "possible", "tool": "http_probe",
            "evidence": {"response": 200}}
    first = await handler(args)
    second = await handler({**args, "title": "missing csp"})
    assert first == {"recorded": True, "id": first["id"], "duplicate": False}
    assert second == {"recorded": False, "id": first["id"], "duplicate": True}
    assert len(memory.findings()) == 1
