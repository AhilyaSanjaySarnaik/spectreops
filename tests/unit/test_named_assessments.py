"""Named assessment comparison: true new/repeat/resolved/unverified categories."""
from __future__ import annotations

import json
import time

import pytest

from spectreops.core.assessments import AssessmentError, Assessments, export_comparison
from spectreops.core.memory import Memory
from spectreops.tools.builtin.findings_tool import make_record_finding


@pytest.mark.asyncio
async def test_named_assessments_diff_and_exports(tmp_path):
    memory = Memory(tmp_path / "runs.sqlite")
    tracker = Assessments(memory)
    record = make_record_finding(memory)
    tracker.start("baseline")
    first = await record({"title": "Missing CSP", "target": "http://127.0.0.1/a",
                          "severity": "low", "confidence": "possible", "tool": "probe",
                          "evidence": {"header": "missing"}})
    old = await record({"title": "Old debug endpoint", "target": "http://127.0.0.1/b",
                        "severity": "high", "confidence": "verified", "tool": "probe",
                        "evidence": {"status": 200}})
    absent = await record({"title": "Unverified later", "target": "http://127.0.0.1/c",
                           "severity": "medium", "confidence": "likely", "tool": "probe"})
    tracker.complete("baseline")
    time.sleep(0.01)
    tracker.start("followup")
    again = await record({"title": "missing csp", "target": "http://127.0.0.1/a",
                          "severity": "high", "confidence": "verified", "tool": "retest",
                          "evidence": {"header": "still missing"}})
    new = await record({"title": "New exposure", "target": "http://127.0.0.1/d",
                        "severity": "high", "confidence": "likely", "tool": "retest",
                        "evidence": {"observed": True}})
    assert memory.set_finding_status(old["id"], "resolved")
    tracker.complete("followup")

    diff = tracker.compare("baseline", "followup")
    assert [x["id"] for x in diff["new"]] == [new["id"]]
    assert [x["id"] for x in diff["recurring"]] == [first["id"]]
    assert [x["id"] for x in diff["explicitly_resolved"]] == [old["id"]]
    assert [x["id"] for x in diff["not_observed_unverified"]] == [absent["id"]]
    assert again["id"] == first["id"]
    assert diff["recurring"][0]["severity"] == "high"
    assert diff["recurring"][0]["evidence"] == {"header": "still missing"}
    assert len(tracker.list_runs()) == 2

    json_path, md_path = tmp_path / "diff.json", tmp_path / "diff.md"
    export_comparison(diff, json_path)
    export_comparison(diff, md_path)
    assert json.loads(json_path.read_text()) == diff
    assert "Not observed (unverified)" in md_path.read_text()
    assert "Old debug endpoint" in md_path.read_text()

    memory.conn.close()
    reopened = Assessments(Memory(tmp_path / "runs.sqlite"))
    assert reopened.compare("baseline", "followup") == diff


def test_incomplete_overlap_and_duplicate_names_are_rejected(tmp_path):
    tracker = Assessments(Memory(tmp_path / "db.sqlite"))
    tracker.start("first")
    with pytest.raises(AssessmentError, match="complete the current"):
        tracker.start("second")
    with pytest.raises(AssessmentError, match="missing or incomplete"):
        tracker.compare("first", "second")
    tracker.complete("first")
    with pytest.raises(AssessmentError, match="already exists"):
        tracker.start("first")
    tracker.start("second")
    with pytest.raises(AssessmentError, match="missing or incomplete"):
        tracker.compare("first", "second")
    tracker.complete("second")
    with pytest.raises(AssessmentError, match="sequential"):
        tracker.compare("second", "first")


def test_no_assessment_does_not_record_snapshot(tmp_path):
    memory = Memory(tmp_path / "db.sqlite")
    tracker = Assessments(memory)
    fid = memory.add_finding("Header missing", "low", "possible",
                             "http://127.0.0.1", {}, "probe")
    tracker.record(fid, severity="low", confidence="possible",
                   evidence={}, tool="probe")
    assert not tracker.list_runs()
    assert memory.findings()[0]["id"] == fid
