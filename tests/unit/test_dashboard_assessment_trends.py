"""Dashboard assessment API and HTML presentation tests."""
from __future__ import annotations

import time

from fastapi.testclient import TestClient

from spectreops.core.assessments import Assessments
from spectreops.core.memory import Memory
from spectreops.dashboard import app as dashboard


def test_dashboard_assessment_api_and_trends(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DATA_DIR", tmp_path)
    memory = Memory(tmp_path / "memory.db")
    runs = Assessments(memory)
    runs.start("baseline")
    old = memory.add_finding("Debug endpoint", "medium", "likely",
                             "http://127.0.0.1/a", {"a": 1}, "probe")
    runs.record(old, severity="medium", confidence="likely",
                evidence={"a": 1}, tool="probe")
    runs.complete("baseline")
    time.sleep(0.01)
    runs.start("retest")
    new = memory.add_finding("New issue", "high", "verified",
                             "http://127.0.0.1/b", {"b": 2}, "probe")
    runs.record(new, severity="high", confidence="verified",
                evidence={"b": 2}, tool="probe")
    assert memory.set_finding_status(old, "resolved")
    runs.complete("retest")
    memory.conn.close()

    client = TestClient(dashboard.app)
    run_response = client.get("/assessments")
    assert run_response.status_code == 200
    assert [r["name"] for r in run_response.json()] == ["baseline", "retest"]

    diff = client.get("/assessments/compare", params={
        "baseline": "baseline", "comparison": "retest",
    })
    assert diff.status_code == 200
    assert [r["id"] for r in diff.json()["new"]] == [new]
    assert [r["id"] for r in diff.json()["explicitly_resolved"]] == [old]

    trend_response = client.get("/assessments/trends")
    assert trend_response.status_code == 200
    assert trend_response.json()[0]["new"] == 1
    assert trend_response.json()[0]["explicitly_resolved"] == 1

    invalid = client.get("/assessments/compare", params={
        "baseline": "unknown", "comparison": "retest",
    })
    assert invalid.status_code == 400

    page = client.get("/")
    assert page.status_code == 200
    assert "Assessment trends" in page.text
    assert "textContent" in page.text
    assert "innerHTML" not in page.text


def test_dashboard_empty_runs_and_missing_db(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DATA_DIR", tmp_path)
    client = TestClient(dashboard.app)
    assert client.get("/assessments").status_code == 404
    memory = Memory(tmp_path / "memory.db")
    memory.conn.close()
    assert client.get("/assessments").json() == []
    assert client.get("/assessments/trends").json() == []
