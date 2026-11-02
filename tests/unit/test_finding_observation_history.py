"""Observation history, legacy migration, explicit resolution and rediscovery."""
from __future__ import annotations

import sqlite3

import pytest

from spectreops.core.memory import Memory


def test_repeat_preserves_original_evidence_and_history(tmp_path):
    store = Memory(tmp_path / "history.sqlite")
    a = store.add_finding("Missing CSP", "low", "possible", "http://127.0.0.1",
                          {"headers": "first"}, "http_probe")
    b = store.add_finding("missing csp", "high", "verified", "http://127.0.0.1",
                          {"headers": "second"}, "http_replay")
    assert a == b
    row = store.findings()[0]
    assert row["seen_count"] == 2
    assert row["last_seen"] >= row["ts"]
    assert row["evidence"] == {"headers": "first"}
    history = store.finding_history(a)
    assert len(history) == 2
    assert [h["severity"] for h in history] == ["low", "high"]
    assert history[1]["evidence"] == {"headers": "second"}
    store.conn.close()
    reopened = Memory(tmp_path / "history.sqlite")
    assert len(reopened.finding_history(a)) == 2


def test_manual_resolution_reopened_only_when_reobserved(tmp_path):
    store = Memory(tmp_path / "reopen.sqlite")
    a = store.add_finding("Missing CSP", "low", "possible", "http://127.0.0.1", {}, "probe")
    assert store.set_finding_status(a, "resolved")
    assert store.findings()[0]["status"] == "resolved"
    assert not store.set_finding_status(a + 10, "resolved")
    store.add_finding("Missing CSP", "low", "possible", "http://127.0.0.1", {}, "probe")
    assert store.findings()[0]["status"] == "open"
    assert store.findings()[0]["seen_count"] == 2
    with pytest.raises(ValueError, match="invalid finding status"):
        store.set_finding_status(a, "bogus")


def test_migrate_legacy_findings_without_losing_data(tmp_path):
    db = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, "
        "title TEXT, severity TEXT, confidence TEXT, target TEXT, "
        "evidence TEXT, tool TEXT, status TEXT DEFAULT 'open')"
    )
    conn.execute(
        "INSERT INTO findings (ts,title,severity,confidence,target,evidence,tool) "
        "VALUES (10,'Header issue','medium','likely','http://127.0.0.1',"
        "'{\"legacy\":true}','http_probe')"
    )
    conn.commit()
    conn.close()
    store = Memory(db)
    issue = store.findings()[0]
    assert issue["seen_count"] == 1
    assert issue["last_seen"] == 10
    assert store.finding_history(issue["id"])[0]["evidence"] == {"legacy": True}
    store.conn.close()
    reopened = Memory(db)
    assert len(reopened.finding_history(issue["id"])) == 1
