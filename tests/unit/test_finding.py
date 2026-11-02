# tests/unit/test_finding.py
from spectreops.reporting.findings import Finding, dedup_and_sort


def test_dedup_and_order():
    fs = [Finding("B", "low", "possible", "t"),
          Finding("A", "high", "verified", "t"),
          Finding("A", "high", "verified", "t")]
    out = dedup_and_sort(fs)
    assert len(out) == 2 and out[0].severity == "high"
