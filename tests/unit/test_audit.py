from spectreops.core.audit import AuditLog


def test_chain_and_tamper_detection(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.record("e1", actor="t")
    log.record("e2", actor="t")
    assert log.verify()

    # tamper with the first record
    p = tmp_path / "a.jsonl"
    text = p.read_text().replace("e1", "EVIL")
    p.write_text(text)
    log2 = AuditLog(p)
    assert not log2.verify()
