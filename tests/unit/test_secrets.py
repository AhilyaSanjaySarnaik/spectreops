from spectreops.safety import secrets


def test_redact_patterns():
    out = secrets.redact("password=hunter2 and key AKIAIOSFODNN7EXAMPLE")
    assert "[REDACTED]" in out and "AKIAIOSFODNN7EXAMPLE" not in out


def test_store_and_redact(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "_SECRET_FILE", tmp_path / "s.json")
    secrets.store_secret("labpass", "s3cret-value")
    assert "[REDACTED]" in secrets.redact("token is s3cret-value")
