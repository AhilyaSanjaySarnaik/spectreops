"""Secure offline agent release configuration must fail closed."""
from __future__ import annotations

import pytest

from spectreops.cli.main import build
from spectreops.core.config import AppConfig, RuntimeConfig


def test_secure_lab_defaults_disabled():
    cfg = AppConfig()
    assert cfg.runtime.secure_lab_container_id == ""
    assert cfg.runtime.allow_host_scanners is False


@pytest.mark.parametrize("field,value", [
    ("allow_host_scanners", True),
    ("sandbox_network", "host"),
])
def test_unsafe_runtime_settings_rejected_in_secure_lab(tmp_path, field, value):
    data = {
        "llm": {"base_url": "http://127.0.0.1:11434"},
        "agent": {"autonomy": "supervised"},
        "scope": {"mode": "active", "targets": ["127.0.0.1"]},
        "runtime": {"data_dir": str(tmp_path), "sandbox": "none",
                    "secure_lab_container_id": "a" * 64,
                    "allow_host_scanners": False, "sandbox_network": "none"},
    }
    data["runtime"][field] = value
    import yaml

    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match="secure lab requires"):
        build(config)


def test_secure_lab_rejects_automatic_approval(tmp_path):
    import yaml

    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "scope": {"mode": "active", "targets": ["127.0.0.1"]},
        "runtime": {"data_dir": str(tmp_path), "sandbox": "none",
                    "secure_lab_container_id": "a" * 64},
    }))
    with pytest.raises(ValueError, match="supervised approval"):
        build(config, yes=True)
