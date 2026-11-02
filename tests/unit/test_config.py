from pathlib import Path

from spectreops.core.config import AppConfig, load_config


def test_defaults():
    cfg = AppConfig()
    assert cfg.llm.backend == "ollama"
    assert cfg.scope.mode == "none"
    assert cfg.runtime.offline is True


def test_yaml_and_env_override(tmp_path: Path):
    p = tmp_path / "c.yaml"
    p.write_text("scope:\n  mode: active\n  targets: ['127.0.0.1']\n")
    cfg = load_config(p)
    assert cfg.scope.mode == "active" and cfg.scope.targets == ["127.0.0.1"]
