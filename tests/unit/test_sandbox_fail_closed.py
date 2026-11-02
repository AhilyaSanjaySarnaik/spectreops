"""Regression tests: automatic sandbox selection must never silently run on host."""
from __future__ import annotations

import pytest

from spectreops.safety import sandbox


def test_auto_prefers_docker(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    assert sandbox.Sandbox(mode="auto").mode == "docker"


def test_auto_falls_back_to_bwrap(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)
    assert sandbox.Sandbox(mode="auto").mode == "bwrap"


def test_auto_fails_closed_without_isolation(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="no sandbox available"):
        sandbox.Sandbox(mode="auto")


def test_explicit_unsandboxed_mode_remains_possible(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda _name: None)
    assert sandbox.Sandbox(mode="none", network="none").mode == "none"


@pytest.mark.parametrize("mode", ["", "unrestricted", "host", "none-ish"])
def test_reject_unknown_sandbox_modes(mode):
    with pytest.raises(ValueError, match="sandbox mode"):
        sandbox.Sandbox(mode=mode)
