from __future__ import annotations

import json
import time
from pathlib import Path


def create_project(data_dir: Path, name: str, scope_targets: list[str]) -> Path:
    pdir = data_dir / "projects" / name
    (pdir / "evidence").mkdir(parents=True, exist_ok=True)
    (pdir / "project.json").write_text(json.dumps({
        "name": name, "created": time.time(), "targets": scope_targets,
    }, indent=2))
    return pdir


def list_projects(data_dir: Path) -> list[str]:
    root = data_dir / "projects"
    if not root.exists():
        return []
    return sorted(d.name for d in root.iterdir() if (d / "project.json").exists())
