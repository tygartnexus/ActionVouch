"""Local JSON store for ActionVouch audit projects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import AuditProject, ValidationError


def load_project(path: str | Path) -> AuditProject:
    project_path = Path(path)
    with project_path.open("r", encoding="utf-8") as handle:
        data: Any = json.load(handle)
    if not isinstance(data, dict):
        raise ValidationError(
            f"ActionVouch project must be a JSON object: {project_path}"
        )
    return AuditProject.from_dict(data)


def save_project(project: AuditProject, path: str | Path) -> Path:
    project_path = Path(path)
    project_path.parent.mkdir(parents=True, exist_ok=True)
    with project_path.open("w", encoding="utf-8") as handle:
        json.dump(project.to_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return project_path
