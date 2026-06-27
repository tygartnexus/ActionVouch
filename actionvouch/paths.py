"""Filesystem locations for the standalone ActionVouch app.

``PROJECT_ROOT`` resolves to the repository root (the parent of the
``actionvouch`` package) and ``DOCS_DIR`` points to the bundled docs that
ship with the app. These standalone path constants are vendored here so the
app is fully self-contained with no external dependency.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _project_root() -> Path:
    """Repo root in source mode; the PyInstaller bundle dir when frozen.

    Explicit rather than relying on ``parents[1]`` resolving to ``_MEIPASS`` by
    coincidence, so a future package move can't silently misplace bundled data.
    """

    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[1]


PROJECT_ROOT = _project_root()
DOCS_DIR = PROJECT_ROOT / "docs"
