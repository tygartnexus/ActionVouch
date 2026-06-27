"""Single source of truth for the ActionVouch version.

Kept dependency-free so it can be imported by the package, the app, and
``pyproject.toml`` (dynamic version) without import cycles.
"""

from __future__ import annotations

__version__ = "0.1.0"
