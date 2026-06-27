"""Launcher for the ActionVouch verification platform.

Run from the repo root::

    python verify_actionvouch.py [--output-dir DIR] [--json] [--markdown PATH]

Exit code is 0 when every stage passes, 1 otherwise - so it can gate CI.
"""

from __future__ import annotations

from actionvouch.verify import main

if __name__ == "__main__":
    raise SystemExit(main())
