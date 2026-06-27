# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the ActionVouch self-serve desktop launcher.

Build a one-file executable (per platform) from the repository root:

    python -m pip install -e ".[package]"
    pyinstaller packaging/actionvouch.spec

The result is ``dist/ActionVouch`` (``.exe`` on Windows). Run with no arguments
to launch the local-first self-serve app in the browser; run with arguments to
use the ``actionvouch`` CLI. The build is local-first: the bundled binary makes
no network calls and the optional ``browser`` extra (Playwright) is excluded.
"""

import os
from pathlib import Path

_spec_dir = Path(globals().get("SPECPATH", os.getcwd())).resolve()
ROOT = _spec_dir.parent if _spec_dir.name == "packaging" else _spec_dir

a = Analysis(
    [str(ROOT / "actionvouch" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (
            str(ROOT / "examples" / "actionvouch" / "sample_project.json"),
            "examples/actionvouch",
        ),
    ],
    hiddenimports=["actionvouch"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # The packaged app never needs the test/dev extras.
    excludes=["playwright", "pytest", "black", "ruff", "mypy", "pyinstaller"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ActionVouch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,  # show the local URL and allow Ctrl+C to stop the server
    disable_windowed_traceback=False,
)
