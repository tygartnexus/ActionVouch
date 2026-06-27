"""Entry point for the packaged ActionVouch desktop launcher.

When the bundled executable is double-clicked (no command-line arguments) it
launches the local-first self-serve app in the browser. When run with arguments
it behaves exactly like the ``actionvouch`` CLI, so the single binary serves both
the non-technical "just open it" path and power-user commands.

Absolute imports are used (not relative) so this module also works as a
PyInstaller entry script.
"""

from __future__ import annotations

import sys

from actionvouch.app import serve_app
from actionvouch.cli import main as cli_main


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        # Double-clicked / launched with no arguments: open the self-serve app.
        serve_app(open_browser=True)
    else:
        cli_main(args)


if __name__ == "__main__":
    main()
