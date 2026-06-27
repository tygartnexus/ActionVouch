"""Real-browser smoke tests for the generated dashboard and console.

These render the artifacts in a headless Chromium and drive their client-side
behaviour. They are *optional*: when the browser extra (Playwright + its
browser binaries) is not installed, the whole module is skipped rather than
failed - ActionVouch's runtime stays standard-library only and offline.

The deterministic fail-open contract (absent extra => SKIP, never FAIL) is
covered without a browser in ``test_actionvouch_verify.py``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from actionvouch import (
    load_project,
    render_dashboard_html,
    render_editable_console_html,
    run_browser_smoke,
)
from actionvouch.browser_smoke import BrowserSmokeUnavailable
from actionvouch.paths import PROJECT_ROOT

SAMPLE = PROJECT_ROOT / "examples" / "actionvouch" / "sample_project.json"


def test_importing_actionvouch_does_not_import_playwright():
    # Packaging invariant: the optional browser extra must never be pulled in by
    # `import actionvouch`, so the standard-library-only runtime stays
    # installable and offline. Run in a clean subprocess so other tests that
    # import Playwright cannot pollute sys.modules.
    code = (
        "import sys, actionvouch; " "sys.exit(1 if 'playwright' in sys.modules else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    assert result.returncode == 0, (
        "import actionvouch pulled in playwright:\n" + result.stderr
    )


@pytest.fixture(scope="module")
def smoke(tmp_path_factory):
    """Run the browser smoke once for the module, or skip if unavailable."""

    project = load_project(SAMPLE)
    out = tmp_path_factory.mktemp("browser-smoke")
    dashboard = out / "dashboard.html"
    console = out / "console.html"
    dashboard.write_text(render_dashboard_html(project), encoding="utf-8")
    console.write_text(render_editable_console_html(project), encoding="utf-8")
    try:
        results = run_browser_smoke(dashboard, console, screenshot_dir=out / "shots")
    except BrowserSmokeUnavailable as exc:
        pytest.skip(f"browser extra unavailable: {exc}")
    return {result.kind: result for result in results}, out


def test_dashboard_renders_in_a_real_browser(smoke):
    results, _ = smoke
    dashboard = results["dashboard"]

    assert dashboard.valid is True, dashboard.errors
    assert dashboard.checks["sections_rendered"] is True
    assert dashboard.checks["summary_cards_rendered"] is True
    assert dashboard.checks["risk_findings_rows_present"] is True


def test_console_interaction_runs_in_a_real_browser(smoke):
    results, _ = smoke
    console = results["console"]

    assert console.valid is True, console.errors
    # The client-side validator, quick-add, and mode persistence actually run -
    # this is what the static source check cannot prove.
    assert console.checks["validate_marks_ok"] is True
    assert console.checks["validate_catches_invalid_json"] is True
    assert console.checks["add_agent_grows_inventory"] is True
    assert console.checks["response_mode_persists"] is True


def test_artifacts_make_zero_external_network_requests_at_runtime(smoke):
    results, _ = smoke

    for result in results.values():
        assert result.network_offenders == [], result.network_offenders
        assert result.console_errors == [], result.console_errors
        assert result.checks["no_external_network"] is True
        assert result.checks["no_console_errors"] is True


def test_screenshot_evidence_is_captured(smoke):
    results, out = smoke
    shots = out / "shots"

    assert (shots / "dashboard.png").exists()
    assert (shots / "console.png").exists()
    assert (shots / "console-validated.png").exists()
    for result in results.values():
        assert result.screenshots, f"{result.kind} captured no screenshots"


def test_relative_artifact_paths_are_supported(tmp_path, monkeypatch):
    # Regression: a relative output path must still resolve to a file:// URI.
    project = load_project(SAMPLE)
    monkeypatch.chdir(tmp_path)
    Path("dashboard.html").write_text(render_dashboard_html(project), encoding="utf-8")
    Path("console.html").write_text(
        render_editable_console_html(project), encoding="utf-8"
    )
    try:
        results = run_browser_smoke("dashboard.html", "console.html")
    except BrowserSmokeUnavailable as exc:
        pytest.skip(f"browser extra unavailable: {exc}")
    assert all(result.valid for result in results), [r.errors for r in results]
