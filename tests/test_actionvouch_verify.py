"""Tests for the ActionVouch end-to-end verification platform.

These assert two things the harness must guarantee:

1. It reports PASS when run against the real bundled example projects.
2. It actually *can* fail - it reports FAIL/ERROR when the audited pipeline is
   fed broken input - so a green run is meaningful.
"""

from __future__ import annotations

import actionvouch.verify as verify_module
from actionvouch.browser_smoke import BrowserSmokeUnavailable
from actionvouch.verify import (
    ERROR,
    FAIL,
    PASS,
    SKIP,
    VerificationReport,
    run_verification,
)
from actionvouch.paths import PROJECT_ROOT

EXAMPLES = PROJECT_ROOT / "examples" / "actionvouch"
SAMPLE = EXAMPLES / "sample_project.json"
INCOMPLETE = EXAMPLES / "incomplete_project.json"


def test_verification_passes_on_real_examples(tmp_path):
    report = run_verification(output_dir=tmp_path)

    assert isinstance(report, VerificationReport)
    assert report.overall == PASS, "\n" + report.render_text()
    assert report.failed == 0
    assert report.errored == 0
    assert all(stage.outcome == PASS for stage in report.stages)
    # Generated artifacts are written to the output dir.
    assert (tmp_path / "dashboard.html").exists()
    assert (tmp_path / "console.html").exists()
    assert (tmp_path / "risk-report.md").exists()
    assert (tmp_path / "evidence-room" / "manifest.json").exists()


def test_verification_runs_hermetically_with_default_temp_dir():
    # No output_dir -> internal temp dir, removed afterwards. Still PASS and it
    # must not require or leave any persistent artifacts.
    report = run_verification()

    assert report.overall == PASS, "\n" + report.render_text()
    assert len(report.stages) >= 12


def test_report_dict_is_serializable_and_complete(tmp_path):
    report = run_verification(output_dir=tmp_path)
    payload = report.to_dict()

    assert payload["product"] == "ActionVouch"
    assert payload["overall"] == PASS
    assert payload["counts"]["total"] == len(report.stages)
    assert payload["counts"]["passed"] == report.passed
    # Every stage round-trips with the required keys.
    for stage in payload["stages"]:
        assert set(stage) >= {"name", "outcome", "detail", "duration_ms"}


def test_verification_fails_when_known_good_input_is_invalid(tmp_path):
    # Feed the deliberately-incomplete project in the "known-good" sample slot.
    # The validate stage must turn red, proving the harness can fail.
    report = run_verification(output_dir=tmp_path, sample_path=INCOMPLETE)

    assert report.overall == FAIL
    stage = _stage(report, "sample_load_and_validate")
    assert stage.outcome == FAIL


def test_verification_errors_on_missing_sample_file(tmp_path):
    missing = tmp_path / "does_not_exist.json"

    report = run_verification(output_dir=tmp_path, sample_path=missing)

    assert report.overall == FAIL
    stage = _stage(report, "sample_load_and_validate")
    assert stage.outcome == ERROR


def test_negative_control_flips_when_fed_a_valid_project(tmp_path):
    # The negative-control stage EXPECTS the incomplete project to be rejected.
    # If we hand it the valid sample instead, that stage must turn red.
    report = run_verification(output_dir=tmp_path, incomplete_path=SAMPLE)

    stage = _stage(report, "negative_control_incomplete_fails_closed")
    assert stage.outcome == FAIL
    assert report.overall == FAIL


def test_core_harness_stage_set_is_stable_without_browser(tmp_path):
    # The browser stages are opt-in; the default run stays the documented core.
    report = run_verification(output_dir=tmp_path)

    assert len(report.stages) == 15
    names = {stage.name for stage in report.stages}
    assert "mcp_manifest_scan" in names
    assert "app_local_first_ui" in names
    assert "browser_dashboard_smoke" not in names
    assert "browser_console_smoke" not in names


def test_include_browser_adds_optional_stages(tmp_path):
    # With the extra requested, two browser stages are appended. They PASS when
    # the browser extra is installed and SKIP otherwise - never FAIL/ERROR - so
    # the overall verdict stays PASS either way.
    report = run_verification(output_dir=tmp_path, include_browser=True)

    assert report.overall == PASS, "\n" + report.render_text()
    for name in ("browser_dashboard_smoke", "browser_console_smoke"):
        assert _stage(report, name).outcome in {PASS, SKIP}


def test_browser_stages_skip_when_extra_is_unavailable(tmp_path, monkeypatch):
    # Simulate the optional browser extra being absent: the stages must SKIP
    # (fail-open), the run stays PASS, and the skip is counted, not hidden.
    def _unavailable(*args, **kwargs):
        raise BrowserSmokeUnavailable("playwright not installed (test)")

    monkeypatch.setattr(verify_module, "run_browser_smoke", _unavailable)

    report = run_verification(output_dir=tmp_path, include_browser=True)

    assert report.overall == PASS
    assert report.failed == 0
    assert report.errored == 0
    assert report.skipped == 2
    assert report.to_dict()["counts"]["skipped"] == 2
    for name in ("browser_dashboard_smoke", "browser_console_smoke"):
        assert _stage(report, name).outcome == SKIP


def _stage(report: VerificationReport, name: str):
    return next(stage for stage in report.stages if stage.name == name)
