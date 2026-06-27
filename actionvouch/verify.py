"""End-to-end verification platform for ActionVouch.

This drives the REAL ActionVouch pipeline over the bundled example projects and
emits a single ``PASS`` / ``FAIL`` readout, so a human can confirm "ActionVouch
is running as it should" without reading the pytest suite.

It is an acceptance / smoke harness layered on top of the library functions and
the static HTML smoke checker (:mod:`actionvouch.smoke`); it does **not**
replace ``tests/test_actionvouch.py``. It performs ZERO network calls and
explicitly re-asserts the local-first guarantee (no ``fetch()`` /
``XMLHttpRequest`` in generated HTML).

Run it from the repo root::

    python verify_actionvouch.py
    python verify_actionvouch.py --output-dir reports/actionvouch/verification
    python verify_actionvouch.py --json
    python verify_actionvouch.py --markdown reports/actionvouch/verification.md

(You can also run ``python -m actionvouch.verify``.)

By default artifacts are written to a temporary directory that is removed when
the run finishes, so a verification run never dirties the working tree. Pass
``--output-dir`` to keep the generated dashboard, console, report, and evidence
room for inspection.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .paths import PROJECT_ROOT
from .app import render_app_html
from .browser_smoke import BrowserSmokeUnavailable, run_browser_smoke
from .compliance import build_compliance_readiness_report
from .console import render_editable_console_html
from .dashboard import render_dashboard_html
from .evidence_room import build_evidence_room
from .importers import live_import_status
from .mcp_scan import scan_mcp_manifest
from .permissions import build_permission_graph
from .report import build_report, render_json_report, render_markdown_report
from .research_watch import build_research_watch_report
from .scoring import score_project
from .smoke import smoke_html
from .store import load_project

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
SKIP = "SKIP"

REPORT_VERSION = "actionvouch.verification.v1"

EXAMPLES_DIR = PROJECT_ROOT / "examples" / "actionvouch"
DEFAULT_SAMPLE = EXAMPLES_DIR / "sample_project.json"
DEFAULT_PILOT = EXAMPLES_DIR / "internal_pilot_project.json"
DEFAULT_INCOMPLETE = EXAMPLES_DIR / "incomplete_project.json"

_LIVE_IMPORT_PROVIDERS = ("zapier", "n8n", "make", "mcp")
_INCOMPLETE_ERROR_KEYWORDS = ("owner", "business_purpose", "unknown tool reference")


@dataclass(frozen=True)
class StageResult:
    """Outcome of a single verification stage."""

    name: str
    outcome: str  # PASS | FAIL | ERROR
    detail: str
    duration_ms: float

    @property
    def ok(self) -> bool:
        return self.outcome == PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 1),
        }


@dataclass(frozen=True)
class VerificationReport:
    """Aggregate result of an ActionVouch verification run."""

    stages: tuple[StageResult, ...]
    output_dir: str

    @property
    def passed(self) -> int:
        return sum(1 for stage in self.stages if stage.outcome == PASS)

    @property
    def failed(self) -> int:
        return sum(1 for stage in self.stages if stage.outcome == FAIL)

    @property
    def errored(self) -> int:
        return sum(1 for stage in self.stages if stage.outcome == ERROR)

    @property
    def skipped(self) -> int:
        return sum(1 for stage in self.stages if stage.outcome == SKIP)

    @property
    def overall(self) -> str:
        # A skipped optional stage (e.g. browser extra absent) never fails the
        # run; only real failures and errors do.
        return PASS if self.failed == 0 and self.errored == 0 else FAIL

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": "ActionVouch",
            "report_version": REPORT_VERSION,
            "overall": self.overall,
            "counts": {
                "total": len(self.stages),
                "passed": self.passed,
                "failed": self.failed,
                "errored": self.errored,
                "skipped": self.skipped,
            },
            "output_dir": self.output_dir,
            "stages": [stage.to_dict() for stage in self.stages],
            "guardrails": [
                "Local acceptance harness over bundled example projects; "
                "not public deployment proof.",
                "Zero network calls; asserts no fetch()/XMLHttpRequest in "
                "generated HTML.",
            ],
        }

    def render_text(self) -> str:
        lines = [
            "ActionVouch Verification Platform",
            "=================================",
            f"Artifacts: {self.output_dir}",
            "",
        ]
        width = max((len(stage.name) for stage in self.stages), default=0)
        for stage in self.stages:
            lines.append(
                f"  [{stage.outcome:<5}] {stage.name.ljust(width)}  {stage.detail}"
            )
        lines.extend(
            [
                "",
                (
                    f"Overall: {self.overall}  ("
                    f"{self.passed} passed, {self.failed} failed, "
                    f"{self.errored} error, {self.skipped} skipped "
                    f"/ {len(self.stages)} total)"
                ),
            ]
        )
        return "\n".join(lines)

    def render_markdown(self) -> str:
        lines = [
            "# ActionVouch Verification Report",
            "",
            f"- Overall: `{self.overall}`",
            (
                f"- Stages: {self.passed} passed, {self.failed} failed, "
                f"{self.errored} error, {self.skipped} skipped "
                f"/ {len(self.stages)} total"
            ),
            f"- Artifacts: `{self.output_dir}`",
            "",
            "This is a local acceptance harness over bundled example projects. "
            "It is not public deployment proof, and performs no network calls.",
            "",
            "| Stage | Outcome | Detail |",
            "| --- | --- | --- |",
        ]
        for stage in self.stages:
            detail = stage.detail.replace("|", "\\|")
            lines.append(f"| {stage.name} | `{stage.outcome}` | {detail} |")
        lines.append("")
        return "\n".join(lines)


class _SkipStage(Exception):
    """Raised by an optional stage to mark itself skipped (not failed).

    Used when an optional capability (such as the browser-smoke extra) is not
    installed: its absence must not fail the harness.
    """


def _run_stage(name: str, func: Callable[[], tuple[bool, str]]) -> StageResult:
    start = time.perf_counter()
    try:
        ok, detail = func()
        outcome = PASS if ok else FAIL
    except _SkipStage as skip:
        outcome = SKIP
        detail = str(skip)
    except Exception as exc:  # noqa: BLE001 - harness must capture any failure
        outcome = ERROR
        detail = f"{type(exc).__name__}: {exc}"
    duration_ms = (time.perf_counter() - start) * 1000.0
    return StageResult(
        name=name, outcome=outcome, detail=detail, duration_ms=duration_ms
    )


def run_verification(
    *,
    output_dir: str | Path | None = None,
    sample_path: str | Path | None = None,
    pilot_path: str | Path | None = None,
    incomplete_path: str | Path | None = None,
    include_browser: bool = False,
) -> VerificationReport:
    """Run the full ActionVouch verification pipeline.

    When ``output_dir`` is ``None`` a temporary directory is used and removed
    afterwards, so the run never dirties the working tree. The fixture paths
    default to the bundled examples but can be overridden (used by the harness's
    own tests to prove it fails on bad input).

    When ``include_browser`` is true, two extra real-browser stages render and
    drive the dashboard and console in a headless Chromium. They are *opt-in*
    and degrade to ``SKIP`` (never FAIL) when the optional browser extra is not
    installed, so the core 15-stage harness stays dependency-free.
    """

    sample = Path(sample_path) if sample_path else DEFAULT_SAMPLE
    pilot = Path(pilot_path) if pilot_path else DEFAULT_PILOT
    incomplete = Path(incomplete_path) if incomplete_path else DEFAULT_INCOMPLETE

    if output_dir is None:
        with tempfile.TemporaryDirectory(prefix="actionvouch-verify-") as tmp:
            return _run_all(Path(tmp), sample, pilot, incomplete, include_browser)
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    return _run_all(target, sample, pilot, incomplete, include_browser)


def _run_all(
    out: Path,
    sample_path: Path,
    pilot_path: Path,
    incomplete_path: Path,
    include_browser: bool = False,
) -> VerificationReport:
    cache: dict[str, Any] = {}

    def sample_project() -> Any:
        if "sample" not in cache:
            cache["sample"] = load_project(sample_path)
        return cache["sample"]

    def stage_sample_load_and_validate() -> tuple[bool, str]:
        project = sample_project()
        errors = project.validate()
        if errors:
            return False, f"{len(errors)} validation error(s): " + "; ".join(errors[:3])
        return True, f"{sample_path.name} valid (project_id={project.project_id})"

    def stage_sample_risk_scoring() -> tuple[bool, str]:
        findings = score_project(sample_project())
        if not findings:
            return False, "score_project returned no findings"
        if not any(finding.severity in {"high", "critical"} for finding in findings):
            return False, "no high/critical findings produced"
        for index, finding in enumerate(findings):
            if not (
                finding.facts
                and finding.risks
                and finding.recommendation
                and finding.what_would_change_the_recommendation
            ):
                return False, f"finding #{index} missing required narrative fields"
            if not 0 <= finding.confidence_score <= 1:
                return False, f"finding #{index} confidence out of range"
        severities = ", ".join(sorted({finding.severity for finding in findings}))
        return True, f"{len(findings)} findings (severities: {severities})"

    def stage_sample_report_render() -> tuple[bool, str]:
        project = sample_project()
        payload = build_report(project)
        if not isinstance(payload, dict) or "summary" not in payload:
            return False, "build_report payload missing 'summary'"
        if "status" not in payload:
            return False, "build_report payload missing 'status'"
        markdown = render_markdown_report(project)
        if not markdown.startswith("# ActionVouch Risk Audit Report"):
            return False, "markdown report missing expected title"
        json_report = render_json_report(project)
        parsed = json.loads(json_report)
        if parsed.get("status") != payload.get("status"):
            return False, "json/markdown report status mismatch"
        (out / "risk-report.md").write_text(markdown, encoding="utf-8")
        (out / "risk-report.json").write_text(json_report, encoding="utf-8")
        return True, f"json+markdown rendered (status={payload['status']})"

    def stage_sample_dashboard_html_smoke() -> tuple[bool, str]:
        path = out / "dashboard.html"
        path.write_text(render_dashboard_html(sample_project()), encoding="utf-8")
        result = smoke_html(path, artifact_kind="dashboard")
        if not result.valid:
            return False, "dashboard smoke failed: " + ", ".join(result.errors)
        return True, f"dashboard html ok ({len(result.checks)} checks passed)"

    def stage_sample_console_html_smoke() -> tuple[bool, str]:
        path = out / "console.html"
        path.write_text(
            render_editable_console_html(sample_project()), encoding="utf-8"
        )
        result = smoke_html(path, artifact_kind="console")
        if not result.valid:
            return False, "console smoke failed: " + ", ".join(result.errors)
        return True, f"console html ok ({len(result.checks)} checks passed)"

    def stage_local_first_no_network_guarantee() -> tuple[bool, str]:
        offenders: list[str] = []
        for name in ("dashboard.html", "console.html"):
            path = out / name
            if not path.exists():
                return False, f"{name} was not generated"
            checks = smoke_html(path, artifact_kind="auto").checks
            if not checks.get("no_fetch_calls", False):
                offenders.append(f"{name}: fetch()")
            if not checks.get("no_xml_http_request", False):
                offenders.append(f"{name}: XMLHttpRequest")
        if offenders:
            return False, "network-call markers found: " + ", ".join(offenders)
        return True, "no fetch()/XMLHttpRequest in generated HTML"

    def stage_sample_permission_graph() -> tuple[bool, str]:
        graph = build_permission_graph(sample_project())
        summary = graph.get("summary", {})
        if summary.get("node_count", 0) <= 0:
            return False, "permission graph has no nodes"
        if summary.get("high_risk_path_count", 0) <= 0:
            return False, "expected at least one high-risk path for the sample"
        (out / "permission-graph.json").write_text(
            json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return True, (
            f"{summary['node_count']} nodes, {summary['edge_count']} edges, "
            f"{summary['high_risk_path_count']} high-risk paths"
        )

    def stage_sample_compliance_fail_closed() -> tuple[bool, str]:
        payload = build_compliance_readiness_report(sample_project())
        if payload.get("certification_status") != "not_certified":
            return False, (
                "certification_status="
                f"{payload.get('certification_status')!r} (expected not_certified)"
            )
        if payload.get("attestation_status") != "not_attested":
            return False, (
                "attestation_status="
                f"{payload.get('attestation_status')!r} (expected not_attested)"
            )
        return True, "fail-closed (not_certified, not_attested)"

    def stage_sample_evidence_room() -> tuple[bool, str]:
        target = out / "evidence-room"
        manifest = build_evidence_room(sample_project(), target)
        if (
            manifest.get("certification_status") != "not_certified"
            or manifest.get("attestation_status") != "not_attested"
        ):
            return False, "evidence room manifest is not fail-closed"
        if not manifest.get("guardrails"):
            return False, "evidence room manifest missing guardrails"
        for required in (
            "manifest.json",
            "risk-report.md",
            "console.html",
            "dashboard.html",
        ):
            if not (target / required).exists():
                return False, f"evidence room missing {required}"
        return True, f"evidence room written ({len(manifest.get('files', []))} files)"

    def stage_research_watch_signals() -> tuple[bool, str]:
        payload = build_research_watch_report()
        count = payload.get("signal_count", 0)
        if count <= 0:
            return False, "no capability signals produced"
        stale = len(payload.get("stale_recommendation_flags", []))
        return True, f"{count} capability signals; {stale} stale-recommendation flags"

    def stage_live_import_fail_closed() -> tuple[bool, str]:
        offenders: list[str] = []
        for provider in _LIVE_IMPORT_PROVIDERS:
            status = live_import_status(provider)
            if not status.get("blocked", False) or status.get("valid", True):
                offenders.append(provider)
        if offenders:
            return False, "live import NOT fail-closed for: " + ", ".join(offenders)
        return True, "live import fail-closed for " + ", ".join(_LIVE_IMPORT_PROVIDERS)

    def stage_internal_pilot_validates() -> tuple[bool, str]:
        project = load_project(pilot_path)
        errors = project.validate()
        if errors:
            return False, f"{len(errors)} validation error(s) in pilot project"
        return True, f"{pilot_path.name} valid (project_id={project.project_id})"

    def stage_negative_control_incomplete_fails_closed() -> tuple[bool, str]:
        project = load_project(incomplete_path)
        errors = project.validate()
        if not errors:
            return False, "incomplete project validated (fail-closed is BROKEN)"
        joined = " ".join(errors)
        missing = [kw for kw in _INCOMPLETE_ERROR_KEYWORDS if kw not in joined]
        if missing:
            return False, "missing expected error keywords: " + ", ".join(missing)
        return True, f"correctly rejected with {len(errors)} actionable error(s)"

    def stage_app_local_first_ui() -> tuple[bool, str]:
        html = render_app_html()
        required = (
            "Content-Security-Policy",
            "connect-src 'self'",
            "no network",
            "/api/",
        )
        missing = [token for token in required if token not in html]
        if missing:
            return False, "self-serve app UI missing: " + ", ".join(missing)
        return True, "local-first self-serve UI renders with localhost-only CSP"

    def stage_mcp_manifest_scan() -> tuple[bool, str]:
        manifest = EXAMPLES_DIR / "mcp_manifests" / "write_destructive_crm_server.json"
        result = scan_mcp_manifest(manifest)
        if not result.valid:
            return False, "mcp scan failed: " + ", ".join(result.errors)
        if result.summary.get("destructive_tool_count", 0) < 1:
            return False, "expected at least one destructive tool to be flagged"
        if not result.guardrails:
            return False, "mcp scan result is missing guardrails"
        return True, (
            f"{result.summary['server_count']} server(s), "
            f"{result.summary['tool_count']} tools, highest risk "
            f"{result.summary['highest_server_risk']}"
        )

    def browser_smoke_results() -> tuple[str, Any]:
        """Run real-browser smoke once and cache it (or cache the skip reason)."""

        if "browser" not in cache:
            dashboard = out / "dashboard.html"
            console = out / "console.html"
            # Always (re)render so the smoked artifact matches the current
            # sample project, even if the output dir already held stale HTML.
            dashboard.write_text(
                render_dashboard_html(sample_project()), encoding="utf-8"
            )
            console.write_text(
                render_editable_console_html(sample_project()), encoding="utf-8"
            )
            try:
                results = run_browser_smoke(
                    dashboard, console, screenshot_dir=out / "browser-screenshots"
                )
            except BrowserSmokeUnavailable as exc:
                cache["browser"] = ("skip", str(exc))
            else:
                cache["browser"] = ("ok", {item.kind: item for item in results})
        return cache["browser"]

    def stage_browser_dashboard_smoke() -> tuple[bool, str]:
        state, payload = browser_smoke_results()
        if state == "skip":
            raise _SkipStage(f"browser extra not installed ({payload})")
        result = payload["dashboard"]
        if not result.valid:
            return False, "dashboard browser smoke failed: " + ", ".join(result.errors)
        return True, f"rendered DOM + zero-network ok ({len(result.checks)} checks)"

    def stage_browser_console_smoke() -> tuple[bool, str]:
        state, payload = browser_smoke_results()
        if state == "skip":
            raise _SkipStage(f"browser extra not installed ({payload})")
        result = payload["console"]
        if not result.valid:
            return False, "console browser smoke failed: " + ", ".join(result.errors)
        return True, (
            f"DOM + interaction + zero-network ok ({len(result.checks)} checks)"
        )

    stages = [
        _run_stage("sample_load_and_validate", stage_sample_load_and_validate),
        _run_stage("sample_risk_scoring", stage_sample_risk_scoring),
        _run_stage("sample_report_render", stage_sample_report_render),
        _run_stage("sample_dashboard_html_smoke", stage_sample_dashboard_html_smoke),
        _run_stage("sample_console_html_smoke", stage_sample_console_html_smoke),
        _run_stage(
            "local_first_no_network_guarantee",
            stage_local_first_no_network_guarantee,
        ),
        _run_stage("sample_permission_graph", stage_sample_permission_graph),
        _run_stage("mcp_manifest_scan", stage_mcp_manifest_scan),
        _run_stage("app_local_first_ui", stage_app_local_first_ui),
        _run_stage(
            "sample_compliance_fail_closed", stage_sample_compliance_fail_closed
        ),
        _run_stage("sample_evidence_room", stage_sample_evidence_room),
        _run_stage("research_watch_signals", stage_research_watch_signals),
        _run_stage("live_import_fail_closed", stage_live_import_fail_closed),
        _run_stage("internal_pilot_validates", stage_internal_pilot_validates),
        _run_stage(
            "negative_control_incomplete_fails_closed",
            stage_negative_control_incomplete_fails_closed,
        ),
    ]
    if include_browser:
        stages.extend(
            [
                _run_stage("browser_dashboard_smoke", stage_browser_dashboard_smoke),
                _run_stage("browser_console_smoke", stage_browser_console_smoke),
            ]
        )
    return VerificationReport(stages=tuple(stages), output_dir=str(out))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m actionvouch.verify",
        description="Run the ActionVouch end-to-end verification platform.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Persist generated artifacts here (default: temp dir, auto-removed).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--markdown",
        default=None,
        help="Also write a markdown report to this path.",
    )
    parser.add_argument(
        "--include-browser",
        action="store_true",
        help=(
            "Add real-browser smoke stages (needs the 'browser' extra; "
            "skips cleanly without it)."
        ),
    )
    args = parser.parse_args(argv)

    report = run_verification(
        output_dir=args.output_dir, include_browser=args.include_browser
    )

    if args.markdown:
        markdown_path = Path(args.markdown)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(report.render_markdown(), encoding="utf-8")

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render_text())

    return 0 if report.overall == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
