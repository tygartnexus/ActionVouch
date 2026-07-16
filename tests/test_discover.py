"""Tests for machine-wide AI-agent discovery.

All roots/drives/home/clock are injected so the tests never scan the real
machine - they scan small synthetic "machine" trees under tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path

from actionvouch.discover import (
    ScanRoot,
    candidate_roots,
    discover_machine,
    render_review_worksheet,
)
from actionvouch.scoring import score_project
from actionvouch.store import load_project


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _planted_machine(root: Path) -> None:
    _write(
        root, "billing/.mcp.json", json.dumps({"mcpServers": {"shadow_payments": {}}})
    )
    _write(root, "billing/tools.py", "@tool\ndef wire_funds(amount):\n    ...\n")
    _write(root, "ops/.env", "STRIPE_SECRET_KEY=sk_live_x\n")


# --------------------------------------------------------------------------- #
# Root selection
# --------------------------------------------------------------------------- #
def test_candidate_roots_excludes_drives_by_default(tmp_path):
    roots = candidate_roots(
        home=tmp_path,
        environ={},
        drive_lister=lambda: ["C"],
        drive_typer=lambda _l: "fixed",
    )
    assert "C:\\" not in {r.path for r in roots}  # drives are opt-in (--deep)


def test_deep_includes_fixed_excludes_removable_and_network(tmp_path):
    types = {"C": "fixed", "D": "removable", "E": "network"}
    roots = candidate_roots(
        include_drives=True,
        home=tmp_path,
        environ={},
        drive_lister=lambda: ["C", "D", "E"],
        drive_typer=types.get,
    )
    paths = {r.path for r in roots}
    assert "C:\\" in paths
    assert "D:\\" not in paths
    assert "E:\\" not in paths


def test_candidate_roots_opt_in_removable(tmp_path):
    roots = candidate_roots(
        include_drives=True,
        include_removable=True,
        home=tmp_path,
        environ={},
        drive_lister=lambda: ["D"],
        drive_typer=lambda _l: "removable",
    )
    assert "D:\\" in {r.path for r in roots}


def test_candidate_roots_includes_known_config_locations(tmp_path):
    (tmp_path / ".cursor").mkdir()
    appdata = tmp_path / "AppData"
    (appdata / "Claude").mkdir(parents=True)
    roots = candidate_roots(
        home=tmp_path,
        environ={"APPDATA": str(appdata)},
        drive_lister=lambda: [],
    )
    reasons = {r.reason for r in roots}
    assert any("cursor" in r for r in reasons)
    assert any("claude_desktop" in r for r in reasons)


# --------------------------------------------------------------------------- #
# Orchestration + draft
# --------------------------------------------------------------------------- #
def test_discover_builds_draft_inventory_from_planted_surface(tmp_path):
    machine = tmp_path / "machine"
    _planted_machine(machine)
    out = tmp_path / "draft.json"

    result = discover_machine(
        roots=[ScanRoot(str(machine), "test")],
        save_path=out,
        scan_source=True,  # exercise source detection too
        timestamp="2026-06-22",
    )

    names = {item.name for item in result.observed.items}
    assert "shadow_payments" in names
    assert "wire_funds" in names
    assert "stripe" in names
    assert result.draft_project.agents and result.draft_project.tools
    assert result.draft_valid, result.validation_errors
    assert out.exists()
    # Round-trips through the store and scores (discovered surface is risky).
    loaded = load_project(out)
    assert loaded.validate() == []
    assert score_project(loaded)


def test_draft_project_validates_and_is_scoreable(tmp_path):
    machine = tmp_path / "m"
    _planted_machine(machine)
    result = discover_machine(roots=[ScanRoot(str(machine), "t")])
    project = result.draft_project
    assert project.validate() == []
    findings = score_project(project)
    assert any(f.severity in {"high", "critical"} for f in findings)


def test_report_and_dashboard_surface_discovery_provenance(tmp_path):
    from actionvouch.dashboard import render_dashboard_html
    from actionvouch.report import build_report, render_markdown_report

    machine = tmp_path / "m"
    _write(machine, ".mcp.json", json.dumps({"mcpServers": {"shadow_payments": {}}}))
    project = discover_machine(roots=[ScanRoot(str(machine), "t")]).draft_project

    disc = build_report(project)["summary"]["discovery"]
    assert disc["discovered_agent_count"] >= 1
    assert disc["is_discovery_draft"] is True
    assert "machine-discovered" in disc["note"]

    html = render_dashboard_html(project)
    assert "Discovered (unreviewed)" in html
    assert "machine-discovered" in html  # the banner
    assert "Discovery:" in render_markdown_report(project)


def test_business_purpose_is_surface_derived_not_fabricated(tmp_path):
    machine = tmp_path / "m"
    _planted_machine(machine)
    project = discover_machine(
        roots=[ScanRoot(str(machine), "t")], scan_source=True
    ).draft_project

    agent = project.agents[0]
    # Honest: describes the observed surface and stays UNCONFIRMED about intent;
    # owner is never invented.
    assert agent.business_purpose.startswith("UNCONFIRMED purpose.")
    assert "implied actions:" in agent.business_purpose
    assert agent.owner == "unknown"


def test_review_worksheet_lists_agents_with_blank_owner_fields(tmp_path):
    machine = tmp_path / "m"
    _planted_machine(machine)
    project = discover_machine(
        roots=[ScanRoot(str(machine), "t")], scan_source=True
    ).draft_project

    sheet = render_review_worksheet(project)
    assert "Discovered Inventory Review Worksheet" in sheet
    assert "agent surface(s) need review" in sheet
    assert "wire_funds" in sheet  # observed tool is listed for context
    assert "[ ] **Owner**" in sheet  # blank field for the human to fill
    assert "______" in sheet  # fields are blank, not pre-filled
    assert "UNCONFIRMED" in sheet  # autonomy is not asserted as fact


def test_review_worksheet_handles_empty_project():
    from actionvouch.models import AuditProject

    empty = AuditProject(
        project_id="p",
        name="n",
        version="actionvouch.audit_project.v1",
        created_at="",
        updated_at="",
        scope="s",
        agents=[],
        tools=[],
        policies=[],
        action_events=[],
        evidence=[],
    )
    sheet = render_review_worksheet(empty)
    assert "nothing to review" in sheet


def test_discover_runs_to_completion_by_default(tmp_path):
    # Default max_seconds=None -> no artificial cut-off; coverage is complete.
    machine = tmp_path / "m"
    _planted_machine(machine)
    result = discover_machine(roots=[ScanRoot(str(machine), "t")])
    assert result.stats["coverage_complete"] is True


def test_discover_scan_source_false_skips_source(tmp_path):
    machine = tmp_path / "m"
    _write(machine, ".mcp.json", json.dumps({"mcpServers": {"shadow": {}}}))
    _write(machine, "tools.py", "@tool\ndef wire_funds(x):\n    ...\n")
    result = discover_machine(roots=[ScanRoot(str(machine), "t")], scan_source=False)
    names = {i.name for i in result.observed.items}
    assert "shadow" in names  # config is still read
    assert "wire_funds" not in names  # source files are skipped


def test_discover_respects_global_file_budget(tmp_path):
    machine = tmp_path / "m"
    _planted_machine(machine)
    result = discover_machine(roots=[ScanRoot(str(machine), "t")], max_total_files=0)
    assert result.stats["files_scanned"] == 0
    assert any("budget" in w for w in result.warnings)


def test_discover_respects_time_budget(tmp_path):
    machine = tmp_path / "m"
    _planted_machine(machine)
    ticks = iter([0.0, 999.0, 999.0, 999.0])

    result = discover_machine(
        roots=[ScanRoot(str(machine), "t")],
        max_seconds=1.0,
        clock=lambda: next(ticks),
    )
    assert result.stats["roots_scanned"] == 0
    assert any("time budget" in w for w in result.warnings)


def test_discover_handles_missing_root_without_raising(tmp_path):
    result = discover_machine(roots=[ScanRoot(str(tmp_path / "does_not_exist"), "t")])
    # No crash; nothing observed; a warning is recorded by the underlying scanner.
    assert result.observed.items == ()
    assert result.draft_project is not None


def test_discover_cli_runs_bounded(capsys, tmp_path):
    # Exercises the CLI wiring end-to-end. Hard-bounded to 1 file + 5s so it does
    # not actually crawl the machine during the test suite.
    from actionvouch import cli

    cli.main(["discover", "--max-files", "1", "--max-seconds", "5"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "discovered"
    assert payload["valid"] is True
    assert "stats" in payload and "files_scanned" in payload["stats"]


def test_discover_cli_writes_worksheet(capsys, tmp_path):
    # --worksheet writes a Markdown review checklist next to the JSON draft.
    from actionvouch import cli

    out = tmp_path / "worksheet.md"
    cli.main(
        [
            "discover",
            "--max-files",
            "1",
            "--max-seconds",
            "5",
            "--worksheet",
            str(out),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["worksheet_path"] == str(out)
    assert out.exists()
    assert "Review Worksheet" in out.read_text(encoding="utf-8")


def test_within_handles_drive_roots_and_escapes():
    # Regression: a drive root like "C:\\" has a trailing separator; children must
    # count as within it (else drive scans silently find nothing), while a path on
    # another drive must not.
    from actionvouch.reconcile import _within

    assert _within(r"C:\Users\x\proj", "C:\\") is True
    assert _within(r"C:\Users", "C:\\") is True
    assert _within(r"D:\other", "C:\\") is False
    assert _within(r"E:\repo\sub", r"E:\repo") is True
    assert _within(r"E:\repo_other", r"E:\repo") is False


def test_empty_machine_yields_empty_draft_flagged_invalid(tmp_path):
    # Nothing discovered -> a draft with no agents, which is intentionally NOT a
    # valid audit project (there is nothing to audit). discover_machine reports
    # that honestly rather than fabricating an agent.
    result = discover_machine(roots=[ScanRoot(str(tmp_path), "t")])
    assert result.observed.items == ()
    assert result.draft_project.agents == []
    assert result.draft_valid is False
