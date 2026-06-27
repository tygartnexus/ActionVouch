"""CLI handlers for local ActionVouch commands."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from .response_quality import normalize_response_mode
from .approvals import (
    create_approval_request,
    list_approval_candidates,
    load_approval,
    render_approval_markdown,
    review_approval,
    save_approval,
)
from .browser_smoke import (
    BrowserSmokeUnavailable,
    render_browser_smoke_report,
    run_browser_smoke,
)
from .compliance import build_compliance_readiness_report, render_compliance_markdown
from .console import render_editable_console_html
from .dashboard import render_dashboard_html
from ._version import __version__
from .app import DEFAULT_PORT, serve_app
from .evidence_room import build_evidence_room, verify_evidence_room
from .mcp_scan import render_mcp_scan_markdown, scan_mcp_manifest
from .importers import import_project_from_paths, live_import_status
from .models import ValidationError
from .permissions import build_permission_graph
from .report import build_report, render_json_report, render_markdown_report
from .research_watch import (
    build_research_watch_report,
    render_research_watch_json,
    render_research_watch_markdown,
)
from .scoring import score_project
from .smoke import render_smoke_report, smoke_html
from .store import load_project, save_project


def _port_arg(value: str) -> int:
    """argparse type for --port: a TCP port in 1..65535 (0 = OS-assigned)."""

    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port must be an integer, got {value!r}")
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def command_actionvouch(args: Any) -> dict[str, Any]:
    if args.actionvouch_action == "live-import":
        return live_import_status(args.provider)
    if args.actionvouch_action == "import":
        return _import_command(args)
    if args.actionvouch_action == "smoke-html":
        return _smoke_html_command(args)
    if args.actionvouch_action == "verify-evidence-room":
        return _verify_evidence_room_command(args)
    if args.actionvouch_action == "mcp-scan":
        return _mcp_scan_command(args)
    if args.actionvouch_action == "app":
        serve_app(port=args.port, open_browser=not args.no_browser)
        return {"status": "app_stopped", "valid": True}
    if args.actionvouch_action == "approvals":
        return _approvals_command(args)
    if args.actionvouch_action == "research-watch":
        return _research_watch_command(args)

    try:
        project = load_project(args.project_path)
    except (OSError, ValidationError, ValueError) as exc:
        return {"status": "invalid", "valid": False, "errors": [str(exc)]}
    if getattr(args, "response_mode", ""):
        project = replace(
            project,
            response_mode=normalize_response_mode(args.response_mode).value,
        )

    if args.actionvouch_action == "validate":
        errors = project.validate()
        return {
            "status": "valid" if not errors else "invalid",
            "valid": not errors,
            "errors": errors,
            "project_id": project.project_id,
        }
    if args.actionvouch_action == "score":
        errors = project.validate()
        findings = (
            [] if errors else [finding.to_dict() for finding in score_project(project)]
        )
        return {
            "status": "invalid" if errors else "scored",
            "valid": not errors,
            "errors": errors,
            "project_id": project.project_id,
            "risk_findings": findings,
        }
    if args.actionvouch_action == "report":
        return _report_command(args, project)
    if args.actionvouch_action == "dashboard":
        return _dashboard_command(args, project)
    if args.actionvouch_action == "console":
        return _console_command(args, project)
    if args.actionvouch_action == "browser-smoke":
        return _browser_smoke_command(args, project)
    if args.actionvouch_action == "compliance":
        return _compliance_command(args, project)
    if args.actionvouch_action == "evidence-room":
        return _evidence_room_command(args, project)
    if args.actionvouch_action == "permission-graph":
        return _permission_graph_command(args, project)
    return {
        "status": "invalid",
        "valid": False,
        "errors": ["Unknown actionvouch action"],
    }


def _import_command(args: Any) -> dict[str, Any]:
    try:
        result = import_project_from_paths(
            args.source_paths,
            project_id=args.project_id,
            name=args.name,
            scope=args.scope,
            timestamp=args.timestamp,
        )
    except (OSError, ValidationError, ValueError) as exc:
        return {"status": "invalid", "valid": False, "errors": [str(exc)]}
    errors = result.project.validate()
    output_path = save_project(result.project, args.output)
    return {
        "status": "invalid" if errors else "imported",
        "valid": not errors,
        "errors": errors,
        "project_id": result.project.project_id,
        "output_path": str(output_path),
        "imported_sources": result.imported_sources,
        "blocked_live_sources": result.blocked_live_sources,
        "warnings": result.warnings,
    }


def _smoke_html_command(args: Any) -> dict[str, Any]:
    results = [
        smoke_html(path, artifact_kind=args.kind).to_dict() for path in args.html_paths
    ]
    valid = all(item["valid"] for item in results)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            render_smoke_report(
                [smoke_html(path, artifact_kind=args.kind) for path in args.html_paths]
            ),
            encoding="utf-8",
        )
    return {
        "status": "smoked" if valid else "smoke_failed",
        "valid": valid,
        "results": results,
        "output_path": args.output,
    }


def _verify_evidence_room_command(args: Any) -> dict[str, Any]:
    try:
        result = verify_evidence_room(args.directory)
    except (OSError, ValueError) as exc:
        return {"status": "invalid", "valid": False, "errors": [str(exc)]}
    return {
        "status": (
            "evidence_room_intact" if result["intact"] else "evidence_room_tampered"
        ),
        "valid": result["intact"],
        **result,
    }


def _mcp_scan_command(args: Any) -> dict[str, Any]:
    result = scan_mcp_manifest(args.manifest_path)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            render_mcp_scan_markdown(result)
            if args.format == "markdown"
            else json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
        )
        output_path.write_text(content, encoding="utf-8")
    payload = result.to_dict()
    payload["status"] = "mcp_scanned" if result.valid else "mcp_scan_invalid"
    payload["output_path"] = args.output
    return payload


def _approvals_command(args: Any) -> dict[str, Any]:
    if args.approvals_action == "review":
        try:
            record = load_approval(args.approval_path)
            project = load_project(args.project_path)
            reviewed = review_approval(
                record,
                project=project,
                decision=args.decision,
                reviewer=args.reviewer,
                reviewed_at=args.reviewed_at,
                note=args.note,
            )
            errors = reviewed.validate()
            # L1: never persist a record that fails validation.
            if args.output and not errors:
                save_approval(reviewed, args.output)
            return {
                "status": "invalid" if errors else "approval_reviewed",
                "valid": not errors,
                "errors": errors,
                "approval": reviewed.to_dict(),
                "downgraded": reviewed.decision != args.decision,
                "output_path": args.output if (args.output and not errors) else "",
            }
        except (OSError, ValidationError, ValueError) as exc:
            return {"status": "invalid", "valid": False, "errors": [str(exc)]}

    try:
        project = load_project(args.project_path)
    except (OSError, ValidationError, ValueError) as exc:
        return {"status": "invalid", "valid": False, "errors": [str(exc)]}

    if args.approvals_action == "list":
        errors = project.validate()
        candidates = [] if errors else list_approval_candidates(project)
        return {
            "status": "invalid" if errors else "approvals_listed",
            "valid": not errors,
            "errors": errors,
            "project_id": project.project_id,
            "approvals": candidates,
        }
    if args.approvals_action == "request":
        errors = project.validate()
        if errors:
            return {
                "status": "invalid",
                "valid": False,
                "errors": errors,
                "project_id": project.project_id,
            }
        try:
            record = create_approval_request(
                project,
                args.event_id,
                requested_state=args.requested_state,
                created_at=args.created_at,
            )
            record_errors = record.validate()
            # L1: never persist a record that fails validation.
            if args.output and not record_errors:
                save_approval(record, args.output)
            if args.markdown_output:
                output_path = Path(args.markdown_output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    render_approval_markdown(record), encoding="utf-8"
                )
            return {
                "status": "invalid" if record_errors else "approval_requested",
                "valid": not record_errors,
                "errors": record_errors,
                "approval": record.to_dict(),
                "output_path": args.output,
                "markdown_output_path": args.markdown_output,
            }
        except ValueError as exc:
            return {"status": "invalid", "valid": False, "errors": [str(exc)]}
    return {"status": "invalid", "valid": False, "errors": ["Unknown approval action"]}


def _report_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    if args.format == "json":
        content = render_json_report(project)
    else:
        content = render_markdown_report(project)
    payload = build_report(project)
    result: dict[str, Any] = {
        "status": "invalid" if errors else "reported",
        "valid": not errors,
        "errors": errors,
        "project_id": project.project_id,
        "format": args.format,
    }
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        result["output_path"] = str(output_path)
    else:
        result["report"] = payload if args.format == "json" else content
    return result


def _dashboard_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    html = render_dashboard_html(project)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return {
        "status": "invalid" if errors else "dashboard_written",
        "valid": not errors,
        "errors": errors,
        "project_id": project.project_id,
        "output_path": str(output_path),
    }


def _console_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    html = render_editable_console_html(project)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return {
        "status": "invalid" if errors else "console_written",
        "valid": not errors,
        "errors": errors,
        "project_id": project.project_id,
        "output_path": str(output_path),
    }


def _browser_smoke_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    if errors:
        return {
            "status": "invalid",
            "valid": False,
            "errors": errors,
            "project_id": project.project_id,
        }
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dashboard_path = out_dir / "dashboard.html"
    console_path = out_dir / "console.html"
    dashboard_path.write_text(render_dashboard_html(project), encoding="utf-8")
    console_path.write_text(render_editable_console_html(project), encoding="utf-8")
    screenshot_dir = (out_dir / "screenshots") if not args.no_screenshots else None
    try:
        results = run_browser_smoke(
            dashboard_path, console_path, screenshot_dir=screenshot_dir
        )
    except BrowserSmokeUnavailable as exc:
        return {
            "status": "skipped",
            "valid": True,
            "skipped": True,
            "reason": str(exc),
            "project_id": project.project_id,
            "output_dir": str(out_dir),
        }
    report_path = out_dir / "browser-smoke-report.md"
    report_path.write_text(render_browser_smoke_report(results), encoding="utf-8")
    valid = all(result.valid for result in results)
    return {
        "status": "browser_smoked" if valid else "browser_smoke_failed",
        "valid": valid,
        "skipped": False,
        "project_id": project.project_id,
        "results": [result.to_dict() for result in results],
        "output_dir": str(out_dir),
        "report_path": str(report_path),
    }


def _compliance_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    payload = build_compliance_readiness_report(
        project, packet_dir=args.packet_dir or None
    )
    content = (
        render_compliance_markdown(payload)
        if args.format == "markdown"
        else _render_json_payload(payload)
    )
    result: dict[str, Any] = {
        "status": "invalid" if errors else "compliance_reviewed",
        "valid": not errors,
        "errors": errors,
        "project_id": project.project_id,
        "format": args.format,
        "certification_status": payload["certification_status"],
        "attestation_status": payload["attestation_status"],
    }
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        result["output_path"] = str(output_path)
    else:
        result["report"] = payload if args.format == "json" else content
    return result


def _render_json_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _research_watch_command(args: Any) -> dict[str, Any]:
    payload = build_research_watch_report(
        retrieved_at=args.retrieved_at,
        last_taxonomy_reviewed_at=args.last_taxonomy_reviewed_at,
    )
    content = (
        render_research_watch_markdown(payload)
        if args.format == "markdown"
        else render_research_watch_json(payload)
    )
    result: dict[str, Any] = {
        "status": "research_watch_ready",
        "valid": True,
        "format": args.format,
        "signal_count": payload["signal_count"],
        "stale_recommendation_flag_count": len(payload["stale_recommendation_flags"]),
    }
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        result["output_path"] = str(output_path)
    else:
        result["report"] = payload if args.format == "json" else content
    return result


def _permission_graph_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    graph = None if errors else build_permission_graph(project)
    result: dict[str, Any] = {
        "status": "invalid" if errors else "permission_graph_ready",
        "valid": not errors,
        "errors": errors,
        "project_id": project.project_id,
    }
    if errors:
        return result
    content = json.dumps(graph, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        result["output_path"] = str(output_path)
    else:
        result["graph"] = graph
    return result


def _evidence_room_command(args: Any, project: Any) -> dict[str, Any]:
    errors = project.validate()
    if errors:
        return {
            "status": "invalid",
            "valid": False,
            "errors": errors,
            "project_id": project.project_id,
        }
    try:
        manifest = build_evidence_room(
            project,
            args.output,
            release_packet_dir=args.packet_dir or None,
        )
    except OSError as exc:
        return {
            "status": "invalid",
            "valid": False,
            "errors": [str(exc)],
            "project_id": project.project_id,
        }
    return {
        "status": "evidence_room_written",
        "valid": True,
        "errors": [],
        "project_id": project.project_id,
        "output_path": args.output,
        "manifest": manifest,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the standalone ActionVouch CLI parser.

    Subcommands use ``dest="actionvouch_action"`` (and ``approvals_action``)
    so :func:`command_actionvouch` dispatches without modification.
    """

    parser = argparse.ArgumentParser(
        prog="actionvouch",
        description=(
            "Local-first ActionVouch audit: validate, score, report, dashboard, "
            "console, import, compliance, evidence-room, permission-graph, "
            "research-watch, and approvals. No live external actions."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"actionvouch {__version__}"
    )
    sub = parser.add_subparsers(dest="actionvouch_action", required=True)

    validate_p = sub.add_parser(
        "validate", help="Validate a local ActionVouch audit project JSON file"
    )
    validate_p.add_argument("project_path")

    score_p = sub.add_parser("score", help="Score local ActionVouch risk findings")
    score_p.add_argument("project_path")

    report_p = sub.add_parser("report", help="Generate a local ActionVouch report")
    report_p.add_argument("project_path")
    report_p.add_argument("--format", choices=("json", "markdown"), default="json")
    report_p.add_argument(
        "--output",
        default="",
        help="Optional output file. Without it, the report is embedded in JSON stdout.",
    )
    report_p.add_argument(
        "--response-mode",
        default="",
        help="Override the report response mode, e.g. accuracy, red-team, ceo, technical, or legal-risk.",
    )

    dashboard_p = sub.add_parser(
        "dashboard", help="Write a static local ActionVouch dashboard HTML file"
    )
    dashboard_p.add_argument("project_path")
    dashboard_p.add_argument("--output", required=True, help="Output HTML file path.")
    dashboard_p.add_argument(
        "--response-mode",
        default="",
        help="Override the dashboard response mode badge.",
    )

    console_p = sub.add_parser(
        "console", help="Write a local editable ActionVouch console HTML file"
    )
    console_p.add_argument("project_path")
    console_p.add_argument("--output", required=True, help="Output HTML file path.")
    console_p.add_argument(
        "--response-mode",
        default="",
        help="Set the initial local console response mode.",
    )

    browser_smoke_p = sub.add_parser(
        "browser-smoke",
        help=(
            "Render the dashboard/console in a headless browser and assert DOM, "
            "interaction, and runtime zero-network behaviour (needs the 'browser' "
            "extra; skips cleanly without it)"
        ),
    )
    browser_smoke_p.add_argument("project_path")
    browser_smoke_p.add_argument(
        "--output-dir",
        required=True,
        help="Directory for generated HTML, screenshots, and the smoke report.",
    )
    browser_smoke_p.add_argument(
        "--no-screenshots",
        action="store_true",
        help="Run the checks without capturing screenshot evidence.",
    )
    browser_smoke_p.add_argument(
        "--response-mode",
        default="",
        help="Override the response mode metadata before rendering artifacts.",
    )

    import_p = sub.add_parser(
        "import",
        help="Import credential-free local exports or redacted summaries into an audit project",
    )
    import_p.add_argument("source_paths", nargs="+")
    import_p.add_argument("--output", required=True)
    import_p.add_argument("--project-id", required=True)
    import_p.add_argument("--name", required=True)
    import_p.add_argument(
        "--scope",
        default=(
            "Imported ActionVouch controlled-pilot project. No live external "
            "actions executed."
        ),
    )
    import_p.add_argument(
        "--timestamp",
        default="",
        help="Optional ISO timestamp to stamp imported records.",
    )

    live_import_p = sub.add_parser(
        "live-import",
        help="Report gated live-provider import status without using credentials",
    )
    live_import_p.add_argument("provider")

    compliance_p = sub.add_parser(
        "compliance",
        help="Generate a third-party security/compliance readiness report",
    )
    compliance_p.add_argument("project_path")
    compliance_p.add_argument("--format", choices=("json", "markdown"), default="json")
    compliance_p.add_argument("--output", default="")
    compliance_p.add_argument(
        "--response-mode",
        default="",
        help="Override response mode metadata for the compliance report context.",
    )
    compliance_p.add_argument(
        "--packet-dir",
        default="",
        help="Release packet directory to inspect for readiness evidence.",
    )

    evidence_room_p = sub.add_parser(
        "evidence-room", help="Generate a local ActionVouch evidence-room folder"
    )
    evidence_room_p.add_argument("project_path")
    evidence_room_p.add_argument("--output", required=True)
    evidence_room_p.add_argument(
        "--response-mode",
        default="",
        help="Override response mode metadata for generated evidence-room artifacts.",
    )
    evidence_room_p.add_argument(
        "--packet-dir",
        default="",
        help="Release packet directory to include in the evidence room.",
    )

    permission_graph_p = sub.add_parser(
        "permission-graph",
        help="Export a local ActionVouch permission graph JSON artifact",
    )
    permission_graph_p.add_argument("project_path")
    permission_graph_p.add_argument("--output", default="")

    smoke_p = sub.add_parser(
        "smoke-html",
        help="Run static local HTML smoke checks on dashboard/console artifacts",
    )
    smoke_p.add_argument("html_paths", nargs="+")
    smoke_p.add_argument(
        "--kind", choices=("auto", "dashboard", "console"), default="auto"
    )
    smoke_p.add_argument("--output", default="")

    verify_room_p = sub.add_parser(
        "verify-evidence-room",
        help="Recompute and verify an evidence room's manifest SHA-256 hashes",
    )
    verify_room_p.add_argument("directory")

    mcp_scan_p = sub.add_parser(
        "mcp-scan",
        help=(
            "Statically scan a local MCP manifest for tool-scope risk; never "
            "starts a server, calls tools/list, reads env values, or hits the net"
        ),
    )
    mcp_scan_p.add_argument("manifest_path")
    mcp_scan_p.add_argument("--format", choices=("json", "markdown"), default="json")
    mcp_scan_p.add_argument("--output", default="")

    app_p = sub.add_parser(
        "app",
        help=(
            "Run the local self-serve ActionVouch app in your browser "
            "(localhost only; no network, no data leaves your machine)"
        ),
    )
    app_p.add_argument("--port", type=_port_arg, default=DEFAULT_PORT)
    app_p.add_argument(
        "--no-browser",
        action="store_true",
        help="Start the server without opening a browser window.",
    )

    research_p = sub.add_parser(
        "research-watch",
        help="Generate ActionVouch agent-capability research-watch signals",
    )
    research_p.add_argument("--format", choices=("json", "markdown"), default="json")
    research_p.add_argument("--output", default="")
    research_p.add_argument("--retrieved-at", default="2026-06-19")
    research_p.add_argument("--last-taxonomy-reviewed-at", default="")

    approvals_p = sub.add_parser(
        "approvals",
        help="Manage local ActionVouch approval records without executing actions",
    )
    approvals_sub = approvals_p.add_subparsers(dest="approvals_action", required=True)
    approvals_list = approvals_sub.add_parser(
        "list", help="List approval candidates for a local audit project"
    )
    approvals_list.add_argument("project_path")
    approvals_request = approvals_sub.add_parser(
        "request", help="Create a local approval request for an action event"
    )
    approvals_request.add_argument("project_path")
    approvals_request.add_argument("--event-id", required=True)
    approvals_request.add_argument("--output", required=True)
    approvals_request.add_argument("--markdown-output", default="")
    approvals_request.add_argument("--requested-state", default="approved_draft")
    approvals_request.add_argument("--created-at", default="")
    approvals_review = approvals_sub.add_parser(
        "review", help="Review a local approval record"
    )
    approvals_review.add_argument("approval_path")
    approvals_review.add_argument(
        "--project",
        dest="project_path",
        required=True,
        help="Audit project the record is reviewed against (recomputes the live "
        "policy decision; a forged record cannot be promoted).",
    )
    approvals_review.add_argument(
        "--decision",
        choices=("approved_draft", "rejected", "blocked", "needs_evidence"),
        required=True,
    )
    approvals_review.add_argument("--reviewer", required=True)
    approvals_review.add_argument("--reviewed-at", default="")
    approvals_review.add_argument("--note", default="")
    approvals_review.add_argument("--output", default="")

    return parser


def main(argv: list[str] | None = None) -> None:
    """Standalone ActionVouch CLI entry point.

    Prints the command result as JSON and exits non-zero when a command
    reports ``valid: false``.
    """

    args = build_parser().parse_args(argv)
    payload = command_actionvouch(args)
    print(json.dumps(payload, indent=2, sort_keys=True))
    if payload.get("valid") is False:
        sys.exit(1)


if __name__ == "__main__":
    main()
