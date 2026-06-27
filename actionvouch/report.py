"""Report generation for ActionVouch audits."""

from __future__ import annotations

import json
from html import escape as _html_escape
from typing import Any

from .response_quality import (
    REQUIRED_SECTIONS,
    build_quality_contract,
    normalize_response_mode,
)
from .models import AuditProject, RiskFinding
from .permissions import build_permission_graph
from .policies import evaluate_action_event
from .scoring import score_project


def _md(value: object) -> str:
    """Neutralize HTML so user-controlled text cannot inject markup when the
    markdown is rendered to HTML (GitHub, IDE preview, Obsidian, etc.).

    Escaping ``&<>`` is sufficient to defeat tag injection in every markdown
    position (plain text and code spans alike): even a value that breaks out of
    a backtick span lands among already-escaped angle brackets, so no element is
    ever produced. A stray backtick can still disturb formatting (cosmetic), but
    not execute markup.
    """

    return _html_escape(str(value), quote=False)


def build_report(project: AuditProject) -> dict[str, Any]:
    errors = project.validate()
    response_mode = normalize_response_mode(project.response_mode)
    quality_contract = build_quality_contract(response_mode)
    findings = score_project(project) if not errors else []
    policy_decisions = (
        [
            evaluate_action_event(project, event).to_dict()
            for event in project.action_events
        ]
        if not errors
        else []
    )
    status = "invalid" if errors else "review_ready"
    top_findings = findings[:5]
    evidence_gap_count = _evidence_gap_count(project, findings)
    confidence = _confidence(project, findings, errors)
    permission_graph = build_permission_graph(project) if not errors else None

    sections = {
        "Facts": _facts(project),
        "Assumptions": project.assumptions
        or [
            "Audit conclusions are based on local records and fixture/import evidence only."
        ],
        "Unknowns": _unknowns(project, findings, errors),
        "Confidence score": [f"{confidence:.2f}"],
        "Evidence": _evidence_lines(project),
        "Risks": _risk_lines(top_findings),
        "Counterarguments": _counterargument_lines(top_findings),
        "Recommendation": _recommendation_lines(top_findings, errors),
        "Tradeoffs": _tradeoff_lines(top_findings),
        "What would change the recommendation": _change_condition_lines(top_findings),
    }

    return {
        "product": "ActionVouch",
        "report_version": "actionvouch.report.v1",
        "status": status,
        "project": {
            "project_id": project.project_id,
            "name": project.name,
            "scope": project.scope,
            "version": project.version,
            "response_mode": response_mode.value,
        },
        "response_quality": quality_contract.to_dict(),
        "summary": {
            "agent_count": len(project.agents),
            "tool_count": len(project.tools),
            "action_event_count": len(project.action_events),
            "policy_count": len(project.policies),
            "evidence_count": len(project.evidence),
            "risk_finding_count": len(findings),
            "evidence_gap_count": evidence_gap_count,
            "confidence_score": confidence,
            "autonomy_counts": _autonomy_counts(project),
            "protocol_counts": _protocol_counts(project),
            "response_mode": response_mode.value,
            "response_mode_label": quality_contract.to_dict()["ui_label"],
            "permission_graph": (
                permission_graph["summary"]
                if permission_graph
                else {
                    "node_count": 0,
                    "edge_count": 0,
                    "high_risk_path_count": 0,
                    "missing_evidence_edge_count": 0,
                }
            ),
        },
        "validation_errors": errors,
        "required_sections": list(REQUIRED_SECTIONS),
        "sections": sections,
        "policy_decisions": policy_decisions,
        "risk_findings": [finding.to_dict() for finding in findings],
        "framework_mappings": _framework_mappings(findings),
        "permission_graph": permission_graph,
        "evidence_appendix": [item.to_dict() for item in project.evidence],
        "capability_signals": [item.to_dict() for item in project.capability_signals],
        "guardrails": [
            "This report is local desk/audit output, not legal advice.",
            "This report does not certify compliance or guarantee protection.",
            "No live external action was executed by ActionVouch.",
            "Legal/compliance response mode is issue spotting, not legal advice or certification.",
        ],
    }


def render_json_report(project: AuditProject) -> str:
    return json.dumps(build_report(project), indent=2, sort_keys=True) + "\n"


def render_markdown_report(project: AuditProject) -> str:
    report = build_report(project)
    lines = [
        f"# ActionVouch Risk Audit Report: {_md(report['project']['name'])}",
        "",
        f"Status: `{report['status']}`",
        f"Confidence: `{report['summary']['confidence_score']:.2f}`",
        f"Response mode: `{report['summary']['response_mode']}` ({report['summary']['response_mode_label']})",
        "",
        "## Executive Summary",
        "",
        f"- Agents reviewed: {report['summary']['agent_count']}",
        f"- Tools reviewed: {report['summary']['tool_count']}",
        f"- Action events reviewed: {report['summary']['action_event_count']}",
        f"- Risk findings: {report['summary']['risk_finding_count']}",
        f"- Evidence gaps: {report['summary']['evidence_gap_count']}",
        f"- Autonomy levels: {_format_counts(report['summary']['autonomy_counts'])}",
        f"- Protocols/connectors: {_format_counts(report['summary']['protocol_counts'])}",
        f"- Permission graph high-risk paths: {report['summary']['permission_graph']['high_risk_path_count']}",
        "",
    ]
    if report["validation_errors"]:
        lines.extend(["## Validation Errors", ""])
        lines.extend(f"- {_md(error)}" for error in report["validation_errors"])
        lines.append("")
    for section in REQUIRED_SECTIONS:
        lines.extend([f"## {section}", ""])
        values = report["sections"].get(section, [])
        if values:
            lines.extend(f"- {_md(value)}" for value in values)
        else:
            lines.append("- None recorded.")
        lines.append("")
    if "Tradeoffs" not in REQUIRED_SECTIONS:
        lines.extend(["## Tradeoffs", ""])
        lines.extend(f"- {_md(value)}" for value in report["sections"]["Tradeoffs"])
        lines.append("")
    lines.extend(["## Policy Decisions", ""])
    for decision in report["policy_decisions"]:
        lines.append(
            f"- `{_md(decision['event_id'])}`: **{decision['classification']}** "
            f"under `{_md(decision['policy_id'])}` - "
            f"{_md('; '.join(decision['reasons']))}"
        )
    if not report["policy_decisions"]:
        lines.append("- No policy decisions generated.")
    lines.extend(["", "## Risk Findings", ""])
    for finding in report["risk_findings"]:
        affected = (
            f"{_md(finding['affected_record_type'])}:"
            f"{_md(finding['affected_record_id'])}"
        )
        lines.extend(
            [
                f"### {finding['severity'].upper()}: {_md(finding['title'])}",
                "",
                f"- Affected: `{affected}`",
                f"- Recommendation: {_md(finding['recommendation'])}",
                f"- Confidence: `{finding['confidence_score']:.2f}`",
                "- Evidence: "
                f"{_md(', '.join(finding['evidence'])) or 'missing evidence recorded'}",
                "- Tradeoffs: "
                f"{_md('; '.join(finding.get('tradeoffs', []))) or 'none'}",
                "- Framework mappings: "
                f"{_md(', '.join(finding.get('framework_mappings', []))) or 'none'}",
                "",
            ]
        )
    if not report["risk_findings"]:
        lines.append("- No risk findings generated.")
        lines.append("")
    lines.extend(["## Guardrails", ""])
    lines.extend(f"- {item}" for item in report["guardrails"])
    lines.append("")
    return "\n".join(lines)


def _facts(project: AuditProject) -> list[str]:
    return [
        f"Project {project.project_id} contains {len(project.agents)} agent records.",
        f"Project contains {len(project.tools)} tool records and {len(project.action_events)} action events.",
        f"Project contains {len(project.policies)} local policy rules and {len(project.evidence)} evidence items.",
        f"Agent autonomy levels: {_format_counts(_autonomy_counts(project))}.",
        f"Tool connector/protocol types: {_format_counts(_protocol_counts(project))}.",
    ]


def _unknowns(
    project: AuditProject, findings: list[RiskFinding], errors: list[str]
) -> list[str]:
    unknowns = list(project.unknowns)
    unknowns.extend(errors)
    for finding in findings:
        unknowns.extend(finding.unknowns)
    return unknowns or [
        "No additional unknowns were recorded in the local audit project."
    ]


def _evidence_lines(project: AuditProject) -> list[str]:
    if not project.evidence:
        return ["No evidence items attached."]
    return [
        f"{item.evidence_id}: {item.summary}"
        + (f" Limitation: {item.limitation}" if item.limitation else "")
        for item in project.evidence
    ]


def _risk_lines(findings: list[RiskFinding]) -> list[str]:
    return [f"{finding.severity}: {finding.title}" for finding in findings] or [
        "No scored risk findings were generated from the current records."
    ]


def _counterargument_lines(findings: list[RiskFinding]) -> list[str]:
    values: list[str] = []
    for finding in findings:
        values.extend(finding.counterarguments)
    return values or [
        "No counterarguments were generated because no scored findings exist."
    ]


def _recommendation_lines(findings: list[RiskFinding], errors: list[str]) -> list[str]:
    if errors:
        return ["Fix validation errors before treating this report as review-ready."]
    return [finding.recommendation for finding in findings[:5]] or [
        "Keep the project in observe-only mode and continue collecting evidence."
    ]


def _tradeoff_lines(findings: list[RiskFinding]) -> list[str]:
    values: list[str] = []
    for finding in findings[:5]:
        values.extend(finding.tradeoffs)
    return values or ["No tradeoffs were generated because no scored findings exist."]


def _change_condition_lines(findings: list[RiskFinding]) -> list[str]:
    values: list[str] = []
    for finding in findings[:5]:
        values.extend(finding.what_would_change_the_recommendation)
    return values or [
        "New evidence showing current owners, scoped tool permissions, and observe-only action posture."
    ]


def _evidence_gap_count(project: AuditProject, findings: list[RiskFinding]) -> int:
    missing_items = sum(
        1 for item in project.evidence if item.source_type == "missing_evidence"
    )
    missing_in_findings = sum(1 for finding in findings if finding.unknowns)
    return missing_items + missing_in_findings


def _confidence(
    project: AuditProject, findings: list[RiskFinding], errors: list[str]
) -> float:
    if errors:
        return 0.25
    if not project.evidence:
        return 0.4
    if not findings:
        return 0.72
    base = sum(finding.confidence_score for finding in findings) / len(findings)
    gap_penalty = min(0.25, _evidence_gap_count(project, findings) * 0.03)
    return max(0.3, min(0.9, base - gap_penalty))


def _autonomy_counts(project: AuditProject) -> dict[str, int]:
    counts: dict[str, int] = {}
    for agent in project.agents:
        counts[agent.autonomy_level] = counts.get(agent.autonomy_level, 0) + 1
    return dict(sorted(counts.items()))


def _protocol_counts(project: AuditProject) -> dict[str, int]:
    counts: dict[str, int] = {}
    for tool in project.tools:
        counts[tool.connector_type] = counts.get(tool.connector_type, 0) + 1
    return dict(sorted(counts.items()))


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in counts.items()) or "none"


def _framework_mappings(findings: list[RiskFinding]) -> list[str]:
    values: set[str] = set()
    for finding in findings:
        values.update(finding.framework_mappings)
    return sorted(values)
