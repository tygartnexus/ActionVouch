"""Third-party security and compliance readiness support for ActionVouch."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import DOCS_DIR
from .models import AuditProject
from .report import _md, build_report

DEFAULT_RELEASE_PACKET_DIR = DOCS_DIR / "actionvouch-release"


@dataclass(frozen=True)
class ComplianceControl:
    control_id: str
    name: str
    framework: str
    status: str
    evidence: list[str]
    gaps: list[str]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "framework": self.framework,
            "status": self.status,
            "evidence": self.evidence,
            "gaps": self.gaps,
            "recommendation": self.recommendation,
        }


def build_compliance_readiness_report(
    project: AuditProject, *, packet_dir: str | Path | None = None
) -> dict[str, Any]:
    """Build a readiness report without claiming certification."""

    report = build_report(project)
    packet = _resolve_packet_dir(packet_dir)
    controls = _controls(project, packet, report)
    blockers = [
        gap
        for control in controls
        for gap in control.gaps
        if control.status in {"blocked", "gap"}
    ]
    return {
        "product": "ActionVouch",
        "report_version": "actionvouch.compliance_readiness.v1",
        "status": "readiness_review",
        "certification_status": "not_certified",
        "attestation_status": "not_attested",
        "guardrails": [
            "This is a third-party audit readiness package, not a certification.",
            "SOC 2, ISO 27001, ISO 42001, HIPAA, PCI, FedRAMP, and legal compliance are not claimed.",
            "A qualified auditor, attorney, or assessor must review evidence before external claims are made.",
        ],
        "summary": {
            "control_count": len(controls),
            "passed_or_documented": sum(
                1
                for control in controls
                if control.status in {"documented", "tested_locally"}
            ),
            "gap_count": sum(1 for control in controls if control.status == "gap"),
            "blocked_count": sum(
                1 for control in controls if control.status == "blocked"
            ),
        },
        "controls": [control.to_dict() for control in controls],
        "blockers": blockers,
        "recommendation": (
            "Use this as an auditor/security-review prep packet for controlled pilots. "
            "Do not claim certification until an external assessor completes the relevant audit."
        ),
    }


def render_compliance_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# ActionVouch Security And Compliance Readiness Report",
        "",
        f"Status: `{payload['status']}`",
        f"Certification status: `{payload['certification_status']}`",
        f"Attestation status: `{payload['attestation_status']}`",
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {item}" for item in payload["guardrails"])
    lines.extend(["", "## Summary", ""])
    for key, value in payload["summary"].items():
        lines.append(f"- {key}: {_md(value)}")
    lines.extend(["", "## Controls", ""])
    for control in payload["controls"]:
        lines.extend(
            [
                f"### {_md(control['control_id'])}: {_md(control['name'])}",
                "",
                f"- Framework: {_md(control['framework'])}",
                f"- Status: {_md(control['status'])}",
                f"- Evidence: {_md(', '.join(control['evidence'])) or 'none'}",
                f"- Gaps: {_md(', '.join(control['gaps'])) or 'none'}",
                f"- Recommendation: {_md(control['recommendation'])}",
                "",
            ]
        )
    lines.extend(["## Recommendation", "", f"- {_md(payload['recommendation'])}", ""])
    return "\n".join(lines)


def _controls(
    project: AuditProject, packet_dir: Path | None, report: dict[str, Any]
) -> list[ComplianceControl]:
    docs = _packet_docs(packet_dir)
    validation_errors = project.validate()
    missing_evidence = [
        item.evidence_id
        for item in project.evidence
        if item.source_type == "missing_evidence"
    ]
    high_risk_actions = sorted(
        {
            event.action_class
            for event in project.action_events
            if event.action_class
            in {
                "customer_message",
                "crm_write",
                "file_share",
                "file_delete",
                "finance_action",
                "payment_refund",
                "public_publish",
                "compliance_sensitive_claim",
                "legal_sensitive_claim",
                "external_api_call",
            }
        }
    )
    autonomous_agents = sorted(
        agent.agent_id
        for agent in project.agents
        if agent.autonomy_level == "autonomous"
    )
    act_with_approval_agents = sorted(
        agent.agent_id
        for agent in project.agents
        if agent.autonomy_level == "act_with_approval"
    )
    mcp_tools = sorted(
        tool.tool_id for tool in project.tools if tool.connector_type == "mcp"
    )
    a2a_tools = sorted(
        tool.tool_id for tool in project.tools if tool.connector_type == "a2a"
    )
    protocol_gaps = _protocol_gaps(project)
    return [
        ComplianceControl(
            control_id="AV-GOV-001",
            name="AI governance scope and owner accountability",
            framework="NIST AI RMF Govern / ISO 42001 readiness",
            status="tested_locally" if not validation_errors else "blocked",
            evidence=[
                "project.validate",
                *[agent.agent_id for agent in project.agents],
            ],
            gaps=validation_errors,
            recommendation="Keep owner, purpose, policy, and evidence required for every agent.",
        ),
        ComplianceControl(
            control_id="AV-GOV-002",
            name="Proportional autonomy governance",
            framework="Gartner AI agent governance / NIST AI RMF Govern",
            status="blocked" if autonomous_agents else "documented",
            evidence=act_with_approval_agents,
            gaps=[
                f"Autonomous agent requires explicit blocker review: {agent_id}"
                for agent_id in autonomous_agents
            ],
            recommendation=(
                "Classify every workflow as observe, advise, act with approval, "
                "or autonomous; block autonomous external action in the MVP."
            ),
        ),
        ComplianceControl(
            control_id="AV-MAP-001",
            name="AI workflow inventory and context mapping",
            framework="NIST AI RMF Map / SOC 2 security readiness",
            status="documented" if project.agents and project.tools else "gap",
            evidence=[project.project_id],
            gaps=(
                [] if project.agents and project.tools else ["Inventory is incomplete."]
            ),
            recommendation="Maintain a current inventory of agents, tools, data classes, and action classes.",
        ),
        ComplianceControl(
            control_id="AV-MEASURE-001",
            name="Risk scoring and evidence gaps",
            framework="NIST AI RMF Measure / OWASP LLM risk readiness",
            status="tested_locally" if report["risk_findings"] else "gap",
            evidence=[finding["finding_id"] for finding in report["risk_findings"][:5]],
            gaps=[f"Missing evidence item: {item}" for item in missing_evidence],
            recommendation="Treat missing evidence as a blocker for verified claims.",
        ),
        ComplianceControl(
            control_id="AV-MANAGE-001",
            name="Human approval for high-risk actions",
            framework="NIST AI RMF Manage / SOC 2 change management readiness",
            status="documented" if high_risk_actions else "gap",
            evidence=high_risk_actions,
            gaps=(
                []
                if high_risk_actions
                else ["No representative high-risk actions were reviewed."]
            ),
            recommendation="Require human approval before external-effect actions.",
        ),
        ComplianceControl(
            control_id="AV-MCP-001",
            name="Agent protocol and tool trust boundary review",
            framework="MCP specification / NSA MCP guidance / Google A2A readiness",
            status=(
                "blocked"
                if protocol_gaps
                else ("documented" if (mcp_tools or a2a_tools) else "gap")
            ),
            evidence=[*mcp_tools, *a2a_tools],
            gaps=protocol_gaps
            or ["No MCP or A2A manifest/tool boundary evidence attached."],
            recommendation=(
                "Capture MCP server IDs, A2A agent card IDs, tool scopes, consent, "
                "and allowlist controls before treating protocol tools as verified."
            ),
        ),
        ComplianceControl(
            control_id="AV-SEC-001",
            name="Credential-free intake and data minimization",
            framework="FTC data security / SOC 2 confidentiality readiness",
            status="documented" if "redaction-guide.md" in docs else "gap",
            evidence=(
                ["docs/actionvouch-release/redaction-guide.md"]
                if "redaction-guide.md" in docs
                else []
            ),
            gaps=(
                [] if "redaction-guide.md" in docs else ["Redaction guide is missing."]
            ),
            recommendation="Continue rejecting secrets and unnecessary sensitive data from intake.",
        ),
        ComplianceControl(
            control_id="AV-IR-001",
            name="Incident response procedure",
            framework="SOC 2 security readiness / FTC data security",
            status="documented" if "incident-response-runbook.md" in docs else "gap",
            evidence=(
                ["docs/actionvouch-release/incident-response-runbook.md"]
                if "incident-response-runbook.md" in docs
                else []
            ),
            gaps=(
                []
                if "incident-response-runbook.md" in docs
                else ["Incident response runbook is missing."]
            ),
            recommendation="Run tabletop tests before scaling beyond friendly pilots.",
        ),
        ComplianceControl(
            control_id="AV-CLAIM-001",
            name="Customer-facing claim hygiene",
            framework="FTC advertising substantiation / AI marketing claims",
            status="documented" if "claim-register.md" in docs else "gap",
            evidence=(
                ["docs/actionvouch-release/claim-register.md"]
                if "claim-register.md" in docs
                else []
            ),
            gaps=[] if "claim-register.md" in docs else ["Claim register is missing."],
            recommendation="Block certification, legal-advice, live-monitoring, and ROI claims until externally verified.",
        ),
        ComplianceControl(
            control_id="AV-3PA-001",
            name="External assessor readiness",
            framework="SOC 2 / ISO 27001 / ISO 42001 readiness",
            status="blocked",
            evidence=[],
            gaps=[
                "No third-party auditor engaged.",
                "No formal SOC 2, ISO 27001, ISO 42001, HIPAA, PCI, or FedRAMP assessment completed.",
            ],
            recommendation="Prepare evidence rooms and engage the appropriate assessor only after product scope stabilizes.",
        ),
    ]


def _protocol_gaps(project: AuditProject) -> list[str]:
    gaps: list[str] = []
    for tool in project.tools:
        if tool.connector_type not in {"mcp", "a2a"}:
            continue
        label = f"tool {tool.tool_id}"
        if tool.connector_type == "mcp" and not tool.mcp_server_id:
            gaps.append(f"{label}: MCP server identity is missing.")
        if tool.connector_type == "a2a" and not tool.a2a_agent_card_id:
            gaps.append(f"{label}: A2A agent card identity is missing.")
        if not tool.oauth_scopes:
            gaps.append(f"{label}: auth scope or consent evidence is not attached.")
        if tool.unknowns:
            gaps.append(
                f"{label}: unresolved protocol boundary unknowns: "
                + "; ".join(tool.unknowns)
            )
        if not _has_non_missing_evidence(project, tool.evidence):
            gaps.append(f"{label}: non-missing protocol evidence is not attached.")
        if not _has_protocol_control_evidence(project, tool.evidence):
            gaps.append(
                f"{label}: allowlist, logging, consent, or tool-permission control evidence is missing."
            )
    return gaps


def _has_non_missing_evidence(project: AuditProject, evidence_ids: list[str]) -> bool:
    for evidence_id in evidence_ids:
        evidence = project.get_evidence(evidence_id)
        if evidence and evidence.source_type != "missing_evidence":
            return True
    return False


def _has_protocol_control_evidence(
    project: AuditProject, evidence_ids: list[str]
) -> bool:
    control_terms = {
        "tool_permissions",
        "auth_boundary",
        "consent_record",
        "allowlist",
        "audit_log",
        "logging",
    }
    for evidence_id in evidence_ids:
        evidence = project.get_evidence(evidence_id)
        if evidence is None or evidence.source_type == "missing_evidence":
            continue
        if control_terms & set(evidence.satisfies):
            return True
    return False


def _packet_docs(packet_dir: Path | None) -> set[str]:
    if not packet_dir or not packet_dir.exists():
        return set()
    return {path.name for path in packet_dir.glob("*.md")}


def _resolve_packet_dir(packet_dir: str | Path | None) -> Path:
    if not packet_dir:
        return DEFAULT_RELEASE_PACKET_DIR
    path = Path(packet_dir)
    if path.is_absolute():
        return path
    if path.as_posix() == "docs/actionvouch-release":
        return DEFAULT_RELEASE_PACKET_DIR
    return path
