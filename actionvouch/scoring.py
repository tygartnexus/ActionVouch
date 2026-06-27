"""Evidence-backed risk scoring for ActionVouch."""

from __future__ import annotations

from .models import (
    AUTONOMY_LEVELS,
    COMPLIANCE_ACTION_CLASSES,
    DESTRUCTIVE_ACTION_CLASSES,
    HIGH_RISK_ACTION_CLASSES,
    SENSITIVE_DATA_CLASSES,
    ActionEvent,
    AgentRecord,
    AuditProject,
    RiskFinding,
    ToolRecord,
)
from .policies import evaluate_action_event


def score_project(project: AuditProject) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for agent in project.agents:
        finding = _score_agent(project, agent)
        if finding:
            findings.append(finding)
    for tool in project.tools:
        finding = _score_tool(tool)
        if finding:
            findings.append(finding)
    for event in project.action_events:
        finding = _score_event(project, event)
        if finding:
            findings.append(finding)
    return sorted(findings, key=lambda item: _severity_sort(item.severity))


def _score_agent(project: AuditProject, agent: AgentRecord) -> RiskFinding | None:
    score = 0
    facts = [
        f"Agent {agent.name} uses provider/runtime {agent.provider}/{agent.model_or_runtime}.",
        f"Agent autonomy level is {agent.autonomy_level}.",
    ]
    unknowns = list(agent.unknowns)
    risks: list[str] = []
    evidence = list(agent.evidence)

    if not agent.owner or agent.owner.lower() == "unknown":
        score += 3
        unknowns.append("Human owner is missing or unknown.")
        risks.append("Accountability is unclear if the agent acts incorrectly.")
    if any(item in SENSITIVE_DATA_CLASSES for item in agent.data_classes):
        score += 2
        risks.append("Agent can access sensitive data classes.")
    if any(item in HIGH_RISK_ACTION_CLASSES for item in agent.action_classes):
        score += 2
        risks.append("Agent is associated with high-risk action classes.")
    if agent.autonomy_level == "autonomous":
        score += 4
        risks.append(
            "Agent is marked autonomous; ActionVouch MVP treats L4 autonomous external action as blocked pending review."
        )
        unknowns.append(
            "Autonomous runtime controls, rollback, monitoring, and approval bypass protections are not verified."
        )
    elif agent.autonomy_level not in AUTONOMY_LEVELS:
        score += 2
        unknowns.append("Agent autonomy level is unsupported or unclear.")
    elif agent.autonomy_level == "act_with_approval" and not agent.approval_policy_id:
        score += 2
        unknowns.append("Act-with-approval workflow has no approval policy attached.")
    if not evidence:
        score += 2
        unknowns.append("No evidence item is attached to the agent record.")
    if (
        agent.approval_policy_id
        and project.get_policy(agent.approval_policy_id) is None
    ):
        score += 2
        unknowns.append("Approval policy reference does not resolve.")

    if score < 2:
        return None
    return RiskFinding(
        finding_id=f"agent-{agent.agent_id}-risk",
        severity=_severity(score),
        title=f"Agent risk requires review: {agent.name}",
        affected_record_type="agent",
        affected_record_id=agent.agent_id,
        facts=facts,
        assumptions=[
            "Risk score is based on local inventory and attached evidence only."
        ],
        unknowns=unknowns,
        evidence=_evidence_or_gap(evidence, "agent evidence is missing"),
        risks=risks,
        counterarguments=[
            "The agent may be safe if missing owner, policy, and permission evidence is supplied."
        ],
        recommendation="Assign/confirm owner, verify tool permissions, attach evidence, and apply an approval policy.",
        tradeoffs=[
            "Tighter approval reduces speed but improves accountability for external effects."
        ],
        what_would_change_the_recommendation=[
            "Current owner signoff, verified tool permissions, and event evidence showing low-risk observe-only use."
        ],
        confidence_score=0.72 if evidence else 0.58,
        framework_mappings=_framework_mappings(
            "Gartner proportional agent governance",
            "NIST AI RMF Govern",
            "NIST AI RMF Map",
            "ISO/IEC 42001 AI management system readiness",
            (
                "OWASP Agentic Top 10 excessive agency"
                if agent.autonomy_level == "autonomous"
                else "OWASP Agentic Top 10 agent governance"
            ),
        ),
    )


def _score_tool(tool: ToolRecord) -> RiskFinding | None:
    score = 0
    facts = [
        f"Tool {tool.name} is connected to {tool.system} with {tool.permission_type} permission.",
        f"Tool connector type is {tool.connector_type}.",
    ]
    unknowns = list(tool.unknowns)
    risks: list[str] = []

    if tool.external_effect:
        score += 2
        risks.append("Tool can create external effects.")
    if any(item in SENSITIVE_DATA_CLASSES for item in tool.data_access):
        score += 2
        risks.append("Tool can access sensitive data classes.")
    if any(item in HIGH_RISK_ACTION_CLASSES for item in tool.actions_supported):
        score += 2
        risks.append("Tool supports high-risk action classes.")
    if tool.connector_type == "mcp":
        score += 2
        risks.append(
            "MCP tool surface can expose external data or actions across an agent trust boundary."
        )
        if not tool.mcp_server_id:
            unknowns.append("MCP server identity is not attached.")
    if tool.connector_type == "a2a":
        score += 2
        risks.append(
            "A2A/inter-agent communication can route work across agent boundaries that need explicit review."
        )
        if not tool.a2a_agent_card_id:
            unknowns.append("A2A agent card identity is not attached.")
    if tool.external_effect and not tool.oauth_scopes:
        score += 1
        unknowns.append(
            "OAuth/API scopes are not attached for an external-effect tool."
        )
    if "unknown" in tool.permission_type.lower():
        score += 1
        unknowns.append("Permission type is explicitly unknown pending export review.")
    if not tool.credential_owner or tool.credential_owner.lower() == "unknown":
        score += 2
        unknowns.append("Credential owner is missing or unknown.")
    if not tool.evidence:
        score += 1
        unknowns.append("No evidence item is attached to the tool record.")

    if score < 2:
        return None
    return RiskFinding(
        finding_id=f"tool-{tool.tool_id}-risk",
        severity=_severity(score),
        title=f"Tool access risk requires review: {tool.name}",
        affected_record_type="tool",
        affected_record_id=tool.tool_id,
        facts=facts,
        assumptions=[
            "Tool permissions are based on local inventory, not live API inspection."
        ],
        unknowns=unknowns,
        evidence=_evidence_or_gap(tool.evidence, "tool evidence is missing"),
        risks=risks,
        counterarguments=[
            "The access may be acceptable if scoped credentials and audit logs are verified."
        ],
        recommendation="Verify credential owner, permission scope, data classes, and approval policy.",
        tradeoffs=[
            "Reducing permissions may require workflow changes or narrower automation roles."
        ],
        what_would_change_the_recommendation=[
            "A current permission export proving least-privilege access and named credential ownership."
        ],
        confidence_score=0.7 if tool.evidence else 0.56,
        framework_mappings=_tool_framework_mappings(tool),
    )


def _score_event(project: AuditProject, event: ActionEvent) -> RiskFinding | None:
    decision = evaluate_action_event(project, event)
    agent = project.get_agent(event.agent_id)
    score = 0
    facts = [f"Action event {event.event_id} requested {event.action_class}."]
    unknowns = list(event.unknowns)
    risks: list[str] = []

    if event.action_class in HIGH_RISK_ACTION_CLASSES:
        score += 2
        risks.append(
            "Action class can affect customers, records, files, finances, compliance, or external systems."
        )
    if event.action_class in DESTRUCTIVE_ACTION_CLASSES:
        score += 3
        risks.append("Action class can be destructive or financial.")
    if event.action_class in COMPLIANCE_ACTION_CLASSES:
        score += 3
        risks.append("Action class can create legal or compliance exposure.")
    if agent and agent.autonomy_level == "autonomous":
        score += 3
        risks.append(
            "Event belongs to an autonomous agent; MVP requires blocking or explicit human review."
        )
    if decision.classification in {"blocked", "needs_review"}:
        score += 2
        risks.append(f"Policy classified the event as {decision.classification}.")
    if not event.evidence:
        score += 2
        unknowns.append("Event evidence is missing.")
    if (
        event.approval_state not in {"approved_draft", "completed_observed"}
        and event.action_class in HIGH_RISK_ACTION_CLASSES
    ):
        score += 1
        unknowns.append("High-risk event lacks completed human approval.")

    if score < 2:
        return None
    return RiskFinding(
        finding_id=f"event-{event.event_id}-risk",
        severity=_severity(score),
        title=f"Action event requires review: {event.action_class}",
        affected_record_type="action_event",
        affected_record_id=event.event_id,
        facts=facts + decision.reasons,
        assumptions=[
            "Event risk is scored from local event records and policy decisions only."
        ],
        unknowns=unknowns,
        evidence=_evidence_or_gap(event.evidence, "event evidence is missing"),
        risks=risks,
        counterarguments=[
            "The event may be acceptable if human approval and supporting evidence are supplied."
        ],
        recommendation="Keep the action in draft/review until policy, evidence, and human approval are complete.",
        tradeoffs=[
            "Blocking action may slow operations but prevents unsupported external effects."
        ],
        what_would_change_the_recommendation=[
            "Verified approver, complete evidence pack, and a policy decision changing to approved_draft."
        ],
        confidence_score=max(
            0.5,
            min(0.9, decision.confidence_score - (0.1 if not event.evidence else 0.0)),
        ),
        framework_mappings=_event_framework_mappings(event),
    )


def _severity(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _severity_sort(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)


def _evidence_or_gap(evidence: list[str], reason: str) -> list[str]:
    return evidence or [f"missing_evidence:{reason}"]


def _framework_mappings(*items: str) -> list[str]:
    return sorted({item for item in items if item})


def _tool_framework_mappings(tool: ToolRecord) -> list[str]:
    mappings = [
        "NIST AI RMF Map",
        "NIST AI RMF Measure",
        "OWASP Agentic Top 10 tool misuse",
        "ISO/IEC 42001 AI management system readiness",
    ]
    if tool.connector_type == "mcp":
        mappings.extend(
            [
                "Model Context Protocol tool safety",
                "NSA MCP security design considerations",
            ]
        )
    if tool.connector_type == "a2a":
        mappings.append("Google A2A inter-agent interoperability risk")
    if tool.external_effect:
        mappings.append("Gartner act-with-approval governance")
    return _framework_mappings(*mappings)


def _event_framework_mappings(event: ActionEvent) -> list[str]:
    mappings = [
        "NIST AI RMF Manage",
        "OWASP Agentic Top 10 excessive agency",
        "Gartner proportional agent governance",
    ]
    if event.action_class in COMPLIANCE_ACTION_CLASSES:
        mappings.extend(["FTC AI claim substantiation", "EU AI Act risk-based review"])
    if event.action_class in DESTRUCTIVE_ACTION_CLASSES:
        mappings.append("OWASP Agentic Top 10 cascading failures")
    return _framework_mappings(*mappings)
