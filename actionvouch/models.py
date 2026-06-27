"""Data models for the local-first ActionVouch MVP."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .response_quality import normalize_response_mode

ACTION_CLASSES = {
    "observe",
    "draft",
    "customer_message",
    "crm_write",
    "file_share",
    "file_delete",
    "finance_action",
    "payment_refund",
    "public_publish",
    "compliance_sensitive_claim",
    "legal_sensitive_claim",
    "support_response",
    "external_api_call",
}

APPROVAL_STATES = {
    "proposed",
    "blocked",
    "needs_review",
    "approved_draft",
    "rejected",
    "completed_observed",
}

RISK_LEVELS = {"low", "medium", "high", "critical", "unknown"}

AUTONOMY_LEVELS = {"observe", "advise", "act_with_approval", "autonomous"}

AUTONOMY_ALIASES = {
    "l1": "observe",
    "read_only": "observe",
    "read-only": "observe",
    "observe_only": "observe",
    "observe-only": "observe",
    "l2": "advise",
    "draft": "advise",
    "recommend": "advise",
    "l3": "act_with_approval",
    "approval_required": "act_with_approval",
    "human_approval": "act_with_approval",
    "human-in-the-loop": "act_with_approval",
    "human_in_the_loop": "act_with_approval",
    "l4": "autonomous",
    "auto": "autonomous",
    "fully_autonomous": "autonomous",
}

CONNECTOR_TYPES = {
    "manual",
    "zapier",
    "n8n",
    "make",
    "crm",
    "crm_automation",
    "workspace_ai",
    "mcp",
    "a2a",
    "hubspot",
    "google_workspace",
    "microsoft_365",
    "support_workflow_notes",
    "unknown",
}

EVIDENCE_TYPES = {
    "local_file",
    "source_registry",
    "owner_statement",
    "repo_scan",
    "action_event",
    "manual_note",
    "missing_evidence",
}

SENSITIVE_DATA_CLASSES = {
    "customer_pii",
    "financial",
    "health",
    "credentials",
    "legal",
    "payment",
    "employee",
}

HIGH_RISK_ACTION_CLASSES = {
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

DESTRUCTIVE_ACTION_CLASSES = {"file_delete", "payment_refund", "finance_action"}

COMPLIANCE_ACTION_CLASSES = {"compliance_sensitive_claim", "legal_sensitive_claim"}


class ValidationError(ValueError):
    """Raised when ActionVouch input fails closed validation."""


def ensure_string(value: Any, field_name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string")
    return value.strip()


def ensure_string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError(f"{field_name} must be a list")
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValidationError(f"{field_name}[{index}] must be a string")
        if item.strip():
            items.append(item.strip())
    return items


def require(value: str, field_name: str, errors: list[str]) -> None:
    if not value:
        errors.append(f"{field_name} is required")


def _float_between(value: Any, field_name: str) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field_name} must be a number between 0 and 1") from exc
    if not 0.0 <= score <= 1.0:
        raise ValidationError(f"{field_name} must be between 0 and 1")
    return score


def normalize_autonomy_level(value: Any, action_classes: list[str]) -> str:
    text = ensure_string(value, "autonomy_level").lower()
    if text:
        canonical = AUTONOMY_ALIASES.get(text, text)
        return canonical
    return infer_autonomy_level(action_classes)


def infer_autonomy_level(action_classes: list[str]) -> str:
    actions = set(action_classes)
    if actions <= {"observe"}:
        return "observe"
    if actions <= {"observe", "draft"}:
        return "advise"
    return "act_with_approval"


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    source_type: str
    summary: str
    source_ref: str = ""
    limitation: str = ""
    confidence: float = 0.5
    collected_at: str = ""
    reviewer: str = ""
    satisfies: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceItem":
        return cls(
            evidence_id=ensure_string(data.get("evidence_id"), "evidence_id"),
            source_type=ensure_string(data.get("source_type"), "source_type"),
            summary=ensure_string(data.get("summary"), "summary"),
            source_ref=ensure_string(data.get("source_ref", ""), "source_ref"),
            limitation=ensure_string(data.get("limitation", ""), "limitation"),
            confidence=_float_between(data.get("confidence", 0.5), "confidence"),
            collected_at=ensure_string(data.get("collected_at", ""), "collected_at"),
            reviewer=ensure_string(data.get("reviewer", ""), "reviewer"),
            satisfies=ensure_string_list(data.get("satisfies"), "satisfies"),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        require(self.evidence_id, "evidence_id", errors)
        require(self.source_type, "source_type", errors)
        require(self.summary, "summary", errors)
        if self.source_type and self.source_type not in EVIDENCE_TYPES:
            errors.append(
                f"{self.evidence_id}: unsupported evidence source_type {self.source_type}"
            )
        if self.source_type != "missing_evidence" and not self.source_ref:
            errors.append(
                f"{self.evidence_id}: source_ref is required unless source_type is missing_evidence"
            )
        if self.source_type == "missing_evidence" and not self.limitation:
            errors.append(
                f"{self.evidence_id}: missing evidence must explain the limitation"
            )
        if self.source_type == "missing_evidence" and self.satisfies:
            errors.append(
                f"{self.evidence_id}: missing evidence cannot satisfy policy evidence requirements"
            )
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "summary": self.summary,
            "limitation": self.limitation,
            "confidence": self.confidence,
            "collected_at": self.collected_at,
            "reviewer": self.reviewer,
            "satisfies": self.satisfies,
        }


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    name: str
    owner: str
    business_purpose: str
    provider: str
    model_or_runtime: str
    tools: list[str]
    data_classes: list[str]
    action_classes: list[str]
    autonomy_level: str
    risk_level: str
    approval_policy_id: str
    status: str
    last_reviewed_at: str = ""
    evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentRecord":
        action_classes = ensure_string_list(
            data.get("action_classes"), "action_classes"
        )
        return cls(
            agent_id=ensure_string(data.get("agent_id"), "agent_id"),
            name=ensure_string(data.get("name"), "name"),
            owner=ensure_string(data.get("owner"), "owner"),
            business_purpose=ensure_string(
                data.get("business_purpose"), "business_purpose"
            ),
            provider=ensure_string(data.get("provider"), "provider"),
            model_or_runtime=ensure_string(
                data.get("model_or_runtime"), "model_or_runtime"
            ),
            tools=ensure_string_list(data.get("tools"), "tools"),
            data_classes=ensure_string_list(data.get("data_classes"), "data_classes"),
            action_classes=action_classes,
            autonomy_level=normalize_autonomy_level(
                data.get("autonomy_level", ""), action_classes
            ),
            risk_level=ensure_string(data.get("risk_level", "unknown"), "risk_level"),
            approval_policy_id=ensure_string(
                data.get("approval_policy_id"), "approval_policy_id"
            ),
            status=ensure_string(data.get("status", "unknown"), "status"),
            last_reviewed_at=ensure_string(
                data.get("last_reviewed_at", ""), "last_reviewed_at"
            ),
            evidence=ensure_string_list(data.get("evidence"), "evidence"),
            unknowns=ensure_string_list(data.get("unknowns"), "unknowns"),
        )

    def validate(
        self, *, tool_ids: set[str], policy_ids: set[str], evidence_ids: set[str]
    ) -> list[str]:
        errors: list[str] = []
        prefix = f"agent {self.agent_id or '<missing>'}"
        require(self.agent_id, f"{prefix}: agent_id", errors)
        require(self.name, f"{prefix}: name", errors)
        require(self.owner, f"{prefix}: owner", errors)
        require(self.business_purpose, f"{prefix}: business_purpose", errors)
        require(self.provider, f"{prefix}: provider", errors)
        require(self.model_or_runtime, f"{prefix}: model_or_runtime", errors)
        if self.risk_level not in RISK_LEVELS:
            errors.append(f"{prefix}: unsupported risk_level {self.risk_level}")
        if self.autonomy_level not in AUTONOMY_LEVELS:
            errors.append(f"{prefix}: unsupported autonomy_level {self.autonomy_level}")
        if not self.tools:
            errors.append(
                f"{prefix}: at least one tool or explicit unknown tool is required"
            )
        if not self.data_classes:
            errors.append(f"{prefix}: at least one data class is required")
        if not self.action_classes:
            errors.append(f"{prefix}: at least one action class is required")
        for tool_id in self.tools:
            if tool_id != "unknown" and tool_id not in tool_ids:
                errors.append(f"{prefix}: unknown tool reference {tool_id}")
        for action_class in self.action_classes:
            if action_class not in ACTION_CLASSES:
                errors.append(f"{prefix}: unsupported action_class {action_class}")
        if self.approval_policy_id and self.approval_policy_id not in policy_ids:
            errors.append(
                f"{prefix}: unknown approval_policy_id {self.approval_policy_id}"
            )
        for evidence_id in self.evidence:
            if evidence_id not in evidence_ids:
                errors.append(f"{prefix}: unknown evidence reference {evidence_id}")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "owner": self.owner,
            "business_purpose": self.business_purpose,
            "provider": self.provider,
            "model_or_runtime": self.model_or_runtime,
            "tools": self.tools,
            "data_classes": self.data_classes,
            "action_classes": self.action_classes,
            "autonomy_level": self.autonomy_level,
            "risk_level": self.risk_level,
            "approval_policy_id": self.approval_policy_id,
            "status": self.status,
            "last_reviewed_at": self.last_reviewed_at,
            "evidence": self.evidence,
            "unknowns": self.unknowns,
        }


@dataclass(frozen=True)
class ToolRecord:
    tool_id: str
    name: str
    system: str
    permission_type: str
    data_access: list[str]
    actions_supported: list[str]
    external_effect: bool
    credential_owner: str
    risk_level: str
    notes: str = ""
    connector_type: str = "manual"
    oauth_scopes: list[str] = field(default_factory=list)
    mcp_server_id: str = ""
    a2a_agent_card_id: str = ""
    evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolRecord":
        return cls(
            tool_id=ensure_string(data.get("tool_id"), "tool_id"),
            name=ensure_string(data.get("name"), "name"),
            system=ensure_string(data.get("system"), "system"),
            permission_type=ensure_string(
                data.get("permission_type"), "permission_type"
            ),
            data_access=ensure_string_list(data.get("data_access"), "data_access"),
            actions_supported=ensure_string_list(
                data.get("actions_supported"), "actions_supported"
            ),
            external_effect=bool(data.get("external_effect", False)),
            credential_owner=ensure_string(
                data.get("credential_owner"), "credential_owner"
            ),
            risk_level=ensure_string(data.get("risk_level", "unknown"), "risk_level"),
            notes=ensure_string(data.get("notes", ""), "notes"),
            connector_type=ensure_string(
                data.get("connector_type", "manual"), "connector_type"
            )
            or "manual",
            oauth_scopes=ensure_string_list(data.get("oauth_scopes"), "oauth_scopes"),
            mcp_server_id=ensure_string(data.get("mcp_server_id", ""), "mcp_server_id"),
            a2a_agent_card_id=ensure_string(
                data.get("a2a_agent_card_id", ""), "a2a_agent_card_id"
            ),
            evidence=ensure_string_list(data.get("evidence"), "evidence"),
            unknowns=ensure_string_list(data.get("unknowns"), "unknowns"),
        )

    def validate(self, *, evidence_ids: set[str]) -> list[str]:
        errors: list[str] = []
        prefix = f"tool {self.tool_id or '<missing>'}"
        require(self.tool_id, f"{prefix}: tool_id", errors)
        require(self.name, f"{prefix}: name", errors)
        require(self.system, f"{prefix}: system", errors)
        require(self.permission_type, f"{prefix}: permission_type", errors)
        if not self.data_access:
            errors.append(f"{prefix}: data_access is required")
        if not self.actions_supported:
            errors.append(f"{prefix}: actions_supported is required")
        if not self.credential_owner:
            errors.append(
                f"{prefix}: credential_owner is required or must be explicit unknown"
            )
        if self.risk_level not in RISK_LEVELS:
            errors.append(f"{prefix}: unsupported risk_level {self.risk_level}")
        if self.connector_type not in CONNECTOR_TYPES:
            errors.append(f"{prefix}: unsupported connector_type {self.connector_type}")
        if self.connector_type == "mcp" and not self.mcp_server_id:
            errors.append(f"{prefix}: mcp_server_id is required for MCP tools")
        if self.connector_type == "a2a" and not self.a2a_agent_card_id:
            errors.append(f"{prefix}: a2a_agent_card_id is required for A2A tools")
        for action_class in self.actions_supported:
            if action_class not in ACTION_CLASSES:
                errors.append(f"{prefix}: unsupported action_class {action_class}")
        for evidence_id in self.evidence:
            if evidence_id not in evidence_ids:
                errors.append(f"{prefix}: unknown evidence reference {evidence_id}")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "system": self.system,
            "permission_type": self.permission_type,
            "data_access": self.data_access,
            "actions_supported": self.actions_supported,
            "external_effect": self.external_effect,
            "credential_owner": self.credential_owner,
            "risk_level": self.risk_level,
            "notes": self.notes,
            "connector_type": self.connector_type,
            "oauth_scopes": self.oauth_scopes,
            "mcp_server_id": self.mcp_server_id,
            "a2a_agent_card_id": self.a2a_agent_card_id,
            "evidence": self.evidence,
            "unknowns": self.unknowns,
        }


@dataclass(frozen=True)
class PolicyRule:
    policy_id: str
    name: str
    applies_to: list[str]
    blocked_actions: list[str]
    approval_required_actions: list[str]
    allowed_actions: list[str]
    evidence_required: list[str]
    human_owner_required: bool = True
    retention_requirement: str = "local_audit_record"
    review_cadence: str = "quarterly"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyRule":
        return cls(
            policy_id=ensure_string(data.get("policy_id"), "policy_id"),
            name=ensure_string(data.get("name"), "name"),
            applies_to=ensure_string_list(data.get("applies_to"), "applies_to"),
            blocked_actions=ensure_string_list(
                data.get("blocked_actions"), "blocked_actions"
            ),
            approval_required_actions=ensure_string_list(
                data.get("approval_required_actions"), "approval_required_actions"
            ),
            allowed_actions=ensure_string_list(
                data.get("allowed_actions"), "allowed_actions"
            ),
            evidence_required=ensure_string_list(
                data.get("evidence_required"), "evidence_required"
            ),
            human_owner_required=bool(data.get("human_owner_required", True)),
            retention_requirement=ensure_string(
                data.get("retention_requirement", "local_audit_record"),
                "retention_requirement",
            ),
            review_cadence=ensure_string(
                data.get("review_cadence", "quarterly"), "review_cadence"
            ),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        prefix = f"policy {self.policy_id or '<missing>'}"
        require(self.policy_id, f"{prefix}: policy_id", errors)
        require(self.name, f"{prefix}: name", errors)
        if not (
            self.blocked_actions
            or self.approval_required_actions
            or self.allowed_actions
        ):
            errors.append(f"{prefix}: at least one action list is required")
        for group_name, action_group in (
            ("blocked_actions", self.blocked_actions),
            ("approval_required_actions", self.approval_required_actions),
            ("allowed_actions", self.allowed_actions),
        ):
            for action_class in action_group:
                if action_class not in ACTION_CLASSES:
                    errors.append(
                        f"{prefix}: {group_name} has unsupported action_class {action_class}"
                    )
        if set(self.allowed_actions) & set(self.blocked_actions):
            errors.append(f"{prefix}: action cannot be both allowed and blocked")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "applies_to": self.applies_to,
            "blocked_actions": self.blocked_actions,
            "approval_required_actions": self.approval_required_actions,
            "allowed_actions": self.allowed_actions,
            "evidence_required": self.evidence_required,
            "human_owner_required": self.human_owner_required,
            "retention_requirement": self.retention_requirement,
            "review_cadence": self.review_cadence,
        }


@dataclass(frozen=True)
class ActionEvent:
    event_id: str
    agent_id: str
    timestamp: str
    request_summary: str
    action_class: str
    action_payload_summary: str
    approval_state: str
    outcome: str
    tool_called: str = ""
    policy_id: str = ""
    approver: str = ""
    enhanced_prompt_hash: str = ""
    retrieved_sources: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionEvent":
        return cls(
            event_id=ensure_string(data.get("event_id"), "event_id"),
            agent_id=ensure_string(data.get("agent_id"), "agent_id"),
            timestamp=ensure_string(data.get("timestamp"), "timestamp"),
            request_summary=ensure_string(
                data.get("request_summary"), "request_summary"
            ),
            action_class=ensure_string(data.get("action_class"), "action_class"),
            action_payload_summary=ensure_string(
                data.get("action_payload_summary"), "action_payload_summary"
            ),
            approval_state=ensure_string(
                data.get("approval_state", "proposed"), "approval_state"
            ),
            outcome=ensure_string(data.get("outcome", "not_executed"), "outcome"),
            tool_called=ensure_string(data.get("tool_called", ""), "tool_called"),
            policy_id=ensure_string(data.get("policy_id", ""), "policy_id"),
            approver=ensure_string(data.get("approver", ""), "approver"),
            enhanced_prompt_hash=ensure_string(
                data.get("enhanced_prompt_hash", ""), "enhanced_prompt_hash"
            ),
            retrieved_sources=ensure_string_list(
                data.get("retrieved_sources"), "retrieved_sources"
            ),
            risk_flags=ensure_string_list(data.get("risk_flags"), "risk_flags"),
            evidence=ensure_string_list(data.get("evidence"), "evidence"),
            unknowns=ensure_string_list(data.get("unknowns"), "unknowns"),
        )

    def validate(
        self,
        *,
        agent_ids: set[str],
        tool_ids: set[str],
        policy_ids: set[str],
        evidence_ids: set[str],
    ) -> list[str]:
        errors: list[str] = []
        prefix = f"action_event {self.event_id or '<missing>'}"
        require(self.event_id, f"{prefix}: event_id", errors)
        require(self.agent_id, f"{prefix}: agent_id", errors)
        require(self.timestamp, f"{prefix}: timestamp", errors)
        require(self.request_summary, f"{prefix}: request_summary", errors)
        require(
            self.action_payload_summary, f"{prefix}: action_payload_summary", errors
        )
        if self.agent_id and self.agent_id not in agent_ids:
            errors.append(f"{prefix}: unknown agent_id {self.agent_id}")
        if self.tool_called and self.tool_called not in tool_ids:
            errors.append(f"{prefix}: unknown tool_called {self.tool_called}")
        if self.policy_id and self.policy_id not in policy_ids:
            errors.append(f"{prefix}: unknown policy_id {self.policy_id}")
        if self.action_class not in ACTION_CLASSES:
            errors.append(f"{prefix}: unsupported action_class {self.action_class}")
        if self.approval_state not in APPROVAL_STATES:
            errors.append(f"{prefix}: unsupported approval_state {self.approval_state}")
        for evidence_id in self.evidence:
            if evidence_id not in evidence_ids:
                errors.append(f"{prefix}: unknown evidence reference {evidence_id}")
        if not self.evidence:
            errors.append(
                f"{prefix}: evidence or explicit missing_evidence reference is required"
            )
        if self.approval_state == "approved_draft" and not self.approver:
            errors.append(f"{prefix}: approved_draft requires approver")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "request_summary": self.request_summary,
            "enhanced_prompt_hash": self.enhanced_prompt_hash,
            "retrieved_sources": self.retrieved_sources,
            "tool_called": self.tool_called,
            "action_class": self.action_class,
            "action_payload_summary": self.action_payload_summary,
            "policy_id": self.policy_id,
            "approval_state": self.approval_state,
            "approver": self.approver,
            "outcome": self.outcome,
            "risk_flags": self.risk_flags,
            "evidence": self.evidence,
            "unknowns": self.unknowns,
        }


@dataclass(frozen=True)
class RiskFinding:
    finding_id: str
    severity: str
    title: str
    affected_record_type: str
    affected_record_id: str
    facts: list[str]
    assumptions: list[str]
    unknowns: list[str]
    evidence: list[str]
    risks: list[str]
    counterarguments: list[str]
    recommendation: str
    tradeoffs: list[str]
    what_would_change_the_recommendation: list[str]
    confidence_score: float
    framework_mappings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "title": self.title,
            "affected_record_type": self.affected_record_type,
            "affected_record_id": self.affected_record_id,
            "facts": self.facts,
            "assumptions": self.assumptions,
            "unknowns": self.unknowns,
            "evidence": self.evidence,
            "risks": self.risks,
            "counterarguments": self.counterarguments,
            "recommendation": self.recommendation,
            "tradeoffs": self.tradeoffs,
            "what_would_change_the_recommendation": self.what_would_change_the_recommendation,
            "confidence_score": self.confidence_score,
            "framework_mappings": self.framework_mappings,
        }


@dataclass(frozen=True)
class CapabilitySignal:
    signal_id: str
    source: str
    source_url: str
    publisher: str
    published_at: str
    retrieved_at: str
    capability_area: str
    change_summary: str
    affected_product_area: str
    risk_impact: str
    action_required: str
    confidence: float
    evidence_status: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CapabilitySignal":
        return cls(
            signal_id=ensure_string(data.get("signal_id"), "signal_id"),
            source=ensure_string(data.get("source"), "source"),
            source_url=ensure_string(data.get("source_url"), "source_url"),
            publisher=ensure_string(data.get("publisher"), "publisher"),
            published_at=ensure_string(data.get("published_at"), "published_at"),
            retrieved_at=ensure_string(data.get("retrieved_at"), "retrieved_at"),
            capability_area=ensure_string(
                data.get("capability_area"), "capability_area"
            ),
            change_summary=ensure_string(data.get("change_summary"), "change_summary"),
            affected_product_area=ensure_string(
                data.get("affected_product_area"), "affected_product_area"
            ),
            risk_impact=ensure_string(data.get("risk_impact"), "risk_impact"),
            action_required=ensure_string(
                data.get("action_required"), "action_required"
            ),
            confidence=_float_between(data.get("confidence", 0.5), "confidence"),
            evidence_status=ensure_string(
                data.get("evidence_status"), "evidence_status"
            ),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        prefix = f"capability_signal {self.signal_id or '<missing>'}"
        require(self.signal_id, f"{prefix}: signal_id", errors)
        require(self.source, f"{prefix}: source", errors)
        require(self.source_url, f"{prefix}: source_url", errors)
        require(self.publisher, f"{prefix}: publisher", errors)
        require(self.published_at, f"{prefix}: published_at", errors)
        require(self.retrieved_at, f"{prefix}: retrieved_at", errors)
        require(self.capability_area, f"{prefix}: capability_area", errors)
        require(self.change_summary, f"{prefix}: change_summary", errors)
        require(self.affected_product_area, f"{prefix}: affected_product_area", errors)
        require(self.risk_impact, f"{prefix}: risk_impact", errors)
        require(self.action_required, f"{prefix}: action_required", errors)
        require(self.evidence_status, f"{prefix}: evidence_status", errors)
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "source": self.source,
            "source_url": self.source_url,
            "publisher": self.publisher,
            "published_at": self.published_at,
            "retrieved_at": self.retrieved_at,
            "capability_area": self.capability_area,
            "change_summary": self.change_summary,
            "affected_product_area": self.affected_product_area,
            "risk_impact": self.risk_impact,
            "action_required": self.action_required,
            "confidence": self.confidence,
            "evidence_status": self.evidence_status,
        }


@dataclass(frozen=True)
class AuditProject:
    project_id: str
    name: str
    version: str
    created_at: str
    updated_at: str
    scope: str
    agents: list[AgentRecord]
    tools: list[ToolRecord]
    policies: list[PolicyRule]
    action_events: list[ActionEvent]
    evidence: list[EvidenceItem]
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    capability_signals: list[CapabilitySignal] = field(default_factory=list)
    response_mode: str = "evidence_based_answer"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditProject":
        return cls(
            project_id=ensure_string(data.get("project_id"), "project_id"),
            name=ensure_string(data.get("name"), "name"),
            version=ensure_string(
                data.get("version", "actionvouch.audit_project.v1"), "version"
            ),
            created_at=ensure_string(data.get("created_at", ""), "created_at"),
            updated_at=ensure_string(data.get("updated_at", ""), "updated_at"),
            scope=ensure_string(data.get("scope", ""), "scope"),
            agents=[AgentRecord.from_dict(item) for item in data.get("agents", [])],
            tools=[ToolRecord.from_dict(item) for item in data.get("tools", [])],
            policies=[PolicyRule.from_dict(item) for item in data.get("policies", [])],
            action_events=[
                ActionEvent.from_dict(item) for item in data.get("action_events", [])
            ],
            evidence=[
                EvidenceItem.from_dict(item) for item in data.get("evidence", [])
            ],
            assumptions=ensure_string_list(data.get("assumptions"), "assumptions"),
            unknowns=ensure_string_list(data.get("unknowns"), "unknowns"),
            capability_signals=[
                CapabilitySignal.from_dict(item)
                for item in data.get("capability_signals", [])
            ],
            response_mode=normalize_response_mode(
                data.get("response_mode", "evidence_based_answer")
            ).value,
        )

    def ids(self) -> dict[str, set[str]]:
        return {
            "agents": {item.agent_id for item in self.agents},
            "tools": {item.tool_id for item in self.tools},
            "policies": {item.policy_id for item in self.policies},
            "evidence": {item.evidence_id for item in self.evidence},
            "events": {item.event_id for item in self.action_events},
        }

    def validate(self) -> list[str]:
        errors: list[str] = []
        require(self.project_id, "project_id", errors)
        require(self.name, "name", errors)
        require(self.version, "version", errors)
        require(self.scope, "scope", errors)
        if not self.agents:
            errors.append("at least one agent record is required")
        ids = self.ids()
        for group_name, values in ids.items():
            if len(values) != len(getattr(self, _attribute_for_group(group_name))):
                errors.append(f"duplicate {group_name} id detected")
        for evidence_item in self.evidence:
            errors.extend(evidence_item.validate())
        for policy in self.policies:
            errors.extend(policy.validate())
        for tool in self.tools:
            errors.extend(tool.validate(evidence_ids=ids["evidence"]))
        for agent in self.agents:
            errors.extend(
                agent.validate(
                    tool_ids=ids["tools"],
                    policy_ids=ids["policies"],
                    evidence_ids=ids["evidence"],
                )
            )
        for event in self.action_events:
            errors.extend(
                event.validate(
                    agent_ids=ids["agents"],
                    tool_ids=ids["tools"],
                    policy_ids=ids["policies"],
                    evidence_ids=ids["evidence"],
                )
            )
        for signal in self.capability_signals:
            errors.extend(signal.validate())
        return errors

    def get_agent(self, agent_id: str) -> AgentRecord | None:
        return next((item for item in self.agents if item.agent_id == agent_id), None)

    def get_tool(self, tool_id: str) -> ToolRecord | None:
        return next((item for item in self.tools if item.tool_id == tool_id), None)

    def get_policy(self, policy_id: str) -> PolicyRule | None:
        return next(
            (item for item in self.policies if item.policy_id == policy_id), None
        )

    def get_evidence(self, evidence_id: str) -> EvidenceItem | None:
        return next(
            (item for item in self.evidence if item.evidence_id == evidence_id), None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "scope": self.scope,
            "agents": [item.to_dict() for item in self.agents],
            "tools": [item.to_dict() for item in self.tools],
            "policies": [item.to_dict() for item in self.policies],
            "action_events": [item.to_dict() for item in self.action_events],
            "evidence": [item.to_dict() for item in self.evidence],
            "assumptions": self.assumptions,
            "unknowns": self.unknowns,
            "capability_signals": [item.to_dict() for item in self.capability_signals],
            "response_mode": self.response_mode,
        }


def _attribute_for_group(group_name: str) -> str:
    return {
        "agents": "agents",
        "tools": "tools",
        "policies": "policies",
        "evidence": "evidence",
        "events": "action_events",
    }[group_name]
