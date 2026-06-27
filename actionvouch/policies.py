"""Default policy templates and deterministic policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import (
    ActionEvent,
    AuditProject,
    HIGH_RISK_ACTION_CLASSES,
    PolicyRule,
)

# Source types that are self-asserted by the operator/owner and therefore carry
# no independent verification weight.
_SELF_ATTESTATION_SOURCES = frozenset({"owner_statement", "manual_note"})

# Control-grade evidence requirements that a self-asserted owner statement or
# manual note must NOT be able to satisfy on its own.
_SELF_ATTESTATION_EXEMPT = frozenset(
    {"tool_permissions", "claim_evidence", "business_approval", "brand_approval"}
)


@dataclass(frozen=True)
class PolicyDecision:
    event_id: str
    classification: str
    policy_id: str
    reasons: list[str]
    evidence: list[str]
    confidence_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "classification": self.classification,
            "policy_id": self.policy_id,
            "reasons": self.reasons,
            "evidence": self.evidence,
            "confidence_score": self.confidence_score,
        }


def default_policy_rules() -> list[PolicyRule]:
    """Return local default policies. These are guardrails, not legal advice."""

    return [
        PolicyRule(
            policy_id="observe_only_default",
            name="Observe-only default",
            applies_to=["all_agents"],
            blocked_actions=["file_delete", "finance_action", "payment_refund"],
            approval_required_actions=sorted(
                HIGH_RISK_ACTION_CLASSES
                - {"file_delete", "finance_action", "payment_refund"}
            ),
            allowed_actions=["observe", "draft"],
            evidence_required=[
                "owner",
                "purpose",
                "tool_permissions",
                "action_summary",
            ],
            review_cadence="monthly",
        ),
        PolicyRule(
            policy_id="customer_communication_approval",
            name="Customer communication approval",
            applies_to=["customer_message", "support_response"],
            blocked_actions=[],
            approval_required_actions=["customer_message", "support_response"],
            allowed_actions=["observe", "draft"],
            evidence_required=["customer_context", "source_citations", "human_owner"],
        ),
        PolicyRule(
            policy_id="crm_write_approval",
            name="CRM write approval",
            applies_to=["crm_write"],
            blocked_actions=[],
            approval_required_actions=["crm_write"],
            allowed_actions=["observe", "draft"],
            evidence_required=["crm_record_summary", "human_owner", "change_reason"],
        ),
        PolicyRule(
            policy_id="destructive_action_block",
            name="Destructive and financial action block",
            applies_to=["file_delete", "finance_action", "payment_refund"],
            blocked_actions=["file_delete", "finance_action", "payment_refund"],
            approval_required_actions=[],
            allowed_actions=["observe", "draft"],
            evidence_required=["human_owner", "business_approval"],
            review_cadence="monthly",
        ),
        PolicyRule(
            policy_id="public_publishing_approval",
            name="Public publishing approval",
            applies_to=["public_publish"],
            blocked_actions=[],
            approval_required_actions=["public_publish"],
            allowed_actions=["observe", "draft"],
            evidence_required=["claim_evidence", "brand_approval", "human_owner"],
        ),
        PolicyRule(
            policy_id="legal_compliance_review",
            name="Legal and compliance risk review",
            applies_to=["compliance_sensitive_claim", "legal_sensitive_claim"],
            blocked_actions=[],
            approval_required_actions=[
                "compliance_sensitive_claim",
                "legal_sensitive_claim",
            ],
            allowed_actions=["observe", "draft"],
            evidence_required=["review_scope", "human_reviewer", "claim_evidence"],
            review_cadence="per_event",
        ),
    ]


def evaluate_action_event(project: AuditProject, event: ActionEvent) -> PolicyDecision:
    agent = project.get_agent(event.agent_id)
    policy_id = event.policy_id or (agent.approval_policy_id if agent else "")
    policy = project.get_policy(policy_id) if policy_id else None
    reasons: list[str] = []
    confidence = 0.82

    if agent is None:
        reasons.append(f"Agent {event.agent_id} is not registered.")
        return PolicyDecision(
            event_id=event.event_id,
            classification="blocked",
            policy_id=policy_id or "missing_policy",
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=0.9,
        )

    if agent.autonomy_level == "autonomous" and event.action_class != "observe":
        reasons.append(
            "L4 autonomous action is blocked in ActionVouch MVP pending explicit human governance review."
        )
        return PolicyDecision(
            event_id=event.event_id,
            classification="blocked",
            policy_id=policy_id or "autonomous_action_block",
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=0.9,
        )

    if policy is None:
        reasons.append(
            "No policy rule was attached or inherited; defaulting to review."
        )
        confidence = 0.64
        return PolicyDecision(
            event_id=event.event_id,
            classification="needs_review",
            policy_id=policy_id or "missing_policy",
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    if policy.human_owner_required and not agent.owner:
        reasons.append("Policy requires a human owner, but the agent owner is missing.")
        confidence = min(confidence, 0.7)
        return PolicyDecision(
            event_id=event.event_id,
            classification="blocked",
            policy_id=policy.policy_id,
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    if not event.evidence:
        reasons.append("Event has no evidence reference; defaulting to review.")
        confidence = min(confidence, 0.6)
        return PolicyDecision(
            event_id=event.event_id,
            classification="needs_review",
            policy_id=policy.policy_id,
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    if event.action_class in policy.blocked_actions:
        reasons.append(f"{event.action_class} is blocked by {policy.name}.")
        return PolicyDecision(
            event_id=event.event_id,
            classification="blocked",
            policy_id=policy.policy_id,
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    missing_required = _missing_required_evidence(project, event, policy, agent)
    if missing_required:
        reasons.append(
            "Missing required policy evidence: " + ", ".join(missing_required)
        )
        confidence = min(confidence, 0.62)
        return PolicyDecision(
            event_id=event.event_id,
            classification="needs_review",
            policy_id=policy.policy_id,
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    if event.action_class in policy.approval_required_actions:
        if event.approval_state == "approved_draft" and event.approver:
            if _identity_key(event.approver) == _identity_key(agent.owner):
                reasons.append(
                    f"{event.action_class} approval cannot be self-approved by owner {event.approver}."
                )
                classification = "needs_review"
                confidence = min(confidence, 0.62)
            else:
                reasons.append(
                    f"{event.action_class} required approval and has approver {event.approver}."
                )
                classification = "approved_draft"
        else:
            reasons.append(
                f"{event.action_class} requires human approval under {policy.name}."
            )
            classification = "needs_review"
        return PolicyDecision(
            event_id=event.event_id,
            classification=classification,
            policy_id=policy.policy_id,
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    if event.action_class in policy.allowed_actions:
        reasons.append(
            f"{event.action_class} is allowed for observe/draft use under {policy.name}."
        )
        return PolicyDecision(
            event_id=event.event_id,
            classification="allowed_observe",
            policy_id=policy.policy_id,
            reasons=reasons,
            evidence=event.evidence,
            confidence_score=confidence,
        )

    reasons.append(
        f"{event.action_class} is not listed in policy {policy.name}; defaulting to review."
    )
    return PolicyDecision(
        event_id=event.event_id,
        classification="needs_review",
        policy_id=policy.policy_id,
        reasons=reasons,
        evidence=event.evidence,
        confidence_score=0.66,
    )


def _missing_required_evidence(
    project: AuditProject,
    event: ActionEvent,
    policy: PolicyRule,
    agent: object,
) -> list[str]:
    satisfied: set[str] = set()
    agent_owner = getattr(agent, "owner", "")
    if agent_owner and agent_owner.strip().lower() != "unknown":
        satisfied.update({"owner", "human_owner"})
    if event.request_summary:
        satisfied.add("action_summary")
    if event.approver and event.approver.strip().lower() != "unknown":
        satisfied.update({"human_owner", "human_reviewer", "business_approval"})
    if event.tool_called:
        tool = project.get_tool(event.tool_called)
        if tool and _evidence_satisfies(
            project,
            tool.evidence,
            "tool_permissions",
            allow_owner_statement=False,
        ):
            satisfied.add("tool_permissions")
    for evidence_id in event.evidence:
        evidence = project.get_evidence(evidence_id)
        if not evidence or evidence.source_type == "missing_evidence":
            continue
        self_attested = evidence.source_type in _SELF_ATTESTATION_SOURCES
        for requirement in evidence.satisfies:
            if self_attested and requirement in _SELF_ATTESTATION_EXEMPT:
                # A self-asserted note cannot satisfy a control-grade requirement.
                continue
            satisfied.add(requirement)
    return [
        requirement
        for requirement in policy.evidence_required
        if requirement not in satisfied
    ]


def _evidence_satisfies(
    project: AuditProject,
    evidence_ids: list[str],
    requirement: str,
    *,
    allow_owner_statement: bool,
) -> bool:
    for evidence_id in evidence_ids:
        evidence = project.get_evidence(evidence_id)
        if evidence is None or evidence.source_type == "missing_evidence":
            continue
        if not allow_owner_statement and evidence.source_type in {
            "owner_statement",
            "manual_note",
        }:
            continue
        if requirement in evidence.satisfies:
            return True
    return False


def _identity_key(value: str) -> str:
    """Normalize a person/owner name for identity comparison.

    Reduces to lowercase alphanumerics so ``Jane Doe``, ``jane  doe`` (double
    space), and ``Jane Doe.`` all compare equal. A false match only ever errs
    toward *more* review (self-approval downgraded to ``needs_review``), never
    toward auto-approval, so over-merging is the safe direction.
    """

    return "".join(char for char in value.lower() if char.isalnum())
