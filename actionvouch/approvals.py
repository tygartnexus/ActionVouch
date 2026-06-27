"""Local approval queue support for ActionVouch.

Approvals are local review records only. They do not execute external actions.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ActionEvent, AuditProject, DESTRUCTIVE_ACTION_CLASSES
from .policies import PolicyDecision, _identity_key, evaluate_action_event

APPROVAL_DECISIONS = {
    "approved_draft",
    "rejected",
    "blocked",
    "needs_evidence",
    "needs_review",
}


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    project_id: str
    event_id: str
    action_class: str
    requested_state: str
    decision: str
    reviewer: str
    policy_id: str
    reasons: list[str]
    required_evidence: list[str]
    evidence: list[str]
    scope: str
    created_at: str = ""
    reviewed_at: str = ""
    notes: list[str] = field(default_factory=list)
    review_history: list[dict[str, str]] = field(default_factory=list)
    previous_record_hash: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovalRecord":
        return cls(
            approval_id=str(data.get("approval_id", "")).strip(),
            project_id=str(data.get("project_id", "")).strip(),
            event_id=str(data.get("event_id", "")).strip(),
            action_class=str(data.get("action_class", "")).strip(),
            requested_state=str(data.get("requested_state", "approved_draft")).strip(),
            decision=str(data.get("decision", "needs_evidence")).strip(),
            reviewer=str(data.get("reviewer", "")).strip(),
            policy_id=str(data.get("policy_id", "")).strip(),
            reasons=_string_list(data.get("reasons")),
            required_evidence=_string_list(data.get("required_evidence")),
            evidence=_string_list(data.get("evidence")),
            scope=str(data.get("scope", "")).strip(),
            created_at=str(data.get("created_at", "")).strip(),
            reviewed_at=str(data.get("reviewed_at", "")).strip(),
            notes=_string_list(data.get("notes")),
            review_history=_history_list(data.get("review_history")),
            previous_record_hash=str(data.get("previous_record_hash", "")).strip(),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.approval_id:
            errors.append("approval_id is required")
        if not self.project_id:
            errors.append("project_id is required")
        if not self.event_id:
            errors.append("event_id is required")
        if not self.action_class:
            errors.append("action_class is required")
        if self.decision not in APPROVAL_DECISIONS:
            errors.append(f"unsupported decision {self.decision}")
        if self.decision == "approved_draft" and not self.reviewer:
            errors.append("approved_draft requires reviewer")
        if self.decision == "approved_draft" and self.required_evidence:
            errors.append("approved_draft cannot have missing required evidence")
        if self.decision == "approved_draft" and not self.evidence:
            errors.append("approved_draft requires evidence")
        if (
            self.action_class in DESTRUCTIVE_ACTION_CLASSES
            and self.decision == "approved_draft"
        ):
            errors.append("destructive and financial actions cannot be approved_draft")
        if self.decision == "approved_draft" and not self.review_history:
            errors.append("approved_draft requires append-only review history")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "project_id": self.project_id,
            "event_id": self.event_id,
            "action_class": self.action_class,
            "requested_state": self.requested_state,
            "decision": self.decision,
            "reviewer": self.reviewer,
            "policy_id": self.policy_id,
            "reasons": self.reasons,
            "required_evidence": self.required_evidence,
            "evidence": self.evidence,
            "scope": self.scope,
            "created_at": self.created_at,
            "reviewed_at": self.reviewed_at,
            "notes": self.notes,
            "review_history": self.review_history,
            "previous_record_hash": self.previous_record_hash,
        }


def list_approval_candidates(project: AuditProject) -> list[dict[str, Any]]:
    return [
        _candidate_payload(project, event, evaluate_action_event(project, event))
        for event in project.action_events
    ]


def create_approval_request(
    project: AuditProject,
    event_id: str,
    *,
    requested_state: str = "approved_draft",
    created_at: str = "",
) -> ApprovalRecord:
    event = _event_by_id(project, event_id)
    decision = evaluate_action_event(project, event)
    missing = _missing_evidence_from_reasons(decision.reasons)
    proposed_decision = _initial_decision(event, decision, missing)
    return ApprovalRecord(
        approval_id=f"approval_{project.project_id}_{event.event_id}",
        project_id=project.project_id,
        event_id=event.event_id,
        action_class=event.action_class,
        requested_state=requested_state,
        decision=proposed_decision,
        reviewer="",
        policy_id=decision.policy_id,
        reasons=decision.reasons,
        required_evidence=missing,
        evidence=event.evidence,
        scope="Local approval record only; no live external action is authorized.",
        created_at=created_at,
        notes=[
            "Approval request was generated from local project evidence.",
            "Run review before treating any draft as approved.",
        ],
        review_history=[
            {
                "decision": proposed_decision,
                "reviewer": "",
                "reviewed_at": "",
                "note": "Initial local approval request. No live external action is authorized.",
            }
        ],
    )


def review_approval(
    record: ApprovalRecord,
    *,
    project: AuditProject,
    decision: str,
    reviewer: str,
    reviewed_at: str = "",
    note: str = "",
) -> ApprovalRecord:
    """Record a human review against ground truth.

    An ``approved_draft`` is only honored when, for the record's bound event in
    ``project``, ALL of the following hold: the action is non-destructive, the
    live policy decision also yields ``approved_draft``, the reviewer is
    independent of the agent owner, and no required evidence is still missing.
    Otherwise the decision is downgraded. A forged or stale record therefore
    cannot be promoted to ``approved_draft`` through this gate, and the
    record's own (forgeable) ``required_evidence``/``policy_id`` are replaced
    with values recomputed from the project.
    """

    if decision not in APPROVAL_DECISIONS:
        raise ValueError(f"unsupported approval decision: {decision}")
    if record.project_id and record.project_id != project.project_id:
        raise ValueError(
            f"approval record project_id {record.project_id!r} does not match "
            f"project {project.project_id!r}"
        )

    event = _event_by_id(project, record.event_id)
    live = evaluate_action_event(project, event)
    live_missing = _missing_evidence_from_reasons(live.reasons)
    agent = project.get_agent(event.agent_id)
    reasons = list(record.reasons)
    final = decision

    if decision == "approved_draft":
        if record.action_class in DESTRUCTIVE_ACTION_CLASSES:
            final = "blocked"
            reasons.append(
                "Destructive or financial actions are blocked in ActionVouch MVP."
            )
        elif live.classification != "approved_draft":
            final = "needs_evidence" if live_missing else "needs_review"
            reasons.append(
                "Approval downgraded: the live policy decision for this event is "
                f"'{live.classification}', not approved_draft."
            )
        elif agent is not None and _identity_key(reviewer) == _identity_key(
            agent.owner
        ):
            final = "needs_review"
            reasons.append(
                f"Approval downgraded: reviewer {reviewer} is the agent owner; "
                "an independent reviewer is required."
            )
        elif live_missing:
            final = "needs_evidence"
            reasons.append(
                "Approval downgraded because required evidence is still missing."
            )

    notes = list(record.notes)
    if note:
        notes.append(note)
    history = [
        *record.review_history,
        {
            "decision": final,
            "reviewer": reviewer,
            "reviewed_at": reviewed_at,
            "note": note
            or "Local review recorded. Approval does not authorize live execution.",
        },
    ]
    return ApprovalRecord(
        approval_id=record.approval_id,
        project_id=record.project_id,
        event_id=record.event_id,
        action_class=record.action_class,
        requested_state=record.requested_state,
        decision=final,
        reviewer=reviewer,
        policy_id=live.policy_id,
        reasons=reasons,
        required_evidence=live_missing,
        evidence=record.evidence,
        scope=record.scope,
        created_at=record.created_at,
        reviewed_at=reviewed_at,
        notes=notes,
        review_history=history,
        previous_record_hash=_record_hash(record),
    )


def verify_record_link(current: ApprovalRecord, previous: ApprovalRecord) -> bool:
    """Return ``True`` iff ``current`` was derived from ``previous``.

    Recomputes the predecessor's hash and compares it to the stored
    ``previous_record_hash``, making the append-only chain actually verifiable
    instead of decorative. A tampered predecessor breaks the link.
    """

    return bool(current.previous_record_hash) and (
        current.previous_record_hash == _record_hash(previous)
    )


def load_approval(path: str | Path) -> ApprovalRecord:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Approval record must be a JSON object")
    return ApprovalRecord.from_dict(data)


def save_approval(record: ApprovalRecord, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return target


def render_approval_markdown(record: ApprovalRecord) -> str:
    lines = [
        f"# ActionVouch Approval Record: {record.approval_id}",
        "",
        f"- Project: `{record.project_id}`",
        f"- Event: `{record.event_id}`",
        f"- Action class: `{record.action_class}`",
        f"- Requested state: `{record.requested_state}`",
        f"- Decision: `{record.decision}`",
        f"- Reviewer: `{record.reviewer or 'not reviewed'}`",
        f"- Policy: `{record.policy_id}`",
        f"- Scope: {record.scope}",
        "",
        "## Reasons",
        "",
    ]
    lines.extend(f"- {item}" for item in record.reasons or ["No reasons recorded."])
    lines.extend(["", "## Required Evidence Still Missing", ""])
    lines.extend(f"- {item}" for item in record.required_evidence or ["None."])
    lines.extend(["", "## Evidence", ""])
    lines.extend(f"- {item}" for item in record.evidence or ["None."])
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {item}" for item in record.notes or ["None."])
    lines.extend(["", "## Review History", ""])
    for entry in record.review_history:
        lines.append(
            "- "
            + "; ".join(
                f"{key}={value or 'not recorded'}" for key, value in entry.items()
            )
        )
    if not record.review_history:
        lines.append("- None.")
    lines.extend(["", "## Chain", ""])
    lines.append(f"- Previous record hash: `{record.previous_record_hash or 'none'}`")
    lines.append("")
    return "\n".join(lines)


def _candidate_payload(
    project: AuditProject, event: ActionEvent, decision: PolicyDecision
) -> dict[str, Any]:
    missing = _missing_evidence_from_reasons(decision.reasons)
    return {
        "project_id": project.project_id,
        "event_id": event.event_id,
        "action_class": event.action_class,
        "approval_state": event.approval_state,
        "policy_classification": decision.classification,
        "policy_id": decision.policy_id,
        "required_evidence": missing,
        "evidence": event.evidence,
        "review_recommended": decision.classification in {"blocked", "needs_review"}
        or bool(missing),
        "reasons": decision.reasons,
    }


def _event_by_id(project: AuditProject, event_id: str) -> ActionEvent:
    for event in project.action_events:
        if event.event_id == event_id:
            return event
    raise ValueError(f"event_id not found: {event_id}")


def _initial_decision(
    event: ActionEvent, decision: PolicyDecision, missing: list[str]
) -> str:
    if event.action_class in DESTRUCTIVE_ACTION_CLASSES:
        return "blocked"
    if missing or decision.classification in {"blocked", "needs_review"}:
        return "needs_evidence"
    return "needs_evidence"


def _missing_evidence_from_reasons(reasons: list[str]) -> list[str]:
    missing: list[str] = []
    prefix = "Missing required policy evidence:"
    for reason in reasons:
        if reason.startswith(prefix):
            values = reason.replace(prefix, "", 1)
            missing.extend(item.strip() for item in values.split(",") if item.strip())
    return missing


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _history_list(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    history: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        history.append({str(key): str(val) for key, val in item.items()})
    return history


def _record_hash(record: ApprovalRecord) -> str:
    payload = record.to_dict()
    payload["previous_record_hash"] = ""
    content = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
