"""Credential-safe import mapping for ActionVouch.

The importers consume local exports or redacted summaries from automation
platforms. Direct API import is intentionally represented as a blocked mode
until a provider-specific read-only connector has consent, credentials, tests,
and data-handling review.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import (
    ACTION_CLASSES,
    HIGH_RISK_ACTION_CLASSES,
    ActionEvent,
    AgentRecord,
    AuditProject,
    EvidenceItem,
    ToolRecord,
    normalize_autonomy_level,
)
from .policies import default_policy_rules

SUPPORTED_LOCAL_IMPORTERS = {
    "actionvouch.manual_agent_inventory.v1",
    "actionvouch.zapier_summary.v1",
    "actionvouch.n8n_summary.v1",
    "actionvouch.make_summary.v1",
    "actionvouch.crm_automation_summary.v1",
    "actionvouch.workspace_ai_usage.v1",
    "actionvouch.mcp_config_summary.v1",
    "actionvouch.support_workflow_notes.v1",
}

LIVE_PROVIDER_STATUS = {
    "zapier": "blocked_pending_oauth_consent_and_readonly_api_tests",
    "n8n": "blocked_pending_instance_url_token_and_readonly_api_tests",
    "make": "blocked_pending_oauth_consent_and_readonly_api_tests",
    "hubspot": "blocked_pending_private_app_scope_review_and_readonly_api_tests",
    "google_workspace": "blocked_pending_admin_export_or_domain_delegation_review",
    "microsoft_365": "blocked_pending_admin_export_or_graph_scope_review",
    "mcp": "blocked_pending_server_manifest_and_tool_scope_review",
}

ACTION_CLASS_ALIASES = {
    "email": "customer_message",
    "send_email": "customer_message",
    "email_customer": "customer_message",
    "customer_email": "customer_message",
    "send_message": "customer_message",
    "message_customer": "customer_message",
    "send_sms": "customer_message",
    "support_reply": "support_response",
    "support_email": "support_response",
    "update_crm": "crm_write",
    "crm_update": "crm_write",
    "write_crm": "crm_write",
    "create_crm_record": "crm_write",
    "update_customer_record": "crm_write",
    "delete_customer_record": "file_delete",
    "delete_record": "file_delete",
    "remove_customer_record": "file_delete",
    "remove_record": "file_delete",
    "delete_file": "file_delete",
    "remove_file": "file_delete",
    "destroy_record": "file_delete",
    "refund": "payment_refund",
    "issue_refund": "payment_refund",
    "refund_payment": "payment_refund",
    "charge_card": "finance_action",
    "create_invoice": "finance_action",
    "send_invoice": "finance_action",
    "publish": "public_publish",
    "publish_post": "public_publish",
    "post_publicly": "public_publish",
    "make_public": "public_publish",
    "api_call": "external_api_call",
    "http_request": "external_api_call",
    "webhook": "external_api_call",
    "call_webhook": "external_api_call",
}


@dataclass(frozen=True)
class ImportResult:
    project: AuditProject
    imported_sources: list[str]
    blocked_live_sources: list[dict[str, str]]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project.to_dict(),
            "imported_sources": self.imported_sources,
            "blocked_live_sources": self.blocked_live_sources,
            "warnings": self.warnings,
        }


def import_project_from_paths(
    paths: list[str | Path],
    *,
    project_id: str,
    name: str,
    scope: str,
    timestamp: str = "",
) -> ImportResult:
    records: list[dict[str, Any]] = []
    imported_sources: list[str] = []
    warnings: list[str] = []
    for item in paths:
        path = Path(item)
        source_records, source_warnings = _read_source_records(path)
        records.extend(source_records)
        warnings.extend(source_warnings)
        imported_sources.append(str(path))

    evidence_by_id: dict[str, EvidenceItem] = {}
    tool_by_id: dict[str, ToolRecord] = {}
    agents: list[AgentRecord] = []
    events: list[ActionEvent] = []

    for index, record in enumerate(records, start=1):
        normalized = _normalize_record(record, index)
        warnings.extend(normalized["warnings"])
        evidence_ids = _merge_evidence(
            evidence_by_id,
            normalized,
            source_ref=normalized["source_ref"],
            timestamp=timestamp,
        )
        missing_permission_id = f"ev_missing_permissions_{normalized['record_id']}"
        evidence_by_id.setdefault(
            missing_permission_id,
            EvidenceItem(
                evidence_id=missing_permission_id,
                source_type="missing_evidence",
                summary="Live permission export or reviewed admin screenshot is not attached.",
                limitation="Tool scopes cannot be treated as verified.",
                confidence=0.35,
                collected_at=timestamp,
                reviewer="ActionVouch importer",
            ),
        )
        additional_evidence_ids = [missing_permission_id]
        if normalized["unsupported_action_classes"]:
            unsupported_action_id = f"ev_unsupported_actions_{normalized['record_id']}"
            raw_actions = ", ".join(normalized["unsupported_action_classes"])
            mapping_notes = ", ".join(normalized["action_mapping_notes"])
            evidence_by_id.setdefault(
                unsupported_action_id,
                EvidenceItem(
                    evidence_id=unsupported_action_id,
                    source_type="missing_evidence",
                    summary=(
                        "Source listed non-canonical or unsupported action "
                        f"classes: {raw_actions}."
                    ),
                    limitation=(
                        "Mapped action classes are conservative review labels, "
                        f"not live-verified permissions. Mapping: {mapping_notes}."
                    ),
                    confidence=0.2,
                    collected_at=timestamp,
                    reviewer="ActionVouch importer",
                ),
            )
            additional_evidence_ids.append(unsupported_action_id)
        all_evidence_ids = evidence_ids + additional_evidence_ids
        for tool_name in normalized["tools"]:
            tool_id = _slug(tool_name)
            existing = tool_by_id.get(tool_id)
            tool_record = ToolRecord(
                tool_id=tool_id,
                name=_title(tool_name),
                system=normalized["platform"],
                permission_type="unknown_until_export_reviewed",
                data_access=sorted(set(normalized["data_classes"])),
                actions_supported=sorted(set(normalized["action_classes"])),
                external_effect=any(
                    action in HIGH_RISK_ACTION_CLASSES
                    for action in normalized["action_classes"]
                ),
                credential_owner=normalized["owner"] or "unknown",
                risk_level=_risk_level(normalized["action_classes"]),
                notes="Imported from redacted local export or summary.",
                connector_type=normalized["connector_type"],
                oauth_scopes=normalized["oauth_scopes"],
                mcp_server_id=normalized["mcp_server_id"],
                a2a_agent_card_id=normalized["a2a_agent_card_id"],
                evidence=all_evidence_ids,
                unknowns=["Live permission scope is not verified."],
            )
            if existing:
                tool_record = _merge_tool(existing, tool_record)
            tool_by_id[tool_id] = tool_record

        policy_id = _policy_for_actions(normalized["action_classes"])
        agents.append(
            AgentRecord(
                agent_id=normalized["record_id"],
                name=normalized["name"],
                owner=normalized["owner"] or "unknown",
                business_purpose=normalized["business_purpose"],
                provider=normalized["platform"],
                model_or_runtime=normalized["runtime"],
                tools=[_slug(tool) for tool in normalized["tools"]] or ["unknown"],
                data_classes=normalized["data_classes"] or ["unknown"],
                action_classes=normalized["action_classes"] or ["observe"],
                autonomy_level=normalized["autonomy_level"],
                risk_level=_risk_level(normalized["action_classes"]),
                approval_policy_id=policy_id,
                status="imported_needs_review",
                last_reviewed_at=timestamp[:10] if timestamp else "",
                evidence=all_evidence_ids,
                unknowns=normalized["unknowns"]
                + ["Imported records require owner review before delivery."],
            )
        )
        event_action = _representative_action(normalized["action_classes"])
        events.append(
            ActionEvent(
                event_id=f"evt_{normalized['record_id']}_{event_action}",
                agent_id=normalized["record_id"],
                timestamp=timestamp,
                request_summary=normalized["trigger_summary"]
                or f"Imported workflow review for {normalized['name']}.",
                action_class=event_action,
                action_payload_summary=normalized["external_effect_summary"],
                approval_state=(
                    "needs_review"
                    if event_action in HIGH_RISK_ACTION_CLASSES
                    else "proposed"
                ),
                outcome="not_executed_imported_record",
                tool_called=(
                    _slug(normalized["tools"][0]) if normalized["tools"] else "unknown"
                ),
                policy_id=policy_id,
                evidence=all_evidence_ids,
                unknowns=normalized["unknowns"],
            )
        )

    project = AuditProject(
        project_id=project_id,
        name=name,
        version="actionvouch.audit_project.v1",
        created_at=timestamp,
        updated_at=timestamp,
        scope=scope,
        agents=agents,
        tools=list(tool_by_id.values()),
        policies=default_policy_rules(),
        action_events=events,
        evidence=list(evidence_by_id.values()),
        assumptions=[
            "Imported records are based on local exports or owner-provided summaries.",
            "Live platform permissions are not verified unless a current admin export is attached.",
        ],
        unknowns=[
            "Direct API import remains blocked until provider credentials, consent, and read-only tests are configured."
        ],
    )
    return ImportResult(
        project=project,
        imported_sources=imported_sources,
        blocked_live_sources=[],
        warnings=warnings,
    )


def live_import_status(provider: str) -> dict[str, Any]:
    normalized = provider.strip().lower()
    status = LIVE_PROVIDER_STATUS.get(normalized, "unsupported_provider")
    return {
        "provider": normalized,
        "status": status,
        "valid": False,
        "blocked": True,
        "reason": (
            "Direct live API import is not enabled in the MVP because it needs "
            "customer consent, read-only credentials, provider-specific tests, "
            "secret handling, and a reviewed data-processing path."
        ),
        "safe_alternative": (
            "Use `actionvouch import` with a credential-free local export or "
            "redacted summary template."
        ),
    }


def _read_source_records(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Importer input must be a JSON object: {path}")
        return _records_from_json(data, path), []
    if path.suffix.lower() in {".md", ".txt"}:
        return [_record_from_markdown(path)], []
    raise ValueError(f"Unsupported importer file type: {path}")


def _records_from_json(data: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    version = str(data.get("template_version", "")).strip()
    if version and version not in SUPPORTED_LOCAL_IMPORTERS:
        raise ValueError(f"Unsupported ActionVouch importer template: {version}")
    platform = _platform_from_version(version) or str(data.get("platform", "manual"))
    source_ref = str(path)
    if "agents" in data:
        return [
            {**item, "platform": platform, "source_ref": source_ref}
            for item in _list(data.get("agents"))
        ]
    for key in (
        "zaps",
        "workflows",
        "scenarios",
        "automations",
        "usage_patterns",
        "mcp_servers",
    ):
        if key in data:
            return [
                {**item, "platform": platform, "source_ref": source_ref}
                for item in _list(data.get(key))
            ]
    return [{**data, "platform": platform, "source_ref": source_ref}]


def _record_from_markdown(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    fields: dict[str, Any] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*-\s*([^:]+):\s*(.+)$", line)
        if match:
            key = _slug(match.group(1))
            fields[key] = match.group(2).strip()
    return {
        "workflow_id": _slug(fields.get("name", path.stem)),
        "name": fields.get("name", path.stem.replace("_", " ").title()),
        "owner": fields.get("owner", "unknown"),
        "business_purpose": fields.get("business_purpose", ""),
        "tools": _split_list(fields.get("tools", "")),
        "data_classes": _split_list(fields.get("data_classes", "")),
        "action_classes": _split_list(fields.get("action_classes", "")),
        "approval_expectations": fields.get("approval_expectations", ""),
        "trigger_summary": fields.get("request_summary", ""),
        "external_effects": [fields.get("external_effect_if_executed", "")],
        "evidence": [
            {
                "evidence_id": fields.get("evidence_id", f"ev_{path.stem}"),
                "source_type": "owner_statement",
                "summary": fields.get("summary", "Imported markdown workflow notes."),
                "limitation": fields.get(
                    "limitation", "Markdown notes were not live-verified."
                ),
            }
        ],
        "unknowns": [
            fields.get("whether_the_email_tool_can_send_directly_is_unknown", "")
        ],
        "platform": "support_workflow_notes",
        "source_ref": str(path),
    }


def _normalize_record(record: dict[str, Any], index: int) -> dict[str, Any]:
    record_id = _slug(
        str(
            record.get("agent_id")
            or record.get("workflow_id")
            or record.get("scenario_id")
            or record.get("automation_id")
            or record.get("usage_id")
            or record.get("server_id")
            or f"imported_record_{index}"
        )
    )
    action_classes, unsupported_action_classes, action_mapping_notes = (
        _normalize_action_classes(_string_list(record.get("action_classes")))
    )
    platform = str(record.get("platform") or "manual")
    connector_type = _connector_type(record, platform)
    tools = _string_list(record.get("tools")) or ["unknown"]
    evidence = _list(record.get("evidence"))
    unknowns = [item for item in _string_list(record.get("unknowns")) if item.strip()]
    warnings: list[str] = []
    if unsupported_action_classes:
        raw_actions = ", ".join(unsupported_action_classes)
        mapping_notes = ", ".join(action_mapping_notes)
        warnings.append(
            f"{record_id}: non-canonical or unsupported action_classes require "
            f"owner review: {raw_actions}; mapped as {mapping_notes}."
        )
        unknowns.append(
            "Source action classes require owner/platform review before they can "
            f"be treated as verified permissions: {raw_actions}."
        )
    return {
        "record_id": record_id,
        "name": str(record.get("name") or _title(record_id)),
        "owner": str(record.get("owner") or "unknown"),
        "business_purpose": str(
            record.get("business_purpose")
            or "Imported workflow purpose requires owner confirmation."
        ),
        "runtime": str(
            record.get("model_or_runtime")
            or record.get("provider_or_runtime")
            or "imported_workflow"
        ),
        "platform": platform,
        "connector_type": connector_type,
        "oauth_scopes": _string_list(record.get("oauth_scopes")),
        "mcp_server_id": (
            _slug(str(record.get("server_id") or "")) if connector_type == "mcp" else ""
        ),
        "a2a_agent_card_id": (
            _slug(str(record.get("agent_card_id") or ""))
            if connector_type == "a2a"
            else ""
        ),
        "autonomy_level": normalize_autonomy_level(
            record.get("autonomy_level", ""), action_classes
        ),
        "tools": tools,
        "data_classes": _string_list(record.get("data_classes")) or ["unknown"],
        "action_classes": action_classes,
        "trigger_summary": str(
            record.get("trigger_summary") or record.get("request_summary") or ""
        ),
        "external_effect_summary": "; ".join(
            _string_list(record.get("external_effects"))
        )
        or "Imported record; no live action executed.",
        "evidence": evidence,
        "unknowns": unknowns,
        "unsupported_action_classes": unsupported_action_classes,
        "action_mapping_notes": action_mapping_notes,
        "warnings": warnings,
        "source_ref": str(record.get("source_ref", "")),
    }


def _normalize_action_classes(
    raw_actions: list[str],
) -> tuple[list[str], list[str], list[str]]:
    actions: list[str] = []
    unsupported: list[str] = []
    mapping_notes: list[str] = []
    for raw_action in raw_actions:
        raw = raw_action.strip()
        if not raw:
            continue
        normalized = _slug(raw)
        if normalized in ACTION_CLASSES:
            actions.append(normalized)
            continue
        mapped = ACTION_CLASS_ALIASES.get(normalized)
        if mapped:
            actions.append(mapped)
            unsupported.append(raw)
            mapping_notes.append(f"{raw}->{mapped}")
            continue
        actions.append("external_api_call")
        unsupported.append(raw)
        mapping_notes.append(f"{raw}->external_api_call")
    return _dedupe(actions) or ["observe"], _dedupe(unsupported), _dedupe(mapping_notes)


def _merge_evidence(
    evidence_by_id: dict[str, EvidenceItem],
    normalized: dict[str, Any],
    *,
    source_ref: str,
    timestamp: str,
) -> list[str]:
    evidence_ids: list[str] = []
    source_items = normalized["evidence"] or [
        {
            "evidence_id": f"ev_{normalized['record_id']}_owner_summary",
            "source_type": "owner_statement",
            "summary": f"Imported summary for {normalized['name']}.",
            "limitation": "Importer input was not independently live-verified.",
        }
    ]
    for raw_item in source_items:
        if not isinstance(raw_item, dict):
            continue
        evidence_id = _slug(str(raw_item.get("evidence_id") or "evidence"))
        item = EvidenceItem(
            evidence_id=evidence_id,
            source_type=str(raw_item.get("source_type") or "owner_statement"),
            source_ref=str(raw_item.get("source_ref") or source_ref),
            summary=str(raw_item.get("summary") or "Imported evidence summary."),
            limitation=str(
                raw_item.get("limitation")
                or "Imported evidence was not independently live-verified."
            ),
            confidence=float(raw_item.get("confidence", 0.62)),
            collected_at=str(raw_item.get("collected_at") or timestamp),
            reviewer=str(raw_item.get("reviewer") or "ActionVouch importer"),
            satisfies=_string_list(raw_item.get("satisfies"))
            or ["owner", "purpose", "action_summary"],
        )
        evidence_by_id.setdefault(evidence_id, item)
        evidence_ids.append(evidence_id)
    return evidence_ids


def _merge_tool(existing: ToolRecord, incoming: ToolRecord) -> ToolRecord:
    return ToolRecord(
        tool_id=existing.tool_id,
        name=existing.name,
        system=existing.system,
        permission_type=existing.permission_type,
        data_access=sorted(set(existing.data_access) | set(incoming.data_access)),
        actions_supported=sorted(
            set(existing.actions_supported) | set(incoming.actions_supported)
        ),
        external_effect=existing.external_effect or incoming.external_effect,
        credential_owner=(
            existing.credential_owner
            if existing.credential_owner != "unknown"
            else incoming.credential_owner
        ),
        risk_level=_highest_risk(existing.risk_level, incoming.risk_level),
        notes=existing.notes,
        connector_type=(
            incoming.connector_type
            if existing.connector_type in {"manual", "unknown"}
            else existing.connector_type
        ),
        oauth_scopes=sorted(set(existing.oauth_scopes) | set(incoming.oauth_scopes)),
        mcp_server_id=existing.mcp_server_id or incoming.mcp_server_id,
        a2a_agent_card_id=existing.a2a_agent_card_id or incoming.a2a_agent_card_id,
        evidence=sorted(set(existing.evidence) | set(incoming.evidence)),
        unknowns=sorted(set(existing.unknowns) | set(incoming.unknowns)),
    )


def _policy_for_actions(actions: list[str]) -> str:
    if any(
        action in {"file_delete", "finance_action", "payment_refund"}
        for action in actions
    ):
        return "destructive_action_block"
    if any(action in {"customer_message", "support_response"} for action in actions):
        return "customer_communication_approval"
    if "crm_write" in actions:
        return "crm_write_approval"
    if "public_publish" in actions:
        return "public_publishing_approval"
    if any(
        action in {"compliance_sensitive_claim", "legal_sensitive_claim"}
        for action in actions
    ):
        return "legal_compliance_review"
    return "observe_only_default"


def _representative_action(actions: list[str]) -> str:
    for action in ("file_delete", "finance_action", "payment_refund"):
        if action in actions:
            return action
    for action in actions:
        if action in HIGH_RISK_ACTION_CLASSES:
            return action
    return actions[-1] if actions else "observe"


def _risk_level(actions: list[str]) -> str:
    if any(
        action in {"file_delete", "finance_action", "payment_refund"}
        for action in actions
    ):
        return "critical"
    if any(action in HIGH_RISK_ACTION_CLASSES for action in actions):
        return "high"
    if "draft" in actions:
        return "medium"
    return "low"


def _highest_risk(left: str, right: str) -> str:
    order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _platform_from_version(version: str) -> str:
    parts = version.split(".")
    return parts[1] if len(parts) > 2 else ""


def _connector_type(record: dict[str, Any], platform: str) -> str:
    raw = _slug(str(record.get("connector_type") or record.get("protocol") or platform))
    mapping = {
        "manual_agent_inventory": "manual",
        "zapier_summary": "zapier",
        "n8n_summary": "n8n",
        "make_summary": "make",
        "crm_automation_summary": "crm_automation",
        "workspace_ai_usage": "workspace_ai",
        "mcp_config_summary": "mcp",
        "support_workflow_notes": "support_workflow_notes",
        "model_context_protocol": "mcp",
        "agent2agent": "a2a",
        "agent_to_agent": "a2a",
    }
    return mapping.get(raw, raw or "unknown")


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return _split_list(value)
    return []


def _split_list(value: str) -> list[str]:
    return [item.strip() for item in re.split(r",|;", value) if item.strip()]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "unknown"


def _title(value: str) -> str:
    return _slug(value).replace("_", " ").title()
