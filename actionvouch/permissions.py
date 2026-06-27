"""Permission graph export for ActionVouch projects."""

from __future__ import annotations

from typing import Any

from .models import HIGH_RISK_ACTION_CLASSES, AuditProject


def build_permission_graph(project: AuditProject) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    high_risk_paths: list[dict[str, Any]] = []

    for agent in project.agents:
        nodes.append(
            {
                "id": f"agent:{agent.agent_id}",
                "type": "agent",
                "label": agent.name,
                "risk_level": agent.risk_level,
                "autonomy_level": agent.autonomy_level,
                "evidence": agent.evidence,
                "unknowns": agent.unknowns,
            }
        )
        for tool_id in agent.tools:
            edge = {
                "from": f"agent:{agent.agent_id}",
                "to": f"tool:{tool_id}",
                "type": "uses_tool",
                "evidence": agent.evidence,
                "missing_evidence": _evidence_is_missing(project, agent.evidence),
            }
            edges.append(edge)

    for tool in project.tools:
        nodes.append(
            {
                "id": f"tool:{tool.tool_id}",
                "type": "tool",
                "label": tool.name,
                "system": tool.system,
                "risk_level": tool.risk_level,
                "connector_type": tool.connector_type,
                "oauth_scopes": tool.oauth_scopes,
                "mcp_server_id": tool.mcp_server_id,
                "a2a_agent_card_id": tool.a2a_agent_card_id,
                "external_effect": tool.external_effect,
                "evidence": tool.evidence,
                "unknowns": tool.unknowns,
            }
        )
        for action_class in tool.actions_supported:
            edge = {
                "from": f"tool:{tool.tool_id}",
                "to": f"action:{action_class}",
                "type": "supports_action",
                "evidence": tool.evidence,
                "missing_evidence": _evidence_is_missing(project, tool.evidence),
            }
            edges.append(edge)
            if action_class in HIGH_RISK_ACTION_CLASSES or (
                tool.external_effect and action_class not in {"observe", "draft"}
            ):
                high_risk_paths.append(
                    {
                        "tool_id": tool.tool_id,
                        "action_class": action_class,
                        "connector_type": tool.connector_type,
                        "reason": "High-risk or external-effect tool path.",
                        "evidence": tool.evidence,
                        "missing_evidence": _evidence_is_missing(
                            project, tool.evidence
                        ),
                    }
                )
        for data_class in tool.data_access:
            edges.append(
                {
                    "from": f"tool:{tool.tool_id}",
                    "to": f"data:{data_class}",
                    "type": "accesses_data",
                    "evidence": tool.evidence,
                    "missing_evidence": _evidence_is_missing(project, tool.evidence),
                }
            )

    for event in project.action_events:
        nodes.append(
            {
                "id": f"event:{event.event_id}",
                "type": "action_event",
                "label": event.action_class,
                "approval_state": event.approval_state,
                "policy_id": event.policy_id,
                "evidence": event.evidence,
                "unknowns": event.unknowns,
            }
        )
        edges.extend(
            [
                {
                    "from": f"agent:{event.agent_id}",
                    "to": f"event:{event.event_id}",
                    "type": "requested_event",
                    "evidence": event.evidence,
                    "missing_evidence": _evidence_is_missing(project, event.evidence),
                },
                {
                    "from": f"event:{event.event_id}",
                    "to": f"action:{event.action_class}",
                    "type": "event_action_class",
                    "evidence": event.evidence,
                    "missing_evidence": _evidence_is_missing(project, event.evidence),
                },
            ]
        )
        if event.tool_called:
            edges.append(
                {
                    "from": f"event:{event.event_id}",
                    "to": f"tool:{event.tool_called}",
                    "type": "called_tool",
                    "evidence": event.evidence,
                    "missing_evidence": _evidence_is_missing(project, event.evidence),
                }
            )
        if event.policy_id:
            edges.append(
                {
                    "from": f"event:{event.event_id}",
                    "to": f"policy:{event.policy_id}",
                    "type": "governed_by_policy",
                    "evidence": event.evidence,
                    "missing_evidence": _evidence_is_missing(project, event.evidence),
                }
            )

    for policy in project.policies:
        nodes.append(
            {
                "id": f"policy:{policy.policy_id}",
                "type": "policy",
                "label": policy.name,
                "blocked_actions": policy.blocked_actions,
                "approval_required_actions": policy.approval_required_actions,
                "allowed_actions": policy.allowed_actions,
            }
        )

    for evidence in project.evidence:
        nodes.append(
            {
                "id": f"evidence:{evidence.evidence_id}",
                "type": "evidence",
                "label": evidence.summary,
                "source_type": evidence.source_type,
                "confidence": evidence.confidence,
                "limitation": evidence.limitation,
            }
        )

    return {
        "graph_version": "actionvouch.permission_graph.v1",
        "project_id": project.project_id,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "high_risk_path_count": len(high_risk_paths),
            "missing_evidence_edge_count": sum(
                1 for edge in edges if edge["missing_evidence"]
            ),
        },
        "nodes": nodes,
        "edges": edges,
        "high_risk_paths": high_risk_paths,
        "guardrails": [
            "Graph edges are local audit evidence, not live permission proof.",
            "Missing evidence edges must not be treated as verified access.",
            "No live external action is authorized by this graph.",
        ],
    }


def _evidence_is_missing(project: AuditProject, evidence_ids: list[str]) -> bool:
    if not evidence_ids:
        return True
    if _has_missing_evidence(project, evidence_ids):
        return True
    return not _has_verifying_evidence(project, evidence_ids)


def _has_missing_evidence(project: AuditProject, evidence_ids: list[str]) -> bool:
    for evidence_id in evidence_ids:
        evidence = project.get_evidence(evidence_id)
        if evidence is None or evidence.source_type == "missing_evidence":
            return True
    return False


def _has_verifying_evidence(project: AuditProject, evidence_ids: list[str]) -> bool:
    for evidence_id in evidence_ids:
        evidence = project.get_evidence(evidence_id)
        if evidence and evidence.source_type != "missing_evidence":
            return True
    return False
