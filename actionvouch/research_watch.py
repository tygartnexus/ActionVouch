"""ActionVouch research-watch and capability-signal support.

The watch is local and evidence-first. It records the sources that should
trigger product review when agent capabilities, tool protocols, or governance
guidance change. It does not fetch the web or silently update policy.
"""

from __future__ import annotations

import json
from typing import Any

from .models import CapabilitySignal

DEFAULT_RETRIEVED_AT = "2026-06-19"

BASELINE_SIGNALS: tuple[dict[str, object], ...] = (
    {
        "signal_id": "gartner_agent_sprawl_2026",
        "source": "Gartner agent sprawl press release",
        "source_url": "https://www.gartner.com/en/newsroom/press-releases/2026-04-28-gartner-identifies-six-steps-to-manage-artificial-intelligence-agent-sprawl",
        "publisher": "Gartner",
        "published_at": "2026-04-28",
        "capability_area": "agent_governance",
        "change_summary": "Agent sprawl is becoming a governance problem; organizations report weak governance confidence.",
        "affected_product_area": "inventory_lifecycle_monitoring",
        "risk_impact": "ActionVouch needs owner, lifecycle, permission, and remediation tracking.",
        "action_required": "Keep inventory and ownership fields mandatory.",
        "confidence": 0.82,
        "evidence_status": "analyst_source",
    },
    {
        "signal_id": "gartner_autonomy_governance_2026",
        "source": "Gartner proportional autonomy governance press release",
        "source_url": "https://www.gartner.com/en/newsroom/press-releases/2026-05-26-gartner-says-applying-uniform-governance-across-ai-agents-will-lead-to-enterprise-ai-agent-failure",
        "publisher": "Gartner",
        "published_at": "2026-05-26",
        "capability_area": "autonomy_levels",
        "change_summary": "Agent controls should vary across observe, advise, act with approval, and autonomous operation.",
        "affected_product_area": "risk_taxonomy_policy_engine_reports",
        "risk_impact": "Uniform risk labels can hide L4 autonomous risk or over-control L1 observe workflows.",
        "action_required": "Preserve autonomy_level as a first-class field and block L4 external action in MVP.",
        "confidence": 0.84,
        "evidence_status": "analyst_source",
    },
    {
        "signal_id": "gartner_enterprise_app_agents_2026",
        "source": "Gartner task-specific AI agents in enterprise apps",
        "source_url": "https://www.gartner.com/en/newsroom/press-releases/2025-08-26-gartner-predicts-40-percent-of-enterprise-apps-will-feature-task-specific-ai-agents-by-2026-up-from-less-than-5-percent-in-2025",
        "publisher": "Gartner",
        "published_at": "2025-08-26",
        "capability_area": "agent_market_adoption",
        "change_summary": "Task-specific AI agents are expected to appear in many enterprise applications.",
        "affected_product_area": "importer_priorities_buyer_positioning",
        "risk_impact": "ActionVouch should audit agents embedded in ordinary SaaS and workflow products.",
        "action_required": "Keep SaaS/workflow import fixtures ahead of custom-agent-only assumptions.",
        "confidence": 0.78,
        "evidence_status": "analyst_source",
    },
    {
        "signal_id": "mcp_spec_2025_06_18",
        "source": "Model Context Protocol specification",
        "source_url": "https://modelcontextprotocol.io/specification/2025-06-18",
        "publisher": "Model Context Protocol",
        "published_at": "2025-06-18",
        "capability_area": "tool_protocols",
        "change_summary": "MCP standardizes tool, resource, prompt, elicitation, sampling, roots, and logging surfaces.",
        "affected_product_area": "mcp_importer_tool_boundary_review",
        "risk_impact": "MCP tools can cross trust boundaries and need consent, scope, and allowlist evidence.",
        "action_required": "Keep MCP server ID, tool list, scope evidence, and missing auth boundary checks in importer fixtures.",
        "confidence": 0.87,
        "evidence_status": "official_specification",
    },
    {
        "signal_id": "nsa_mcp_security_2026",
        "source": "NSA MCP security design considerations",
        "source_url": "https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/",
        "publisher": "NSA",
        "published_at": "2026-05-20",
        "capability_area": "mcp_security",
        "change_summary": "MCP security guidance is now important enough for government security review.",
        "affected_product_area": "mcp_risk_controls_evidence_room",
        "risk_impact": "Production MCP use should be treated as high risk until auth, logging, and tool trust are verified.",
        "action_required": "Add MCP-specific checklist items to risk findings and compliance readiness.",
        "confidence": 0.85,
        "evidence_status": "official_government_guidance",
    },
    {
        "signal_id": "owasp_agentic_top_10_2026",
        "source": "OWASP Top 10 for Agentic Applications 2026",
        "source_url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "publisher": "OWASP",
        "published_at": "2025-12-09",
        "capability_area": "agentic_security",
        "change_summary": "Agentic apps need coverage beyond classic prompt injection, including tool misuse, agency, memory, and inter-agent risk.",
        "affected_product_area": "risk_taxonomy_tests",
        "risk_impact": "Risk findings must map to agentic failure modes, not generic chatbot risks.",
        "action_required": "Keep OWASP Agentic mappings in findings and add adversarial tests for approval bypass.",
        "confidence": 0.83,
        "evidence_status": "primary_security_community_source",
    },
    {
        "signal_id": "nist_ai_rmf_playbook",
        "source": "NIST AI RMF and AIRC Playbook",
        "source_url": "https://airc.nist.gov/airmf-resources/playbook/",
        "publisher": "NIST",
        "published_at": "current_page",
        "capability_area": "ai_risk_management",
        "change_summary": "NIST organizes AI risk work around Govern, Map, Measure, and Manage.",
        "affected_product_area": "framework_mappings_compliance_readiness",
        "risk_impact": "ActionVouch findings need explicit governance, mapping, measurement, and management evidence.",
        "action_required": "Keep NIST AI RMF mappings in reports and compliance readiness.",
        "confidence": 0.86,
        "evidence_status": "official_government_source",
    },
    {
        "signal_id": "iso_iec_42001_ai_management",
        "source": "ISO/IEC 42001 AI management system standard page",
        "source_url": "https://www.iso.org/standard/42001",
        "publisher": "ISO",
        "published_at": "current_page",
        "capability_area": "ai_management_system",
        "change_summary": "ISO/IEC 42001 frames AI governance as a management system with continual improvement.",
        "affected_product_area": "readiness_packet_evidence_room",
        "risk_impact": "ActionVouch should support readiness evidence without claiming certification.",
        "action_required": "Keep certification and attestation status explicitly not_certified until external review.",
        "confidence": 0.8,
        "evidence_status": "official_standards_body_source",
    },
    {
        "signal_id": "openai_agents_mcp_docs",
        "source": "OpenAI Agents SDK and MCP docs",
        "source_url": "https://developers.openai.com/api/docs/guides/tools-connectors-mcp",
        "publisher": "OpenAI",
        "published_at": "current_docs",
        "capability_area": "agent_tool_approvals",
        "change_summary": "Agent apps own orchestration, tool execution, approvals, and state; MCP calls can require approvals for sensitive data sharing.",
        "affected_product_area": "approval_queue_protocol_controls",
        "risk_impact": "Approvals and state are product-critical control surfaces across providers.",
        "action_required": "Audit approval state and data-sharing risk for every tool-connected workflow.",
        "confidence": 0.79,
        "evidence_status": "official_vendor_docs",
    },
    {
        "signal_id": "google_a2a_protocol_2025",
        "source": "Google Agent2Agent protocol announcement",
        "source_url": "https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/",
        "publisher": "Google",
        "published_at": "2025-04-09",
        "capability_area": "inter_agent_protocols",
        "change_summary": "A2A is an open protocol for agent interoperability across enterprise platforms.",
        "affected_product_area": "a2a_manifest_import_inter_agent_risk",
        "risk_impact": "Inter-agent routing adds owner, trust, delegation, and audit-log risk.",
        "action_required": "Track A2A agent card identity after MCP intake is stable.",
        "confidence": 0.74,
        "evidence_status": "official_vendor_source",
    },
    {
        "signal_id": "eu_ai_act_risk_framework",
        "source": "European Commission EU AI Act overview",
        "source_url": "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
        "publisher": "European Commission",
        "published_at": "current_page",
        "capability_area": "regulatory_risk",
        "change_summary": "EU AI Act uses a risk-based framework for AI developers and deployers.",
        "affected_product_area": "legal_compliance_risk_review_claims",
        "risk_impact": "EU-facing customers may need risk-tier and deployer/provider caveats.",
        "action_required": "Keep EU AI Act output as issue-spotting/readiness, not legal compliance advice.",
        "confidence": 0.76,
        "evidence_status": "official_government_source",
    },
    {
        "signal_id": "ftc_ai_claims_enforcement",
        "source": "FTC artificial intelligence industry page",
        "source_url": "https://www.ftc.gov/industry/technology/artificial-intelligence",
        "publisher": "FTC",
        "published_at": "current_page",
        "capability_area": "claim_hygiene",
        "change_summary": "FTC AI enforcement history highlights unsupported earnings, legal-replacement, and capability claims.",
        "affected_product_area": "marketing_claim_scanner",
        "risk_impact": "Customer-facing copy must avoid guarantees, certification, legal replacement, and unsupported ROI.",
        "action_required": "Keep blocked claims in release packet, reports, and offer copy.",
        "confidence": 0.86,
        "evidence_status": "official_regulator_source",
    },
    {
        "signal_id": "cursor_series_d_market_context",
        "source": "Cursor Series D announcement",
        "source_url": "https://cursor.com/blog/series-d",
        "publisher": "Cursor",
        "published_at": "2025-11-13",
        "capability_area": "market_context",
        "change_summary": "Cursor's growth validates willingness to pay for agentic developer workflows.",
        "affected_product_area": "positioning_competitive_strategy",
        "risk_impact": "Direct IDE competition is capital-intensive; ActionVouch should focus on governance/control.",
        "action_required": "Avoid Cursor-clone positioning unless paid evidence supports that lane.",
        "confidence": 0.73,
        "evidence_status": "official_company_source",
    },
    {
        "signal_id": "cursor_product_surface_context",
        "source": "Cursor product page",
        "source_url": "https://cursor.com/product",
        "publisher": "Cursor",
        "published_at": "current_page",
        "capability_area": "agentic_ide_competition",
        "change_summary": "Agentic coding products bundle IDE, codebase context, CLI, web/mobile, and cloud-agent surfaces.",
        "affected_product_area": "competitive_scope_guardrails",
        "risk_impact": "ActionVouch should not overstate parity with coding-agent platforms.",
        "action_required": "Keep market copy focused on agent risk audit and governance.",
        "confidence": 0.72,
        "evidence_status": "official_company_source",
    },
)


def baseline_capability_signals(
    *, retrieved_at: str = DEFAULT_RETRIEVED_AT
) -> list[CapabilitySignal]:
    signals: list[CapabilitySignal] = []
    for item in BASELINE_SIGNALS:
        payload = dict(item)
        payload["retrieved_at"] = retrieved_at
        signals.append(CapabilitySignal.from_dict(payload))
    return signals


def build_research_watch_report(
    *, retrieved_at: str = DEFAULT_RETRIEVED_AT, last_taxonomy_reviewed_at: str = ""
) -> dict[str, Any]:
    signals = baseline_capability_signals(retrieved_at=retrieved_at)
    stale_flags = stale_recommendation_flags(
        last_taxonomy_reviewed_at=last_taxonomy_reviewed_at,
        signals=signals,
    )
    return {
        "product": "ActionVouch",
        "report_version": "actionvouch.research_watch.v1",
        "retrieved_at": retrieved_at,
        "last_taxonomy_reviewed_at": last_taxonomy_reviewed_at,
        "signal_count": len(signals),
        "signals": [signal.to_dict() for signal in signals],
        "stale_recommendation_flags": stale_flags,
        "guardrails": [
            "Research signals propose review items; they do not silently change policy.",
            "Vendor claims remain unverified until tested locally or supported by customer evidence.",
            "Customer-facing security, legal, pricing, and compliance claims must be rechecked before use.",
        ],
    }


def stale_recommendation_flags(
    *, last_taxonomy_reviewed_at: str, signals: list[CapabilitySignal]
) -> list[dict[str, str]]:
    if not last_taxonomy_reviewed_at:
        return [
            {
                "signal_id": signal.signal_id,
                "reason": "No last_taxonomy_reviewed_at value was supplied.",
                "action_required": signal.action_required,
            }
            for signal in signals
        ]
    flags: list[dict[str, str]] = []
    for signal in signals:
        if signal.published_at in {"current_docs", "current_page"}:
            if last_taxonomy_reviewed_at < signal.retrieved_at:
                flags.append(
                    {
                        "signal_id": signal.signal_id,
                        "reason": (
                            f"Dynamic source retrieved at {signal.retrieved_at} "
                            f"postdates taxonomy review {last_taxonomy_reviewed_at}."
                        ),
                        "action_required": signal.action_required,
                    }
                )
            continue
        if signal.published_at > last_taxonomy_reviewed_at:
            flags.append(
                {
                    "signal_id": signal.signal_id,
                    "reason": (
                        f"Signal published at {signal.published_at} postdates taxonomy review "
                        f"{last_taxonomy_reviewed_at}."
                    ),
                    "action_required": signal.action_required,
                }
            )
    return flags


def render_research_watch_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_research_watch_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# ActionVouch Research Watch",
        "",
        f"Retrieved at: `{payload['retrieved_at']}`",
        f"Signals: `{payload['signal_count']}`",
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {item}" for item in payload["guardrails"])
    lines.extend(["", "## Signals", ""])
    for signal in payload["signals"]:
        lines.extend(
            [
                f"### {signal['signal_id']}",
                "",
                f"- Source: {signal['source']} ({signal['publisher']})",
                f"- URL: {signal['source_url']}",
                f"- Published: {signal['published_at']}",
                f"- Area: {signal['capability_area']}",
                f"- Change: {signal['change_summary']}",
                f"- Product impact: {signal['affected_product_area']}",
                f"- Risk impact: {signal['risk_impact']}",
                f"- Action required: {signal['action_required']}",
                f"- Confidence: `{signal['confidence']:.2f}`",
                f"- Evidence status: `{signal['evidence_status']}`",
                "",
            ]
        )
    lines.extend(["## Stale Recommendation Flags", ""])
    if payload["stale_recommendation_flags"]:
        for flag in payload["stale_recommendation_flags"]:
            lines.append(
                f"- {flag['signal_id']}: {flag['reason']} Action: {flag['action_required']}"
            )
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)
