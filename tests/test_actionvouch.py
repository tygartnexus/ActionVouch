from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from actionvouch import cli
from actionvouch import (
    ActionEvent,
    ApprovalRecord,
    EvidenceItem,
    build_evidence_room,
    build_compliance_readiness_report,
    build_permission_graph,
    build_report,
    build_research_watch_report,
    create_approval_request,
    default_policy_rules,
    evaluate_action_event,
    import_project_from_paths,
    list_approval_candidates,
    load_project,
    live_import_status,
    render_dashboard_html,
    render_editable_console_html,
    render_markdown_report,
    review_approval,
    save_project,
    score_project,
    smoke_html,
    verify_evidence_room,
    verify_record_link,
)
from actionvouch.paths import PROJECT_ROOT
from actionvouch.response_quality import REQUIRED_SECTIONS

SAMPLE = PROJECT_ROOT / "examples" / "actionvouch" / "sample_project.json"


PILOT = PROJECT_ROOT / "examples" / "actionvouch" / "internal_pilot_project.json"
INCOMPLETE = PROJECT_ROOT / "examples" / "actionvouch" / "incomplete_project.json"
RELEASE_PACKET_DIR = PROJECT_ROOT / "docs" / "actionvouch-release"
IMPORT_TEMPLATE_DIR = PROJECT_ROOT / "examples" / "actionvouch" / "import_templates"
IMPORT_FIXTURE_DIR = PROJECT_ROOT / "examples" / "actionvouch" / "import_fixtures"
IMPORT_TEMPLATES = [
    "README.md",
    "manual_agent_inventory_template.json",
    "zapier_summary_template.json",
    "n8n_summary_template.json",
    "make_summary_template.json",
    "crm_automation_summary_template.json",
    "support_workflow_notes_template.md",
    "workspace_ai_usage_template.json",
    "mcp_config_summary_template.json",
    "pilot_metrics_template.json",
]


def _run(capsys, argv) -> dict:
    cli.main(argv)
    return json.loads(capsys.readouterr().out)


def test_sample_project_validates_and_scores_risk_findings():
    project = load_project(SAMPLE)

    assert project.validate() == []
    findings = score_project(project)

    assert findings
    assert any(finding.severity in {"high", "critical"} for finding in findings)
    for finding in findings:
        assert finding.facts
        assert finding.risks
        assert finding.recommendation
        assert finding.what_would_change_the_recommendation
        assert 0 <= finding.confidence_score <= 1


def test_incomplete_project_fails_closed_with_actionable_errors():
    project = load_project(INCOMPLETE)

    errors = project.validate()

    assert errors
    assert any("owner" in error for error in errors)
    assert any("business_purpose" in error for error in errors)
    assert any("unknown tool reference" in error for error in errors)


def test_policy_evaluator_blocks_destructive_file_action():
    project = load_project(SAMPLE)
    event = next(
        item for item in project.action_events if item.event_id == "evt_file_delete_001"
    )

    decision = evaluate_action_event(project, event)

    assert decision.classification == "blocked"
    assert decision.policy_id == "destructive_action_block"
    assert decision.evidence
    assert any("blocked" in reason for reason in decision.reasons)


def test_policy_evaluator_requires_human_review_for_customer_message():
    project = load_project(SAMPLE)
    event = next(
        item
        for item in project.action_events
        if item.event_id == "evt_support_draft_001"
    )

    decision = evaluate_action_event(project, event)

    assert decision.classification == "needs_review"
    assert decision.policy_id == "customer_communication_approval"
    assert any("source_citations" in reason for reason in decision.reasons)


def test_policy_evaluator_refuses_approval_without_required_evidence():
    project = load_project(SAMPLE)
    event = next(
        item
        for item in project.action_events
        if item.event_id == "evt_support_draft_001"
    )
    approved_without_sources = replace(
        event,
        approval_state="approved_draft",
        approver="Ops Lead",
        evidence=["ev_manual_intake"],
    )

    decision = evaluate_action_event(project, approved_without_sources)

    assert decision.classification == "needs_review"
    assert any("source_citations" in reason for reason in decision.reasons)


def test_self_approval_guard_resists_owner_name_spoofing():
    # M4: the owner-vs-approver equality must not be defeated by internal
    # whitespace or trailing punctuation in the approver name.
    project = load_project(SAMPLE)
    event = next(
        item
        for item in project.action_events
        if item.event_id == "evt_support_draft_001"
    )
    agent = project.get_agent(event.agent_id)  # owner "Ops Lead"
    assert agent is not None
    proof = EvidenceItem(
        evidence_id="ev_cc_proof",
        source_type="local_file",
        summary="Customer context, source citations, and owner sign-off.",
        source_ref="local://cc.md",
        satisfies=["customer_context", "source_citations", "human_owner"],
    )
    project = replace(project, evidence=[*project.evidence, proof])

    # A genuinely independent approver reaches approved_draft.
    approved = replace(
        event,
        approval_state="approved_draft",
        approver="Independent Reviewer",
        evidence=["ev_cc_proof"],
    )
    assert evaluate_action_event(project, approved).classification == "approved_draft"

    # The same owner, disguised with a double space + trailing punctuation, is
    # still recognized as a self-approval and downgraded.
    spoof = "  ".join(agent.owner.split()) + " ."
    spoofed = replace(approved, approver=spoof)
    decision = evaluate_action_event(project, spoofed)
    assert decision.classification == "needs_review"
    assert any("self-approved" in reason for reason in decision.reasons)


def test_owner_statement_cannot_satisfy_control_grade_evidence():
    # M3: a self-asserted owner_statement on the event must not satisfy a
    # control-grade requirement (tool_permissions); an independent source can.
    project = load_project(SAMPLE)
    project = replace(project, policies=default_policy_rules())
    agent = project.agents[0]
    event = ActionEvent(
        event_id="evt_m3_probe",
        agent_id=agent.agent_id,
        timestamp="2026-06-19T00:00:00Z",
        request_summary="Draft a routine note",
        action_class="draft",
        action_payload_summary="local draft only",
        approval_state="proposed",
        outcome="not_executed",
        policy_id="observe_only_default",
        evidence=["ev_m3_probe"],
    )

    def evaluate_with(source_type: str):
        evidence = EvidenceItem(
            evidence_id="ev_m3_probe",
            source_type=source_type,
            summary="supplies purpose and (claims) tool permissions",
            source_ref="local://note.md",
            satisfies=["purpose", "tool_permissions"],
        )
        scoped = replace(project, evidence=[*project.evidence, evidence])
        return evaluate_action_event(scoped, event)

    # A self-asserted owner_statement cannot satisfy tool_permissions ...
    self_attested = evaluate_with("owner_statement")
    assert self_attested.classification == "needs_review"
    assert any("tool_permissions" in reason for reason in self_attested.reasons)

    # ... but an independent local_file evidence can.
    independent = evaluate_with("local_file")
    assert independent.classification == "allowed_observe"


def test_markdown_artifacts_escape_hostile_project_strings(tmp_path):
    # M1: user-controlled strings must not inject raw HTML into markdown
    # artifacts, which render as live HTML in GitHub / IDE preview / Obsidian.
    payload = "<script>alert('xss')</script>"
    project = load_project(SAMPLE)
    project = replace(project, name=payload, project_id="av_evil", scope=payload)

    report_md = render_markdown_report(project)
    assert payload not in report_md
    assert "&lt;script&gt;" in report_md  # neutralized, still visible as text

    build_evidence_room(project, tmp_path)
    for md_file in tmp_path.glob("*.md"):
        text = md_file.read_text(encoding="utf-8")
        assert payload not in text, f"raw HTML leaked into {md_file.name}"


def test_report_contains_required_sections_and_guardrails():
    project = load_project(SAMPLE)

    report = build_report(project)

    assert report["status"] == "review_ready"
    for section in REQUIRED_SECTIONS:
        assert section in report["sections"]
        assert report["sections"][section]
    assert report["risk_findings"]
    assert any("does not certify compliance" in item for item in report["guardrails"])
    assert any("No live external action" in item for item in report["guardrails"])
    assert report["summary"]["autonomy_counts"]["act_with_approval"] == 2
    assert report["summary"]["permission_graph"]["high_risk_path_count"] > 0
    assert report["summary"]["response_mode"] == "evidence_based_answer"
    assert report["response_quality"]["prompt_templates"]
    assert report["framework_mappings"]
    assert report["sections"]["Tradeoffs"]
    assert all(finding["framework_mappings"] for finding in report["risk_findings"])


def test_autonomous_agent_actions_are_blocked_in_mvp():
    project = load_project(SAMPLE)
    autonomous = replace(project.agents[0], autonomy_level="autonomous")
    project = replace(project, agents=[autonomous, *project.agents[1:]])
    event = next(
        item for item in project.action_events if item.agent_id == autonomous.agent_id
    )

    decision = evaluate_action_event(project, event)
    findings = score_project(project)

    assert decision.classification == "blocked"
    assert any("L4 autonomous" in reason for reason in decision.reasons)
    assert any(
        finding.affected_record_id == autonomous.agent_id
        and any("autonomous" in risk.lower() for risk in finding.risks)
        for finding in findings
    )


def test_json_report_never_emits_empty_finding_evidence():
    project = load_project(SAMPLE)
    project_with_gap = replace(
        project,
        agents=[replace(project.agents[0], evidence=[]), *project.agents[1:]],
    )

    report = build_report(project_with_gap)

    assert report["risk_findings"]
    assert all(finding["evidence"] for finding in report["risk_findings"])
    assert any(
        evidence.startswith("missing_evidence:")
        for finding in report["risk_findings"]
        for evidence in finding["evidence"]
    )


def test_markdown_report_is_owner_readable_and_cites_evidence():
    project = load_project(SAMPLE)

    markdown = render_markdown_report(project)

    assert "# ActionVouch Risk Audit Report" in markdown
    assert "## Facts" in markdown
    assert "## Unknowns" in markdown
    assert "## Tradeoffs" in markdown
    assert "evt_file_delete_001" in markdown
    assert "ev_manual_intake" in markdown


def test_static_dashboard_renders_summary_risks_and_unknowns():
    project = load_project(SAMPLE)

    html = render_dashboard_html(project)

    assert "<title>ActionVouch Dashboard" in html
    assert "Top Risk Findings" in html
    assert "Policy Decisions" in html
    assert "Unknowns And Missing Evidence" in html
    assert "Framework Mappings" in html
    assert "MCP Tools" in html
    assert "Response Quality Mode" in html
    assert "Accuracy Mode" in html
    assert "Evidence And Source Index" in html
    assert "ev_manual_intake" in html


def test_editable_console_renders_local_editor_and_download_flow():
    project = load_project(SAMPLE)

    html = render_editable_console_html(project)

    assert "<title>ActionVouch Editable Console" in html
    assert "Editable Audit Project JSON" in html
    assert "downloadProject()" in html
    assert "downloadAuditRequest()" in html
    assert "loadExampleAgent()" in html
    assert 'id="responseMode"' in html
    assert "Accuracy Mode" in html
    assert "Red Team Mode" in html
    assert "CEO Review Mode" in html
    assert "Technical Review Mode" in html
    assert "Legal Risk Review Mode" in html
    assert "not legal advice" in html
    assert "actionvouch validate" in html
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html


def test_editable_console_script_json_escapes_closing_script_payload():
    project = load_project(SAMPLE)
    malicious = replace(
        project,
        name="Injected </script><script>window.evil=true</script>",
    )

    html = render_editable_console_html(malicious)

    assert "</script><script>window.evil=true</script>" not in html
    assert "\\u003c/script\\u003e" in html
    assert "&lt;/script&gt;&lt;script&gt;window.evil=true&lt;/script&gt;" in html


def test_script_json_unit_neutralizes_script_breakout():
    # App red-team L4: a direct unit pin on the script-context escaper the
    # console (reachable via the app's /api/console) depends on.
    from actionvouch.console import _script_json

    encoded = _script_json("</script><script>alert(1)</script>")
    assert "</script>" not in encoded
    assert "\\u003c/script\\u003e" in encoded


def test_static_html_smoke_checks_dashboard_and_console(tmp_path):
    project = load_project(SAMPLE)
    dashboard_path = tmp_path / "dashboard.html"
    console_path = tmp_path / "console.html"
    dashboard_path.write_text(render_dashboard_html(project), encoding="utf-8")
    console_path.write_text(render_editable_console_html(project), encoding="utf-8")

    dashboard = smoke_html(dashboard_path, artifact_kind="dashboard")
    console = smoke_html(console_path, artifact_kind="console")

    assert dashboard.valid is True
    assert dashboard.checks["dashboard_has_risks"] is True
    assert console.valid is True
    assert console.checks["console_has_validation_function"] is True
    assert console.checks["console_has_response_mode_selector"] is True
    assert console.checks["console_has_audit_request_export"] is True
    assert console.checks["no_fetch_calls"] is True


def test_project_store_round_trips_without_data_loss(tmp_path):
    project = load_project(SAMPLE)
    target = tmp_path / "project.json"

    save_project(project, target)
    loaded = load_project(target)

    assert loaded.to_dict() == project.to_dict()
    assert loaded.response_mode == "evidence_based_answer"


def test_actionvouch_cli_validate_score_report_and_dashboard(capsys, tmp_path):
    sample_path = str(SAMPLE)
    validate_payload = _run(capsys, ["validate", sample_path])
    assert validate_payload["valid"] is True

    score_payload = _run(capsys, ["score", sample_path])
    assert score_payload["risk_findings"]

    report_path = tmp_path / "report.md"
    report_payload = _run(
        capsys,
        [
            "report",
            sample_path,
            "--format",
            "markdown",
            "--output",
            str(report_path),
        ],
    )
    assert report_payload["valid"] is True
    assert report_path.exists()
    assert "ActionVouch Risk Audit Report" in report_path.read_text(encoding="utf-8")

    dashboard_path = tmp_path / "dashboard.html"
    dashboard_payload = _run(
        capsys,
        [
            "dashboard",
            sample_path,
            "--output",
            str(dashboard_path),
            "--response-mode",
            "technical",
        ],
    )
    assert dashboard_payload["valid"] is True
    assert dashboard_path.exists()
    assert "Technical Review Mode" in dashboard_path.read_text(encoding="utf-8")


def test_actionvouch_cli_console_import_live_import_and_compliance(capsys, tmp_path):
    console_path = tmp_path / "console.html"
    console_payload = _run(
        capsys,
        [
            "console",
            str(SAMPLE),
            "--output",
            str(console_path),
            "--response-mode",
            "legal-risk",
        ],
    )
    assert console_payload["valid"] is True
    assert console_payload["status"] == "console_written"
    console_text = console_path.read_text(encoding="utf-8")
    assert "Editable Console" in console_text
    assert '"response_mode": "legal_compliance_risk_review"' in console_text

    import_output = tmp_path / "imported_project.json"
    import_payload = _run(
        capsys,
        [
            "import",
            str(IMPORT_TEMPLATE_DIR / "manual_agent_inventory_template.json"),
            str(IMPORT_TEMPLATE_DIR / "zapier_summary_template.json"),
            "--output",
            str(import_output),
            "--project-id",
            "av_import_cli_test",
            "--name",
            "Imported CLI Test",
            "--timestamp",
            "2026-06-18T09:00:00-04:00",
        ],
    )
    assert import_payload["valid"] is True
    assert import_payload["status"] == "imported"
    assert import_output.exists()
    assert load_project(import_output).validate() == []

    with pytest.raises(SystemExit):
        cli.main(["live-import", "zapier"])
    live_payload = json.loads(capsys.readouterr().out)
    assert live_payload["blocked"] is True
    assert live_payload["valid"] is False
    assert "safe_alternative" in live_payload

    compliance_path = tmp_path / "compliance.md"
    compliance_payload = _run(
        capsys,
        [
            "compliance",
            str(SAMPLE),
            "--format",
            "markdown",
            "--output",
            str(compliance_path),
        ],
    )
    assert compliance_payload["valid"] is True
    assert compliance_payload["certification_status"] == "not_certified"
    assert "Security And Compliance Readiness" in compliance_path.read_text(
        encoding="utf-8"
    )

    smoke_path = tmp_path / "smoke.md"
    smoke_payload = _run(
        capsys,
        [
            "smoke-html",
            str(console_path),
            "--kind",
            "console",
            "--output",
            str(smoke_path),
        ],
    )
    assert smoke_payload["valid"] is True
    assert "Local HTML Smoke Report" in smoke_path.read_text(encoding="utf-8")


def test_actionvouch_cli_invalid_project_exits_nonzero(capsys):
    with pytest.raises(SystemExit):
        cli.main(["validate", str(INCOMPLETE)])

    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is False
    assert payload["errors"]


def test_actionvouch_package_has_no_live_external_action_imports():
    package_dir = PROJECT_ROOT / "actionvouch"
    forbidden = {
        "requests",
        "smtplib",
        "boto3",
        "googleapiclient",
        "stripe",
        "twilio",
        "subprocess",
    }
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in package_dir.glob("*.py")
    )

    for token in forbidden:
        assert f"import {token}" not in source
        assert f"from {token}" not in source


def test_actionvouch_claim_register_blocks_unsupported_launch_claims():
    text = (RELEASE_PACKET_DIR / "claim-register.md").read_text(encoding="utf-8")

    blocked_claims = [
        "certifies AI compliance",
        "replaces legal review",
        "guarantees protection",
        "monitors live systems",
        "proven ROI",
        "production SaaS-ready",
    ]
    for claim in blocked_claims:
        assert claim in text
    assert "ActionVouch supports an evidence-based AI workflow risk review." in text
    assert "ActionVouch helps identify visible risks and evidence gaps." in text


def test_actionvouch_import_templates_are_credential_free_and_complete():
    forbidden_tokens = (
        "password:",
        "sk_live_",
        "xoxb-",
        "ghp_",
        "akia",
        "secret_access_key",
        "-----begin",
    )
    required_terms = (
        "owner",
        "business_purpose",
        "tools",
        "data_classes",
        "action_classes",
        "approval_expectations",
        "evidence",
        "unknowns",
        "redaction_confirmation",
    )

    for name in IMPORT_TEMPLATES:
        path = IMPORT_TEMPLATE_DIR / name
        assert path.exists(), f"missing import template: {name}"
        text = path.read_text(encoding="utf-8")
        normalized = text.lower().replace(" ", "_")
        assert not any(token in normalized for token in forbidden_tokens), path
        if name.endswith(".json"):
            json.loads(text)
        if name != "README.md":
            for term in required_terms:
                assert term in normalized, f"{path} missing {term}"


def test_actionvouch_pilot_metrics_keep_commercial_proof_unverified():
    payload = json.loads(
        (IMPORT_TEMPLATE_DIR / "pilot_metrics_template.json").read_text(
            encoding="utf-8"
        )
    )

    assert payload["time_to_complete_audit_hours"] > 0
    assert payload["agents_reviewed"] > 0
    assert payload["evidence_gaps"] > 0
    assert payload["blocked_actions"] > 0
    assert payload["customer_prioritized_fixes"]
    assert (
        payload["willingness_to_pay_signal"]["status"]
        == "unproven_until_paid_or_signed"
    )
    assert payload["learning_feedback_allowed"] is False


def test_actionvouch_local_importers_create_valid_project(tmp_path):
    result = import_project_from_paths(
        [
            IMPORT_TEMPLATE_DIR / "manual_agent_inventory_template.json",
            IMPORT_TEMPLATE_DIR / "n8n_summary_template.json",
            IMPORT_TEMPLATE_DIR / "support_workflow_notes_template.md",
        ],
        project_id="av_import_test",
        name="Imported ActionVouch Test",
        scope="Local importer test. No live external actions.",
        timestamp="2026-06-18T09:00:00-04:00",
    )
    target = tmp_path / "imported.json"

    save_project(result.project, target)
    loaded = load_project(target)

    assert loaded.validate() == []
    assert len(loaded.agents) >= 3
    assert loaded.tools
    assert loaded.action_events
    assert any(item.source_type == "missing_evidence" for item in loaded.evidence)
    assert all(
        event.outcome == "not_executed_imported_record"
        for event in loaded.action_events
    )


def test_actionvouch_importer_preserves_unsupported_action_risk(tmp_path):
    source = tmp_path / "unsupported_actions.json"
    source.write_text(
        json.dumps(
            {
                "template_version": "actionvouch.manual_agent_inventory.v1",
                "agents": [
                    {
                        "agent_id": "risky_agent",
                        "name": "Risky Agent",
                        "owner": "Ops",
                        "business_purpose": "Exercise unsupported action imports.",
                        "tools": ["Email", "CRM", "Shell"],
                        "data_classes": ["customer_pii"],
                        "action_classes": [
                            "send_email",
                            "delete_customer_record",
                            "run_shell_command",
                        ],
                        "evidence": [
                            {
                                "evidence_id": "ev_risky_agent_summary",
                                "source_type": "owner_statement",
                                "source_ref": "local redacted fixture",
                                "summary": "Owner-provided import fixture.",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = import_project_from_paths(
        [source],
        project_id="av_unsupported_actions",
        name="Unsupported Actions Test",
        scope="Importer risk preservation test.",
        timestamp="2026-06-19T09:00:00-04:00",
    )
    agent = result.project.agents[0]
    event = result.project.action_events[0]

    assert result.project.validate() == []
    assert {"customer_message", "file_delete", "external_api_call"} <= set(
        agent.action_classes
    )
    assert agent.risk_level == "critical"
    assert event.action_class == "file_delete"
    assert event.approval_state == "needs_review"
    assert any("send_email" in warning for warning in result.warnings)
    assert any("run_shell_command" in unknown for unknown in agent.unknowns)
    assert any(
        item.evidence_id.startswith("ev_unsupported_actions_")
        and item.source_type == "missing_evidence"
        for item in result.project.evidence
    )


def test_actionvouch_live_import_status_fails_closed():
    status = live_import_status("zapier")

    assert status["valid"] is False
    assert status["blocked"] is True
    assert "read-only credentials" in status["reason"]
    assert "actionvouch import" in status["safe_alternative"]


def test_live_import_is_unconditionally_blocked_for_every_provider():
    # L7: pin the live-import block shut. Every known provider, and any
    # unknown one, fails closed; and the API exposes no override/enable flag
    # that a future change could use to bypass the block without breaking this.
    import inspect

    from actionvouch.importers import LIVE_PROVIDER_STATUS

    for provider in LIVE_PROVIDER_STATUS:
        status = live_import_status(provider)
        assert status["blocked"] is True, provider
        assert status["valid"] is False, provider

    bogus = live_import_status("zapiir_typo")
    assert bogus["blocked"] is True
    assert bogus["valid"] is False

    assert list(inspect.signature(live_import_status).parameters) == ["provider"]


def test_actionvouch_compliance_readiness_never_claims_certification():
    project = load_project(SAMPLE)

    payload = build_compliance_readiness_report(project, packet_dir=RELEASE_PACKET_DIR)

    assert payload["certification_status"] == "not_certified"
    assert payload["attestation_status"] == "not_attested"
    assert payload["summary"]["control_count"] >= 6
    assert any(control["control_id"] == "AV-3PA-001" for control in payload["controls"])
    assert any(control["control_id"] == "AV-GOV-002" for control in payload["controls"])
    assert any(control["control_id"] == "AV-MCP-001" for control in payload["controls"])
    assert any("SOC 2" in item for item in payload["guardrails"])


def test_actionvouch_approval_queue_fails_closed_for_missing_evidence(tmp_path):
    project = load_project(SAMPLE)
    candidates = list_approval_candidates(project)

    assert candidates
    support = create_approval_request(project, "evt_support_draft_001")
    reviewed = review_approval(
        support,
        project=project,
        decision="approved_draft",
        reviewer="Ops Lead",
        reviewed_at="2026-06-19T09:00:00-04:00",
    )

    assert isinstance(reviewed, ApprovalRecord)
    assert reviewed.decision == "needs_evidence"
    assert "source_citations" in reviewed.required_evidence
    assert reviewed.validate() == []
    assert reviewed.review_history
    assert reviewed.previous_record_hash

    destructive = create_approval_request(project, "evt_file_delete_001")
    destructive_reviewed = review_approval(
        destructive,
        project=project,
        decision="approved_draft",
        reviewer="IT Lead",
    )
    assert destructive_reviewed.decision == "blocked"
    assert any("Destructive" in reason for reason in destructive_reviewed.reasons)
    assert destructive_reviewed.review_history


def _approvable_project():
    # Build a project whose single event legitimately reaches a live
    # 'approved_draft' policy decision, so the approval gate's happy path and
    # independence check can be exercised.
    project = load_project(SAMPLE)
    project = replace(project, policies=default_policy_rules())
    event = next(
        item
        for item in project.action_events
        if item.event_id == "evt_support_draft_001"
    )
    proof = EvidenceItem(
        evidence_id="ev_cc_full",
        source_type="local_file",
        summary="Customer context, citations, owner sign-off.",
        source_ref="local://cc.md",
        satisfies=["customer_context", "source_citations", "human_owner"],
    )
    approved_event = replace(
        event,
        approval_state="approved_draft",
        approver="Independent Reviewer",
        evidence=["ev_cc_full"],
    )
    others = [e for e in project.action_events if e.event_id != event.event_id]
    project = replace(
        project,
        evidence=[*project.evidence, proof],
        action_events=[approved_event, *others],
    )
    return project, approved_event


def test_approval_gate_honors_an_independent_reviewer():
    # M2: when the live policy decision is approved_draft and the reviewer is
    # independent of the agent owner, the approval is honored.
    project, event = _approvable_project()
    record = create_approval_request(project, event.event_id)

    reviewed = review_approval(
        record,
        project=project,
        decision="approved_draft",
        reviewer="Independent Reviewer",
    )

    assert reviewed.decision == "approved_draft"
    assert reviewed.validate() == []


def test_approval_gate_blocks_self_review_by_the_owner():
    # M2: even with a clean live decision, the agent owner cannot self-approve.
    project, event = _approvable_project()
    agent = project.get_agent(event.agent_id)
    assert agent is not None
    record = create_approval_request(project, event.event_id)

    reviewed = review_approval(
        record,
        project=project,
        decision="approved_draft",
        reviewer=agent.owner,
    )

    assert reviewed.decision == "needs_review"
    assert any("independent reviewer" in reason for reason in reviewed.reasons)


def test_approval_gate_rejects_a_forged_approved_record():
    # M2: a hand-forged record claiming approved_draft with empty required
    # evidence cannot be promoted; the gate recomputes from the project.
    project = load_project(SAMPLE)
    forged = ApprovalRecord.from_dict(
        {
            "approval_id": "approval_forged",
            "project_id": project.project_id,
            "event_id": "evt_support_draft_001",
            "action_class": "customer_message",
            "decision": "approved_draft",
            "reviewer": "Totally Real Reviewer",
            "required_evidence": [],
            "evidence": ["ev_manual_intake"],
            "review_history": [{"decision": "approved_draft", "reviewer": "x"}],
        }
    )
    # The forged record passes structural validation on its own ...
    assert forged.validate() == []

    # ... but the gate recomputes the live decision and refuses to promote it.
    reviewed = review_approval(
        forged,
        project=project,
        decision="approved_draft",
        reviewer="Totally Real Reviewer",
    )
    assert reviewed.decision != "approved_draft"
    assert "source_citations" in reviewed.required_evidence


def test_evidence_room_hash_verification_detects_tampering(tmp_path):
    # L2: the manifest's SHA-256 hashes must be verifiable, not decorative.
    project = load_project(SAMPLE)
    build_evidence_room(project, tmp_path)

    intact = verify_evidence_room(tmp_path)
    assert intact["intact"] is True
    assert intact["checked"] > 0
    assert intact["mismatched"] == []

    report = tmp_path / "risk-report.md"
    report.write_text(
        report.read_text(encoding="utf-8") + "\nTAMPERED\n", encoding="utf-8"
    )

    tampered = verify_evidence_room(tmp_path)
    assert tampered["intact"] is False
    assert "risk-report.md" in tampered["mismatched"]


def test_approval_record_chain_link_is_verifiable():
    # L2: the approval previous_record_hash chain must be verifiable.
    project, event = _approvable_project()
    request = create_approval_request(project, event.event_id)
    reviewed = review_approval(
        request,
        project=project,
        decision="approved_draft",
        reviewer="Independent Reviewer",
    )

    assert verify_record_link(reviewed, request) is True
    # A tampered predecessor breaks the link.
    forged_predecessor = replace(request, reviewer="Someone Else")
    assert verify_record_link(reviewed, forged_predecessor) is False


def test_actionvouch_cli_approval_request_and_review(capsys, tmp_path):
    approval_path = tmp_path / "approval.json"
    markdown_path = tmp_path / "approval.md"
    request_payload = _run(
        capsys,
        [
            "approvals",
            "request",
            str(SAMPLE),
            "--event-id",
            "evt_support_draft_001",
            "--output",
            str(approval_path),
            "--markdown-output",
            str(markdown_path),
        ],
    )

    assert request_payload["valid"] is True
    assert approval_path.exists()
    assert markdown_path.exists()

    review_path = tmp_path / "reviewed.json"
    review_payload = _run(
        capsys,
        [
            "approvals",
            "review",
            str(approval_path),
            "--project",
            str(SAMPLE),
            "--decision",
            "approved_draft",
            "--reviewer",
            "Ops Lead",
            "--output",
            str(review_path),
        ],
    )
    assert review_payload["valid"] is True
    assert review_payload["approval"]["decision"] == "needs_evidence"


def test_actionvouch_realistic_import_fixtures_validate(tmp_path):
    fixtures = sorted(IMPORT_FIXTURE_DIR.glob("*.json"))
    assert fixtures
    result = import_project_from_paths(
        fixtures,
        project_id="av_realistic_fixture_test",
        name="Realistic Fixture Test",
        scope="Importer fixture test. No live external actions.",
        timestamp="2026-06-19T09:00:00-04:00",
    )
    target = tmp_path / "fixtures.json"
    save_project(result.project, target)
    loaded = load_project(target)

    assert loaded.validate() == []
    assert len(loaded.agents) == len(fixtures)
    assert any("external_api_call" in agent.action_classes for agent in loaded.agents)
    assert any(item.source_type == "missing_evidence" for item in loaded.evidence)


def test_actionvouch_mcp_fixture_preserves_protocol_risk():
    result = import_project_from_paths(
        [IMPORT_FIXTURE_DIR / "mcp_realistic_manifest.json"],
        project_id="av_mcp_fixture_test",
        name="MCP Fixture Test",
        scope="MCP fixture test. No live external actions.",
        timestamp="2026-06-19T09:00:00-04:00",
    )
    project = result.project
    report = build_report(project)
    graph = build_permission_graph(project)

    assert project.validate() == []
    assert project.agents[0].autonomy_level == "act_with_approval"
    assert all(tool.connector_type == "mcp" for tool in project.tools)
    assert all(
        tool.mcp_server_id == "mcp_crm_server_redacted" for tool in project.tools
    )
    assert report["summary"]["protocol_counts"]["mcp"] == len(project.tools)
    assert any(
        "Model Context Protocol" in item for item in report["framework_mappings"]
    )
    assert graph["summary"]["high_risk_path_count"] > 0
    assert any(path["connector_type"] == "mcp" for path in graph["high_risk_paths"])
    compliance = build_compliance_readiness_report(
        project, packet_dir=RELEASE_PACKET_DIR
    )
    mcp_control = next(
        control
        for control in compliance["controls"]
        if control["control_id"] == "AV-MCP-001"
    )
    assert mcp_control["status"] == "blocked"
    assert mcp_control["gaps"]


def test_actionvouch_missing_permission_evidence_cannot_satisfy_approval(tmp_path):
    source = tmp_path / "external_api_missing_permissions.json"
    source.write_text(
        json.dumps(
            {
                "template_version": "actionvouch.manual_agent_inventory.v1",
                "agents": [
                    {
                        "agent_id": "api_agent",
                        "name": "API Agent",
                        "owner": "Ops Lead",
                        "business_purpose": "Call a redacted external API.",
                        "tools": ["External API Tool"],
                        "data_classes": ["customer_pii"],
                        "action_classes": ["external_api_call"],
                        "evidence": [
                            {
                                "evidence_id": "ev_api_owner_statement",
                                "source_type": "owner_statement",
                                "source_ref": "local redacted fixture",
                                "summary": "Owner says the workflow exists.",
                                "satisfies": ["owner", "purpose", "action_summary"],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = import_project_from_paths(
        [source],
        project_id="av_missing_permission_test",
        name="Missing Permission Test",
        scope="Missing permission evidence test.",
        timestamp="2026-06-19T09:00:00-04:00",
    )
    project = result.project
    event = replace(
        project.action_events[0],
        approval_state="approved_draft",
        approver="Independent Reviewer",
    )
    project = replace(project, action_events=[event])

    decision = evaluate_action_event(project, event)
    graph_project = replace(
        project,
        tools=[
            replace(
                project.tools[0],
                evidence=[
                    item.evidence_id
                    for item in project.evidence
                    if item.source_type == "missing_evidence"
                ],
            )
        ],
    )
    graph = build_permission_graph(graph_project)

    assert decision.classification == "needs_review"
    assert any("tool_permissions" in reason for reason in decision.reasons)
    assert graph["summary"]["missing_evidence_edge_count"] > 0


def test_actionvouch_evidence_room_contains_manifest_and_guardrails(tmp_path):
    project = load_project(SAMPLE)
    manifest = build_evidence_room(project, tmp_path / "evidence-room")

    file_names = {Path(item["path"]).name for item in manifest["files"]}
    assert manifest["certification_status"] == "not_certified"
    assert "manifest.json" in file_names
    assert "risk-report.md" in file_names
    assert "console.html" in file_names
    assert "claim-register.md" in file_names
    assert "permission-graph.json" in file_names
    assert "customer-executive-summary.md" in file_names


def test_actionvouch_evidence_room_requires_release_packet_docs(tmp_path):
    project = load_project(SAMPLE)
    empty_packet = tmp_path / "empty-packet"
    empty_packet.mkdir()

    with pytest.raises(FileNotFoundError):
        build_evidence_room(
            project,
            tmp_path / "evidence-room",
            release_packet_dir=empty_packet,
        )


def test_actionvouch_evidence_room_default_packet_dir_is_project_root(
    capsys, tmp_path, monkeypatch
):
    monkeypatch.chdir(PROJECT_ROOT.parent)
    output_dir = tmp_path / "evidence-room"

    payload = _run(
        capsys,
        [
            "evidence-room",
            str(SAMPLE),
            "--output",
            str(output_dir),
        ],
    )

    assert payload["valid"] is True
    assert (output_dir / "claim-register.md").exists()


def test_actionvouch_cli_evidence_room(capsys, tmp_path):
    payload = _run(
        capsys,
        [
            "evidence-room",
            str(SAMPLE),
            "--output",
            str(tmp_path / "evidence-room"),
        ],
    )

    assert payload["valid"] is True
    assert payload["status"] == "evidence_room_written"
    assert (tmp_path / "evidence-room" / "manifest.json").exists()


def test_actionvouch_permission_graph_cli(capsys, tmp_path):
    graph_path = tmp_path / "permission-graph.json"
    payload = _run(
        capsys,
        [
            "permission-graph",
            str(SAMPLE),
            "--output",
            str(graph_path),
        ],
    )

    assert payload["valid"] is True
    assert payload["status"] == "permission_graph_ready"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    assert graph["summary"]["high_risk_path_count"] > 0
    assert graph["summary"]["missing_evidence_edge_count"] > 0
    assert any(path["missing_evidence"] for path in graph["high_risk_paths"])
    assert all(
        path["action_class"] not in {"observe", "draft"}
        for path in graph["high_risk_paths"]
    )
    assert graph["guardrails"]


def test_actionvouch_research_watch_cli_and_stale_flags(capsys, tmp_path):
    report_path = tmp_path / "research-watch.md"
    payload = _run(
        capsys,
        [
            "research-watch",
            "--format",
            "markdown",
            "--output",
            str(report_path),
            "--last-taxonomy-reviewed-at",
            "2026-01-01",
        ],
    )
    direct = build_research_watch_report(last_taxonomy_reviewed_at="2026-01-01")

    assert payload["valid"] is True
    assert payload["signal_count"] >= 14
    assert payload["stale_recommendation_flag_count"] > 0
    assert direct["stale_recommendation_flags"]
    assert any(
        flag["signal_id"] == "openai_agents_mcp_docs"
        for flag in direct["stale_recommendation_flags"]
    )
    text = report_path.read_text(encoding="utf-8")
    assert "ActionVouch Research Watch" in text
    assert "mcp_spec_2025_06_18" in text


def test_internal_pilot_project_validates_and_preserves_missing_evidence():
    project = load_project(PILOT)
    report = build_report(project)

    assert project.validate() == []
    assert project.response_mode == "evidence_based_answer"
    assert any(item.source_type == "missing_evidence" for item in project.evidence)
    assert report["summary"]["evidence_gap_count"] > 0
    assert "Tradeoffs" in report["sections"]
    assert any("not legal advice" in item for item in report["guardrails"])
