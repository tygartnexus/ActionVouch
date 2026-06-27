"""Editable local HTML console for ActionVouch audit projects."""

from __future__ import annotations

import json
from html import escape

from .response_quality import response_mode_options
from .models import AuditProject
from .report import build_report


def render_editable_console_html(project: AuditProject) -> str:
    """Render a self-contained local editor.

    The console intentionally has no network calls and no backend write path. It
    lets a pilot operator edit the project JSON in the browser, run lightweight
    client-side checks, and download a revised JSON file for CLI validation.
    """

    report = build_report(project)
    project_payload = project.to_dict()
    project_json = json.dumps(project_payload, indent=2, sort_keys=True)
    project_script_json = _script_json(project_payload)
    summary = report["summary"]
    mode_options = response_mode_options()
    mode_options_json = _script_json(mode_options)
    mode_options_html = "\n".join(
        (
            f'<option value="{escape(option["value"])}">'
            f'{escape(option["ui_label"])}</option>'
        )
        for option in mode_options
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ActionVouch Editable Console - {escape(project.name)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #202734;
      --muted: #5e6a7a;
      --line: #d7dde8;
      --accent: #0f766e;
      --danger: #a33a22;
      --warn: #8a5a00;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      padding: 18px 24px;
    }}
    main {{
      display: grid;
      grid-template-columns: minmax(320px, 440px) minmax(420px, 1fr);
      gap: 16px;
      padding: 16px;
    }}
    h1, h2, h3 {{ margin: 0 0 10px; }}
    p {{ margin: 0 0 10px; color: var(--muted); }}
    button {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      padding: 9px 11px;
      cursor: pointer;
      font-weight: 700;
    }}
    button.primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
    button.warn {{ border-color: #d9aa48; color: var(--warn); }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(3, minmax(90px, 1fr));
      gap: 8px;
      margin-top: 12px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      min-height: 66px;
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; font-size: 22px; margin-top: 6px; }}
    textarea {{
      width: 100%;
      min-height: calc(100vh - 220px);
      resize: vertical;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      font-family: Consolas, "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      color: var(--text);
      background: #fbfcfe;
    }}
    .status {{
      white-space: pre-wrap;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
      min-height: 72px;
    }}
    .status.error {{ border-color: #e2a099; color: var(--danger); }}
    .status.ok {{ border-color: #94c9bc; color: var(--accent); }}
    label {{ display: block; font-size: 12px; color: var(--muted); margin-bottom: 5px; }}
    select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      margin-bottom: 8px;
      background: var(--panel);
      color: var(--text);
    }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      margin-bottom: 8px;
    }}
    .quick-add {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }}
    .mode-badge {{
      display: inline-block;
      border: 1px solid #94c9bc;
      border-radius: 999px;
      padding: 4px 8px;
      color: var(--accent);
      font-weight: 700;
    }}
    @media (max-width: 900px) {{
      main {{ grid-template-columns: 1fr; }}
      .summary {{ grid-template-columns: repeat(2, minmax(90px, 1fr)); }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>ActionVouch Editable Console</h1>
    <p>{escape(project.name)} - local-only editor. Download JSON and re-run CLI validation before using outputs.</p>
    <div class="toolbar">
      <button class="primary" type="button" onclick="validateProject()">Validate JSON</button>
      <button type="button" onclick="downloadProject()">Download Project JSON</button>
      <button type="button" onclick="downloadAuditRequest()">Download Audit Request JSON</button>
      <button type="button" onclick="loadExampleAgent()">Add Agent</button>
      <button type="button" onclick="loadExampleTool()">Add Tool</button>
      <button type="button" onclick="loadMissingEvidence()">Add Missing Evidence</button>
      <button class="warn" type="button" onclick="resetOriginal()">Reset Original</button>
    </div>
  </header>
  <main>
    <section class="panel">
      <h2>Project Gate</h2>
      <p>Current report status: <strong>{escape(report['status'])}</strong></p>
      <div class="summary">
        <div class="metric"><span>Agents</span><strong>{summary['agent_count']}</strong></div>
        <div class="metric"><span>Tools</span><strong>{summary['tool_count']}</strong></div>
        <div class="metric"><span>Events</span><strong>{summary['action_event_count']}</strong></div>
        <div class="metric"><span>Findings</span><strong>{summary['risk_finding_count']}</strong></div>
        <div class="metric"><span>Evidence Gaps</span><strong>{summary['evidence_gap_count']}</strong></div>
        <div class="metric"><span>Confidence</span><strong>{summary['confidence_score']:.2f}</strong></div>
      </div>
      <h3>Quick Add Fields</h3>
      <h3>AI Response Mode</h3>
      <label for="responseMode">Mode selector</label>
      <select id="responseMode" onchange="persistResponseMode()">
        {mode_options_html}
      </select>
      <p>Selected: <span id="selectedModeBadge" class="mode-badge">Accuracy Mode</span></p>
      <p>Legal Risk Review Mode is issue spotting only. It is not legal advice, certification, or an approval.</p>
      <p>Use Download Audit Request JSON to persist the selected mode into a local request payload.</p>
      <div class="quick-add">
        <div>
          <label for="quickOwner">Owner</label>
          <input id="quickOwner" value="Human Owner">
        </div>
        <div>
          <label for="quickTool">Tool ID</label>
          <input id="quickTool" value="review_tool">
        </div>
        <div>
          <label for="quickAction">Action Class</label>
          <input id="quickAction" value="draft">
        </div>
        <div>
          <label for="quickEvidence">Evidence ID</label>
          <input id="quickEvidence" value="ev_owner_note">
        </div>
      </div>
      <h3>Client-Side Status</h3>
      <div id="status" class="status">No browser-side validation has run yet.</div>
      <p>This console does not save automatically, call APIs, or validate every server-side rule. The final gate remains `actionvouch validate <project.json>`.</p>
    </section>
    <section class="panel">
      <h2>Editable Audit Project JSON</h2>
      <textarea id="projectJson" spellcheck="false">{escape(project_json)}</textarea>
    </section>
  </main>
  <script>
    const originalProject = {project_script_json};
    const responseModeOptions = {mode_options_json};
    const responseModeStorageKey = "actionvouch.response_mode.v1";
    const projectResponseMode = originalProject.response_mode || "evidence_based_answer";
    const requiredTopLevel = ["project_id", "name", "version", "scope", "agents", "tools", "policies", "action_events", "evidence"];

    function getProject() {{
      return JSON.parse(document.getElementById("projectJson").value);
    }}

    function setProject(project) {{
      document.getElementById("projectJson").value = JSON.stringify(project, null, 2);
    }}

    function validateProject() {{
      const status = document.getElementById("status");
      try {{
        const project = getProject();
        const errors = [];
        for (const field of requiredTopLevel) {{
          if (!(field in project)) errors.push("Missing top-level field: " + field);
        }}
        if (!Array.isArray(project.agents) || project.agents.length === 0) errors.push("At least one agent is required.");
        if (!Array.isArray(project.tools)) errors.push("tools must be an array.");
        if (!Array.isArray(project.evidence)) errors.push("evidence must be an array.");
        if (project.response_mode && !responseModeOptions.some((item) => item.value === project.response_mode)) errors.push("response_mode is not a supported response mode.");
        for (const agent of project.agents || []) {{
          if (!agent.agent_id) errors.push("Agent missing agent_id.");
          if (!agent.owner) errors.push("Agent " + (agent.agent_id || "<missing>") + " missing owner.");
          if (!agent.business_purpose) errors.push("Agent " + (agent.agent_id || "<missing>") + " missing business_purpose.");
        }}
        if (errors.length) {{
          status.className = "status error";
          status.textContent = errors.join("\\n");
        }} else {{
          status.className = "status ok";
          status.textContent = "Browser-side checks passed. Download and run the CLI validator for authoritative validation.";
        }}
      }} catch (err) {{
        status.className = "status error";
        status.textContent = "Invalid JSON: " + err.message;
      }}
    }}

    function downloadProject() {{
      const project = getProject();
      project.response_mode = selectedResponseMode();
      const blob = new Blob([JSON.stringify(project, null, 2) + "\\n"], {{type: "application/json"}});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = (project.project_id || "actionvouch-project") + ".json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }}

    function selectedResponseMode() {{
      return document.getElementById("responseMode").value || "evidence_based_answer";
    }}

    function selectedModeMetadata() {{
      const mode = selectedResponseMode();
      return responseModeOptions.find((item) => item.value === mode) || responseModeOptions[0];
    }}

    function persistResponseMode() {{
      const mode = selectedResponseMode();
      localStorage.setItem(responseModeStorageKey, mode);
      const metadata = selectedModeMetadata();
      document.getElementById("selectedModeBadge").textContent = metadata.ui_label;
    }}

    function loadSavedResponseMode() {{
      const select = document.getElementById("responseMode");
      const saved = localStorage.getItem(responseModeStorageKey);
      if (saved && responseModeOptions.some((item) => item.value === saved)) {{
        select.value = saved;
      }} else if (responseModeOptions.some((item) => item.value === projectResponseMode)) {{
        select.value = projectResponseMode;
      }} else {{
        select.value = "evidence_based_answer";
      }}
      persistResponseMode();
    }}

    function buildAuditRequestPayload(project) {{
      const metadata = selectedModeMetadata();
      return {{
        request_id: (project.project_id || "actionvouch_project") + "_response_quality_review",
        title: "Review " + (project.name || "ActionVouch project") + " with " + metadata.ui_label,
        request: "Review this local ActionVouch audit package using the selected Accuracy, Evidence, and Honest Feedback mode. Separate facts, assumptions, unknowns, confidence, evidence, risks, counterarguments, recommendation, tradeoffs, and what would change the recommendation.",
        domain: "ai_agent_governance",
        objectives: [
          "Assess the audit package without inventing evidence.",
          "Identify missing evidence and unsafe claims.",
          "Recommend the next controlled-pilot action."
        ],
        constraints: [
          "Local-only review.",
          "No live external actions.",
          "No legal advice or certification claim."
        ],
        response_mode: selectedResponseMode(),
        business_context: {{
          source_project_id: project.project_id || "",
          source_project_name: project.name || "",
          selected_mode_label: metadata.ui_label,
          generated_by: "ActionVouch local editable console"
        }}
      }};
    }}

    function downloadAuditRequest() {{
      const project = getProject();
      const requestPayload = buildAuditRequestPayload(project);
      const blob = new Blob([JSON.stringify(requestPayload, null, 2) + "\\n"], {{type: "application/json"}});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = requestPayload.request_id + ".json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }}

    function loadExampleAgent() {{
      const project = getProject();
      const owner = document.getElementById("quickOwner").value || "Human Owner";
      const tool = document.getElementById("quickTool").value || "review_tool";
      const evidence = document.getElementById("quickEvidence").value || "ev_owner_note";
      project.agents = project.agents || [];
      project.agents.push({{
        agent_id: "agent_" + (project.agents.length + 1),
        name: "New Review Agent",
        owner,
        business_purpose: "Describe the business purpose before validation.",
        provider: "unknown",
        model_or_runtime: "unknown",
        tools: [tool],
        data_classes: ["customer_pii"],
        action_classes: ["observe", document.getElementById("quickAction").value || "draft"],
        risk_level: "unknown",
        approval_policy_id: "observe_only_default",
        status: "draft_inventory",
        evidence: [evidence],
        unknowns: ["Imported from editable console; verify details before delivery."]
      }});
      setProject(project);
      validateProject();
    }}

    function loadExampleTool() {{
      const project = getProject();
      const owner = document.getElementById("quickOwner").value || "Human Owner";
      const tool = document.getElementById("quickTool").value || "review_tool";
      const evidence = document.getElementById("quickEvidence").value || "ev_owner_note";
      project.tools = project.tools || [];
      project.tools.push({{
        tool_id: tool,
        name: "Review Tool",
        system: "unknown",
        permission_type: "unknown",
        data_access: ["customer_pii"],
        actions_supported: ["observe", document.getElementById("quickAction").value || "draft"],
        external_effect: false,
        credential_owner: owner,
        risk_level: "unknown",
        notes: "Added from editable console; verify permissions.",
        evidence: [evidence],
        unknowns: ["Permission export not attached."]
      }});
      setProject(project);
      validateProject();
    }}

    function loadMissingEvidence() {{
      const project = getProject();
      const evidence = document.getElementById("quickEvidence").value || "ev_missing_detail";
      project.evidence = project.evidence || [];
      project.evidence.push({{
        evidence_id: evidence,
        source_type: "missing_evidence",
        source_ref: "",
        summary: "Required evidence has not been attached.",
        limitation: "Cannot treat this item as verified until evidence is supplied.",
        confidence: 0.35,
        collected_at: "",
        reviewer: "ActionVouch editable console",
        satisfies: []
      }});
      setProject(project);
      validateProject();
    }}

    function resetOriginal() {{
      setProject(originalProject);
      validateProject();
    }}

    document.addEventListener("DOMContentLoaded", loadSavedResponseMode);
  </script>
</body>
</html>
"""


def _script_json(value: object) -> str:
    """Serialize JSON safely for embedding inside a script block."""

    return (
        json.dumps(value, sort_keys=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
