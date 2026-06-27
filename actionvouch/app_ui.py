"""Single-page UI for the local-first ActionVouch app.

This module holds only the HTML/CSS/JS string served by :mod:`actionvouch.app`.
It is intentionally separate so the server module stays focused on request
handling and security. The page is static and data-driven: it pulls allowed
vocabularies from ``/api/schema`` and runs the audit over the other ``/api/*``
endpoints. All user-entered values are rendered with ``textContent`` (never
``innerHTML``), so the guided wizard cannot introduce DOM injection.

The page carries no inline event handlers: every interaction is wired with
``addEventListener`` over ``data-act`` attributes, so the Content-Security-Policy
can pin the one inline script by ``sha256`` hash instead of allowing
``script-src 'unsafe-inline'``. :func:`app_csp` is the single source of truth for
that policy and is shared by the page ``<meta>`` tag and the server response
header.
"""

from __future__ import annotations

import base64
import hashlib


def render_app_html() -> str:
    """Return the self-contained single-page UI."""

    return _APP_HTML


def app_csp() -> str:
    """Content-Security-Policy for the app page.

    ``script-src`` pins the sha256 of the single inline script (no
    ``'unsafe-inline'``), so an injected ``<script>`` or inline handler cannot
    execute even if a future change introduced a DOM-injection sink. Shared by
    the page ``<meta>`` tag and the server header so the two never drift.
    """

    return APP_CSP


# The one inline script. Kept as a normal (non-raw) triple-quoted string so the
# ``\\n`` sequences below stay byte-identical to the previous version. The CSP
# hash is computed from exactly these bytes, and these same bytes are embedded
# verbatim between the <script> tags, so the browser-computed hash always
# matches.
_APP_SCRIPT = """
    var SCHEMA = null;
    var P = emptyProject();

    function emptyProject() {
      return { project_id: "", name: "", version: "actionvouch.audit_project.v1",
        created_at: "", updated_at: "", scope: "", agents: [], tools: [],
        policies: (SCHEMA ? SCHEMA.default_policies : []), action_events: [],
        evidence: [], assumptions: [], unknowns: [], response_mode: "evidence_based_answer" };
    }
    function el(id) { return document.getElementById(id); }
    function val(id) { var e = el(id); return e ? e.value.trim() : ""; }
    function slug(s) { return (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "item"; }
    function splitList(s) { return (s || "").split(",").map(function (x) { return x.trim(); }).filter(Boolean); }
    function orList(s, dflt) { var x = splitList(s); return x.length ? x : dflt; }
    function api(action, body) {
      var payload = body || {};
      return fetch("/api/" + action, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).then(function (r) { return r.json(); });
    }
    function failed(d) {
      if (!d || !d.error) return false;
      show("Error: " + d.error, false);
      return true;
    }
    function show(text, ok) { var r = el("result"); r.textContent = text; r.className = "result " + (ok ? "ok" : "error"); }

    function fillSelect(id, values, opts) {
      var sel = el(id); sel.replaceChildren();
      (values || []).forEach(function (v) {
        var o = document.createElement("option"); o.value = v; o.textContent = v; sel.appendChild(o);
      });
    }
    function fillChecks(id, values, highlight) {
      var box = el(id); box.replaceChildren();
      (values || []).forEach(function (v) {
        var lab = document.createElement("label");
        var cb = document.createElement("input"); cb.type = "checkbox"; cb.value = v; cb.className = id + "-cb";
        lab.appendChild(cb);
        var span = document.createElement("span"); span.textContent = v;
        if (highlight && highlight.indexOf(v) !== -1) span.className = "hi";
        lab.appendChild(span); box.appendChild(lab);
      });
    }
    function checked(id) {
      return Array.prototype.slice.call(document.querySelectorAll("." + id + "-cb:checked")).map(function (c) { return c.value; });
    }
    function fillDatalist(id, values) {
      var dl = el(id); dl.replaceChildren();
      (values || []).forEach(function (v) { var o = document.createElement("option"); o.value = v; dl.appendChild(o); });
    }
    function setDefault(id, v) {
      var e = el(id);
      if (Array.prototype.slice.call(e.options).some(function (o) { return o.value === v; })) e.value = v;
    }

    function showTab(name) {
      ["wizard", "advanced", "mcp"].forEach(function (n) {
        el("view-" + n).classList.toggle("hidden", n !== name);
        el("tab" + n.charAt(0).toUpperCase() + n.slice(1)).classList.toggle("active", n === name);
      });
      if (name === "advanced") syncJson();
    }
    function showAbout() { el("about").classList.remove("hidden"); }
    function hideAbout() { el("about").classList.add("hidden"); }
    function showHelp() { el("help").classList.remove("hidden"); }
    function hideHelp() { el("help").classList.add("hidden"); }
    function dismissWelcome() { el("welcome").classList.add("hidden"); }
    function welcomeExample() {
      api("example", {}).then(function (d) {
        el("json").value = JSON.stringify(d.project, null, 2);
        syncFromJson(); dismissWelcome();
      });
    }
    function onProjectField() {
      P.name = val("pName"); P.scope = val("pScope");
      if (!P.project_id) P.project_id = slug(P.name || "audit_project");
      syncJson();
    }

    function addTool() {
      var name = val("tName"); if (!name) { show("Tool needs a name.", false); return; }
      P.tools.push({ tool_id: slug(name), name: name, system: val("tSystem") || "unknown",
        permission_type: val("tPerm") || "unknown", data_access: orList(val("tData"), ["unknown"]),
        actions_supported: checked("tActions").length ? checked("tActions") : ["observe"], external_effect: el("tExternal").checked,
        credential_owner: val("tOwner") || "unknown", risk_level: val("tRisk") || "unknown",
        connector_type: val("tConnector") || "manual", notes: "Added via wizard.", evidence: [], unknowns: [] });
      ["tName", "tSystem", "tPerm", "tOwner", "tData"].forEach(function (i) { el(i).value = ""; });
      el("tExternal").checked = false;
      renderAll(); refreshDependents(); syncJson();
    }
    function addAgent() {
      var name = val("aName"); if (!name) { show("Agent needs a name.", false); return; }
      var tools = checked("aTools"); if (!tools.length) tools = ["unknown"];
      P.agents.push({ agent_id: slug(name), name: name, owner: val("aOwner") || "unknown",
        business_purpose: val("aPurpose") || "Describe the business purpose.", provider: val("aProvider") || "unknown",
        model_or_runtime: val("aModel") || "unknown", tools: tools, data_classes: orList(val("aData"), ["unknown"]),
        action_classes: checked("aActions").length ? checked("aActions") : ["observe"],
        autonomy_level: val("aAutonomy") || "observe", risk_level: val("aRisk") || "unknown",
        approval_policy_id: val("aPolicy") || "observe_only_default", status: "draft_inventory", evidence: [], unknowns: [] });
      ["aName", "aOwner", "aProvider", "aModel", "aData", "aPurpose"].forEach(function (i) { el(i).value = ""; });
      renderAll(); refreshDependents(); syncJson();
    }
    function addEvidence() {
      var id = val("eId") || ("ev_" + (P.evidence.length + 1));
      var type = val("eType") || "owner_statement";
      P.evidence.push({ evidence_id: slug(id), source_type: type, source_ref: val("eRef") || "local self-serve input",
        summary: val("eSummary") || "Evidence summary.", limitation: val("eLimit"),
        confidence: 0.5, collected_at: "", reviewer: "Self-serve wizard", satisfies: splitList(val("eSat")) });
      ["eId", "eRef", "eSat", "eSummary", "eLimit"].forEach(function (i) { el(i).value = ""; });
      renderAll(); refreshDependents(); syncJson();
    }
    function addEvent() {
      var agent = val("vAgent"); if (!agent) { show("Add an agent first, then the event.", false); return; }
      var ev = checked("vEvidence");
      P.action_events.push({ event_id: "evt_" + slug(agent) + "_" + (P.action_events.length + 1),
        agent_id: agent, timestamp: new Date().toISOString(), request_summary: val("vRequest") || "Imported workflow review.",
        action_class: val("vAction") || "observe", action_payload_summary: val("vPayload") || "No live action executed.",
        approval_state: val("vApproval") || "proposed", outcome: "not_executed", tool_called: val("vTool"),
        approver: val("vApprover"), evidence: ev, unknowns: [] });
      ["vRequest", "vPayload", "vApprover"].forEach(function (i) { el(i).value = ""; });
      renderAll(); syncJson();
    }
    function removeItem(kind, i) { P[kind].splice(i, 1); renderAll(); refreshDependents(); syncJson(); }

    function renderList(kind, containerId, labelFn) {
      var c = el(containerId); c.replaceChildren();
      P[kind].forEach(function (item, i) {
        var row = document.createElement("div"); row.className = "item";
        var meta = document.createElement("div"); meta.className = "meta";
        labelFn(meta, item);
        var btn = document.createElement("button"); btn.className = "small"; btn.textContent = "Remove";
        btn.onclick = (function (idx) { return function () { removeItem(kind, idx); }; })(i);
        row.appendChild(meta); row.appendChild(btn); c.appendChild(row);
      });
    }
    function line(parent, boldText, rest) {
      var b = document.createElement("b"); b.textContent = boldText; parent.appendChild(b);
      var s = document.createElement("div"); s.textContent = rest; parent.appendChild(s);
    }
    function renderAll() {
      el("cTools").textContent = "(" + P.tools.length + ")";
      el("cAgents").textContent = "(" + P.agents.length + ")";
      el("cEvidence").textContent = "(" + P.evidence.length + ")";
      el("cEvents").textContent = "(" + P.action_events.length + ")";
      renderList("tools", "listTools", function (m, t) { line(m, t.name, t.connector_type + " - actions: " + (t.actions_supported.join(", ") || "none") + (t.external_effect ? " - external effect" : "")); });
      renderList("agents", "listAgents", function (m, a) { line(m, a.name, a.autonomy_level + " - tools: " + a.tools.join(", ") + " - actions: " + a.action_classes.join(", ")); });
      renderList("evidence", "listEvidence", function (m, e) { line(m, e.evidence_id, e.source_type + " - " + e.summary); });
      renderList("action_events", "listEvents", function (m, v) { line(m, v.event_id, v.action_class + " by " + v.agent_id + " [" + v.approval_state + "]"); });
    }
    function refreshDependents() {
      fillChecks("aTools", P.tools.map(function (t) { return t.tool_id; }));
      if (!P.tools.length) el("aTools").replaceChildren(Object.assign(document.createElement("span"), { className: "hint", textContent: "Add tools above first." }));
      fillSelect("vAgent", P.agents.map(function (a) { return a.agent_id; }));
      var vt = el("vTool"); vt.replaceChildren();
      var none = document.createElement("option"); none.value = ""; none.textContent = "(none)"; vt.appendChild(none);
      P.tools.forEach(function (t) { var o = document.createElement("option"); o.value = t.tool_id; o.textContent = t.tool_id; vt.appendChild(o); });
      fillChecks("vEvidence", P.evidence.map(function (e) { return e.evidence_id; }));
      if (!P.evidence.length) el("vEvidence").replaceChildren(Object.assign(document.createElement("span"), { className: "hint", textContent: "Add evidence above first." }));
    }

    function syncJson() { el("json").value = JSON.stringify(P, null, 2); }
    function isObject(x) { return x !== null && typeof x === "object" && !Array.isArray(x); }
    function syncFromJson() {
      var parsed;
      try { parsed = JSON.parse(el("json").value); } catch (e) { show("Invalid JSON: " + e.message, false); return; }
      if (!isObject(parsed)) { show("Project JSON must be an object.", false); return; }
      ["agents", "tools", "action_events", "evidence"].forEach(function (k) {
        if (!Array.isArray(parsed[k])) parsed[k] = [];
      });
      P = parsed;
      if (!P.policies || !P.policies.length) P.policies = SCHEMA.default_policies;
      el("pName").value = P.name || ""; el("pScope").value = P.scope || "";
      renderAll(); refreshDependents(); show("Applied JSON to the wizard.", true); showTab("wizard");
    }
    function loadExample() {
      api("example", {}).then(function (d) { el("json").value = JSON.stringify(d.project, null, 2); show("Loaded an example. Click 'Apply JSON to wizard' or Validate.", true); });
    }

    function run(action) {
      api(action, { project: P }).then(function (d) {
        if (failed(d)) return;
        if (action === "validate") {
          if (d.valid) show("Valid. project_id = " + d.project_id + "\\nReady to score and report.", true);
          else show("Not valid yet (fix these):\\n- " + d.errors.join("\\n- "), false);
        } else if (action === "score") {
          if (!d.valid) { show("Fix validation first:\\n- " + d.errors.join("\\n- "), false); return; }
          show(d.findings.length + " risk finding(s):\\n" + d.findings.map(function (f) { return "[" + f.severity + "] " + f.title; }).join("\\n"), true);
        }
      });
    }
    function report(format) {
      api("report", { project: P, format: format }).then(function (d) {
        if (failed(d)) return;
        show(d.content, true);
        setDownloads([{ label: "Download report (.md)", name: "actionvouch-report.md", content: d.content, mime: "text/markdown" }]);
      });
    }
    function openDashboard() {
      api("dashboard", { project: P }).then(function (d) {
        if (failed(d)) return;
        var u = URL.createObjectURL(new Blob([d.html], { type: "text/html" }));
        window.open(u, "_blank");
        setTimeout(function () { URL.revokeObjectURL(u); }, 60000);
        show("Dashboard opened in a new tab.", true);
        setDownloads([{ label: "Download dashboard (.html)", name: "actionvouch-dashboard.html", content: d.html, mime: "text/html" }]);
      });
    }
    function downloadProject() { download("actionvouch-project.json", JSON.stringify(P, null, 2), "application/json"); }
    function mcpScan() {
      var raw = val("manifest"); var manifest;
      try { manifest = raw ? JSON.parse(raw) : null; } catch (e) { show("Invalid manifest JSON: " + e.message, false); return; }
      api("mcp-scan", { manifest: manifest }).then(function (d) {
        var r = d.result;
        if (!r || !r.valid) { show("MCP scan could not run: " + ((r && r.errors) || ["no manifest"]).join("; "), false); return; }
        var lines = ["Servers: " + r.summary.server_count + " (network-reaching: " + r.summary.network_reaching_servers + ")",
          "Tools: " + r.summary.tool_count + " (destructive: " + r.summary.destructive_tool_count + ", write-capable: " + r.summary.write_capable_tool_count + ")",
          "Highest server risk: " + r.summary.highest_server_risk, ""];
        r.servers.forEach(function (s) {
          lines.push("- " + s.name + " [" + s.risk_level + "] " + (s.risk_flags.join(", ") || ""));
          (s.tools || []).forEach(function (t) { lines.push("    " + t.name + " (" + t.risk_level + ")"); });
        });
        show(lines.join("\\n"), true);
      });
    }
    function setDownloads(items) {
      var bar = el("downloads"); bar.replaceChildren();
      (items || []).forEach(function (it) {
        var b = document.createElement("button"); b.textContent = it.label;
        b.onclick = function () { download(it.name, it.content, it.mime); };
        bar.appendChild(b);
      });
    }
    function download(name, content, mime) {
      var url = URL.createObjectURL(new Blob([content], { type: mime || "text/plain" }));
      var a = document.createElement("a"); a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    }

    // Wire every interaction declaratively (no inline handlers, so the CSP can
    // forbid 'unsafe-inline'). Elements carry data-act (handler name), optional
    // data-arg (single string argument), and optional data-on (event; default
    // "click").
    var ACTIONS = {
      showHelp: showHelp, hideHelp: hideHelp, showAbout: showAbout, hideAbout: hideAbout,
      helpToAbout: function () { hideHelp(); showAbout(); },
      showTab: showTab, welcomeExample: welcomeExample, dismissWelcome: dismissWelcome,
      onProjectField: onProjectField, addTool: addTool, addAgent: addAgent,
      addEvidence: addEvidence, addEvent: addEvent, run: run, report: report,
      openDashboard: openDashboard, downloadProject: downloadProject,
      loadExample: loadExample, syncFromJson: syncFromJson, mcpScan: mcpScan
    };
    function wireActions() {
      Array.prototype.slice.call(document.querySelectorAll("[data-act]")).forEach(function (node) {
        var evt = node.getAttribute("data-on") || "click";
        node.addEventListener(evt, function () {
          var fn = ACTIONS[node.getAttribute("data-act")];
          if (fn) fn(node.getAttribute("data-arg") || undefined);
        });
      });
    }

    function init() {
      api("schema", {}).then(function (d) {
        SCHEMA = d.schema; if (!P.policies.length) P.policies = SCHEMA.default_policies;
        el("aboutVersion").textContent = "v" + (SCHEMA.app_version || "");
        fillSelect("tConnector", SCHEMA.connector_types); fillSelect("tRisk", SCHEMA.risk_levels);
        fillSelect("aAutonomy", SCHEMA.autonomy_levels); fillSelect("aRisk", SCHEMA.risk_levels);
        fillSelect("aPolicy", SCHEMA.policy_ids);
        fillSelect("eType", SCHEMA.evidence_source_types);
        fillSelect("vAction", SCHEMA.action_classes); fillSelect("vApproval", SCHEMA.approval_states);
        setDefault("tConnector", "manual"); setDefault("tRisk", "unknown");
        setDefault("aAutonomy", "observe"); setDefault("aRisk", "unknown");
        setDefault("eType", "owner_statement");
        setDefault("vAction", "observe"); setDefault("vApproval", "proposed");
        fillChecks("tActions", SCHEMA.action_classes, SCHEMA.high_risk_action_classes);
        fillChecks("aActions", SCHEMA.action_classes, SCHEMA.high_risk_action_classes);
        fillDatalist("dataSuggest", SCHEMA.data_class_suggestions);
        refreshDependents(); renderAll(); syncJson();
      });
    }
    document.addEventListener("DOMContentLoaded", function () { wireActions(); init(); });
"""


_SCRIPT_SHA256 = base64.b64encode(
    hashlib.sha256(_APP_SCRIPT.encode("utf-8")).digest()
).decode("ascii")

APP_CSP = (
    "default-src 'self'; "
    "script-src 'sha256-" + _SCRIPT_SHA256 + "'; "
    "style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


# Page chrome (everything except the inline <script>). ``__CSP__`` is replaced
# with the hashed policy below; the script is concatenated verbatim so its bytes
# match the hash. No inline event handlers appear here — interactions use
# data-act and are wired by wireActions().
_APP_HEAD_BODY = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="__CSP__">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ActionVouch - Local Self-Serve Audit</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef1f6; --panel: #ffffff; --text: #16202b; --muted: #5f6b7a;
      --line: #d7dde8; --accent: #0f766e; --accent-deep: #0b5048; --accent-soft: #e7f3f0;
      --danger: #a33a22; --warn: #8a5a00;
      --shadow: 0 1px 2px rgba(16,32,40,.06), 0 6px 20px rgba(16,32,40,.05);
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); }
    .brandbar { display: flex; align-items: center; gap: 14px; background: linear-gradient(180deg, var(--accent) 0%, var(--accent-deep) 100%); color: #fff; padding: 13px 24px; }
    .brandbar .logo { width: 34px; height: 34px; flex: none; }
    .brandbar .word { font-size: 20px; font-weight: 800; letter-spacing: .2px; line-height: 1.1; }
    .brandbar .word span { opacity: .82; font-weight: 600; }
    .brandbar .tag { font-size: 12px; opacity: .9; }
    .brandbar .nav { margin-left: auto; display: flex; gap: 16px; }
    .brandbar .nav a { color: #fff; text-decoration: none; font-size: 13px; font-weight: 700; opacity: .95; cursor: pointer; border-bottom: 1px solid rgba(255,255,255,.4); }
    .subbar { background: var(--panel); border-bottom: 1px solid var(--line); padding: 8px 24px; }
    .badge { display: inline-block; border: 1px solid #94c9bc; background: var(--accent-soft); border-radius: 999px; padding: 4px 12px; color: var(--accent-deep); font-weight: 700; font-size: 12px; }
    .welcome { background: var(--accent-soft); border: 1px solid #bfe0d8; border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
    .welcome h3 { margin: 0 0 6px; color: var(--accent-deep); font-size: 15px; }
    .welcome p { margin: 0 0 10px; color: #2c4a44; font-size: 13px; }
    .modal { position: fixed; inset: 0; background: rgba(12,27,42,.45); display: flex; align-items: center; justify-content: center; padding: 20px; z-index: 50; }
    .modal .card { background: var(--panel); border-radius: 12px; box-shadow: var(--shadow); max-width: 560px; width: 100%; padding: 22px; max-height: 86vh; overflow: auto; }
    .modal h2 { display: flex; align-items: baseline; gap: 10px; }
    .modal .ver { color: var(--muted); font-size: 13px; font-weight: 400; }
    .modal h3 { margin: 14px 0 4px; font-size: 14px; }
    .modal ul { margin: 8px 0; padding-left: 18px; }
    .modal li { font-size: 13px; margin: 4px 0; }
    .modal .close { float: right; }
    .tabs { display: flex; gap: 8px; padding: 12px 24px 0; }
    .tab { border: 1px solid var(--line); border-bottom: none; border-radius: 8px 8px 0 0; background: #eef1f6; padding: 8px 14px; cursor: pointer; font-weight: 700; font-size: 13px; }
    .tab.active { background: var(--panel); color: var(--accent); }
    main { display: grid; grid-template-columns: minmax(420px, 1fr) minmax(360px, 0.8fr); gap: 16px; padding: 16px 24px; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; box-shadow: var(--shadow); }
    h2 { margin: 0 0 6px; font-size: 16px; }
    h3 { margin: 16px 0 6px; font-size: 14px; }
    p.hint, .hint { color: var(--muted); font-size: 12.5px; margin: 0 0 10px; }
    .redact { border: 1px solid #d9aa48; background: #fbf4e4; color: var(--warn); border-radius: 8px; padding: 8px 12px; font-size: 12.5px; margin-bottom: 12px; }
    label { display: block; font-size: 12px; color: var(--muted); margin: 8px 0 3px; }
    input, select, textarea { width: 100%; border: 1px solid var(--line); border-radius: 6px; padding: 8px; font-size: 13px; background: #fbfcfe; color: var(--text); }
    textarea { font-family: Consolas, "Courier New", monospace; }
    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .checks { display: flex; flex-wrap: wrap; gap: 6px 14px; border: 1px solid var(--line); border-radius: 6px; padding: 8px; background: #fbfcfe; }
    .checks label { display: inline-flex; align-items: center; gap: 5px; margin: 0; color: var(--text); font-size: 12.5px; }
    .checks input { width: auto; }
    .hi { color: var(--danger); font-weight: 700; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
    button { border: 1px solid var(--line); border-radius: 6px; background: var(--panel); color: var(--text); padding: 9px 12px; cursor: pointer; font-weight: 700; font-size: 13px; }
    button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.add { background: #eef6f4; border-color: #94c9bc; color: var(--accent); }
    button.small { padding: 4px 8px; font-size: 12px; }
    .item { border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
    .item .meta { font-size: 12.5px; }
    .item .meta b { font-size: 13px; }
    .count { color: var(--muted); font-size: 12px; font-weight: 400; }
    .result { white-space: pre-wrap; border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fbfcfe; min-height: 90px; font-family: Consolas, "Courier New", monospace; font-size: 12.5px; max-height: 70vh; overflow: auto; }
    .result.ok { border-color: #94c9bc; }
    .result.error { border-color: #e2a099; color: var(--danger); }
    .hidden { display: none; }
    @media (max-width: 960px) { main { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header class="brandbar">
    <svg class="logo" viewBox="0 0 48 48" aria-hidden="true">
      <path d="M24 3 6 10v12c0 11 7.6 19.4 18 23 10.4-3.6 18-12 18-23V10L24 3Z" fill="#ffffff" opacity=".16"/>
      <path d="M24 3 6 10v12c0 11 7.6 19.4 18 23 10.4-3.6 18-12 18-23V10L24 3Z" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linejoin="round"/>
      <path d="M15.5 24.5 21 30l11.5-12" fill="none" stroke="#ffffff" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div>
      <div class="word">Action<span>Vouch</span></div>
      <div class="tag">Local-first AI agent risk audit - runs on your machine</div>
    </div>
    <nav class="nav"><a data-act="showHelp">Help</a><a data-act="showAbout">About</a></nav>
  </header>
  <div class="subbar"><span class="badge">No network &middot; no credentials &middot; your data never leaves this computer</span></div>
  <div class="tabs">
    <div class="tab active" id="tabWizard" data-act="showTab" data-arg="wizard">Guided wizard</div>
    <div class="tab" id="tabAdvanced" data-act="showTab" data-arg="advanced">Advanced (JSON)</div>
    <div class="tab" id="tabMcp" data-act="showTab" data-arg="mcp">MCP scan</div>
  </div>
  <main>
    <section class="panel">
      <!-- WIZARD -->
      <div id="view-wizard">
        <div id="welcome" class="welcome">
          <h3>Welcome - build your audit in 6 guided steps</h3>
          <p>New to ActionVouch? Load a finished example to see how it works, or start fresh. Everything runs on your machine; nothing is sent anywhere.</p>
          <div class="toolbar">
            <button class="primary" type="button" data-act="welcomeExample">Load an example</button>
            <button type="button" data-act="dismissWelcome">Start fresh</button>
          </div>
        </div>
        <div class="redact">Redaction reminder: enter summaries only. Do not paste API keys, tokens, passwords, payment/bank/health data, or unredacted customer records.</div>

        <h2>1. Project</h2>
        <div class="grid2">
          <div><label>Business / project name</label><input id="pName" placeholder="Sample Services Co AI Agent Risk Audit" data-act="onProjectField" data-on="input"></div>
          <div><label>Scope (one line)</label><input id="pScope" placeholder="Customer support and CRM AI workflows" data-act="onProjectField" data-on="input"></div>
        </div>

        <h2>2. Tools / connectors <span class="count" id="cTools">(0)</span></h2>
        <p class="hint">Add each tool or connector your AI agents can use. Add these before agents so you can attach them.</p>
        <div class="grid2">
          <div><label>Tool name</label><input id="tName" placeholder="CRM API"></div>
          <div><label>System</label><input id="tSystem" placeholder="HubSpot"></div>
          <div><label>Permission type</label><input id="tPerm" placeholder="read_write / unknown"></div>
          <div><label>Credential owner</label><input id="tOwner" placeholder="Ops Lead"></div>
          <div><label>Data access (comma-separated)</label><input id="tData" list="dataSuggest" placeholder="customer_pii, financial"></div>
          <div><label>Connector type</label><select id="tConnector"></select></div>
          <div><label>Risk level</label><select id="tRisk"></select></div>
          <div><label style="display:inline-flex;gap:6px;align-items:center;margin-top:22px;"><input type="checkbox" id="tExternal" style="width:auto;"> Has external effect</label></div>
        </div>
        <label>Actions this tool supports</label>
        <div class="checks" id="tActions"></div>
        <div class="toolbar"><button class="add" type="button" data-act="addTool">+ Add tool</button></div>
        <div id="listTools"></div>

        <h2>3. Agents <span class="count" id="cAgents">(0)</span></h2>
        <p class="hint">Add each AI agent, copilot, or automation. Autonomy: <b>observe</b> (reads only), <b>advise</b> (drafts), <b>act_with_approval</b> (acts after a human approves), <b>autonomous</b> (acts on its own - blocked in this MVP).</p>
        <div class="grid2">
          <div><label>Agent name</label><input id="aName" placeholder="Support Reply Agent"></div>
          <div><label>Owner (human)</label><input id="aOwner" placeholder="Ops Lead"></div>
          <div><label>Provider</label><input id="aProvider" placeholder="OpenAI / Anthropic / internal"></div>
          <div><label>Model or runtime</label><input id="aModel" placeholder="gpt-4o / claude / n8n"></div>
          <div><label>Autonomy level</label><select id="aAutonomy"></select></div>
          <div><label>Risk level</label><select id="aRisk"></select></div>
          <div><label>Approval policy</label><select id="aPolicy"></select></div>
          <div><label>Data classes (comma-separated)</label><input id="aData" list="dataSuggest" placeholder="customer_pii"></div>
        </div>
        <label>Business purpose</label><input id="aPurpose" placeholder="Draft support replies for human review.">
        <label>Tools it can use</label>
        <div class="checks" id="aTools"><span class="hint">Add tools above first.</span></div>
        <label>Action classes it can perform</label>
        <div class="checks" id="aActions"></div>
        <div class="toolbar"><button class="add" type="button" data-act="addAgent">+ Add agent</button></div>
        <div id="listAgents"></div>

        <h2>4. Evidence <span class="count" id="cEvidence">(0)</span></h2>
        <p class="hint">Attach the evidence behind each workflow (an owner statement, a redacted export, a note). Missing evidence is recorded honestly, not guessed.</p>
        <div class="grid2">
          <div><label>Evidence id</label><input id="eId" placeholder="ev_owner_note"></div>
          <div><label>Source type</label><select id="eType"></select></div>
          <div><label>Source ref</label><input id="eRef" placeholder="local note / redacted export"></div>
          <div><label>Satisfies (comma-separated)</label><input id="eSat" placeholder="owner, purpose, action_summary"></div>
        </div>
        <label>Summary</label><input id="eSummary" placeholder="Owner-provided workflow summary.">
        <label>Limitation (required for missing evidence)</label><input id="eLimit" placeholder="Not independently verified.">
        <div class="toolbar"><button class="add" type="button" data-act="addEvidence">+ Add evidence</button></div>
        <div id="listEvidence"></div>

        <h2>5. Action events <span class="count" id="cEvents">(0)</span></h2>
        <p class="hint">Add representative actions an agent took or could take. Each needs at least one evidence reference.</p>
        <div class="grid2">
          <div><label>Agent</label><select id="vAgent"></select></div>
          <div><label>Action class</label><select id="vAction"></select></div>
          <div><label>Tool called</label><select id="vTool"></select></div>
          <div><label>Approval state</label><select id="vApproval"></select></div>
          <div><label>Approver (if approved_draft)</label><input id="vApprover" placeholder="Independent Reviewer"></div>
        </div>
        <label>Request summary</label><input id="vRequest" placeholder="Draft a support reply about a billing question.">
        <label>Action payload summary</label><input id="vPayload" placeholder="Draft email text only; no send executed.">
        <label>Evidence for this event</label>
        <div class="checks" id="vEvidence"><span class="hint">Add evidence above first.</span></div>
        <div class="toolbar"><button class="add" type="button" data-act="addEvent">+ Add action event</button></div>
        <div id="listEvents"></div>

        <h2>6. Run your audit</h2>
        <div class="toolbar">
          <button class="primary" type="button" data-act="run" data-arg="validate">Validate</button>
          <button type="button" data-act="run" data-arg="score">Score risks</button>
          <button type="button" data-act="report" data-arg="markdown">Generate report</button>
          <button type="button" data-act="openDashboard">Open dashboard</button>
          <button type="button" data-act="downloadProject">Download project JSON</button>
        </div>
      </div>

      <!-- ADVANCED -->
      <div id="view-advanced" class="hidden">
        <h2>Advanced: edit the project JSON</h2>
        <p class="hint">Power users can paste or edit the raw audit project. Changes here and in the wizard share the same project.</p>
        <div class="toolbar">
          <button type="button" data-act="loadExample">Load example</button>
          <button type="button" data-act="syncFromJson">Apply JSON to wizard</button>
          <button class="primary" type="button" data-act="run" data-arg="validate">Validate</button>
          <button type="button" data-act="report" data-arg="markdown">Generate report</button>
          <button type="button" data-act="openDashboard">Open dashboard</button>
        </div>
        <textarea id="json" style="min-height:60vh;" spellcheck="false"></textarea>
      </div>

      <!-- MCP -->
      <div id="view-mcp" class="hidden">
        <h2>Scan an MCP manifest</h2>
        <p class="hint">Paste a local Model Context Protocol config to statically scan its tool scopes. No server is started or contacted.</p>
        <textarea id="manifest" style="min-height:40vh;" spellcheck="false" placeholder='{ "mcpServers": { ... } }'></textarea>
        <div class="toolbar"><button class="primary" type="button" data-act="mcpScan">Scan MCP manifest</button></div>
      </div>
    </section>

    <section class="panel">
      <h2>Results</h2>
      <p class="hint">Everything runs locally over <code>127.0.0.1</code>.</p>
      <div id="result" class="result">Fill in the wizard, then Validate.</div>
      <div class="toolbar" id="downloads"></div>
    </section>
  </main>

  <div id="help" class="modal hidden">
    <div class="card">
      <button class="close small" type="button" data-act="hideHelp">Close</button>
      <h2>Help &amp; support</h2>
      <h3>Troubleshooting</h3>
      <ul>
        <li><b>The browser didn't open:</b> open the address shown in the ActionVouch window (for example <code>http://127.0.0.1:8765</code>).</li>
        <li><b>"Port already in use":</b> start on another port - <code>actionvouch app --port 8080</code> (or, with the packaged app, <code>ActionVouch app --port 8080</code>).</li>
        <li><b>"Not valid yet":</b> the wizard lists exactly which fields to fix; complete them and Validate again.</li>
        <li><b>Don't lose work:</b> use <b>Download project JSON</b> to save, and <b>Advanced (JSON)</b> &rarr; <b>Apply JSON to wizard</b> to reload it.</li>
        <li><b>MCP scan "could not run":</b> paste a valid config containing <code>mcpServers</code> or <code>servers</code>.</li>
      </ul>
      <h3>Your data stays on your machine</h3>
      <p class="hint">ActionVouch makes no network calls. <b>Never paste your audit project or any customer data into a support message</b> - it is local and may be sensitive. Describe the problem instead.</p>
      <h3>Get support</h3>
      <p class="hint">Report issues on the project's GitHub Issues page and include: your ActionVouch version (see <a data-act="helpToAbout" style="cursor:pointer;color:var(--accent);">About</a>), your operating system, and what you were doing when the problem happened.</p>
      <p class="hint">See also the self-serve guide that came with ActionVouch.</p>
    </div>
  </div>

  <div id="about" class="modal hidden">
    <div class="card">
      <button class="close small" type="button" data-act="hideAbout">Close</button>
      <h2>About ActionVouch <span class="ver" id="aboutVersion"></span></h2>
      <p class="hint">A local-first AI agent risk audit you run yourself.</p>
      <ul>
        <li>Runs entirely on your machine over <code>127.0.0.1</code>.</li>
        <li>Makes no network calls and asks for no credentials - your data never leaves this computer.</li>
        <li>It surfaces visible risks, approval gaps, and missing evidence. It does not certify compliance, replace a lawyer/auditor/security engineer, guarantee protection, or take any action on your behalf.</li>
      </ul>
      <h3>Updates</h3>
      <p class="hint">ActionVouch never phones home or checks for updates automatically - doing so would mean a network call. To get a newer version, return to wherever you downloaded ActionVouch.</p>
      <h3>Status</h3>
      <p class="hint">Pre-1.0 software, internally security-reviewed (not a third-party certification or compliance certification).</p>
    </div>
  </div>

  <datalist id="dataSuggest"></datalist>

  <script>"""


_APP_TAIL = """</script>
</body>
</html>
"""


_APP_HTML = (_APP_HEAD_BODY + _APP_SCRIPT + _APP_TAIL).replace("__CSP__", APP_CSP)
