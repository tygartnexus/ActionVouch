"""Static local dashboard rendering for ActionVouch."""

from __future__ import annotations

from html import escape

from .models import AuditProject
from .report import build_report


def render_dashboard_html(project: AuditProject) -> str:
    report = build_report(project)
    findings = report["risk_findings"]
    decisions = report["policy_decisions"]
    cards = [
        ("Agents", report["summary"]["agent_count"]),
        ("Tools", report["summary"]["tool_count"]),
        ("Action Events", report["summary"]["action_event_count"]),
        ("Risk Findings", report["summary"]["risk_finding_count"]),
        ("Evidence Gaps", report["summary"]["evidence_gap_count"]),
        ("Confidence", f"{report['summary']['confidence_score']:.2f}"),
        (
            "Act With Approval",
            report["summary"]["autonomy_counts"].get("act_with_approval", 0),
        ),
        ("Autonomous", report["summary"]["autonomy_counts"].get("autonomous", 0)),
        ("MCP Tools", report["summary"]["protocol_counts"].get("mcp", 0)),
        ("A2A Tools", report["summary"]["protocol_counts"].get("a2a", 0)),
        ("Response Mode", report["summary"]["response_mode_label"]),
    ]
    card_html = "\n".join(
        f'<section class="card"><span>{escape(str(label))}</span><strong>{escape(str(value))}</strong></section>'
        for label, value in cards
    )
    finding_rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(finding['severity'])}</td>"
            f"<td>{escape(finding['title'])}</td>"
            f"<td>{escape(finding['affected_record_type'])}:{escape(finding['affected_record_id'])}</td>"
            f"<td>{escape(finding['recommendation'])}</td>"
            "</tr>"
            for finding in findings
        )
        or '<tr><td colspan="4">No risk findings generated.</td></tr>'
    )
    decision_rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(decision['event_id'])}</td>"
            f"<td>{escape(decision['classification'])}</td>"
            f"<td>{escape(decision['policy_id'])}</td>"
            f"<td>{escape('; '.join(decision['reasons']))}</td>"
            "</tr>"
            for decision in decisions
        )
        or '<tr><td colspan="4">No policy decisions generated.</td></tr>'
    )
    unknown_rows = "\n".join(
        f"<li>{escape(item)}</li>" for item in report["sections"].get("Unknowns", [])
    )
    framework_rows = "\n".join(
        f"<li>{escape(item)}</li>" for item in report.get("framework_mappings", [])
    )
    evidence_rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(item['evidence_id'])}</td>"
            f"<td>{escape(item['source_type'])}</td>"
            f"<td>{escape(item.get('source_ref', '') or 'not attached')}</td>"
            f"<td>{escape(item.get('limitation', '') or 'none recorded')}</td>"
            "</tr>"
            for item in report["evidence_appendix"]
        )
        or '<tr><td colspan="4">No evidence sources attached.</td></tr>'
    )
    mode_rules = "\n".join(
        f"<li>{escape(item)}</li>"
        for item in report["response_quality"].get("output_rules", [])
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ActionVouch Dashboard - {escape(project.name)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #1d2430;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --accent: #136f63;
      --risk: #a33a22;
    }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header, main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    h1, h2 {{
      margin: 0 0 12px;
    }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 20px 0;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-height: 70px;
    }}
    .card span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 8px;
    }}
    .card strong {{
      font-size: 24px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      margin-bottom: 28px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px;
      vertical-align: top;
      text-align: left;
      overflow-wrap: anywhere;
    }}
    th {{
      color: var(--muted);
      font-size: 13px;
    }}
    .status {{
      color: var(--accent);
      font-weight: 700;
    }}
    .mode-badge {{
      display: inline-block;
      border: 1px solid #94c9bc;
      border-radius: 999px;
      padding: 4px 8px;
      color: var(--accent);
      font-weight: 700;
    }}
    .unknowns {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }}
  </style>
</head>
<body>
  <header>
    <h1>ActionVouch Dashboard</h1>
    <p><strong>{escape(project.name)}</strong> <span class="status">{escape(report['status'])}</span></p>
    <p>Response mode: <span class="mode-badge">{escape(str(report['summary']['response_mode_label']))}</span></p>
    <p>{escape(project.scope)}</p>
  </header>
  <main>
    <div class="summary">{card_html}</div>
    <h2>Top Risk Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Affected</th><th>Recommendation</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
    <h2>Policy Decisions</h2>
    <table>
      <thead><tr><th>Event</th><th>Classification</th><th>Policy</th><th>Reason</th></tr></thead>
      <tbody>{decision_rows}</tbody>
    </table>
    <section class="unknowns">
      <h2>Unknowns And Missing Evidence</h2>
      <ul>{unknown_rows}</ul>
    </section>
    <section class="unknowns">
      <h2>Framework Mappings</h2>
      <ul>{framework_rows or '<li>No framework mappings generated.</li>'}</ul>
    </section>
    <section class="unknowns">
      <h2>Response Quality Mode</h2>
      <p>{escape(str(report['summary']['response_mode']))}</p>
      <ul>{mode_rules or '<li>No mode-specific rules generated.</li>'}</ul>
    </section>
    <h2>Evidence And Source Index</h2>
    <table>
      <thead><tr><th>Evidence ID</th><th>Type</th><th>Source</th><th>Limitation</th></tr></thead>
      <tbody>{evidence_rows}</tbody>
    </table>
  </main>
</body>
</html>
"""
