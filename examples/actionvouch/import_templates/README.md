# ActionVouch Credential-Free Import Templates

These templates collect enough information for a controlled pilot without
requesting credentials or production access.

## Use

1. Copy the relevant template into the customer pilot folder.
2. Replace the example values with redacted customer summaries.
3. Preserve unknowns instead of guessing.
4. Map the result into an ActionVouch audit project JSON file.
5. Validate the mapped project before report generation.

## Templates

| Source | File |
|---|---|
| Manual agent inventory | `manual_agent_inventory_template.json` |
| Zapier workflow summary | `zapier_summary_template.json` |
| n8n workflow summary | `n8n_summary_template.json` |
| Make scenario summary | `make_summary_template.json` |
| CRM automation summary | `crm_automation_summary_template.json` |
| Support workflow notes | `support_workflow_notes_template.md` |
| Workspace AI usage summary | `workspace_ai_usage_template.json` |
| MCP config summary | `mcp_config_summary_template.json` |
| Pilot outcome metrics | `pilot_metrics_template.json` |

## Required Fields Across Templates

- owner;
- business purpose;
- tools;
- data classes;
- action classes;
- approval expectations;
- evidence;
- unknowns;
- redaction confirmation.

## Do Not Include

- passwords;
- API keys;
- OAuth tokens;
- payment card numbers;
- bank account numbers;
- health information;
- unrelated legal matter details;
- production database exports.
