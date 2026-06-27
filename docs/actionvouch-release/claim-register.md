# ActionVouch Claim Register

This register records the claims ActionVouch makes and does not make about
itself, with safer wording for each.

## Allowed Claims

| Claim | Status | Evidence | Safer wording |
|---|---|---|---|
| ActionVouch runs locally as a standalone tool. | Built locally | `actionvouch/` and CLI commands | ActionVouch is a standalone local-first audit workflow. |
| ActionVouch validates local JSON audit projects. | Tested locally | `actionvouch validate examples/actionvouch/sample_project.json` | ActionVouch can validate local audit records and name missing evidence. |
| ActionVouch scores local AI-agent workflow risks. | Tested locally | `actionvouch/scoring.py` and tests | ActionVouch ranks local risk findings from supplied records. |
| ActionVouch generates Markdown, JSON, and static HTML outputs. | Tested locally | `actionvouch report` / `dashboard` outputs and tests | ActionVouch can generate local report and dashboard artifacts. |
| ActionVouch exports a local editable console. | Tested locally | `actionvouch console ...` and tests | ActionVouch can export a self-contained local HTML editor for audit JSON review and download. |
| ActionVouch imports credential-free local exports and redacted summaries. | Tested locally | `actionvouch import ...` and tests | ActionVouch can map approved local templates into a validated audit project. |
| ActionVouch produces a security/compliance readiness report. | Tested locally | `actionvouch compliance ...` and tests | ActionVouch can prepare a readiness review for external assessor discussion without claiming certification. |
| The pilot is credential-free by default. | Documented and gated | Release packet and intake templates | The controlled pilot is designed for credential-free intake. |
| The report separates facts, assumptions, unknowns, evidence, risks, counterarguments, recommendations, tradeoffs, confidence, and change conditions. | Tested locally | Report tests and sample report | Reports are structured to keep evidence and uncertainty visible. |
| ActionVouch produces real-browser smoke evidence for its dashboard and console. | Tested locally (optional `browser` extra) | `actionvouch browser-smoke`, `actionvouch/browser_smoke.py`, `tests/test_actionvouch_browser_smoke.py` | ActionVouch can render its artifacts in a headless browser, exercise their client-side behavior, capture screenshots, and confirm they make no external network requests at runtime. |
| ActionVouch records local approval decisions that are gated against policy. | Tested locally | `actionvouch approvals`, `actionvouch/approvals.py` and `policies.py`, approval-gate tests | ActionVouch can record local approval decisions that are re-checked against the project's policy and require an independent reviewer; it does not execute the approved action. |
| ActionVouch exports a permission graph and verifies evidence-room integrity. | Tested locally | `actionvouch permission-graph`, `actionvouch verify-evidence-room`, `actionvouch/permissions.py` and `evidence_room.py`, tests | ActionVouch can export a local agent/tool permission graph and re-verify an evidence room's per-file SHA-256 hashes. |
| ActionVouch's generated HTML artifacts are escaped and CSP-restricted. | Tested locally | `report.py`/`dashboard.py`/`console.py` escaping and CSP, XSS-safety tests | ActionVouch escapes audit content in its generated artifacts and ships them with a restrictive content-security policy. |
| ActionVouch passed an internal adversarial red-team with no critical findings. | Documented (internal review) | Internal review documentation (not included in this repository) | ActionVouch has passed an internal adversarial security review with no critical findings; this is an internal review, not a third-party assessment or certification. |
| ActionVouch ships a local-first self-serve app the customer runs themselves. | Tested locally | `actionvouch app`, `actionvouch/app.py` and `app_ui.py`, app + wizard tests | ActionVouch includes a local self-serve app: the customer runs a guided audit on their own machine over `127.0.0.1`, with no network calls and no credentials. |
| The self-serve app has a guided wizard (no JSON editing). | Tested locally | `/api/schema`, the wizard in `app_ui.py`, the Playwright wizard test | A non-technical user can build a valid audit through guided forms driven by the tool's own validation rules. |
| ActionVouch can be packaged as a one-file desktop executable. | Built and verified | `packaging/actionvouch.spec`, `actionvouch/launcher.py`; a built binary that launched and served locally | ActionVouch can be packaged as a one-file executable so a non-developer can run the self-serve app without installing Python. |
| The local self-serve server passed an internal adversarial red-team. | Documented (internal review) | Internal review documentation (not included in this repository) | The local app server was internally security-reviewed (no critical findings; the one HIGH was fixed); this is an internal review, not a third-party assessment. |

## Blocked Claims

| Claim | Status | Evidence missing | Risk | Safer wording |
|---|---|---|---|---|
| ActionVouch certifies AI compliance. | Blocked | Formal compliance framework mapping and qualified audit | Deceptive compliance claim | ActionVouch supports an evidence-based AI workflow risk review. |
| ActionVouch replaces legal review. | Blocked | Attorney approval and legal-service authorization | Unauthorized practice and customer harm | ActionVouch surfaces issues for human and professional review. |
| ActionVouch guarantees protection from AI mistakes. | Blocked | Impossible guarantee and no production monitoring | False certainty | ActionVouch helps identify visible risks and evidence gaps. |
| ActionVouch monitors live systems. | Blocked | Live monitoring implementation and verification | Product overstatement | The MVP reviews customer-provided local records and examples. |
| ActionVouch directly imports from live SaaS APIs. | Blocked | Provider credentials, customer consent, read-only scopes, secret handling, and provider-specific tests | Privacy/security overreach | ActionVouch can import credential-free local exports and summaries; live API pulls remain gated. |
| ActionVouch integrates with all AI tools. | Blocked | Connector inventory and live verification | Scope misrepresentation | The MVP uses manual, credential-free intake templates. |
| ActionVouch is SOC 2, ISO 27001, ISO 42001, HIPAA, PCI, or FedRAMP certified. | Blocked | Third-party assessment and certification evidence | False compliance claim | ActionVouch can produce readiness materials for review by qualified assessors. |
| ActionVouch has proven ROI. | Blocked | Paid customer outcomes and reproducible measurement | Unsupported earnings or savings claim | ActionVouch does not measure or claim ROI. |
| ActionVouch is production SaaS-ready. | Blocked | Hosted app, auth, billing, observability, legal packet approval | Launch-readiness overstatement | ActionVouch ships a local self-serve app today; a hosted, production-grade SaaS is not built. |
| ActionVouch is a finished, sellable self-serve product. | Blocked | A reviewed software license / EULA, production hardening, and a supported distribution model | Selling pre-production software without a license | The self-serve app is available for local use and internal evaluation; offering it as a paid self-serve product still needs a software license and counsel review. |
