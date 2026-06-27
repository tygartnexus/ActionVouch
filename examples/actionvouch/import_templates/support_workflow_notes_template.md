# Support Workflow Notes Template

Redaction confirmation: no credentials, secrets, payment card data, health
information, or unrelated legal matter details are included.

## Workflow

- Name: Support Reply Draft Review
- Owner: Support Lead
- Business purpose: Draft support replies for human review.
- Tools: support desk, knowledge base, email draft tool
- Data classes: customer_pii, support
- Action classes: observe, draft, customer_message
- Approval expectations: human approval required before any customer message is
  sent.

## Representative Action

- Request summary: draft a response to a billing correction question.
- Proposed action: customer_message
- External effect if executed: customer receives a message.
- Current approval state: needs_review

## Evidence

- Evidence ID: support_owner_summary_1
- Source type: owner_statement
- Summary: owner says the workflow drafts replies and requires review.
- Limitation: not independently verified against live support-desk permissions.

## Unknowns

- Whether the email tool can send directly is unknown.
- Whether source citations are attached to every draft is unknown.
