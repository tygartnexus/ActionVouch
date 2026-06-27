"""Local-first ActionVouch audit and approval MVP."""

from ._version import __version__
from .app import render_app_html, serve_app
from .approvals import (
    ApprovalRecord,
    create_approval_request,
    list_approval_candidates,
    review_approval,
    verify_record_link,
)
from .browser_smoke import (
    BrowserSmokeResult,
    BrowserSmokeUnavailable,
    playwright_unavailable_reason,
    render_browser_smoke_report,
    run_browser_smoke,
)
from .compliance import build_compliance_readiness_report, render_compliance_markdown
from .console import render_editable_console_html
from .dashboard import render_dashboard_html
from .evidence_room import build_evidence_room, verify_evidence_room
from .mcp_scan import (
    McpScanResult,
    render_mcp_scan_markdown,
    scan_mcp_data,
    scan_mcp_manifest,
)
from .importers import import_project_from_paths, live_import_status
from .models import (
    ActionEvent,
    AgentRecord,
    AuditProject,
    CapabilitySignal,
    EvidenceItem,
    PolicyRule,
    RiskFinding,
    ToolRecord,
    ValidationError,
)
from .permissions import build_permission_graph
from .policies import PolicyDecision, default_policy_rules, evaluate_action_event
from .report import build_report, render_markdown_report
from .research_watch import (
    baseline_capability_signals,
    build_research_watch_report,
    render_research_watch_json,
    render_research_watch_markdown,
)
from .scoring import score_project
from .smoke import render_smoke_report, smoke_html
from .store import load_project, save_project

__all__ = [
    "__version__",
    "ActionEvent",
    "AgentRecord",
    "ApprovalRecord",
    "AuditProject",
    "BrowserSmokeResult",
    "BrowserSmokeUnavailable",
    "CapabilitySignal",
    "EvidenceItem",
    "McpScanResult",
    "PolicyDecision",
    "PolicyRule",
    "RiskFinding",
    "ToolRecord",
    "ValidationError",
    "build_evidence_room",
    "build_permission_graph",
    "build_report",
    "build_compliance_readiness_report",
    "build_research_watch_report",
    "baseline_capability_signals",
    "create_approval_request",
    "default_policy_rules",
    "evaluate_action_event",
    "import_project_from_paths",
    "list_approval_candidates",
    "load_project",
    "live_import_status",
    "playwright_unavailable_reason",
    "render_browser_smoke_report",
    "render_compliance_markdown",
    "render_mcp_scan_markdown",
    "render_dashboard_html",
    "render_editable_console_html",
    "render_markdown_report",
    "render_app_html",
    "render_research_watch_json",
    "render_research_watch_markdown",
    "render_smoke_report",
    "review_approval",
    "run_browser_smoke",
    "save_project",
    "scan_mcp_data",
    "scan_mcp_manifest",
    "score_project",
    "serve_app",
    "smoke_html",
    "verify_evidence_room",
    "verify_record_link",
]
