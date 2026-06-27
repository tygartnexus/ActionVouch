"""Local-first self-serve web app for ActionVouch.

Runs a small HTTP server bound to ``127.0.0.1`` that serves a single-page UI and
a JSON API over the existing ActionVouch library, so a customer can run a full
audit on their own machine without an operator or the command line. It is
local-first by construction:

* the socket binds to loopback only (never ``0.0.0.0``);
* the ``Host`` header must be local, which blocks DNS-rebinding from a website;
* request bodies are size-capped;
* the server makes **no** outbound network calls and writes no files — results
  are returned to the browser, which renders and downloads them locally.

Start it with ``actionvouch app`` (or :func:`serve_app`).
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ._version import __version__
from .app_ui import app_csp, render_app_html
from .console import render_editable_console_html
from .dashboard import render_dashboard_html
from .mcp_scan import scan_mcp_data
from .models import (
    ACTION_CLASSES,
    APPROVAL_STATES,
    AUTONOMY_LEVELS,
    CONNECTOR_TYPES,
    EVIDENCE_TYPES,
    HIGH_RISK_ACTION_CLASSES,
    RISK_LEVELS,
    SENSITIVE_DATA_CLASSES,
    AuditProject,
    ValidationError,
)
from .paths import PROJECT_ROOT
from .policies import default_policy_rules
from .report import render_json_report, render_markdown_report
from .scoring import score_project

# A generous cap for an audit project pasted into the browser; rejects
# memory-exhaustion attempts without limiting real use.
MAX_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_PORT = 8765
# Exact hostnames that count as local. Compared after parsing out scheme/port/
# brackets - a prefix match (e.g. "127.0.0.1.attacker.com") must NOT pass.
_LOCAL_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})
# Single source of truth for the policy, shared with the page's <meta> tag so the
# two never drift. script-src pins the inline script by sha256 (no
# 'unsafe-inline'), so an injected script/handler cannot execute.
_CSP = app_csp()

_SAMPLE_PROJECT = PROJECT_ROOT / "examples" / "actionvouch" / "sample_project.json"

# Minimal starting point returned if the bundled sample is missing (e.g. an
# incomplete packaged build). Keeps the example endpoint from failing.
_FALLBACK_EXAMPLE = {
    "project_id": "av_example",
    "name": "Example Audit",
    "version": "actionvouch.audit_project.v1",
    "scope": "Example scope - replace with your own using the wizard.",
    "agents": [],
    "tools": [],
    "policies": [],
    "action_events": [],
    "evidence": [],
}


def _hostname(value: str) -> str:
    """Reduce a Host/Origin header value to a bare lowercase hostname."""

    host = value.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.startswith("["):  # [::1] or [::1]:port
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:  # ipv4/hostname:port (not a bare IPv6 address)
        host = host.split(":", 1)[0]
    return host


def _example_project() -> dict[str, Any]:
    try:
        return json.loads(_SAMPLE_PROJECT.read_text(encoding="utf-8"))
    except OSError:
        return dict(_FALLBACK_EXAMPLE)


def _schema() -> dict[str, Any]:
    """Model vocabularies that drive the wizard's dropdowns and guidance."""

    return {
        "app_version": __version__,
        "action_classes": sorted(ACTION_CLASSES),
        "high_risk_action_classes": sorted(HIGH_RISK_ACTION_CLASSES),
        "autonomy_levels": sorted(AUTONOMY_LEVELS),
        "connector_types": sorted(CONNECTOR_TYPES),
        "evidence_source_types": sorted(EVIDENCE_TYPES),
        "approval_states": sorted(APPROVAL_STATES),
        "risk_levels": sorted(RISK_LEVELS),
        "data_class_suggestions": sorted(SENSITIVE_DATA_CLASSES),
        "policy_ids": [rule.policy_id for rule in default_policy_rules()],
        "default_policies": [rule.to_dict() for rule in default_policy_rules()],
    }


def _dispatch(action: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Map an API action to the local library. Pure: no network, no file writes."""

    if action == "example":
        return 200, {"project": _example_project()}
    if action == "schema":
        return 200, {"schema": _schema()}
    if action == "mcp-scan":
        result = scan_mcp_data(payload.get("manifest"), source="local-app")
        return 200, {"result": result.to_dict()}

    project_payload = payload.get("project")
    if not isinstance(project_payload, dict):
        return 400, {"error": "project must be a JSON object"}
    project = AuditProject.from_dict(project_payload)
    if action == "validate":
        errors = project.validate()
        return 200, {
            "valid": not errors,
            "errors": errors,
            "project_id": project.project_id,
        }
    if action == "score":
        errors = project.validate()
        findings = [] if errors else [f.to_dict() for f in score_project(project)]
        return 200, {"valid": not errors, "errors": errors, "findings": findings}
    if action == "report":
        fmt = "json" if payload.get("format") == "json" else "markdown"
        content = (
            render_json_report(project)
            if fmt == "json"
            else render_markdown_report(project)
        )
        return 200, {"format": fmt, "content": content}
    if action == "dashboard":
        return 200, {"html": render_dashboard_html(project)}
    if action == "console":
        return 200, {"html": render_editable_console_html(project)}
    return 404, {"error": f"unknown action: {action}"}


class _AppHandler(BaseHTTPRequestHandler):
    # Default HTTP/1.0 (connection closes after each response) so an early error
    # return can never desync a kept-alive connection. The read timeout bounds
    # slow/lying clients (no indefinite thread hang / Slowloris).
    server_version = "ActionVouchLocal/1"
    # Suppress the default "Python/X.Y.Z" suffix on the Server header (it is a
    # free fingerprint for a local caller and adds nothing for the user).
    sys_version = ""
    timeout = 30

    def _host_is_local(self) -> bool:
        host = self.headers.get("Host") or ""
        return host == "" or _hostname(host) in _LOCAL_HOSTNAMES

    def _origin_is_local(self) -> bool:
        # A present Origin must be local (cross-origin POST defense); an absent
        # Origin (curl, same-origin navigation) is allowed.
        origin = self.headers.get("Origin")
        return not origin or _hostname(origin) in _LOCAL_HOSTNAMES

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionError, OSError):
            self.close_connection = True  # client disconnected; no traceback

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload) + "\n").encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def _reject(self, code: int, message: str) -> None:
        print(f"actionvouch app: rejected request ({code} {message})", file=sys.stderr)
        self._send_json(code, {"error": message})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._host_is_local():
            self._reject(403, "non-local Host header rejected")
            return
        if self.path.split("?", 1)[0] in ("/", "/index.html"):
            self._send(
                200, render_app_html().encode("utf-8"), "text/html; charset=utf-8"
            )
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._host_is_local():
            self._reject(403, "non-local Host header rejected")
            return
        if not self._origin_is_local():
            self._reject(403, "cross-origin request rejected")
            return
        if not self.path.startswith("/api/"):
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length >= MAX_BODY_BYTES:
            self._reject(413, "request body too large")
            return
        try:
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw or b"{}")
        except (ValueError, OSError):
            self._send_json(400, {"error": "invalid JSON body"})
            return
        except RecursionError:
            # Deeply nested JSON exhausts the decoder's recursion. Fail closed
            # with a 400 instead of letting it kill the handler thread.
            self._send_json(400, {"error": "JSON body nested too deeply"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "request body must be a JSON object"})
            return
        # Strip any query string / fragment so it is never reflected back.
        action = self.path[len("/api/") :].split("?", 1)[0].split("#", 1)[0]
        try:
            code, result = _dispatch(action, payload)
        except ValidationError as exc:
            # ValidationError messages are intentionally user-facing.
            code, result = 400, {"error": str(exc)}
        except Exception:  # noqa: BLE001 - never crash the local server
            # Don't leak the internal exception type/message to the caller.
            code, result = 400, {"error": "could not process request"}
        self._send_json(code, result)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # silence default request logging


_LOOPBACK_BIND = frozenset({"127.0.0.1", "::1", "localhost"})


def build_server(
    host: str = "127.0.0.1", port: int = DEFAULT_PORT
) -> ThreadingHTTPServer:
    """Build the local app server (loopback only). Used by serve_app and tests."""

    if host not in _LOOPBACK_BIND:
        raise ValueError(
            "host must be a loopback address (127.0.0.1 / ::1 / localhost), "
            f"got {host!r}"
        )
    return ThreadingHTTPServer((host, port), _AppHandler)


def serve_app(
    *, port: int = DEFAULT_PORT, host: str = "127.0.0.1", open_browser: bool = True
) -> None:
    """Run the local self-serve app until interrupted."""

    server = build_server(host, port)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}/"
    if open_browser:
        import webbrowser

        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - headless machines have no browser
            pass
    print(f"ActionVouch local app running at {url}")
    print(
        "Local-only: bound to 127.0.0.1, no network calls, no data leaves this "
        "machine. Press Ctrl+C to stop."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
