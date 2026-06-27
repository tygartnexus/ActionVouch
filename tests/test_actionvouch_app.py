"""Tests for the local-first self-serve app.

The app is a localhost-only HTTP server over the existing library. These tests
start it on an ephemeral port in a background thread and drive it over loopback,
covering the full audit pipeline plus the security posture (local-only Host,
body-size cap, fail-closed on bad input).
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

import actionvouch.app as app_module
from actionvouch.app import build_server


@pytest.fixture
def port():
    server = build_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _post(port_, action, body, host=None, origin=None):
    headers = {"Content-Type": "application/json"}
    if host:
        headers["Host"] = host
    if origin:
        headers["Origin"] = origin
    request = urllib.request.Request(
        f"http://127.0.0.1:{port_}/api/{action}",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(port_, path="/"):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{port_}{path}", timeout=5
    ) as response:
        return response.status, response.read().decode("utf-8")


def test_app_serves_local_first_ui(port):
    status, html = _get(port)

    assert status == 200
    assert "ActionVouch" in html
    assert "Content-Security-Policy" in html
    assert "connect-src 'self'" in html
    # The app shell references no external origins.
    assert "http://" not in html.replace("http://127.0.0.1", "")
    assert "https://" not in html


def test_app_runs_the_full_audit_pipeline(port):
    _, example = _post(port, "example", {})
    project = example["project"]

    _, validated = _post(port, "validate", {"project": project})
    assert validated["valid"] is True

    _, scored = _post(port, "score", {"project": project})
    assert len(scored["findings"]) >= 1

    _, reported = _post(port, "report", {"project": project, "format": "markdown"})
    assert reported["content"].startswith("# ActionVouch")

    _, dashboard = _post(port, "dashboard", {"project": project})
    assert "ActionVouch Dashboard" in dashboard["html"]


def test_app_schema_endpoint(port):
    # The wizard's dropdowns are driven by this model-derived vocabulary.
    from actionvouch import __version__

    _, payload = _post(port, "schema", {})
    schema = payload["schema"]
    for key in (
        "app_version",
        "action_classes",
        "autonomy_levels",
        "evidence_source_types",
        "approval_states",
        "policy_ids",
        "default_policies",
    ):
        assert key in schema and schema[key], key
    assert schema["app_version"] == __version__
    assert "observe" in schema["action_classes"]
    assert schema["default_policies"][0]["policy_id"]


def test_app_ui_has_branding_about_and_onboarding():
    from actionvouch.app import render_app_html

    html = render_app_html()
    assert 'class="brandbar"' in html  # branded header
    assert 'id="about"' in html and "showAbout()" in html  # About panel
    assert 'id="welcome"' in html  # first-run onboarding card
    assert "aboutVersion" in html  # version shown in About
    assert "never phones home" in html  # honest no-auto-update statement


def test_app_ui_has_help_and_support_channel():
    from actionvouch.app import render_app_html

    html = render_app_html()
    assert 'id="help"' in html and "showHelp()" in html  # in-app Help panel
    assert "Troubleshooting" in html
    assert "GitHub Issues" in html  # support contact (no email address)
    # Local-first support guidance: never send your data.
    assert "Never paste your audit project or any customer data" in html


def test_app_rejects_deeply_nested_json_with_400(port):
    # F1 (red team): a deeply nested JSON body raises RecursionError in the
    # decoder. The server must answer a clean 400, not let the handler thread die
    # and drop the connection.
    body = ('{"k":' * 2000) + "1" + ("}" * 2000)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/validate",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        status = urllib.request.urlopen(request, timeout=5).status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 400


def test_app_strips_query_string_from_action(port):
    # F6 (red team): a query string on the action is stripped before the action
    # is echoed in an error, so it cannot be reflected back to the caller.
    # A dict project gets past the project check so we reach the unknown-action
    # fallback, where the (query-stripped) action name is echoed.
    status, body = _post(port, "bogus?x=INJECTED_MARKER", {"project": {}})
    assert status == 404
    assert "INJECTED_MARKER" not in json.dumps(body)
    assert body.get("error") == "unknown action: bogus"


def test_app_server_header_hides_python_version(port):
    # F6 (red team): the Server header should not advertise the Python version.
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
        server = response.headers.get("Server") or ""
    assert "Python/" not in server


def test_app_csp_pins_script_by_hash_not_unsafe_inline():
    # F4 (red team): script-src pins the inline script by sha256 (no
    # 'unsafe-inline'); the <meta> and the response header share one policy; and
    # there are no inline event handlers. The pinned hash must match the actual
    # inline script, or the page would be dead.
    import base64
    import hashlib
    import re

    from actionvouch.app import _CSP
    from actionvouch.app_ui import app_csp, render_app_html

    html = render_app_html()
    assert "script-src 'unsafe-inline'" not in html
    assert "script-src 'sha256-" in html
    assert _CSP == app_csp()
    assert "onclick=" not in html and "oninput=" not in html
    match = re.search(r"<script>(.*)</script>", html, re.DOTALL)
    assert match is not None
    script = match.group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode(
        "ascii"
    )
    assert ("sha256-" + digest) in app_csp()


def test_dashboard_csp_forbids_scripts(port):
    # F5 (red team): the dashboard is opened as a blob in a new tab, so its own
    # embedded CSP must forbid scripts outright.
    _, example = _post(port, "example", {})
    _, dashboard = _post(port, "dashboard", {"project": example["project"]})
    assert "script-src 'none'" in dashboard["html"]


def test_app_serves_all_outputs_ungated(port):
    # All audit outputs are served unconditionally (no paywall, no gating).
    _, example = _post(port, "example", {})
    project = example["project"]
    for action, body in (
        ("dashboard", {"project": project}),
        ("console", {"project": project}),
        ("report", {"project": project, "format": "json"}),
        ("report", {"project": project, "format": "markdown"}),
    ):
        status, payload = _post(port, action, body)
        assert status == 200, action
        assert "locked" not in payload and "edition" not in payload


def test_app_scores_an_oversized_audit_ungated(port):
    # A large surface is no longer capped: score runs for any size.
    oversized = {
        "project": {
            "project_id": "p",
            "name": "p",
            "version": "actionvouch.audit_project.v1",
            "scope": "x",
            "agents": [{"agent_id": f"a{i}"} for i in range(4)],
            "tools": [],
            "action_events": [],
            "evidence": [],
            "policies": [],
        }
    }
    status, body = _post(port, "score", oversized)
    assert status == 200 and "locked" not in body


def test_app_mcp_scan_endpoint(port):
    manifest = {
        "mcpServers": {
            "crm": {
                "command": "x",
                "tools": [
                    {"name": "delete_x", "annotations": {"destructiveHint": True}}
                ],
            }
        }
    }
    _, payload = _post(port, "mcp-scan", {"manifest": manifest})

    assert payload["result"]["valid"] is True
    assert payload["result"]["summary"]["destructive_tool_count"] == 1


def test_app_rejects_non_local_host(port):
    # Defense against DNS-rebinding: a request claiming a non-local Host is 403.
    status, _ = _post(port, "validate", {"project": {}}, host="evil.example.com")
    assert status == 403


def test_app_rejects_oversized_body(port, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_BODY_BYTES", 16)
    status, _ = _post(port, "validate", {"project": {"x": "y" * 1000}})
    assert status == 413


def test_app_fails_closed_on_bad_input(port):
    # Wrong-typed project -> error -> 400, never a server crash.
    status, body = _post(port, "validate", {"project": {"agents": "not-a-list"}})
    assert status == 400
    assert "error" in body


def test_app_rejects_prefix_spoofed_host(port):
    # H1 (red-team): a DNS-rebindable name that merely *starts with* a local
    # host must NOT pass the guard.
    for spoof in ("127.0.0.1.attacker.com", "localhost.evil.com"):
        status, _ = _post(port, "example", {}, host=spoof)
        assert status == 403, spoof


def test_app_rejects_cross_origin_post(port):
    # M1: a present non-local Origin (a cross-origin page) is rejected.
    status, _ = _post(port, "example", {}, origin="http://evil.example.com")
    assert status == 403


def test_app_allows_local_origin_post(port):
    status, _ = _post(port, "example", {}, origin=f"http://127.0.0.1:{port}")
    assert status == 200


def test_app_rejects_non_dict_project(port):
    # M4: a non-object project yields a clean 400, not a leaked Python exception.
    status, body = _post(port, "validate", {"project": "not-a-dict"})
    assert status == 400
    assert body["error"] == "project must be a JSON object"


def test_app_sets_security_headers(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
        headers = response.headers
    csp = headers.get("Content-Security-Policy") or ""
    assert "frame-ancestors 'none'" in csp
    assert "connect-src 'self'" in csp
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"


def test_app_handler_has_a_read_timeout():
    # M2: a finite read timeout bounds slow/lying clients (no indefinite hang).
    from actionvouch.app import _AppHandler

    assert _AppHandler.timeout is not None
    assert _AppHandler.timeout > 0


def test_build_server_rejects_non_loopback_host():
    # L1: the bind host is allowlisted to loopback.
    with pytest.raises(ValueError, match="loopback"):
        build_server(host="0.0.0.0")
