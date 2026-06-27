"""End-to-end test of the self-serve guided wizard (Phase 2).

Drives the wizard in a headless browser: fills the guided forms (project, tool,
agent, evidence, action event) and asserts the assembled project validates - the
proof that a customer can build a valid audit without editing JSON. Auto-skips
when the optional ``browser`` extra (Playwright + browsers) is unavailable.
"""

from __future__ import annotations

import threading

import pytest

from actionvouch.app import build_server


@pytest.fixture
def app_url():
    server = build_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _sync_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001 - optional extra
        pytest.skip(f"browser extra unavailable: {exc}")
    return sync_playwright


def test_wizard_builds_a_valid_project(app_url):
    sync_playwright = _sync_playwright()
    with sync_playwright() as runner:
        try:
            browser = runner.chromium.launch()
        except Exception as exc:  # noqa: BLE001 - browsers not installed
            pytest.skip(f"chromium unavailable: {exc}")
        try:
            page = browser.new_page()
            page.goto(app_url, wait_until="load")
            # Wait until /api/schema has populated the action-class checkboxes.
            page.wait_for_selector("#tActions input[value='observe']", timeout=10000)

            page.fill("#pName", "Wizard Test Co")
            page.fill("#pScope", "AI workflow audit")

            page.fill("#tName", "CRM API")
            page.fill("#tData", "customer_pii")
            page.check("#tActions input[value='observe']")
            page.click("button:has-text('+ Add tool')")

            page.fill("#aName", "Support Agent")
            page.fill("#aOwner", "Ops Lead")
            page.fill("#aPurpose", "Draft replies for review")
            page.check("#aTools input[value='crm_api']")
            page.check("#aActions input[value='observe']")
            page.click("button:has-text('+ Add agent')")

            page.fill("#eId", "ev_owner")
            page.fill("#eSummary", "Owner-provided summary")
            page.fill("#eSat", "owner, purpose, action_summary")
            page.click("button:has-text('+ Add evidence')")

            page.check("#vEvidence input[value='ev_owner']")
            page.fill("#vRequest", "Review a billing question")
            page.fill("#vPayload", "Draft only; no send")
            page.click("button:has-text('+ Add action event')")

            page.click("button:has-text('Validate')")
            page.wait_for_selector("#result.ok, #result.error", timeout=8000)

            assert page.get_attribute("#result", "class") == "result ok"
            assert "Valid" in (page.text_content("#result") or "")
        finally:
            browser.close()


def test_apply_malformed_json_is_rejected(app_url):
    # F8 (red team): "Apply JSON to wizard" structurally validates the pasted
    # JSON (must be an object) instead of throwing and leaving a broken state.
    sync_playwright = _sync_playwright()
    with sync_playwright() as runner:
        try:
            browser = runner.chromium.launch()
        except Exception as exc:  # noqa: BLE001 - browsers not installed
            pytest.skip(f"chromium unavailable: {exc}")
        try:
            page = browser.new_page()
            page.goto(app_url, wait_until="load")
            page.wait_for_selector("#tActions input[value='observe']", timeout=10000)

            page.click("#tabAdvanced")
            page.fill("#json", '"a string, not an object"')
            page.click("button:has-text('Apply JSON to wizard')")
            page.wait_for_selector("#result.error", timeout=8000)

            assert "must be an object" in (page.text_content("#result") or "")
        finally:
            browser.close()
