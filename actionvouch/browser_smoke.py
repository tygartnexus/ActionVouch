"""Real-browser smoke checks for generated ActionVouch HTML (optional).

The static checker in :mod:`actionvouch.smoke` inspects HTML *source*. This
module renders the generated dashboard and console in a headless Chromium via
Playwright and asserts the **rendered DOM**, the **interactive behaviour**
(the console's client-side validator, quick-add, and response-mode persistence
actually run), and the **runtime local-first guarantee** (the page issues zero
external network requests while loading and being driven). It can also capture
screenshot evidence.

Playwright is a *development / test* extra, never a runtime dependency:
ActionVouch's shipped runtime stays standard-library only and offline. When
Playwright or its browser binaries are not installed, callers receive a clean
skip (:class:`BrowserSmokeUnavailable`) rather than an error.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# A local-first artifact may only load local resources (file:/data:/blob:/about:
# and similar). A request whose scheme is one of these is an external network
# call and fails the runtime local-first guarantee. Compared case-insensitively
# against the parsed URL scheme, not a raw string prefix.
_EXTERNAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})

_DASHBOARD_SECTIONS = (
    "Top Risk Findings",
    "Policy Decisions",
    "Unknowns And Missing Evidence",
)

_INVALID_JSON = "{ this is not valid json"
_RESPONSE_MODE_STORAGE_KEY = "actionvouch.response_mode.v1"


class BrowserSmokeUnavailable(RuntimeError):
    """Raised when Playwright or its browser binaries are unavailable.

    Callers should treat this as a *skip*, not a failure: the local-first
    runtime does not depend on Playwright.
    """


@dataclass(frozen=True)
class BrowserSmokeResult:
    """Outcome of rendering and driving one HTML artifact in a real browser."""

    kind: str
    path: str
    valid: bool
    checks: dict[str, bool]
    errors: list[str]
    console_errors: list[str]
    network_offenders: list[str]
    screenshots: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "valid": self.valid,
            "checks": self.checks,
            "errors": self.errors,
            "console_errors": self.console_errors,
            "network_offenders": self.network_offenders,
            "screenshots": self.screenshots,
        }


def playwright_unavailable_reason() -> str | None:
    """Return why browser smoke cannot run, or ``None`` if it can.

    Checks only that the Python package is importable; a missing browser binary
    is surfaced later (on launch) and converted to the same skip signal.
    """

    try:
        spec = importlib.util.find_spec("playwright.sync_api")
    except (ImportError, ValueError):
        spec = None
    if spec is None:
        return "playwright not installed (install the 'browser' extra)"
    return None


def run_browser_smoke(
    dashboard_path: str | Path,
    console_path: str | Path,
    *,
    screenshot_dir: str | Path | None = None,
) -> list[BrowserSmokeResult]:
    """Render and drive the dashboard and console in a headless browser.

    Raises :class:`BrowserSmokeUnavailable` when Playwright or its browsers are
    not installed, so callers can record a skip instead of a failure.
    """

    reason = playwright_unavailable_reason()
    if reason is not None:
        raise BrowserSmokeUnavailable(reason)

    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    shots = Path(screenshot_dir) if screenshot_dir is not None else None
    if shots is not None:
        shots.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as runner:
        try:
            browser = runner.chromium.launch()
        except PlaywrightError as exc:
            first_line = str(exc).splitlines()[0] if str(exc) else repr(exc)
            raise BrowserSmokeUnavailable(
                f"chromium not launchable: {first_line}"
            ) from exc
        try:
            context = browser.new_context()
            # Context-level backstop: page-level routes (attached per page for
            # per-artifact attribution) do not see Service Worker, popup, or
            # sub-frame requests. A context route catches those, so a leak the
            # page guard misses still fails the run.
            context_offenders = _attach_context_guard(context)
            try:
                results = [
                    _smoke_dashboard(context, Path(dashboard_path), shots),
                    _smoke_console(context, Path(console_path), shots),
                ]
            finally:
                context.close()
        finally:
            browser.close()
    return [_merge_context_offenders(result, context_offenders) for result in results]


def _attach_context_guard(context: Any) -> list[str]:
    offenders: list[str] = []

    def _route(route: Any) -> None:
        url = route.request.url
        if urlsplit(url).scheme.lower() in _EXTERNAL_SCHEMES:
            offenders.append(url)
            route.abort()
        else:
            route.continue_()

    context.route("**/*", _route)
    return offenders


def _merge_context_offenders(
    result: BrowserSmokeResult, extra: list[str]
) -> BrowserSmokeResult:
    if not extra:
        return result
    checks = {**result.checks, "no_external_network": False}
    errors = [name for name, passed in checks.items() if not passed]
    return replace(
        result,
        valid=not errors,
        checks=checks,
        errors=errors,
        network_offenders=[*result.network_offenders, *extra],
    )


def _attach_observers(page: Any) -> tuple[list[str], list[str]]:
    """Record external network attempts and JS errors; block external calls."""

    offenders: list[str] = []
    console_errors: list[str] = []

    def _on_console(message: Any) -> None:
        if message.type == "error":
            console_errors.append(message.text)

    def _on_pageerror(error: Any) -> None:
        console_errors.append(str(error))

    def _route(route: Any) -> None:
        url = route.request.url
        if urlsplit(url).scheme.lower() in _EXTERNAL_SCHEMES:
            offenders.append(url)
            route.abort()
        else:
            route.continue_()

    page.on("console", _on_console)
    page.on("pageerror", _on_pageerror)
    page.route("**/*", _route)
    return offenders, console_errors


def _screenshot(page: Any, shots: Path | None, name: str) -> str | None:
    if shots is None:
        return None
    target = shots / name
    page.screenshot(path=str(target), full_page=True)
    return str(target)


def _result(
    kind: str,
    path: Path,
    checks: dict[str, bool],
    offenders: list[str],
    console_errors: list[str],
    screenshots: list[str | None],
) -> BrowserSmokeResult:
    errors = [name for name, passed in checks.items() if not passed]
    return BrowserSmokeResult(
        kind=kind,
        path=str(path),
        valid=not errors,
        checks=checks,
        errors=errors,
        console_errors=list(console_errors),
        network_offenders=list(offenders),
        screenshots=[shot for shot in screenshots if shot],
    )


def _smoke_dashboard(
    context: Any, path: Path, shots: Path | None
) -> BrowserSmokeResult:
    page = context.new_page()
    offenders, console_errors = _attach_observers(page)
    try:
        page.goto(path.resolve().as_uri(), wait_until="load")
        title = page.title()
        headings = " ".join(
            page.eval_on_selector_all("h2", "els => els.map(e => e.textContent)")
        )
        card_count = page.eval_on_selector_all(".card", "els => els.length")
        first_card = page.eval_on_selector_all(
            ".card strong", "els => (els[0] && els[0].textContent) || ''"
        )
        finding_rows = page.eval_on_selector_all("table tbody tr", "els => els.length")
        screenshots = [_screenshot(page, shots, "dashboard.png")]
        checks = {
            "rendered_title": "ActionVouch Dashboard" in title,
            "rendered_h1": page.inner_text("h1").strip() == "ActionVouch Dashboard",
            "sections_rendered": all(s in headings for s in _DASHBOARD_SECTIONS),
            "summary_cards_rendered": card_count >= 6 and bool(first_card.strip()),
            "risk_findings_rows_present": finding_rows >= 1,
            "no_console_errors": not console_errors,
            "no_external_network": not offenders,
        }
    finally:
        page.close()
    return _result("dashboard", path, checks, offenders, console_errors, screenshots)


def _smoke_console(context: Any, path: Path, shots: Path | None) -> BrowserSmokeResult:
    page = context.new_page()
    offenders, console_errors = _attach_observers(page)
    try:
        page.goto(path.resolve().as_uri(), wait_until="load")
        checks = _console_dom_checks(page)
        screenshots = [_screenshot(page, shots, "console.png")]
        checks.update(_console_interaction_checks(page, shots, screenshots))
        checks["no_console_errors"] = not console_errors
        checks["no_external_network"] = not offenders
    finally:
        page.close()
    return _result("console", path, checks, offenders, console_errors, screenshots)


def _console_dom_checks(page: Any) -> dict[str, bool]:
    editor_value = page.input_value("#projectJson")
    json_ok = page.evaluate(
        "() => { try { JSON.parse("
        "document.getElementById('projectJson').value); return true; }"
        " catch (e) { return false; } }"
    )
    option_count = page.eval_on_selector_all(
        "#responseMode option", "els => els.length"
    )
    return {
        "rendered_title": "ActionVouch Editable Console" in page.title(),
        "editor_present_nonempty": bool(editor_value.strip()),
        "editor_json_parseable": bool(json_ok),
        "response_mode_options_present": option_count >= 1,
    }


def _console_interaction_checks(
    page: Any, shots: Path | None, screenshots: list[str | None]
) -> dict[str, bool]:
    return {
        "validate_marks_ok": _safe_check(
            lambda: _check_validate_ok(page, shots, screenshots)
        ),
        "add_agent_grows_inventory": _safe_check(lambda: _check_add_agent(page)),
        "response_mode_persists": _safe_check(lambda: _check_mode_persist(page)),
        "validate_catches_invalid_json": _safe_check(lambda: _check_invalid_json(page)),
    }


def _safe_check(func: Any) -> bool:
    """Run an interaction check; a Playwright error (timeout, missing element,
    JS error from a changed console) is a failed check, not a crashed run."""

    from playwright.sync_api import Error as PlaywrightError

    try:
        return bool(func())
    except PlaywrightError:
        return False


def _agent_count(page: Any) -> int:
    return int(
        page.evaluate(
            "() => { try { return (JSON.parse("
            "document.getElementById('projectJson').value).agents || []).length; }"
            " catch (e) { return -1; } }"
        )
    )


def _check_validate_ok(
    page: Any, shots: Path | None, screenshots: list[str | None]
) -> bool:
    page.click('button:has-text("Validate JSON")')
    page.wait_for_selector("#status.ok", timeout=5000)
    screenshots.append(_screenshot(page, shots, "console-validated.png"))
    return "passed" in (page.inner_text("#status") or "").lower()


def _check_add_agent(page: Any) -> bool:
    page.evaluate("() => resetOriginal()")
    before = _agent_count(page)
    page.click('button:has-text("Add Agent")')
    after = _agent_count(page)
    return before >= 0 and after == before + 1


def _check_mode_persist(page: Any) -> bool:
    page.evaluate("() => resetOriginal()")
    current = page.input_value("#responseMode")
    options = page.eval_on_selector_all(
        "#responseMode option", "els => els.map(e => e.value)"
    )
    alternatives = [value for value in options if value and value != current]
    if not alternatives:
        return False
    target = alternatives[0]
    page.select_option("#responseMode", value=target)
    stored = page.evaluate(
        "(key) => localStorage.getItem(key)", _RESPONSE_MODE_STORAGE_KEY
    )
    badge = page.inner_text("#selectedModeBadge").strip()
    return stored == target and bool(badge)


def _check_invalid_json(page: Any) -> bool:
    page.fill("#projectJson", _INVALID_JSON)
    page.click('button:has-text("Validate JSON")')
    page.wait_for_selector("#status.error", timeout=5000)
    return True


def render_browser_smoke_report(results: list[BrowserSmokeResult]) -> str:
    """Render a markdown report for a real-browser smoke run."""

    lines = [
        "# ActionVouch Real-Browser Smoke Report",
        "",
        "Generated by rendering the dashboard and console in a headless "
        "Chromium (Playwright) and driving their client-side behaviour. This "
        "is local browser evidence, not public deployment proof.",
        "",
    ]
    for result in results:
        lines.extend(
            [
                f"## {result.kind}: {result.path}",
                "",
                f"- Valid: `{str(result.valid).lower()}`",
                f"- Errors: {', '.join(result.errors) if result.errors else 'none'}",
                "- External network requests: "
                f"{', '.join(result.network_offenders) or 'none'}",
                "- Console / page errors: "
                f"{', '.join(result.console_errors) or 'none'}",
                "- Screenshots: "
                f"{', '.join(result.screenshots) if result.screenshots else 'none'}",
                "",
            ]
        )
        for check, passed in result.checks.items():
            lines.append(f"- {check}: `{str(passed).lower()}`")
        lines.append("")
    return "\n".join(lines)
