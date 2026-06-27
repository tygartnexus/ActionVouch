"""Static, dependency-free smoke checks over generated ActionVouch HTML.

These inspect the HTML *source* (tags, ids, embedded script text) and need no
browser, so they run anywhere. For *rendered* DOM, live client-side
interaction, and a runtime zero-network guarantee, see
:mod:`actionvouch.browser_smoke` (an optional Playwright-backed runner).
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class HtmlSmokeResult:
    path: str
    valid: bool
    checks: dict[str, bool]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "valid": self.valid,
            "checks": self.checks,
            "errors": self.errors,
        }


class _HtmlProbe(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()
        self.ids: set[str] = set()
        self.text: list[str] = []
        self.scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        attrs_dict = {key: value or "" for key, value in attrs}
        if "id" in attrs_dict:
            self.ids.add(attrs_dict["id"])
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.scripts.append(data)
        else:
            stripped = data.strip()
            if stripped:
                self.text.append(stripped)


def smoke_html(path: str | Path, *, artifact_kind: str = "auto") -> HtmlSmokeResult:
    html_path = Path(path)
    text = html_path.read_text(encoding="utf-8")
    parser = _HtmlProbe()
    parser.feed(text)
    visible_text = "\n".join(parser.text)
    script_text = "\n".join(parser.scripts)
    checks = {
        "has_html_tag": "html" in parser.tags,
        "has_title": "title" in parser.tags,
        "has_visible_text": bool(visible_text),
        "no_fetch_calls": "fetch(" not in script_text,
        "no_xml_http_request": "XMLHttpRequest" not in script_text,
    }
    if artifact_kind in {"dashboard", "auto"} and "Dashboard" in visible_text:
        checks.update(
            {
                "dashboard_has_risks": "Top Risk Findings" in visible_text,
                "dashboard_has_policy_decisions": "Policy Decisions" in visible_text,
                "dashboard_has_unknowns": "Unknowns And Missing Evidence"
                in visible_text,
            }
        )
    if artifact_kind in {"console", "auto"} and "Editable Console" in visible_text:
        checks.update(
            {
                "console_has_editor": "projectJson" in parser.ids,
                "console_has_status": "status" in parser.ids,
                "console_has_validation_function": "validateProject()" in script_text,
                "console_has_download_function": "downloadProject()" in script_text,
                "console_has_response_mode_selector": "responseMode" in parser.ids,
                "console_has_audit_request_export": "downloadAuditRequest()"
                in script_text,
            }
        )
    errors = [name for name, passed in checks.items() if not passed]
    return HtmlSmokeResult(
        path=str(html_path),
        valid=not errors,
        checks=checks,
        errors=errors,
    )


def render_smoke_report(results: list[HtmlSmokeResult]) -> str:
    lines = [
        "# ActionVouch Local HTML Smoke Report",
        "",
        "This is a static local HTML smoke check. It is not public deployment proof.",
        "",
    ]
    for result in results:
        lines.extend(
            [
                f"## {result.path}",
                "",
                f"- Valid: `{str(result.valid).lower()}`",
                f"- Errors: {', '.join(result.errors) if result.errors else 'none'}",
                "",
            ]
        )
        for check, passed in result.checks.items():
            lines.append(f"- {check}: `{str(passed).lower()}`")
        lines.append("")
    return "\n".join(lines)
