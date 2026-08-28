"""Repo/config reconciler for ActionVouch - the omission detector.

ActionVouch's default audit is *attestation*: it scores what the operator
declares. A pure lie of omission - simply not declaring a dangerous tool, MCP
server, or connector - is invisible to attestation, because the missing item is
absent from the input by construction.

This module adds *observation*. It enumerates the REAL tool surface wired up in a
codebase (MCP server configs, agent-framework tool registrations, and connector
credential keys) and reconciles it against the declared inventory. The set
difference ``observed - declared`` is the omission, surfaced as risk findings.

It is local-first and consent-scoped by construction: it only reads files under
a root the operator explicitly points it at. It makes ZERO network calls and
runs no external processes - it parses files with the standard library only.
"""

from __future__ import annotations

import ast
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from .models import (
    ACTION_CLASSES,
    DESTRUCTIVE_ACTION_CLASSES,
    HIGH_RISK_ACTION_CLASSES,
    AuditProject,
    RiskFinding,
)

# Directories that hold vendored / generated code, never the operator's own
# wiring. Scanning them is noise and can be enormous.
_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        "dist",
        "build",
        "target",
        ".tox",
        ".idea",
        ".next",
        ".cache",
        "vendor",
    }
)

_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".tsx",
        ".jsx",
        ".mts",
        ".cts",
        # Other common agent-tooling languages (best-effort literal-name match):
        ".go",
        ".rs",
        ".rb",
        ".java",
        ".php",
        ".cs",
        ".kt",
        ".scala",
        ".swift",
    }
)
_MCP_FILENAME_HINTS = ("mcp.json", ".mcp.json", "claude_desktop_config.json")

# Tool-registration patterns across the common agent frameworks. Curated for
# high signal; each capturing group is the declared tool name. The ``@(?:\w+\.)?``
# prefix covers FastMCP / server-object decorators (@mcp.tool, @app.tool,
# @server.tool) in addition to a bare @tool.
_TOOL_PATTERNS = (
    re.compile(
        r"@(?:\w+\.)?tool\b[^\n]*\n\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)"
    ),
    re.compile(r"@(?:\w+\.)?tool\(\s*[\"']([^\"']+)[\"']"),
    re.compile(r"\bStructuredTool\.from_function\([^)]*name\s*=\s*[\"']([^\"']+)[\"']"),
    re.compile(r"\bFunctionTool\([^)]*name\s*=\s*[\"']([^\"']+)[\"']"),
    re.compile(r"\"function\"\s*:\s*\{\s*\"name\"\s*:\s*\"([A-Za-z0-9_\-]+)\""),
    re.compile(r"register_function\([^,)]+,\s*name\s*=\s*[\"']([^\"']+)[\"']"),
    # Language-agnostic: a "name" key (= or :) near a "tool" token. Catches
    # Tool(name="x") (Python), tool(name: "x") (Go/Ruby), ToolSpec{name:"x"}.
    re.compile(r"[Tt]ool[^\n]{0,40}?\bname\s*[:=]\s*[\"']([^\"']+)[\"']"),
)

# Substring (in an env var KEY, lowercased) -> (connector name, implied actions).
_CONNECTOR_ENV_HINTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "stripe": ("stripe", ("payment_refund", "finance_action")),
    "plaid": ("plaid", ("finance_action",)),
    "paypal": ("paypal", ("payment_refund", "finance_action")),
    "braintree": ("braintree", ("payment_refund", "finance_action")),
    "hubspot": ("hubspot", ("crm_write",)),
    "salesforce": ("salesforce", ("crm_write",)),
    "sfdc": ("salesforce", ("crm_write",)),
    "pipedrive": ("pipedrive", ("crm_write",)),
    "twilio": ("twilio", ("customer_message",)),
    "sendgrid": ("sendgrid", ("customer_message",)),
    "mailgun": ("mailgun", ("customer_message",)),
    "slack": ("slack", ("customer_message",)),
    "sendgrid_api": ("sendgrid", ("customer_message",)),
    "hubspot_token": ("hubspot", ("crm_write",)),
    "aws": ("aws", ("file_delete", "file_share", "external_api_call")),
    "s3": ("aws_s3", ("file_delete", "file_share")),
    "gcs": ("gcs", ("file_delete", "file_share")),
    "github": ("github", ("public_publish", "external_api_call")),
    "gitlab": ("gitlab", ("public_publish", "external_api_call")),
    "notion": ("notion", ("file_share",)),
    "jira": ("jira", ("crm_write",)),
    "zendesk": ("zendesk", ("support_response",)),
    "intercom": ("intercom", ("customer_message",)),
    "zapier": ("zapier", ("external_api_call",)),
    "square": ("square", ("payment_refund", "finance_action")),
    "adyen": ("adyen", ("payment_refund", "finance_action")),
    "gocardless": ("gocardless", ("finance_action",)),
    "wise": ("wise", ("finance_action",)),
    "mercury": ("mercury", ("finance_action",)),
    "brex": ("brex", ("finance_action",)),
    "ramp": ("ramp", ("finance_action",)),
    "quickbooks": ("quickbooks", ("finance_action",)),
    "xero": ("xero", ("finance_action",)),
    "resend": ("resend", ("customer_message",)),
    "postmark": ("postmark", ("customer_message",)),
    "klaviyo": ("klaviyo", ("customer_message",)),
    "mailchimp": ("mailchimp", ("customer_message",)),
    "customer_io": ("customer_io", ("customer_message",)),
    "customerio": ("customer_io", ("customer_message",)),
    "freshdesk": ("freshdesk", ("support_response",)),
    "monday": ("monday", ("crm_write",)),
    "airtable": ("airtable", ("crm_write", "file_share")),
    "shopify": ("shopify", ("finance_action", "crm_write")),
    "openai": ("openai", ()),
    "anthropic": ("anthropic", ()),
}

# Heuristic fallback for connectors whose vendor is NOT in the list above: an
# env key that looks like a credential AND carries a risk keyword is flagged as a
# (custom) connector, so an internal/renamed payment integration like
# ACME_WIRE_TRANSFER_API_KEY is not invisible just because its vendor is unknown.
_CREDENTIAL_MARKERS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "api",
    "auth",
    "dsn",
    "url",
    "webhook",
    "access",
)
_CONNECTOR_RISK_KEYWORDS: dict[str, tuple[str, ...]] = {
    "payment": ("payment_refund", "finance_action"),
    "payout": ("finance_action",),
    "wire": ("finance_action",),
    "bank": ("finance_action",),
    "billing": ("finance_action",),
    "invoice": ("finance_action",),
    "charge": ("finance_action",),
    "refund": ("payment_refund",),
    "transfer": ("finance_action",),
    "ach": ("finance_action",),
    "swift": ("finance_action",),
    "payroll": ("finance_action",),
}

# Verb keyword (substring of a tool name, lowercased) -> implied action class.
_ACTION_KEYWORDS: dict[str, str] = {
    "refund": "payment_refund",
    "charge": "finance_action",
    "invoice": "finance_action",
    "payout": "finance_action",
    "wire": "finance_action",
    "transfer": "finance_action",
    "payment": "payment_refund",
    "delete": "file_delete",
    "remove": "file_delete",
    "destroy": "file_delete",
    "purge": "file_delete",
    "drop": "file_delete",
    "send": "customer_message",
    "email": "customer_message",
    "message": "customer_message",
    "sms": "customer_message",
    "notify": "customer_message",
    "publish": "public_publish",
    "post": "public_publish",
    "tweet": "public_publish",
    "crm": "crm_write",
    "contact": "crm_write",
    "upsert": "crm_write",
    "deploy": "external_api_call",
    "exec": "external_api_call",
    "shell": "external_api_call",
    "http": "external_api_call",
    "webhook": "external_api_call",
    "share": "file_share",
    "upload": "file_share",
}


@dataclass(frozen=True)
class ObservedItem:
    """One capability surface observed in the codebase."""

    name: str
    kind: str  # "mcp_server" | "tool" | "connector"
    source_ref: str
    detail: str = ""
    implied_actions: tuple[str, ...] = ()
    # Stable cross-config identity for an mcp_server (normalized command/args or
    # url); "" otherwise. Used ONLY as a dedup key so the SAME server registered
    # under different roots/names collapses to one. It is deliberately NOT part of
    # to_dict(): it is an internal dedup key, not report output, so serialized
    # reconcile/discovery reports are unchanged.
    identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "source_ref": self.source_ref,
            "detail": self.detail,
            "implied_actions": list(self.implied_actions),
        }


@dataclass(frozen=True)
class ObservedSurface:
    """Everything the scanner found wired up under a root."""

    items: tuple[ObservedItem, ...] = ()
    scanned_files: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    coverage_map: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_count": len(self.items),
            "scanned_file_count": len(self.scanned_files),
            "items": [item.to_dict() for item in self.items],
            "warnings": list(self.warnings),
            "coverage_map": dict(self.coverage_map),
        }


@dataclass(frozen=True)
class ReconciliationResult:
    """Outcome of diffing an observed surface against a declared inventory."""

    project_id: str
    repo_root: str
    observed: ObservedSurface
    matched: tuple[ObservedItem, ...] = ()
    undeclared: tuple[ObservedItem, ...] = ()
    findings: tuple[RiskFinding, ...] = ()

    @property
    def coverage(self) -> float:
        total = len(self.matched) + len(self.undeclared)
        if total == 0:
            return 1.0
        return round(len(self.matched) / total, 4)

    def explanations(self) -> list[dict[str, str]]:
        """Per-observation reasons: WHY each item matched or stayed undeclared.

        Turns the reconciler from a bare verdict into a guide - the reviewer can
        see, for each observed surface item, whether it was matched to the declared
        inventory and (for an undeclared item) where it was seen so they can either
        declare it or explain the omission.
        """

        decisions: list[dict[str, str]] = []
        for item in self.matched:
            noun = "action class" if item.kind == "action" else "inventory token"
            decisions.append(
                {
                    "name": item.name,
                    "kind": item.kind,
                    "status": "matched",
                    "reason": f"observed {item.kind} '{item.name}' matches a declared {noun}",
                }
            )
        for item in self.undeclared:
            noun = "action class" if item.kind == "action" else "agent/tool token"
            decisions.append(
                {
                    "name": item.name,
                    "kind": item.kind,
                    "status": "undeclared",
                    "reason": (
                        f"no declared {noun} exactly matches observed {item.kind} "
                        f"'{item.name}' (seen at {item.source_ref}) — possible omission"
                    ),
                }
            )
        return decisions

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": "ActionVouch",
            "report_version": "actionvouch.reconcile.v1",
            "project_id": self.project_id,
            "repo_root": self.repo_root,
            "coverage": self.coverage,
            "observed_surface_count": len(self.observed.items),
            "matched_surface_count": len(self.matched),
            "undeclared_surface_count": len(self.undeclared),
            "undeclared": [item.to_dict() for item in self.undeclared],
            "matched": [item.to_dict() for item in self.matched],
            "decisions": self.explanations(),
            "coverage_map": dict(self.observed.coverage_map),
            "findings": [finding.to_dict() for finding in self.findings],
            "scanned_files": list(self.observed.scanned_files),
            "warnings": list(self.observed.warnings),
            "guardrails": [
                "Reconciliation reads only files under the operator-provided root; "
                "no network calls and no external processes are run.",
                "An undeclared surface is evidence of a possible omission, not proof "
                "of intent; confirm scope with the owner.",
                "Absence of findings means nothing undeclared was OBSERVED here - it "
                "is not proof the inventory is complete.",
                "The repo scan is HEURISTIC (it misses unsupported languages, "
                "obfuscated/dynamic wiring, and ignored dirs); the action-log and "
                "MCP-tools-list sources are OPERATOR-PROVIDED and unverified. A "
                "determined omission can still evade this - treat it as a tripwire.",
            ],
        }


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def scan_codebase(
    root: str | Path,
    *,
    max_files: int = 5000,
    max_file_bytes: int = 1_000_000,
    ignored_dirs: frozenset[str] | set[str] | None = None,
    deadline: float | None = None,
    name_filter: "Callable[[str], bool] | None" = None,
) -> ObservedSurface:
    """Enumerate the observable tool surface under ``root`` (read-only).

    HEURISTIC, NOT EXHAUSTIVE: this catches the common wiring patterns (the
    frameworks/configs in the pattern tables) but a determined adversary can wire
    a tool in a way it misses - obfuscated/dynamic names, unsupported languages,
    non-standard config formats, or surface under an ignored dir. Treat a clean
    scan as a tripwire that did not trip, not as proof the inventory is complete.
    """

    root_path = Path(root)
    ignored = _IGNORED_DIRS if ignored_dirs is None else frozenset(ignored_dirs)
    items: list[ObservedItem] = []
    scanned: list[str] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    skipped_ignored: set[str] = set()

    if not root_path.exists():
        return ObservedSurface(warnings=(f"root does not exist: {root_path}",))

    file_budget = max_files
    for path in _walk_files(
        root_path, ignored, skipped_ignored, name_filter=name_filter
    ):
        if file_budget <= 0:
            warnings.append(
                f"file scan cap reached ({max_files}); results may be partial"
            )
            break
        # Enforce the time budget DURING the walk, not just between roots, so a
        # single large root cannot run far past the caller's deadline. With a
        # name_filter, _walk_files only yields candidate files, so the millions of
        # non-candidates never reach here - this is what lets a whole-machine scan
        # finish instead of reading (or even Path-constructing) every file.
        if deadline is not None and time.monotonic() > deadline:
            warnings.append("time budget reached during scan; results may be partial")
            break
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        file_budget -= 1
        rel = _rel(path, root_path)
        scanned.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append(f"could not read {rel}: {exc}")
            continue
        for item in _scan_file(path, rel, text):
            key = (item.kind, item.name)
            if key in seen:
                continue
            seen.add(key)
            items.append(item)

    if skipped_ignored:
        warnings.append(
            "skipped ignored dirs (wiring inside them was NOT checked): "
            + ", ".join(sorted(skipped_ignored))
        )

    return ObservedSurface(
        items=tuple(items),
        scanned_files=tuple(scanned),
        warnings=tuple(warnings),
        coverage_map=_coverage_map(scanned),
    )


_EXT_LANGUAGE = {
    ".py": "python (AST + regex)",
    ".js": "javascript/typescript (regex)",
    ".ts": "javascript/typescript (regex)",
    ".mjs": "javascript/typescript (regex)",
    ".cjs": "javascript/typescript (regex)",
    ".tsx": "javascript/typescript (regex)",
    ".jsx": "javascript/typescript (regex)",
    ".json": "json config (parsed)",
}


def _coverage_map(scanned: list[str]) -> dict[str, Any]:
    """Transparency map: what the scan actually covered (and how), and what it didn't.

    A coverage map narrows the "heuristic, not exhaustive" gap by making it
    inspectable - it does NOT close it: dynamic/obfuscated/runtime-built wiring and
    unlisted file types remain undetectable by a static scan.
    """

    ext_counts: dict[str, int] = {}
    for rel in scanned:
        ext = (os.path.splitext(rel)[1] or "(none)").lower()
        ext_counts[ext] = ext_counts.get(ext, 0) + 1
    languages = sorted(
        {_EXT_LANGUAGE[ext] for ext in ext_counts if ext in _EXT_LANGUAGE}
    )
    return {
        "files_scanned": len(scanned),
        "extensions_scanned": dict(sorted(ext_counts.items())),
        "python_files_ast_scanned": ext_counts.get(".py", 0),
        "languages_covered": languages,
        "note": (
            "Detection is by file type — AST for Python, regex for JS/TS, parsed "
            "JSON for MCP config. Dynamic/obfuscated/runtime-built wiring and "
            "unlisted file types are NOT covered: this is a coverage map, not proof "
            "of completeness."
        ),
    }


def _walk_files(
    root: Path,
    ignored_dirs: frozenset[str],
    skipped_ignored: set[str],
    *,
    max_depth: int = 60,
    name_filter: "Callable[[str], bool] | None" = None,
):
    # Uses os.scandir (DirEntry caches type info, so no extra stat per file) and
    # only resolves SYMLINKED dirs - a regular directory tree cannot cycle, so the
    # common path stays cheap on a full-drive walk. A depth cap backstops any
    # cycle (symlink or Windows junction); symlinked dirs are additionally checked
    # for escaping the scan root.
    root_real = _safe_resolve(root)
    visited: set[str] = set()
    stack: list[tuple[str, int]] = [(str(root), 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=True):
                    if entry.name in ignored_dirs:
                        skipped_ignored.add(entry.name)
                        continue
                    if entry.is_symlink():
                        real = _safe_resolve(Path(entry.path))
                        if real is None or real in visited:
                            continue
                        if root_real is not None and not _within(real, root_real):
                            continue  # symlink escaping the scan root
                        visited.add(real)
                    stack.append((entry.path, depth + 1))
                elif entry.is_file(follow_symlinks=True):
                    # Filter on the cheap DirEntry name BEFORE building a Path, so
                    # the millions of non-candidate files on a drive cost almost
                    # nothing (no Path object, no downstream processing).
                    if name_filter is None or name_filter(entry.name):
                        yield Path(entry.path)
            except OSError:
                continue


def _safe_resolve(path: Path) -> str | None:
    try:
        return str(path.resolve())
    except OSError:
        return None


def _within(real: str, root_real: str, pathmod: ModuleType = os.path) -> bool:
    # Robust to drive roots like "C:\\" (which carry a trailing separator) and to
    # case-insensitive Windows paths. commonpath raises ValueError across drives,
    # which correctly means "not within".
    #
    # Containment is path-FLAVOUR dependent, so the flavour is an explicit
    # parameter defaulting to the host's (os.path). Tests inject ntpath/posixpath
    # to assert both flavours on any platform: asserted against the default, the
    # Windows drive-root cases are untestable on a Linux runner, where a backslash
    # is an ordinary filename character rather than a path separator.
    real_n = pathmod.normcase(pathmod.normpath(real))
    root_n = pathmod.normcase(pathmod.normpath(root_real))
    if real_n == root_n:
        return True
    try:
        return pathmod.commonpath([real_n, root_n]) == root_n
    except ValueError:
        return False


def _scan_file(path: Path, rel: str, text: str) -> list[ObservedItem]:
    items: list[ObservedItem] = []
    suffix = path.suffix.lower()
    if suffix == ".json":
        items.extend(_scan_json_for_mcp(path, rel, text))
    if suffix == ".py":
        # AST-precise pass for Python, in addition to the regex pass; dedupe in
        # scan_codebase merges any overlap by (kind, name).
        items.extend(_scan_python_ast(rel, text))
    if suffix in _SOURCE_SUFFIXES:
        items.extend(_scan_source_for_tools(rel, text))
    if _is_env_file(path):
        items.extend(_scan_env_for_connectors(rel, text))
    return items


def _decorator_attr(decorator: ast.expr) -> str:
    """Resolve a decorator to its leaf name: @tool / @x.tool / @x.tool(...) -> 'tool'."""

    node: ast.expr = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _scan_python_ast(rel: str, text: str) -> list[ObservedItem]:
    """AST-precise detection of decorator-registered tools in Python source.

    Robust where regex is brittle: multi-line decorators, aliases, and arbitrary
    whitespace around ``@tool`` / ``@x.tool(...)`` / FastMCP ``@mcp.tool()``. A
    syntactically invalid file yields nothing here and falls back to the regex pass.
    """

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    items: list[ObservedItem] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_decorator_attr(dec) == "tool" for dec in node.decorator_list):
            continue
        items.append(
            ObservedItem(
                name=_slug(node.name),
                kind="tool",
                source_ref=rel,
                detail="ast: tool-decorated function",
                implied_actions=_implied_actions_for_name(node.name),
            )
        )
    return items


def _scan_json_for_mcp(path: Path, rel: str, text: str) -> list[ObservedItem]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    servers = _mcp_servers_block(path, data)
    items: list[ObservedItem] = []
    for name, spec in servers.items():
        detail = ""
        if isinstance(spec, dict):
            detail = str(
                spec.get("command") or spec.get("url") or spec.get("type") or ""
            )
        items.append(
            ObservedItem(
                name=_slug(name),
                kind="mcp_server",
                source_ref=rel,
                detail=detail,
                implied_actions=("external_api_call",),
                identity=_mcp_identity(spec),
            )
        )
    return items


def _mcp_identity(spec: Any) -> str:
    """Stable cross-config identity for an MCP server spec.

    Returns the server's URL (remote) or its normalized ``command`` + ``args``
    (local), slugged. Two configs that launch the SAME server share this identity
    even when registered under different keys, so discovery can collapse the
    duplicate instead of counting it twice. Returns ``""`` when the spec carries
    no command/url (e.g. an empty ``{}``), so such servers fall back to name-based
    identity and are never over-collapsed together.
    """

    if not isinstance(spec, dict):
        return ""
    url = spec.get("url")
    if isinstance(url, str) and url.strip():
        return _slug(url)
    command = spec.get("command")
    command_str = command.strip() if isinstance(command, str) else ""
    args = spec.get("args")
    args_str = " ".join(str(arg) for arg in args) if isinstance(args, list) else ""
    combined = f"{command_str} {args_str}".strip()
    return _slug(combined) if combined else ""


def _mcp_servers_block(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    if isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"]
    if isinstance(data.get("mcp_servers"), dict):
        return data["mcp_servers"]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    name_hint = path.name.lower()
    if any(hint in name_hint for hint in _MCP_FILENAME_HINTS) and isinstance(
        data.get("servers"), dict
    ):
        return data["servers"]
    return {}


def _scan_source_for_tools(rel: str, text: str) -> list[ObservedItem]:
    items: list[ObservedItem] = []
    for pattern in _TOOL_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1)
            if not raw:
                continue
            items.append(
                ObservedItem(
                    name=_slug(raw),
                    kind="tool",
                    source_ref=rel,
                    detail=f"registered as {raw}",
                    implied_actions=_implied_actions_for_name(raw),
                )
            )
    return items


def _scan_env_for_connectors(rel: str, text: str) -> list[ObservedItem]:
    items: list[ObservedItem] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        raw_key = stripped.split("=", 1)[0].strip()
        key = raw_key.lower()
        matched_vendor = False
        for hint, (connector, actions) in _CONNECTOR_ENV_HINTS.items():
            if hint in key:
                matched_vendor = True
                items.append(
                    ObservedItem(
                        name=_slug(connector),
                        kind="connector",
                        source_ref=rel,
                        detail=f"credential key {raw_key}",
                        implied_actions=actions,
                    )
                )
        if not matched_vendor and any(marker in key for marker in _CREDENTIAL_MARKERS):
            risk = tuple(
                sorted(
                    {
                        action
                        for keyword, actions in _CONNECTOR_RISK_KEYWORDS.items()
                        if keyword in key
                        for action in actions
                    }
                )
            )
            if risk:
                items.append(
                    ObservedItem(
                        name=_slug(raw_key),
                        kind="connector",
                        source_ref=rel,
                        detail=f"credential key {raw_key} (heuristic: risk keyword)",
                        implied_actions=risk,
                    )
                )
    return items


def _is_env_file(path: Path) -> bool:
    name = path.name.lower()
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def _implied_actions_for_name(raw: str) -> tuple[str, ...]:
    lowered = raw.lower()
    actions = {
        action for keyword, action in _ACTION_KEYWORDS.items() if keyword in lowered
    }
    return tuple(sorted(actions))


def observe_mcp_tools_export(
    path: str | Path, *, max_bytes: int = 25_000_000
) -> ObservedSurface:
    """Observe the tools an MCP server actually exposes, from a captured
    ``tools/list`` response the operator exports out-of-band.

    Accepts the raw result ``{"tools": [...]}``, a JSON-RPC envelope
    ``{"result": {"tools": [...]}}``, or a per-server map
    ``{"server_id": {"tools": [...]}}``. Reads one local file; no network call.
    The repo scan finds the *server*; this finds the *tools that server exposes*.

    OPERATOR-PROVIDED, UNVERIFIED: this file is supplied by the operator, so it is
    an attestation, not an independent observation - a sanitized export that omits
    a dangerous tool will read as clean. Trust it only as far as its source.
    """

    file_path = Path(path)
    too_large = _too_large(file_path, max_bytes)
    if too_large is not None:
        return ObservedSurface(warnings=(too_large,))
    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return ObservedSurface(
            warnings=(f"could not parse mcp tools export {path}: {exc}",)
        )
    items: list[ObservedItem] = []
    rel = file_path.name
    for server, tools in _tool_lists_from_export(data):
        if server:
            items.append(
                ObservedItem(
                    name=_slug(server),
                    kind="mcp_server",
                    source_ref=rel,
                    detail="from tools/list export",
                    implied_actions=("external_api_call",),
                )
            )
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "").strip()
            if not name:
                continue
            detail = str(tool.get("description") or "")[:120]
            items.append(
                ObservedItem(
                    name=_slug(name),
                    kind="tool",
                    source_ref=rel,
                    detail=detail or f"mcp tool {name}",
                    implied_actions=_implied_actions_for_name(f"{name} {detail}"),
                )
            )
    return ObservedSurface(items=_dedupe_items(items), scanned_files=(rel,))


def observe_action_log(
    path: str | Path, *, max_bytes: int = 25_000_000
) -> ObservedSurface:
    """Observe tools/actions that executed, from a local agent action log: a JSON
    array, a ``{"events": [...]}`` object, or JSONL (one JSON object per line).

    OPERATOR-PROVIDED, UNVERIFIED: the log is whatever file the operator hands
    over. A curated/filtered log that omits the dangerous actions will read as
    clean, so this is runtime *evidence* only to the extent the log source is
    independent and tamper-evident (e.g. a SIEM) - it is not, by itself, proof.
    """

    file_path = Path(path)
    too_large = _too_large(file_path, max_bytes)
    if too_large is not None:
        return ObservedSurface(warnings=(too_large,))
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return ObservedSurface(warnings=(f"could not read action log {path}: {exc}",))
    records, warnings = _records_from_log(text)
    items: list[ObservedItem] = []
    rel = file_path.name
    for record in records:
        if not isinstance(record, dict):
            continue
        tool = str(
            record.get("tool")
            or record.get("tool_called")
            or record.get("tool_name")
            or ""
        ).strip()
        if tool:
            items.append(
                ObservedItem(
                    name=_slug(tool),
                    kind="tool",
                    source_ref=rel,
                    detail="observed executing in action log",
                    implied_actions=_implied_actions_for_name(tool),
                )
            )
        action = str(record.get("action_class") or record.get("action") or "").strip()
        if action:
            canonical = _canonical_action(action)
            items.append(
                ObservedItem(
                    name=canonical,
                    kind="action",
                    source_ref=rel,
                    detail=f"executed: {action}",
                    implied_actions=(canonical,),
                )
            )
    return ObservedSurface(
        items=_dedupe_items(items), scanned_files=(rel,), warnings=tuple(warnings)
    )


def _tool_lists_from_export(data: Any):
    if isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            yield "", data["tools"]
            return
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            yield "", result["tools"]
            return
        emitted = False
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(value.get("tools"), list):
                emitted = True
                yield key, value["tools"]
        if emitted:
            return
    if isinstance(data, list):
        yield "", data


def _records_from_log(text: str) -> tuple[list[Any], list[str]]:
    text = text.strip()
    if not text:
        return [], []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        data = None
    if isinstance(data, list):
        return data, []
    if isinstance(data, dict):
        for key in ("events", "actions", "action_events", "records", "log"):
            if isinstance(data.get(key), list):
                return data[key], []
        return [data], []
    records: list[Any] = []
    warnings: list[str] = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except (json.JSONDecodeError, ValueError):
            warnings.append(f"action log line {index} is not valid JSON")
    return records, warnings


def _canonical_action(action: str) -> str:
    slug = _slug(action)
    if slug in ACTION_CLASSES:
        return slug
    implied = _implied_actions_for_name(action)
    return implied[0] if implied else slug


def _dedupe_items(
    items: list[ObservedItem],
    *,
    key: "Callable[[ObservedItem], tuple[str, str]] | None" = None,
) -> tuple[ObservedItem, ...]:
    """Drop duplicate observed items, keeping first occurrence.

    The default key is ``(kind, name)`` (unchanged for existing callers). Discovery
    passes a ``key`` that collapses an mcp_server by its normalized command/args/url
    identity, so the SAME server registered under multiple roots/aliases is counted
    once.
    """

    key_fn = key or (lambda item: (item.kind, item.name))
    seen: set[tuple[str, str]] = set()
    out: list[ObservedItem] = []
    for item in items:
        item_key = key_fn(item)
        if item_key in seen:
            continue
        seen.add(item_key)
        out.append(item)
    return tuple(out)


# --------------------------------------------------------------------------- #
# Reconciliation
# --------------------------------------------------------------------------- #
def reconcile_codebase(project: AuditProject, root: str | Path) -> ReconciliationResult:
    return reconcile_surface(project, scan_codebase(root), repo_root=str(root))


def reconcile_sources(
    project: AuditProject,
    *,
    repo: str | Path | None = None,
    mcp_tools_export: str | Path | None = None,
    action_log: str | Path | None = None,
) -> ReconciliationResult:
    """Reconcile against any combination of observation sources.

    Each source independently enumerates real surface; together they cover code
    wiring (repo), the actual tools an MCP server exposes (tools/list export),
    and runtime-evidenced capability (action log).
    """

    surfaces: list[ObservedSurface] = []
    roots: list[str] = []
    if repo is not None:
        surfaces.append(scan_codebase(repo))
        roots.append(f"repo={repo}")
    if mcp_tools_export is not None:
        surfaces.append(observe_mcp_tools_export(mcp_tools_export))
        roots.append(f"mcp_tools={mcp_tools_export}")
    if action_log is not None:
        surfaces.append(observe_action_log(action_log))
        roots.append(f"action_log={action_log}")
    combined = combine_surfaces(*surfaces)
    return reconcile_surface(project, combined, repo_root="; ".join(roots))


def combine_surfaces(*surfaces: ObservedSurface) -> ObservedSurface:
    items: list[ObservedItem] = []
    scanned: list[str] = []
    warnings: list[str] = []
    coverage_map: dict[str, Any] = {}
    seen: set[tuple[str, str]] = set()
    for surface in surfaces:
        for item in surface.items:
            key = (item.kind, item.name)
            if key in seen:
                continue
            seen.add(key)
            items.append(item)
        scanned.extend(surface.scanned_files)
        warnings.extend(surface.warnings)
        if surface.coverage_map:  # the repo scan carries it; later sources don't
            coverage_map = surface.coverage_map
    return ObservedSurface(
        items=tuple(items),
        scanned_files=tuple(scanned),
        warnings=tuple(warnings),
        coverage_map=coverage_map,
    )


def reconcile_surface(
    project: AuditProject,
    observed: ObservedSurface,
    *,
    repo_root: str = "",
) -> ReconciliationResult:
    declared = _declared_tokens(project)
    declared_actions = _declared_action_classes(project)
    matched: list[ObservedItem] = []
    undeclared: list[ObservedItem] = []
    for item in observed.items:
        if _item_is_declared(item, declared, declared_actions):
            matched.append(item)
        else:
            undeclared.append(item)
    findings = tuple(_finding_for(item) for item in undeclared)
    return ReconciliationResult(
        project_id=project.project_id,
        repo_root=repo_root,
        observed=observed,
        matched=tuple(matched),
        undeclared=tuple(undeclared),
        findings=findings,
    )


def _item_is_declared(
    item: ObservedItem, declared_tokens: set[str], declared_actions: set[str]
) -> bool:
    # An executed/declared action class is matched against the action vocabulary
    # exactly (no fuzzy substring), so "draft" never masks "file_delete".
    if item.kind == "action":
        return item.name in declared_actions
    return _is_declared(item.name, declared_tokens)


def _declared_action_classes(project: AuditProject) -> set[str]:
    actions: set[str] = set()
    for agent in project.agents:
        actions.update(_slug(value) for value in agent.action_classes)
    for tool in project.tools:
        actions.update(_slug(value) for value in tool.actions_supported)
    for event in project.action_events:
        if event.action_class:
            actions.add(_slug(event.action_class))
    actions.discard("")
    return actions


def _declared_tokens(project: AuditProject) -> set[str]:
    # Only *tool-surface identity* tokens count as "declared". Agent name,
    # provider, and model_or_runtime are deliberately excluded: a red-team showed
    # broad fields like provider="slack" would absorb an undeclared
    # "slack_exfil_server". The inventory must name the tool/connector to cover it.
    tokens: set[str] = set()
    for tool in project.tools:
        for value in (
            tool.tool_id,
            tool.name,
            tool.system,
            tool.connector_type,
            tool.mcp_server_id,
            tool.a2a_agent_card_id,
        ):
            if value:
                tokens.add(_slug(value))
    for agent in project.agents:
        for tool_ref in agent.tools:
            if tool_ref and tool_ref != "unknown":
                tokens.add(_slug(tool_ref))
    tokens.discard("")
    tokens.discard("unknown")
    return tokens


def _is_declared(observed_slug: str, declared_tokens: set[str]) -> bool:
    # EXACT match only. The previous bidirectional substring match (with a 4-char
    # floor) was a suppression hole: declaring a vague tool named "records" would
    # absorb an undeclared "delete_all_records". An observed surface counts as
    # declared only if the inventory names it exactly (after slugging). Erring
    # toward "undeclared" is the safe direction for a detector - a near-miss gets
    # surfaced for the owner to confirm rather than silently hidden.
    return observed_slug in declared_tokens


def _finding_for(item: ObservedItem) -> RiskFinding:
    severity = _severity_for(item)
    kind_label = item.kind.replace("_", " ")
    return RiskFinding(
        finding_id=f"undeclared-{item.kind}-{item.name}",
        severity=severity,
        title=f"Undeclared {kind_label} observed: {item.name}",
        affected_record_type="undeclared_surface",
        affected_record_id=item.name,
        facts=[
            f"A {kind_label} '{item.name}' was observed ({item.source_ref}) but is "
            "not present in the declared inventory.",
            f"Observed detail: {item.detail or 'n/a'}.",
        ],
        assumptions=[
            "Reconciliation compares the declared inventory against tool surface "
            "observed in the operator-provided codebase only.",
        ],
        unknowns=[
            "Whether this surface is in audit scope, and what permissions it holds, "
            "is not established by the inventory.",
        ],
        evidence=[f"reconciliation:{item.source_ref}"],
        risks=[
            "An undeclared capability means the audit's risk picture is incomplete; "
            "a dangerous tool/connector could be operating without review.",
            *(
                [f"Implied action classes: {', '.join(item.implied_actions)}."]
                if item.implied_actions
                else []
            ),
        ],
        counterarguments=[
            "The surface may be intentionally out of scope or unused; confirm with "
            "the owner before treating it as live.",
        ],
        recommendation=(
            "Add this surface to the inventory (or document it as explicitly "
            "out-of-scope), attach permission evidence, and re-run the audit."
        ),
        tradeoffs=[
            "Declaring more surface increases audit effort but removes a blind spot.",
        ],
        what_would_change_the_recommendation=[
            "An inventory entry covering this surface with verified permissions, or a "
            "signed scope statement excluding it.",
        ],
        confidence_score=0.8,
        framework_mappings=[
            "NIST AI RMF Map",
            "OWASP Agentic Top 10 excessive agency",
            "Gartner proportional agent governance",
        ],
    )


def _severity_for(item: ObservedItem) -> str:
    implied = set(item.implied_actions)
    if implied & DESTRUCTIVE_ACTION_CLASSES:
        return "critical"
    if implied & HIGH_RISK_ACTION_CLASSES:
        return "high"
    # An undeclared MCP server or external connector is an unknown external
    # surface and is treated as high until scoped; a bare tool is medium.
    if item.kind in {"mcp_server", "connector"}:
        return "high"
    return "medium"


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _too_large(path: Path, max_bytes: int) -> str | None:
    """Return a warning if the file is missing or over the size cap, else None.

    Guards the single-shot read in the export/log observers against an oversized
    operator-provided file exhausting memory.
    """

    try:
        size = path.stat().st_size
    except OSError as exc:
        return f"could not stat {path.name}: {exc}"
    if size > max_bytes:
        return (
            f"{path.name} is too large ({size} bytes > {max_bytes}); refused to "
            "avoid memory exhaustion"
        )
    return None


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "unknown"
