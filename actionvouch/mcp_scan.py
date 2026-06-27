"""Read-only MCP manifest / tool-scope scanner for ActionVouch.

Parses a local Model Context Protocol (MCP) configuration manifest **statically**
and reports each server's transport, the environment-variable KEYS it references
(never the values), and — when the manifest includes a tool catalog — each tool's
scope risk (read-only / write / destructive / open-world).

This is a fail-closed, evidence-first scan. It NEVER starts an MCP server, calls
``tools/list``, invokes a tool, reads an environment-variable value, or makes any
network request. A server whose tools are not statically listed is reported as
``tools_not_enumerated`` (unknown), never as safe. Designed for fixture replay:
it reads one local JSON file and uses only the standard library.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Conservative keyword heuristics used only when MCP tool annotations are absent.
_DESTRUCTIVE_WORDS = (
    "delete",
    "remove",
    "drop",
    "destroy",
    "purge",
    "wipe",
    "truncate",
    "erase",
    "revoke",
)
_WRITE_WORDS = (
    "write",
    "update",
    "create",
    "insert",
    "set",
    "put",
    "post",
    "send",
    "publish",
    "upload",
    "modify",
    "edit",
    "rename",
    "move",
    "exec",
    "execute",
    "run",
    "invoke",
    "deploy",
    "patch",
    "push",
)
_OPEN_WORLD_WORDS = (
    "fetch",
    "http",
    "url",
    "web",
    "browse",
    "search",
    "crawl",
    "request",
    "scrape",
    "download",
    "api",
)
_SENSITIVE_DATA_WORDS = (
    "email",
    "customer",
    "payment",
    "card",
    "ssn",
    "password",
    "secret",
    "token",
    "credential",
    "health",
    "patient",
    "financial",
    "bank",
    "pii",
    "invoice",
    "contract",
    "account",
)
_SECRET_KEY_WORDS = ("token", "key", "secret", "password", "passwd", "credential")
_NETWORK_TRANSPORTS = (
    "http",
    "sse",
    "streamable-http",
    "streamable_http",
    "ws",
    "websocket",
)


@dataclass(frozen=True)
class McpToolFinding:
    name: str
    read_only: bool
    write_capable: bool
    destructive: bool
    open_world: bool
    risk_level: str
    risk_flags: list[str]
    data_hints: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "read_only": self.read_only,
            "write_capable": self.write_capable,
            "destructive": self.destructive,
            "open_world": self.open_world,
            "risk_level": self.risk_level,
            "risk_flags": self.risk_flags,
            "data_hints": self.data_hints,
        }


@dataclass(frozen=True)
class McpServerFinding:
    name: str
    transport: str
    network_reaching: bool
    command_summary: str
    referenced_env_keys: list[str]
    tools_enumerated: bool
    tools: list[McpToolFinding]
    risk_level: str
    risk_flags: list[str]
    unknowns: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "network_reaching": self.network_reaching,
            "command_summary": self.command_summary,
            "referenced_env_keys": self.referenced_env_keys,
            "tools_enumerated": self.tools_enumerated,
            "tools": [tool.to_dict() for tool in self.tools],
            "risk_level": self.risk_level,
            "risk_flags": self.risk_flags,
            "unknowns": self.unknowns,
        }


@dataclass(frozen=True)
class McpScanResult:
    source: str
    valid: bool
    errors: list[str]
    servers: list[McpServerFinding]
    summary: dict[str, Any]
    guardrails: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_version": "actionvouch.mcp_scan.v1",
            "source": self.source,
            "valid": self.valid,
            "errors": self.errors,
            "servers": [server.to_dict() for server in self.servers],
            "summary": self.summary,
            "guardrails": self.guardrails,
        }


_GUARDRAILS = [
    "Static manifest scan only: no MCP server was started or executed.",
    "No tools were invoked and no tools/list call was made.",
    "No network calls were performed.",
    "Environment variable values were not read; only key names are listed.",
    "Servers without a static tool catalog are reported as tools_not_enumerated "
    "(unknown), not as safe.",
    "Scope risk is heuristic and unverified; treat it as review input, not a "
    "verified permission audit.",
]


def scan_mcp_manifest(path: str | Path) -> McpScanResult:
    """Statically scan an MCP configuration manifest at ``path``."""

    source = str(path)
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return _invalid(source, f"could not read manifest: {exc}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _invalid(source, f"manifest is not valid JSON: {exc}")
    return scan_mcp_data(data, source=source)


# Bounds so a pathological manifest cannot pin CPU/memory. Far above any real
# MCP config; over the server cap the scan fails closed, and per-server tool
# lists are truncated with a flag rather than scanned without limit.
_MAX_SERVERS = 500
_MAX_TOOLS_PER_SERVER = 2000


def scan_mcp_data(data: Any, *, source: str = "<input>") -> McpScanResult:
    """Scan an already-parsed MCP manifest object (no file or network access)."""

    if not isinstance(data, dict):
        return _invalid(source, "manifest must be a JSON object")
    servers_raw = _extract_servers(data)
    if not servers_raw:
        return _invalid(
            source,
            "no MCP servers found (expected 'mcpServers', 'servers', or a "
            "single-server object with 'command' or 'url')",
        )
    if len(servers_raw) > _MAX_SERVERS:
        return _invalid(
            source,
            f"too many servers ({len(servers_raw)} > {_MAX_SERVERS}); "
            "scan a smaller manifest",
        )
    servers = [_scan_server(name, cfg) for name, cfg in servers_raw]
    return McpScanResult(
        source=source,
        valid=True,
        errors=[],
        servers=servers,
        summary=_summary(servers),
        guardrails=list(_GUARDRAILS),
    )


def _invalid(source: str, error: str) -> McpScanResult:
    return McpScanResult(
        source=source,
        valid=False,
        errors=[error],
        servers=[],
        summary={"server_count": 0, "tool_count": 0},
        guardrails=list(_GUARDRAILS),
    )


def _extract_servers(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    for key in ("mcpServers", "mcp_servers", "servers"):
        block = data.get(key)
        if isinstance(block, dict):
            return [
                (str(name), cfg) for name, cfg in block.items() if isinstance(cfg, dict)
            ]
        if isinstance(block, list):
            return [
                (str(cfg.get("name") or cfg.get("server_id") or f"server_{index}"), cfg)
                for index, cfg in enumerate(block, start=1)
                if isinstance(cfg, dict)
            ]
    if data.get("command") or data.get("url") or data.get("transport"):
        return [(str(data.get("name") or "server"), data)]
    return []


def _scan_server(name: str, cfg: dict[str, Any]) -> McpServerFinding:
    transport = _transport(cfg)
    network_reaching = transport in _NETWORK_TRANSPORTS or bool(cfg.get("url"))
    env = cfg.get("env")
    env_keys: list[str] = []
    if isinstance(env, dict):
        raw_keys = list(env)
        env_keys = sorted(str(key) for key in raw_keys)
    raw_tools = cfg.get("tools")
    enumerated = isinstance(raw_tools, list) and bool(raw_tools)
    tools: list[McpToolFinding] = []
    tools_truncated = False
    if isinstance(raw_tools, list):
        capped = raw_tools[:_MAX_TOOLS_PER_SERVER]
        tools_truncated = len(raw_tools) > _MAX_TOOLS_PER_SERVER
        tools = [_scan_tool(item) for item in capped if isinstance(item, dict)]

    flags: list[str] = []
    unknowns: list[str] = []
    if tools_truncated:
        flags.append("tool_list_truncated")
        unknowns.append(
            f"Tool list exceeded {_MAX_TOOLS_PER_SERVER}; only the first "
            f"{_MAX_TOOLS_PER_SERVER} tools were scanned."
        )
    if network_reaching:
        flags.append("network_reaching")
        unknowns.append(
            "Server reaches the network; endpoint and live scopes are not verified."
        )
    if env_keys:
        flags.append(f"references_env_keys:{len(env_keys)}")
        if any(_looks_secret(key) for key in env_keys):
            flags.append("holds_credentials")
        unknowns.append(
            "Server references environment secrets; values were not read and the "
            "granted scopes are not verified."
        )
    if not enumerated:
        flags.append("tools_not_enumerated")
        unknowns.append(
            "Tool catalog not included; tools cannot be enumerated without "
            "executing the server, which the scanner does not do."
        )

    risk = _highest([tool.risk_level for tool in tools]) if enumerated else "unknown"
    if network_reaching:
        risk = _highest([risk, "medium"]) if risk != "unknown" else "unknown"
    return McpServerFinding(
        name=name,
        transport=transport,
        network_reaching=network_reaching,
        command_summary=_command_summary(cfg),
        referenced_env_keys=env_keys,
        tools_enumerated=enumerated,
        tools=tools,
        risk_level=risk,
        risk_flags=flags,
        unknowns=unknowns,
    )


def _scan_tool(tool: dict[str, Any]) -> McpToolFinding:
    name = str(tool.get("name") or "unnamed_tool")
    raw_annotations = tool.get("annotations")
    annotations = raw_annotations if isinstance(raw_annotations, dict) else {}
    haystack = f"{name} {tool.get('description') or ''}".lower()
    lname = name.lower()

    # Risk evidence from annotations and keyword heuristics, computed
    # independently so one self-declared hint cannot erase the others.
    destructive = _hint_or_keyword(
        annotations.get("destructiveHint"), lname, _DESTRUCTIVE_WORDS
    )
    open_world = _hint_or_keyword(
        annotations.get("openWorldHint"), haystack, _OPEN_WORLD_WORDS
    )
    write_capable = (
        annotations.get("readOnlyHint") is False
        or destructive
        or _matches(lname, _WRITE_WORDS)
    )

    # A readOnlyHint only DOWNGRADES risk when nothing contradicts it. For an
    # untrusted manifest, honoring a self-declared "read-only" over destructive/
    # write evidence would be false assurance, so on conflict keep the higher
    # risk and flag it instead of silently dropping to low.
    read_only_hint = annotations.get("readOnlyHint") is True
    conflict = read_only_hint and (destructive or write_capable)
    read_only = read_only_hint and not conflict
    if read_only:
        write_capable = False
        destructive = False

    flags: list[str] = []
    if destructive:
        flags.append("destructive")
    if write_capable:
        flags.append("write_capable")
    if open_world:
        flags.append("open_world")
    if read_only:
        flags.append("read_only")
    if conflict:
        flags.append("readonly_hint_conflicts_evidence")
    if not read_only and not write_capable and not annotations:
        flags.append("scope_unverified")

    return McpToolFinding(
        name=name,
        read_only=read_only,
        write_capable=write_capable,
        destructive=destructive,
        open_world=open_world,
        risk_level=_tool_risk(read_only, write_capable, destructive, open_world),
        risk_flags=flags,
        data_hints=sorted({word for word in _SENSITIVE_DATA_WORDS if word in haystack}),
    )


def _tool_risk(
    read_only: bool, write_capable: bool, destructive: bool, open_world: bool
) -> str:
    if destructive:
        return "critical"
    if write_capable:
        return "high"
    if open_world:
        return "medium"
    if read_only:
        return "low"
    return "medium"


def _transport(cfg: dict[str, Any]) -> str:
    explicit = str(cfg.get("transport") or cfg.get("type") or "").strip().lower()
    if explicit:
        return explicit
    if cfg.get("url"):
        return "http"
    if cfg.get("command"):
        return "stdio"
    return "unknown"


def _command_summary(cfg: dict[str, Any]) -> str:
    command = cfg.get("command")
    if command:
        args = cfg.get("args")
        arg_count = len(args) if isinstance(args, list) else 0
        return f"{str(command).strip()} ({arg_count} args, values not shown)"
    if cfg.get("url"):
        return "remote endpoint (url not shown)"
    return "unknown"


def _looks_secret(key: str) -> bool:
    lowered = key.lower()
    return any(word in lowered for word in _SECRET_KEY_WORDS)


def _hint_or_keyword(hint: Any, text: str, words: tuple[str, ...]) -> bool:
    """An explicit boolean MCP annotation wins; otherwise fall back to keywords."""

    if hint is True:
        return True
    if hint is False:
        return False
    return _matches(text, words)


def _matches(text: str, words: tuple[str, ...]) -> bool:
    return any(word in text for word in words)


_RISK_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _highest(levels: list[str]) -> str:
    # Defaults to "unknown" (not "low") so an unassessable server never reads as
    # safe; a known level always outranks unknown.
    best = "unknown"
    for level in levels:
        if _RISK_ORDER.get(level, 0) > _RISK_ORDER.get(best, 0):
            best = level
    return best


def _summary(servers: list[McpServerFinding]) -> dict[str, Any]:
    tools = [tool for server in servers for tool in server.tools]
    by_risk: dict[str, int] = {}
    for tool in tools:
        by_risk[tool.risk_level] = by_risk.get(tool.risk_level, 0) + 1
    return {
        "server_count": len(servers),
        "tool_count": len(tools),
        "network_reaching_servers": sum(1 for s in servers if s.network_reaching),
        "servers_referencing_env_keys": sum(
            1 for s in servers if s.referenced_env_keys
        ),
        "servers_not_enumerated": sum(1 for s in servers if not s.tools_enumerated),
        "destructive_tool_count": sum(1 for t in tools if t.destructive),
        "write_capable_tool_count": sum(1 for t in tools if t.write_capable),
        "tool_risk_counts": dict(sorted(by_risk.items())),
        "highest_server_risk": _highest([s.risk_level for s in servers]),
    }


def render_mcp_scan_markdown(result: McpScanResult) -> str:
    """Render a markdown report for an MCP manifest scan."""

    lines = [
        "# ActionVouch MCP Manifest Scan",
        "",
        f"- Source: `{_md(result.source)}`",
        f"- Valid: `{str(result.valid).lower()}`",
    ]
    if not result.valid:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {_md(error)}" for error in result.errors)
        lines.extend(["", "## Guardrails", ""])
        lines.extend(f"- {_md(item)}" for item in result.guardrails)
        return "\n".join(lines) + "\n"

    summary = result.summary
    lines.extend(
        [
            f"- Servers: {summary['server_count']} "
            f"({summary['network_reaching_servers']} network-reaching)",
            f"- Tools: {summary['tool_count']} "
            f"({summary['destructive_tool_count']} destructive, "
            f"{summary['write_capable_tool_count']} write-capable)",
            f"- Highest server risk: `{summary['highest_server_risk']}`",
            "",
            "## Servers",
            "",
        ]
    )
    for server in result.servers:
        lines.extend(_server_markdown(server))
    lines.extend(["## Guardrails", ""])
    lines.extend(f"- {_md(item)}" for item in result.guardrails)
    return "\n".join(lines) + "\n"


def _server_markdown(server: McpServerFinding) -> list[str]:
    lines = [
        f"### `{_md(server.name)}` - risk `{server.risk_level}`",
        "",
        f"- Transport: `{_md(server.transport)}` "
        f"(network-reaching: `{str(server.network_reaching).lower()}`)",
        f"- Command: {_md(server.command_summary)}",
        "- Referenced env keys: "
        f"{', '.join(f'`{_md(k)}`' for k in server.referenced_env_keys) or 'none'}",
        f"- Flags: {', '.join(server.risk_flags) or 'none'}",
    ]
    if server.tools_enumerated:
        lines.append("- Tools:")
        for tool in server.tools:
            lines.append(
                f"  - `{_md(tool.name)}` (`{tool.risk_level}`): "
                f"{', '.join(tool.risk_flags) or 'none'}"
                + (f" - data: {', '.join(tool.data_hints)}" if tool.data_hints else "")
            )
    else:
        lines.append("- Tools: not enumerated (server not executed)")
    for unknown in server.unknowns:
        lines.append(f"- Unknown: {_md(unknown)}")
    lines.append("")
    return lines


def _md(value: object) -> str:
    # Collapse newlines/carriage returns to spaces first: a manifest-controlled
    # string with embedded newlines could otherwise inject Markdown structure
    # (fake headings, list items, fenced code) into the rendered scan report.
    text = str(value).replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
