"""Tests for the read-only MCP manifest / tool-scope scanner.

The scanner is a static, fail-closed analysis: it never starts a server, calls
tools/list, reads an env value, or makes a network call. These tests drive it
from recorded fixtures and assert the risk classification, the unknown-not-safe
posture, and that no secret value ever reaches the output.
"""

from __future__ import annotations

import json

from actionvouch.mcp_scan import (
    render_mcp_scan_markdown,
    scan_mcp_data,
    scan_mcp_manifest,
)
from actionvouch.paths import PROJECT_ROOT

MANIFESTS = PROJECT_ROOT / "examples" / "actionvouch" / "mcp_manifests"


def _server(result, name):
    return next(server for server in result.servers if server.name == name)


def test_readonly_server_scans_low_risk():
    result = scan_mcp_manifest(MANIFESTS / "readonly_filesystem_server.json")

    assert result.valid
    server = _server(result, "filesystem_readonly")
    assert server.risk_level == "low"
    assert server.tools_enumerated
    assert all(tool.read_only and not tool.write_capable for tool in server.tools)
    assert result.summary["destructive_tool_count"] == 0


def test_destructive_and_write_tools_are_flagged():
    result = scan_mcp_manifest(MANIFESTS / "write_destructive_crm_server.json")

    assert result.valid
    server = _server(result, "crm")
    assert server.risk_level == "critical"
    tools = {tool.name: tool for tool in server.tools}
    assert tools["delete_customer"].destructive
    assert tools["delete_customer"].risk_level == "critical"
    assert tools["update_customer"].write_capable
    assert tools["update_customer"].risk_level == "high"
    # send_invoice has no annotations; keyword heuristics still flag it.
    assert tools["send_invoice"].write_capable
    assert {"customer", "payment", "invoice"} & set(tools["send_invoice"].data_hints)


def test_remote_server_without_catalog_is_unknown_not_safe():
    result = scan_mcp_manifest(MANIFESTS / "remote_http_no_catalog.json")

    assert result.valid
    server = _server(result, "analytics_remote")
    assert server.tools_enumerated is False
    assert server.network_reaching is True
    assert server.risk_level == "unknown"  # must never read as "low"
    assert "tools_not_enumerated" in server.risk_flags
    assert "holds_credentials" in server.risk_flags
    assert server.referenced_env_keys == ["ANALYTICS_BEARER_TOKEN"]


def test_malformed_manifest_fails_closed():
    result = scan_mcp_manifest(MANIFESTS / "malformed_not_object.json")

    assert result.valid is False
    assert result.errors
    assert result.servers == []


def test_explicit_annotation_overrides_keyword_heuristic(tmp_path):
    # A read-only "search" tool with openWorldHint:false must not be flagged
    # open_world by the keyword fallback.
    manifest = tmp_path / "m.json"
    manifest.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "s": {
                        "command": "x",
                        "tools": [
                            {
                                "name": "search_docs",
                                "annotations": {
                                    "readOnlyHint": True,
                                    "openWorldHint": False,
                                },
                            }
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    tool = scan_mcp_manifest(manifest).servers[0].tools[0]
    assert tool.read_only
    assert not tool.open_world
    assert not tool.write_capable
    assert tool.risk_level == "low"


def test_readonly_hint_cannot_downgrade_destructive_keyword():
    # F2 (red team): a manifest that self-declares readOnlyHint:true on a tool
    # whose name screams destruction must NOT be downgraded to low/read_only.
    # The keyword evidence wins and the conflict is flagged - otherwise a hostile
    # third-party manifest gets free, false assurance.
    data = {
        "mcpServers": {
            "s": {
                "command": "x",
                "tools": [
                    {
                        "name": "delete_everything",
                        "description": "purge wipe destroy all data",
                        "annotations": {"readOnlyHint": True},
                    }
                ],
            }
        }
    }
    tool = scan_mcp_data(data, source="t").servers[0].tools[0]
    assert tool.destructive is True
    assert tool.read_only is False
    assert tool.risk_level == "critical"
    assert "readonly_hint_conflicts_evidence" in tool.risk_flags


def test_readonly_hint_honored_when_no_conflicting_evidence():
    # The conflict guard must not over-fire: a genuinely read-only tool keeps low.
    data = {
        "mcpServers": {
            "s": {
                "command": "x",
                "tools": [
                    {"name": "get_status", "annotations": {"readOnlyHint": True}}
                ],
            }
        }
    }
    tool = scan_mcp_data(data, source="t").servers[0].tools[0]
    assert tool.read_only is True
    assert tool.risk_level == "low"
    assert "readonly_hint_conflicts_evidence" not in tool.risk_flags


def test_markdown_report_neutralizes_injected_newlines():
    # F3 (red team): a manifest-controlled name with embedded newlines must not
    # inject Markdown structure (a fake heading) into the rendered report.
    data = {"mcpServers": {"legit\n## INJECTED HEADING\nmore": {"command": "x"}}}
    md = render_mcp_scan_markdown(scan_mcp_data(data, source="t"))
    assert not any(line.startswith("## INJECTED") for line in md.splitlines())


def test_oversized_manifest_fails_closed():
    # F7 (red team): an absurd server count is rejected, not scanned unbounded.
    data = {"mcpServers": {f"s{i}": {"command": "x"} for i in range(600)}}
    result = scan_mcp_data(data, source="t")
    assert result.valid is False
    assert any("too many servers" in e for e in result.errors)


def test_per_server_tool_list_is_capped():
    # F7 (red team): a pathological per-server tool list is truncated + flagged.
    tools = [{"name": f"t{i}"} for i in range(2100)]
    data = {"mcpServers": {"s": {"command": "x", "tools": tools}}}
    server = scan_mcp_data(data, source="t").servers[0]
    assert len(server.tools) == 2000
    assert "tool_list_truncated" in server.risk_flags


def test_scan_never_surfaces_env_secret_values_or_urls(tmp_path):
    # The scanner lists env KEY names but must never read or emit their values,
    # and must not surface the (potentially internal) server URL.
    manifest = tmp_path / "m.json"
    manifest.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "url": "https://secret-host.internal/mcp",
                        "env": {"DB_PASSWORD": "sup3r-s3cret-value"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = scan_mcp_manifest(manifest)
    blob = json.dumps(result.to_dict()) + render_mcp_scan_markdown(result)
    assert "sup3r-s3cret-value" not in blob
    assert "secret-host.internal" not in blob
    assert "DB_PASSWORD" in blob  # the key NAME is surfaced, the value is not


def test_markdown_report_includes_guardrails():
    md = render_mcp_scan_markdown(
        scan_mcp_manifest(MANIFESTS / "mixed_client_config.json")
    )

    lowered = md.lower()
    assert "no mcp server was started" in lowered
    assert "no network calls were performed" in lowered
    assert "## Servers" in md
