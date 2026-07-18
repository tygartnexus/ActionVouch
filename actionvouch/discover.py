"""Machine-wide AI-agent discovery for ActionVouch.

One entry point - :func:`discover_machine` - scans the whole PC (all fixed drives
plus the known agent / MCP config locations) for AI-agent *wiring* and builds a
DRAFT inventory the operator can review. The operator does not need to know where
agents live or on which drive.

It REUSES :func:`actionvouch.reconcile.scan_codebase` over many roots, so
it inherits the same read-only, no-network, no-subprocess, symlink-safe,
heuristic signature detection (MCP server configs, agent-framework tool
registrations, connector credential keys). Stdlib only.

HEURISTIC, NOT EXHAUSTIVE, and DRAFT-ONLY. It finds capability *surface* (servers,
tools, connectors), not proven autonomous agents or ownership. The draft it
produces is clearly labelled, never auto-merged into the declared inventory, and
must be completed/confirmed by a human (owner, purpose, permissions are unknown
until reviewed). A clean scan is a tripwire that did not trip, not proof the
machine is agent-free.
"""

from __future__ import annotations

import os
import string
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from .models import (
    ACTION_CLASSES,
    DISCOVERED_AGENT_STATUS,
    DISCOVERED_DRAFT_PROJECT_ID,
    DISCOVERED_TOOL_PERMISSION_TYPE,
    AgentRecord,
    AuditProject,
    EvidenceItem,
    ToolRecord,
    infer_autonomy_level,
)
from .reconcile import (
    _IGNORED_DIRS,
    _SOURCE_SUFFIXES,
    ObservedItem,
    ObservedSurface,
    _dedupe_items,
    _slug,
    combine_surfaces,
    scan_codebase,
)
from .store import save_project

# JSON files worth reading for MCP config. Reading EVERY .json on a machine
# (package.json, tsconfig, lockfiles, data dumps) is the main thing that made a
# whole-machine scan time out; agent/MCP config lives in a few conventional names.
_MCP_JSON_NAMES = frozenset(
    {
        "claude_desktop_config.json",
        "settings.json",
        "mcp.json",
        ".mcp.json",
        "mcp_config.json",
        "cline_mcp_settings.json",
        "servers.json",
    }
)

# OS / system directories never worth crawling for agent wiring; skipping them
# keeps the file budget for real project locations. (AppData is intentionally NOT
# here - that is where Claude Desktop / editor MCP configs live.)
_SYSTEM_DIRS = frozenset(
    {
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "$Recycle.Bin",
        "System Volume Information",
        "Recovery",
        "$WinREAgent",
        "PerfLogs",
        "MSOCache",
        "Config.Msi",
        "$SysReset",
        "OneDriveTemp",
        "Windows.old",
    }
)
# Transient session / agent-mode / cache directories. These hold per-run COPIES
# of plugin + MCP wiring (or pure runtime cache) rather than a standing agent the
# operator manages, so reporting them inflates the surface with throwaway
# snapshots. On a real machine 'local-agent-mode-sessions' alone accounted for 68
# of 77 discovered surfaces. This is DISCOVERY-only: reconcile's declared-audit
# scan keeps the reconcile._IGNORED_DIRS default and is unaffected. Matched by
# exact directory name (as _walk_files does), which also skips their children
# (e.g. the offending .../local-agent-mode-sessions/<uuid>/rpm/plugin_* configs).
_EPHEMERAL_DIRS = frozenset(
    {
        "local-agent-mode-sessions",
        "claude-code-sessions",
        "Cache",
        "Code Cache",
        "GPUCache",
        "DawnGraphiteCache",
        "DawnWebGPUCache",
        "blob_storage",
        "Crashpad",
        "sentry",
    }
)
_DISCOVERY_IGNORED = _IGNORED_DIRS | _SYSTEM_DIRS | _EPHEMERAL_DIRS

# Status marker for an agent surface that was machine-discovered and still needs a
# human to confirm owner, purpose, and permissions before it is an audited entry.
# Canonical value lives in models so the risk scorer can recognise discovered records.
_DISCOVERED_STATUS = DISCOVERED_AGENT_STATUS

# Global safety budgets. Machine-wide scanning multiplies cost, so cap total
# files, wall-clock time, and per-root files; stop gracefully and record a
# warning rather than ever hanging.
# Budgets are now generous SAFETY nets, not the primary limiter: the read filter
# keeps the scan cheap enough to run to completion, so by default there is NO
# time cap (None) - the scan finishes and finds everything it can.
MAX_TOTAL_FILES = 400_000
MAX_FILES_PER_ROOT = 200_000
MAX_SECONDS: float | None = None

# Subdirectories of the user profile that commonly hold code/agents - scanned
# even when a full-drive crawl would be budget-limited.
_DEV_SUBDIRS = (
    "projects",
    "code",
    "src",
    "dev",
    "repos",
    "work",
    "Documents",
    "Desktop",
)

_DRIVE_TYPE_LABELS = {
    2: "removable",
    3: "fixed",
    4: "network",
    5: "cdrom",
    6: "ramdisk",
}


@dataclass(frozen=True)
class ScanRoot:
    """A directory chosen to be scanned, with why it was selected."""

    path: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True)
class DiscoveryResult:
    roots: tuple[ScanRoot, ...]
    observed: ObservedSurface
    draft_project: AuditProject
    draft_project_path: str
    draft_valid: bool
    validation_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": "ActionVouch",
            "report_version": "actionvouch.discovery.v1",
            "roots": [root.to_dict() for root in self.roots],
            "draft_project_path": self.draft_project_path,
            "draft_valid": self.draft_valid,
            "validation_error_count": len(self.validation_errors),
            "stats": self.stats,
            "warnings": list(self.warnings),
            "guardrails": [
                "Discovery is HEURISTIC and DRAFT-ONLY; it finds capability surface, "
                "not proven agents or ownership.",
                "Owner, purpose, and permissions are unknown until a human reviews "
                "the draft; the draft is never auto-merged into the real inventory.",
                "A clean scan is not proof the machine is agent-free - coverage is "
                "bounded by budgets and the heuristic signatures.",
            ],
        }


# --------------------------------------------------------------------------- #
# Root selection
# --------------------------------------------------------------------------- #
def _existing_drive_letters() -> list[str]:
    return [c for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]


def _drive_type(letter: str) -> str:
    if os.name != "nt":
        return "fixed"
    try:
        import ctypes

        code = ctypes.windll.kernel32.GetDriveTypeW(  # type: ignore[attr-defined]
            ctypes.c_wchar_p(f"{letter}:\\")
        )
    except Exception:  # noqa: BLE001 - degrade gracefully if the API is unavailable
        return "unknown"
    return _DRIVE_TYPE_LABELS.get(code, "unknown")


def _drive_roots(
    *,
    include_removable: bool,
    include_network: bool,
    drive_lister: Callable[[], list[str]] | None,
    drive_typer: Callable[[str], str] | None,
) -> list[ScanRoot]:
    if os.name != "nt" and drive_lister is None:
        return []
    letters = (drive_lister or _existing_drive_letters)()
    typer = drive_typer or _drive_type
    roots: list[ScanRoot] = []
    for letter in letters:
        kind = typer(letter)
        allowed = (
            kind in {"fixed", "unknown"}
            or (kind == "removable" and include_removable)
            or (kind == "network" and include_network)
        )
        if allowed:
            roots.append(ScanRoot(f"{letter}:\\", f"{kind}_drive"))
    return roots


def _drive_dev_roots(
    drive_lister: Callable[[], list[str]] | None,
    drive_typer: Callable[[str], str] | None,
) -> list[ScanRoot]:
    """Each fixed drive's common dev/project folders (e.g. D:\\projects).

    This catches project-level agent configs on ANY drive cheaply - small,
    focused folders - without the cost (and near-zero yield) of crawling the
    whole drive. Agents are registered in config files, which live here or in the
    editor/app config dirs, not scattered across the drive.
    """

    letters = (drive_lister or _existing_drive_letters)()
    typer = drive_typer or _drive_type
    roots: list[ScanRoot] = []
    for letter in letters:
        if typer(letter) not in {"fixed", "unknown"}:
            continue
        for sub in _DEV_SUBDIRS:
            path = Path(f"{letter}:\\") / sub
            if path.exists():
                roots.append(ScanRoot(str(path), f"drive_dev:{letter}:{sub}"))
    return roots


def _known_config_roots(home: Path, environ: Mapping[str, str]) -> list[ScanRoot]:
    appdata = environ.get("APPDATA", "")
    candidates: list[tuple[Path, str]] = []
    if appdata:
        candidates += [
            (Path(appdata) / "Claude", "known_config:claude_desktop"),
            (Path(appdata) / "Code" / "User", "known_config:vscode"),
            (Path(appdata) / "Cursor" / "User", "known_config:cursor"),
            (Path(appdata) / "Windsurf", "known_config:windsurf"),
        ]
    candidates += [
        (home / ".cursor", "known_config:cursor_home"),
        (home / ".codeium", "known_config:windsurf_codeium"),
        (home / ".config", "known_config:xdg_config"),
    ]
    candidates += [(home / sub, f"dev_dir:{sub}") for sub in _DEV_SUBDIRS]
    return [ScanRoot(str(p), reason) for p, reason in candidates if p.exists()]


def candidate_roots(
    *,
    include_drives: bool = False,
    include_removable: bool = False,
    include_network: bool = False,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    drive_lister: Callable[[], list[str]] | None = None,
    drive_typer: Callable[[str], str] | None = None,
) -> list[ScanRoot]:
    """Collect the roots to scan.

    By default: known agent-config locations + dev dirs only - fast and high-yield
    (these hold editor/Claude-registered MCP agents). ``include_drives`` adds a
    full crawl of every fixed drive (slow, thorough); removable/network drives are
    a further opt-in. ``home``/``environ``/drive helpers are injectable for tests.
    """

    home = home or Path.home()
    environ = environ if environ is not None else os.environ
    # High-signal config / dev locations FIRST: editor/app config dirs, home dev
    # dirs, and every fixed drive's dev/project folders. This finds agents fast
    # and completely without crawling whole drives.
    roots = _known_config_roots(home, environ)
    roots += _drive_dev_roots(drive_lister, drive_typer)
    if include_drives:
        roots += _drive_roots(
            include_removable=include_removable,
            include_network=include_network,
            drive_lister=drive_lister,
            drive_typer=drive_typer,
        )
    seen: set[str] = set()
    deduped: list[ScanRoot] = []
    for root in roots:
        key = os.path.normcase(os.path.normpath(root.path))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(root)
    return deduped


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _discovery_name_filter(scan_source: bool) -> Callable[[str], bool]:
    """Decide which files are worth touching, from the bare filename. Applied at
    the DirEntry level so the millions of non-candidate files on a drive cost
    almost nothing. Only MCP/editor JSON configs, .env files, and (optionally)
    source files pass.
    """

    def keep(name: str) -> bool:
        lowered = name.lower()
        if lowered == ".env" or lowered.startswith(".env.") or lowered.endswith(".env"):
            return True
        if lowered.endswith(".json"):
            return "mcp" in lowered or lowered in _MCP_JSON_NAMES
        return scan_source and any(lowered.endswith(s) for s in _SOURCE_SUFFIXES)

    return keep


def discover_machine(
    *,
    roots: list[ScanRoot] | None = None,
    save_path: str | Path | None = None,
    deep: bool = False,
    scan_source: bool = False,
    max_total_files: int = MAX_TOTAL_FILES,
    max_seconds: float | None = MAX_SECONDS,
    max_files_per_root: int = MAX_FILES_PER_ROOT,
    include_removable: bool = False,
    include_network: bool = False,
    clock: Callable[[], float] = time.monotonic,
    timestamp: str = "",
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> DiscoveryResult:
    """Scan the machine, build a draft inventory, and (optionally) save it.

    By default reads ONLY MCP/editor config files and ``.env`` (the whole tree is
    still walked, cheaply) - so even a ``deep=True`` whole-drive scan runs to
    completion fast (``max_seconds=None``) instead of timing out. ``deep`` also
    crawls every fixed drive. ``scan_source=True`` additionally reads source files
    to catch code-defined agents - high cost and near-zero yield across full
    drives, so it belongs on a TARGETED repo (use the reconciler), not a machine
    crawl; it is opt-in.
    """

    if roots is None:
        roots = candidate_roots(
            include_drives=deep,
            include_removable=include_removable,
            include_network=include_network,
            home=home,
            environ=environ,
        )
    start = clock()
    name_filter = _discovery_name_filter(scan_source)
    # Absolute wall-clock deadline (real monotonic) passed into scan_codebase so a
    # single huge root cannot blow a (caller-provided) budget. None = no limit.
    real_deadline = None if max_seconds is None else time.monotonic() + max_seconds
    surfaces: list[ObservedSurface] = []
    warnings: list[str] = []
    files_scanned = 0
    roots_scanned = 0

    for root in roots:
        if max_seconds is not None and clock() - start > max_seconds:
            warnings.append(
                f"time budget {max_seconds}s reached; remaining roots skipped"
            )
            break
        if files_scanned >= max_total_files:
            warnings.append(
                f"file budget {max_total_files} reached; remaining roots skipped"
            )
            break
        remaining = min(max_files_per_root, max_total_files - files_scanned)
        try:
            surface = scan_codebase(
                root.path,
                max_files=remaining,
                ignored_dirs=_DISCOVERY_IGNORED,
                deadline=real_deadline,
                name_filter=name_filter,
            )
        except OSError as exc:
            warnings.append(f"could not scan {root.path}: {exc}")
            continue
        roots_scanned += 1
        files_scanned += len(surface.scanned_files)
        warnings.extend(f"{root.path}: {w}" for w in surface.warnings)
        # Qualify each source_ref with its root so locations are absolute.
        qualified = tuple(
            replace(item, source_ref=str(Path(root.path) / item.source_ref))
            for item in surface.items
        )
        surfaces.append(ObservedSurface(items=qualified))
        if progress is not None:
            progress(
                {
                    "roots_done": roots_scanned,
                    "roots_total": len(roots),
                    "files_scanned": files_scanned,
                    "items_so_far": sum(len(s.items) for s in surfaces),
                    "current_root": root.path,
                }
            )

    # combine_surfaces already collapses by (kind, name); this second pass
    # additionally collapses the SAME MCP server registered under multiple
    # roots/aliases (same normalized command/args/url) so discovered_tools counts
    # DISTINCT servers, not one row per config it happens to appear in.
    combined = _dedupe_cross_config(combine_surfaces(*surfaces))
    project = build_draft_project(combined, timestamp=timestamp)
    validation_errors = tuple(project.validate())
    draft_path = ""
    if save_path is not None:
        draft_path = str(save_project(project, save_path))

    kinds: dict[str, int] = {}
    for item in combined.items:
        kinds[item.kind] = kinds.get(item.kind, 0) + 1
    # Complete coverage = every chosen root finished and no budget/time cap fired.
    truncated = any(
        ("budget" in w or "cap reached" in w or "time budget" in w) for w in warnings
    )
    stats = {
        "roots_considered": len(roots),
        "roots_scanned": roots_scanned,
        "files_scanned": files_scanned,
        "seconds": round(clock() - start, 2),
        "surface_by_kind": kinds,
        "discovered_agents": len(project.agents),
        "discovered_tools": len(project.tools),
        "coverage_complete": roots_scanned == len(roots) and not truncated,
    }
    return DiscoveryResult(
        roots=tuple(roots),
        observed=combined,
        draft_project=project,
        draft_project_path=draft_path,
        draft_valid=not validation_errors,
        validation_errors=validation_errors,
        warnings=tuple(warnings),
        stats=stats,
    )


# --------------------------------------------------------------------------- #
# Cross-config dedup
# --------------------------------------------------------------------------- #
def _discovery_dedup_key(item: ObservedItem) -> tuple[str, str]:
    """Dedup key that collapses cross-config MCP-server aliases.

    An mcp_server with a captured command/args/url identity is keyed by that
    identity, so two configs that launch the same server (under different keys)
    count once. Everything else - including an empty-spec server with no identity
    - keys by ``(kind, name)``, matching the base dedup, so distinct servers are
    never over-collapsed.
    """

    if item.kind == "mcp_server" and item.identity:
        return ("mcp_server", item.identity)
    return (item.kind, item.name)


def _dedupe_cross_config(surface: ObservedSurface) -> ObservedSurface:
    deduped = _dedupe_items(list(surface.items), key=_discovery_dedup_key)
    if len(deduped) == len(surface.items):
        return surface
    return replace(surface, items=deduped)


# --------------------------------------------------------------------------- #
# Draft inventory builder
# --------------------------------------------------------------------------- #
def build_draft_project(
    observed: ObservedSurface, *, timestamp: str = ""
) -> AuditProject:
    """Turn observed surface into a VALID-but-unverified draft AuditProject.

    Records are grouped by the directory that holds the wiring (one agent per
    location). Unknown facts (owner, purpose, permissions) are set to explicit
    "unknown" - which validates and which the risk scorer then flags - rather
    than invented, so the draft is honest about what still needs human review.
    """

    groups: dict[str, list[ObservedItem]] = {}
    for item in observed.items:
        groups.setdefault(_location_key(item.source_ref), []).append(item)

    evidence_id = "ev_discovery_unverified"
    tools: list[ToolRecord] = []
    agents: list[AgentRecord] = []
    used_tool_ids: set[str] = set()
    for index, (location, items) in enumerate(sorted(groups.items()), start=1):
        tool_ids: list[str] = []
        agent_actions: set[str] = set()
        for item in items:
            tool = _tool_from_item(item, location, evidence_id, taken=used_tool_ids)
            tools.append(tool)
            used_tool_ids.add(tool.tool_id)
            tool_ids.append(tool.tool_id)
            agent_actions.update(tool.actions_supported)
        actions = sorted(agent_actions & ACTION_CLASSES) or ["observe"]
        agents.append(
            AgentRecord(
                agent_id=f"discovered_agent_{index}",
                name=f"Discovered agent surface: {location}",
                owner="unknown",
                business_purpose=_draft_business_purpose(items, location),
                provider="unknown",
                model_or_runtime="unknown",
                tools=tool_ids or ["unknown"],
                data_classes=["unknown"],
                action_classes=actions,
                # Real autonomy is unknown; infer a valid (conservative) level.
                # The "unknowns" entries below flag it for human review.
                autonomy_level=infer_autonomy_level(actions),
                risk_level="unknown",
                approval_policy_id="",
                status=_DISCOVERED_STATUS,
                evidence=[evidence_id],
                unknowns=[
                    "Machine-discovered wiring; owner, purpose, permissions, and real "
                    "autonomy are unverified.",
                    f"Found at: {location}",
                ],
            )
        )

    evidence = [
        EvidenceItem(
            evidence_id=evidence_id,
            source_type="missing_evidence",
            summary="Auto-discovered surface has no verified ownership or permissions.",
            limitation="Discovery observes wiring only; a human must confirm the facts.",
        )
    ]
    return AuditProject(
        project_id=DISCOVERED_DRAFT_PROJECT_ID,
        name="ActionVouch Discovered Inventory (DRAFT)",
        version="actionvouch.audit_project.v1",
        created_at=timestamp,
        updated_at=timestamp,
        scope=(
            "DRAFT inventory auto-discovered from a local machine scan. Heuristic and "
            "unverified - review and complete before treating as an audit."
        ),
        agents=agents,
        tools=tools,
        policies=[],
        action_events=[],
        evidence=evidence,
        assumptions=[
            "Records were machine-discovered from on-disk agent/tool wiring, not "
            "owner-declared.",
            "Discovery is heuristic and may miss agents or surface non-agent code.",
        ],
        unknowns=[
            "Owner, business purpose, permissions, and true autonomy of every "
            "discovered surface are unverified.",
        ],
    )


_KIND_LABEL = {"mcp_server": "MCP server", "tool": "tool", "connector": "connector"}


def _draft_business_purpose(items: list[ObservedItem], location: str) -> str:
    """Honest, surface-derived purpose string for a discovered agent.

    Describes what was actually observed (kinds, names, implied actions) so the
    reviewer has context, without inventing an owner or a real business intent -
    both stay UNCONFIRMED until a human fills them in.
    """

    kinds: dict[str, list[str]] = {}
    actions: set[str] = set()
    for item in items:
        kinds.setdefault(item.kind, []).append(item.name)
        actions.update(item.implied_actions)

    parts: list[str] = []
    for kind, names in sorted(kinds.items()):
        uniq = sorted(set(names))
        shown = ", ".join(uniq[:6]) + (" …" if len(uniq) > 6 else "")
        noun = _KIND_LABEL.get(kind, kind)
        parts.append(f"{noun}{'s' if len(uniq) != 1 else ''} {shown}")

    risky = sorted(actions & ACTION_CLASSES)
    action_str = ", ".join(risky) if risky else "no high-risk actions detected"
    return (
        "UNCONFIRMED purpose. Machine-discovered wiring exposes "
        + "; ".join(parts)
        + f" — implied actions: {action_str}. A human must confirm the owner, the "
        "real business purpose, and whether this is a live agent before this row "
        "is trusted as an audited inventory entry."
    )


def render_review_worksheet(project: AuditProject) -> str:
    """A human review checklist (Markdown) for a discovered draft inventory.

    Lists every discovered agent surface with its observed tools and implied
    actions, then blank fields for the reviewer to assign owner, purpose,
    permissions, and a keep/decommission decision. It NEVER fills in an owner or
    purpose - those are the reviewer's to supply.
    """

    tools_by_id = {tool.tool_id: tool for tool in project.tools}
    discovered = [a for a in project.agents if a.status == _DISCOVERED_STATUS]
    created = project.created_at or "(undated)"

    lines: list[str] = [
        "# ActionVouch — Discovered Inventory Review Worksheet",
        "",
        f"> DRAFT auto-discovered from a local machine scan ({created}). Heuristic: it "
        "finds capability **surface**, not proven agents or ownership. Complete every "
        "row below before treating this as an audited inventory.",
        "",
        f"**{len(discovered)} agent surface(s) need review.**",
        "",
    ]

    if not discovered:
        lines.append(
            "_No machine-discovered agents in this project — nothing to review._"
        )
        return "\n".join(lines) + "\n"

    for index, agent in enumerate(discovered, start=1):
        location = next(
            (
                u.split("Found at: ", 1)[1]
                for u in agent.unknowns
                if u.startswith("Found at: ")
            ),
            "(unknown location)",
        )
        lines += [
            f"## {index}. {agent.name}",
            "",
            f"- **Location:** {location}",
            f"- **Inferred autonomy (UNCONFIRMED):** {agent.autonomy_level}",
            "- **Observed tools / implied actions:**",
        ]
        agent_tools = [tools_by_id[t] for t in agent.tools if t in tools_by_id]
        if agent_tools:
            for tool in agent_tools:
                acts = ", ".join(tool.actions_supported) or "—"
                lines.append(f"    - `{tool.name}` ({tool.tool_id}) → {acts}")
        else:
            lines.append("    - _(none resolved)_")
        lines += [
            "",
            "Fill in (every box must be checked before sign-off):",
            "",
            "- [ ] **Owner** (a real person or team): ______________________",
            "- [ ] **Business purpose** (what it is actually for): ______________________",
            "- [ ] **Is this a real, live agent?** (yes / no / dormant): ______________________",
            "- [ ] **Data it can access** (replace `unknown`): ______________________",
            "- [ ] **Permissions / approval policy**: ______________________",
            "- [ ] **Confirmed autonomy level** (observe / suggest / act_with_confirmation / act): ____________",
            "- [ ] **Decision**: keep · decommission · out-of-scope: ______________________",
            "",
        ]

    lines += [
        "---",
        "",
        "When every box is checked, update the draft inventory JSON to match and "
        "re-run the audit. Until then ActionVouch treats these as unverified.",
    ]
    return "\n".join(lines) + "\n"


def _location_key(source_ref: str) -> str:
    parent = os.path.dirname(source_ref)
    return parent or source_ref or "unknown_location"


def _tool_from_item(
    item: ObservedItem, location: str, evidence_id: str, *, taken: set[str]
) -> ToolRecord:
    tool_id = _slug(f"{item.kind}_{item.name}")
    while tool_id in taken:
        tool_id = f"{tool_id}_x"
    actions = sorted(set(item.implied_actions) & ACTION_CLASSES)
    connector_type = "mcp" if item.kind == "mcp_server" else "unknown"
    external = item.kind in {"mcp_server", "connector"} or bool(actions)
    if not actions:
        actions = ["external_api_call"] if external else ["observe"]
    return ToolRecord(
        tool_id=tool_id,
        name=item.name,
        system=location,
        permission_type=DISCOVERED_TOOL_PERMISSION_TYPE,
        data_access=["unknown"],
        actions_supported=actions,
        external_effect=external,
        credential_owner="unknown",
        risk_level="unknown",
        notes=f"Discovered ({item.kind}) at {item.source_ref}. {item.detail}".strip(),
        connector_type=connector_type,
        mcp_server_id=item.name if item.kind == "mcp_server" else "",
        evidence=[evidence_id],
        unknowns=["Machine-discovered; permission scope and ownership unverified."],
    )
