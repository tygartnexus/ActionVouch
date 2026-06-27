"""Evidence-room export for ActionVouch controlled pilots."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .paths import DOCS_DIR
from .compliance import build_compliance_readiness_report, render_compliance_markdown
from .console import render_editable_console_html
from .dashboard import render_dashboard_html
from .models import AuditProject
from .permissions import build_permission_graph
from .report import _md, render_json_report, render_markdown_report

DEFAULT_RELEASE_PACKET_DIR = DOCS_DIR / "actionvouch-release"
REQUIRED_RELEASE_PACKET_FILES = {
    "claim-register.md": "claim-register.md",
}


def build_evidence_room(
    project: AuditProject,
    output_dir: str | Path,
    *,
    release_packet_dir: str | Path | None = None,
) -> dict[str, Any]:
    target = Path(output_dir)
    packet_dir = _resolve_release_packet_dir(release_packet_dir)
    _validate_release_packet(packet_dir)
    target.mkdir(parents=True, exist_ok=True)
    files: list[dict[str, Any]] = []

    _write(
        target / "project.json",
        json.dumps(project.to_dict(), indent=2, sort_keys=True) + "\n",
        files,
    )
    _write(target / "risk-report.md", render_markdown_report(project), files)
    _write(target / "risk-report.json", render_json_report(project), files)
    _write(target / "permission-graph.json", _permission_graph_json(project), files)
    _write(target / "customer-executive-summary.md", _executive_summary(project), files)
    _write(target / "dashboard.html", render_dashboard_html(project), files)
    _write(target / "console.html", render_editable_console_html(project), files)

    compliance = build_compliance_readiness_report(project, packet_dir=packet_dir)
    _write(
        target / "compliance-readiness.md",
        render_compliance_markdown(compliance),
        files,
    )
    _write(
        target / "compliance-readiness.json",
        json.dumps(compliance, indent=2, sort_keys=True) + "\n",
        files,
    )
    for source_name, target_name in REQUIRED_RELEASE_PACKET_FILES.items():
        _copy_required(packet_dir / source_name, target / target_name, files)
    _write(target / "README.md", _readme(project), files)

    manifest: dict[str, Any] = {
        "manifest_version": "actionvouch.evidence_room.v1",
        "project_id": project.project_id,
        "product": "ActionVouch",
        "status": "local_evidence_room",
        "certification_status": "not_certified",
        "attestation_status": "not_attested",
        "guardrails": [
            "This evidence room is local review evidence, not public deployment proof.",
            "This evidence room is not legal advice or compliance certification.",
            "No live external action is authorized by this export.",
        ],
        "files": files,
    }
    manifest_path = target / "manifest.json"
    files.append(
        {
            "path": str(manifest_path),
            "size_bytes": None,
            "sha256": None,
            "hash_status": "self_hash_excluded",
            "note": "manifest.json is listed without a content hash because a manifest cannot include a stable hash of itself.",
        }
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def verify_evidence_room(directory: str | Path) -> dict[str, Any]:
    """Recompute and compare the manifest's per-file SHA-256 hashes.

    Makes the manifest hashes meaningful: a consumer can detect tampering or a
    truncated package before trusting the evidence room. Files are matched by
    name within ``directory`` (so a moved room still verifies), and the
    manifest's own ``self_hash_excluded`` entry is skipped.
    """

    target = Path(directory)
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    mismatched: list[str] = []
    missing: list[str] = []
    checked = 0
    for entry in manifest.get("files", []):
        recorded = entry.get("sha256")
        if not recorded:
            continue  # manifest self-entry (self_hash_excluded)
        checked += 1
        path = target / Path(entry["path"]).name
        if not path.exists():
            missing.append(path.name)
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != recorded:
            mismatched.append(path.name)
    return {
        "directory": str(target),
        "intact": not mismatched and not missing,
        "checked": checked,
        "mismatched": mismatched,
        "missing": missing,
    }


def _resolve_release_packet_dir(release_packet_dir: str | Path | None) -> Path:
    if not release_packet_dir:
        return DEFAULT_RELEASE_PACKET_DIR
    packet_dir = Path(release_packet_dir)
    if packet_dir.is_absolute():
        return packet_dir
    if packet_dir.as_posix() == "docs/actionvouch-release":
        return DEFAULT_RELEASE_PACKET_DIR
    return packet_dir


def _validate_release_packet(packet_dir: Path) -> None:
    missing = [
        str(packet_dir / name)
        for name in REQUIRED_RELEASE_PACKET_FILES
        if not (packet_dir / name).exists()
    ]
    if missing:
        raise FileNotFoundError(
            "Required ActionVouch release packet file(s) missing: " + ", ".join(missing)
        )


def _write(path: Path, content: str, files: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    files.append(_file_entry(path))


def _copy_required(source: Path, target: Path, files: list[dict[str, Any]]) -> None:
    _write(target, source.read_text(encoding="utf-8"), files)


def _file_entry(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "path": str(path),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _readme(project: AuditProject) -> str:
    project_id = _md(project.project_id)
    return f"""# ActionVouch Evidence Room

Project: `{project_id}`

This folder is a local evidence package for controlled-pilot review. It is not
public deployment proof, legal advice, compliance certification, or third-party
attestation.

## Contents

- `project.json`
- `risk-report.md`
- `risk-report.json`
- `permission-graph.json`
- `customer-executive-summary.md`
- `dashboard.html`
- `console.html`
- `compliance-readiness.md`
- `compliance-readiness.json`
- `claim-register.md`
- `release-packet-index.md`
- `manifest.json`

## Guardrails

- Certification status is `not_certified`.
- Attestation status is `not_attested`.
- No live external action is authorized by this evidence room.
"""


def _permission_graph_json(project: AuditProject) -> str:
    return json.dumps(build_permission_graph(project), indent=2, sort_keys=True) + "\n"


def _executive_summary(project: AuditProject) -> str:
    project_id = _md(project.project_id)
    return f"""# ActionVouch Customer Executive Summary

Project: `{project_id}`

This summary is a customer-safe index for the local evidence room. It does not
certify compliance, provide legal advice, guarantee protection, or authorize
live external action.

## Included Artifacts

- Risk report.
- Permission graph.
- Dashboard.
- Editable local console.
- Compliance-readiness report.
- Claim register.
- Evidence manifest.

## Required Review

- Verify owners, tool scopes, and approval policies before delivery.
- Treat missing evidence as missing evidence.
- Keep live connectors blocked until a separate read-only connector gate is
  implemented, tested, and approved.
"""
