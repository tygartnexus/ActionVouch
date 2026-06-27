"""Tests for the packaged-launcher entry point and packaging robustness."""

from __future__ import annotations

import argparse
import sys
from types import SimpleNamespace

import pytest

import actionvouch.app as app_module
import actionvouch.launcher as launcher
from actionvouch import paths
from actionvouch.cli import command_actionvouch, _port_arg


def test_launcher_no_args_opens_app(monkeypatch):
    calls = {"serve": 0, "cli": 0}
    monkeypatch.setattr(
        launcher,
        "serve_app",
        lambda **kwargs: calls.__setitem__("serve", calls["serve"] + 1),
    )
    monkeypatch.setattr(
        launcher, "cli_main", lambda *a, **k: calls.__setitem__("cli", calls["cli"] + 1)
    )

    launcher.main([])

    assert calls == {"serve": 1, "cli": 0}


def test_launcher_args_delegate_to_cli(monkeypatch):
    received = {}
    monkeypatch.setattr(
        launcher, "serve_app", lambda **k: received.setdefault("serve", True)
    )
    monkeypatch.setattr(
        launcher, "cli_main", lambda args: received.setdefault("cli_args", args)
    )

    launcher.main(["validate", "x.json"])

    assert received == {"cli_args": ["validate", "x.json"]}


def test_example_endpoint_falls_back_when_sample_missing(monkeypatch, tmp_path):
    # A packaged build with a missing data file must not 500 the example endpoint.
    monkeypatch.setattr(app_module, "_SAMPLE_PROJECT", tmp_path / "missing.json")

    project = app_module._example_project()

    assert project["project_id"] == "av_example"
    assert project["agents"] == []


def test_port_arg_validates_range():
    # F12 (red team): --port is bounded, with a friendly error instead of a raw
    # OSError traceback on an out-of-range or non-numeric value.
    assert _port_arg("8080") == 8080
    for bad in ("99999", "-1", "notaport"):
        with pytest.raises(argparse.ArgumentTypeError):
            _port_arg(bad)


def test_project_root_uses_meipass_when_frozen(monkeypatch, tmp_path):
    # F12 (red team): when PyInstaller-frozen, PROJECT_ROOT resolves to _MEIPASS
    # explicitly, not by parents[1] landing there coincidentally.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert paths._project_root() == tmp_path


SAMPLE = paths.PROJECT_ROOT / "examples" / "actionvouch" / "sample_project.json"


def test_cli_runs_all_subcommands_ungated(tmp_path):
    # There is no edition gate: every subcommand runs unlocked (no paywall). A
    # previously "Pro" output (dashboard) and a core one (validate) both run.
    validated = command_actionvouch(
        SimpleNamespace(
            actionvouch_action="validate",
            project_path=str(SAMPLE),
            response_mode="",
        )
    )
    assert validated["valid"] is True
    assert "locked" not in validated

    dashboarded = command_actionvouch(
        SimpleNamespace(
            actionvouch_action="dashboard",
            project_path=str(SAMPLE),
            response_mode="",
            output=str(tmp_path / "dashboard.html"),
        )
    )
    assert dashboarded["valid"] is True
    assert dashboarded["status"] == "dashboard_written"
    assert "locked" not in dashboarded
