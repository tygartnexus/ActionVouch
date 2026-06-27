# ActionVouch

[![CI](https://github.com/tygartnexus/ActionVouch/actions/workflows/ci.yml/badge.svg)](https://github.com/tygartnexus/ActionVouch/actions/workflows/ci.yml) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Local-first AI agent **risk audit and approval console**. ActionVouch inventories the
AI agents and automations a business runs, records attempted actions, applies local
policy rules, surfaces evidence gaps, and generates an executive risk report - entirely
on the local machine, with **no live external actions** and **no network calls**.

This is a self-contained application with **no third-party runtime dependencies** -
it runs on the Python standard library alone. A small amount of helper logic (a
response-quality contract and path constants) is vendored directly under
`actionvouch/`.

## Install

```bash
python -m pip install -e ".[dev]"
```

The shipped runtime uses the Python standard library alone. Real-browser smoke
evidence is an **optional** extra (Playwright); it is never required to run an
audit:

```bash
python -m pip install -e ".[browser]"
python -m playwright install chromium   # one-time browser download
```

## CLI

```bash
# self-serve local app: a guided wizard (forms - no JSON needed) to build and
# run an audit yourself, bound to 127.0.0.1 only - no network, no credentials,
# data stays on your machine
actionvouch app                 # opens http://127.0.0.1:8765 in your browser

# validate / score / report
actionvouch validate examples/actionvouch/sample_project.json
actionvouch score    examples/actionvouch/sample_project.json
actionvouch report   examples/actionvouch/sample_project.json --format markdown

# generate local artifacts
actionvouch dashboard      examples/actionvouch/sample_project.json --output dashboard.html
actionvouch console        examples/actionvouch/sample_project.json --output console.html
actionvouch evidence-room  examples/actionvouch/sample_project.json --output evidence-room
actionvouch permission-graph examples/actionvouch/sample_project.json --output graph.json

# real-browser smoke evidence (DOM + interaction + zero-network) for the
# dashboard/console; needs the 'browser' extra, otherwise reports status=skipped
actionvouch browser-smoke  examples/actionvouch/sample_project.json --output-dir browser-smoke

# statically scan a local MCP manifest for tool-scope risk
# (never starts a server, calls tools/list, reads env values, or hits the network)
actionvouch mcp-scan examples/actionvouch/mcp_manifests/write_destructive_crm_server.json --format markdown

# re-verify an evidence room's manifest SHA-256 hashes
actionvouch verify-evidence-room evidence-room

# live connectors are intentionally blocked (fail-closed)
actionvouch live-import zapier
```

Without an editable install, run via the module: `python -m actionvouch <subcommand>`.

## Verify it runs correctly

A 15-stage end-to-end PASS/FAIL harness drives the real pipeline over the bundled
example projects (artifacts go to a temp dir by default, so a run never dirties the tree):

```bash
python verify_actionvouch.py            # human-readable; exit 0 = PASS, 1 = FAIL
python verify_actionvouch.py --json     # machine-readable (CI-gateable)
```

The 15 core stages need no third-party packages. Add `--include-browser` to
append two real-browser stages that render and drive the dashboard and console
in a headless Chromium (rendered DOM, the console's client-side validation and
quick-add, and a runtime check that the page makes zero external network
requests). Those stages **SKIP** rather than fail when the `browser` extra is
not installed, so a green run stays meaningful everywhere:

```bash
python verify_actionvouch.py --include-browser
```

## Tests

```bash
python -m pytest
```

The real-browser tests (`tests/test_actionvouch_browser_smoke.py`) auto-skip
when the optional `browser` extra is absent, so the suite stays green without
it. The fail-open contract itself is covered without a browser.

## Layout

```
actionvouch/              # application package
  app.py                  #   local-first self-serve web app (localhost-only server)
  app_ui.py               #   the guided-wizard single-page UI served by app.py
  browser_smoke.py        #   optional real-browser (Playwright) smoke runner
  mcp_scan.py             #   read-only MCP manifest / tool-scope scanner
  smoke.py                #   static, no-deps HTML source smoke checks
  paths.py                #   vendored path constants (PROJECT_ROOT, bundled docs)
  response_quality.py     #   vendored response-quality contract
tests/                    # pytest suite
examples/actionvouch/     # sample / incomplete / pilot projects, import templates,
                          #   mcp_manifests/ (MCP scan fixtures), and import fixtures
docs/actionvouch-release/claim-register.md  # bundled claim register (allowed/blocked claims)
verify_actionvouch.py     # verification-platform launcher
```

## Guardrails

ActionVouch is a local audit tool. It does **not** execute live external actions, make
network calls, provide legal advice, or certify compliance. Live connectors are blocked
by design.

ActionVouch is an evidence and issue-spotting tool: it surfaces visible risks and
evidence gaps for human review. It does **not** guarantee protection from AI mistakes,
replace legal, security, compliance, or audit professionals, or monitor live systems.

## License

ActionVouch is open source under the [Apache License 2.0](LICENSE). It is provided
"AS IS", without warranty of any kind; use it at your own risk.

## Contributing & security

- Contributions are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md).
- To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a
  public issue for security reports.
