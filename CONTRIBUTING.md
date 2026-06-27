# Contributing to ActionVouch

Thanks for your interest in ActionVouch. Contributions are welcome. This project
is maintained on a best-effort basis by a small team, so please be patient with
reviews.

## Project invariants (please preserve these)

ActionVouch is deliberately constrained. Pull requests that break any of these
will be asked to change:

- **Local-first and zero-network at runtime.** The audit pipeline must make no
  network calls. Live connectors are intentionally fail-closed.
- **Python standard library only at runtime.** The shipped tool has no runtime
  third-party dependencies. Optional extras (Playwright for browser smoke,
  PyInstaller for packaging) are test/build-time only.
- **Honest claims.** Documentation and output must not claim that ActionVouch
  certifies compliance, guarantees protection, replaces legal/security/audit
  professionals, or monitors live systems. It surfaces evidence and gaps for
  human review.

## Getting started

```bash
python -m pip install -e ".[dev]"
python -m pytest
python verify_actionvouch.py
```

The 15-stage `verify_actionvouch.py` harness drives the real pipeline end to end
and must stay green (`exit 0`). The optional real-browser stages SKIP—rather than
fail—when the `browser` extra is absent.

## Code style

- `black` for formatting, `ruff` for linting, `mypy` for type checking.
- Type-annotate function signatures.
- Prefer small, focused modules and explicit error handling.

```bash
black actionvouch tests
ruff check actionvouch tests
mypy actionvouch
```

## Tests

- Add or update tests for any behavior change. Cover valid, invalid, and
  adversarial/missing-evidence cases where relevant.
- Do not weaken existing tests to make a change pass.

## Developer Certificate of Origin (DCO)

By contributing, you certify that you wrote the code or otherwise have the right
to submit it under the project's license, per the
[Developer Certificate of Origin](https://developercertificate.org/). Sign off
each commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <your@email>` line to the commit.

## Reporting bugs and proposing changes

- Open a GitHub issue describing the problem or proposal.
- For security issues, **do not** open a public issue—see [SECURITY.md](SECURITY.md).
- For larger changes, open an issue to discuss the approach before sending a PR.
