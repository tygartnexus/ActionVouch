# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab) rather than
opening a public issue or pull request.

Please include enough detail to reproduce: affected version/commit, environment,
steps, and impact. We will acknowledge reports on a best-effort basis and aim to
respond before any public disclosure.

## Design posture

ActionVouch is built to minimize attack surface by construction:

- **No network calls at runtime.** The audit pipeline runs entirely on the local
  machine; live connectors are fail-closed by design.
- **No telemetry and no credentials handled.** ActionVouch does not phone home
  and does not collect or transmit your data.
- **Standard library only at runtime.** No third-party runtime dependencies.
- The optional local app binds to `127.0.0.1` only.

## Scope and limitations

ActionVouch is an evidence and issue-spotting tool. It does **not** certify
compliance, guarantee protection from AI mistakes, replace legal/security/audit
professionals, or monitor live systems. Results depend on the records you
provide. The software is provided "AS IS", without warranty, under the
[Apache License 2.0](LICENSE); use it at your own risk.

## Supported versions

Fixes target the latest `main`. Older versions are supported on a best-effort
basis only.
