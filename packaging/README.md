# Packaging ActionVouch as a desktop executable

This builds a **one-file executable** of the local-first self-serve app so a
non-developer can run ActionVouch without installing Python. Double-clicking it
launches the guided audit in the browser; data never leaves the machine.

Executables are **platform-specific**: build on (and for) each target OS. There
is no cross-compilation — build the Windows `.exe` on Windows, the macOS binary
on macOS, the Linux binary on Linux.

## Build

From the repository root:

```bash
python -m pip install -e ".[package]"
pyinstaller packaging/actionvouch.spec
```

The result is in `dist/`:

- Windows: `dist/ActionVouch.exe`
- macOS / Linux: `dist/ActionVouch`

## What the executable does

- **No arguments (double-click):** starts the local server on `127.0.0.1:8765`
  and opens the guided wizard in the default browser. A console window shows the
  URL; close it (or Ctrl+C) to stop.
- **With arguments:** behaves as the `actionvouch` CLI, e.g.
  `ActionVouch app --no-browser --port 9000`, `ActionVouch validate project.json`.

## What is bundled

- The ActionVouch package and the one data file the app reads
  (`examples/actionvouch/sample_project.json`, used by "Load example").
- The optional `browser` extra (Playwright) and the dev tools are **excluded** —
  the packaged app is standard-library only and makes no network calls.

## Verifying a build

```bash
# headless smoke: start the bundled app, hit it locally, stop it
./dist/ActionVouch app --no-browser --port 8799 &
sleep 2
curl -s http://127.0.0.1:8799/ | grep -q "ActionVouch" && echo "OK"
# then stop the background process
```

## Automated builds (GitHub Actions)

`.github/workflows/build.yml` builds the binary on Windows, macOS, and Linux and
uploads each as an artifact. It runs on `workflow_dispatch` (the Actions tab) and
on any `v*` tag. Each job also smoke-tests its binary (starts it headless and
checks it serves the app) before uploading.

### Code-signing secrets (optional)

Signing runs **only** when these repository secrets are set; without them the
binaries build unsigned.

- **Windows (Authenticode):** `WINDOWS_CERT_PFX_BASE64` (the `.pfx` base64-encoded)
  and `WINDOWS_CERT_PASSWORD`.
- **macOS (Developer ID + notarization):** `APPLE_CERT_P12_BASE64`,
  `APPLE_CERT_PASSWORD`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`. The
  macOS step is a documented placeholder for the keychain-import → `codesign` →
  `notarytool submit --wait` → `stapler staple` flow.

## Notes

- Unsigned binaries trip SmartScreen (Windows) and Gatekeeper (macOS); set the
  signing secrets above (and obtain the certs) before distributing to customers.
- The local development environment may carry an obsolete `typing` backport in
  user site-packages that PyInstaller rejects; build in a clean venv or CI (the
  GitHub runners are clean).
