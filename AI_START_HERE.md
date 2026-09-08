# AI start here

## Objective

Continue the recovered Supertonic + VoxCPM2 Windows application without reverse-engineering the 7 GB payload again. This repository contains readable source, two deliberate Git commits, tests, release scripts, security analysis and a `project.bundle`.

## First actions

1. Read `CURRENT_STATE_INVENTORY.md`, `ARCHITECTURE.md`, `SECURITY_AUDIT.md` and `KNOWN_LIMITATIONS.md`.
2. Run `git log --oneline --decorate --all` and inspect the difference between `recovered-baseline` and `hardened-candidate`.
3. Use a fully patched Windows 11 x64 host with .NET SDK 10.0.302 or later.
4. Run `powershell -ExecutionPolicy Bypass -File .\build.ps1`, then `test.ps1`.
5. Read the payload support `README_먼저읽기.txt` before extraction and the extracted `PRIVATE_USER_STATE_NOTICE.txt` before handling user state. Do not upload `PRIVATE_USER_STATE` to an external AI or public service.
6. Use `WINDOWS_RELEASE_CHECKLIST.md` as the production build, signing and release gate.

## Layout

- `src/DesktopApp`: recovered C# WinForms source.
- `src/VoxCPM2Sidecar`: VoxCPM2 FastAPI sidecar source, lock and tests.
- `src/SupertonicSidecar`: authenticated wrapper around the bundled Supertonic server.
- `tests/DesktopApp.SecurityTests`: dependency-free executable security checks.
- `baseline`: recovery evidence; the original executable itself is in the offline payload `baseline-overlay`.
- `licenses`: required upstream license texts.
- `reports`: machine-readable and human-readable scan outputs.
- `artifacts`: local build output; ignored by Git.

## Security invariants

- Sidecars bind only to loopback and are accepted only when launched by this app.
- A fresh 256-bit token is passed only in the child-process environment and required as `X-Local-TTS-Token`.
- Health checks verify engine, model revision and per-launch session ID.
- Proxy use is disabled for loopback requests.
- Body, reference WAV and response sizes are bounded.
- Model files are verified by size and SHA-256 before use.

Do not weaken those invariants merely to make an integration test convenient.
