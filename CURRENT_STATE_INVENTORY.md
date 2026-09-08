# Current state inventory

## Baseline evidence

- Product: Supertonic + VoxCPM2
- File version: 2.0.0.0
- Baseline executable size: 72,742,810 bytes
- Baseline executable SHA-256: `1DBA58535C8B45B0980E9B0537DA08A80C646A577D442A3120CDE582FE3C2516`
- Authenticode: not signed
- Original portable tree at capture: 7,135,739,901 bytes, 45,788 files
- Baseline .NET runtime embedded in the executable: 8.0.27
- Recovery source timestamp was approximately 23 seconds after the baseline executable, and assembly metadata matched version 2.0.0.

The original Desktop directory was read only. Its content is reproduced in the offline payload. The original executable and changed sidecar files are kept in `baseline-overlay`.

## Recovered components

- WinForms desktop orchestrator and Korean text/pronunciation pipeline.
- Supertonic 3 ONNX engine with ten voice style profiles.
- VoxCPM2 2.0.3 CPU sidecar with four designed presets and a consent-gated cloning mode.
- Portable CPython 3.12.13 runtimes and locked package trees.
- Models, cached assets, settings, SavedText, logs, VoiceSamples and GeneratedAudio.

## Hardened candidate

- .NET target: `net10.0-windows10.0.19041.0`, Windows x64, self-contained, single-file.
- Direct DLL references replaced by locked NuGet references:
  - Newtonsoft.Json 13.0.3
  - HtmlAgilityPack 1.12.2
- Hardened executable remains unsigned because no certificate was provided.
- Hardened candidate executable: 143,223,386 bytes; SHA-256 `795FDA98902ACBDA7FFAFCB17FFFB9214CB25DD4E449860B7B18A6E9C2CD8A84`.
- Candidate apphost uses `CETCompat=false` for the stated Windows 10 target; see security finding STV-011.
- Supertonic secure wrapper added at `_internal/SupertonicLocal/app/secure_server.py`.
- Vox sidecar authentication and request limits added in `src/VoxCPM2Sidecar/app/server.py`.
- Complete offline payload manifest is `FILE_MANIFEST_SHA256.json`.

## Git history contract

- `recovered-baseline`: untouched recovered source arranged into the documented tree.
- `hardened-candidate`: security, tests, documentation and packaging changes.

No earlier commits are represented.

## macOS continuation verification

On 2026-07-27, the handoff ZIP, exact two-commit history, `project.bundle`, transformed transport, restored `.zip.001`, all 11 split parts, combined Zip64 stream and all 45,835 payload manifest entries were independently verified on macOS. Candidate/baseline executable hashes matched this inventory, and both staged sidecars matched the source byte-for-byte. See `reports/MACOS_HANDOFF_VERIFICATION_2026-07-27.md`.

The original handoff was verified with exactly those two commits before continuation. Later commits are permitted only as descendants of `hardened-candidate`; the two evidence commits must never be rewritten. Continuation work is on branch `codex/release-readiness-20260727`. It adds macOS custody scripts and Windows release gates without changing the recovered runtime/security source. Windows build, GUI, real synthesis, dependency qualification and Authenticode evidence remain required before distribution.
