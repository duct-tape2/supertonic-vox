# Cross-platform successor status

Status: **privacy-gated unsigned Mac DMG working — signed cross-platform release not ready**

The authoritative gate table is `RELEASE_READINESS_DASHBOARD.md`.

## 2026-07-29 verified continuation

- Native C# ONNX Supertonic 3 synthesis runs on Apple Silicon without Python or synthesis-time network access.
- Official source is pinned to `v3.0.0` / `5379cc4e…`; the model is pinned to `3cadd1ee…` with file-by-file SHA-256 verification.
- A real Korean smoke produced a valid 44.1 kHz mono PCM16 WAV lasting 5.229 seconds.
- Desktop initialization verified the development-signed embedded catalog, hardware profile, model assets, real benchmark cache and automatic recommendation. Measured local RTF was 0.39 on the current M1 Ultra. Production catalog trust remains disabled and release-blocking.
- The UI exposes text input, M1 voice, synthesize, cancel, playback and atomic save commands.
- A clean `git archive` build at `6fedf6c…` produced an unsigned self-contained Apple Silicon DMG with the official seven-file model payload. The app and read-only remounted DMG each passed the privacy gate with 0 findings across 238 files / 555,539,804 bytes.
- The exact packaged app launched without `SVX_SUPERTONIC_MODEL_ROOT`; its UI generated 5.77 seconds of Korean audio in 1.98 seconds and enabled playback/save.
- Optional sidecars now require protocol v2: immutable pack verification, parent/session-bound handshake HMAC, real OS listener-PID verification, a no-bearer bootstrap challenge, first-request owner rechecks, bounded HTTP/WAV validation, and owned process-tree cleanup. The package-free `FakeVoxSidecar` is a protocol-reference fixture only.
- Current local verification: locked restore; Release build warning 0/error 0; 94/94 Core tests; 81/81 Python privacy/history/model/Windows/macOS/public-staging contract tests; format, dependency vulnerability, shell, plist and workflow checks passed.
- A clean allowlisted public-source candidate at `54e1f9c…` produced staging commit `5660de1…`, a one-commit bundle and strict deterministic source ZIP. The ZIP privacy scan and both delivered histories pass with 0 findings; evidence remains `releaseEligible=false` with all 17 canonical release gates open.
- Claude Fable 5 and ChatGPT web GPT-5.6 Sol Pro agreed on `SOURCE_PREVIEW_PASS / DISTRIBUTION_BLOCK`. Fable approved remediation plan V8.3. Sol and the independent Terra review exposed ZIP slack/metadata, marker-exception, filename-marker and deflate-tail attacks; all identified P1s are fixed, and final Terra delta review reports no remaining P0/P1.

This is not yet distributable: source ownership/license approval, Supertonic provenance approval, production catalog trust, Developer ID signing/notarization, signed MSI, a real Windows native listener-verifier/clean-machine run, audited production VoxCPM2 protocol-v2 packs and protected remote CI remain open.

This work is isolated in `src/CrossPlatform`, `tests/SupertonicVox.Core.Tests`, and `SupertonicVox.CrossPlatform.slnx`. It does not reference, copy, publish, or modify the recovered private payload or Windows portable runtimes.

## Implemented

- Avalonia 12 / .NET 10 MVVM desktop shell builds and runs on Apple Silicon macOS.
- The new solution excludes the Windows-only WinForms project.
- macOS and Windows hardware profiling records OS, architecture, CPU, memory, disk, GPU/backend and a non-identifying local cache fingerprint.
- Deterministic recommendation hard gates cover platform, architecture, RAM, disk, CUDA VRAM and requested features.
- Manual engine choice persists and takes priority until “다시 자동 선택” is used.
- Cold recommendations mark latency pending and renormalize quality/resource/features to 66.67/20/13.33 percent. Current successful benchmarks use 50/25/15/10.
- Benchmark cache keys include app version, engine, model revision and hardware fingerprint; writes are atomic.
- The embedded engine catalog is verified over the exact bytes with Ed25519 before parsing. Unknown engines, origins and licenses fail closed.
- Catalog sequence rollback/replay protection exists. Remote refresh is disabled while the interim development trust root is active.
- Production catalog code now pins the offline root fingerprint, verifies a root-signed sequenced trust manifest, applies leaf validity/revocation, and verifies the exact catalog bytes. A verification-only release tool emits a composite root/manifest/catalog acceptance state; no production signer or private key exists in the repository.
- Artifact downloads require explicit matching consent, HTTPS allowlisted origins, known size and SHA-256. They use resumable `.partial` files and atomic activation.
- Startup composes no HTTP client and makes no external request. Telemetry is disabled by policy and absent from the implementation.
- The UI enables synthesis only after the pinned Supertonic provider, model hashes and local benchmark pass. Optional engine downloads remain disabled.
- A successor-only Windows x64 unsigned ZIP preflight is implemented. It fails closed until a first `windows-2025` publish inventory is reviewed and committed, then applies exact inventory, model, synthesis, privacy, deterministic archive, and evidence checks. It does not create an MSI.
- A WiX 7 MSI/AuthentiCode contract is implemented but not executed. It uses a production-rejected staging UpgradeCode, commit-bound release inputs, complete per-file signing policy, exact expected-signer constraints, reconstructed post-sign inventory evidence, verified prior-MSI identity/signature/version, ICE-before-final-signing evidence, and a protected self-hosted PowerShell 5.1 workflow with no upload or publication step.
- A Developer ID/hardened-runtime macOS contract is implemented but not executed. It thins approved universal inputs to pure arm64, signs nested code deepest-first, binds the actual certificate and entitlements, notarizes/staples the app before DMG construction, then separately signs/notarizes/staples and Gatekeeper-assesses the DMG. The protected workflow uses an explicit ephemeral keychain and never uploads artifacts.

## Development catalog limitations

The bundled catalog now pins the official Supertonic revision, MIT source license, OpenRAIL-M model license, artifact selectors, sizes and hashes. VoxCPM2 and MeloTTS remain `REVIEW-PENDING` with no installable artifacts. The temporary signing private key is generated in memory and discarded. Never enable remote refresh or publish a release with this trust root.

## Release blockers, in order

1. Confirm repository ownership/public license and finish VoxCPM2/MeloTTS redistribution review.
2. Run the first Windows inventory capture, review/commit the literal allowlist, then pass the unsigned x64 preflight.
3. Provision the external offline/HSM production root and leaf, complete two-person custody and rotation/revocation drills, and verify the public production assets with `CatalogReleaseVerifier`.
4. Produce signed, reproducible VoxCPM2 and MeloTTS sidecar runtime packs with all inherited token, loopback, proxy, size, process-ownership, atomic-write and log-rotation controls, or formally descope them from v1.
5. Add real-device Windows x64, NVIDIA CUDA and Apple Silicon 8/16+ GiB matrices. Vox MPS remains benchmark-gated.
6. Build self-contained Windows MSI and arm64 macOS app/DMG. Complete Authenticode, Developer ID hardened runtime, notarization, stapling and clean-machine install/update/uninstall tests.

## Required clean-machine evidence

- No system Python is required.
- Install, first launch, Korean synthesis, playback, atomic save, restart and uninstall all pass.
- Supertonic 3 works fully offline immediately after installation.
- Optional engines disclose exact download size and license before network access.
- Interrupted/corrupt downloads, disk/RAM exhaustion and GPU initialization failures safely return to Supertonic 3.
- Wrong token returns 401, hidden path 404, oversized input 413, PID mismatch, port collision and orphan cleanup tests pass for every sidecar.
- No manuscript, log, reference voice or generated WAV leaves the machine.
