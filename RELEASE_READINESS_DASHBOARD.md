# Supertonic + VoxCPM2 release readiness

- Updated: 2026-07-29 (Asia/Seoul)
- Branch: `codex/release-readiness-20260727`
- Latest release-contract implementation commit: `d087d8c2992265fa16dc3c26216cbd9e50286594`
- Latest Mac preflight evidence commit: `2716142c7a5071697cb9973c48d84e9561e82ba2`
- Latest clean public-staging source commit: `d087d8c2992265fa16dc3c26216cbd9e50286594`
- Release verdict: **NOT READY FOR DISTRIBUTION — code may advance to signing and clean-machine validation, but legal, trust-root, signed Mac/Windows, CI-provenance and VoxCPM2 gates remain open.**

## Evidence dashboard

| Gate | State | Evidence | Owner / next action |
|---|---|---|---|
| Supertonic official provenance | PASS | Code `v3.0.0` / `5379cc4e…`; model `3cadd1ee…`; all 7 bundled artifacts have pinned size and SHA-256 | Automated manifest validation |
| Native Mac Korean synthesis | PASS | C# ONNX Runtime, Python-free, 44.1 kHz mono PCM16; packaged UI generated 5.77 s audio in 1.98 s with playback/save enabled | Keep as release smoke test |
| Hardware benchmark recommendation | PASS (Mac) | Latest packaged M1 Ultra smoke: Supertonic selected, measured RTF 0.38, atomic versioned cache | Add Windows and lower-memory real-device evidence |
| Core automated tests | PASS | Frozen public staging: 119/119 .NET and 107/107 Python tool/contract tests; local isolated Vox protocol/process tests 15/15; runtime-pack builder + archive packager 12/12; Release build warning 0/error 0; format, shell, YAML and compile checks passed | Remote CI must reproduce Windows/macOS .NET, Python release contracts and Linux Vox legs |
| PRIVATE_USER_STATE exclusion | PASS (Mac) / WINDOWS PREFLIGHT IMPLEMENTED | Strict ZIP coverage rejects prefix/trailer/interior slack, comments, descriptors, ZIP64, unsupported extras/methods, filename markers, hidden deflate tails and corrupt streams; hardlinks, nested archives and scan-state changes fail closed. Latest public source ZIP directly scanned with 0 findings | Run and retain the Windows publish/package/ZIP/extracted-tree reports |
| Clean Mac package preflight | PASS / UNSIGNED | Git-archive build at `2716142…`; 119/119 tests; official seven-file model; app and mounted DMG privacy scans each 0 findings; DMG 437,551,824 bytes, SHA-256 `cb23237a…`; package is explicitly not release-eligible | Retain only as local preflight evidence |
| Desktop package flow | PASS (Mac preflight) | Latest packaged DesktopSmoke reports offline startup, Ed25519 catalog verification, 3 engines, Supertonic Korean synthesis ready and RTF 0.38; earlier manual package flow verified text/voice/synthesize/cancel/playback/save states | Repeat on a clean Apple Silicon standard account after notarization |
| Embedded catalog integrity | PASS (development) | Exact-byte Ed25519 verification; sequence 2; numeric enums disabled; artifact selectors and duplicate/size checks | Replace development root for release |
| Remote catalog replay state | IMPLEMENTED / NOT ENABLED | Accepted sequence is serialized across processes and disk-flushed before a remote catalog can be returned; production verifier emits composite root/manifest/catalog state | Production endpoint + retained baseline + crash/rotation drill required |
| Source ownership and app license | OPEN / P0 | Upstream notices are recorded; repository ownership/public license is not approved | Release owner must approve license before public source or binaries |
| Production catalog trust root | CODE CONTRACT PASS / EXTERNAL P0 | Root fingerprint pin, root-signed sequenced manifest, leaf validity/revocation, exact catalog verification, verifier-only release tool, and external asset injection are implemented; checked-in assets remain development-only | Provision offline/HSM root+leaf, two-person custody, produce/verify production public assets, and run a rotation/revocation drill |
| macOS signed/notarized DMG | POLICY CAPTURE PASS / NATIVE EXTERNAL P0 | Commit-bound policy candidate at `7f53e90…` covers 237 files (19 Mach-O/218 resources); 4 universal dylibs were recorded and thinned to pure arm64. Exact Developer ID identity, allow-JIT-only entitlements, deepest-first signing, app-before-DMG dual notarization/stapling, primary-signature Gatekeeper and ephemeral-keychain contracts passed static review. Candidate remains `review-required`; no signed DMG exists | Owner reviews/commits identity and 237-file policy, then runs protected signed candidate and quarantined clean-account rehearsal |
| Windows signed MSI | STATIC CONTRACT PASS / NATIVE EXTERNAL P0 | WiX SDK 7.0.0 is pinned; staging identity is rejected for production; all direct MSI inputs must match the release commit; complete payload policy binds exact existing signers, approved unsigned PEs and owner-sign transitions to a reconstructed final inventory; later baselines require an approved owner signature/timestamp, matching UpgradeCode and lower version; unsigned MSI hash binds ICE before MSI signing; protected PowerShell 5.1 workflow has no upload/publication. Literal publish/signing policies remain capture-required and no MSI has been built | Capture/approve both inventories on Windows, run staging MSI, commit the owner identity/policy, provision certificate/catalog approvals, then sign and execute clean-machine install/synthesis/upgrade/uninstall evidence |
| VoxCPM2 optional runtime | SECURE DESKTOP LIFECYCLE SOURCE PASS / NATIVE PACK OPEN | Commit `c9a14af…` adds a signed catalog-bound runtime artifact contract, strict deterministic USTAR extraction, atomic install/update/rollback/uninstall/recovery, startup re-verification, active-pack fingerprint-bound benchmarks, explicit-consent Desktop flow and stop/cancel orphan protection. Deterministic pack builder + archive packager tests pass. No real model/runtime pack was built | On native targets build, license, scan and benchmark Win x64 CPU/CUDA and Mac arm64 CPU/MPS packs; keep unavailable variants out of production catalog |
| CI matrix and release provenance | IMPLEMENTED / REMOTE RUN OPEN | Actions are SHA-pinned; privacy gate precedes `windows-2025` and Apple Silicon `macos-15` build/test legs | Push private branch and require a green run |
| Full-history source/bundle privacy audit | PASS FOR CLEAN STAGING | Every local object is scanned, including detached/reflog/dangling history; symlink, submodule, LFS, polyglot ZIP, Git pack/bundle and secret negatives pass. Delivered repo/bundle: 0 findings | Re-run from every immutable release commit |
| Canonical release blocker contract | TRACEABILITY + FINAL VERIFIER SOURCE PASS / 17 OPEN | `release-open-gates.json` is canonical; `release-gate-traceability.json` maps all 17 gates exactly once to owner step, envelope and verifier. Final aggregation rejects missing/stale/reordered evidence and retains `releaseEligible=false` until all mappings close | Clear gates only with same-commit signed/native evidence |
| Final release evidence trust chain | CODE CONTRACT PASS / EXTERNAL ROOT CAPTURE P0 | Commit `d087d8c…` adds POSIX descriptor-safe evidence traversal, an out-of-repo SHA-pinned owner root, owner-signed repository policy, SSH-signed exact-index tag, repository/origin binding, root-hash-pinned GitHub CLI, two installer attestation bundles and `gh attestation verify --source-digest <releaseCommit>`. Checked-in policy is deliberately `capture-required`; 10 focused final-evidence tests pass | Owner provisions the external root/key policy and real GitHub attestations only after all release inputs are frozen; run final aggregator on isolated Linux/macOS |
| Clean public-source staging | PASS / NOT PUBLIC | Source `d087d8c…`; staging `5f0eb59…`; source ZIP `4e84ad54…` / 374,227 B; bundle `bc63f485…` / 343,282 B; direct ZIP privacy scan and repository/bundle/delivered-clone audits each 0 findings; Python tools 107/107 and .NET 119/119; `releaseEligible=false` | Keep private until source-license P0 closes |
| Independent release review | SOURCE PREVIEW PASS / DISTRIBUTION BLOCK | Runtime lifecycle review fixed 6 P1s and returned PASS. Final-evidence trust review then found 5 P1s over four rounds (synthetic evidence, parent TOCTOU, circular key trust, self-asserted provenance, missing source-digest); all were fixed and final Terra verdict is PASS with no P0/P1. Fable returned `PLAN_APPROVED` for RPI1.2 after five plan corrections. Exact-current GPT-5.6 Pro web review is still unavailable and is not being claimed | Obtain GPT web review on the final RC or record an explicit owner-approved waiver; rerun all exact-commit reviews after any RC change |
| Release-tooling residuals | PASS WITH DOCUMENTED LIMIT | Strict stored/deflate streams require exact consumption, size and CRC; corrupt zlib input becomes a machine-readable finding; manifest link count/hash/read-only identity is rechecked before sidecar launch | Signed staging must still use an isolated read-only snapshot against adversarial exact restore races |

## Fail-closed final-release plan (Fable RPI1.2 approved)

All trust-root, catalog, runtime-pack and policy mutations must happen before the final release-candidate commit is frozen. Any later change creates a new candidate and invalidates every build, test, native-machine, reviewer and provenance result. Distribution remains blocked until the canonical verifier finds one exact-commit evidence set for every row below.

| Owner step | Canonical gates | Required exact-commit evidence |
|---|---|---|
| LEGAL_APPROVAL | `source-ownership-and-license`; `dependency-license-attribution`; `supertonic-model-redistribution`; `voxcpm2-model-redistribution` | Owner-signed source-license decision, approved notices/audit, exact model revision/hash redistribution decisions |
| TRUST_AND_RUNTIME_ARTIFACTS | `production-catalog-trust-root`; `production-key-custody-and-rotation`; `real-voxcpm2-runtime-packs` | Production public assets/verifier report, key-ceremony custody record, tested client-reachable rotation/revocation/deny-list drill, signed pack manifests/hashes/fingerprints/licenses |
| MAC_NATIVE_RELEASE | `apple-hardened-runtime`; `developer-id-signing`; `apple-notarization-and-stapling`; `macos-clean-machine-validation` | Signing inventory, codesign/notary/staple validation, quarantined standard-account install/synthesis/update/uninstall report |
| WINDOWS_NATIVE_RELEASE | `authenticode-signing`; `msi-installer`; `windows-clean-machine-validation`; `windows-publish-inventory-approval` | Owner-approved inventory, ICE/upgrade report, certificate/timestamp verification, standard-account install/synthesis/update/uninstall report |
| REAL_ENGINE_BENCHMARKS | `real-engine-benchmarks` | Final-candidate Korean WAV/RTF/peak-memory/fallback matrix for Supertonic and available Vox CPU/MPS/CUDA packs |
| REMOTE_PROVENANCE | `remote-ci-provenance` | Protected green workflow and attestation binding the commit, post-sign/post-staple DMG/MSI SHA-256, contained app inventory and runtime-pack fingerprints; identical hashes in signed catalog/release notes |

The final exact-commit review gate requires Terra code/delta review, Fable readiness verification and GPT-5.6 Pro web review. If GPT web remains unavailable, only an explicit owner-approved written waiver with rationale can substitute; otherwise the gate stays open.

## Latest local Mac preflight artifact

Evidence directory: `artifacts/macos-preflight/2716142c7a50/` (ignored by Git; local only).

- Artifact: `SupertonicVox-0.1.0-macos-arm64-UNSIGNED-NOT-FOR-DISTRIBUTION.dmg`
- Evidence is bound to commit `2716142c7a5071697cb9973c48d84e9561e82ba2`.
- DMG SHA-256: `cb23237accc826104464b17e8ae9099eb3e4d6d624862c894b24cb4e37952988` (437,551,824 bytes).
- Frozen Git-archive build/test: 119/119; app and mounted DMG privacy reports: PASS with 0 findings; packaged DesktopSmoke: offline, Ed25519 verified, Supertonic RTF 0.38.
- `release-evidence.json` is authoritative for the DMG size and SHA-256.
- `releaseEligible` is `false`; the artifact must not be uploaded or presented as a release.

## Latest clean public-source staging

Evidence directory: `artifacts/public-release-staging/d087d8c29922/` (ignored by Git; local only).

- Source commit: `d087d8c2992265fa16dc3c26216cbd9e50286594`
- Staging commit: `5f0eb59dbf517ce55925a5ababcb5adb0ba453dd`
- Source ZIP SHA-256: `4e84ad540f9ff478705c2a9c50dc5657f5581f3d1d5b2016831206d4c8a4ed14` (374,227 bytes)
- Git bundle SHA-256: `bc63f485d0b00dc6e95df3e70b511579fbcc3d68e6464f17b6503dd3190f203b` (343,282 bytes)
- `source-archive-privacy-report.json` reports PASS with 0 findings and binds the exact source ZIP fingerprint.
- `history-audit.json` and `delivered-history-audit.json` both report repository and bundle PASS with 0 findings.
- Source is published under the MIT `LICENSE` at the repository root. Binary releases are not part of this source line.

## Latest VoxCPM2 protocol-v2 source milestone

- Implementation commit: `c9a14af1478b25e54718ec54746246fcb6028f87`; the recovered legacy `app/server.py` is unchanged.
- Local isolated tests: protocol/server/subprocess 15/15; runtime-pack builder + archive packager 12/12; frozen public staging .NET 119/119 and Python tools 94/94.
- Security review: Terra PASS after six P1 fixes over three rounds; Fable RPI1.2 `PLAN_APPROVED` for the fail-closed release plan and source-preview classification.
- No real VoxCPM2 model weight, native Python runtime or production pack is present. Native CPU/CUDA/MPS, signed-catalog, license and clean-machine gates remain open.

## Latest macOS signing-policy capture

Evidence directory: `artifacts/macos-signing-policy/7f53e904974f/` (ignored by Git; local only).

- Source commit: `7f53e904974f23795edb353f32c1ccc3294f3300`; package `0.1.0`; `releaseEligible=false`; exact 17 gates open.
- Policy candidate: SHA-256 `4482853a8d9f09ce97cdfb6483a0e8ed25c06dbb2d33ac6898f4cbd2287dbd6e` (89,592 bytes), status `review-required`.
- Pre-normalization inventory: SHA-256 `6bb98ba4e3905dd36bd35d941afe2e240eacbcc0795126fd438f9b2731a74262` (56,652 bytes).
- Normalized inventory: SHA-256 `0bee1d1ca0e8e6d6237b6f4996b64eab6eaa4ccad8d3d6887df8aaedd9a116a2` (56,559 bytes); all 19 Mach-O files are arm64-only.
- Architecture report: SHA-256 `91a1990f691122ef79182e6607c820e9ecda11b23bd65b4e684185a88fec0c93` (9,323 bytes); Avalonia, HarfBuzz, Skia and libsodium were thinned.

## Current reproducible commands

```sh
./.tools/dotnet/dotnet restore SupertonicVox.CrossPlatform.slnx --locked-mode
./.tools/dotnet/dotnet build SupertonicVox.CrossPlatform.slnx --configuration Release --no-restore
./.tools/dotnet/dotnet test tests/SupertonicVox.Core.Tests/SupertonicVox.Core.Tests.csproj --configuration Release --no-build
python3 tools/release_privacy_gate.py --self-test
python3 tools/release_history_audit.py --self-test
python3 tools/release_open_gates.py validate-traceability
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 -m pip install -r src/VoxCPM2Sidecar/tests/requirements-test.txt
python3 -m unittest discover -s src/VoxCPM2Sidecar/tests -p 'test_*.py' -v
./packaging/create-public-release-staging.sh
./packaging/build-macos-release.sh --preflight-unsigned --offline-models
```

On Windows x64, capture the first literal publish inventory with `pwsh -NoProfile -File .\packaging\build-windows-release.ps1 -CapturePublishInventory`. After review and commit, run the same script with `-PreflightUnsigned`.

One non-authoritative local attempt invoked the macOS Bash script through `sh` and failed at Bash-only process substitution. The documented direct invocation above was rerun and passed completely; the failed invocation produced no retained artifact.

No installer may be published while any P0 row is open.
