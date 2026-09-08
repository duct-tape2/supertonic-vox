# Build and release

## Supported build host

Use a fully patched Windows 11 x64 machine and .NET SDK 10.0.302 or a newer compatible 10.0 servicing SDK. The runtime is self-contained; target machines do not need a system-wide .NET installation.

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
powershell -ExecutionPolicy Bypass -File .\test.ps1
powershell -ExecutionPolicy Bypass -File .\package.ps1
```

For the exact locked-runtime test arguments, staging replacements, signing order, real-engine checks and final evidence gate, follow `WINDOWS_RELEASE_CHECKLIST.md`.

`global.json` pins 10.0.302 and `packages.lock.json` pins NuGet resolution. Do not use `--force-evaluate` for a release without reviewing the resulting lock change.

## Older Windows 10 build-host workaround

This recovery host is Windows 10 build 19044 and the .NET 10 Roslyn apphost terminated with “Windows doesn't fully support CET.” Source was still compiled against .NET 10 reference packs by using the .NET 8.0.421 Roslyn host through the optional `-CscToolPath` argument. That emits compiler/analyzer-version warnings and is only recovery evidence. The Windows 10 candidate also sets `CETCompat=false`; remove that property and rebuild a CET-enabled flavor for a fully patched Windows 11-only fleet.

## Offline release overlay

1. Copy the original portable tree to a new staging directory.
2. Preserve original changed files in `baseline-overlay/original`.
3. Copy the published executable to the root.
4. Copy `src/SupertonicSidecar/secure_server.py` to `_internal/SupertonicLocal/app/secure_server.py`.
5. Copy the hardened Vox `server.py` to `_internal/VoxCPM2Local/app/server.py`.
6. Copy the hardened Vox `voxcpm_low_memory.py` and `run_server.ps1` to their matching `_internal/VoxCPM2Local` paths.
7. Sign the staged executable, then generate `FILE_MANIFEST_SHA256.json` after all changes.
8. Run `verify-release.ps1`.
9. Compress to Zip64, split the byte stream into at most 500,000,000-byte parts, hash every part and verify a clean extraction.

## Signing

The supplied executable is unsigned. When a code-signing certificate is available, run `sign.ps1` with a certificate-store thumbprint or a PFX path supplied outside the repository. Never place a PFX, password, cloud-signing token or private key in either ZIP.

## macOS custody verification

For the recovered WinForms release and offline payload, macOS is supported only for source review and payload custody verification; do not run the bundled Windows executable or portable Python runtimes there. Put the transport file, all numbered parts, `PARTS_MANIFEST.json`, `PARTS_SHA256.txt`, `restore_001_on_mac.sh` and `verify_and_extract_mac.sh` in one local directory, then run:

```sh
sh restore_001_on_mac.sh
sh verify_and_extract_mac.sh
```

The first script restores the transformed `.zip.001` and verifies both the transport and restored hashes. The second script checks the manifest contract, every numbered part against both checksum files, the combined archive hash, archive paths, and every extracted file. It refuses a non-empty destination. Install missing prerequisites with `brew install python sevenzip`.

## Cross-platform successor preview

The new Avalonia solution intentionally excludes the Windows-only WinForms project, so it builds on both macOS and Windows:

```sh
dotnet restore SupertonicVox.CrossPlatform.slnx --locked-mode
dotnet build SupertonicVox.CrossPlatform.slnx -c Release --no-restore
dotnet test tests/SupertonicVox.Core.Tests/SupertonicVox.Core.Tests.csproj -c Release --no-build
SVX_SUPERTONIC_MODEL_ROOT=/absolute/path/to/pinned/model \
  dotnet run --project tools/DesktopSmoke/DesktopSmoke.csproj -c Release
SVX_SUPERTONIC_MODEL_ROOT=/absolute/path/to/pinned/model \
  dotnet run --project src/CrossPlatform/SupertonicVox.Desktop/SupertonicVox.Desktop.csproj -c Release
```

The model root must contain `onnx/` and `voice_styles/`. Required file sizes and SHA-256 values are enforced by `SupertonicModelManifest`; only the official pinned `Supertone/supertonic-3` revision is accepted. Use SDK 10.0.302 as pinned in `global.json`. The app makes no startup model download and no synthesis-time network request. Its embedded development catalog is Ed25519-signed, but remote refresh remains fail-closed until a production signing key and key-custody process are available.

Do not publish an installer until every P0 row in `RELEASE_READINESS_DASHBOARD.md` is closed. The current verified Mac synthesis is development evidence, not a signed release.

## Clean public-source staging

The recovery repository and original bundle are never publication inputs. Create a new allowlisted one-commit bundle and source ZIP, validate only a disposable export of its frozen commit, and re-audit the copied bundle:

```sh
python3 tools/release_privacy_gate.py --self-test
python3 tools/release_history_audit.py --self-test
python3 -m unittest discover -s tools -p 'test_*.py' -v
./packaging/create-public-release-staging.sh
```

The command rejects Git symlinks/submodules, LFS pointers, hidden or polyglot ZIPs, unsupported archive containers, private markers, secret patterns and recovery-custody paths. Its output remains local and records `releaseEligible: false` while `SOURCE_LICENSE_PENDING.md` exists.

## Final release evidence aggregation

`packaging/release-gate-traceability.json` binds every canonical blocker to exactly one owner step, one per-gate evidence envelope and one verifier. It also requires exact-candidate Terra and Fable reviews plus either a GPT-5.6 Pro web pass or an explicit owner-approved waiver. Validate the immutable map with:

```sh
python3 tools/release_open_gates.py validate-traceability
```

After the final candidate has real legal, trust-root, native-engine, signed-installer, clean-machine and protected-CI evidence, assemble the canonical envelopes and run:

```sh
SVX_OWNER_TRUST_ROOT_SHA256=<out-of-band-root-sha256> \
python3 tools/final_release_evidence.py validate-final-evidence \
  --index /absolute/path/to/final-release-evidence.json \
  --evidence-root /absolute/path/to/final-release-evidence-root \
  --repo /absolute/path/to/frozen-release-repository \
  --owner-trust-root /offline/owner-trust-root.json \
  --gh-cli /pinned/regular-file/gh
```

The verifier requires all 17 gates and all three reviews at one full repository-native commit ID (40 hexadecimal characters for SHA-1 repositories or 64 for SHA-256 repositories). The repository policy must be signed by a distinct offline owner root whose canonical file hash is supplied out of band. The approved policy key then verifies the annotated tag over the final index. The tag must target clean `HEAD`; the remote origin must match the root repository; and the root-pinned GitHub CLI must successfully run `gh attestation verify` for both installers against their bundles, repository, signer workflow and exact `--source-digest` release commit. Missing, stale, reordered, substituted, symlinked, hardlinked or tampered inputs fail closed. Parent traversal uses POSIX directory handles with no-follow semantics; run final aggregation on an isolated Linux/macOS host. A passing signed test-repository fixture is not release evidence; the checked-in `packaging/final-release-signing-policy.json` remains `capture-required`, so only an out-of-band owner root, approved native artifacts and protected GitHub attestations can make the real index pass.

## Apple Silicon unsigned package preflight

The preflight exports committed `HEAD` with `git archive`, builds only inside that clean temporary tree, verifies the official pinned model files, excludes the crash-dump helper, scans the app, runs the desktop smoke, creates a DMG, mounts it read-only, and scans the mounted contents again. It refuses tracked worktree changes and produces an explicitly non-distributable artifact.

```sh
python3 tools/release_privacy_gate.py --self-test
python3 -m unittest tools/test_release_privacy_gate.py tools/test_fetch_supertonic_model.py -v

python3 tools/fetch_supertonic_model.py \
  --destination artifacts/model-cache/supertonic-3 \
  --report artifacts/model-cache-fetch-report.json

./packaging/build-macos-release.sh --preflight-unsigned --offline-models
```

Evidence is written under `artifacts/macos-preflight/<commit>/` and is ignored by Git. `release-evidence.json` always records `releaseEligible: false`, the source commit, DMG hash/size and SDK version/hash. This command does not sign, notarize, staple or publish anything.

## Windows x64 successor package preflight

Run only on Windows x64 with PowerShell 7 and the exact SDK from `global.json`. First capture and review the literal publish inventory:

```powershell
pwsh -NoProfile -File .\packaging\build-windows-release.ps1 -CapturePublishInventory
```

After the reviewed file list is committed with status `approved` in `packaging/windows-publish-allowlist.json`, run:

```powershell
pwsh -NoProfile -File .\packaging\build-windows-release.ps1 -PreflightUnsigned
```

The output is an explicitly unsigned ZIP with `releaseEligible: false`; it is validation evidence, not an MSI and not a distributable artifact. The script is successor-only and never packages the recovered WinForms application, private payload, Windows Python runtimes, or sidecars. Windows must still prove Authenticode, MSI install/update/uninstall, GUI/audio, and clean-user-machine behavior.

## Optional VoxCPM2 protocol-v2 runtime packs

The successor never reuses the recovered WinForms sidecar folder and never searches GitHub at runtime. Build each optional pack from an external clean Python runtime, pinned dependencies, verified model directory and approved license files with the offline builder:

```sh
python3 tools/build_voxcpm2_runtime_pack.py --help
```

The builder writes a new `.partial` directory only after a deterministic full inventory is complete. Native validation then uses `tools/VoxRuntimePackSmoke` to invoke the same `RuntimePackVerifier`, owned-process host and provider as the desktop app. Exact Windows/macOS commands, expected JSON evidence and release gates are in `VOXCPM2_RUNTIME_PACK_RELEASE.md`.

After native smoke activation, create the exact app-installable archive and signed-catalog metadata with:

```sh
python3 tools/package_voxcpm2_runtime_pack.py --help
```

The desktop app never uses a general archive extractor. It accepts only catalog-bound `RuntimePackTar`/`UstarV1`, persists the verified pack fingerprint, reruns a pack-specific benchmark before selection, and safely falls back to Supertonic 3 on every failure.

The repository contains no release pack, Python runtime or VoxCPM2 weight. Do not set a catalog artifact to installed/available until the corresponding native evidence has passed review and the model/code redistribution decisions are approved.

## Production catalog trust

Use only the verifier-only `tools/CatalogReleaseVerifier` flow described in `CATALOG_TRUST_ROOT_RELEASE.md`. The checked-in catalog remains development-only. Production private keys must stay in an offline device or HSM and must never be supplied to the build, repository, or CI.
