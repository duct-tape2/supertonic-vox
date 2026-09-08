# Build and release

## Supported targets

- Windows 10/11 x64
- Apple Silicon macOS 13 or later
- .NET SDK 10.0.302, as pinned by `global.json`

Supertonic is self-contained in production packages. Target users do not install .NET or Python.

## Build and test

```sh
dotnet restore SupertonicVox.CrossPlatform.slnx --locked-mode
dotnet build SupertonicVox.CrossPlatform.slnx --configuration Release --no-restore
dotnet test tests/SupertonicVox.Core.Tests/SupertonicVox.Core.Tests.csproj --configuration Release --no-build
python3 tools/release_privacy_gate.py --self-test
python3 tools/release_history_audit.py --self-test
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 -m pip install -r src/VoxCPM2Sidecar/tests/requirements-test.txt
python3 -m unittest discover -s src/VoxCPM2Sidecar/tests -p 'test_*.py' -v
```

## Apple Silicon unsigned preflight

```sh
python3 tools/fetch_supertonic_model.py \
  --destination artifacts/model-cache/supertonic-3 \
  --report artifacts/model-cache-fetch-report.json

./packaging/build-macos-release.sh --preflight-unsigned --offline-models
```

The preflight exports committed `HEAD`, builds in an isolated temporary tree, validates the model and source tests, scans the app, runs a local desktop smoke, creates a DMG, mounts it read-only, and scans the mounted contents again. Its output is deliberately named `UNSIGNED-NOT-FOR-DISTRIBUTION`, and `release-evidence.json` records `releaseEligible: false`.

## macOS Developer ID and notarization contract

The checked-in macOS release identity is staging-only and the signing policy is `capture-required`; production mode rejects both. Capture the post-normalization Apple Silicon payload on a protected Mac:

```sh
./packaging/build-macos-release.sh \
  --capture-signing-policy \
  --offline-models \
  --model-cache /absolute/path/to/verified/supertonic-3
```

Every multi-slice Mach-O input is recorded and deterministically thinned to `arm64` before policy capture. After the owner-approved Developer ID identity and complete policy are committed, the protected manual workflow signs nested code deepest-first with hardened runtime and the allow-JIT-only entitlement. It notarizes and staples the app before constructing the DMG, then signs, notarizes and staples the DMG separately. Actual leaf SHA-256, subject, Team ID and secure timestamp are extracted after signing; app/DMG stage hashes, full inventories, both `Accepted` submission IDs, Gatekeeper checks and privacy reports are bound in noneligible evidence. `codesign --deep` is never used for signing, and the workflow never uploads an artifact.

See `MACOS_RELEASE_CHECKLIST.md` for ephemeral-keychain handling and the quarantined clean-account test.

## Windows x64 unsigned preflight

The first clean `windows-2025` run captures a literal self-contained publish inventory for human review:

```powershell
pwsh -NoProfile -File .\packaging\build-windows-release.ps1 `
  -CapturePublishInventory
```

Review the candidate, copy its exact sorted file list to `packaging/windows-publish-allowlist.json`, change its status to `approved`, and commit it. The approved preflight is then:

```powershell
pwsh -NoProfile -File .\packaging\build-windows-release.ps1 `
  -PreflightUnsigned
```

It uses only the Avalonia successor, builds from committed `HEAD` with the exact .NET SDK, packages the verified seven-file Supertonic model, performs a CPU synthesis smoke, scans the publish tree, staged package, ZIP, and extracted ZIP, and emits an unsigned non-distributable ZIP plus hash-bound evidence. It deliberately does not create an MSI or sign anything. Until the literal inventory is approved, the unsigned preflight fails closed.

## Windows MSI and Authenticode contract

The checked-in installer identity is deliberately staging-only. Its UUIDv5 UpgradeCode and `SupertonicVox STAGING ONLY` manufacturer let a protected Windows runner compile an MSI without allocating the owner's production identity. `tools/windows_msi_contract.py` rejects that identity in every production or eligible path.

Validate the static contract anywhere with Python:

```sh
python3 tools/windows_msi_contract.py validate-contract
python3 tools/windows_msi_contract.py validate-policy
python3 -m unittest tools/test_windows_msi_contract.py -v
```

After the literal Windows publish allowlist is approved, capture the complete payload signing-policy candidate on Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -File .\packaging\build-windows-msi.ps1 `
  -CaptureSigningPolicy `
  -ModelCache C:\verified-model-cache\supertonic-3
```

Every payload file must then receive one human-reviewed action: owner-sign, verify an exact existing Authenticode signer, explicitly approve an unsigned PE, or hash-only non-PE. After committing an approved policy, `-BuildStagingMsi` tests WiX with the non-production identity. Production mode requires the owner-approved installer identity and signing policy to be committed at the release commit; an untracked or external replacement is rejected. It additionally requires production catalog assets and verifier baseline, source/model approval records, and a certificate-store/HSM thumbprint.

The production sequence is fixed: reject dirty or untracked release inputs, capture pre-sign hashes, apply the per-file policy, capture final hashes and sizes, reconstruct and bind the final inventory manifest, harvest the exact final tree, build the unsigned MSI, bind and pass ICE validation, sign the MSI last with SHA-256/RFC3161, and bind the final signed hash. A later release must also verify the previous MSI's regular-file status, approved owner signature/timestamp, UpgradeCode, and lower version. PFX files and password parameters are forbidden. The protected workflow never uploads or publishes the result, and its evidence remains `releaseEligible=false` until clean-machine install, offline Korean synthesis, restart, upgrade/downgrade, uninstall, and orphan-process checks are attached.

## Production catalog verification

The app supports an offline-root → signed trust manifest → active leaf → signed catalog chain. The embedded catalog in this repository is development-signed and is not a production trust root. Release builds must use externally supplied public inputs verified by `tools/CatalogReleaseVerifier`; signing keys never enter this repository or CI. See `CATALOG_TRUST_ROOT_RELEASE.md` for the custody, rotation, revocation, verification, and production-build contract.

## Optional VoxCPM2 runtime packs

The public source contains a protocol-v2 real-inference sidecar, deterministic offline pack builder and native smoke tool, but no Python runtime, model weight or release artifact. Build only from external owner-approved inputs and follow `VOXCPM2_RUNTIME_PACK_RELEASE.md`. Source tests do not close the `real-voxcpm2-runtime-packs` gate; each advertised CPU/CUDA/MPS variant needs same-commit native evidence and a signed production catalog entry.

## Public-source staging

```sh
./packaging/create-public-release-staging.sh
```

This creates a clean Git bundle and deterministic source ZIP from an explicit allowlist. Recovery documents, offline payload support, bundles, user state and legacy portable runtimes are excluded. The source ZIP must use the strict SVX profile: no prefix/trailer/interior slack, archive or member comments, data descriptors, ZIP64, unsupported flags, or unapproved extra fields; local and central records must match exactly and cover every byte. The ZIP is privacy-scanned directly after creation. The staging repository and its bundle are audited across every local Git object, including detached, reflog-only and dangling history. Builds run only in a disposable export of the frozen staging commit. A delivered-bundle clone is re-audited in temporary storage and is not shipped as a mutable output. Evidence must contain the exact sorted blocker IDs from `packaging/release-open-gates.json`; `packaging/release-gate-traceability.json` additionally maps each blocker to one owner step, canonical evidence envelope and verifier. A missing, additional, reordered, stale or prematurely cleared gate fails validation. The output remains non-public while `SOURCE_LICENSE_PENDING.md` exists.

## Production release gates

Do not upload source or installers until all of these are proven at the same immutable release commit:

1. Owner-approved public source license and model redistribution review
2. Production Ed25519 trust root, protected private-key custody and rotation/revocation drill
3. Developer ID signed, hardened, notarized and stapled DMG tested on a clean Apple Silicon machine
4. Authenticode signed MSI tested on clean Windows 10/11 x64 machines
5. Green protected Windows/macOS CI matrix and retained artifact provenance
6. VoxCPM2 completed on every advertised backend or formally removed from the v1 catalog/UI/docs

The final aggregator is `tools/final_release_evidence.py`. It accepts `releaseEligible=true` only when all 17 per-gate envelopes, the exact-candidate Terra/Fable/GPT-web review policy, and both post-sign installer identities pass at one immutable commit. The DMG/MSI hashes, contained inventories and runtime-pack fingerprints must match the protected provenance record and signed release metadata. Synthetic tests exercise the failure contract but never count as release evidence.
