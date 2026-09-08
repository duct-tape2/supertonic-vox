# Windows release checklist

## Successor MSI contract status (2026-07-29)

The cross-platform successor now contains a WiX 7 and Authenticode release contract, but no native MSI evidence. The committed UpgradeCode/manufacturer are staging-only and are rejected by production validation.

Mac-safe contract checks:

```sh
python3 tools/windows_msi_contract.py validate-contract
python3 tools/windows_msi_contract.py validate-policy
python3 -m unittest tools/test_windows_msi_contract.py -v
```

Required Windows order:

1. Capture and approve `packaging/windows-publish-allowlist.json`.
2. Run `build-windows-msi.ps1 -CaptureSigningPolicy`; review every path, hash, origin, signer constraint and approval.
3. Commit the approved complete signing policy.
4. Run `-BuildStagingMsi`; retain noneligible MSI/ICE/payload evidence.
5. Supply an owner-approved non-staging UpgradeCode/manufacturer, verified production catalog assets, source/model approval records and certificate-store/HSM identity.
6. Commit the owner-approved installer identity and complete signing policy, then run `-BuildProductionMsi`; it rejects untracked release inputs, signs approved PE entries, verifies existing signers, reconstructs the final payload manifest, builds and ICE-validates the unsigned MSI, signs the MSI last, and still records `releaseEligible=false`.
7. On clean Windows 10/11 x64, attach install, standard-user offline Korean synthesis/save/restart, first-release or upgrade/downgrade, uninstall, user-data preservation and no-orphan-process evidence.

Do not use PFX/password arguments and do not upload either staging or production candidates before all canonical release gates close.

This is the release gate for the recovered Supertonic + VoxCPM2 application. Run it on a fully patched Windows 11 x64 machine with at least 32 GB RAM and 20 GB free space. Keep the offline payload and all `PRIVATE_USER_STATE` local and owner-controlled.

## 1. Verify the handoff and host

Open 64-bit PowerShell and set paths that contain no repository secrets:

```powershell
$ErrorActionPreference = 'Stop'
$Repo = 'C:\SVX\handoff'
$Payload = 'C:\SVX_Extracted\Supertonic + VoxCPM2'
$Evidence = Join-Path $Repo 'release-evidence'
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
Set-Location $Repo

git fsck --full --strict
git bundle verify .\project.bundle
$Baseline = '3d828d2aa0a045a1f19ab838b598ebc7624d58b7'
$Candidate = 'e67165fb7bc2c9dc6c871975e725203e38f07b61'
if ((git show -s --format='%H %s' $Baseline).Trim() -ne "$Baseline recovered-baseline") {
  throw 'Recovered baseline commit contract mismatch.'
}
if ((git show -s --format='%H %s' $Candidate).Trim() -ne "$Candidate hardened-candidate") {
  throw 'Hardened candidate commit contract mismatch.'
}
if ((git show -s --format='%P' $Candidate).Trim() -ne $Baseline) {
  throw 'Hardened candidate parent was rewritten.'
}
git merge-base --is-ancestor $Candidate HEAD
if ($LASTEXITCODE -ne 0) { throw 'Release HEAD is not a continuation of hardened-candidate.' }

$Sdk = [version](dotnet --version)
if ($Sdk.Major -ne 10 -or $Sdk -lt [version]'10.0.302') {
  throw "Use .NET SDK 10.0.302 or a newer .NET 10 servicing SDK; found $Sdk."
}
dotnet --info | Set-Content -Encoding utf8 (Join-Path $Evidence 'dotnet-info.txt')
```

Verify/extract all payload parts at a short path before using them:

```powershell
Set-Location 'C:\SVX\payload-parts'
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify_and_extract.ps1 `
  -Destination 'C:\SVX_Extracted'
```

Required result: every numbered part, the combined archive, and all 45,835 manifest entries pass. Do not proceed on a missing scanner, hash mismatch, unexpected file, or partial extraction.

## 2. Locked build and automated tests

The portable Python paths below come from the verified payload. Do not run the Windows runtimes from macOS.

```powershell
Set-Location $Repo
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 2>&1 |
  Tee-Object (Join-Path $Evidence 'build.txt')
if ($LASTEXITCODE -ne 0) { throw "build.ps1 failed with exit code $LASTEXITCODE." }

$VoxPython = Join-Path $Payload '_internal\VoxCPM2Local\python\python.exe'
$VoxPackages = Join-Path $Payload '_internal\VoxCPM2Local\pkgs'
$SuperPython = Join-Path $Payload '_internal\SupertonicLocal\python\cpython-3.12.13-windows-x86_64-none\python.exe'
$SuperPackages = Join-Path $Payload '_internal\SupertonicLocal\.venv\Lib\site-packages'
powershell -NoProfile -ExecutionPolicy Bypass -File .\test.ps1 `
  -VoxPython $VoxPython -VoxPackages $VoxPackages `
  -SupertonicPython $SuperPython -SupertonicPackages $SuperPackages 2>&1 |
  Tee-Object (Join-Path $Evidence 'tests.txt')
if ($LASTEXITCODE -ne 0) { throw "test.ps1 failed with exit code $LASTEXITCODE." }

powershell -NoProfile -ExecutionPolicy Bypass -File .\package.ps1 2>&1 |
  Tee-Object (Join-Path $Evidence 'publish.txt')
if ($LASTEXITCODE -ne 0) { throw "package.ps1 failed with exit code $LASTEXITCODE." }
```

Required result: locked restore/build succeeds; C# security checks, nine Vox tests, and three Supertonic tests pass. A compiler/analyzer-version workaround is not acceptable for the Windows 11 production build.

## 3. Stage, sign, then generate the manifest

Never build over the only payload copy. Restore a copied tree to the documented baseline, preserve `baseline-overlay`, and apply every hardened replacement—not only the EXE:

```powershell
$Stage = 'C:\SVX_Release\Supertonic + VoxCPM2'
if (Test-Path -LiteralPath $Stage) { throw "Use a new empty staging path: $Stage" }
Copy-Item -LiteralPath $Payload -Destination $Stage -Recurse
powershell -NoProfile -ExecutionPolicy Bypass -File `
  (Join-Path $Stage 'baseline-overlay\restore_baseline.ps1')

Copy-Item -LiteralPath (Join-Path $Repo 'artifacts\publish\Supertonic + VoxCPM2.exe') `
  -Destination (Join-Path $Stage 'Supertonic + VoxCPM2.exe') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'src\SupertonicSidecar\secure_server.py') `
  -Destination (Join-Path $Stage '_internal\SupertonicLocal\app\secure_server.py') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'src\VoxCPM2Sidecar\app\server.py') `
  -Destination (Join-Path $Stage '_internal\VoxCPM2Local\app\server.py') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'src\VoxCPM2Sidecar\app\voxcpm_low_memory.py') `
  -Destination (Join-Path $Stage '_internal\VoxCPM2Local\app\voxcpm_low_memory.py') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'src\VoxCPM2Sidecar\run_server.ps1') `
  -Destination (Join-Path $Stage '_internal\VoxCPM2Local\run_server.ps1') -Force

$HandoffDocs = Join-Path $Stage 'HANDOFF_DOCS'
New-Item -ItemType Directory -Force -Path $HandoffDocs | Out-Null
$RootDocs = @(
  'AI_START_HERE.md', 'ARCHITECTURE.md', 'BUILD_AND_RELEASE.md',
  'CURRENT_STATE_INVENTORY.md', 'DEPENDENCY_AUDIT.md', 'KNOWN_LIMITATIONS.md',
  'MIGRATION_TO_NEW_PC.md', 'MODEL_PROVENANCE.md', 'PRIVACY_AND_USER_DATA.md',
  'SECURITY_AUDIT.md', 'THIRD_PARTY_NOTICES.md', 'WINDOWS_RELEASE_CHECKLIST.md',
  'SBOM.cdx.json'
)
foreach ($Name in $RootDocs) {
  Copy-Item -LiteralPath (Join-Path $Repo $Name) -Destination $HandoffDocs -Force
}
New-Item -ItemType Directory -Force -Path (Join-Path $HandoffDocs 'diagnostics') | Out-Null
Copy-Item -Path (Join-Path $Repo 'src\VoxCPM2Sidecar\diagnostics\*') `
  -Destination (Join-Path $HandoffDocs 'diagnostics') -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $HandoffDocs 'licenses') | Out-Null
Copy-Item -Path (Join-Path $Repo 'licenses\*') `
  -Destination (Join-Path $HandoffDocs 'licenses') -Recurse -Force
New-Item -ItemType Directory -Force -Path (Join-Path $HandoffDocs 'reports') | Out-Null
Copy-Item -Path (Join-Path $Repo 'reports\*') `
  -Destination (Join-Path $HandoffDocs 'reports') -Recurse -Force
Copy-Item -LiteralPath (Join-Path $Repo 'packaging\HARDENED_RELEASE_NOTICE.txt') `
  -Destination (Join-Path $Stage 'HARDENED_RELEASE_NOTICE.txt') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'packaging\PRIVATE_USER_STATE_NOTICE.txt') `
  -Destination (Join-Path $Stage 'PRIVATE_USER_STATE_NOTICE.txt') -Force
Copy-Item -LiteralPath (Join-Path $Repo 'PRIVATE_USER_STATE_INDEX.json') `
  -Destination (Join-Path $Stage 'PRIVATE_USER_STATE_INDEX.json') -Force

$AddedList = Join-Path $Stage 'baseline-overlay\ADDED_HARDENED_FILES.txt'
$AddedLines = @(Get-Content -LiteralPath $AddedList)
foreach ($Relative in @(
  'HANDOFF_DOCS\WINDOWS_RELEASE_CHECKLIST.md',
  'HANDOFF_DOCS\reports\MACOS_HANDOFF_VERIFICATION_2026-07-27.md'
)) {
  if ($Relative -notin $AddedLines) { $AddedLines += $Relative }
}
$AddedLines | Set-Content -LiteralPath $AddedList -Encoding utf8
```

The copied `PRIVATE_USER_STATE_INDEX.json` is valid only if private state is unchanged from the verified handoff. If it changed, regenerate the index locally before continuing. A stale private-state index or baseline overlay blocks release.

Sign the staged EXE before generating `FILE_MANIFEST_SHA256.json`. Prefer a certificate-store/key-provider certificate so no PFX password is exposed to child-process arguments:

```powershell
$Exe = Join-Path $Stage 'Supertonic + VoxCPM2.exe'
powershell -NoProfile -ExecutionPolicy Bypass -File .\sign.ps1 `
  -File $Exe -CertificateThumbprint '<CERTIFICATE_THUMBPRINT>'
signtool.exe verify /pa /all /v $Exe 2>&1 |
  Tee-Object (Join-Path $Evidence 'authenticode.txt')
if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed with exit code $LASTEXITCODE." }

$SourceEpoch = git -C $Repo show -s --format=%ct HEAD
python .\packaging\generate_file_manifest.py $Stage `
  (Join-Path $Stage 'FILE_MANIFEST_SHA256.json') --workers 8 `
  --source-epoch $SourceEpoch
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-release.ps1 `
  -ReleaseRoot $Stage 2>&1 | Tee-Object (Join-Path $Evidence 'manifest-verify.txt')
if ($LASTEXITCODE -ne 0) { throw "verify-release.ps1 failed with exit code $LASTEXITCODE." }
```

Required result: `Get-AuthenticodeSignature $Exe` reports `Valid`, the timestamp is present, and a clean manifest verification passes. Any post-manifest change requires regenerating and rechecking the manifest.

## 4. Real engines and GUI

Run both authenticated sidecars from the staged tree with fresh random tokens/session IDs, fixed model revisions, loopback ports, offline environment flags, proxy-disabled probes and bounded WAV reads:

```powershell
Set-Location $Repo
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-real-engine-validation.ps1 `
  -PayloadRoot $Stage -EvidenceDirectory (Join-Path $Evidence 'real-engines')
if ($LASTEXITCODE -ne 0) { throw "Real-engine validation failed with exit code $LASTEXITCODE." }
```

Run the command as shown in a disposable `powershell -File` process. The token exists in that validation process environment and is inherited by its sidecar/probe children, but is never placed on a command line or written to evidence. The script asserts exact listener PID ownership, model revision/session/rate, wrong-token 401, hidden-docs 404 and oversized-request 413 behavior; it self-tests rejection of pre-bound validation ports, writes local JSON/WAV evidence and verifies owned-process/port shutdown. Then confirm:

1. Supertonic health reports engine `supertonic`, model `supertonic-3`, revision `0d6a2bed57a1c6ec4f7acf77d688c62337655dd1db2a5582b2b2d55c17f5efae`; output is mono PCM16 at 44.1 kHz.
2. Vox health reports engine `voxcpm2`, revision `bffb3df5a29440629464e5e839f4d214c8714c3d`, `model_loaded=true`; output is mono PCM16 at 48 kHz.
3. The desktop app skips/rejects a port occupied by another process and never trusts it without the token/session/model fingerprint. The validation script independently enforces listener PID ownership and refuses occupied test ports.
4. The GUI covers Supertonic and Vox generation, playback, cancellation, timeout, missing model, port collision, memory pressure, unique filenames, and restart/close without orphaned child processes.
5. Compare remaining mojibake/UI resources against the baseline executable and record every intentional difference.

Do not treat an audio SHA-256 as deterministic unless the engine and seed contract guarantees it. `reports/FINAL_PAYLOAD_VALIDATION.md` and `reports/real-engine-supertonic.json` currently contain different Supertonic WAV hashes; the new Windows evidence must reconcile or explicitly explain that discrepancy.

## 5. Scan, split, and release gate

For the Avalonia successor's optional VoxCPM2 engine, do not copy the legacy `_internal\VoxCPM2Local` tree. Build and activate a separate Windows x64 protocol-v2 pack with the commands in `VOXCPM2_RUNTIME_PACK_RELEASE.md`, then retain the smoke JSON/WAV, Defender/dependency scans, listener ownership, cancellation/orphan and CPU/CUDA benchmark evidence. This successor pack remains a release blocker until its source commit, manifest SHA-256 and signed catalog artifact are identical across the retained evidence.

Re-run NuGet advisory scan, `pip-audit` for both portable environments, Bandit, a local secret scan, and Microsoft Defender (or an approved offline malware scanner). A scanner failure is a failure, not a clean result. The current 79 Vox and 10 Supertonic advisory records block public/untrusted multi-user deployment until compatibility-qualified upgrades pass both real synthesis tests.

Create the final Zip64 split payload only after all checks:

```powershell
$Out = 'C:\SVX_Release\parts'
powershell -NoProfile -ExecutionPolicy Bypass -File .\packaging\create_split_payload.ps1 `
  -StagingRoot $Stage -OutputDirectory $Out `
  -SevenZip 'C:\Program Files\7-Zip\7z.exe'
```

Copy `verify_and_extract.ps1`, both macOS scripts, `PARTS_MANIFEST.json`, `PARTS_SHA256.txt`, the extraction launcher, and licensed 7-Zip support files beside the parts. Verify a fresh extraction at a new short path and rerun `verify-release.ps1`. Release only when the signed EXE, all automated tests, two real synthesis tests, GUI checklist, dependency/malware scans, manifests, licenses, rollback overlay and `project.bundle` have current passing evidence.
