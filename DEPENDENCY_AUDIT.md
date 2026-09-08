# Dependency audit

## Direct application dependencies

| Component | Locked version | Source |
|---|---:|---|
| .NET SDK | 10.0.302 | `global.json` |
| .NET runtime in candidate | 10.0.10 | publish output |
| Newtonsoft.Json | 13.0.3 | `src/DesktopApp/packages.lock.json` |
| HtmlAgilityPack | 1.12.2 | `src/DesktopApp/packages.lock.json` |
| Supertonic Python package | 1.3.1 | bundled dist-info |
| VoxCPM | 2.0.3 | `src/VoxCPM2Sidecar/requirements.lock` |
| CPython | 3.12.13 | portable runtimes |
| PyTorch CPU | 2.10.0+cpu | Vox lock |

The full Python dependency set is preserved in `requirements.lock` and in the offline runtime `*.dist-info` metadata. `SBOM.cdx.json` is the machine-readable component inventory.

## Scanner execution

Machine-readable outputs are under `reports/`:

- `dotnet-list-package.json`
- `pip-audit-vox.json`
- `pip-audit-supertonic.json`
- `bandit.json`
- `secret-scan.txt`
- `defender-scan.txt`

An empty or failed scanner output is not treated as “no vulnerabilities.” See `reports/SCAN_SUMMARY.md` for command status, tool versions and any network or host limitations. Model files and private audio are not submitted to online scanners.

The 2026-07-27 scan reported no vulnerable NuGet package, but reported 79 advisory records in 14 Vox packages and 10 advisory records in 2 Supertonic packages. Those Python runtime findings remain open pending compatibility-qualified upgrades; see the scan summary for affected versions and minimum fixes.

## Upgrade policy

Use locked, reviewed updates. Re-run unit tests, both real synthesis tests, audio format checks, file-manifest generation and license review after every model/runtime upgrade. Preserve the exact Vox revision and Supertonic local model manifest revision in health responses.
