# VoxCPM2 protocol-v2 runtime-pack release

Status: source and contract test procedure only. `releaseEligible=false`; no production pack has been built, signed, licensed or benchmarked.

## Inputs held outside Git

Prepare all paths on the native target OS. Every input must be a regular, single-link file tree with no cache/log/user directories. Empty Python runtime/package markers are retained and hashed; sidecar source, presets, lock, provenance, model, entrypoint and license inputs must be nonempty.

- clean portable CPython 3.12 x64 (Windows) or arm64 (macOS)
- `requirements.lock` dependency tree, including `psutil==5.9.8`
- official VoxCPM2 revision `bffb3df5a29440629464e5e839f4d214c8714c3d`
- `model.safetensors`: 4,580,080,592 bytes, SHA-256 `f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d`
- `audiovae.pth`: 376,951,122 bytes, SHA-256 `94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1`
- owner-approved code/model/runtime license and notice files

The builder has no downloader. Obtain official inputs separately, pin their revision, record URL/revision/hash in retained provenance, scan them, and keep them out of the source workspace.

The dependency directory must match every `name==version` entry in `requirements.lock` exactly through its `.dist-info/METADATA`. Missing, additional, duplicate or version-mismatched distributions fail the build; do not reuse a general-purpose Python environment.

`runtime-pack.json` is compact and hard-limited to 8 MiB. The bound is deliberate: the measured 39,921-file legacy inventory needs 6,105,338 bytes in the strict v2 shape, while the legacy 12,616,232-byte pretty manifest remains too large and is rejected. Do not raise or bypass the bound without a new reviewed contract.

The measured payload also contains 1,065 legitimate zero-byte Python package markers. The builder keeps each as an explicit size-0 entry with SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; do not delete or rewrite them to satisfy packaging.

## Windows x64 CPU pack

Run in PowerShell 7 from an immutable source commit:

```powershell
$Work = 'C:\SVX-VoxCPM2-Pack'
New-Item -ItemType Directory -Force -Path $Work | Out-Null
python .\tools\build_voxcpm2_runtime_pack.py `
  --platform windows --architecture x64 --backend cpu `
  --python-runtime 'C:\ApprovedInputs\python' `
  --site-packages 'C:\ApprovedInputs\site-packages' `
  --model-root 'C:\ApprovedInputs\VoxCPM2' `
  --license-file 'C:\ApprovedInputs\licenses\VoxCPM-LICENSE.txt' `
  --license-file 'C:\ApprovedInputs\licenses\Python-LICENSE.txt' `
  --destination "$Work\voxcpm2-win-x64-cpu.partial"

dotnet run --project .\tools\VoxRuntimePackSmoke\VoxRuntimePackSmoke.csproj -c Release --no-restore -- `
  "$Work\voxcpm2-win-x64-cpu.partial" `
  "$Work\voxcpm2-win-x64-cpu" `
  "$Work\data-cpu" `
  "$Work\voxcpm2-win-x64-cpu.wav" |
  Tee-Object "$Work\voxcpm2-win-x64-cpu-smoke.json"

python .\tools\package_voxcpm2_runtime_pack.py `
  --pack-root "$Work\voxcpm2-win-x64-cpu" `
  --output "$Work\voxcpm2-win-x64-cpu.svxpack.tar" `
  --metadata-output "$Work\voxcpm2-win-x64-cpu.catalog-artifact.json"
```

For CUDA, repeat with a separately pinned CUDA dependency tree, `--backend cuda`, a new destination/data/output path, NVIDIA driver inventory and at least 8 GiB VRAM. Never relabel a CPU pack as CUDA.

## Apple Silicon CPU/MPS packs

```sh
set -eu
work="$HOME/SVX-VoxCPM2-Pack"
mkdir -p "$work"

python3 tools/build_voxcpm2_runtime_pack.py \
  --platform macos --architecture arm64 --backend cpu \
  --python-runtime /ApprovedInputs/python-arm64 \
  --site-packages /ApprovedInputs/site-packages-cpu \
  --model-root /ApprovedInputs/VoxCPM2 \
  --license-file /ApprovedInputs/licenses/VoxCPM-LICENSE.txt \
  --license-file /ApprovedInputs/licenses/Python-LICENSE.txt \
  --destination "$work/voxcpm2-macos-arm64-cpu.partial"

dotnet run --project tools/VoxRuntimePackSmoke/VoxRuntimePackSmoke.csproj \
  -c Release --no-restore -- \
  "$work/voxcpm2-macos-arm64-cpu.partial" \
  "$work/voxcpm2-macos-arm64-cpu" \
  "$work/data-cpu" \
  "$work/voxcpm2-macos-arm64-cpu.wav" \
  | tee "$work/voxcpm2-macos-arm64-cpu-smoke.json"

python3 tools/package_voxcpm2_runtime_pack.py \
  --pack-root "$work/voxcpm2-macos-arm64-cpu" \
  --output "$work/voxcpm2-macos-arm64-cpu.svxpack.tar" \
  --metadata-output "$work/voxcpm2-macos-arm64-cpu.catalog-artifact.json"
```

For MPS, repeat with an arm64 PyTorch/MPS dependency tree and `--backend mps`. The sidecar fails before model loading if MPS is unavailable. A successful CPU pack says nothing about MPS eligibility.

The package command writes the app's strict `UstarV1` profile: `runtime-pack.json` first, then the sorted manifest inventory, regular files only, deterministic owner/mode/time fields, exact zero padding, exactly two terminal zero blocks, and no extensions or trailer. It verifies every source size/SHA/link before writing and emits catalog-ready extracted manifest SHA, pack fingerprint, count and byte totals plus archive size/SHA. Add `--download-uri` only when the immutable approved GitHub Release or fixed Hugging Face URL is known; the command rejects other origins and never invents a placeholder URL.

## Required retained evidence per variant

1. immutable source commit and clean status; builder/tool hashes and locked restore/build/test logs
2. input provenance, license approval, malware/dependency scan, model sizes/SHA-256
3. final `runtime-pack.json`, its SHA-256, full inventory and pack fingerprint
4. smoke JSON and WAV; 48 kHz mono PCM16, nonzero duration, cold start, synthesis time and RTF
5. listener PID ownership, wrong-token 401, hidden 404, oversized 413 before inference
6. cancellation/timeout, parent exit and app close leave no listener/orphan; owner data is outside the read-only pack
7. RAM/VRAM peak, disk use and clean standard-user install/update/uninstall behavior
8. `.catalog-artifact.json` and signed catalog bind archive profile/size/SHA plus exact extracted manifest SHA, pack fingerprint, file count, byte total, protocol, platform, architecture and backend

Do not publish or mark the engine available while `real-voxcpm2-runtime-packs`, model redistribution, source license, catalog trust, signing, CI or clean-machine gates remain open. Supertonic 3 stays the default fallback on every failure.
