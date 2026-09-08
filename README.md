# Supertonic Vox

An open-source Windows desktop front-end integrating public open-source TTS engines in one window: Higgs Audio v3 (main), Supertonic 3, and VoxCPM2. All engines run locally with no cloud connection and no telemetry.

## Status

v0.2.0 with Higgs Audio v3 support added. Higgs is now the primary engine; Supertonic 3 and VoxCPM2 are lighter-weight alternatives for testing and fallback.

## What it does

- Runs Higgs Audio v3 TTS (primary engine), Supertonic 3 (OpenRAIL-M, ONNX), and VoxCPM2 (Apache-2.0, Python sidecar) locally
- Hardware profiling and deterministic engine recommendation
- Korean text synthesis, playback, cancellation, atomic WAV save
- No network calls during synthesis; models download on first run only
- File-hash verification for engine catalogs
- No telemetry, no manuscript or audio upload, no crash reporting

## Requirements

- **Windows 10 or later**, x64 CPU
- **.NET SDK 10.0.302** or later ([download](https://dotnet.microsoft.com/download))
- **Python 3.10+** (for VoxCPM2 sidecar; see `src/VoxCPM2Sidecar/requirements.lock`)
- **Higgs Audio v3 runtime** (optional, for primary engine; see [HIGGS_ENGINE.md](docs/HIGGS_ENGINE.md))
  - 5.1 GB GGUF model (q8_0 quantization)
  - audio.cpp server (CPU or CUDA)
  - Minimum 12 GB available commit memory recommended
- Supertonic 3: ~380 MB model
- VoxCPM2: ~4.6 GB model (downloaded on first run)

## Build

```powershell
# Restore and build the WinForms desktop app
.\build.ps1 -Configuration Release

# Or manually:
dotnet restore src\DesktopApp\TTS_WinForms_App.csproj --locked-mode
dotnet build src\DesktopApp\TTS_WinForms_App.csproj -c Release --no-restore
```

See `BUILD_AND_RELEASE.md` for cross-platform .NET 10 successor (Avalonia) and platform-specific procedures.

## Package

```powershell
# Create self-contained Win x64 executable
.\package.ps1 -Configuration Release

# Output: artifacts\publish\SupertonicVox.exe
```

## First run

1. Start the application
2. Select an engine: Higgs Audio v3 (primary), Supertonic 3, or VoxCPM2
3. For Higgs, install the runtime per [HIGGS_ENGINE.md](docs/HIGGS_ENGINE.md); for other engines, models download on demand
4. Synthesis begins once runtime/models are ready

No installation or administrator privileges required—the executable is standalone.

## Engines

| Engine | Params | Model format | Hardware | Languages | Quality notes | License |
|--------|--------|--------------|----------|-----------|---------------|---------|
| **Higgs Audio v3** | ~4B decoder / ~5B total | GGUF q8_0 (5.1 GB) | CUDA GPU or CPU | 102+ | Primary engine, best quality in listening tests | Boson Research + Non-Commercial, Creator Use Grant (credited use) |
| **Supertonic 3** | ~99M | ONNX Runtime | CPU only | 31 | Lightweight, fast | OpenRAIL-M |
| **VoxCPM2** | 2B | PyTorch (sidecar) | CPU only | 30 | Experimental | Apache-2.0 |

**Quality**: The three engines are not benchmarked on a shared test set. Published metrics use different datasets. In the owner's listening tests, Higgs Audio v3 produces the most natural Korean synthesis.

See [HIGGS_ENGINE.md](docs/HIGGS_ENGINE.md) for Higgs Audio v3 setup, GPU/CPU selection, and voice configuration.

## Known limitations

- The recovered `Form1.cs` (main UI) is ~4,600 lines and contains decompiler-style variable names and some text encoding artifacts. Builds and runs, but visual UI text should be compared against the baseline before any public release.
- Tested on Windows 10 build 19044 with workarounds for .NET compiler host compatibility.
- Interactive playback, cancellation, timeout, and memory-pressure scenarios were not exhaustively automated on this host.
- C# security helpers are tested; Korean pronunciation rules remain tightly coupled to the form and need extraction.
- The executable is unsigned. File-manifest verification requires the manifest to remain trusted.
- No installer or updater. The Avalonia successor now includes signed-catalog runtime-pack install, side-by-side update/rollback, and stop-before-uninstall (see `BUILD_AND_RELEASE.md`).
- Supertonic model provenance cannot be locally verified; the SHA-256 hash in `MODEL_PROVENANCE.md` is authoritative.
- Higgs Audio v3 GPU/CPU selection is automatic; manual override via code modification only.

## Screenshots

(To be added by maintainer)

## Contributing

Contributions are welcome. Open an issue or PR for bug reports, improvements, or features.

## License

Application source code: **MIT** (see `LICENSE`)

Third-party components retain their own licenses:
- **Higgs Audio v3 model**: Boson Higgs TTS 3 Research and Non-Commercial License
  - Requires separate download from https://huggingface.co/audio-cpp/audio.cpp-gguf
  - Creator Use Grant: free for credited monetized content ("Boson AI's Higgs Audio")
  - Products and hosted APIs require separate agreement; cloning without consent prohibited
- **Supertonic 3 model**: BigScience Open RAIL-M (see `licenses/Supertonic-3_OpenRAIL.txt`)
  - Model weights are downloaded at runtime, not shipped with this source.
  - Use-based restrictions apply to anyone downloading the weights.
- **VoxCPM2 model**: Apache-2.0 (see `licenses/VoxCPM_Apache-2.0.txt`)
  - Model weights are downloaded at runtime.
- **Supertonic Python package**: MIT (see `licenses/Supertonic-Python_MIT.txt`)

See `THIRD_PARTY_NOTICES.md` for full attribution.

Models are verified by SHA-256 hash on download (see `MODEL_PROVENANCE.md`).

---

# 한글 섹션

**Supertonic Vox** 는 오프라인 한국어 TTS 윈도우 데스크톱 애플리케이션입니다. 클라우드 연결 없이 로컬에서 Supertonic 3 과 VoxCPM2 엔진을 실행합니다. 사용자 데이터를 수집하지 않습니다.

v0.1.0 소스 릴리스입니다. 2026-07-27 버전 2.0.0 데스크톱 바이너리에서 복구된 코드베이스이며, 개발자의 2.3.0 CUDA 빌드는 별도 저장소에 있습니다.

- Windows x64 전용
- .NET SDK 10.0.302+, Python 3.10+
- 첫 실행 시 모델 자동 다운로드 (~4.9 GB)
- 인터넷 없이 합성 실행
- MIT 라이선스 (모델은 별도 라이선스: OpenRAIL-M, Apache-2.0)

자세한 내용은 영어 문서를 참고하세요.
