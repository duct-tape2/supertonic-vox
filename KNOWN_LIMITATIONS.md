# Known limitations

- The recovered `Form1.cs` is approximately 4,600 lines and still contains decompiler-style names and some mojibake strings. It builds, but UI text must be compared visually with the baseline before public release.
- The handoff host is Windows 10 build 19044. The .NET 10 compiler required a documented Roslyn 8 host workaround. The released apphost uses `CETCompat=false` to support this Windows target, reducing hardware shadow-stack protection; publish a CET-enabled flavor for Windows 11-only fleets.
- Real secured Supertonic and VoxCPM2 short Korean synthesis passed. Interactive GUI playback, cancellation, timeout, missing-model, memory-pressure and server-collision scenarios were not all exhaustively automated on this host.
- C# tests cover security helpers; private WAV parsing and Korean pronunciation rules remain tightly coupled to the form and need extraction plus fuzz/regression suites.
- The executable is unsigned. The file manifest detects accidental or targeted changes only if the manifest itself remains trusted.
- The offline payload contains private user state by explicit request and is not encrypted.
- CPU operation and at least 32 GB RAM are assumed. CUDA/GPU packaging is not included.
- The recovered WinForms candidate has no installer/updater. The Avalonia successor now implements signed-catalog Vox runtime-pack install, side-by-side update/rollback and stop-before-uninstall, but the checked-in development catalog intentionally contains no downloadable Vox artifact. No telemetry service, crash upload or multi-user service mode is provided.
- Supertonic’s exact upstream download commit is not locally provable; the local SHA-256 model revision is authoritative.
- Historical Supertonic smoke evidence is internally inconsistent: `reports/FINAL_PAYLOAD_VALIDATION.md` and `reports/real-engine-supertonic.json` record different WAV SHA-256 values. Re-run on Windows and treat health/audio-format assertions—not an unexplained WAV hash—as the gate until reconciled.
