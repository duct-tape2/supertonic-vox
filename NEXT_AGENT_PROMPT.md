# Prompt for the next Codex or Claude task

You are continuing a recovered and hardened Windows WinForms application named **Supertonic + VoxCPM2**.

Read `AI_START_HERE.md`, `CURRENT_STATE_INVENTORY.md`, `ARCHITECTURE.md`, `SECURITY_AUDIT.md`, `BUILD_AND_RELEASE.md`, `WINDOWS_RELEASE_CHECKLIST.md`, `MODEL_PROVENANCE.md`, `KNOWN_LIMITATIONS.md`, and the Git history before editing. Treat commit `recovered-baseline` as evidence and `hardened-candidate` as the working candidate. Do not invent older history.

Preserve these non-negotiable controls: loopback-only child-owned sidecars; new 256-bit token per launch; `X-Local-TTS-Token` on every request; no proxy; engine/model/session fingerprinting; bounded requests/responses; pre-allocation WAV validation; SHA-256 model verification; rotating logs; atomic writes; collision-safe output names.

The large offline payload contains models, Python runtimes and `PRIVATE_USER_STATE`. Do not upload those files externally. Restore it to a local path with Korean characters and spaces, verify `FILE_MANIFEST_SHA256.json`, then run tests. Use .NET 10 LTS on a fully updated Windows 11 x64 host. This handoff was compiled on an older Windows 10 host with a documented Roslyn 8 compiler-host workaround because the .NET 10 compiler apphost required CET support not available there.

Current highest-value follow-ups:

1. Run the complete GUI and both real synthesis smoke tests on a fully patched Windows 11 machine.
2. Refactor the 4,600-line `Form1.cs` into services and add tests for WAV parsing, pronunciation rules, cancellation and process ownership.
3. Replace the recovered mojibake/decompiler text where it remains, comparing against the baseline executable resources.
4. Resolve dependency-scanner findings in `DEPENDENCY_AUDIT.md` without changing model behavior.
5. Add an Authenticode certificate through `sign.ps1`; never commit or package private keys.

Finish by updating audits, test evidence, SBOM, full file manifest and `project.bundle`.
