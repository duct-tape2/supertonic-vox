# Security audit

Audit date: 2026-07-27. Scope: recovered C# source, VoxCPM2 sidecar, bundled Supertonic interface, dependency locks, release packaging and baseline executable. This is an engineering audit, not a penetration-test certification.

## Findings and disposition

| ID | Severity | CWE/CVE | Evidence / reproduction | Impact | Fix and verification | Residual risk |
|---|---|---|---|---|---|---|
| STV-001 | Critical | CWE-306, CWE-441 | Baseline accepted an unauthenticated service on the expected loopback port. Bind a fake health/TTS service before app start. | Local process can spoof audio or consume private text. | Fresh 256-bit token, child-only ownership, proxy-disabled client and engine/model/session health checks. C# and Python auth tests pass. | A process with debug/admin rights can inspect another process environment. |
| STV-002 | High | CWE-770, CWE-400 | Baseline buffered unrestricted HTTP output and accepted large bodies. | Memory exhaustion and UI crash. | Request ceilings, streamed bounded reads (128/512 MiB), reference ceiling 64 MiB. Oversize unit tests pass. | Model inference itself is CPU/RAM intensive. |
| STV-003 | High | CWE-20, CWE-190 | Baseline WAV parsing used signed 32-bit chunk lengths before all bounds checks. Supply malformed RIFF chunk sizes. | Overflow, invalid allocation or truncated audio processing. | Unsigned/64-bit checked arithmetic and format/channel/rate/duration checks were added before allocation. | Private Form1 WAV logic still needs a dedicated fuzz harness. |
| STV-004 | High | CWE-494 | Supertonic models were checked only for presence; portable Python/runtime files had no whole-release manifest. | Silent model/runtime replacement. | Sixteen Supertonic files and both Vox model files are SHA-256 checked; full release manifest covers every file. | Unsigned top-level EXE and scripts can still be replaced together with the manifest. Sign releases. |
| STV-005 | Medium | CWE-22 | Voice-clone reference path and user-chosen files crossed trust boundaries. | Reading unexpected files or consuming hostile WAV. | Canonical path confinement, extension/size/audio validation and explicit consent gate. Python path tests pass. | Consent is an operator assertion, not identity verification. |
| STV-006 | Medium | CWE-400 | Supertonic log was append-only. | Disk exhaustion and retention of sensitive text/errors. | 5 MiB × 3 rotation for both sidecars. C# rotation test passes. | Existing historical logs remain in `PRIVATE_USER_STATE`. |
| STV-007 | Medium | CWE-367, CWE-732 | Settings, SavedText and output WAV writes were non-atomic and output names could collide within one second. | Truncation or silent overwrite. | Same-directory temporary write plus atomic move; millisecond/collision suffix for WAV. C# tests pass. | ACLs inherit from destination directory; no encryption at rest. |
| STV-008 | Medium | CWE-200 | Full user state contains source text, generated speech, reference voices and logs. | Disclosure when an archive is shared with an external AI. | AI ZIP excludes bulk private WAV data; offline payload labels `PRIVATE_USER_STATE` and documents risk. | User requested inclusion, so confidentiality depends on storage and transfer controls. |
| STV-009 | High | CWE-1104 | Recovered C# project used direct DLL references; pip-audit reported 79 Vox and 10 Supertonic advisory records. | Vulnerable parsers/web libraries can become exploitable if exposed to untrusted traffic or hostile files. | NuGet references are locked and clean in the advisory scan; route allow-list, token, loopback and body limits reduce reachability; complete Python scan evidence is supplied. | Python upgrades remain open pending model-compatibility and real-synthesis qualification. Public/service deployment is blocked. |
| STV-010 | Medium | CWE-295/CWE-345 | Baseline and candidate executables are not Authenticode-signed. | SmartScreen warning and weak publisher/integrity assurance. | `sign.ps1` and post-sign verification procedure provided. | Open until a certificate is provisioned. |
| STV-011 | Medium | CWE-693 | The recovery host (Windows 10 build 19044) terminates the .NET 10 CET-enabled apphost with CLR exit `0x80131506`. | A default CET build is unusable on part of the stated Windows 10 target; disabling it removes hardware shadow-stack protection. | Candidate is published with `CETCompat=false` for Windows 10 compatibility; all application-layer controls remain. A CET-enabled build is recommended for a Windows 11-only release. | Reduced exploit mitigation on supported hardware; maintain a separate CET-enabled production flavor when the fleet permits. |

## Implemented control locations

- Token generation, no-proxy clients, bounded response, atomic persistence and rotation: `src/DesktopApp/TTS_WinForms_App/Services/LocalSidecarSecurity.cs`.
- Child creation, model hashes and health fingerprinting: `src/DesktopApp/TTS_WinForms_App/Form1.cs`.
- Vox middleware and limits: `src/VoxCPM2Sidecar/app/server.py`.
- Supertonic route allow-list and authentication: `src/SupertonicSidecar/secure_server.py`.
- Tests: `tests/DesktopApp.SecurityTests`, `src/VoxCPM2Sidecar/tests`, `src/SupertonicSidecar/tests`.

## Verification status at handoff

- Hardened source builds against .NET 10 reference/runtime packs.
- C# security checks: pass.
- Vox Python unit/integration tests: 9 pass.
- Supertonic middleware tests: 3 pass.
- Full file and split-part verification is recorded in the final output manifest.
- Short real-engine Korean synthesis passed for both secured sidecars. The compatibility apphost starts on this Windows 10 host; interactive playback/cancel/error-path GUI coverage remains manual.
