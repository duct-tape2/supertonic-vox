# Architecture

```text
WinForms UI (single owner process)
  ├─ text normalization, pronunciation, WAV merge/playback, persistence
  ├─ starts Supertonic child with token + session + model revision
  │    └─ secure_server.py → bundled supertonic 1.3.1 → ONNX models
  └─ starts Vox child with token + session + fixed model revision
       └─ server.py → voxcpm 2.0.3 → safetensors + AudioVAE
```

Both HTTP links are loopback-only. The desktop app uses a proxy-disabled client, sends the token header, streams responses into bounded buffers and rejects a mismatched session/engine/model fingerprint.

## Trust boundaries

1. **User/UI boundary:** text and reference audio are untrusted. Paths must remain under the designated voice directory and WAV structure is validated.
2. **Local HTTP boundary:** another local process can bind a port or send traffic. Ports are selected only for newly launched children, and cryptographic per-launch credentials are mandatory.
3. **Model/runtime boundary:** portable binaries and weights are executable or high-impact assets. The release manifest covers them; both model families also have explicit hashes.
4. **Persistence boundary:** settings, SavedText, logs and WAV output may contain private material. Writes are atomic and output names are collision-safe; the payload labels them `PRIVATE_USER_STATE`.

## Ports and routes

- Supertonic: first free port in 7788–7798; only `GET /v1/health` and `POST /v1/tts`.
- VoxCPM2: first free port in 7800–7810; only `GET /v1/health`, `GET /v1/presets` and `POST /v1/tts`.
- Docs, OpenAPI, style imports and arbitrary routes are hidden or rejected.

## Resource ceilings

- Vox request: 16 KiB; response: 128 MiB.
- Supertonic request: 256 KiB; response: 512 MiB.
- Voice-clone reference WAV: 64 MiB.
- Sidecar logs: 5 MiB with three backups.
