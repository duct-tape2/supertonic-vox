# Privacy and user data

The offline payload intentionally contains the current settings, SavedText, logs, VoiceSamples, GeneratedAudio, imported reference WAV files and caches. These are marked `PRIVATE_USER_STATE`.

Those files may reveal:

- scripts, names, account or business information typed for synthesis;
- a speaker’s biometric voice characteristics;
- generated speech and pronunciation experiments;
- file paths, timestamps, errors and machine details in logs.

Do not upload the offline payload, its file manifest, logs or voice files to Codex, Claude, cloud storage or ticketing systems unless the data owner has approved that transfer. The AI handoff ZIP contains source and file metadata but does not duplicate large private WAV files.

The application is local-only and has no intended telemetry or cloud inference path. Network-independent operation is enforced for the bundled model stacks. Local data is not encrypted by the application; use encrypted storage and access controls where needed.

Voice cloning must be used only for the operator’s own voice or with the speaker’s explicit authorization and consent. The UI asks for confirmation on first import, but the operator remains responsible for retention, disclosure and downstream use.
