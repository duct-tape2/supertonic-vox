# macOS release checklist

Status: the Developer ID, dual-notarization and stapling contract is implemented, but no signed candidate has been produced. The checked-in identity and signing policy are deliberately staging/capture placeholders and production validation rejects them.

## 1. Capture and approve the exact payload

Run on a protected Apple Silicon macOS host with the verified model cache:

```sh
./packaging/build-macos-release.sh \
  --capture-signing-policy \
  --offline-models \
  --model-cache /absolute/path/to/verified/supertonic-3
```

Review every normalized file. Multi-slice `arm64`, `arm64e` and `x86_64` Mach-O inputs must be recorded and thinned to exactly `arm64` before the signing inventory is captured. Commit the complete owner-approved policy and the Developer ID Application leaf SHA-256, normalized subject, Team ID and approval ID. Never bypass a native runtime failure by adding an entitlement directly in the script; revise and review the contract first.

## 2. Protected signed-candidate run

Use `.github/workflows/macos-release.yml`. It creates a temporary keychain, imports the Developer ID certificate, stores the notary profile in that exact keychain, signs nested code deepest-first, and deletes the keychain in an `always()` cleanup. It never uploads or publishes the DMG.

Required order:

1. Sign and strictly verify the app with hardened runtime and the checked-in allow-JIT-only entitlements.
2. Submit a `ditto --keepParent` app ZIP and require notarization status `Accepted`.
3. Staple and validate the app, then strictly verify it again.
4. Build the DMG from the stapled app, sign the DMG, submit it separately, and require `Accepted`.
5. Staple/validate the DMG, mount it read-only, assess the shipped app and primary DMG signature, and run both privacy scans.

The output name contains `SIGNED-NOT-RELEASE-ELIGIBLE`. Both notarization submission IDs, all stage hashes and the exact 17 open gates must remain in evidence.

## 3. Quarantined clean-account validation

Copy the final stapled DMG to a clean standard-user account without launching it. Apply and verify quarantine before mounting so Gatekeeper is actually exercised:

```sh
xattr -w com.apple.quarantine '0081;00000000;SupertonicVoxReleaseTest;' SupertonicVox-*.dmg
xattr -p com.apple.quarantine SupertonicVox-*.dmg
open SupertonicVox-*.dmg
```

Record all of the following against the same DMG SHA-256:

1. Gatekeeper permits the first launch of the app dragged from the quarantined DMG.
2. Supertonic 3 synthesizes Korean fully offline; playback and atomic save succeed.
3. Restart preserves settings and the app leaves no sidecar or orphan process.
4. Removing the app does not delete `~/Library/Application Support/SupertonicVox` or `~/Documents/SupertonicVox`.
5. A later release upgrades only from a lower, signed/notarized/stapled baseline with the same bundle ID and Team ID; first release records upgrade as not applicable.

## 4. Publication gate

If the optional VoxCPM2 Apple Silicon engine is claimed, first build an external macOS arm64 protocol-v2 pack and run the exact native smoke in `VOXCPM2_RUNTIME_PACK_RELEASE.md`. CPU evidence is separate from MPS evidence; an MPS pack is enabled only after `torch.backends.mps.is_available()`, Korean WAV validation, resource/RTF capture, cancellation and parent/orphan cleanup all pass on the signed app commit. A source-only or synthetic pack test is not native evidence.

Do not upload the DMG while any canonical gate remains open. Source ownership/license, model redistribution, production catalog custody, remote CI provenance, real VoxCPM2 packs, Windows signed MSI, and both clean-machine matrices are still external blockers.
