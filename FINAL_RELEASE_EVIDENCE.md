# Final release evidence contract

This repository is not release-eligible while any canonical gate is open. This document describes the evidence layout accepted by `tools/final_release_evidence.py`; it does not replace native testing, owner approval, signing, notarization or protected CI.

## Freeze rule

Complete trust-root, catalog, runtime-pack and release-policy changes first. Freeze one full repository-native commit ID (40 hexadecimal characters for SHA-1 repositories or 64 for SHA-256 repositories). Every evidence envelope, review, DMG, MSI, contained inventory and runtime-pack fingerprint must bind that exact commit. Any later source or release-input change invalidates the complete set.

## Required layout

Place the index at the fixed path shown below. All paths inside JSON are forward-slash relative paths under this regular, non-symlink evidence root.

```text
final-release-evidence-root/
  final-release-evidence.json
  evidence/
    gates/<one canonical gate id>.json
    reviews/fable-readiness.json
    reviews/gpt-5.6-pro-web.json
    reviews/terra-code.json
  supporting/
    ... native logs, signed approvals, reports and attestations ...
  release-files/
    SupertonicVox.dmg
    SupertonicVox.msi
```

The exact 17 gate paths, owner steps and verifier IDs are authoritative in `packaging/release-gate-traceability.json`. Do not invent aliases or omit a gate.

## Independent owner trust root and release-evidence signing key

The checked-in `packaging/final-release-signing-policy.json` deliberately has status `capture-required`; therefore the production verifier cannot pass in the current repository. It cannot approve itself. The owner must first create a canonical trust-root file outside the repository containing the expected GitHub repository/origin, the offline policy-signing SSH Ed25519 public key/principal, the allowed signer workflow and the SHA-256 of the exact GitHub CLI binary used for attestation verification. Deliver its SHA-256 through an independent trusted channel as `SVX_OWNER_TRUST_ROOT_SHA256`.

Before the final candidate is frozen, replace the repository policy with status `approved`, the identical repository ID, the release-tag SSH Ed25519 public key/principal and exact tag name. Sign the canonical policy bytes with the offline root in SSH namespace `supertonic-release-policy`; commit the detached signature as `packaging/final-release-signing-policy.sig`. The policy-signing root and release-tag private keys stay outside the repository and CI and follow the production custody/rotation gate. A committer who substitutes both a policy and their own key still cannot satisfy the independently pinned root fingerprint/signature.

After the index and every referenced artifact are final, create an SSH-signed annotated tag targeting the frozen commit. Its message must be exactly:

```text
supertonic-final-release-evidence-v1
repositoryId=<owner/repository>
releaseCommit=<full commit id>
indexSha256=<final-release-evidence.json SHA-256>
gateContractSha256=<validate-contract SHA-256>
traceabilitySha256=<validate-traceability SHA-256>
```

The verifier first authenticates the repository policy with the offline owner root, then checks the tag with the policy public key. It requires clean repository `HEAD` to equal its target, requires `remote.origin.url` to match the external root, and verifies that the policy, detached signature, gate contract and traceability map are byte-identical to their blobs in that commit. A locally invented repository, unsigned index or substituted key cannot pass.

## Gate envelope

Each `evidence/gates/<gate-id>.json` is canonical ASCII JSON with two-space indentation, the exact key order below and one trailing newline. `evidence` must be sorted by `path`, contain no duplicate path, and contain at least one real supporting artifact.

```json
{
  "schemaVersion": 1,
  "gateId": "apple-notarization-and-stapling",
  "sourceCommit": "FULL_REPOSITORY_NATIVE_RELEASE_COMMIT",
  "verifierId": "macos-release-contract",
  "verificationStatus": "pass",
  "evidence": [
    {
      "path": "supporting/macos/release-evidence.json",
      "sha256": "LOWERCASE_SHA256",
      "sizeBytes": 123
    }
  ]
}
```

The envelope is a binding record, not a self-assertion. The mapped verifier must have produced or validated every referenced supporting artifact. Legal and key-custody envelopes require retained owner-approved records; native envelopes require logs and machine-readable reports from the target platform.

## Review envelope

Terra code review and Fable readiness review accept only `pass`. GPT-5.6 Pro web accepts `pass` or `owner-approved-waiver`; a waiver still requires a real signed owner decision in `supporting/` and must state why exact-current web review was unavailable.

```json
{
  "schemaVersion": 1,
  "reviewId": "gpt-5.6-pro-web",
  "sourceCommit": "FULL_REPOSITORY_NATIVE_RELEASE_COMMIT",
  "outcome": "pass",
  "evidence": [
    {
      "path": "supporting/reviews/gpt-5.6-pro-web-verdict.txt",
      "sha256": "LOWERCASE_SHA256",
      "sizeBytes": 123
    }
  ]
}
```

## Final index

`final-release-evidence.json` is also canonical ASCII JSON. Its `gateEvidence` order must match `requiredOpenGateIds`; its review order must match `reviewRequirements`; shipped artifacts must be `macos-dmg` then `windows-msi`. `gateContractSha256` and `traceabilitySha256` come from the validation commands below.

Each gate/review index record contains the exact envelope path, size and SHA-256. Each shipped-artifact record contains the post-sign/post-staple file identity, exact source commit, contained-app inventory SHA-256 and the sorted non-empty list of production runtime-pack fingerprints advertised to that platform. The `remote-ci-provenance` envelope must include canonical `supporting/provenance/release-provenance.json` plus `macos-dmg.sigstore.json` and `windows-msi.sigstore.json`. The provenance identities must exactly match the index. The root-pinned `gh` binary verifies both artifact/bundle pairs with the external root's repository and signer-workflow restrictions and `--source-digest` equal to the frozen release commit; JSON booleans alone cannot close the gate.

```sh
python3 tools/release_open_gates.py validate-contract
python3 tools/release_open_gates.py validate-traceability
SVX_OWNER_TRUST_ROOT_SHA256=<out-of-band-root-sha256> \
python3 tools/final_release_evidence.py validate-final-evidence \
  --index /absolute/path/final-release-evidence-root/final-release-evidence.json \
  --evidence-root /absolute/path/final-release-evidence-root \
  --repo /absolute/path/frozen-release-repository \
  --owner-trust-root /offline/owner-trust-root.json \
  --gh-cli /pinned/regular-file/gh
```

The final command returns exit code 0 and `"releaseEligible": true` only when the whole set passes. It re-hashes every envelope, supporting file, attestation bundle, DMG and MSI through descriptor-relative regular single-link reads, verifies the two GitHub attestations using a copied hash-pinned CLI, and requires the protected provenance envelope to contain the identical shipped-artifact identities. Missing files, stale commits, wrong order, unsafe paths, symlinks, hardlinks, parent-directory substitutions, unsupported review waivers, post-sign changes, invalid signatures/attestations or contract drift return exit code 4. Race-safe directory traversal is intentionally POSIX-only; run the final aggregation step on an isolated Linux/macOS host after collecting native Windows evidence.

## Evidence acquisition order

1. Obtain source ownership, dependency attribution and both model-redistribution approvals.
2. Provision the production catalog root/leaf, record the key ceremony, and pass a client-reachable rotation/revocation/deny-list drill.
3. Build and verify the real platform-specific VoxCPM2 packs; commit their signed catalog metadata before freezing the candidate.
4. Freeze the release commit and rerun clean staging, privacy/history audits, all tests and the three required reviews.
5. On Apple Silicon, run real Supertonic/Vox benchmarks, sign with Developer ID, notarize and staple, then test the quarantined DMG from a clean standard account.
6. On Windows 10/11 x64, run real Supertonic/Vox CPU/CUDA benchmarks, build/verify/sign the MSI, then test install, synthesis, restart, upgrade/downgrade, uninstall and orphan cleanup from a clean standard account.
7. Run the protected CI workflow and retain provenance that binds the final commit, both shipped installer hashes, contained inventories and runtime-pack fingerprints.
8. Create the canonical envelopes/index in an isolated read-only snapshot, run the final verifier and retain its output with the release.

The test fixture under `tools/test_final_release_evidence.py` creates a disposable Git repository, independent policy root, release key and hash-pinned fake attestation command to exercise trust-boundary handling. It proves only that malformed, unsigned, unpinned, unverified or tampered inputs are rejected. The production `capture-required` signing policy, missing external root fingerprint and missing real GitHub bundles prevent that fixture from closing any real release gate.
