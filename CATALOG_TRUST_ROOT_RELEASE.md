# Production catalog trust-root release contract

This repository contains verification code only. It must never create, import, or persist a production private key.

## Trust chain

1. The application embeds `engine-catalog.bootstrap.json`, which pins the SHA-256 fingerprint, key ID, and version of the offline Ed25519 root public key.
2. The exact bytes of `engine-catalog.trust-manifest.json` are signed by that offline root. The manifest has a monotonically increasing sequence, validity window, active catalog leaf keys, and revocations.
3. The exact bytes of `engine-catalog.json` are signed by one active, unexpired, unrevoked leaf key from the accepted manifest.
4. The catalog sequence and trust-manifest sequence must both advance beyond the retained acceptance baseline. Root fingerprint or root-version changes are never accepted as an ordinary catalog update.

Root rotation is an application release event: ship a newly code-signed application containing a newly reviewed bootstrap. Leaf rotation and revocation are trust-manifest events signed by the existing offline root.

## Custody and approval

- Generate and retain the root key in an offline device or HSM with a non-exportable private key.
- Keep the online catalog leaf key separate from the root and give it the shortest practical validity period.
- Require two named custodians to approve root signatures, leaf issuance, revocation, and root rotation.
- Retain immutable signing logs, public inputs, exact signed bytes, signatures, release commit, verifier report, and application artifact hashes.
- Perform and record a leaf-revocation/rotation drill before the first public release and at least annually.
- Never place signing secrets in Git, GitHub Actions artifacts, workflow logs, installer inputs, command-line arguments, or this verifier.

## Verification-only command

After the external signer has produced the six public files, verify them from a clean checkout:

```sh
dotnet restore tools/CatalogReleaseVerifier/CatalogReleaseVerifier.csproj --locked-mode
dotnet run --project tools/CatalogReleaseVerifier/CatalogReleaseVerifier.csproj \
  --no-restore \
  --configuration Release -- \
  /secure/public-input/engine-catalog.json \
  /secure/public-input/engine-catalog.signature.json \
  /secure/public-input/engine-catalog.trust.json \
  /secure/public-input/engine-catalog.bootstrap.json \
  /secure/public-input/engine-catalog.trust-manifest.json \
  /secure/public-input/engine-catalog.trust-manifest.signature.json \
  /secure/evidence/catalog-release-verification.json \
  /secure/previous/catalog-release-verification.json
```

For the first production release only, replace the final previous-report path with the explicit `--first-production-release` flag. The baseline can otherwise be the previous verifier report or its extracted `state` object. The verifier records which mode was used and the baseline file identity. It rejects development material, a substituted root, manifest/catalog rollback, revoked or expired leaf keys, `REVIEW-PENDING` licenses, optional engines without artifacts, non-canonical artifact URLs, reparse-point inputs, Windows hard-linked inputs, and oversized release metadata. It emits the composite acceptance state and role-keyed hashes of all exact public input bytes using an atomic, disk-flushed write.

## Production build inputs

Keep the six verified public inputs in a read-only directory outside the repository. Build with:

```sh
dotnet publish src/CrossPlatform/SupertonicVox.Desktop/SupertonicVox.Desktop.csproj \
  --configuration Release \
  -p:CatalogProductionAssets=true \
  -p:CatalogAssetRoot=/secure/public-input
```

The production property requires all six files. The packaged application re-verifies the bootstrap fingerprint, root-signed trust manifest, active leaf, and exact catalog signature at startup. Synthesis and downloads remain disabled on any failure.

## Release stop conditions

Stop the release if the verifier report is absent, any input hash changes after verification, the source commit differs from the packaging evidence, code signing/notarization fails, or the two-person custody record is incomplete. A successful verifier report is necessary but does not by itself make a package release-eligible.
