from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import final_release_evidence as final  # noqa: E402
import release_open_gates as gates  # noqa: E402


PACK_FINGERPRINT = "b" * 64
INVENTORY_SHA = "c" * 64
TAG_NAME = "supertonic-test-v1"
PRINCIPAL = "release@example.test"
REPOSITORY_ID = "test-owner/test-repo"
REPOSITORY_URL = f"https://github.com/{REPOSITORY_ID}.git"
SIGNER_WORKFLOW = f"{REPOSITORY_ID}/.github/workflows/release.yml"


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"},
    )
    return completed.stdout.strip()


def identity(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sizeBytes": len(data),
    }


def write_bytes(root: Path, relative: str, data: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def sign_index(fixture: dict) -> None:
    repo = fixture["repo"]
    try:
        git(repo, "tag", "-d", TAG_NAME)
    except subprocess.CalledProcessError:
        pass
    index_raw = fixture["index"].read_bytes()
    message = (
        "supertonic-final-release-evidence-v1\n"
        f"repositoryId={REPOSITORY_ID}\n"
        f"releaseCommit={fixture['release_commit']}\n"
        f"indexSha256={hashlib.sha256(index_raw).hexdigest()}\n"
        f"gateContractSha256={gates.contract_identity(fixture['contract'])['sha256']}\n"
        f"traceabilitySha256={gates.traceability_identity(fixture['traceability'], fixture['contract'])['sha256']}\n"
    )
    message_path = fixture["base"] / "tag-message.txt"
    message_path.write_text(message, encoding="ascii")
    git(
        repo,
        "-c",
        "gpg.format=ssh",
        "-c",
        f"user.signingkey={fixture['private_key']}",
        "tag",
        "-s",
        TAG_NAME,
        fixture["release_commit"],
        "-F",
        str(message_path),
    )


def create_fixture(base: Path, *, gh_exit_code: int = 0) -> dict:
    repo = base / "repo"
    evidence_root = base / "evidence-root"
    repo.mkdir()
    evidence_root.mkdir()
    private_key = base / "release-signing-key"
    policy_root_key = base / "policy-root-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(private_key)],
        check=True,
    )
    public_key = " ".join((base / "release-signing-key.pub").read_text().split()[:2])
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(policy_root_key)],
        check=True,
    )
    policy_root_public_key = " ".join(
        (base / "policy-root-key.pub").read_text().split()[:2]
    )
    gh_cli = base / "trusted-gh"
    gh_cli.write_text(
        "#!/bin/sh\n"
        "[ \"$1\" = attestation ] || exit 90\n"
        "[ \"$2\" = verify ] || exit 91\n"
        "found_source_digest=0\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = --source-digest ]; then\n"
        "    [ -n \"$2\" ] || exit 92\n"
        "    found_source_digest=1\n"
        "  fi\n"
        "  shift\n"
        "done\n"
        "[ $found_source_digest -eq 1 ] || exit 93\n"
        f"exit {gh_exit_code}\n",
        encoding="ascii",
    )
    gh_cli.chmod(0o700)
    owner_root_payload = {
        "schemaVersion": 1,
        "repositoryId": REPOSITORY_ID,
        "repositoryUrl": REPOSITORY_URL,
        "policyPrincipal": "policy-root@example.test",
        "policyPublicKey": policy_root_public_key,
        "githubSignerWorkflow": SIGNER_WORKFLOW,
        "ghCliSha256": hashlib.sha256(gh_cli.read_bytes()).hexdigest(),
    }
    owner_root = base / "owner-trust-root.json"
    owner_root.write_bytes(final.canonical_owner_trust_root_bytes(owner_root_payload))

    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Release Test")
    git(repo, "config", "user.email", "release@example.test")
    git(repo, "remote", "add", "origin", REPOSITORY_URL)
    contract_path = write_bytes(
        repo,
        "packaging/release-open-gates.json",
        gates.DEFAULT_CONTRACT.read_bytes(),
    )
    traceability_path = write_bytes(
        repo,
        "packaging/release-gate-traceability.json",
        gates.DEFAULT_TRACEABILITY.read_bytes(),
    )
    policy = {
        "schemaVersion": 1,
        "status": "approved",
        "repositoryId": REPOSITORY_ID,
        "tagName": TAG_NAME,
        "principal": PRINCIPAL,
        "publicKey": public_key,
    }
    policy_path = write_bytes(
        repo,
        "packaging/final-release-signing-policy.json",
        final.canonical_signing_policy_bytes(policy),
    )
    subprocess.run(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(policy_root_key),
            "-n",
            "supertonic-release-policy",
            str(policy_path),
        ],
        check=True,
        capture_output=True,
    )
    Path(f"{policy_path}.sig").replace(
        repo / "packaging/final-release-signing-policy.sig"
    )
    git(repo, "add", "--", "packaging")
    git(repo, "commit", "-q", "-m", "freeze release candidate")
    release_commit = git(repo, "rev-parse", "HEAD")

    shipped = []
    for artifact_id, suffix in (("macos-dmg", "dmg"), ("windows-msi", "msi")):
        relative = f"release-files/SupertonicVox.{suffix}"
        path = write_bytes(evidence_root, relative, artifact_id.encode("ascii"))
        shipped.append(
            {
                "artifactId": artifact_id,
                "path": relative,
                **identity(path),
                "sourceCommit": release_commit,
                "containedInventorySha256": INVENTORY_SHA,
                "runtimePackFingerprints": [PACK_FINGERPRINT],
            }
        )
    provenance = {
        "schemaVersion": 1,
        "sourceCommit": release_commit,
        "provider": "github-actions",
        "githubRepository": REPOSITORY_ID,
        "signerWorkflow": SIGNER_WORKFLOW,
        "protectedWorkflow": True,
        "attestationVerified": True,
        "attestationBundles": [],
        "shippedArtifacts": shipped,
    }
    for artifact_id in final.SHIPPED_ARTIFACT_IDS:
        relative = f"supporting/provenance/{artifact_id}.sigstore.json"
        bundle_path = write_bytes(
            evidence_root,
            relative,
            json.dumps({"artifact": artifact_id}, sort_keys=True).encode("ascii"),
        )
        provenance["attestationBundles"].append(
            {"artifactId": artifact_id, "path": relative, **identity(bundle_path)}
        )
    provenance_path = write_bytes(
        evidence_root,
        "supporting/provenance/release-provenance.json",
        final.canonical_provenance_bytes(provenance),
    )

    traceability = gates.load_traceability(traceability_path, contract_path)
    gate_index = []
    for mapping in traceability["mappings"]:
        supporting_relative = f"supporting/gates/{mapping['gateId']}.txt"
        supporting_path = write_bytes(
            evidence_root,
            supporting_relative,
            mapping["gateId"].encode("ascii"),
        )
        evidence = [{"path": supporting_relative, **identity(supporting_path)}]
        if mapping["gateId"] == "remote-ci-provenance":
            evidence.append(
                {
                    "path": "supporting/provenance/release-provenance.json",
                    **identity(provenance_path),
                }
            )
            for bundle in provenance["attestationBundles"]:
                evidence.append(
                    {
                        "path": bundle["path"],
                        "sha256": bundle["sha256"],
                        "sizeBytes": bundle["sizeBytes"],
                    }
                )
        evidence.sort(key=lambda item: item["path"])
        envelope = {
            "schemaVersion": 1,
            "gateId": mapping["gateId"],
            "sourceCommit": release_commit,
            "verifierId": mapping["verifierId"],
            "verificationStatus": "pass",
            "evidence": evidence,
        }
        envelope_path = write_bytes(
            evidence_root,
            mapping["evidenceArtifact"],
            final.canonical_gate_envelope_bytes(envelope),
        )
        envelope_identity = identity(envelope_path)
        gate_index.append(
            {
                "gateId": mapping["gateId"],
                "envelopeArtifact": mapping["evidenceArtifact"],
                "envelopeSha256": envelope_identity["sha256"],
                "envelopeSizeBytes": envelope_identity["sizeBytes"],
            }
        )

    review_index = []
    for requirement in traceability["reviewRequirements"]:
        supporting_relative = f"supporting/reviews/{requirement['reviewId']}.txt"
        supporting_path = write_bytes(
            evidence_root,
            supporting_relative,
            requirement["reviewId"].encode("ascii"),
        )
        envelope = {
            "schemaVersion": 1,
            "reviewId": requirement["reviewId"],
            "sourceCommit": release_commit,
            "outcome": "pass",
            "evidence": [{"path": supporting_relative, **identity(supporting_path)}],
        }
        envelope_path = write_bytes(
            evidence_root,
            requirement["evidenceArtifact"],
            final.canonical_review_envelope_bytes(envelope),
        )
        envelope_identity = identity(envelope_path)
        review_index.append(
            {
                "reviewId": requirement["reviewId"],
                "envelopeArtifact": requirement["evidenceArtifact"],
                "envelopeSha256": envelope_identity["sha256"],
                "envelopeSizeBytes": envelope_identity["sizeBytes"],
            }
        )

    payload = {
        "schemaVersion": 1,
        "releaseEligible": True,
        "releaseCommit": release_commit,
        "gateContractSha256": gates.contract_identity(contract_path)["sha256"],
        "traceabilitySha256": gates.traceability_identity(
            traceability_path,
            contract_path,
        )["sha256"],
        "gateEvidence": gate_index,
        "reviewEvidence": review_index,
        "shippedArtifacts": shipped,
    }
    index = write_bytes(
        evidence_root,
        "final-release-evidence.json",
        final.canonical_index_bytes(payload),
    )
    fixture = {
        "base": base,
        "repo": repo,
        "evidence_root": evidence_root,
        "index": index,
        "payload": payload,
        "contract": contract_path,
        "traceability": traceability_path,
        "policy": policy_path,
        "owner_root": owner_root,
        "owner_root_sha256": hashlib.sha256(owner_root.read_bytes()).hexdigest(),
        "gh_cli": gh_cli,
        "private_key": private_key,
        "release_commit": release_commit,
    }
    sign_index(fixture)
    return fixture


def validate(
    fixture: dict,
    *,
    policy: Path | None = None,
    owner_root_sha256: str | None = None,
) -> dict[str, object]:
    with mock.patch.dict(
        os.environ,
        {
            "SVX_OWNER_TRUST_ROOT_SHA256": (
                owner_root_sha256 or fixture["owner_root_sha256"]
            )
        },
    ):
        return final.validate_final_evidence(
            fixture["index"],
            fixture["evidence_root"],
            fixture["repo"],
            fixture["owner_root"],
            fixture["gh_cli"],
            fixture["contract"],
            fixture["traceability"],
            policy or fixture["policy"],
        )


def rewrite_index(fixture: dict, payload: dict, *, resign: bool = True) -> None:
    fixture["index"].write_bytes(final.canonical_index_bytes(payload))
    fixture["payload"] = payload
    if resign:
        sign_index(fixture)


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is required")
class FinalReleaseEvidenceTests(unittest.TestCase):
    def test_checked_in_signing_policy_is_canonical_and_capture_required(self) -> None:
        policy, raw = final.load_signing_policy(
            final.DEFAULT_SIGNING_POLICY,
            require_approved=False,
        )
        self.assertEqual("capture-required", policy["status"])
        self.assertEqual(final.canonical_signing_policy_bytes(policy), raw)

    def test_real_commit_owner_signed_exact_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            result = validate(fixture)
            self.assertEqual("pass", result["status"])
            self.assertTrue(result["releaseEligible"])
            self.assertEqual(17, result["gateCount"])
            self.assertEqual(3, result["reviewCount"])
            self.assertEqual(2, result["shippedArtifactCount"])

    def test_nonexistent_synthetic_commit_and_capture_policy_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            synthetic = json.loads(json.dumps(fixture["payload"]))
            synthetic["releaseCommit"] = "a" * 40
            rewrite_index(fixture, synthetic, resign=False)
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "git-verification-failed"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "not-approved"):
                validate(fixture, policy=final.DEFAULT_SIGNING_POLICY)

    def test_external_owner_root_and_policy_signature_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            with self.assertRaisesRegex(
                final.FinalReleaseEvidenceError,
                "owner-trust-root-fingerprint-invalid",
            ):
                validate(fixture, owner_root_sha256="0" * 64)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            signature = fixture["repo"] / "packaging/final-release-signing-policy.sig"
            signature.write_bytes(b"forged-policy-signature")
            with self.assertRaisesRegex(
                final.FinalReleaseEvidenceError,
                "signing-policy-signature-invalid",
            ):
                validate(fixture)

    def test_github_attestation_verifier_failure_is_not_self_assertable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary), gh_exit_code=7)
            with self.assertRaisesRegex(
                final.FinalReleaseEvidenceError,
                "github-attestation-verification-failed",
            ):
                validate(fixture)

    def test_attestation_command_binds_the_exact_source_commit(self) -> None:
        source = (TOOLS / "final_release_evidence.py").read_text(encoding="utf-8")
        self.assertIn('"--source-digest",\n                    release_commit,', source)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            fixture["gh_cli"].write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            fixture["gh_cli"].chmod(0o700)
            with self.assertRaisesRegex(
                final.FinalReleaseEvidenceError,
                "external-tool-hash-invalid",
            ):
                validate(fixture)

    def test_missing_gate_stale_signature_and_false_eligibility_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            missing = json.loads(json.dumps(fixture["payload"]))
            missing["gateEvidence"].pop()
            rewrite_index(fixture, missing)
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "gate-coverage"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            changed = json.loads(json.dumps(fixture["payload"]))
            changed["shippedArtifacts"][0]["containedInventorySha256"] = "d" * 64
            rewrite_index(fixture, changed, resign=False)
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "tag-message-invalid"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            ineligible = json.loads(json.dumps(fixture["payload"]))
            ineligible["releaseEligible"] = False
            rewrite_index(fixture, ineligible, resign=False)
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "state-invalid"):
                validate(fixture)

    def test_tamper_symlink_hardlink_and_parent_swap_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            target = fixture["evidence_root"] / "supporting/gates/apple-hardened-runtime.txt"
            target.write_bytes(b"tampered")
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "identity-mismatch"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            target = fixture["evidence_root"] / "supporting/gates/apple-hardened-runtime.txt"
            original = fixture["base"] / "outside.txt"
            original.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(original)
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "link-invalid"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            target = fixture["evidence_root"] / "supporting/gates/apple-hardened-runtime.txt"
            os.link(target, fixture["base"] / "second-link.txt")
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "identity-invalid"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            root_descriptor = final._open_evidence_root(fixture["evidence_root"])
            try:
                gates_dir = fixture["evidence_root"] / "supporting/gates"
                moved = fixture["base"] / "moved-gates"
                gates_dir.rename(moved)
                gates_dir.symlink_to(moved, target_is_directory=True)
                with self.assertRaisesRegex(
                    final.FinalReleaseEvidenceError,
                    "parent-link-invalid",
                ):
                    final._read_regular_beneath(
                        root_descriptor,
                        "supporting/gates/apple-hardened-runtime.txt",
                    )
            finally:
                os.close(root_descriptor)

    def test_only_gpt_web_review_accepts_owner_approved_waiver(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            requirements = gates.load_traceability(
                fixture["traceability"],
                fixture["contract"],
            )["reviewRequirements"]
            requirement = requirements[1]
            envelope_path = fixture["evidence_root"] / requirement["evidenceArtifact"]
            envelope = json.loads(envelope_path.read_text(encoding="ascii"))
            envelope["outcome"] = "owner-approved-waiver"
            envelope_path.write_bytes(final.canonical_review_envelope_bytes(envelope))
            envelope_identity = identity(envelope_path)
            fixture["payload"]["reviewEvidence"][1]["envelopeSha256"] = envelope_identity["sha256"]
            fixture["payload"]["reviewEvidence"][1]["envelopeSizeBytes"] = envelope_identity["sizeBytes"]
            rewrite_index(fixture, fixture["payload"])
            self.assertEqual("pass", validate(fixture)["status"])

            fable_requirement = requirements[0]
            fable_path = fixture["evidence_root"] / fable_requirement["evidenceArtifact"]
            fable = json.loads(fable_path.read_text(encoding="ascii"))
            fable["outcome"] = "owner-approved-waiver"
            fable_path.write_bytes(final.canonical_review_envelope_bytes(fable))
            fable_identity = identity(fable_path)
            fixture["payload"]["reviewEvidence"][0]["envelopeSha256"] = fable_identity["sha256"]
            fixture["payload"]["reviewEvidence"][0]["envelopeSizeBytes"] = fable_identity["sizeBytes"]
            rewrite_index(fixture, fixture["payload"])
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "binding-invalid"):
                validate(fixture)

    def test_provenance_and_shipped_installers_are_exactly_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            fixture["payload"]["shippedArtifacts"][0]["runtimePackFingerprints"] = []
            rewrite_index(fixture, fixture["payload"])
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "binding-invalid"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            shipped_path = fixture["evidence_root"] / fixture["payload"]["shippedArtifacts"][0]["path"]
            shipped_path.write_bytes(b"post-sign-tamper")
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "identity-mismatch"):
                validate(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = create_fixture(Path(temporary))
            provenance_path = fixture["evidence_root"] / "supporting/provenance/release-provenance.json"
            provenance = json.loads(provenance_path.read_text(encoding="ascii"))
            provenance["shippedArtifacts"][0]["containedInventorySha256"] = "d" * 64
            provenance_path.write_bytes(final.canonical_provenance_bytes(provenance))
            remote = next(
                item
                for item in gates.load_traceability(
                    fixture["traceability"], fixture["contract"]
                )["mappings"]
                if item["gateId"] == "remote-ci-provenance"
            )
            envelope_path = fixture["evidence_root"] / remote["evidenceArtifact"]
            envelope = json.loads(envelope_path.read_text(encoding="ascii"))
            provenance_item = next(
                item
                for item in envelope["evidence"]
                if item["path"] == "supporting/provenance/release-provenance.json"
            )
            provenance_item.update(identity(provenance_path))
            envelope_path.write_bytes(final.canonical_gate_envelope_bytes(envelope))
            envelope_identity = identity(envelope_path)
            gate_item = next(
                item
                for item in fixture["payload"]["gateEvidence"]
                if item["gateId"] == "remote-ci-provenance"
            )
            gate_item["envelopeSha256"] = envelope_identity["sha256"]
            gate_item["envelopeSizeBytes"] = envelope_identity["sizeBytes"]
            rewrite_index(fixture, fixture["payload"])
            with self.assertRaisesRegex(final.FinalReleaseEvidenceError, "provenance-binding-invalid"):
                validate(fixture)


if __name__ == "__main__":
    unittest.main()
