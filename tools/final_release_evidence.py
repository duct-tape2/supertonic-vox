#!/usr/bin/env python3
"""Fail-closed aggregator for exact-commit final release evidence."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

import release_open_gates


DEFAULT_CONTRACT = release_open_gates.DEFAULT_CONTRACT
DEFAULT_TRACEABILITY = release_open_gates.DEFAULT_TRACEABILITY
DEFAULT_SIGNING_POLICY = (
    Path(__file__).resolve().parents[1] / "packaging" / "final-release-signing-policy.json"
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SAFE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,254}\Z")
GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
GITHUB_WORKFLOW = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.(?:yml|yaml)\Z"
)
SHIPPED_ARTIFACT_IDS = ("macos-dmg", "windows-msi")


class FinalReleaseEvidenceError(RuntimeError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FinalReleaseEvidenceError(f"duplicate-key:{key}")
        result[key] = value
    return result


def _canonical_json(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _is_commit_id(value: object) -> bool:
    return isinstance(value, str) and COMMIT_ID.fullmatch(value) is not None


def _is_safe_relative(value: object, prefix: str | None = None) -> bool:
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value):
        return False
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        return False
    return prefix is None or value.startswith(prefix)


def _parse_json_bytes(raw: bytes, unavailable: str) -> dict:
    try:
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FinalReleaseEvidenceError(unavailable) from exc
    if not isinstance(payload, dict):
        raise FinalReleaseEvidenceError(f"{unavailable}-shape")
    return payload


def canonical_index_bytes(payload: dict) -> bytes:
    ordered = {
        "schemaVersion": payload["schemaVersion"],
        "releaseEligible": payload["releaseEligible"],
        "releaseCommit": payload["releaseCommit"],
        "gateContractSha256": payload["gateContractSha256"],
        "traceabilitySha256": payload["traceabilitySha256"],
        "gateEvidence": [
            {
                "gateId": item["gateId"],
                "envelopeArtifact": item["envelopeArtifact"],
                "envelopeSha256": item["envelopeSha256"],
                "envelopeSizeBytes": item["envelopeSizeBytes"],
            }
            for item in payload["gateEvidence"]
        ],
        "reviewEvidence": [
            {
                "reviewId": item["reviewId"],
                "envelopeArtifact": item["envelopeArtifact"],
                "envelopeSha256": item["envelopeSha256"],
                "envelopeSizeBytes": item["envelopeSizeBytes"],
            }
            for item in payload["reviewEvidence"]
        ],
        "shippedArtifacts": [
            {
                "artifactId": item["artifactId"],
                "path": item["path"],
                "sha256": item["sha256"],
                "sizeBytes": item["sizeBytes"],
                "sourceCommit": item["sourceCommit"],
                "containedInventorySha256": item["containedInventorySha256"],
                "runtimePackFingerprints": item["runtimePackFingerprints"],
            }
            for item in payload["shippedArtifacts"]
        ],
    }
    return _canonical_json(ordered)


def canonical_gate_envelope_bytes(payload: dict) -> bytes:
    ordered = {
        "schemaVersion": payload["schemaVersion"],
        "gateId": payload["gateId"],
        "sourceCommit": payload["sourceCommit"],
        "verifierId": payload["verifierId"],
        "verificationStatus": payload["verificationStatus"],
        "evidence": [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "sizeBytes": item["sizeBytes"],
            }
            for item in payload["evidence"]
        ],
    }
    return _canonical_json(ordered)


def canonical_review_envelope_bytes(payload: dict) -> bytes:
    ordered = {
        "schemaVersion": payload["schemaVersion"],
        "reviewId": payload["reviewId"],
        "sourceCommit": payload["sourceCommit"],
        "outcome": payload["outcome"],
        "evidence": [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "sizeBytes": item["sizeBytes"],
            }
            for item in payload["evidence"]
        ],
    }
    return _canonical_json(ordered)


def canonical_signing_policy_bytes(payload: dict) -> bytes:
    return _canonical_json(
        {
            "schemaVersion": payload["schemaVersion"],
            "status": payload["status"],
            "repositoryId": payload["repositoryId"],
            "tagName": payload["tagName"],
            "principal": payload["principal"],
            "publicKey": payload["publicKey"],
        }
    )


def canonical_provenance_bytes(payload: dict) -> bytes:
    return _canonical_json(
        {
            "schemaVersion": payload["schemaVersion"],
            "sourceCommit": payload["sourceCommit"],
            "provider": payload["provider"],
            "githubRepository": payload["githubRepository"],
            "signerWorkflow": payload["signerWorkflow"],
            "protectedWorkflow": payload["protectedWorkflow"],
            "attestationVerified": payload["attestationVerified"],
            "attestationBundles": [
                {
                    "artifactId": item["artifactId"],
                    "path": item["path"],
                    "sha256": item["sha256"],
                    "sizeBytes": item["sizeBytes"],
                }
                for item in payload["attestationBundles"]
            ],
            "shippedArtifacts": [
                {
                    "artifactId": item["artifactId"],
                    "path": item["path"],
                    "sha256": item["sha256"],
                    "sizeBytes": item["sizeBytes"],
                    "sourceCommit": item["sourceCommit"],
                    "containedInventorySha256": item["containedInventorySha256"],
                    "runtimePackFingerprints": item["runtimePackFingerprints"],
                }
                for item in payload["shippedArtifacts"]
            ],
        }
    )


def canonical_owner_trust_root_bytes(payload: dict) -> bytes:
    return _canonical_json(
        {
            "schemaVersion": payload["schemaVersion"],
            "repositoryId": payload["repositoryId"],
            "repositoryUrl": payload["repositoryUrl"],
            "policyPrincipal": payload["policyPrincipal"],
            "policyPublicKey": payload["policyPublicKey"],
            "githubSignerWorkflow": payload["githubSignerWorkflow"],
            "ghCliSha256": payload["ghCliSha256"],
        }
    )


def load_owner_trust_root(path: Path) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FinalReleaseEvidenceError("owner-trust-root-unavailable") from exc
    expected_sha256 = os.environ.get("SVX_OWNER_TRUST_ROOT_SHA256", "")
    if not _is_hex64(expected_sha256) or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise FinalReleaseEvidenceError("owner-trust-root-fingerprint-invalid")
    payload = _parse_json_bytes(raw, "owner-trust-root-unavailable")
    if tuple(payload) != (
        "schemaVersion",
        "repositoryId",
        "repositoryUrl",
        "policyPrincipal",
        "policyPublicKey",
        "githubSignerWorkflow",
        "ghCliSha256",
    ):
        raise FinalReleaseEvidenceError("owner-trust-root-shape-invalid")
    repository_id = payload["repositoryId"]
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or not isinstance(repository_id, str)
        or not GITHUB_REPOSITORY.fullmatch(repository_id)
        or payload["repositoryUrl"] != f"https://github.com/{repository_id}.git"
        or not isinstance(payload["policyPrincipal"], str)
        or not PRINCIPAL.fullmatch(payload["policyPrincipal"])
        or not isinstance(payload["policyPublicKey"], str)
        or not payload["policyPublicKey"].startswith("ssh-ed25519 ")
        or "\n" in payload["policyPublicKey"]
        or "\r" in payload["policyPublicKey"]
        or not isinstance(payload["githubSignerWorkflow"], str)
        or not GITHUB_WORKFLOW.fullmatch(payload["githubSignerWorkflow"])
        or not _is_hex64(payload["ghCliSha256"])
    ):
        raise FinalReleaseEvidenceError("owner-trust-root-invalid")
    if canonical_owner_trust_root_bytes(payload) != raw:
        raise FinalReleaseEvidenceError("owner-trust-root-not-canonical")
    return payload, raw


def load_signing_policy(
    path: Path,
    *,
    require_approved: bool = True,
) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FinalReleaseEvidenceError("signing-policy-unavailable") from exc
    payload = _parse_json_bytes(raw, "signing-policy-unavailable")
    if tuple(payload) != (
        "schemaVersion",
        "status",
        "repositoryId",
        "tagName",
        "principal",
        "publicKey",
    ):
        raise FinalReleaseEvidenceError("signing-policy-shape-invalid")
    if payload["schemaVersion"] != 1 or isinstance(payload["schemaVersion"], bool):
        raise FinalReleaseEvidenceError("signing-policy-version-invalid")
    if canonical_signing_policy_bytes(payload) != raw:
        raise FinalReleaseEvidenceError("signing-policy-not-canonical")
    if payload["status"] == "capture-required":
        if (
            payload["repositoryId"] != "CAPTURE_REQUIRED"
            or payload["tagName"] != "CAPTURE_REQUIRED"
            or payload["principal"] != "CAPTURE_REQUIRED"
            or payload["publicKey"] != "CAPTURE_REQUIRED"
        ):
            raise FinalReleaseEvidenceError("signing-policy-capture-invalid")
        if require_approved:
            raise FinalReleaseEvidenceError("signing-policy-not-approved")
        return payload, raw
    if payload["status"] != "approved":
        raise FinalReleaseEvidenceError("signing-policy-status-invalid")
    if (
        not isinstance(payload["repositoryId"], str)
        or not GITHUB_REPOSITORY.fullmatch(payload["repositoryId"])
        or not isinstance(payload["tagName"], str)
        or not TAG_NAME.fullmatch(payload["tagName"])
        or not isinstance(payload["principal"], str)
        or not PRINCIPAL.fullmatch(payload["principal"])
        or not isinstance(payload["publicKey"], str)
        or not payload["publicKey"].startswith("ssh-ed25519 ")
        or "\n" in payload["publicKey"]
        or "\r" in payload["publicKey"]
    ):
        raise FinalReleaseEvidenceError("signing-policy-identity-invalid")
    return payload, raw


def _run_git(repo: Path, arguments: list[str], *, text: bool = False) -> bytes | str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            check=False,
            capture_output=True,
            text=text,
            env=environment,
        )
    except OSError as exc:
        raise FinalReleaseEvidenceError("git-unavailable") from exc
    if completed.returncode != 0:
        raise FinalReleaseEvidenceError("git-verification-failed")
    return completed.stdout


def _read_external_regular(path: Path, expected_sha256: str) -> bytes:
    try:
        before_path = path.lstat()
    except OSError as exc:
        raise FinalReleaseEvidenceError("external-tool-unavailable") from exc
    if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
        raise FinalReleaseEvidenceError("external-tool-identity-invalid")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FinalReleaseEvidenceError("external-tool-open-invalid") from exc
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise FinalReleaseEvidenceError("external-tool-post-read-unavailable") from exc
    identities = [
        (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        for value in (before_path, before, after, after_path)
    ]
    if len(set(identities)) != 1:
        raise FinalReleaseEvidenceError("external-tool-changed-during-read")
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise FinalReleaseEvidenceError("external-tool-hash-invalid")
    return data


def _verify_owner_signed_policy(
    repo: Path,
    policy: dict,
    policy_raw: bytes,
    owner_root: dict,
) -> tuple[Path, bytes]:
    if policy["repositoryId"] != owner_root["repositoryId"]:
        raise FinalReleaseEvidenceError("signing-policy-repository-invalid")
    origin = str(_run_git(repo, ["config", "--get", "remote.origin.url"], text=True)).strip()
    if origin != owner_root["repositoryUrl"]:
        raise FinalReleaseEvidenceError("release-repository-origin-invalid")
    signature_path = repo / "packaging/final-release-signing-policy.sig"
    try:
        signature_raw = signature_path.read_bytes()
    except OSError as exc:
        raise FinalReleaseEvidenceError("signing-policy-signature-unavailable") from exc
    ssh_keygen = Path("/usr/bin/ssh-keygen")
    if not ssh_keygen.is_file() or ssh_keygen.is_symlink():
        raise FinalReleaseEvidenceError("ssh-keygen-unavailable")
    with tempfile.TemporaryDirectory() as temporary:
        allowed_signers = Path(temporary) / "allowed_signers"
        allowed_signers.write_text(
            f"{owner_root['policyPrincipal']} {owner_root['policyPublicKey']}\n",
            encoding="ascii",
        )
        completed = subprocess.run(
            [
                str(ssh_keygen),
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                owner_root["policyPrincipal"],
                "-n",
                "supertonic-release-policy",
                "-s",
                str(signature_path),
            ],
            input=policy_raw,
            check=False,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    if completed.returncode != 0:
        raise FinalReleaseEvidenceError("signing-policy-signature-invalid")
    return signature_path, signature_raw


def _verify_signed_release_tag(
    repo: Path,
    release_commit: str,
    index_raw: bytes,
    contract_sha256: str,
    traceability_sha256: str,
    policy_path: Path,
    policy: dict,
    policy_raw: bytes,
    policy_signature_path: Path,
    policy_signature_raw: bytes,
    contract_path: Path,
    traceability_path: Path,
) -> None:
    if not repo.is_dir() or repo.is_symlink():
        raise FinalReleaseEvidenceError("release-repository-invalid")
    expected_paths = {
        "packaging/final-release-signing-policy.json": (policy_path, policy_raw),
        "packaging/final-release-signing-policy.sig": (
            policy_signature_path,
            policy_signature_raw,
        ),
        "packaging/release-open-gates.json": (contract_path, contract_path.read_bytes()),
        "packaging/release-gate-traceability.json": (
            traceability_path,
            traceability_path.read_bytes(),
        ),
    }
    for relative, (actual_path, expected_bytes) in expected_paths.items():
        if Path(os.path.abspath(actual_path)) != Path(os.path.abspath(repo / relative)):
            raise FinalReleaseEvidenceError("release-input-location-invalid")
        committed = _run_git(repo, ["cat-file", "blob", f"{release_commit}:{relative}"])
        if committed != expected_bytes:
            raise FinalReleaseEvidenceError("release-input-commit-binding-invalid")

    head = str(_run_git(repo, ["rev-parse", "--verify", "HEAD"], text=True)).strip()
    if head != release_commit:
        raise FinalReleaseEvidenceError("release-head-commit-invalid")
    dirty = str(
        _run_git(repo, ["status", "--porcelain", "--untracked-files=no"], text=True)
    )
    if dirty:
        raise FinalReleaseEvidenceError("release-repository-dirty")

    tag_name = policy["tagName"]
    target = str(
        _run_git(
            repo,
            ["rev-parse", "--verify", f"refs/tags/{tag_name}^{{commit}}"],
            text=True,
        )
    ).strip()
    if target != release_commit:
        raise FinalReleaseEvidenceError("release-tag-target-invalid")
    tag_raw = _run_git(repo, ["cat-file", "tag", f"refs/tags/{tag_name}"])
    if not isinstance(tag_raw, bytes):
        raise FinalReleaseEvidenceError("release-tag-object-invalid")
    try:
        headers, body = tag_raw.split(b"\n\n", 1)
        signature_marker = b"-----BEGIN SSH SIGNATURE-----"
        message, signature = body.split(signature_marker, 1)
    except ValueError as exc:
        raise FinalReleaseEvidenceError("release-tag-object-invalid") from exc
    header_lines = headers.splitlines()
    if (
        f"object {release_commit}".encode("ascii") not in header_lines
        or b"type commit" not in header_lines
        or not signature.startswith(b"\n")
    ):
        raise FinalReleaseEvidenceError("release-tag-binding-invalid")
    expected_message = (
        "supertonic-final-release-evidence-v1\n"
        f"repositoryId={policy['repositoryId']}\n"
        f"releaseCommit={release_commit}\n"
        f"indexSha256={hashlib.sha256(index_raw).hexdigest()}\n"
        f"gateContractSha256={contract_sha256}\n"
        f"traceabilitySha256={traceability_sha256}\n"
    ).encode("ascii")
    if message != expected_message:
        raise FinalReleaseEvidenceError("release-tag-message-invalid")

    with tempfile.TemporaryDirectory() as temporary:
        allowed_signers = Path(temporary) / "allowed_signers"
        allowed_signers.write_text(
            f"{policy['principal']} {policy['publicKey']}\n",
            encoding="ascii",
        )
        _run_git(
            repo,
            [
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed_signers}",
                "verify-tag",
                tag_name,
            ],
        )


def _open_evidence_root(root: Path) -> int:
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise FinalReleaseEvidenceError("race-safe-open-unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise FinalReleaseEvidenceError("evidence-root-open-invalid") from exc
    metadata = os.fstat(descriptor)
    try:
        current = root.lstat()
    except OSError as exc:
        os.close(descriptor)
        raise FinalReleaseEvidenceError("evidence-root-post-open-unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
    ):
        os.close(descriptor)
        raise FinalReleaseEvidenceError("evidence-root-identity-invalid")
    return descriptor


def _read_regular_beneath(root_descriptor: int, relative: str) -> bytes:
    if not _is_safe_relative(relative):
        raise FinalReleaseEvidenceError("artifact-path-invalid")
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parts = PurePosixPath(relative).parts
    current_descriptor = os.dup(root_descriptor)
    file_descriptor: int | None = None
    try:
        for part in parts[:-1]:
            try:
                next_descriptor = os.open(
                    part,
                    directory_flags,
                    dir_fd=current_descriptor,
                )
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise FinalReleaseEvidenceError("artifact-parent-link-invalid") from exc
                raise FinalReleaseEvidenceError("artifact-parent-open-invalid") from exc
            os.close(current_descriptor)
            current_descriptor = next_descriptor
            if not stat.S_ISDIR(os.fstat(current_descriptor).st_mode):
                raise FinalReleaseEvidenceError("artifact-parent-identity-invalid")
        try:
            file_descriptor = os.open(
                parts[-1],
                file_flags,
                dir_fd=current_descriptor,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise FinalReleaseEvidenceError("artifact-link-invalid") from exc
            raise FinalReleaseEvidenceError("artifact-open-invalid") from exc
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise FinalReleaseEvidenceError("artifact-open-identity-invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(file_descriptor)
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(current_descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise FinalReleaseEvidenceError("artifact-changed-during-read")
    return b"".join(chunks)


def _verify_identity(root_descriptor: int, item: dict, path_key: str) -> bytes:
    if not isinstance(item.get("sizeBytes"), int) or isinstance(item["sizeBytes"], bool):
        raise FinalReleaseEvidenceError("artifact-size-invalid")
    if item["sizeBytes"] < 0 or not _is_hex64(item.get("sha256")):
        raise FinalReleaseEvidenceError("artifact-identity-invalid")
    data = _read_regular_beneath(root_descriptor, item[path_key])
    if len(data) != item["sizeBytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise FinalReleaseEvidenceError("artifact-identity-mismatch")
    return data


def _validate_supporting_evidence(root_descriptor: int, evidence: object) -> None:
    if not isinstance(evidence, list) or not evidence:
        raise FinalReleaseEvidenceError("supporting-evidence-invalid")
    paths: list[str] = []
    for item in evidence:
        if not isinstance(item, dict) or tuple(item) != ("path", "sha256", "sizeBytes"):
            raise FinalReleaseEvidenceError("supporting-evidence-shape-invalid")
        if not _is_safe_relative(item["path"], "supporting/"):
            raise FinalReleaseEvidenceError("supporting-evidence-path-invalid")
        paths.append(item["path"])
        _verify_identity(root_descriptor, item, "path")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise FinalReleaseEvidenceError("supporting-evidence-order-invalid")


def _validate_gate_envelope(
    root_descriptor: int,
    index_item: dict,
    mapping: dict,
    release_commit: str,
) -> dict:
    if not isinstance(index_item, dict) or tuple(index_item) != (
        "gateId",
        "envelopeArtifact",
        "envelopeSha256",
        "envelopeSizeBytes",
    ):
        raise FinalReleaseEvidenceError("gate-index-shape-invalid")
    if (
        index_item["gateId"] != mapping["gateId"]
        or index_item["envelopeArtifact"] != mapping["evidenceArtifact"]
    ):
        raise FinalReleaseEvidenceError("gate-index-mapping-invalid")
    identity = {
        "path": index_item["envelopeArtifact"],
        "sha256": index_item["envelopeSha256"],
        "sizeBytes": index_item["envelopeSizeBytes"],
    }
    raw = _verify_identity(root_descriptor, identity, "path")
    payload = _parse_json_bytes(raw, "gate-envelope-unavailable")
    if tuple(payload) != (
        "schemaVersion",
        "gateId",
        "sourceCommit",
        "verifierId",
        "verificationStatus",
        "evidence",
    ):
        raise FinalReleaseEvidenceError("gate-envelope-shape-invalid")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["gateId"] != mapping["gateId"]
        or payload["sourceCommit"] != release_commit
        or payload["verifierId"] != mapping["verifierId"]
        or payload["verificationStatus"] != "pass"
    ):
        raise FinalReleaseEvidenceError("gate-envelope-binding-invalid")
    _validate_supporting_evidence(root_descriptor, payload["evidence"])
    if canonical_gate_envelope_bytes(payload) != raw:
        raise FinalReleaseEvidenceError("gate-envelope-not-canonical")
    return payload


def _validate_review_envelope(
    root_descriptor: int,
    index_item: dict,
    requirement: dict,
    release_commit: str,
) -> None:
    if not isinstance(index_item, dict) or tuple(index_item) != (
        "reviewId",
        "envelopeArtifact",
        "envelopeSha256",
        "envelopeSizeBytes",
    ):
        raise FinalReleaseEvidenceError("review-index-shape-invalid")
    if (
        index_item["reviewId"] != requirement["reviewId"]
        or index_item["envelopeArtifact"] != requirement["evidenceArtifact"]
    ):
        raise FinalReleaseEvidenceError("review-index-mapping-invalid")
    identity = {
        "path": index_item["envelopeArtifact"],
        "sha256": index_item["envelopeSha256"],
        "sizeBytes": index_item["envelopeSizeBytes"],
    }
    raw = _verify_identity(root_descriptor, identity, "path")
    payload = _parse_json_bytes(raw, "review-envelope-unavailable")
    if tuple(payload) != (
        "schemaVersion",
        "reviewId",
        "sourceCommit",
        "outcome",
        "evidence",
    ):
        raise FinalReleaseEvidenceError("review-envelope-shape-invalid")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["reviewId"] != requirement["reviewId"]
        or payload["sourceCommit"] != release_commit
        or payload["outcome"] not in requirement["allowedOutcomes"]
    ):
        raise FinalReleaseEvidenceError("review-envelope-binding-invalid")
    _validate_supporting_evidence(root_descriptor, payload["evidence"])
    if canonical_review_envelope_bytes(payload) != raw:
        raise FinalReleaseEvidenceError("review-envelope-not-canonical")


def _validate_protected_provenance(
    root_descriptor: int,
    remote_gate_envelope: dict,
    release_commit: str,
    shipped: list[dict],
    owner_root: dict,
    gh_cli_path: Path,
) -> None:
    expected_path = "supporting/provenance/release-provenance.json"
    matches = [
        item
        for item in remote_gate_envelope["evidence"]
        if item["path"] == expected_path
    ]
    if len(matches) != 1:
        raise FinalReleaseEvidenceError("protected-provenance-evidence-invalid")
    raw = _verify_identity(root_descriptor, matches[0], "path")
    payload = _parse_json_bytes(raw, "protected-provenance-unavailable")
    if tuple(payload) != (
        "schemaVersion",
        "sourceCommit",
        "provider",
        "githubRepository",
        "signerWorkflow",
        "protectedWorkflow",
        "attestationVerified",
        "attestationBundles",
        "shippedArtifacts",
    ):
        raise FinalReleaseEvidenceError("protected-provenance-shape-invalid")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["sourceCommit"] != release_commit
        or payload["provider"] != "github-actions"
        or payload["githubRepository"] != owner_root["repositoryId"]
        or payload["signerWorkflow"] != owner_root["githubSignerWorkflow"]
        or payload["protectedWorkflow"] is not True
        or payload["attestationVerified"] is not True
        or payload["shippedArtifacts"] != shipped
    ):
        raise FinalReleaseEvidenceError("protected-provenance-binding-invalid")
    if canonical_provenance_bytes(payload) != raw:
        raise FinalReleaseEvidenceError("protected-provenance-not-canonical")

    bundles = payload["attestationBundles"]
    if not isinstance(bundles, list) or len(bundles) != len(SHIPPED_ARTIFACT_IDS):
        raise FinalReleaseEvidenceError("attestation-bundle-coverage-invalid")
    observed_bundle_ids: list[str] = []
    remote_identities = {
        item["path"]: item for item in remote_gate_envelope["evidence"]
    }
    for bundle in bundles:
        if not isinstance(bundle, dict) or tuple(bundle) != (
            "artifactId",
            "path",
            "sha256",
            "sizeBytes",
        ):
            raise FinalReleaseEvidenceError("attestation-bundle-shape-invalid")
        observed_bundle_ids.append(bundle["artifactId"])
        expected_path = f"supporting/provenance/{bundle['artifactId']}.sigstore.json"
        if bundle["path"] != expected_path or remote_identities.get(expected_path) != {
            "path": bundle["path"],
            "sha256": bundle["sha256"],
            "sizeBytes": bundle["sizeBytes"],
        }:
            raise FinalReleaseEvidenceError("attestation-bundle-binding-invalid")
        _verify_identity(root_descriptor, bundle, "path")
    if tuple(observed_bundle_ids) != SHIPPED_ARTIFACT_IDS:
        raise FinalReleaseEvidenceError("attestation-bundle-order-invalid")

    gh_cli = _read_external_regular(gh_cli_path, owner_root["ghCliSha256"])
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        secured_gh = temporary_root / "gh"
        secured_gh.write_bytes(gh_cli)
        secured_gh.chmod(0o700)
        for shipped_item, bundle in zip(shipped, bundles):
            artifact_copy = temporary_root / shipped_item["artifactId"]
            bundle_copy = temporary_root / f"{shipped_item['artifactId']}.sigstore.json"
            artifact_copy.write_bytes(
                _read_regular_beneath(root_descriptor, shipped_item["path"])
            )
            bundle_copy.write_bytes(_read_regular_beneath(root_descriptor, bundle["path"]))
            completed = subprocess.run(
                [
                    str(secured_gh),
                    "attestation",
                    "verify",
                    str(artifact_copy),
                    "--repo",
                    owner_root["repositoryId"],
                    "--signer-workflow",
                    owner_root["githubSignerWorkflow"],
                    "--source-digest",
                    release_commit,
                    "--bundle",
                    str(bundle_copy),
                ],
                check=False,
                capture_output=True,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            if completed.returncode != 0:
                raise FinalReleaseEvidenceError("github-attestation-verification-failed")


def _validate_final_evidence_open(
    root_descriptor: int,
    index_path: Path,
    evidence_root: Path,
    repo_path: Path,
    owner_trust_root_path: Path,
    gh_cli_path: Path,
    contract_path: Path = DEFAULT_CONTRACT,
    traceability_path: Path = DEFAULT_TRACEABILITY,
    signing_policy_path: Path = DEFAULT_SIGNING_POLICY,
) -> dict[str, object]:
    expected_index = evidence_root / "final-release-evidence.json"
    if Path(os.path.abspath(index_path)) != Path(os.path.abspath(expected_index)):
        raise FinalReleaseEvidenceError("final-index-location-invalid")
    raw = _read_regular_beneath(root_descriptor, "final-release-evidence.json")
    payload = _parse_json_bytes(raw, "final-index-unavailable")
    if tuple(payload) != (
        "schemaVersion",
        "releaseEligible",
        "releaseCommit",
        "gateContractSha256",
        "traceabilitySha256",
        "gateEvidence",
        "reviewEvidence",
        "shippedArtifacts",
    ):
        raise FinalReleaseEvidenceError("final-index-shape-invalid")
    release_commit = payload["releaseCommit"]
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["releaseEligible"] is not True
        or not _is_commit_id(release_commit)
    ):
        raise FinalReleaseEvidenceError("final-index-state-invalid")

    contract_identity = release_open_gates.contract_identity(contract_path)
    traceability = release_open_gates.load_traceability(traceability_path, contract_path)
    traceability_identity = release_open_gates.traceability_identity(
        traceability_path,
        contract_path,
    )
    signing_policy, signing_policy_raw = load_signing_policy(signing_policy_path)
    owner_root, _ = load_owner_trust_root(owner_trust_root_path)
    policy_signature_path, policy_signature_raw = _verify_owner_signed_policy(
        repo_path,
        signing_policy,
        signing_policy_raw,
        owner_root,
    )
    if (
        payload["gateContractSha256"] != contract_identity["sha256"]
        or payload["traceabilitySha256"] != traceability_identity["sha256"]
    ):
        raise FinalReleaseEvidenceError("final-index-contract-binding-invalid")
    _verify_signed_release_tag(
        repo_path,
        release_commit,
        raw,
        str(contract_identity["sha256"]),
        str(traceability_identity["sha256"]),
        signing_policy_path,
        signing_policy,
        signing_policy_raw,
        policy_signature_path,
        policy_signature_raw,
        contract_path,
        traceability_path,
    )

    gate_evidence = payload["gateEvidence"]
    mappings = traceability["mappings"]
    if not isinstance(gate_evidence, list) or len(gate_evidence) != len(mappings):
        raise FinalReleaseEvidenceError("final-index-gate-coverage-invalid")
    validated_gate_envelopes: dict[str, dict] = {}
    for item, mapping in zip(gate_evidence, mappings):
        validated_gate_envelopes[mapping["gateId"]] = _validate_gate_envelope(
            root_descriptor,
            item,
            mapping,
            release_commit,
        )

    review_evidence = payload["reviewEvidence"]
    requirements = traceability["reviewRequirements"]
    if not isinstance(review_evidence, list) or len(review_evidence) != len(requirements):
        raise FinalReleaseEvidenceError("final-index-review-coverage-invalid")
    for item, requirement in zip(review_evidence, requirements):
        _validate_review_envelope(root_descriptor, item, requirement, release_commit)

    shipped = payload["shippedArtifacts"]
    if not isinstance(shipped, list) or len(shipped) != len(SHIPPED_ARTIFACT_IDS):
        raise FinalReleaseEvidenceError("shipped-artifacts-invalid")
    observed_ids: list[str] = []
    for item in shipped:
        if not isinstance(item, dict) or tuple(item) != (
            "artifactId",
            "path",
            "sha256",
            "sizeBytes",
            "sourceCommit",
            "containedInventorySha256",
            "runtimePackFingerprints",
        ):
            raise FinalReleaseEvidenceError("shipped-artifact-shape-invalid")
        observed_ids.append(item["artifactId"])
        fingerprints = item["runtimePackFingerprints"]
        if (
            not _is_safe_relative(item["path"], "release-files/")
            or item["sourceCommit"] != release_commit
            or not _is_hex64(item["containedInventorySha256"])
            or not isinstance(fingerprints, list)
            or not fingerprints
            or fingerprints != sorted(fingerprints)
            or len(fingerprints) != len(set(fingerprints))
            or not all(_is_hex64(value) for value in fingerprints)
        ):
            raise FinalReleaseEvidenceError("shipped-artifact-binding-invalid")
        _verify_identity(root_descriptor, item, "path")
    if tuple(observed_ids) != SHIPPED_ARTIFACT_IDS:
        raise FinalReleaseEvidenceError("shipped-artifact-coverage-invalid")

    if canonical_index_bytes(payload) != raw:
        raise FinalReleaseEvidenceError("final-index-not-canonical")
    _validate_protected_provenance(
        root_descriptor,
        validated_gate_envelopes["remote-ci-provenance"],
        release_commit,
        shipped,
        owner_root,
        gh_cli_path,
    )
    return {
        "status": "pass",
        "releaseEligible": True,
        "releaseCommit": release_commit,
        "gateCount": len(gate_evidence),
        "reviewCount": len(review_evidence),
        "shippedArtifactCount": len(shipped),
    }


def validate_final_evidence(
    index_path: Path,
    evidence_root: Path,
    repo_path: Path,
    owner_trust_root_path: Path,
    gh_cli_path: Path,
    contract_path: Path = DEFAULT_CONTRACT,
    traceability_path: Path = DEFAULT_TRACEABILITY,
    signing_policy_path: Path = DEFAULT_SIGNING_POLICY,
) -> dict[str, object]:
    root_descriptor = _open_evidence_root(evidence_root)
    try:
        return _validate_final_evidence_open(
            root_descriptor,
            index_path,
            evidence_root,
            repo_path,
            owner_trust_root_path,
            gh_cli_path,
            contract_path,
            traceability_path,
            signing_policy_path,
        )
    finally:
        os.close(root_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("validate-final-evidence",))
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--owner-trust-root", type=Path, required=True)
    parser.add_argument("--gh-cli", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--traceability", type=Path, default=DEFAULT_TRACEABILITY)
    parser.add_argument("--signing-policy", type=Path, default=DEFAULT_SIGNING_POLICY)
    args = parser.parse_args()
    try:
        result = validate_final_evidence(
            args.index,
            args.evidence_root,
            args.repo,
            args.owner_trust_root,
            args.gh_cli,
            args.contract,
            args.traceability,
            args.signing_policy,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (FinalReleaseEvidenceError, release_open_gates.ReleaseOpenGateError) as exc:
        print(json.dumps({"finalReleaseEvidenceError": str(exc)}, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
