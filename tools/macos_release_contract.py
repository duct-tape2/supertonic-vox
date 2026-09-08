#!/usr/bin/env python3
"""Fail-closed macOS architecture, signing, notarization, and evidence contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import tempfile
import unicodedata
import uuid

import release_open_gates


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "packaging" / "macos-release-contract.json"
DEFAULT_POLICY = ROOT / "packaging" / "macos-signing-policy.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TEAM_ID = re.compile(r"[A-Z0-9]{10}\Z")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
CONTRACT_KEYS = (
    "schemaVersion",
    "target",
    "minimumSystemVersion",
    "hashAlgorithm",
    "bundleIdentifier",
    "identity",
    "architecture",
    "signing",
    "notarization",
    "userData",
    "releaseEligible",
    "openGates",
)
POLICY_KEYS = (
    "schemaVersion",
    "target",
    "status",
    "hashAlgorithm",
    "approvedInventorySha256",
    "bundleTarget",
    "entries",
)
INVENTORY_KEYS = ("schemaVersion", "target", "hashAlgorithm", "files", "inventorySha256")
FILE_KEYS = ("path", "sha256", "sizeBytes", "type", "architectures")
POLICY_ENTRY_KEYS = (
    "path",
    "origin",
    "type",
    "action",
    "preSignSha256",
    "sizeBytes",
    "architectures",
    "entitlementsProfile",
    "approvalId",
)
EVIDENCE_KEYS = {
    "schemaVersion",
    "releaseEligible",
    "sourceCommit",
    "packageVersion",
    "contractSha256",
    "signingPolicySha256",
    "identityMode",
    "preNormalizationInventory",
    "normalizationDecisions",
    "normalizedInventory",
    "signingDecisions",
    "signedInventory",
    "stapledInventory",
    "appStages",
    "dmgStages",
    "signers",
    "entitlements",
    "notarization",
    "verifications",
    "privacyEvidence",
    "externalApprovals",
    "toolchain",
    "nativeChecks",
    "openGates",
}
CPU_TYPES = {
    0x0100000C: "arm64",
    0x01000007: "x86_64",
}
SIGNING_METADATA_PATHS = {"Contents/_CodeSignature/CodeResources"}


class MacReleaseContractError(RuntimeError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MacReleaseContractError(f"duplicate-key:{key}")
        result[key] = value
    return result


def _canonical_bytes(payload: object) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _load_ascii_json(path: Path, label: str) -> tuple[bytes, dict]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MacReleaseContractError(f"{label}-unavailable") from exc
    if not isinstance(payload, dict):
        raise MacReleaseContractError(f"{label}-shape-invalid")
    return raw, payload


def _closed(value: object, keys: tuple[str, ...], label: str) -> dict:
    if not isinstance(value, dict) or tuple(value) != keys:
        raise MacReleaseContractError(f"{label}-shape-invalid")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(character) < 0x20 for character in value):
        raise MacReleaseContractError(f"{label}-invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise MacReleaseContractError(f"{label}-invalid")
    return value


def _safe_path(value: object, label: str) -> str:
    raw = _string(value, label)
    path = PurePosixPath(raw)
    if (
        "\\" in raw
        or "\x00" in raw
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or unicodedata.normalize("NFC", raw) != raw
    ):
        raise MacReleaseContractError(f"{label}-invalid")
    return raw


def _normalized_subject(value: object, label: str) -> str:
    subject = _string(value, label)
    if unicodedata.normalize("NFKC", subject).strip() != subject or len(subject) > 512:
        raise MacReleaseContractError(f"{label}-invalid")
    return subject


def _identity(value: object, label: str) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"name", "sha256", "sizeBytes"}
        or PurePosixPath(str(value.get("name", ""))).name != value.get("name")
        or not isinstance(value.get("sizeBytes"), int)
        or isinstance(value.get("sizeBytes"), bool)
        or value["sizeBytes"] < 1
    ):
        raise MacReleaseContractError(f"{label}-invalid")
    _sha256(value["sha256"], f"{label}-sha256")
    return value


def load_contract(path: Path = DEFAULT_CONTRACT, *, production: bool = False) -> dict:
    raw, payload = _load_ascii_json(path, "macos-contract")
    _closed(payload, CONTRACT_KEYS, "macos-contract")
    if raw != _canonical_bytes(payload):
        raise MacReleaseContractError("macos-contract-not-canonical")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["target"] != "macos-arm64"
        or payload["minimumSystemVersion"] != "13.0"
        or payload["hashAlgorithm"] != "SHA-256"
        or payload["bundleIdentifier"] != "io.github.supertonicvox.desktop"
    ):
        raise MacReleaseContractError("macos-contract-header-invalid")
    identity = payload["identity"]
    if not isinstance(identity, dict) or set(identity) != {
        "status", "certificateKind", "leafCertificateSha256", "subject", "teamId", "approvalId"
    }:
        raise MacReleaseContractError("macos-identity-shape-invalid")
    if identity["certificateKind"] != "Developer ID Application" or identity["status"] not in {
        "staging-placeholder", "owner-approved"
    }:
        raise MacReleaseContractError("macos-identity-invalid")
    if identity["status"] == "staging-placeholder":
        if any(identity[key] is not None for key in (
            "leafCertificateSha256", "subject", "teamId", "approvalId"
        )):
            raise MacReleaseContractError("macos-staging-identity-invalid")
    else:
        _sha256(identity["leafCertificateSha256"], "macos-owner-leaf")
        _normalized_subject(identity["subject"], "macos-owner-subject")
        if not isinstance(identity["teamId"], str) or TEAM_ID.fullmatch(identity["teamId"]) is None:
            raise MacReleaseContractError("macos-owner-team-invalid")
        _string(identity["approvalId"], "macos-owner-approval")
    architecture = payload["architecture"]
    if architecture != {
        "mode": "arm64-only-after-normalization",
        "acceptedInputSets": [
            ["arm64"],
            ["arm64", "arm64e"],
            ["arm64", "x86_64"],
            ["arm64", "arm64e", "x86_64"],
        ],
        "normalizationTool": "lipo -thin arm64",
        "finalArchitectures": ["arm64"],
    }:
        raise MacReleaseContractError("macos-architecture-contract-invalid")
    signing = payload["signing"]
    if not isinstance(signing, dict) or set(signing) != {
        "digestAlgorithm", "hardenedRuntime", "secureTimestampRequired", "signatureMetadataPaths", "entitlementsPath",
        "entitlementsSha256", "allowedEntitlements", "forbiddenEntitlements"
    }:
        raise MacReleaseContractError("macos-signing-contract-shape-invalid")
    if (
        signing["digestAlgorithm"] != "SHA-256"
        or signing["hardenedRuntime"] is not True
        or signing["secureTimestampRequired"] is not True
        or signing["signatureMetadataPaths"] != ["Contents/_CodeSignature/CodeResources"]
        or signing["entitlementsPath"] != "packaging/macos/SupertonicVox.entitlements"
        or signing["allowedEntitlements"] != ["com.apple.security.cs.allow-jit"]
        or signing["forbiddenEntitlements"] != [
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.network.client",
            "com.apple.security.network.server",
        ]
    ):
        raise MacReleaseContractError("macos-signing-contract-invalid")
    entitlements = path.parent / "macos" / "SupertonicVox.entitlements"
    try:
        entitlements_hash = hashlib.sha256(entitlements.read_bytes()).hexdigest()
    except OSError as exc:
        raise MacReleaseContractError("macos-entitlements-unavailable") from exc
    if _sha256(signing["entitlementsSha256"], "macos-entitlements-sha256") != entitlements_hash:
        raise MacReleaseContractError("macos-entitlements-binding-invalid")
    notarization = payload["notarization"]
    if notarization != {
        "appSubmissionFormat": "ditto-zip-keepParent",
        "appStapledBeforeDmg": True,
        "dualSubmissionRequired": True,
        "acceptedStatus": "Accepted",
        "dmgAssessmentContext": "context:primary-signature",
        "stapleMutablePaths": ["Contents/CodeResources"],
    }:
        raise MacReleaseContractError("macos-notarization-contract-invalid")
    user_data = payload["userData"]
    if user_data != {
        "installerOwnsUserData": False,
        "preservePaths": [
            "~/Documents/SupertonicVox",
            "~/Library/Application Support/SupertonicVox",
        ],
    }:
        raise MacReleaseContractError("macos-user-data-contract-invalid")
    if payload["releaseEligible"] is not False:
        raise MacReleaseContractError("macos-contract-release-state-invalid")
    if payload["openGates"] != release_open_gates.load_contract()["requiredOpenGateIds"]:
        raise MacReleaseContractError("macos-contract-open-gates-invalid")
    if production and identity["status"] != "owner-approved":
        raise MacReleaseContractError("macos-production-identity-not-approved")
    return payload


def inventory_digest(files: list[dict]) -> str:
    raw = json.dumps(files, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _architecture_name(cpu: int, subtype: int) -> str:
    if cpu == 0x0100000C and subtype & 0x00FFFFFF == 2:
        return "arm64e"
    return CPU_TYPES.get(cpu, f"unknown-0x{cpu:08x}")


def macho_architectures(path: Path) -> list[str]:
    try:
        with path.open("rb") as stream:
            header = stream.read(12)
            if len(header) < 8:
                return []
            magic = header[:4]
            if magic in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"}:
                if len(header) < 12:
                    raise MacReleaseContractError("macho-header-truncated")
                cpu, subtype = struct.unpack("<II", header[4:12])
                return [_architecture_name(cpu, subtype)]
            if magic in {b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"}:
                if len(header) < 12:
                    raise MacReleaseContractError("macho-header-truncated")
                cpu, subtype = struct.unpack(">II", header[4:12])
                return [_architecture_name(cpu, subtype)]
            fat_formats = {
                b"\xca\xfe\xba\xbe": (">", 20),
                b"\xbe\xba\xfe\xca": ("<", 20),
                b"\xca\xfe\xba\xbf": (">", 32),
                b"\xbf\xba\xfe\xca": ("<", 32),
            }
            if magic not in fat_formats:
                return []
            endian, entry_size = fat_formats[magic]
            count = struct.unpack(f"{endian}I", header[4:8])[0]
            stream.seek(8)
            if count < 1 or count > 32:
                raise MacReleaseContractError("macho-fat-count-invalid")
            architectures = []
            for _ in range(count):
                entry = stream.read(entry_size)
                if len(entry) != entry_size:
                    raise MacReleaseContractError("macho-fat-truncated")
                cpu, subtype = struct.unpack(f"{endian}II", entry[:8])
                architectures.append(_architecture_name(cpu, subtype))
            if len(architectures) != len(set(architectures)):
                raise MacReleaseContractError("macho-architecture-duplicate")
            return sorted(architectures)
    except OSError as exc:
        raise MacReleaseContractError("macho-unreadable") from exc


def _file_identity(path: Path, relative: str) -> dict:
    try:
        info = path.lstat()
    except OSError as exc:
        raise MacReleaseContractError("macos-inventory-file-unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        raise MacReleaseContractError("macos-inventory-file-invalid")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    if total != info.st_size:
        raise MacReleaseContractError("macos-inventory-file-changed")
    architectures = macho_architectures(path)
    return {
        "path": relative,
        "sha256": digest.hexdigest(),
        "sizeBytes": total,
        "type": "macho" if architectures else "resource",
        "architectures": architectures,
    }


def capture_inventory(root: Path, *, require_arm64_only: bool = False) -> dict:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise MacReleaseContractError("macos-inventory-root-unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
        raise MacReleaseContractError("macos-inventory-root-invalid")
    files: list[dict] = []
    canonical_paths: set[str] = set()
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        current_path = Path(current)
        for directory in directories:
            candidate = current_path / directory
            if candidate.is_symlink() or not candidate.is_dir():
                raise MacReleaseContractError("macos-inventory-directory-invalid")
        for name in names:
            path = current_path / name
            relative = _safe_path(path.relative_to(root).as_posix(), "macos-inventory-path")
            canonical = unicodedata.normalize("NFKC", relative).casefold()
            if canonical in canonical_paths:
                raise MacReleaseContractError("macos-inventory-path-duplicate")
            canonical_paths.add(canonical)
            item = _file_identity(path, relative)
            if item["type"] == "macho":
                if item["architectures"] not in (
                    ["arm64"],
                    ["arm64", "arm64e"],
                    ["arm64", "x86_64"],
                    ["arm64", "arm64e", "x86_64"],
                ):
                    raise MacReleaseContractError("macos-macho-input-architecture-invalid")
                if require_arm64_only and item["architectures"] != ["arm64"]:
                    raise MacReleaseContractError("macos-final-architecture-invalid")
            files.append(item)
    files.sort(key=lambda item: item["path"])
    if not files:
        raise MacReleaseContractError("macos-inventory-empty")
    return {
        "schemaVersion": 1,
        "target": "macos-arm64",
        "hashAlgorithm": "SHA-256",
        "files": files,
        "inventorySha256": inventory_digest(files),
    }


def _validate_inventory(payload: object, *, require_arm64_only: bool = True) -> dict:
    inventory = _closed(payload, INVENTORY_KEYS, "macos-inventory")
    if (
        inventory["schemaVersion"] != 1
        or isinstance(inventory["schemaVersion"], bool)
        or inventory["target"] != "macos-arm64"
        or inventory["hashAlgorithm"] != "SHA-256"
        or not isinstance(inventory["files"], list)
        or not inventory["files"]
    ):
        raise MacReleaseContractError("macos-inventory-header-invalid")
    paths = []
    for value in inventory["files"]:
        item = _closed(value, FILE_KEYS, "macos-inventory-file")
        paths.append(_safe_path(item["path"], "macos-inventory-path"))
        _sha256(item["sha256"], "macos-inventory-sha256")
        if (
            not isinstance(item["sizeBytes"], int)
            or isinstance(item["sizeBytes"], bool)
            or item["sizeBytes"] < 0
            or item["type"] not in {"macho", "resource"}
            or not isinstance(item["architectures"], list)
        ):
            raise MacReleaseContractError("macos-inventory-file-invalid")
        if item["type"] == "resource" and item["architectures"] != []:
            raise MacReleaseContractError("macos-resource-architecture-invalid")
        if item["type"] == "macho" and (
            item["architectures"] != ["arm64"] if require_arm64_only
            else item["architectures"] not in (
                ["arm64"],
                ["arm64", "arm64e"],
                ["arm64", "x86_64"],
                ["arm64", "arm64e", "x86_64"],
            )
        ):
            raise MacReleaseContractError("macos-inventory-architecture-invalid")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise MacReleaseContractError("macos-inventory-order-invalid")
    if inventory_digest(inventory["files"]) != inventory["inventorySha256"]:
        raise MacReleaseContractError("macos-inventory-digest-invalid")
    return inventory


def load_inventory(path: Path, *, require_arm64_only: bool = True) -> dict:
    raw, payload = _load_ascii_json(path, "macos-inventory")
    if raw != _canonical_bytes(payload):
        raise MacReleaseContractError("macos-inventory-not-canonical")
    return _validate_inventory(payload, require_arm64_only=require_arm64_only)


def normalize_arm64(root: Path) -> tuple[dict, dict, list[dict]]:
    before = capture_inventory(root)
    decisions = []
    for item in before["files"]:
        if item["type"] != "macho":
            continue
        path = root / PurePosixPath(item["path"])
        if len(item["architectures"]) > 1:
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=path.parent, prefix=f".{path.name}.", suffix=".arm64", delete=False
                ) as stream:
                    temporary = Path(stream.name)
                completed = subprocess.run(
                    ["lipo", str(path), "-thin", "arm64", "-output", str(temporary)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if completed.returncode != 0:
                    raise MacReleaseContractError("macos-lipo-failed")
                os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
                os.replace(temporary, path)
                temporary = None
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        after_item = _file_identity(path, item["path"])
        if after_item["architectures"] != ["arm64"]:
            raise MacReleaseContractError(
                f"macos-normalization-final-architecture-invalid:{item['path']}:{after_item['architectures']}"
            )
        decisions.append(
            {
                "path": item["path"],
                "originalArchitectures": item["architectures"],
                "originalSha256": item["sha256"],
                "originalSizeBytes": item["sizeBytes"],
                "normalizedArchitectures": after_item["architectures"],
                "normalizedSha256": after_item["sha256"],
                "normalizedSizeBytes": after_item["sizeBytes"],
                "changedByArm64Thinning": item["sha256"] != after_item["sha256"],
            }
        )
    after = capture_inventory(root, require_arm64_only=True)
    return before, after, decisions


def create_policy_candidate(inventory: dict) -> dict:
    _validate_inventory(inventory)
    return {
        "schemaVersion": 1,
        "target": "macos-arm64",
        "status": "review-required",
        "hashAlgorithm": "SHA-256",
        "approvedInventorySha256": inventory["inventorySha256"],
        "bundleTarget": "SupertonicVox.app",
        "entries": [
            {
                "path": item["path"],
                "origin": "REVIEW-REQUIRED",
                "type": item["type"],
                "action": "REVIEW-REQUIRED",
                "preSignSha256": item["sha256"],
                "sizeBytes": item["sizeBytes"],
                "architectures": item["architectures"],
                "entitlementsProfile": "REVIEW-REQUIRED" if item["type"] == "macho" else None,
                "approvalId": None,
            }
            for item in inventory["files"]
        ],
    }


def load_policy(path: Path = DEFAULT_POLICY, *, production: bool = False) -> dict:
    raw, payload = _load_ascii_json(path, "macos-signing-policy")
    _closed(payload, POLICY_KEYS, "macos-signing-policy")
    if raw != _canonical_bytes(payload):
        raise MacReleaseContractError("macos-signing-policy-not-canonical")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["target"] != "macos-arm64"
        or payload["hashAlgorithm"] != "SHA-256"
        or payload["status"] not in {"capture-required", "approved"}
    ):
        raise MacReleaseContractError("macos-signing-policy-header-invalid")
    if payload["status"] == "capture-required":
        if payload["approvedInventorySha256"] is not None or payload["bundleTarget"] is not None or payload["entries"] != []:
            raise MacReleaseContractError("macos-capture-policy-invalid")
        if production:
            raise MacReleaseContractError("macos-production-policy-not-approved")
        return payload
    _sha256(payload["approvedInventorySha256"], "macos-policy-inventory")
    if payload["bundleTarget"] != "SupertonicVox.app" or not isinstance(payload["entries"], list) or not payload["entries"]:
        raise MacReleaseContractError("macos-approved-policy-invalid")
    files = []
    paths = []
    for value in payload["entries"]:
        item = _closed(value, POLICY_ENTRY_KEYS, "macos-policy-entry")
        path_value = _safe_path(item["path"], "macos-policy-path")
        paths.append(path_value)
        if item["origin"] not in {"first-party", "microsoft", "third-party"}:
            raise MacReleaseContractError("macos-policy-origin-invalid")
        if item["type"] not in {"macho", "resource"}:
            raise MacReleaseContractError("macos-policy-type-invalid")
        expected_action = "owner-sign" if item["type"] == "macho" else "hash-only-resource"
        if item["action"] != expected_action:
            raise MacReleaseContractError("macos-policy-action-invalid")
        _sha256(item["preSignSha256"], "macos-policy-pre-sign")
        if not isinstance(item["sizeBytes"], int) or isinstance(item["sizeBytes"], bool) or item["sizeBytes"] < 0:
            raise MacReleaseContractError("macos-policy-size-invalid")
        expected_architectures = ["arm64"] if item["type"] == "macho" else []
        if item["architectures"] != expected_architectures:
            raise MacReleaseContractError("macos-policy-architecture-invalid")
        expected_profile = "none" if item["type"] == "macho" else None
        if item["entitlementsProfile"] != expected_profile:
            raise MacReleaseContractError("macos-policy-entitlements-profile-invalid")
        if item["origin"] == "third-party" and not isinstance(item["approvalId"], str):
            raise MacReleaseContractError("macos-third-party-approval-required")
        if item["origin"] != "third-party" and item["approvalId"] is not None:
            raise MacReleaseContractError("macos-policy-unexpected-approval")
        files.append(
            {
                "path": path_value,
                "sha256": item["preSignSha256"],
                "sizeBytes": item["sizeBytes"],
                "type": item["type"],
                "architectures": item["architectures"],
            }
        )
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise MacReleaseContractError("macos-policy-order-invalid")
    if inventory_digest(files) != payload["approvedInventorySha256"]:
        raise MacReleaseContractError("macos-policy-inventory-binding-invalid")
    return payload


def verify_signing_transition(policy: dict, inventory: dict, phase: str) -> list[dict]:
    if policy["status"] != "approved" or phase not in {"pre-sign", "signed"}:
        raise MacReleaseContractError("macos-signing-transition-state-invalid")
    _validate_inventory(inventory)
    expected = {item["path"]: item for item in policy["entries"]}
    actual = {item["path"]: item for item in inventory["files"]}
    required_paths = set(expected) if phase == "pre-sign" else set(expected) | SIGNING_METADATA_PATHS
    if required_paths != set(actual):
        raise MacReleaseContractError("macos-signing-transition-path-set-invalid")
    for path in SIGNING_METADATA_PATHS & set(actual):
        if actual[path]["type"] != "resource" or actual[path]["architectures"] != []:
            raise MacReleaseContractError("macos-signing-metadata-invalid")
    decisions = []
    for path in sorted(expected):
        policy_item = expected[path]
        item = actual[path]
        if item["type"] != policy_item["type"] or item["architectures"] != policy_item["architectures"]:
            raise MacReleaseContractError("macos-signing-transition-type-invalid")
        changed = item["sha256"] != policy_item["preSignSha256"] or item["sizeBytes"] != policy_item["sizeBytes"]
        must_change = phase == "signed" and policy_item["action"] == "owner-sign"
        if changed != must_change:
            raise MacReleaseContractError("macos-signing-transition-change-invalid")
        decisions.append(
            {
                "path": path,
                "action": policy_item["action"],
                "type": item["type"],
                "architectures": item["architectures"],
                "preSignSha256": policy_item["preSignSha256"],
                "finalSha256": item["sha256"],
                "finalSizeBytes": item["sizeBytes"],
                "changedByOwnerSigning": changed,
            }
        )
    return decisions


def _validate_signer(value: object, contract: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "leafCertificateSha256", "subject", "teamId", "secureTimestamp", "certificateKind"
    }:
        raise MacReleaseContractError("macos-evidence-signer-shape-invalid")
    identity = contract["identity"]
    if (
        _sha256(value["leafCertificateSha256"], "macos-evidence-signer-leaf") != identity["leafCertificateSha256"]
        or _normalized_subject(value["subject"], "macos-evidence-signer-subject") != identity["subject"]
        or value["teamId"] != identity["teamId"]
        or value["secureTimestamp"] is not True
        or value["certificateKind"] != "Developer ID Application"
    ):
        raise MacReleaseContractError("macos-evidence-signer-binding-invalid")
    return value


def _validate_notary(value: object, label: str) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"submissionId", "status", "logFile"}
        or not isinstance(value["submissionId"], str)
        or UUID.fullmatch(value["submissionId"]) is None
        or value["status"] != "Accepted"
    ):
        raise MacReleaseContractError(f"{label}-invalid")
    _identity(value["logFile"], f"{label}-log")
    return value


def validate_evidence(payload: object, contract: dict, policy: dict) -> None:
    if not isinstance(payload, dict) or set(payload) != EVIDENCE_KEYS:
        raise MacReleaseContractError("macos-evidence-shape-invalid")
    if payload["schemaVersion"] != 2 or isinstance(payload["schemaVersion"], bool):
        raise MacReleaseContractError("macos-evidence-version-invalid")
    if payload["releaseEligible"] is not False:
        raise MacReleaseContractError("macos-evidence-must-remain-noneligible")
    if not isinstance(payload["sourceCommit"], str) or COMMIT.fullmatch(payload["sourceCommit"]) is None:
        raise MacReleaseContractError("macos-evidence-commit-invalid")
    if not isinstance(payload["packageVersion"], str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", payload["packageVersion"]) is None:
        raise MacReleaseContractError("macos-evidence-version-string-invalid")
    if payload["identityMode"] != "owner-approved" or contract["identity"]["status"] != "owner-approved":
        raise MacReleaseContractError("macos-evidence-owner-identity-required")
    if policy["status"] != "approved":
        raise MacReleaseContractError("macos-evidence-approved-policy-required")
    if payload["contractSha256"] != hashlib.sha256(_canonical_bytes(contract)).hexdigest():
        raise MacReleaseContractError("macos-evidence-contract-binding-invalid")
    if payload["signingPolicySha256"] != hashlib.sha256(_canonical_bytes(policy)).hexdigest():
        raise MacReleaseContractError("macos-evidence-policy-binding-invalid")
    pre_normalization = _validate_inventory(
        payload["preNormalizationInventory"], require_arm64_only=False
    )
    normalized = _validate_inventory(payload["normalizedInventory"])
    signed = _validate_inventory(payload["signedInventory"])
    stapled = _validate_inventory(payload["stapledInventory"])
    if normalized["inventorySha256"] != policy["approvedInventorySha256"]:
        raise MacReleaseContractError("macos-evidence-normalized-inventory-binding-invalid")
    expected_decisions = verify_signing_transition(policy, signed, "signed")
    if payload["signingDecisions"] != expected_decisions:
        raise MacReleaseContractError("macos-evidence-signing-decisions-invalid")
    if not isinstance(payload["normalizationDecisions"], list) or not payload["normalizationDecisions"]:
        raise MacReleaseContractError("macos-evidence-normalization-decisions-invalid")
    normalization_keys = {
        "path",
        "originalArchitectures",
        "originalSha256",
        "originalSizeBytes",
        "normalizedArchitectures",
        "normalizedSha256",
        "normalizedSizeBytes",
        "changedByArm64Thinning",
    }
    pre_by_path = {item["path"]: item for item in pre_normalization["files"]}
    normalized_by_path = {item["path"]: item for item in normalized["files"]}
    if set(pre_by_path) != set(normalized_by_path):
        raise MacReleaseContractError("macos-evidence-normalization-file-set-invalid")
    normalized_machos = {
        item["path"]: item for item in normalized["files"] if item["type"] == "macho"
    }
    normalization_by_path: dict[str, dict] = {}
    accepted_inputs = contract["architecture"]["acceptedInputSets"]
    for value in payload["normalizationDecisions"]:
        if not isinstance(value, dict) or set(value) != normalization_keys:
            raise MacReleaseContractError("macos-evidence-normalization-decision-shape-invalid")
        path = _safe_path(value["path"], "macos-evidence-normalization-path")
        if path in normalization_by_path:
            raise MacReleaseContractError("macos-evidence-normalization-decision-duplicate")
        normalization_by_path[path] = value
        _sha256(value["originalSha256"], "macos-evidence-original-sha256")
        _sha256(value["normalizedSha256"], "macos-evidence-normalized-sha256")
        for key in ("originalSizeBytes", "normalizedSizeBytes"):
            if not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0:
                raise MacReleaseContractError("macos-evidence-normalization-size-invalid")
        if (
            value["originalArchitectures"] not in accepted_inputs
            or value["normalizedArchitectures"] != ["arm64"]
            or not isinstance(value["changedByArm64Thinning"], bool)
        ):
            raise MacReleaseContractError("macos-evidence-normalization-architecture-invalid")
        changed = (
            value["originalSha256"] != value["normalizedSha256"]
            or value["originalSizeBytes"] != value["normalizedSizeBytes"]
        )
        if value["changedByArm64Thinning"] is not changed:
            raise MacReleaseContractError("macos-evidence-normalization-transition-invalid")
        if changed != (len(value["originalArchitectures"]) > 1):
            raise MacReleaseContractError("macos-evidence-normalization-change-mode-invalid")
    if set(normalization_by_path) != set(normalized_machos):
        raise MacReleaseContractError("macos-evidence-normalization-path-set-invalid")
    for path, item in normalized_machos.items():
        decision = normalization_by_path[path]
        original = pre_by_path[path]
        if (
            original["type"] != "macho"
            or decision["originalSha256"] != original["sha256"]
            or decision["originalSizeBytes"] != original["sizeBytes"]
            or decision["originalArchitectures"] != original["architectures"]
            or decision["normalizedSha256"] != item["sha256"]
            or decision["normalizedSizeBytes"] != item["sizeBytes"]
            or decision["normalizedArchitectures"] != item["architectures"]
        ):
            raise MacReleaseContractError("macos-evidence-normalization-binding-invalid")
    for path, item in pre_by_path.items():
        if item["type"] == "resource" and item != normalized_by_path[path]:
            raise MacReleaseContractError("macos-evidence-normalization-resource-change-invalid")
    signed_by_path = {item["path"]: item for item in signed["files"]}
    stapled_by_path = {item["path"]: item for item in stapled["files"]}
    allowed_staple = set(contract["notarization"]["stapleMutablePaths"])
    if not set(signed_by_path).issubset(set(stapled_by_path)):
        raise MacReleaseContractError("macos-evidence-staple-removed-path-invalid")
    if set(stapled_by_path) - set(signed_by_path) != allowed_staple - set(signed_by_path):
        raise MacReleaseContractError("macos-evidence-staple-added-path-invalid")
    for path in set(signed_by_path) & set(stapled_by_path):
        if path not in allowed_staple and signed_by_path[path] != stapled_by_path[path]:
            raise MacReleaseContractError("macos-evidence-staple-change-invalid")
    app_stages = payload["appStages"]
    if not isinstance(app_stages, dict) or set(app_stages) != {
        "normalizedInventorySha256", "signedInventorySha256", "submissionZip", "stapledInventorySha256"
    }:
        raise MacReleaseContractError("macos-evidence-app-stages-invalid")
    if (
        app_stages["normalizedInventorySha256"] != normalized["inventorySha256"]
        or app_stages["signedInventorySha256"] != signed["inventorySha256"]
        or app_stages["stapledInventorySha256"] != stapled["inventorySha256"]
    ):
        raise MacReleaseContractError("macos-evidence-app-stage-binding-invalid")
    _identity(app_stages["submissionZip"], "macos-evidence-app-zip")
    dmg = payload["dmgStages"]
    if not isinstance(dmg, dict) or set(dmg) != {"unsigned", "signed", "stapled"}:
        raise MacReleaseContractError("macos-evidence-dmg-stages-invalid")
    for key in ("unsigned", "signed", "stapled"):
        _identity(dmg[key], f"macos-evidence-dmg-{key}")
    if len({dmg[key]["sha256"] for key in dmg}) != 3:
        raise MacReleaseContractError("macos-evidence-dmg-transition-invalid")
    signers = payload["signers"]
    if not isinstance(signers, dict) or set(signers) != {"app", "dmg"}:
        raise MacReleaseContractError("macos-evidence-signers-invalid")
    app_signer = _validate_signer(signers["app"], contract)
    dmg_signer = _validate_signer(signers["dmg"], contract)
    if app_signer != dmg_signer:
        raise MacReleaseContractError("macos-evidence-artifact-signer-mismatch")
    entitlements = payload["entitlements"]
    if not isinstance(entitlements, dict) or set(entitlements) != {"file", "extracted", "allowedKeys"}:
        raise MacReleaseContractError("macos-evidence-entitlements-invalid")
    if (
        _identity(entitlements["file"], "macos-evidence-entitlements-file")["sha256"]
        != contract["signing"]["entitlementsSha256"]
        or entitlements["extracted"] is not True
        or entitlements["allowedKeys"] != contract["signing"]["allowedEntitlements"]
    ):
        raise MacReleaseContractError("macos-evidence-entitlements-binding-invalid")
    notarization = payload["notarization"]
    if not isinstance(notarization, dict) or set(notarization) != {"app", "dmg"}:
        raise MacReleaseContractError("macos-evidence-notarization-invalid")
    app_notary = _validate_notary(notarization["app"], "macos-evidence-app-notary")
    dmg_notary = _validate_notary(notarization["dmg"], "macos-evidence-dmg-notary")
    if app_notary["submissionId"].casefold() == dmg_notary["submissionId"].casefold():
        raise MacReleaseContractError("macos-evidence-notary-submissions-not-distinct")
    verification_keys = {
        "signedAppCodesignStrict", "stapledAppCodesignStrict", "appStaplerValidate",
        "signedDmgCodesign", "dmgStaplerValidate", "mountedAppCodesignStrict",
        "mountedAppGatekeeper", "dmgGatekeeperPrimarySignature",
    }
    if (
        not isinstance(payload["verifications"], dict)
        or set(payload["verifications"]) != verification_keys
        or any(value is not True for value in payload["verifications"].values())
    ):
        raise MacReleaseContractError("macos-evidence-verification-incomplete")
    if not isinstance(payload["privacyEvidence"], list) or len(payload["privacyEvidence"]) < 2:
        raise MacReleaseContractError("macos-evidence-privacy-invalid")
    for value in payload["privacyEvidence"]:
        _identity(value, "macos-evidence-privacy")
    approvals = payload["externalApprovals"]
    if not isinstance(approvals, dict) or set(approvals) != {
        "sourceLicense", "modelRedistribution", "productionCatalogVerification"
    }:
        raise MacReleaseContractError("macos-evidence-approvals-invalid")
    for value in approvals.values():
        _identity(value, "macos-evidence-approval")
    if not isinstance(payload["toolchain"], dict) or set(payload["toolchain"]) != {
        "dotnetSdkVersion", "macosVersion", "xcodeVersion", "codesignExecutableSha256", "notarytoolVersion"
    }:
        raise MacReleaseContractError("macos-evidence-toolchain-invalid")
    _sha256(payload["toolchain"]["codesignExecutableSha256"], "macos-evidence-codesign-sha256")
    native = payload["nativeChecks"]
    if not isinstance(native, dict) or set(native) != {
        "quarantineApplied", "cleanAccountFirstLaunch", "offlineSynthesis", "saveRestart",
        "uninstall", "userDataPreserved", "noOrphanProcesses", "upgrade", "priorBaselineSha256"
    }:
        raise MacReleaseContractError("macos-evidence-native-checks-invalid")
    if any(native[key] != "missing" for key in (
        "quarantineApplied", "cleanAccountFirstLaunch", "offlineSynthesis", "saveRestart",
        "uninstall", "userDataPreserved", "noOrphanProcesses"
    )):
        raise MacReleaseContractError("macos-evidence-native-checks-premature")
    if native["upgrade"] not in {"not-applicable-first-release", "missing"}:
        raise MacReleaseContractError("macos-evidence-upgrade-state-invalid")
    if native["upgrade"] == "not-applicable-first-release":
        if native["priorBaselineSha256"] is not None:
            raise MacReleaseContractError("macos-evidence-first-release-baseline-invalid")
    else:
        _sha256(native["priorBaselineSha256"], "macos-evidence-prior-baseline")
    if payload["openGates"] != release_open_gates.load_contract()["requiredOpenGateIds"]:
        raise MacReleaseContractError("macos-evidence-open-gates-invalid")


def write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(_canonical_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise MacReleaseContractError("macos-atomic-write-failed") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    contract_parser = subparsers.add_parser("validate-contract")
    contract_parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    contract_parser.add_argument("--production", action="store_true")
    policy_parser = subparsers.add_parser("validate-policy")
    policy_parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    policy_parser.add_argument("--production", action="store_true")
    capture = subparsers.add_parser("capture-inventory")
    capture.add_argument("--root", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--require-arm64-only", action="store_true")
    normalize = subparsers.add_parser("normalize-arm64")
    normalize.add_argument("--root", type=Path, required=True)
    normalize.add_argument("--pre-inventory", type=Path, required=True)
    normalize.add_argument("--inventory", type=Path, required=True)
    normalize.add_argument("--report", type=Path, required=True)
    candidate = subparsers.add_parser("create-policy-candidate")
    candidate.add_argument("--inventory", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    transition = subparsers.add_parser("verify-signing-transition")
    transition.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    transition.add_argument("--inventory", type=Path, required=True)
    transition.add_argument("--phase", choices=("pre-sign", "signed"), required=True)
    transition.add_argument("--report", type=Path, required=True)
    evidence = subparsers.add_parser("validate-evidence")
    evidence.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    evidence.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    evidence.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-contract":
            contract = load_contract(args.contract, production=args.production)
            print(json.dumps({"contractSha256": hashlib.sha256(_canonical_bytes(contract)).hexdigest()}, sort_keys=True))
        elif args.command == "validate-policy":
            policy = load_policy(args.policy, production=args.production)
            print(json.dumps({"policySha256": hashlib.sha256(_canonical_bytes(policy)).hexdigest()}, sort_keys=True))
        elif args.command == "capture-inventory":
            inventory = capture_inventory(args.root.resolve(), require_arm64_only=args.require_arm64_only)
            write_json_atomic(args.output.resolve(), inventory)
            print(json.dumps({"inventorySha256": inventory["inventorySha256"]}, sort_keys=True))
        elif args.command == "normalize-arm64":
            pre_inventory, inventory, decisions = normalize_arm64(args.root.resolve())
            write_json_atomic(args.pre_inventory.resolve(), pre_inventory)
            write_json_atomic(args.inventory.resolve(), inventory)
            write_json_atomic(args.report.resolve(), {"schemaVersion": 1, "decisions": decisions})
            print(json.dumps({"normalizedInventorySha256": inventory["inventorySha256"]}, sort_keys=True))
        elif args.command == "create-policy-candidate":
            inventory = load_inventory(args.inventory)
            write_json_atomic(args.output.resolve(), create_policy_candidate(inventory))
            print(json.dumps({"policyCandidate": "review-required"}, sort_keys=True))
        elif args.command == "verify-signing-transition":
            policy = load_policy(args.policy, production=True)
            inventory = load_inventory(args.inventory)
            decisions = verify_signing_transition(policy, inventory, args.phase)
            write_json_atomic(args.report.resolve(), {"schemaVersion": 1, "phase": args.phase, "decisions": decisions})
            print(json.dumps({"signingTransition": "pass", "phase": args.phase}, sort_keys=True))
        else:
            contract = load_contract(args.contract, production=True)
            policy = load_policy(args.policy, production=True)
            _, payload = _load_ascii_json(args.evidence, "macos-evidence")
            validate_evidence(payload, contract, policy)
            print(json.dumps({"macosReleaseEvidence": "pass"}, sort_keys=True))
        return 0
    except (MacReleaseContractError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({"macosReleaseContractError": str(exc)}, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
