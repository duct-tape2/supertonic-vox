#!/usr/bin/env python3
"""Fail-closed Windows MSI identity, payload, signing-policy, and evidence contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import unicodedata
import uuid
import xml.etree.ElementTree as ET

import release_open_gates


DEFAULT_CONTRACT = Path(__file__).resolve().parents[1] / "packaging" / "windows-installer-contract.json"
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "packaging" / "windows-signing-policy.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
GUID = re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\Z")
STAGING_UPGRADE_CODE = "192DEAC4-89A6-5EB6-BF21-0E2F0AF94A5A"
STAGING_MANUFACTURER = "SupertonicVox STAGING ONLY"
CONTRACT_KEYS = (
    "schemaVersion",
    "target",
    "wixSdkVersion",
    "hashAlgorithm",
    "productCanonicalUri",
    "identity",
    "package",
    "signing",
    "requiredPayloadSubset",
    "userData",
    "releaseEligible",
    "openGates",
)
IDENTITY_KEYS = (
    "status",
    "upgradeCode",
    "stagingUpgradeCode",
    "manufacturer",
    "stagingManufacturer",
    "ownerApprovalId",
)
PACKAGE_KEYS = (
    "name",
    "platform",
    "scope",
    "installFolder",
    "executable",
    "startMenuShortcut",
    "allowDowngrades",
    "allowSameVersionUpgrades",
)
SIGNING_KEYS = (
    "mode",
    "digestAlgorithm",
    "timestampDigestAlgorithm",
    "timestampUrl",
)
USER_DATA_KEYS = ("installerOwnsUserData", "preservePaths")
POLICY_KEYS = (
    "schemaVersion",
    "target",
    "status",
    "hashAlgorithm",
    "approvedInventorySha256",
    "ownerCertificate",
    "entries",
)
POLICY_ENTRY_KEYS = (
    "path",
    "origin",
    "type",
    "action",
    "preSignSha256",
    "sizeBytes",
    "approvalId",
    "allowedSigners",
)
SIGNER_KEYS = ("leafCertificateSha256", "subject")
OWNER_SIGNER_KEYS = ("leafCertificateSha256", "subject", "approvalId")
INVENTORY_KEYS = ("schemaVersion", "target", "hashAlgorithm", "files", "inventorySha256")
INVENTORY_FILE_KEYS = ("path", "sha256", "sizeBytes", "type")
EVIDENCE_KEYS = {
    "schemaVersion",
    "releaseEligible",
    "sourceCommit",
    "packageVersion",
    "identityMode",
    "upgradeCode",
    "productCode",
    "packageCode",
    "contractSha256",
    "signingPolicySha256",
    "preSignInventorySha256",
    "finalInventorySha256",
    "payloadManifestSha256",
    "unsignedMsiSha256",
    "iceValidatedUnsignedMsiSha256",
    "signedMsiSha256",
    "msiSigner",
    "timestamp",
    "toolchain",
    "signingDecisions",
    "iceValidation",
    "privacyEvidence",
    "externalApprovals",
    "nativeChecks",
    "openGates",
}


class WindowsMsiContractError(RuntimeError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WindowsMsiContractError(f"duplicate-key:{key}")
        result[key] = value
    return result


def _load_ascii_json(path: Path, label: str) -> tuple[bytes, dict]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsMsiContractError(f"{label}-unavailable") from exc
    if not isinstance(payload, dict):
        raise WindowsMsiContractError(f"{label}-shape-invalid")
    return raw, payload


def _canonical_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _closed_dict(value: object, keys: tuple[str, ...], label: str) -> dict:
    if not isinstance(value, dict) or tuple(value) != keys:
        raise WindowsMsiContractError(f"{label}-shape-invalid")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(character) < 0x20 for character in value):
        raise WindowsMsiContractError(f"{label}-invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise WindowsMsiContractError(f"{label}-invalid")
    return value


def _guid(value: object, label: str) -> str:
    if not isinstance(value, str) or GUID.fullmatch(value) is None:
        raise WindowsMsiContractError(f"{label}-invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise WindowsMsiContractError(f"{label}-invalid") from exc
    if parsed.int == 0:
        raise WindowsMsiContractError(f"{label}-invalid")
    return value


def _safe_path(value: object, label: str) -> str:
    path = _string(value, label)
    pure = PurePosixPath(path)
    if (
        "\\" in path
        or "\x00" in path
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise WindowsMsiContractError(f"{label}-invalid")
    return path


def _normalized_subject(value: object, label: str) -> str:
    subject = _string(value, label)
    normalized = unicodedata.normalize("NFKC", subject).strip()
    if normalized != subject or len(subject) > 512:
        raise WindowsMsiContractError(f"{label}-invalid")
    return subject


def parse_version(value: str) -> tuple[int, int, int]:
    match = VERSION.fullmatch(value)
    if match is None:
        raise WindowsMsiContractError("package-version-invalid")
    parts = tuple(int(item) for item in match.groups())
    if parts[0] > 255 or parts[1] > 255 or parts[2] > 65535:
        raise WindowsMsiContractError("package-version-msi-overflow")
    return parts


def load_contract(path: Path = DEFAULT_CONTRACT, *, production: bool = False) -> dict:
    raw, payload = _load_ascii_json(path, "installer-contract")
    _closed_dict(payload, CONTRACT_KEYS, "installer-contract")
    if _canonical_bytes(payload) != raw:
        raise WindowsMsiContractError("installer-contract-not-canonical")
    if payload["schemaVersion"] != 1 or isinstance(payload["schemaVersion"], bool):
        raise WindowsMsiContractError("installer-contract-version-invalid")
    if (
        payload["target"] != "win-x64"
        or payload["wixSdkVersion"] != "7.0.0"
        or payload["hashAlgorithm"] != "SHA-256"
        or payload["productCanonicalUri"] != "https://supertonicvox.example.invalid/windows"
    ):
        raise WindowsMsiContractError("installer-contract-platform-invalid")

    identity = _closed_dict(payload["identity"], IDENTITY_KEYS, "installer-identity")
    upgrade_code = _guid(identity["upgradeCode"], "upgrade-code")
    if identity["stagingUpgradeCode"] != STAGING_UPGRADE_CODE:
        raise WindowsMsiContractError("staging-upgrade-code-invalid")
    manufacturer = _string(identity["manufacturer"], "manufacturer")
    if identity["stagingManufacturer"] != STAGING_MANUFACTURER:
        raise WindowsMsiContractError("staging-manufacturer-invalid")
    if identity["status"] not in {"staging-placeholder", "owner-approved"}:
        raise WindowsMsiContractError("identity-status-invalid")
    if identity["status"] == "staging-placeholder":
        if (
            upgrade_code != STAGING_UPGRADE_CODE
            or manufacturer != STAGING_MANUFACTURER
            or identity["ownerApprovalId"] is not None
        ):
            raise WindowsMsiContractError("staging-identity-invalid")
    else:
        if (
            upgrade_code == STAGING_UPGRADE_CODE
            or manufacturer == STAGING_MANUFACTURER
            or not isinstance(identity["ownerApprovalId"], str)
            or not identity["ownerApprovalId"]
        ):
            raise WindowsMsiContractError("owner-identity-invalid")

    package = _closed_dict(payload["package"], PACKAGE_KEYS, "installer-package")
    expected_package = {
        "name": "SupertonicVox",
        "platform": "x64",
        "scope": "perMachine",
        "installFolder": "ProgramFiles64Folder\\SupertonicVox",
        "executable": "SupertonicVox.Desktop.exe",
        "startMenuShortcut": True,
        "allowDowngrades": False,
        "allowSameVersionUpgrades": False,
    }
    if package != expected_package:
        raise WindowsMsiContractError("installer-package-invalid")

    signing = _closed_dict(payload["signing"], SIGNING_KEYS, "installer-signing")
    if signing != {
        "mode": "certificate-store-or-hsm",
        "digestAlgorithm": "SHA-256",
        "timestampDigestAlgorithm": "SHA-256",
        "timestampUrl": "https://timestamp.digicert.com",
    }:
        raise WindowsMsiContractError("installer-signing-invalid")

    subset = payload["requiredPayloadSubset"]
    if (
        not isinstance(subset, list)
        or len(subset) < 10
        or subset != sorted(subset)
        or len(subset) != len(set(subset))
    ):
        raise WindowsMsiContractError("required-payload-subset-invalid")
    for item in subset:
        _safe_path(item, "required-payload-path")

    user_data = _closed_dict(payload["userData"], USER_DATA_KEYS, "installer-user-data")
    if user_data != {
        "installerOwnsUserData": False,
        "preservePaths": [
            "%LOCALAPPDATA%\\SupertonicVox",
            "%USERPROFILE%\\Documents\\SupertonicVox",
        ],
    }:
        raise WindowsMsiContractError("installer-user-data-invalid")
    if payload["releaseEligible"] is not False:
        raise WindowsMsiContractError("installer-contract-release-state-invalid")
    if payload["openGates"] != release_open_gates.load_contract()["requiredOpenGateIds"]:
        raise WindowsMsiContractError("installer-contract-open-gates-invalid")
    if production and identity["status"] != "owner-approved":
        raise WindowsMsiContractError("production-identity-not-approved")
    return payload


def contract_sha256(path: Path = DEFAULT_CONTRACT) -> str:
    load_contract(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_signer(value: object, label: str, *, owner: bool = False) -> dict:
    keys = OWNER_SIGNER_KEYS if owner else SIGNER_KEYS
    signer = _closed_dict(value, keys, label)
    _sha256(signer["leafCertificateSha256"], f"{label}-leaf")
    _normalized_subject(signer["subject"], f"{label}-subject")
    if owner and not isinstance(signer["approvalId"], str):
        raise WindowsMsiContractError(f"{label}-approval-invalid")
    return signer


def inventory_digest(files: list[dict]) -> str:
    raw = json.dumps(files, ensure_ascii=True, separators=(",", ":"), sort_keys=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def load_policy(path: Path = DEFAULT_POLICY, *, production: bool = False) -> dict:
    raw, payload = _load_ascii_json(path, "signing-policy")
    _closed_dict(payload, POLICY_KEYS, "signing-policy")
    if _canonical_bytes(payload) != raw:
        raise WindowsMsiContractError("signing-policy-not-canonical")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["target"] != "win-x64"
        or payload["hashAlgorithm"] != "SHA-256"
        or payload["status"] not in {"capture-required", "approved"}
    ):
        raise WindowsMsiContractError("signing-policy-header-invalid")
    if payload["status"] == "capture-required":
        if payload["approvedInventorySha256"] is not None or payload["ownerCertificate"] is not None or payload["entries"] != []:
            raise WindowsMsiContractError("capture-required-policy-invalid")
        if production:
            raise WindowsMsiContractError("production-signing-policy-not-approved")
        return payload

    approved_digest = _sha256(payload["approvedInventorySha256"], "approved-inventory-sha256")
    entries = payload["entries"]
    if not isinstance(entries, list) or not entries:
        raise WindowsMsiContractError("signing-policy-entries-invalid")
    paths: set[str] = set()
    canonical_paths: set[str] = set()
    inventory_files: list[dict] = []
    owner_sign_required = False
    for entry in entries:
        item = _closed_dict(entry, POLICY_ENTRY_KEYS, "signing-policy-entry")
        path_value = _safe_path(item["path"], "signing-policy-path")
        canonical_path = unicodedata.normalize("NFKC", path_value).casefold()
        if path_value in paths or canonical_path in canonical_paths:
            raise WindowsMsiContractError("signing-policy-path-duplicate")
        paths.add(path_value)
        canonical_paths.add(canonical_path)
        if item["origin"] not in {"first-party", "microsoft", "third-party"}:
            raise WindowsMsiContractError("signing-policy-origin-invalid")
        if item["type"] not in {"pe", "non-pe"}:
            raise WindowsMsiContractError("signing-policy-type-invalid")
        if item["action"] not in {
            "owner-sign",
            "verify-existing-authenticode",
            "approved-unsigned-pe",
            "hash-only-non-pe",
        }:
            raise WindowsMsiContractError("signing-policy-action-invalid")
        _sha256(item["preSignSha256"], "pre-sign-sha256")
        if not isinstance(item["sizeBytes"], int) or isinstance(item["sizeBytes"], bool) or item["sizeBytes"] < 0:
            raise WindowsMsiContractError("signing-policy-size-invalid")
        if not isinstance(item["allowedSigners"], list):
            raise WindowsMsiContractError("allowed-signers-invalid")
        action = item["action"]
        if item["type"] == "non-pe" and action != "hash-only-non-pe":
            raise WindowsMsiContractError("non-pe-signing-action-invalid")
        if item["type"] == "pe" and action == "hash-only-non-pe":
            raise WindowsMsiContractError("pe-signing-action-invalid")
        if action == "verify-existing-authenticode":
            if not item["allowedSigners"]:
                raise WindowsMsiContractError("expected-signer-required")
            for signer in item["allowedSigners"]:
                _validate_signer(signer, "expected-signer")
            if item["approvalId"] is not None:
                raise WindowsMsiContractError("verify-existing-approval-invalid")
        else:
            if item["allowedSigners"] != []:
                raise WindowsMsiContractError("unexpected-allowed-signer")
        if action == "owner-sign":
            owner_sign_required = True
            if item["origin"] == "third-party" and not isinstance(item["approvalId"], str):
                raise WindowsMsiContractError("third-party-sign-approval-required")
        elif action == "approved-unsigned-pe":
            if not isinstance(item["approvalId"], str) or not item["approvalId"]:
                raise WindowsMsiContractError("unsigned-pe-approval-required")
        elif action == "hash-only-non-pe" and item["approvalId"] is not None:
            raise WindowsMsiContractError("non-pe-approval-invalid")
        inventory_files.append(
            {
                "path": path_value,
                "sha256": item["preSignSha256"],
                "sizeBytes": item["sizeBytes"],
                "type": item["type"],
            }
        )
    if [entry["path"] for entry in entries] != sorted(paths):
        raise WindowsMsiContractError("signing-policy-order-invalid")
    if inventory_digest(inventory_files) != approved_digest:
        raise WindowsMsiContractError("approved-inventory-sha256-mismatch")
    if production and payload["ownerCertificate"] is None:
        raise WindowsMsiContractError("production-owner-certificate-required")
    if owner_sign_required:
        _validate_signer(payload["ownerCertificate"], "owner-certificate", owner=True)
    elif payload["ownerCertificate"] is not None:
        _validate_signer(payload["ownerCertificate"], "owner-certificate", owner=True)
    return payload


def policy_sha256(path: Path = DEFAULT_POLICY) -> str:
    load_policy(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_policy_candidate(inventory: dict) -> dict:
    return {
        "schemaVersion": 1,
        "target": "win-x64",
        "status": "review-required",
        "hashAlgorithm": "SHA-256",
        "approvedInventorySha256": inventory["inventorySha256"],
        "ownerCertificate": None,
        "entries": [
            {
                "path": item["path"],
                "origin": "REVIEW-REQUIRED",
                "type": item["type"],
                "action": "REVIEW-REQUIRED",
                "preSignSha256": item["sha256"],
                "sizeBytes": item["sizeBytes"],
                "approvalId": None,
                "allowedSigners": [],
            }
            for item in inventory["files"]
        ],
    }


def verify_inventory_transition(policy: dict, inventory: dict, phase: str) -> list[dict]:
    if policy["status"] != "approved":
        raise WindowsMsiContractError("inventory-transition-policy-not-approved")
    if phase not in {"pre-sign", "final"}:
        raise WindowsMsiContractError("inventory-transition-phase-invalid")
    policy_by_path = {item["path"]: item for item in policy["entries"]}
    inventory_by_path = {item["path"]: item for item in inventory["files"]}
    if set(policy_by_path) != set(inventory_by_path):
        raise WindowsMsiContractError("inventory-transition-path-set-mismatch")
    decisions: list[dict] = []
    for path in sorted(policy_by_path):
        expected = policy_by_path[path]
        actual = inventory_by_path[path]
        if actual["type"] != expected["type"]:
            raise WindowsMsiContractError("inventory-transition-type-mismatch")
        changed = (
            actual["sha256"] != expected["preSignSha256"]
            or actual["sizeBytes"] != expected["sizeBytes"]
        )
        if phase == "pre-sign" and changed:
            raise WindowsMsiContractError("pre-sign-inventory-mismatch")
        if phase == "final" and expected["action"] != "owner-sign" and changed:
            raise WindowsMsiContractError("unapproved-final-inventory-change")
        if phase == "final" and expected["action"] == "owner-sign" and not changed:
            raise WindowsMsiContractError("owner-sign-transition-missing")
        decisions.append(
            {
                "path": path,
                "action": expected["action"],
                "type": actual["type"],
                "preSignSha256": expected["preSignSha256"],
                "finalSha256": actual["sha256"],
                "finalSizeBytes": actual["sizeBytes"],
                "changedByApprovedOwnerSigning": phase == "final" and changed,
            }
        )
    return decisions


def derive_product_code(contract: dict, version: str, *, production: bool = False) -> str:
    parse_version(version)
    identity = contract["identity"]
    if production and (
        identity["status"] != "owner-approved"
        or identity["upgradeCode"] == STAGING_UPGRADE_CODE
    ):
        raise WindowsMsiContractError("production-product-code-refuses-staging-identity")
    namespace = uuid.UUID(identity["upgradeCode"])
    name = f"{contract['productCanonicalUri']}\n{version}"
    return str(uuid.uuid5(namespace, name)).upper()


def derive_component_guid(contract: dict, relative: str) -> str:
    path = _safe_path(relative, "component-path")
    return str(uuid.uuid5(uuid.UUID(contract["identity"]["upgradeCode"]), f"component:{path}")).upper()


def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                return False
            stream.seek(0x3C)
            offset_raw = stream.read(4)
            if len(offset_raw) != 4:
                return False
            offset = int.from_bytes(offset_raw, "little")
            if offset < 0x40 or offset > 16 * 1024 * 1024:
                return False
            stream.seek(offset)
            return stream.read(4) == b"PE\x00\x00"
    except OSError as exc:
        raise WindowsMsiContractError("inventory-file-unreadable") from exc


def capture_inventory(root: Path) -> dict:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise WindowsMsiContractError("inventory-root-unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
        raise WindowsMsiContractError("inventory-root-invalid")
    files: list[dict] = []
    canonical_paths: set[str] = set()
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        names.sort()
        for directory in directories:
            candidate = current_path / directory
            if candidate.is_symlink() or not candidate.is_dir():
                raise WindowsMsiContractError("inventory-directory-invalid")
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            safe = _safe_path(relative, "inventory-path")
            try:
                info = path.lstat()
            except OSError as exc:
                raise WindowsMsiContractError("inventory-file-unavailable") from exc
            canonical = unicodedata.normalize("NFKC", safe).casefold()
            if (
                not stat.S_ISREG(info.st_mode)
                or path.is_symlink()
                or info.st_nlink != 1
                or canonical in canonical_paths
            ):
                raise WindowsMsiContractError("inventory-file-invalid")
            canonical_paths.add(canonical)
            digest = hashlib.sha256()
            total = 0
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                    total += len(chunk)
            if total != info.st_size:
                raise WindowsMsiContractError("inventory-file-changed")
            files.append(
                {
                    "path": safe,
                    "sha256": digest.hexdigest(),
                    "sizeBytes": total,
                    "type": "pe" if _is_pe(path) else "non-pe",
                }
            )
    files.sort(key=lambda item: item["path"])
    if not files:
        raise WindowsMsiContractError("inventory-empty")
    return {
        "schemaVersion": 1,
        "target": "win-x64",
        "hashAlgorithm": "SHA-256",
        "files": files,
        "inventorySha256": inventory_digest(files),
    }


def load_inventory(path: Path) -> dict:
    raw, payload = _load_ascii_json(path, "inventory")
    _closed_dict(payload, INVENTORY_KEYS, "inventory")
    if _canonical_bytes(payload) != raw:
        raise WindowsMsiContractError("inventory-not-canonical")
    if (
        payload["schemaVersion"] != 1
        or isinstance(payload["schemaVersion"], bool)
        or payload["target"] != "win-x64"
        or payload["hashAlgorithm"] != "SHA-256"
        or not isinstance(payload["files"], list)
        or not payload["files"]
    ):
        raise WindowsMsiContractError("inventory-header-invalid")
    paths = []
    for item in payload["files"]:
        file = _closed_dict(item, INVENTORY_FILE_KEYS, "inventory-file")
        paths.append(_safe_path(file["path"], "inventory-path"))
        _sha256(file["sha256"], "inventory-sha256")
        if not isinstance(file["sizeBytes"], int) or isinstance(file["sizeBytes"], bool) or file["sizeBytes"] < 0:
            raise WindowsMsiContractError("inventory-size-invalid")
        if file["type"] not in {"pe", "non-pe"}:
            raise WindowsMsiContractError("inventory-type-invalid")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise WindowsMsiContractError("inventory-path-order-invalid")
    if inventory_digest(payload["files"]) != payload["inventorySha256"]:
        raise WindowsMsiContractError("inventory-digest-mismatch")
    return payload


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(_canonical_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise WindowsMsiContractError("atomic-write-failed") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _wix_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}_{digest}"


def generate_components(contract: dict, inventory: dict, output: Path) -> None:
    namespace = "http://wixtoolset.org/schemas/v4/wxs"
    ET.register_namespace("", namespace)
    wix = ET.Element(f"{{{namespace}}}Wix")
    directory_fragment = ET.SubElement(wix, f"{{{namespace}}}Fragment")
    root_ref = ET.SubElement(directory_fragment, f"{{{namespace}}}DirectoryRef", {"Id": "INSTALLFOLDER"})
    directories: dict[tuple[str, ...], ET.Element] = {(): root_ref}
    component_ids: list[str] = []
    for item in inventory["files"]:
        relative = _safe_path(item["path"], "inventory-path")
        parts = PurePosixPath(relative).parts
        parent_parts: tuple[str, ...] = ()
        parent = root_ref
        for part in parts[:-1]:
            parent_parts = parent_parts + (part,)
            if parent_parts not in directories:
                directories[parent_parts] = ET.SubElement(
                    parent,
                    f"{{{namespace}}}Directory",
                    {"Id": _wix_id("dir", "/".join(parent_parts)), "Name": part},
                )
            parent = directories[parent_parts]
        component_id = _wix_id("cmp", relative)
        component_ids.append(component_id)
        component = ET.SubElement(
            parent,
            f"{{{namespace}}}Component",
            {"Id": component_id, "Guid": derive_component_guid(contract, relative)},
        )
        ET.SubElement(
            component,
            f"{{{namespace}}}File",
            {
                "Id": _wix_id("fil", relative),
                "Source": "$(var.PayloadRoot)\\" + relative.replace("/", "\\"),
                "Name": parts[-1],
                "KeyPath": "yes",
            },
        )
    group_fragment = ET.SubElement(wix, f"{{{namespace}}}Fragment")
    group = ET.SubElement(group_fragment, f"{{{namespace}}}ComponentGroup", {"Id": "ProductComponents"})
    for component_id in component_ids:
        ET.SubElement(group, f"{{{namespace}}}ComponentRef", {"Id": component_id})
    ET.indent(wix, space="  ")
    raw = ET.tostring(wix, encoding="utf-8", xml_declaration=True) + b"\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)


def validate_evidence(payload: object, contract: dict, policy: dict) -> None:
    if not isinstance(payload, dict) or set(payload) != EVIDENCE_KEYS:
        raise WindowsMsiContractError("msi-evidence-shape-invalid")
    if payload["schemaVersion"] != 2 or isinstance(payload["schemaVersion"], bool):
        raise WindowsMsiContractError("msi-evidence-version-invalid")
    if not isinstance(payload["releaseEligible"], bool):
        raise WindowsMsiContractError("msi-evidence-release-state-invalid")
    if not isinstance(payload["sourceCommit"], str) or COMMIT.fullmatch(payload["sourceCommit"]) is None:
        raise WindowsMsiContractError("msi-evidence-commit-invalid")
    parse_version(payload["packageVersion"])
    if payload["identityMode"] not in {"staging-placeholder", "owner-approved"}:
        raise WindowsMsiContractError("msi-evidence-identity-invalid")
    for key in ("upgradeCode", "productCode", "packageCode"):
        _guid(payload[key], f"msi-evidence-{key}")
    if payload["upgradeCode"] != contract["identity"]["upgradeCode"]:
        raise WindowsMsiContractError("msi-evidence-upgrade-code-binding-invalid")
    if payload["productCode"] != derive_product_code(
        contract,
        payload["packageVersion"],
        production=False,
    ):
        raise WindowsMsiContractError("msi-evidence-product-code-binding-invalid")
    if payload["packageCode"] in {payload["upgradeCode"], payload["productCode"]}:
        raise WindowsMsiContractError("msi-evidence-package-code-invalid")
    for key in (
        "contractSha256",
        "signingPolicySha256",
        "preSignInventorySha256",
        "finalInventorySha256",
        "payloadManifestSha256",
        "unsignedMsiSha256",
        "iceValidatedUnsignedMsiSha256",
    ):
        _sha256(payload[key], f"msi-evidence-{key}")
    signed_hash = payload["signedMsiSha256"]
    if signed_hash is not None:
        _sha256(signed_hash, "msi-evidence-signed-msi")
    if payload["iceValidatedUnsignedMsiSha256"] != payload["unsignedMsiSha256"]:
        raise WindowsMsiContractError("ice-unsigned-msi-binding-invalid")
    if payload["contractSha256"] != hashlib.sha256(_canonical_bytes(contract)).hexdigest():
        raise WindowsMsiContractError("msi-evidence-contract-binding-invalid")
    if payload["signingPolicySha256"] != hashlib.sha256(_canonical_bytes(policy)).hexdigest():
        raise WindowsMsiContractError("msi-evidence-policy-binding-invalid")
    if policy["status"] != "approved":
        raise WindowsMsiContractError("msi-evidence-signing-policy-not-approved")
    if payload["preSignInventorySha256"] != policy["approvedInventorySha256"]:
        raise WindowsMsiContractError("msi-evidence-pre-sign-inventory-binding-invalid")
    if not isinstance(payload["signingDecisions"], list):
        raise WindowsMsiContractError("msi-evidence-signing-decisions-invalid")
    decision_keys = {
        "path",
        "action",
        "type",
        "preSignSha256",
        "finalSha256",
        "finalSizeBytes",
        "changedByApprovedOwnerSigning",
    }
    decisions_by_path: dict[str, dict] = {}
    for decision in payload["signingDecisions"]:
        if not isinstance(decision, dict) or set(decision) != decision_keys:
            raise WindowsMsiContractError("msi-evidence-signing-decision-shape-invalid")
        decision_path = _safe_path(decision["path"], "msi-evidence-signing-path")
        if decision_path in decisions_by_path:
            raise WindowsMsiContractError("msi-evidence-signing-decision-duplicate")
        decisions_by_path[decision_path] = decision
        if decision["type"] not in {"pe", "non-pe"}:
            raise WindowsMsiContractError("msi-evidence-signing-type-invalid")
        _sha256(decision["preSignSha256"], "msi-evidence-pre-sign-sha256")
        _sha256(decision["finalSha256"], "msi-evidence-final-sha256")
        if (
            not isinstance(decision["finalSizeBytes"], int)
            or isinstance(decision["finalSizeBytes"], bool)
            or decision["finalSizeBytes"] < 0
        ):
            raise WindowsMsiContractError("msi-evidence-final-size-invalid")
        if not isinstance(decision["changedByApprovedOwnerSigning"], bool):
            raise WindowsMsiContractError("msi-evidence-signing-transition-invalid")
    entries_by_path = {entry["path"]: entry for entry in policy["entries"]}
    if set(decisions_by_path) != set(entries_by_path):
        raise WindowsMsiContractError("msi-evidence-signing-decisions-incomplete")
    final_files: list[dict] = []
    for path, entry in entries_by_path.items():
        decision = decisions_by_path[path]
        if (
            decision["action"] != entry["action"]
            or decision["type"] != entry["type"]
            or decision["preSignSha256"] != entry["preSignSha256"]
        ):
            raise WindowsMsiContractError("msi-evidence-signing-decision-binding-invalid")
        changed = (
            decision["preSignSha256"] != decision["finalSha256"]
            or entry["sizeBytes"] != decision["finalSizeBytes"]
        )
        if decision["changedByApprovedOwnerSigning"] is not changed:
            raise WindowsMsiContractError("msi-evidence-signing-transition-invalid")
        if changed != (entry["action"] == "owner-sign"):
            raise WindowsMsiContractError("msi-evidence-signing-action-transition-invalid")
        final_files.append(
            {
                "path": path,
                "sha256": decision["finalSha256"],
                "sizeBytes": decision["finalSizeBytes"],
                "type": decision["type"],
            }
        )
    final_files.sort(key=lambda item: item["path"])
    computed_final_digest = inventory_digest(final_files)
    if computed_final_digest != payload["finalInventorySha256"]:
        raise WindowsMsiContractError("msi-evidence-final-inventory-binding-invalid")
    final_manifest = {
        "schemaVersion": 1,
        "target": "win-x64",
        "hashAlgorithm": "SHA-256",
        "files": final_files,
        "inventorySha256": computed_final_digest,
    }
    if hashlib.sha256(_canonical_bytes(final_manifest)).hexdigest() != payload["payloadManifestSha256"]:
        raise WindowsMsiContractError("msi-evidence-payload-manifest-binding-invalid")
    if not isinstance(payload["privacyEvidence"], list) or not payload["privacyEvidence"]:
        raise WindowsMsiContractError("msi-evidence-privacy-invalid")
    for identity in payload["privacyEvidence"]:
        if (
            not isinstance(identity, dict)
            or set(identity) != {"name", "sha256", "sizeBytes"}
            or not isinstance(identity["name"], str)
            or PurePosixPath(identity["name"]).name != identity["name"]
            or not isinstance(identity["sizeBytes"], int)
            or isinstance(identity["sizeBytes"], bool)
            or identity["sizeBytes"] < 1
        ):
            raise WindowsMsiContractError("msi-evidence-privacy-identity-invalid")
        _sha256(identity["sha256"], "msi-evidence-privacy-sha256")
    approvals = payload["externalApprovals"]
    if not isinstance(approvals, dict) or set(approvals) != {
        "sourceLicense",
        "modelRedistribution",
        "productionCatalogVerification",
    }:
        raise WindowsMsiContractError("msi-evidence-approvals-invalid")
    for role, identity in approvals.items():
        if identity is None:
            continue
        if (
            not isinstance(identity, dict)
            or set(identity) != {"name", "sha256", "sizeBytes"}
            or not isinstance(identity["name"], str)
            or PurePosixPath(identity["name"]).name != identity["name"]
            or not isinstance(identity["sizeBytes"], int)
            or isinstance(identity["sizeBytes"], bool)
            or identity["sizeBytes"] < 1
        ):
            raise WindowsMsiContractError(f"msi-evidence-approval-identity-invalid:{role}")
        _sha256(identity["sha256"], f"msi-evidence-approval-sha256:{role}")
    expected_toolchain = {
        "dotnetSdkVersion",
        "wixSdkVersion",
        "powerShellVersion",
        "windowsVersion",
        "signToolVersion",
    }
    if not isinstance(payload["toolchain"], dict) or set(payload["toolchain"]) != expected_toolchain:
        raise WindowsMsiContractError("msi-evidence-toolchain-invalid")
    if payload["toolchain"]["wixSdkVersion"] != contract["wixSdkVersion"]:
        raise WindowsMsiContractError("msi-evidence-wix-version-invalid")
    ice = payload["iceValidation"]
    if (
        not isinstance(ice, dict)
        or set(ice) != {"status", "unsignedMsiSha256", "suppressions"}
        or ice["status"] != "passed"
        or ice["unsignedMsiSha256"] != payload["unsignedMsiSha256"]
        or ice["suppressions"] != []
    ):
        raise WindowsMsiContractError("msi-evidence-ice-invalid")
    native = payload["nativeChecks"]
    required_native = {
        "firstRelease",
        "cleanInstall",
        "offlineSynthesis",
        "saveRestart",
        "uninstall",
        "noOrphanProcesses",
        "upgrade",
        "downgradePrevention",
        "priorSignedMsiSha256",
    }
    if not isinstance(native, dict) or set(native) != required_native or not isinstance(native["firstRelease"], bool):
        raise WindowsMsiContractError("msi-evidence-native-checks-invalid")
    if native["firstRelease"]:
        if (
            native["upgrade"] != "not-applicable-first-release"
            or native["downgradePrevention"] != "not-applicable-first-release"
            or native["priorSignedMsiSha256"] is not None
        ):
            raise WindowsMsiContractError("first-release-upgrade-evidence-invalid")
    else:
        _sha256(native["priorSignedMsiSha256"], "prior-signed-msi-sha256")
        if payload["releaseEligible"]:
            if native["upgrade"] != "passed" or native["downgradePrevention"] != "passed":
                raise WindowsMsiContractError("upgrade-evidence-invalid")
        elif native["upgrade"] not in {"passed", "missing"} or native["downgradePrevention"] not in {
            "passed",
            "missing",
        }:
            raise WindowsMsiContractError("preflight-upgrade-evidence-invalid")

    signer_keys = {
        "leafCertificateSha256",
        "subject",
        "serialNumber",
        "codeSigningEku",
        "timestampVerified",
        "timestampAuthoritySubject",
    }
    if payload["msiSigner"] is not None:
        signer = payload["msiSigner"]
        if not isinstance(signer, dict) or set(signer) != signer_keys:
            raise WindowsMsiContractError("msi-evidence-signer-invalid")
        _sha256(signer["leafCertificateSha256"], "msi-evidence-signer-sha256")
        _normalized_subject(signer["subject"], "msi-evidence-signer-subject")
        if signer["codeSigningEku"] is not True or signer["timestampVerified"] is not True:
            raise WindowsMsiContractError("msi-evidence-signer-verification-invalid")
    if payload["timestamp"] is not None:
        timestamp = payload["timestamp"]
        if (
            not isinstance(timestamp, dict)
            or set(timestamp) != {"url", "digestAlgorithm", "authoritySubject", "verified"}
            or timestamp["url"] != contract["signing"]["timestampUrl"]
            or timestamp["digestAlgorithm"] != "SHA-256"
            or timestamp["verified"] is not True
        ):
            raise WindowsMsiContractError("msi-evidence-timestamp-invalid")

    if payload["identityMode"] == "staging-placeholder":
        if (
            contract["identity"]["status"] != "staging-placeholder"
            or payload["upgradeCode"] != STAGING_UPGRADE_CODE
            or signed_hash is not None
            or payload["msiSigner"] is not None
            or payload["timestamp"] is not None
        ):
            raise WindowsMsiContractError("staging-msi-evidence-invalid")
    elif (
        contract["identity"]["status"] != "owner-approved"
        or policy["status"] != "approved"
        or signed_hash is None
        or payload["msiSigner"] is None
        or payload["timestamp"] is None
        or any(value is None for value in approvals.values())
    ):
        raise WindowsMsiContractError("owner-msi-evidence-invalid")

    if payload["releaseEligible"]:
        if (
            payload["identityMode"] != "owner-approved"
            or contract["identity"]["status"] != "owner-approved"
            or contract["identity"]["upgradeCode"] == STAGING_UPGRADE_CODE
            or policy["status"] != "approved"
            or payload["openGates"] != []
            or signed_hash is None
            or payload["msiSigner"] is None
            or payload["timestamp"] is None
        ):
            raise WindowsMsiContractError("eligible-msi-evidence-invalid")
        for key in ("cleanInstall", "offlineSynthesis", "saveRestart", "uninstall", "noOrphanProcesses"):
            if native[key] != "passed":
                raise WindowsMsiContractError("eligible-native-checks-incomplete")
    else:
        if payload["openGates"] != release_open_gates.load_contract()["requiredOpenGateIds"]:
            raise WindowsMsiContractError("preflight-open-gates-invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-contract", "derive-product-code", "derive-component-guid"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
        sub.add_argument("--production", action="store_true")
        if name == "derive-product-code":
            sub.add_argument("--version", required=True)
        elif name == "derive-component-guid":
            sub.add_argument("--path", required=True)
    policy_parser = subparsers.add_parser("validate-policy")
    policy_parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    policy_parser.add_argument("--production", action="store_true")
    capture = subparsers.add_parser("capture-inventory")
    capture.add_argument("--root", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    candidate = subparsers.add_parser("create-policy-candidate")
    candidate.add_argument("--inventory", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    transition = subparsers.add_parser("verify-inventory")
    transition.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    transition.add_argument("--inventory", type=Path, required=True)
    transition.add_argument("--phase", choices=("pre-sign", "final"), required=True)
    transition.add_argument("--report", type=Path, required=True)
    wix = subparsers.add_parser("generate-components")
    wix.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    wix.add_argument("--inventory", type=Path, required=True)
    wix.add_argument("--output", type=Path, required=True)
    evidence = subparsers.add_parser("validate-evidence")
    evidence.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    evidence.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    evidence.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-contract":
            contract = load_contract(args.contract, production=args.production)
            print(json.dumps({"contractSha256": hashlib.sha256(_canonical_bytes(contract)).hexdigest()}, sort_keys=True))
        elif args.command == "derive-product-code":
            contract = load_contract(args.contract, production=args.production)
            print(derive_product_code(contract, args.version, production=args.production))
        elif args.command == "derive-component-guid":
            contract = load_contract(args.contract, production=args.production)
            print(derive_component_guid(contract, args.path))
        elif args.command == "validate-policy":
            policy = load_policy(args.policy, production=args.production)
            print(json.dumps({"policySha256": hashlib.sha256(_canonical_bytes(policy)).hexdigest()}, sort_keys=True))
        elif args.command == "capture-inventory":
            inventory = capture_inventory(args.root.resolve())
            write_json_atomic(args.output.resolve(), inventory)
            print(json.dumps({"inventorySha256": inventory["inventorySha256"]}, sort_keys=True))
        elif args.command == "create-policy-candidate":
            inventory = load_inventory(args.inventory)
            candidate_payload = create_policy_candidate(inventory)
            write_json_atomic(args.output.resolve(), candidate_payload)
            print(json.dumps({"policyCandidate": "review-required"}, sort_keys=True))
        elif args.command == "verify-inventory":
            policy = load_policy(args.policy, production=True)
            inventory = load_inventory(args.inventory)
            decisions = verify_inventory_transition(policy, inventory, args.phase)
            report = {
                "schemaVersion": 1,
                "phase": args.phase,
                "inventorySha256": inventory["inventorySha256"],
                "decisions": decisions,
            }
            write_json_atomic(args.report.resolve(), report)
            print(json.dumps({"inventoryTransition": "pass", "phase": args.phase}, sort_keys=True))
        elif args.command == "generate-components":
            contract = load_contract(args.contract)
            inventory = load_inventory(args.inventory)
            if not set(contract["requiredPayloadSubset"]).issubset(
                {item["path"] for item in inventory["files"]}
            ):
                raise WindowsMsiContractError("required-payload-subset-missing")
            generate_components(contract, inventory, args.output.resolve())
            print(json.dumps({"generatedComponentCount": len(inventory["files"])}, sort_keys=True))
        else:
            contract = load_contract(args.contract)
            policy = load_policy(args.policy)
            _, payload = _load_ascii_json(args.evidence, "msi-evidence")
            validate_evidence(payload, contract, policy)
            print(json.dumps({"windowsMsiEvidence": "pass"}, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, WindowsMsiContractError) as exc:
        print(json.dumps({"windowsMsiContractError": str(exc)}, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
