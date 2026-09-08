#!/usr/bin/env python3
"""Mac-safe contract helpers for the Windows unsigned release preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

import release_open_gates


BUFFER_BYTES = 1024 * 1024
FORBIDDEN_NAMES = {"createdump.exe", "createdump"}
FORBIDDEN_SUFFIXES = {".log", ".pdb", ".py", ".pyc", ".wav", ".xml"}
REQUIRED_OPEN_GATES = tuple(
    release_open_gates.load_contract()["requiredOpenGateIds"]
)


class WindowsPreflightContractError(RuntimeError):
    pass


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(BUFFER_BYTES):
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        raise WindowsPreflightContractError(f"file-unreadable:{path.name}") from exc
    return digest.hexdigest(), total


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise WindowsPreflightContractError(f"json-unwritable:{path.name}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def safe_relative_path(value: str) -> str:
    canonical = value.replace("\\", "/")
    pure = PurePosixPath(canonical)
    if (
        not canonical
        or "\x00" in canonical
        or pure.is_absolute()
        or ".." in pure.parts
        or ":" in canonical
        or canonical != pure.as_posix()
    ):
        raise WindowsPreflightContractError(f"unsafe-publish-path:{value}")
    return canonical


def load_allowlist(
    path: Path,
    *,
    require_approved: bool,
    expected_sdk_version: str | None = None,
) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsPreflightContractError("allowlist-unavailable") from exc
    if set(payload) != {"schemaVersion", "target", "dotnetSdkVersion", "status", "files"}:
        raise WindowsPreflightContractError("allowlist-shape-invalid")
    if payload["schemaVersion"] != 1 or payload["target"] != "win-x64":
        raise WindowsPreflightContractError("allowlist-contract-invalid")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", payload["dotnetSdkVersion"] or "") is None:
        raise WindowsPreflightContractError("allowlist-sdk-invalid")
    if (
        expected_sdk_version is not None
        and payload["dotnetSdkVersion"] != expected_sdk_version
    ):
        raise WindowsPreflightContractError("allowlist-sdk-mismatch")
    if payload["status"] not in {"capture-required", "approved"}:
        raise WindowsPreflightContractError("allowlist-status-invalid")
    files = payload["files"]
    if not isinstance(files, list) or not all(isinstance(value, str) for value in files):
        raise WindowsPreflightContractError("allowlist-files-invalid")
    canonical = [safe_relative_path(value) for value in files]
    if canonical != sorted(canonical, key=lambda value: (value.casefold(), value)):
        raise WindowsPreflightContractError("allowlist-order-invalid")
    if len({value.casefold() for value in canonical}) != len(canonical):
        raise WindowsPreflightContractError("allowlist-duplicate")
    if require_approved and (payload["status"] != "approved" or not canonical):
        raise WindowsPreflightContractError("allowlist-not-approved")
    return payload


def inspect_publish_tree(root: Path) -> list[dict[str, object]]:
    if root.is_symlink() or not root.is_dir():
        raise WindowsPreflightContractError("publish-root-invalid")
    records: list[dict[str, object]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort(key=lambda value: (value.casefold(), value))
        files.sort(key=lambda value: (value.casefold(), value))
        for name in directories:
            directory = current_path / name
            if directory.is_symlink():
                raise WindowsPreflightContractError(
                    f"publish-symlink:{directory.relative_to(root).as_posix()}"
                )
        for name in files:
            path = current_path / name
            relative = safe_relative_path(path.relative_to(root).as_posix())
            try:
                details = path.lstat()
            except OSError as exc:
                raise WindowsPreflightContractError(f"publish-unreadable:{relative}") from exc
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise WindowsPreflightContractError(f"publish-file-invalid:{relative}")
            lowered = PurePosixPath(relative).name.casefold()
            if lowered in FORBIDDEN_NAMES or PurePosixPath(lowered).suffix in FORBIDDEN_SUFFIXES:
                raise WindowsPreflightContractError(f"publish-file-forbidden:{relative}")
            digest, size = sha256_file(path)
            records.append({"path": relative, "sha256": digest, "sizeBytes": size})
    if not records:
        raise WindowsPreflightContractError("publish-empty")
    return sorted(records, key=lambda item: (str(item["path"]).casefold(), str(item["path"])))


def compare_publish_tree(root: Path, allowlist: dict) -> list[dict[str, object]]:
    records = inspect_publish_tree(root)
    actual = [str(item["path"]) for item in records]
    expected = list(allowlist["files"])
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        summary = f"missing={len(missing)},unexpected={len(unexpected)}"
        raise WindowsPreflightContractError(f"publish-inventory-mismatch:{summary}")
    return records


def capture_inventory(root: Path, sdk_version: str, output: Path) -> None:
    records = inspect_publish_tree(root)
    write_json_atomic(
        output,
        {
            "schemaVersion": 1,
            "target": "win-x64",
            "dotnetSdkVersion": sdk_version,
            "status": "review-required",
            "files": records,
        },
    )


def verify_source_git_modes(repo: Path, commit: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise WindowsPreflightContractError("source-commit-invalid")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    completed = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-c",
            "core.quotepath=false",
            "-C",
            str(repo),
            "ls-tree",
            "-rz",
            "--full-tree",
            commit,
        ],
        check=False,
        capture_output=True,
        env=environment,
    )
    if completed.returncode != 0:
        raise WindowsPreflightContractError("source-tree-unavailable")
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0]
        if mode in {b"120000", b"160000"}:
            shown = path.decode("utf-8", errors="backslashreplace")
            raise WindowsPreflightContractError(
                f"source-git-mode-rejected:{mode.decode()}:{shown}"
            )


def deterministic_zip(source: Path, output: Path, epoch: int, prefix: str = "") -> None:
    records = inspect_publish_tree(source)
    if prefix:
        if not prefix.endswith("/") or safe_relative_path(prefix[:-1]) != prefix[:-1]:
            raise WindowsPreflightContractError("zip-prefix-invalid")
    date_time = time.gmtime(max(epoch, 315532800))[:6]
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for record in records:
                source_relative = str(record["path"])
                relative = prefix + source_relative
                path = source / PurePosixPath(source_relative)
                if path.stat().st_size >= zipfile.ZIP64_LIMIT:
                    raise WindowsPreflightContractError("zip64-source-file-unsupported")
                info = zipfile.ZipInfo(relative, date_time=date_time)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with path.open("rb") as source_stream, archive.open(info, "w") as target_stream:
                    shutil.copyfileobj(source_stream, target_stream, BUFFER_BYTES)
        os.replace(temporary, output)
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise WindowsPreflightContractError("zip-creation-failed") from exc
    finally:
        temporary.unlink(missing_ok=True)


def validate_evidence(path: Path, output_root: Path | None = None) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsPreflightContractError("evidence-unavailable") from exc
    required = {
        "schemaVersion",
        "mode",
        "releaseEligible",
        "releaseCommit",
        "sourceMode",
        "packageVersion",
        "artifact",
        "toolchain",
        "evidenceFiles",
        "openGates",
    }
    if not isinstance(payload, dict) or set(payload) != required or payload["schemaVersion"] != 1:
        raise WindowsPreflightContractError("evidence-shape-invalid")
    if payload["mode"] != "preflight-unsigned" or payload["releaseEligible"] is not False:
        raise WindowsPreflightContractError("evidence-release-state-invalid")
    if (
        payload["sourceMode"] != "git-archive"
        or not isinstance(payload["releaseCommit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", payload["releaseCommit"]) is None
        or not isinstance(payload["packageVersion"], str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", payload["packageVersion"])
        is None
    ):
        raise WindowsPreflightContractError("evidence-source-invalid")
    artifact = payload["artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {"name", "sha256", "sizeBytes"}:
        raise WindowsPreflightContractError("evidence-artifact-invalid")
    if (
        not isinstance(artifact["name"], str)
        or PurePosixPath(artifact["name"]).name != artifact["name"]
        or not artifact["name"].endswith(".zip",)
        or "UNSIGNED-NOT-FOR-DISTRIBUTION" not in artifact["name"]
        or not isinstance(artifact["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None
        or not isinstance(artifact["sizeBytes"], int)
        or isinstance(artifact["sizeBytes"], bool)
        or artifact["sizeBytes"] < 1
    ):
        raise WindowsPreflightContractError("evidence-artifact-invalid")
    toolchain = payload["toolchain"]
    if (
        not isinstance(toolchain, dict)
        or set(toolchain) != {"dotnetSdkVersion", "dotnetExecutableSha256"}
        or not isinstance(toolchain["dotnetSdkVersion"], str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain["dotnetSdkVersion"])
        is None
        or not isinstance(toolchain["dotnetExecutableSha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", toolchain["dotnetExecutableSha256"])
        is None
    ):
        raise WindowsPreflightContractError("evidence-toolchain-invalid")
    open_gates = payload["openGates"]
    if (
        not isinstance(open_gates, list)
        or not all(isinstance(value, str) and value for value in open_gates)
        or len(open_gates) != len(set(open_gates))
        or open_gates != list(REQUIRED_OPEN_GATES)
    ):
        raise WindowsPreflightContractError("evidence-open-gates-invalid")
    evidence_files = payload["evidenceFiles"]
    if not isinstance(evidence_files, dict) or not evidence_files:
        raise WindowsPreflightContractError("evidence-files-empty")
    names: list[str] = []
    for role, identity in evidence_files.items():
        if (
            not isinstance(role, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", role) is None
            or not isinstance(identity, dict)
            or set(identity) != {"name", "sha256", "sizeBytes"}
            or not isinstance(identity["name"], str)
            or safe_relative_path(identity["name"]) != identity["name"]
            or PurePosixPath(identity["name"]).name != identity["name"]
            or not isinstance(identity["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]) is None
            or not isinstance(identity["sizeBytes"], int)
            or isinstance(identity["sizeBytes"], bool)
            or identity["sizeBytes"] < 1
        ):
            raise WindowsPreflightContractError("evidence-file-identity-invalid")
        names.append(identity["name"])
    if len({name.casefold() for name in names}) != len(names):
        raise WindowsPreflightContractError("evidence-file-name-duplicate")

    if output_root is not None:
        if output_root.is_symlink() or not output_root.is_dir():
            raise WindowsPreflightContractError("evidence-root-invalid")
        root = output_root.resolve()
        evidence_path = path.resolve()
        if evidence_path.parent != root or evidence_path.name != "release-evidence.json":
            raise WindowsPreflightContractError("evidence-path-outside-root")
        expected_names = {"release-evidence.json", artifact["name"], *names}
        records = inspect_publish_tree(root)
        actual_names = {str(record["path"]) for record in records}
        if actual_names != expected_names:
            raise WindowsPreflightContractError("evidence-root-inventory-mismatch")
        artifact_digest, artifact_size = sha256_file(root / artifact["name"])
        if artifact_digest != artifact["sha256"] or artifact_size != artifact["sizeBytes"]:
            raise WindowsPreflightContractError("evidence-artifact-mismatch")
        for identity in evidence_files.values():
            digest, size = sha256_file(root / identity["name"])
            if digest != identity["sha256"] or size != identity["sizeBytes"]:
                raise WindowsPreflightContractError(
                    f"evidence-file-mismatch:{identity['name']}"
                )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-allowlist")
    validate.add_argument("--allowlist", type=Path, required=True)
    validate.add_argument("--require-approved", action="store_true")
    validate.add_argument("--sdk-version")

    compare = subparsers.add_parser("compare-publish")
    compare.add_argument("--allowlist", type=Path, required=True)
    compare.add_argument("--publish", type=Path, required=True)
    compare.add_argument("--report", type=Path, required=True)

    capture = subparsers.add_parser("capture-inventory")
    capture.add_argument("--publish", type=Path, required=True)
    capture.add_argument("--sdk-version", required=True)
    capture.add_argument("--output", type=Path, required=True)

    archive = subparsers.add_parser("create-zip")
    archive.add_argument("--source", type=Path, required=True)
    archive.add_argument("--output", type=Path, required=True)
    archive.add_argument("--epoch", type=int, required=True)
    archive.add_argument("--prefix", default="")

    evidence = subparsers.add_parser("validate-evidence")
    evidence.add_argument("--evidence", type=Path, required=True)
    evidence.add_argument("--output-root", type=Path)

    source_modes = subparsers.add_parser("verify-source-modes")
    source_modes.add_argument("--repo", type=Path, required=True)
    source_modes.add_argument("--commit", required=True)

    args = parser.parse_args()
    try:
        if args.command == "validate-allowlist":
            load_allowlist(
                args.allowlist.resolve(),
                require_approved=args.require_approved,
                expected_sdk_version=args.sdk_version,
            )
        elif args.command == "compare-publish":
            allowlist = load_allowlist(args.allowlist.resolve(), require_approved=True)
            records = compare_publish_tree(args.publish.resolve(), allowlist)
            write_json_atomic(args.report.resolve(), {"schemaVersion": 1, "status": "pass", "files": records})
        elif args.command == "capture-inventory":
            capture_inventory(args.publish.resolve(), args.sdk_version, args.output.resolve())
        elif args.command == "create-zip":
            deterministic_zip(args.source.resolve(), args.output.resolve(), args.epoch, args.prefix)
        elif args.command == "validate-evidence":
            validate_evidence(
                args.evidence.resolve(),
                args.output_root.resolve() if args.output_root else None,
            )
        elif args.command == "verify-source-modes":
            verify_source_git_modes(args.repo.resolve(), args.commit)
        print(json.dumps({"windowsPreflightContract": "pass", "command": args.command}, sort_keys=True))
        return 0
    except WindowsPreflightContractError as exc:
        print(json.dumps({"windowsPreflightContractError": str(exc)}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
