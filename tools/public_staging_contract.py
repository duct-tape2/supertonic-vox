#!/usr/bin/env python3
"""Validate clean public-source staging evidence without granting release eligibility."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import time
import unicodedata
import zipfile

import release_open_gates


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class PublicStagingContractError(RuntimeError):
    pass


def _stable_name(value: str) -> tuple[str, str]:
    return unicodedata.normalize("NFKC", value).casefold(), value


def _safe_relative_path(value: str) -> bool:
    pure = PurePosixPath(value)
    return bool(
        value
        and "\\" not in value
        and "\x00" not in value
        and not pure.is_absolute()
        and all(part not in {"", ".", ".."} for part in pure.parts)
    )


def inspect_source_tree(root: Path) -> list[tuple[str, Path]]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise PublicStagingContractError("source-root-unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
        raise PublicStagingContractError("source-root-invalid")

    records: list[tuple[str, Path]] = []
    canonical_paths: set[str] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort(key=_stable_name)
        files.sort(key=_stable_name)
        for name in directories:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            try:
                info = candidate.lstat()
            except OSError as exc:
                raise PublicStagingContractError("source-entry-unavailable") from exc
            if not _safe_relative_path(relative) or not stat.S_ISDIR(info.st_mode) or candidate.is_symlink():
                raise PublicStagingContractError("source-directory-invalid")
        for name in files:
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            try:
                info = candidate.lstat()
            except OSError as exc:
                raise PublicStagingContractError("source-entry-unavailable") from exc
            canonical = unicodedata.normalize("NFKC", relative).casefold()
            if (
                not _safe_relative_path(relative)
                or not stat.S_ISREG(info.st_mode)
                or candidate.is_symlink()
                or info.st_nlink != 1
                or info.st_size >= zipfile.ZIP64_LIMIT
                or canonical in canonical_paths
            ):
                raise PublicStagingContractError("source-file-invalid")
            canonical_paths.add(canonical)
            records.append((relative, candidate))
    records.sort(key=lambda item: _stable_name(item[0]))
    if not records:
        raise PublicStagingContractError("source-tree-empty")
    return records


def deterministic_source_zip(source: Path, output: Path, epoch: int, prefix: str) -> None:
    if not prefix.endswith("/") or not _safe_relative_path(prefix[:-1]):
        raise PublicStagingContractError("source-zip-prefix-invalid")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 315532800 or epoch > 4354819199:
        raise PublicStagingContractError("source-zip-epoch-invalid")
    records = inspect_source_tree(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
        date_time = time.gmtime(epoch)[:6]
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=False,
        ) as archive:
            for relative, path in records:
                info = zipfile.ZipInfo(prefix + relative, date_time=date_time)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with path.open("rb") as source_stream, archive.open(info, "w") as target_stream:
                    shutil.copyfileobj(source_stream, target_stream, 1024 * 1024)
        os.replace(temporary, output)
        temporary = None
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise PublicStagingContractError("source-zip-create-failed") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_identity(value: object, suffix: str) -> None:
    if not isinstance(value, dict) or set(value) != {"name", "sha256", "sizeBytes"}:
        raise PublicStagingContractError("artifact-identity-shape-invalid")
    name = value["name"]
    if (
        not isinstance(name, str)
        or PurePosixPath(name).name != name
        or not name.endswith(suffix)
        or not isinstance(value["sha256"], str)
        or SHA256.fullmatch(value["sha256"]) is None
        or not isinstance(value["sizeBytes"], int)
        or isinstance(value["sizeBytes"], bool)
        or value["sizeBytes"] < 1
    ):
        raise PublicStagingContractError("artifact-identity-invalid")


def validate_evidence(payload: object, gate_contract: Path) -> None:
    required = {
        "schemaVersion",
        "releaseEligible",
        "sourceCommit",
        "stagingCommit",
        "bundle",
        "sourceArchive",
        "openGates",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise PublicStagingContractError("evidence-shape-invalid")
    if (
        not isinstance(payload["schemaVersion"], int)
        or isinstance(payload["schemaVersion"], bool)
        or payload["schemaVersion"] != 1
        or payload["releaseEligible"] is not False
    ):
        raise PublicStagingContractError("evidence-release-state-invalid")
    if (
        not isinstance(payload["sourceCommit"], str)
        or COMMIT.fullmatch(payload["sourceCommit"]) is None
        or not isinstance(payload["stagingCommit"], str)
        or COMMIT.fullmatch(payload["stagingCommit"]) is None
    ):
        raise PublicStagingContractError("evidence-commit-invalid")
    validate_identity(payload["bundle"], ".bundle")
    validate_identity(payload["sourceArchive"], ".zip")
    try:
        release_open_gates.validate_evidence(payload, gate_contract)
    except release_open_gates.ReleaseOpenGateError as exc:
        raise PublicStagingContractError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-evidence")
    validate.add_argument("--evidence", type=Path, required=True)
    validate.add_argument("--gate-contract", type=Path, required=True)
    archive = subparsers.add_parser("create-zip")
    archive.add_argument("--source", type=Path, required=True)
    archive.add_argument("--output", type=Path, required=True)
    archive.add_argument("--epoch", type=int, required=True)
    archive.add_argument("--prefix", required=True)
    args = parser.parse_args()
    try:
        if args.command == "create-zip":
            deterministic_source_zip(
                args.source.resolve(),
                args.output.resolve(),
                args.epoch,
                args.prefix,
            )
            print(json.dumps({"publicStagingSourceZip": "pass"}, sort_keys=True))
        else:
            payload = json.loads(args.evidence.read_text(encoding="utf-8"))
            validate_evidence(payload, args.gate_contract)
            print(json.dumps({"publicStagingContract": "pass"}, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, PublicStagingContractError) as exc:
        print(json.dumps({"publicStagingContractError": str(exc)}, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
