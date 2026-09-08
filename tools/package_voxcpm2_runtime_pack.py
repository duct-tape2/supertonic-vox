#!/usr/bin/env python3
"""Package a verified VoxCPM2 directory into the strict SVX USTAR profile.

This command is offline. It verifies the runtime-pack manifest and every file,
writes exactly one deterministic regular-file-only USTAR archive, and emits the
catalog artifact metadata that binds both archive and extracted identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
import unicodedata
import urllib.parse
import uuid
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Sequence


BLOCK_BYTES = 512
MAXIMUM_MANIFEST_BYTES = 8 * 1024 * 1024
MAXIMUM_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAXIMUM_FILES = 50_000
FORBIDDEN_PARTS = {
    "cache", "generatedaudio", "logs", "savedtext", "settings",
    "user", "voiceprofiles", "voicesamples", "__pycache__",
}


class PackageError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def normalize_path(value: str) -> str:
    if not value or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise PackageError(f"archive path is not printable ASCII: {value!r}")
    if "\\" in value or ":" in value:
        raise PackageError(f"archive path is unsafe: {value}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageError(f"archive path is unsafe: {value}")
    if any(part.endswith((" ", ".")) for part in path.parts):
        raise PackageError(f"archive path has a platform-ambiguous suffix: {value}")
    if any(part.casefold() in FORBIDDEN_PARTS for part in path.parts):
        raise PackageError(f"archive path contains private or mutable state: {value}")
    normalized = path.as_posix()
    if len(normalized.encode("ascii")) > 255:
        raise PackageError(f"archive path exceeds the USTAR profile: {value}")
    return normalized


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def require_regular(path: Path, label: str, expected_size: int | None = None) -> os.stat_result:
    if not os.path.lexists(path):
        raise PackageError(f"missing file: {label}")
    metadata = path.lstat()
    if is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PackageError(f"linked, hard-linked or special file: {label}")
    if metadata.st_size < 0 or metadata.st_size > MAXIMUM_FILE_BYTES:
        raise PackageError(f"file size is outside the runtime-pack limit: {label}")
    if expected_size is not None and metadata.st_size != expected_size:
        raise PackageError(f"file size does not match the manifest: {label}")
    return metadata


def require_pack_root(root: Path) -> None:
    if not root.is_absolute() or not root.exists():
        raise PackageError("pack root must be an existing absolute directory")
    metadata = root.lstat()
    if is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise PackageError("pack root must not be linked or special")


def read_manifest(root: Path) -> tuple[dict[str, object], bytes, list[dict[str, object]]]:
    path = root / "runtime-pack.json"
    metadata = require_regular(path, "runtime-pack.json")
    if metadata.st_size < 1 or metadata.st_size > MAXIMUM_MANIFEST_BYTES:
        raise PackageError("runtime-pack manifest size is invalid")
    data = path.read_bytes()
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"runtime-pack manifest is invalid: {exc}") from exc
    required = {
        "schemaVersion", "protocolVersion", "engineId", "engineVersion", "modelRevision",
        "platform", "architecture", "backend", "entryPoint", "launchArguments",
        "prelaunchVerifyPaths", "files",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise PackageError("runtime-pack manifest fields are not exact")
    if manifest["schemaVersion"] != 1 or manifest["protocolVersion"] != 2 or manifest["engineId"] != "voxcpm2":
        raise PackageError("runtime-pack protocol or engine identity is unsupported")
    if manifest["platform"] not in {"Windows", "MacOS"} or manifest["architecture"] not in {"X64", "Arm64"}:
        raise PackageError("runtime-pack platform identity is invalid")
    if manifest["backend"] not in {"Cpu", "Cuda", "Mps", "Metal"}:
        raise PackageError("runtime-pack backend identity is invalid")
    files = manifest["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAXIMUM_FILES:
        raise PackageError("runtime-pack file inventory is invalid")
    return manifest, data, files


def verify_pack(root: Path) -> tuple[dict[str, object], bytes, list[dict[str, object]], str]:
    require_pack_root(root)
    manifest, manifest_bytes, files = read_manifest(root)
    declared: set[str] = set()
    stable: set[str] = set()
    previous: str | None = None
    total = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sizeBytes", "sha256"}:
            raise PackageError("runtime-pack file record is invalid")
        relative = normalize_path(entry["path"] if isinstance(entry["path"], str) else "")
        size = entry["sizeBytes"]
        digest = entry["sha256"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > MAXIMUM_FILE_BYTES:
            raise PackageError(f"runtime-pack file size is invalid: {relative}")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise PackageError(f"runtime-pack file digest is invalid: {relative}")
        key = stable_key(relative)
        if relative in declared or key in stable or (previous is not None and previous >= key):
            raise PackageError("runtime-pack file inventory is duplicated or unsorted")
        declared.add(relative)
        stable.add(key)
        previous = key
        source = root.joinpath(*PurePosixPath(relative).parts)
        require_regular(source, relative, size)
        if sha256_file(source) != digest:
            raise PackageError(f"runtime-pack file digest mismatch: {relative}")
        total += size
        if total > MAXIMUM_TOTAL_BYTES:
            raise PackageError("runtime-pack extracted size exceeds 16 GiB")

    actual: set[str] = set()
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            if is_link_or_reparse(child.lstat()):
                raise PackageError(f"linked directory in pack: {child.relative_to(root)}")
        for name in filenames:
            child = directory_path / name
            relative = child.relative_to(root).as_posix()
            require_regular(child, relative)
            if relative != "runtime-pack.json":
                actual.add(normalize_path(relative))
    if actual != declared:
        raise PackageError("runtime-pack directory and manifest inventories differ")

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    fingerprint = hashlib.sha256()
    append_field(fingerprint, manifest_sha256)
    for entry in files:
        append_field(fingerprint, str(entry["path"]))
        append_field(fingerprint, str(entry["sizeBytes"]))
        append_field(fingerprint, str(entry["sha256"]))
    return manifest, manifest_bytes, files, fingerprint.hexdigest()


def append_field(digest: "hashlib._Hash", value: str) -> None:
    data = value.encode("utf-8")
    digest.update(struct.pack(">I", len(data)))
    digest.update(data)


def split_ustar_path(path: str) -> tuple[bytes, bytes]:
    encoded = path.encode("ascii")
    if len(encoded) <= 100:
        return encoded, b""
    for index in range(len(path) - 1, -1, -1):
        if path[index] != "/":
            continue
        prefix = path[:index].encode("ascii")
        name = path[index + 1:].encode("ascii")
        if len(prefix) <= 155 and 0 < len(name) <= 100:
            return name, prefix
    raise PackageError(f"archive path cannot be represented by USTAR: {path}")


def write_octal(field: memoryview, value: int) -> None:
    digits = format(value, "o").encode("ascii")
    if len(digits) > len(field) - 1:
        raise PackageError("USTAR numeric field overflow")
    field[:] = b"0" * (len(field) - 1 - len(digits)) + digits + b"\0"


def make_header(path: str, size: int) -> bytes:
    name, prefix = split_ustar_path(path)
    header = bytearray(BLOCK_BYTES)
    header[0:len(name)] = name
    write_octal(memoryview(header)[100:108], 0o644)
    write_octal(memoryview(header)[108:116], 0)
    write_octal(memoryview(header)[116:124], 0)
    write_octal(memoryview(header)[124:136], size)
    write_octal(memoryview(header)[136:148], 0)
    header[148:156] = b" " * 8
    header[156] = ord("0")
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[345:345 + len(prefix)] = prefix
    checksum = format(sum(header), "o").encode("ascii")
    if len(checksum) > 6:
        raise PackageError("USTAR checksum overflow")
    header[148:156] = b"0" * (6 - len(checksum)) + checksum + b"\0 "
    return bytes(header)


def write_entry(
    output: BinaryIO,
    path: str,
    source: Path,
    expected_size: int,
    expected_sha256: str,
) -> None:
    require_regular(source, path, expected_size)
    size = expected_size
    output.write(make_header(path, size))
    digest = hashlib.sha256()
    written = 0
    with source.open("rb") as input_stream:
        while True:
            block = input_stream.read(1024 * 1024)
            if not block:
                break
            output.write(block)
            digest.update(block)
            written += len(block)
    require_regular(source, path, expected_size)
    if written != expected_size or digest.hexdigest() != expected_sha256:
        raise PackageError(f"runtime-pack file changed while packaging: {path}")
    padding = (-size) % BLOCK_BYTES
    if padding:
        output.write(b"\0" * padding)


def validate_download_uri(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PackageError("download URI must be a fixed credential-free HTTPS URL")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in {"https://github.com", "https://huggingface.co"}:
        raise PackageError("download URI origin is not approved")
    return value


def package(
    pack_root: Path,
    output: Path,
    metadata_output: Path,
    download_uri: str | None,
) -> dict[str, object]:
    root = pack_root.absolute()
    output = output.absolute()
    metadata_output = metadata_output.absolute()
    if (not output.name.endswith(".svxpack.tar") or output == metadata_output or
            output.exists() or metadata_output.exists()):
        raise PackageError("new .svxpack.tar and metadata output paths are required")
    if output.parent != metadata_output.parent:
        raise PackageError("archive and metadata outputs must be siblings")
    output.parent.mkdir(parents=True, exist_ok=True)
    if is_link_or_reparse(output.parent.lstat()):
        raise PackageError("output directory must not be linked")
    download_uri = validate_download_uri(download_uri)
    manifest, manifest_bytes, files, pack_fingerprint = verify_pack(root)
    archive_partial = output.with_name(f".{output.name}.partial-{uuid.uuid4().hex}")
    metadata_partial = metadata_output.with_name(f".{metadata_output.name}.partial-{uuid.uuid4().hex}")
    moved_archive = False
    try:
        with archive_partial.open("xb") as stream:
            write_entry(
                stream,
                "runtime-pack.json",
                root / "runtime-pack.json",
                len(manifest_bytes),
                hashlib.sha256(manifest_bytes).hexdigest(),
            )
            for entry in files:
                relative = str(entry["path"])
                write_entry(
                    stream,
                    relative,
                    root.joinpath(*PurePosixPath(relative).parts),
                    int(entry["sizeBytes"]),
                    str(entry["sha256"]),
                )
            stream.write(b"\0" * (2 * BLOCK_BYTES))
            stream.flush()
            os.fsync(stream.fileno())
        archive_size = archive_partial.stat().st_size
        archive_sha256 = sha256_file(archive_partial)
        extracted_bytes = len(manifest_bytes) + sum(int(entry["sizeBytes"]) for entry in files)
        runtime_metadata: dict[str, object] = {
            "archiveProfile": "UstarV1",
            "protocolVersion": manifest["protocolVersion"],
            "engineVersion": manifest["engineVersion"],
            "modelRevision": manifest["modelRevision"],
            "platform": manifest["platform"],
            "architecture": manifest["architecture"],
            "backend": manifest["backend"],
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "packFingerprint": pack_fingerprint,
            "extractedFileCount": len(files) + 1,
            "extractedBytes": extracted_bytes,
        }
        artifact: dict[str, object] = {
            "name": output.name,
            "sizeBytes": archive_size,
            "sha256": archive_sha256,
            "platforms": [manifest["platform"]],
            "architectures": [manifest["architecture"]],
            "backends": [manifest["backend"]],
            "kind": "RuntimePackTar",
            "runtimePack": runtime_metadata,
        }
        if download_uri is not None:
            artifact["downloadUri"] = download_uri
        metadata_partial.write_text(
            json.dumps(artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with metadata_partial.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(archive_partial, output)
        moved_archive = True
        os.replace(metadata_partial, metadata_output)
        return artifact
    except Exception:
        archive_partial.unlink(missing_ok=True)
        metadata_partial.unlink(missing_ok=True)
        if moved_archive:
            output.unlink(missing_ok=True)
        raise


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--metadata-output", required=True, type=Path)
    parser.add_argument("--download-uri")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        artifact = package(
            arguments.pack_root,
            arguments.output,
            arguments.metadata_output,
            arguments.download_uri,
        )
    except (OSError, PackageError) as exc:
        print(f"runtime-pack packaging failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(artifact, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
