#!/usr/bin/env python3
"""Fail-closed PRIVATE_USER_STATE scanner for release staging trees and ZIPs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import unicodedata
import zipfile
import zlib

import svx_zip_profile as zip_profile


DEFAULT_RULES = Path(__file__).with_name("release_privacy_rules.json")
BUFFER_BYTES = 1024 * 1024
CONTAINER_PREFIX_BYTES = 512
UNSUPPORTED_CONTAINER_EXTENSIONS = (
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".xz",
)
ZIP_READ_EXCEPTIONS = (
    OSError,
    EOFError,
    RuntimeError,
    NotImplementedError,
    ValueError,
    zipfile.BadZipFile,
    lzma.LZMAError,
    zlib.error,
)
RULE_KEYS = (
    "version",
    "forbiddenPathSegments",
    "forbiddenFileNames",
    "forbiddenExtensions",
    "contentMarkers",
    "textExtensions",
    "allowedZipExtraFieldIds",
    "maximumTextBytes",
    "maximumArchiveDepth",
    "maximumArchiveMembers",
    "maximumArchiveUncompressedBytes",
    "maximumArchiveMemberBytes",
    "maximumNestedArchiveBytes",
    "maximumCompressionRatio",
)
SUPPORTED_ZIP_EXTRA_FIELD_IDS = {
    zip_profile.NTFS_EXTRA_ID,
    zip_profile.EXTENDED_TIMESTAMP_EXTRA_ID,
    zip_profile.UNIX_UID_GID_EXTRA_ID,
}
EXPECTED_CONTENT_MARKERS = (
    "SVX_PRIVATE_" + "USER_STATE_PAYLOAD",
    "PRIVATE_" + "USER_STATE:",
)


class PrivacyGateError(RuntimeError):
    """The scanner could not establish a trustworthy pass/fail result."""


def normalized(value: str) -> str:
    return unicodedata.normalize("NFKC", value).replace("\\", "/").casefold()


def stable_name_key(value: str) -> tuple[str, str]:
    return normalized(value), value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PrivacyGateError(f"rules-duplicate-key:{key}")
        result[key] = value
    return result


def canonical_rules_bytes(payload: dict) -> bytes:
    ordered = {key: payload[key] for key in RULE_KEYS}
    return (json.dumps(ordered, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def parse_rules_bytes(raw: bytes) -> dict:
    try:
        text = raw.decode("ascii")
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PrivacyGateError("rules-unavailable") from exc
    if not isinstance(payload, dict) or tuple(payload) != RULE_KEYS:
        raise PrivacyGateError("rules-schema-invalid")
    if canonical_rules_bytes(payload) != raw:
        raise PrivacyGateError("rules-not-canonical")

    required_lists = (
        "forbiddenPathSegments",
        "forbiddenFileNames",
        "forbiddenExtensions",
        "contentMarkers",
        "textExtensions",
    )
    required_positive_integers = (
        "maximumTextBytes",
        "maximumArchiveDepth",
        "maximumArchiveMembers",
        "maximumArchiveUncompressedBytes",
        "maximumArchiveMemberBytes",
        "maximumNestedArchiveBytes",
        "maximumCompressionRatio",
    )
    if (
        not isinstance(payload.get("version"), int)
        or isinstance(payload.get("version"), bool)
        or payload["version"] != 1
    ):
        raise PrivacyGateError("rules-version-invalid")
    for key in required_lists:
        values = payload.get(key)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(item, str) and item.strip() for item in values)
        ):
            raise PrivacyGateError(f"rules-invalid:{key}")
        canonical = [normalized(item) for item in values]
        if len(canonical) != len(set(canonical)):
            raise PrivacyGateError(f"rules-duplicate:{key}")
    for key in required_positive_integers:
        value = payload.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise PrivacyGateError(f"rules-invalid:{key}")
    if payload["maximumNestedArchiveBytes"] > payload["maximumArchiveMemberBytes"]:
        raise PrivacyGateError("rules-invalid:maximumNestedArchiveBytes")
    if tuple(payload["contentMarkers"]) != EXPECTED_CONTENT_MARKERS:
        raise PrivacyGateError("rules-invalid:contentMarkers")
    extra_ids = payload.get("allowedZipExtraFieldIds")
    if (
        not isinstance(extra_ids, list)
        or not extra_ids
        or not all(isinstance(item, int) and not isinstance(item, bool) for item in extra_ids)
        or len(extra_ids) != len(set(extra_ids))
        or set(extra_ids) != SUPPORTED_ZIP_EXTRA_FIELD_IDS
    ):
        raise PrivacyGateError("rules-invalid:allowedZipExtraFieldIds")
    return payload


def load_rules(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PrivacyGateError(f"rules-unavailable:{path.name}") from exc
    return parse_rules_bytes(raw)


def authorized_rules_definition(raw: bytes, expected: dict) -> str | None:
    try:
        parsed = parse_rules_bytes(raw)
    except PrivacyGateError:
        return None
    if parsed != expected:
        return None
    if b"\\u" in raw or b"\\U" in raw:
        return None
    try:
        marker_start = raw.index(b'  "contentMarkers": [')
        marker_end = raw.index(b'  ],\n  "textExtensions":', marker_start)
    except ValueError:
        return None
    for marker in expected["contentMarkers"]:
        encoded = marker.encode("ascii")
        offset = raw.find(encoded)
        if raw.count(encoded) != 1 or not (marker_start < offset < marker_end):
            return None
    return hashlib.sha256(raw).hexdigest()


def is_text_path(display_path: str, rules: dict) -> bool:
    suffix = PurePosixPath(normalized(display_path)).suffix
    return suffix in {normalized(item) for item in rules["textExtensions"]}


def is_zip_path(display_path: str) -> bool:
    return normalized(display_path).endswith(".zip")


def is_zip_bytes(data: bytes) -> bool:
    return zipfile.is_zipfile(io.BytesIO(data))


def is_zip_file(path: Path, display_path: str) -> bool:
    try:
        return zipfile.is_zipfile(path)
    except OSError as exc:
        raise PrivacyGateError(f"file-unreadable:{display_path}") from exc


def unsupported_container_kind(display_path: str, prefix: bytes) -> str | None:
    canonical = normalized(display_path)
    extension_matches = [value for value in UNSUPPORTED_CONTAINER_EXTENSIONS if canonical.endswith(value)]
    if extension_matches:
        return max(extension_matches, key=len)
    if prefix.startswith(b"\x1f\x8b"):
        return "gzip"
    if prefix.startswith(b"BZh"):
        return "bzip2"
    if prefix.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if prefix.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7zip"
    if prefix.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if len(prefix) >= 262 and prefix[257:262] == b"ustar":
        return "tar"
    if prefix.startswith(b"PACK"):
        return "git-pack"
    if prefix.startswith((b"# v2 git bundle", b"# v3 git bundle")):
        return "git-bundle"
    return None


def read_file_prefix(path: Path, display_path: str) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(CONTAINER_PREFIX_BYTES)
    except OSError as exc:
        raise PrivacyGateError(f"file-unreadable:{display_path}") from exc


def path_findings(display_path: str, rules: dict, *, reported_path: str | None = None) -> list[dict[str, str]]:
    canonical = normalized(display_path)
    shown = reported_path or display_path
    pure = PurePosixPath(canonical)
    findings: list[dict[str, str]] = []
    if "\x00" in canonical or pure.is_absolute() or ".." in pure.parts or re.match(r"^[a-z]:/", canonical):
        findings.append({"category": "unsafe-path", "path": shown})
        return findings

    segments = set(pure.parts)
    for forbidden in rules["forbiddenPathSegments"]:
        if normalized(forbidden) in segments:
            findings.append({"category": "forbidden-path", "path": shown})
            break
    name = pure.name
    if name in {normalized(item) for item in rules["forbiddenFileNames"]}:
        findings.append({"category": "forbidden-name", "path": shown})
    if any(name.endswith(normalized(extension)) for extension in rules["forbiddenExtensions"]):
        findings.append({"category": "forbidden-extension", "path": shown})
    if any(normalized(marker) in canonical for marker in rules["contentMarkers"]):
        findings.append({"category": "private-marker-path", "path": shown})
    return findings


def content_findings(display_path: str, data: bytes, rules: dict) -> list[dict[str, str]]:
    if not is_text_path(display_path, rules):
        return []
    if len(data) > rules["maximumTextBytes"]:
        return [{"category": "oversized-text", "path": display_path}]
    try:
        text = normalized(data.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return [{"category": "invalid-text-encoding", "path": display_path}]
    candidate = display_path.rsplit("!/", 1)[-1]
    parts = PurePosixPath(candidate).parts
    if (
        len(parts) >= 2
        and parts[-2:] == ("tools", "release_privacy_rules.json")
        and authorized_rules_definition(data, rules) is not None
    ):
        return []
    for marker in rules["contentMarkers"]:
        if normalized(marker) in text:
            return [{"category": "private-marker", "path": display_path}]
    return []


def marker_byte_patterns(rules: dict) -> tuple[bytes, ...]:
    return tuple(marker.casefold().encode("utf-8") for marker in rules["contentMarkers"])


def bytes_have_private_marker(data: bytes, rules: dict) -> bool:
    lowered = data.lower()
    return any(pattern in lowered for pattern in marker_byte_patterns(rules))


def stream_has_private_marker(stream, rules: dict) -> bool:  # type: ignore[no-untyped-def]
    patterns = marker_byte_patterns(rules)
    overlap = max(len(pattern) for pattern in patterns) - 1
    carry = b""
    while chunk := stream.read(BUFFER_BYTES):
        haystack = (carry + chunk).lower()
        if any(pattern in haystack for pattern in patterns):
            return True
        carry = haystack[-overlap:] if overlap else b""
    return False


def binary_file_findings(path: Path, display_path: str, rules: dict) -> list[dict[str, str]]:
    try:
        with path.open("rb") as stream:
            found = stream_has_private_marker(stream, rules)
    except OSError as exc:
        raise PrivacyGateError(f"file-unreadable:{display_path}") from exc
    return [{"category": "private-marker-binary", "path": display_path}] if found else []


def binary_zip_member_findings(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    display_path: str,
    rules: dict,
) -> list[dict[str, str]]:
    try:
        with archive.open(info, "r") as stream:
            found = stream_has_private_marker(stream, rules)
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-member-unreadable:{info.filename}") from exc
    return [{"category": "private-marker-binary", "path": display_path}] if found else []


def read_file_limited(path: Path, maximum_bytes: int) -> bytes | None:
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise PrivacyGateError(f"file-unreadable:{path.name}") from exc
    return None if len(data) > maximum_bytes else data


def read_zip_member_limited(archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum_bytes: int) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    try:
        with archive.open(info, "r") as stream:
            while True:
                chunk = stream.read(min(BUFFER_BYTES, maximum_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    return None
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-member-unreadable:{info.filename}") from exc
    return b"".join(chunks)


def probe_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[bool, bytes, bool]:
    try:
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as candidate:
            prefix = bytearray()
            tail = bytearray()
            suspicious_signatures = (
                zip_profile.LOCAL_SIGNATURE,
                zip_profile.CENTRAL_SIGNATURE,
                zip_profile.EOCD_SIGNATURE,
                zip_profile.ZIP64_EOCD_SIGNATURE,
                zip_profile.ZIP64_LOCATOR_SIGNATURE,
                zip_profile.DATA_DESCRIPTOR_SIGNATURE,
            )
            suspicious = False
            carry = b""
            with archive.open(info, "r") as stream:
                while chunk := stream.read(BUFFER_BYTES):
                    if len(prefix) < CONTAINER_PREFIX_BYTES:
                        prefix.extend(chunk[: CONTAINER_PREFIX_BYTES - len(prefix)])
                    tail.extend(chunk)
                    if len(tail) > 65557:
                        del tail[: len(tail) - 65557]
                    probe = carry + chunk
                    if any(signature in probe for signature in suspicious_signatures):
                        suspicious = True
                    carry = probe[-3:]
                    candidate.write(chunk)
            candidate.seek(0)
            is_zip = zipfile.is_zipfile(candidate)
            return is_zip, bytes(prefix), suspicious
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-member-unreadable:{info.filename}") from exc


def _profile_findings(
    profile: zip_profile.ValidatedZipProfile,
    archive: zipfile.ZipFile,
    display_path: str,
    rules: dict,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    try:
        infos = archive.infolist()
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-unreadable:{display_path}") from exc
    if archive.comment:
        findings.append({"category": "archive-comment-unsupported", "path": display_path})
    if len(infos) != len(profile.records) or archive.start_dir != profile.central_offset:
        findings.append({"category": "archive-parser-mismatch", "path": display_path})
        return findings
    for info, record in zip(infos, profile.records):
        if (
            info.header_offset != record.local_offset
            or info.filename != record.filename
            or info.flag_bits != record.flags
            or info.compress_type != record.method
            or info.CRC != record.crc32
            or info.compress_size != record.compressed_size
            or info.file_size != record.uncompressed_size
            or info.extra != record.central_extra
            or info.comment
        ):
            findings.append(
                {
                    "category": "archive-parser-mismatch",
                    "path": f"{display_path}!/{record.filename}",
                }
            )
    for label, raw in profile.extra_fields:
        if bytes_have_private_marker(raw, rules):
            findings.append(
                {
                    "category": "private-marker-binary",
                    "path": f"{display_path}!/<extra:{label}>",
                }
            )
    return findings


def scan_zip_archive(
    archive: zipfile.ZipFile,
    display_path: str,
    rules: dict,
    depth: int,
) -> list[dict[str, str]]:
    if depth > rules["maximumArchiveDepth"]:
        return [{"category": "archive-depth", "path": display_path}]

    findings: list[dict[str, str]] = []
    try:
        infos = archive.infolist()
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-unreadable:{display_path}") from exc
    if not infos:
        return [{"category": "empty-archive", "path": display_path}]
    if len(infos) > rules["maximumArchiveMembers"]:
        return [{"category": "archive-member-count", "path": display_path}]

    total_uncompressed = 0
    seen_members: set[str] = set()
    for info in infos:
        member = info.filename
        shown = f"{display_path}!/{member}"
        canonical_member = normalized(member)
        findings.extend(path_findings(member, rules, reported_path=shown))
        if canonical_member in seen_members:
            findings.append({"category": "archive-duplicate-member", "path": shown})
        seen_members.add(canonical_member)

        if info.flag_bits & 0x1:
            findings.append({"category": "archive-encrypted-member", "path": shown})
            continue

        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(unix_mode):
            findings.append({"category": "archive-symlink", "path": shown})
            continue
        file_type = stat.S_IFMT(unix_mode)
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            findings.append({"category": "archive-special-file", "path": shown})
            continue
        if info.is_dir():
            continue

        total_uncompressed += info.file_size
        if total_uncompressed > rules["maximumArchiveUncompressedBytes"]:
            findings.append({"category": "archive-uncompressed-size", "path": display_path})
            break
        if info.file_size > rules["maximumArchiveMemberBytes"]:
            findings.append({"category": "archive-member-size", "path": shown})
            continue
        if info.file_size and info.file_size / max(info.compress_size, 1) > rules["maximumCompressionRatio"]:
            findings.append({"category": "archive-compression-ratio", "path": shown})
            continue

        member_is_zip, member_prefix, member_zip_suspicious = probe_zip_member(archive, info)
        if is_zip_path(member) or member_is_zip:
            nested = read_zip_member_limited(archive, info, rules["maximumNestedArchiveBytes"])
            if nested is None:
                findings.append({"category": "nested-archive-size", "path": shown})
                continue
            if not member_is_zip:
                findings.append({"category": "nested-archive-invalid", "path": shown})
                continue
            findings.extend(scan_zip_bytes(nested, shown, rules, depth + 1))
        elif member_zip_suspicious:
            findings.append({"category": "nested-archive-suspicious", "path": shown})
        elif container := unsupported_container_kind(member, member_prefix):
            findings.append({"category": "unsupported-container", "path": shown, "detail": container})
        elif is_text_path(member, rules):
            text = read_zip_member_limited(archive, info, rules["maximumTextBytes"])
            if text is None:
                findings.append({"category": "oversized-text", "path": shown})
                continue
            findings.extend(content_findings(shown, text, rules))
        else:
            findings.extend(binary_zip_member_findings(archive, info, shown, rules))
    return findings


def scan_zip_bytes(data: bytes, display_path: str, rules: dict, depth: int) -> list[dict[str, str]]:
    try:
        profile = zip_profile.validate_zip_profile(
            data,
            len(data),
            set(rules["allowedZipExtraFieldIds"]),
            rules["maximumArchiveMemberBytes"],
            rules["maximumArchiveUncompressedBytes"],
        )
    except zip_profile.ZipProfileError as exc:
        return [{"category": exc.code, "path": display_path}]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            findings = _profile_findings(profile, archive, display_path, rules)
            if findings:
                return findings
            return scan_zip_archive(archive, display_path, rules, depth)
    except PrivacyGateError:
        raise
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-unreadable:{display_path}") from exc


def scan_zip_path(path: Path, display_path: str, rules: dict, depth: int) -> list[dict[str, str]]:
    try:
        with path.open("rb") as stream:
            profile = zip_profile.validate_zip_profile(
                stream,
                path.stat().st_size,
                set(rules["allowedZipExtraFieldIds"]),
                rules["maximumArchiveMemberBytes"],
                rules["maximumArchiveUncompressedBytes"],
            )
    except zip_profile.ZipProfileError as exc:
        return [{"category": exc.code, "path": display_path}]
    except OSError as exc:
        raise PrivacyGateError(f"file-unreadable:{display_path}") from exc
    try:
        with zipfile.ZipFile(path) as archive:
            findings = _profile_findings(profile, archive, display_path, rules)
            if findings:
                return findings
            return scan_zip_archive(archive, display_path, rules, depth)
    except PrivacyGateError:
        raise
    except ZIP_READ_EXCEPTIONS as exc:
        raise PrivacyGateError(f"archive-unreadable:{display_path}") from exc


def _walk_error(error: OSError) -> None:
    raise PrivacyGateError(f"directory-unreadable:{Path(error.filename or 'unknown').name}") from error


def scan_directory(root: Path, rules: dict) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        directories.sort(key=stable_name_key)
        files.sort(key=stable_name_key)
        for name in list(directories):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            findings.extend(path_findings(relative, rules))
            if path.is_symlink():
                findings.append({"category": "symlink", "path": relative})
                directories.remove(name)
        for name in files:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            findings.extend(path_findings(relative, rules))
            if path.is_symlink():
                findings.append({"category": "symlink", "path": relative})
                continue
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise PrivacyGateError(f"file-unreadable:{relative}") from exc
            if not stat.S_ISREG(mode):
                findings.append({"category": "special-file", "path": relative})
                continue
            if path.lstat().st_nlink != 1:
                findings.append({"category": "hardlink", "path": relative})
                continue
            if is_zip_path(name) or is_zip_file(path, relative):
                findings.extend(scan_zip_path(path, relative, rules, 1))
            elif container := unsupported_container_kind(relative, read_file_prefix(path, relative)):
                findings.append({"category": "unsupported-container", "path": relative, "detail": container})
            elif is_text_path(name, rules):
                data = read_file_limited(path, rules["maximumTextBytes"])
                if data is None:
                    findings.append({"category": "oversized-text", "path": relative})
                else:
                    findings.extend(content_findings(relative, data, rules))
            else:
                findings.extend(binary_file_findings(path, relative, rules))
    return findings


def scan(path: Path, rules: dict) -> list[dict[str, str]]:
    if path.is_symlink():
        return [{"category": "symlink-root", "path": path.name}]
    if not path.exists():
        raise PrivacyGateError(f"target-missing:{path.name}")
    if path.is_dir():
        return scan_directory(path, rules)
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise PrivacyGateError(f"file-unreadable:{path.name}") from exc
    if not stat.S_ISREG(mode):
        return [{"category": "special-file-root", "path": path.name}]
    if path.lstat().st_nlink != 1:
        return [{"category": "hardlink-root", "path": path.name}]
    findings = path_findings(path.name, rules)
    if is_zip_path(path.name) or is_zip_file(path, path.name):
        findings.extend(scan_zip_path(path, path.name, rules, 1))
    elif container := unsupported_container_kind(path.name, read_file_prefix(path, path.name)):
        findings.append({"category": "unsupported-container", "path": path.name, "detail": container})
    elif is_text_path(path.name, rules):
        data = read_file_limited(path, rules["maximumTextBytes"])
        if data is None:
            findings.append({"category": "oversized-text", "path": path.name})
        else:
            findings.extend(content_findings(path.name, data, rules))
    else:
        findings.extend(binary_file_findings(path, path.name, rules))
    return findings


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(BUFFER_BYTES):
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        raise PrivacyGateError(f"fingerprint-unreadable:{path.name}") from exc
    return digest.hexdigest(), total


def target_fingerprint(path: Path) -> tuple[str, int, int]:
    if path.is_symlink():
        record = json.dumps(
            {"path": path.name, "type": "symlink"}, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return hashlib.sha256(record).hexdigest(), 0, 0
    if path.is_file() and not path.is_symlink():
        digest, size = sha256_file(path)
        return digest, 1, size

    tree = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for current, directories, files in os.walk(path, topdown=True, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        directories[:] = sorted(
            (name for name in directories if not (current_path / name).is_symlink()),
            key=stable_name_key,
        )
        for name in sorted(files, key=stable_name_key):
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            relative = candidate.relative_to(path).as_posix()
            digest, size = sha256_file(candidate)
            record = json.dumps(
                {"path": relative, "sha256": digest, "size": size},
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            tree.update(len(record).to_bytes(8, "big"))
            tree.update(record)
            file_count += 1
            byte_count += size
    return tree.hexdigest(), file_count, byte_count


def filesystem_state(path: Path) -> tuple[tuple[object, ...], ...]:
    def record(candidate: Path, relative: str) -> tuple[object, ...]:
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise PrivacyGateError(f"target-state-unavailable:{relative or candidate.name}") from exc
        return (
            relative,
            info.st_mode,
            info.st_dev,
            info.st_ino,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    root_record = record(path, "")
    if not stat.S_ISDIR(int(root_record[1])) or stat.S_ISLNK(int(root_record[1])):
        return (root_record,)
    records = [root_record]
    for current, directories, files in os.walk(path, topdown=True, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        directories.sort(key=stable_name_key)
        files.sort(key=stable_name_key)
        for name in directories:
            candidate = current_path / name
            records.append(record(candidate, candidate.relative_to(path).as_posix()))
        for name in files:
            candidate = current_path / name
            records.append(record(candidate, candidate.relative_to(path).as_posix()))
    return tuple(records)


def scan_and_fingerprint(path: Path, rules: dict) -> tuple[list[dict[str, str]], str, int, int]:
    before = filesystem_state(path)
    findings = scan(path, rules)
    fingerprint, file_count, byte_count = target_fingerprint(path)
    after = filesystem_state(path)
    if before != after:
        raise PrivacyGateError("target-changed-during-scan")
    return findings, fingerprint, file_count, byte_count


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
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise PrivacyGateError(f"report-unwritable:{path.name}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_zip(path: Path, member: str, data: bytes) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, data)


def require_finding(findings: list[dict[str, str]], category: str, fixture: str) -> None:
    if not any(item["category"] == category for item in findings):
        raise PrivacyGateError(f"self-test-negative-failed:{fixture}:{category}")


def self_test(rules: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="svx-privacy-selftest-") as temporary:
        root = Path(temporary)
        clean = root / "clean"
        clean.mkdir()
        (clean / "app.bin").write_bytes(b"public release fixture")
        (clean / "notice.txt").write_text("public notice", encoding="utf-8")
        write_zip(clean / "assets.zip", "public/readme.txt", b"public archive fixture")
        if scan(clean, rules):
            raise PrivacyGateError("self-test-clean-failed")

        for index, segment in enumerate(rules["forbiddenPathSegments"]):
            target = root / f"path-{index}"
            path = target / segment.swapcase() / "model.bin"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"x")
            require_finding(scan(target, rules), "forbidden-path", f"path-{index}")

        unicode_path = "ＰＲＩＶＡＴＥ＿ＵＳＥＲ＿ＳＴＡＴＥ/model.bin"
        require_finding(path_findings(unicode_path, rules), "forbidden-path", "unicode-path")

        for index, filename in enumerate(rules["forbiddenFileNames"]):
            target = root / f"name-{index}"
            target.mkdir()
            (target / filename.swapcase()).write_bytes(b"x")
            require_finding(scan(target, rules), "forbidden-name", f"name-{index}")

        for index, extension in enumerate(rules["forbiddenExtensions"]):
            target = root / f"extension-{index}"
            target.mkdir()
            (target / f"sample{extension.upper()}").write_bytes(b"x")
            require_finding(scan(target, rules), "forbidden-extension", f"extension-{index}")

        for index, marker in enumerate(rules["contentMarkers"]):
            target = root / f"marker-{index}"
            target.mkdir()
            (target / "notice.txt").write_text(marker.swapcase(), encoding="utf-8")
            require_finding(scan(target, rules), "private-marker", f"marker-{index}")

        binary_marker = root / "binary-marker"
        binary_marker.mkdir()
        (binary_marker / "embedded.dll").write_bytes(
            b"prefix\x00private_" + b"user_state:\x00suffix"
        )
        require_finding(scan(binary_marker, rules), "private-marker-binary", "binary-marker")

        binary_archive = root / "binary-marker.zip"
        write_zip(
            binary_archive,
            "public/embedded.bin",
            b"prefix SVX_PRIVATE_" + b"USER_STATE_PAYLOAD suffix",
        )
        require_finding(scan(binary_archive, rules), "private-marker-binary", "binary-archive-marker")

        prefixed_archive = root / "camouflaged.bin"
        hidden_zip = io.BytesIO()
        with zipfile.ZipFile(hidden_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "public/embedded.bin",
                b"prefix SVX_PRIVATE_" + b"USER_STATE_PAYLOAD suffix",
            )
        prefixed_archive.write_bytes(b"self-extracting-prefix" + hidden_zip.getvalue())
        require_finding(
            scan(prefixed_archive, rules),
            "archive-central-boundary-invalid",
            "prefixed-archive-marker",
        )

        unsupported = root / "compressed.bin"
        unsupported.write_bytes(b"\x1f\x8b\x08\x00fixture")
        require_finding(scan(unsupported, rules), "unsupported-container", "unsupported-container")

        invalid_text = root / "invalid-text"
        invalid_text.mkdir()
        (invalid_text / "notice.txt").write_bytes(b"\xff\xfe")
        require_finding(scan(invalid_text, rules), "invalid-text-encoding", "invalid-text")

        small_text_rules = dict(rules)
        small_text_rules["maximumTextBytes"] = 4
        oversized_text = root / "oversized-text"
        oversized_text.mkdir()
        (oversized_text / "notice.txt").write_bytes(b"12345")
        require_finding(scan(oversized_text, small_text_rules), "oversized-text", "oversized-text")

        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("reference_audio/voice.bin", b"x")
        nested_path = root / "nested.zip"
        write_zip(nested_path, "inner.zip", nested.getvalue())
        require_finding(scan(nested_path, rules), "forbidden-path", "nested-archive")

        nested_camouflaged = root / "nested-camouflaged.zip"
        write_zip(nested_camouflaged, "asset.bin", b"prefix" + nested.getvalue())
        require_finding(
            scan(nested_camouflaged, rules),
            "archive-central-boundary-invalid",
            "nested-prefixed-archive",
        )

        nested_unsupported = root / "nested-unsupported.zip"
        write_zip(nested_unsupported, "payload.bin", b"\x1f\x8b\x08\x00fixture")
        require_finding(scan(nested_unsupported, rules), "unsupported-container", "nested-unsupported")

        unsafe_archive = root / "unsafe.zip"
        write_zip(unsafe_archive, "../escape.txt", b"x")
        require_finding(scan(unsafe_archive, rules), "unsafe-path", "unsafe-archive")

        symlink_archive = root / "archive-symlink.zip"
        with zipfile.ZipFile(symlink_archive, "w") as archive:
            info = zipfile.ZipInfo("public/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
        require_finding(scan(symlink_archive, rules), "archive-symlink", "archive-symlink")

        empty_archive = root / "empty.zip"
        with zipfile.ZipFile(empty_archive, "w"):
            pass
        require_finding(scan(empty_archive, rules), "empty-archive", "empty-archive")

        member_rules = dict(rules)
        member_rules["maximumArchiveMembers"] = 1
        member_archive = root / "members.zip"
        with zipfile.ZipFile(member_archive, "w") as archive:
            archive.writestr("one.bin", b"1")
            archive.writestr("two.bin", b"2")
        require_finding(scan(member_archive, member_rules), "archive-member-count", "archive-member-count")

        ratio_rules = dict(rules)
        ratio_rules["maximumCompressionRatio"] = 1
        ratio_archive = root / "ratio.zip"
        write_zip(ratio_archive, "data.bin", b"0" * 4096)
        require_finding(scan(ratio_archive, ratio_rules), "archive-compression-ratio", "archive-ratio")

        duplicate_archive = root / "duplicate.zip"
        with zipfile.ZipFile(duplicate_archive, "w") as archive:
            archive.writestr("Readme.TXT", b"one")
            archive.writestr("README.txt", b"two")
        require_finding(scan(duplicate_archive, rules), "archive-duplicate-member", "archive-duplicate")

        shallow_rules = dict(rules)
        shallow_rules["maximumArchiveDepth"] = 1
        require_finding(scan(nested_path, shallow_rules), "archive-depth", "archive-depth")

        symlink_target = root / "symlink-target.bin"
        symlink_target.write_bytes(b"x")
        symlink_path = root / "symlink.bin"
        try:
            symlink_path.symlink_to(symlink_target)
        except (NotImplementedError, OSError):
            pass
        else:
            require_finding(scan(symlink_path, rules), "symlink-root", "filesystem-symlink")

        hardlink_source = root / "hardlink-source.bin"
        hardlink_target = root / "hardlink-target.bin"
        hardlink_source.write_bytes(b"public fixture")
        try:
            os.link(hardlink_source, hardlink_target)
        except OSError:
            pass
        else:
            require_finding(scan(hardlink_source, rules), "hardlink-root", "filesystem-hardlink")

        missing_rules = root / "missing-rules.json"
        corrupt_rules = root / "corrupt-rules.json"
        corrupt_rules.write_text("{", encoding="utf-8")
        empty_rules = root / "empty-rules.json"
        empty_rules.write_text("{}", encoding="utf-8")
        for fixture, path in (("missing", missing_rules), ("corrupt", corrupt_rules), ("empty", empty_rules)):
            try:
                load_rules(path)
            except PrivacyGateError:
                pass
            else:
                raise PrivacyGateError(f"self-test-rules-failed:{fixture}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", type=Path)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--release-commit")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        rules = load_rules(args.rules)
        if args.self_test:
            self_test(rules)
            print(json.dumps({"privacyGateSelfTest": "pass"}, sort_keys=True))
            return 0
        if args.target is None:
            raise PrivacyGateError("target-required")
        if args.report is None:
            raise PrivacyGateError("report-required")
        if args.release_commit is None or re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", args.release_commit) is None:
            raise PrivacyGateError("release-commit-invalid")

        target = args.target.expanduser().absolute()
        report = args.report.expanduser().absolute()
        if target.is_dir() and (report == target or target in report.parents):
            raise PrivacyGateError("report-inside-target")

        findings, fingerprint, file_count, byte_count = scan_and_fingerprint(target, rules)
        rules_fingerprint, _ = sha256_file(args.rules.resolve())
        result = {
            "schemaVersion": 1,
            "status": "fail" if findings else "pass",
            "targetName": args.target.name,
            "targetType": "directory" if target.is_dir() else "file",
            "releaseCommit": args.release_commit.lower(),
            "rulesSha256": rules_fingerprint,
            "targetFingerprintSha256": fingerprint,
            "scannedFileCount": file_count,
            "scannedByteCount": byte_count,
            "findingCount": len(findings),
            "findings": findings,
        }
        write_json_atomic(report, result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 3 if findings else 0
    except PrivacyGateError as exc:
        print(json.dumps({"privacyGateError": str(exc)}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
