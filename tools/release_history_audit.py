#!/usr/bin/env python3
"""Audit every reachable Git object and optional bundle without printing contents."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

import release_privacy_gate as privacy


DEFAULT_PRIVACY_RULES = Path(__file__).with_name("release_privacy_rules.json")
DEFAULT_HISTORY_RULES = Path(__file__).with_name("release_history_rules.json")
MARKER_DEFINITION_PATH = "tools/release_privacy_rules.json"
HISTORY_RULE_KEYS = (
    "version",
    "maximumBlobBytes",
    "maximumPathsPerBlob",
    "archiveExtensions",
    "auditedArchiveExtensions",
    "markerDefinitionPath",
    "forbiddenExtensions",
    "secretPatterns",
)


class HistoryAuditError(RuntimeError):
    pass


def git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    if extra:
        environment.update(extra)
    return environment


def run_git(repo: Path, arguments: list[str], *, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-c", "core.quotepath=false", "-C", str(repo), *arguments],
        check=False,
        capture_output=True,
        text=text,
        env=git_environment(),
    )
    if completed.returncode != 0:
        command = arguments[0] if arguments else "unknown"
        raise HistoryAuditError(f"git-command-failed:{command}")
    return completed.stdout


def load_history_rules(path: Path) -> dict:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise HistoryAuditError(f"history-rules-duplicate-key:{key}")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HistoryAuditError("history-rules-unavailable") from exc
    if not isinstance(payload, dict) or tuple(payload) != HISTORY_RULE_KEYS:
        raise HistoryAuditError("history-rules-schema-invalid")
    canonical = (json.dumps(payload, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    if canonical != raw:
        raise HistoryAuditError("history-rules-not-canonical")
    if (
        not isinstance(payload.get("version"), int)
        or isinstance(payload.get("version"), bool)
        or payload["version"] != 1
    ):
        raise HistoryAuditError("history-rules-version-invalid")
    for key in ("maximumBlobBytes", "maximumPathsPerBlob"):
        value = payload.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise HistoryAuditError(f"history-rules-invalid:{key}")
    if payload.get("markerDefinitionPath") != MARKER_DEFINITION_PATH:
        raise HistoryAuditError("history-rules-invalid:markerDefinitionPath")
    for key in ("forbiddenExtensions", "archiveExtensions", "auditedArchiveExtensions"):
        values = payload.get(key)
        if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
            raise HistoryAuditError(f"history-rules-invalid:{key}")
    patterns = payload.get("secretPatterns")
    if not isinstance(patterns, list) or not patterns:
        raise HistoryAuditError("history-rules-invalid:secretPatterns")
    ids: set[str] = set()
    for item in patterns:
        if not isinstance(item, dict) or set(item) != {"id", "pattern"}:
            raise HistoryAuditError("history-rules-invalid:secretPatterns")
        identifier = item["id"]
        pattern = item["pattern"]
        if not isinstance(identifier, str) or not identifier or identifier in ids or not isinstance(pattern, str):
            raise HistoryAuditError("history-rules-invalid:secretPatterns")
        ids.add(identifier)
        try:
            re.compile(pattern.encode("ascii"))
        except (UnicodeEncodeError, re.error) as exc:
            raise HistoryAuditError(f"history-rules-pattern-invalid:{identifier}") from exc
    return payload


def decode_git_path(value: bytes) -> str:
    return value.decode("utf-8", errors="surrogateescape")


def all_local_objects(repo: Path) -> dict[str, tuple[str, int]]:
    raw = run_git(
        repo,
        ["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
    )
    assert isinstance(raw, str)
    result: dict[str, tuple[str, int]] = {}
    for line in raw.splitlines():
        if not line:
            continue
        object_id, object_type, size = line.split(" ")
        result[object_id] = (object_type, int(size))
    return result


def all_blob_paths(
    repo: Path, commits: list[str]
) -> tuple[dict[str, set[str]], list[tuple[str, str]], int]:
    paths: dict[str, set[str]] = {}
    symlinks: list[tuple[str, str]] = []
    submodule_count = 0
    for commit in commits:
        raw = run_git(repo, ["ls-tree", "-rz", "--full-tree", commit], text=False)
        assert isinstance(raw, bytes)
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, path_bytes = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = decode_git_path(path_bytes)
            if mode == "160000" or object_type == "commit":
                submodule_count += 1
                continue
            if object_type == "blob":
                paths.setdefault(object_id, set()).add(path)
                if mode == "120000":
                    symlinks.append((object_id, path))
    return paths, symlinks, submodule_count


def content_marker_hit(data: bytes, privacy_rules: dict) -> bool:
    lowered = data.lower()
    for marker in privacy_rules["contentMarkers"]:
        encoded = marker.casefold().encode("utf-8")
        if encoded in lowered:
            return True
    try:
        text = privacy.normalized(data.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return False
    return any(privacy.normalized(marker) in text for marker in privacy_rules["contentMarkers"])


def secret_hits(data: bytes, history_rules: dict) -> list[str]:
    hits: list[str] = []
    for item in history_rules["secretPatterns"]:
        if re.search(item["pattern"].encode("ascii"), data):
            hits.append(item["id"])
    return hits


def path_policy_findings(path: str, privacy_rules: dict, history_rules: dict) -> list[str]:
    categories = {item["category"] for item in privacy.path_findings(path, privacy_rules)}
    suffix = PurePosixPath(privacy.normalized(path)).suffix
    if suffix in {privacy.normalized(value) for value in history_rules["forbiddenExtensions"]}:
        categories.add("forbidden-secret-extension")
    return sorted(categories)


def archive_extension(path: str, history_rules: dict) -> str | None:
    canonical = privacy.normalized(path)
    matches = [
        privacy.normalized(extension)
        for extension in history_rules["archiveExtensions"]
        if canonical.endswith(privacy.normalized(extension))
    ]
    return max(matches, key=len) if matches else None


def container_kind(data: bytes) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return ".zip"
    if data.startswith(b"PACK"):
        return "git-pack"
    if data.startswith((b"# v2 git bundle", b"# v3 git bundle")):
        return "git-bundle"
    if data.startswith(b"\x1f\x8b"):
        return ".gz"
    if data.startswith(b"BZh"):
        return ".bz2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return ".xz"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ".7z"
    if data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return ".rar"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return ".tar"
    return None


def is_lfs_pointer(data: bytes) -> bool:
    if len(data) > 1024:
        return False
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return False
    return (
        len(lines) >= 3
        and lines[0] == "version https://git-lfs.github.com/spec/v1"
        and re.fullmatch(r"oid sha256:[0-9a-f]{64}", lines[1]) is not None
        and re.fullmatch(r"size [0-9]+", lines[2]) is not None
    )


def zip_secret_findings(data: bytes, display_path: str, history_rules: dict, privacy_rules: dict) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []

    def inspect_zip(payload: bytes, shown: str, depth: int) -> None:
        if depth > privacy_rules["maximumArchiveDepth"]:
            return
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                infos = archive.infolist()
                if len(infos) > privacy_rules["maximumArchiveMembers"]:
                    return
                total = 0
                for info in infos:
                    member_shown = f"{shown}!/{info.filename}"
                    if info.is_dir() or info.flag_bits & 0x1:
                        continue
                    total += info.file_size
                    if (
                        total > privacy_rules["maximumArchiveUncompressedBytes"]
                        or info.file_size > privacy_rules["maximumArchiveMemberBytes"]
                        or info.file_size / max(info.compress_size, 1) > privacy_rules["maximumCompressionRatio"]
                    ):
                        continue
                    try:
                        member = archive.read(info)
                    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile):
                        findings.append(("archive-member-unreadable", member_shown))
                        continue
                    for identifier in secret_hits(member, history_rules):
                        findings.append((f"secret-pattern:{identifier}", member_shown))
                    member_kind = container_kind(member)
                    member_extension = archive_extension(info.filename, history_rules)
                    if privacy.is_zip_bytes(member) or member_kind == ".zip" or member_extension == ".zip":
                        inspect_zip(member, member_shown, depth + 1)
                    elif member_kind is not None or member_extension is not None:
                        findings.append(("unsupported-archive-object", member_shown))
        except (OSError, RuntimeError, zipfile.BadZipFile):
            findings.append(("archive-unreadable", shown))

    inspect_zip(data, display_path, 1)
    return findings


def add_finding(
    findings: list[dict[str, str]],
    seen: set[tuple[str, str, str]],
    category: str,
    object_id: str,
    path: str,
) -> None:
    key = (category, object_id, path)
    if key in seen:
        return
    seen.add(key)
    findings.append({"category": category, "object": object_id, "path": path})


def audit_repository(repo: Path, privacy_rules: dict, history_rules: dict) -> dict:
    try:
        run_git(repo, ["rev-parse", "--git-dir"])
        run_git(repo, ["fsck", "--full", "--strict", "--no-dangling"])
    except HistoryAuditError as exc:
        raise HistoryAuditError("repository-invalid") from exc

    head = run_git(repo, ["rev-parse", "HEAD"])
    refs_raw = run_git(repo, ["for-each-ref", "--format=%(refname) %(objectname)"])
    assert isinstance(head, str) and isinstance(refs_raw, str)
    refs = sorted(line for line in refs_raw.splitlines() if line)
    objects = all_local_objects(repo)
    commits = sorted(object_id for object_id, (kind, _) in objects.items() if kind == "commit")
    blob_paths, symlinks, submodule_count = all_blob_paths(repo, commits)
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    authorized_marker_definitions: list[dict[str, str]] = []
    authorized_marker_definition_keys: set[tuple[str, str]] = set()
    scanned_bytes = 0
    scanned_blobs = 0
    lfs_pointer_count = 0

    for object_id, (object_type, size) in sorted(objects.items()):
        if object_type not in {"blob", "commit", "tag"}:
            continue
        if object_type == "blob":
            paths = sorted(blob_paths.get(object_id, {f"<unmapped-blob:{object_id[:12]}>"}), key=privacy.stable_name_key)
        else:
            paths = [f"<{object_type}:{object_id[:12]}>"]
        if len(paths) > history_rules["maximumPathsPerBlob"]:
            for path in paths[:1]:
                add_finding(findings, seen, "too-many-object-paths", object_id, path)
            continue
        for path in paths:
            if not path.startswith("<"):
                for category in path_policy_findings(path, privacy_rules, history_rules):
                    add_finding(findings, seen, category, object_id, path)
        if size > history_rules["maximumBlobBytes"]:
            for path in paths:
                add_finding(findings, seen, "oversized-object", object_id, path)
            continue

        raw = run_git(repo, ["cat-file", object_type, object_id], text=False)
        assert isinstance(raw, bytes)
        scanned_bytes += len(raw)
        if object_type == "blob":
            scanned_blobs += 1
            if is_lfs_pointer(raw):
                lfs_pointer_count += 1
                for path in paths:
                    add_finding(findings, seen, "git-lfs-pointer-requires-object-audit", object_id, path)
        marker = content_marker_hit(raw, privacy_rules)
        secrets = secret_hits(raw, history_rules)
        for path in paths:
            if marker:
                rules_digest = (
                    privacy.authorized_rules_definition(raw, privacy_rules)
                    if object_type == "blob" and path == MARKER_DEFINITION_PATH
                    else None
                )
                if rules_digest is None:
                    add_finding(findings, seen, "private-marker", object_id, path)
                elif (object_id, path) not in authorized_marker_definition_keys:
                    authorized_marker_definition_keys.add((object_id, path))
                    authorized_marker_definitions.append(
                        {
                            "object": object_id,
                            "path": path,
                            "rulesSha256": rules_digest,
                        }
                    )
            for identifier in secrets:
                add_finding(findings, seen, f"secret-pattern:{identifier}", object_id, path)
            if object_type == "blob":
                kind = container_kind(raw)
                extension = archive_extension(path, history_rules) if not path.startswith("<") else None
                if privacy.is_zip_bytes(raw) or kind == ".zip" or extension == ".zip":
                    try:
                        privacy_findings = privacy.scan_zip_bytes(raw, path, privacy_rules, 1)
                    except privacy.PrivacyGateError:
                        add_finding(findings, seen, "archive-unreadable", object_id, path)
                    else:
                        for item in privacy_findings:
                            add_finding(findings, seen, f"archive:{item['category']}", object_id, item["path"])
                    for category, shown in zip_secret_findings(raw, path, history_rules, privacy_rules):
                        add_finding(findings, seen, category, object_id, shown)
                elif kind is not None or extension is not None:
                    add_finding(findings, seen, "unsupported-archive-object", object_id, path)

    for object_id, path in symlinks:
        add_finding(findings, seen, "git-symlink", object_id, path)
    if submodule_count:
        add_finding(findings, seen, "submodule-present", "none", "<git-tree>")
    findings.sort(key=lambda item: (item["category"], privacy.stable_name_key(item["path"]), item["object"]))
    return {
        "status": "fail" if findings else "pass",
        "head": head.strip(),
        "objectScope": "all-local-objects",
        "refCount": len(refs),
        "commitCount": len(commits),
        "localObjectCount": len(objects),
        "scannedBlobCount": scanned_blobs,
        "scannedByteCount": scanned_bytes,
        "authorizedMarkerDefinitions": sorted(
            authorized_marker_definitions,
            key=lambda item: (privacy.stable_name_key(item["path"]), item["object"]),
        ),
        "submoduleEntryCount": submodule_count,
        "symlinkEntryCount": len(symlinks),
        "lfsPointerCount": lfs_pointer_count,
        "findingCount": len(findings),
        "findings": findings,
    }


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        raise HistoryAuditError("bundle-unreadable") from exc
    return digest.hexdigest(), total


def snapshot_regular_file(source: Path, destination: Path) -> tuple[str, int]:
    try:
        before = source.lstat()
    except OSError as exc:
        raise HistoryAuditError("bundle-unreadable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise HistoryAuditError("bundle-invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_fd = destination_fd = -1
    digest = hashlib.sha256()
    total = 0
    try:
        source_fd = os.open(source, flags)
        opened = os.fstat(source_fd)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size)
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size)
        if identity != opened_identity:
            raise HistoryAuditError("bundle-changed-during-snapshot")
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        while chunk := os.read(source_fd, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        after_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size)
        if opened_identity != after_identity or total != opened.st_size:
            raise HistoryAuditError("bundle-changed-during-snapshot")
        if (opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
            raise HistoryAuditError("bundle-changed-during-snapshot")
    except OSError as exc:
        raise HistoryAuditError("bundle-snapshot-failed") from exc
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
    return digest.hexdigest(), total


def audit_bundle(bundle: Path, privacy_rules: dict, history_rules: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="svx-bundle-audit-") as temporary:
        snapshot = Path(temporary) / "audited.bundle"
        digest, size = snapshot_regular_file(bundle, snapshot)
        mirror = Path(temporary) / "mirror.git"
        completed = subprocess.run(
            ["git", "--no-replace-objects", "clone", "--quiet", "--mirror", str(snapshot), str(mirror)],
            check=False,
            capture_output=True,
            text=True,
            env=git_environment(),
        )
        if completed.returncode != 0:
            raise HistoryAuditError("bundle-clone-failed")
        result = audit_repository(mirror, privacy_rules, history_rules)
    return {"name": bundle.name, "sha256": digest, "sizeBytes": size, "audit": result}


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
            json.dump(payload, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise HistoryAuditError("report-unwritable") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def git(repo: Path, *arguments: str) -> None:
    environment = git_environment(
        {
            "GIT_AUTHOR_NAME": "Release Audit Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Release Audit Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        raise HistoryAuditError(f"self-test-git-failed:{arguments[0]}")


def self_test(privacy_rules: dict, history_rules: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="svx-history-selftest-") as temporary:
        repo = Path(temporary) / "repo"
        repo.mkdir()
        git(repo, "init", "--quiet")
        (repo / "README.md").write_text("public fixture\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "--quiet", "-m", "clean")
        clean = audit_repository(repo, privacy_rules, history_rules)
        if clean["status"] != "pass":
            raise HistoryAuditError("self-test-clean-failed")

        original_branch = run_git(repo, ["branch", "--show-current"])
        assert isinstance(original_branch, str)
        original_branch = original_branch.strip()
        git(repo, "checkout", "--quiet", "--detach")
        detached_secret = b"-----BEGIN " + b"PRIVATE KEY-----\nreflog-only\n"
        (repo / "detached-secret.txt").write_bytes(detached_secret)
        git(repo, "add", "detached-secret.txt")
        git(repo, "commit", "--quiet", "-m", "detached negative fixture")
        git(repo, "checkout", "--quiet", original_branch)

        private = repo / ("PRIVATE_" + "USER_STATE")
        private.mkdir()
        marker = b"SVX_PRIVATE_" + b"USER_STATE_PAYLOAD"
        (private / "preferences.json").write_bytes(marker)
        key = b"-----BEGIN " + b"PRIVATE KEY-----\nfixture\n"
        (repo / "credential.txt").write_bytes(key)
        lfs = (
            "version https://git-lfs.github.com/spec/v1\n"
            + "oid sha256:" + "0" * 64 + "\n"
            + "size 1\n"
        )
        (repo / "model.bin").write_text(lfs, encoding="ascii")
        archive = repo / "deleted-secret.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("nested/credential.txt", key)
        hidden_zip = io.BytesIO()
        with zipfile.ZipFile(hidden_zip, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("nested/credential.txt", key)
        (repo / "camouflaged.bin").write_bytes(b"self-extracting-prefix" + hidden_zip.getvalue())
        (repo / "nested.pack").write_bytes(b"PACK\x00fixture")
        (repo / "nested.bundle").write_bytes(b"# v2 git bundle\nfixture")
        if hasattr(os, "symlink"):
            os.symlink("README.md", repo / "public-link")
        git(repo, "add", ".")
        git(repo, "commit", "--quiet", "-m", "negative fixture")
        (private / "preferences.json").unlink()
        private.rmdir()
        (repo / "credential.txt").unlink()
        (repo / "model.bin").unlink()
        archive.unlink()
        (repo / "camouflaged.bin").unlink()
        (repo / "nested.pack").unlink()
        (repo / "nested.bundle").unlink()
        (repo / "public-link").unlink(missing_ok=True)
        git(repo, "add", "-u")
        git(repo, "commit", "--quiet", "-m", "delete fixture")

        negative = audit_repository(repo, privacy_rules, history_rules)
        categories = {item["category"] for item in negative["findings"]}
        required = {
            "forbidden-path",
            "forbidden-name",
            "private-marker",
            "secret-pattern:pem-private-key",
            "git-lfs-pointer-requires-object-audit",
            "git-symlink",
        }
        if not required.issubset(
            categories
        ):
            raise HistoryAuditError("self-test-history-negative-failed")
        if not any("deleted-secret.zip!/nested/credential.txt" in item["path"] for item in negative["findings"]):
            raise HistoryAuditError("self-test-archive-negative-failed")
        if not any("camouflaged.bin!/nested/credential.txt" in item["path"] for item in negative["findings"]):
            raise HistoryAuditError("self-test-prefixed-archive-negative-failed")
        for container_path in ("nested.pack", "nested.bundle"):
            if not any(
                item["path"] == container_path and item["category"] == "unsupported-archive-object"
                for item in negative["findings"]
            ):
                raise HistoryAuditError("self-test-git-container-negative-failed")
        if not any(
            item["path"] == "detached-secret.txt" and item["category"] == "secret-pattern:pem-private-key"
            for item in negative["findings"]
        ):
            raise HistoryAuditError("self-test-detached-negative-failed")

        bundle = Path(temporary) / "fixture.bundle"
        git(repo, "bundle", "create", str(bundle), "--all")
        bundle_result = audit_bundle(bundle, privacy_rules, history_rules)
        if bundle_result["audit"]["status"] != "fail":
            raise HistoryAuditError("self-test-bundle-negative-failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", nargs="?", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--privacy-rules", type=Path, default=DEFAULT_PRIVACY_RULES)
    parser.add_argument("--history-rules", type=Path, default=DEFAULT_HISTORY_RULES)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        privacy_rules = privacy.load_rules(args.privacy_rules)
        history_rules = load_history_rules(args.history_rules)
        if args.self_test:
            self_test(privacy_rules, history_rules)
            print(json.dumps({"releaseHistoryAuditSelfTest": "pass"}, sort_keys=True))
            return 0
        if args.repo is None or args.report is None:
            raise HistoryAuditError("repo-and-report-required")
        repo = args.repo.expanduser().absolute()
        report = args.report.expanduser().absolute()
        if repo.is_symlink():
            raise HistoryAuditError("repository-symlink-rejected")
        result = {
            "schemaVersion": 1,
            "repository": audit_repository(repo, privacy_rules, history_rules),
        }
        if args.bundle is not None:
            result["bundle"] = audit_bundle(args.bundle.expanduser().absolute(), privacy_rules, history_rules)
        write_json_atomic(report, result)
        print(
            json.dumps(
                {
                    "repositoryStatus": result["repository"]["status"],
                    "repositoryFindingCount": result["repository"]["findingCount"],
                    "bundleStatus": result.get("bundle", {}).get("audit", {}).get("status"),
                    "bundleFindingCount": result.get("bundle", {}).get("audit", {}).get("findingCount"),
                },
                sort_keys=True,
            )
        )
        failed = result["repository"]["findingCount"] > 0
        if "bundle" in result:
            failed = failed or result["bundle"]["audit"]["findingCount"] > 0
        return 3 if failed else 0
    except (HistoryAuditError, privacy.PrivacyGateError) as exc:
        print(json.dumps({"releaseHistoryAuditError": str(exc)}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
