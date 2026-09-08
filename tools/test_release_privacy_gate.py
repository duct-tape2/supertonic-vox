from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

import release_privacy_gate as gate  # noqa: E402


RULES_PATH = TOOLS_DIR / "release_privacy_rules.json"


def make_zip(name: str = "public/payload.bin", data: bytes = b"public fixture") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return output.getvalue()


def add_canonical_prefix(payload: bytes, prefix: bytes) -> bytes:
    result = bytearray(prefix + payload)
    old_eocd = len(payload) - 22
    old_central = int.from_bytes(payload[old_eocd + 16 : old_eocd + 20], "little")
    new_eocd = len(result) - 22
    new_central = old_central + len(prefix)
    result[new_eocd + 16 : new_eocd + 20] = new_central.to_bytes(4, "little")
    cursor = new_central
    while cursor < new_eocd:
        if result[cursor : cursor + 4] != b"PK\x01\x02":
            raise AssertionError("fixture central directory is invalid")
        filename_length = int.from_bytes(result[cursor + 28 : cursor + 30], "little")
        extra_length = int.from_bytes(result[cursor + 30 : cursor + 32], "little")
        comment_length = int.from_bytes(result[cursor + 32 : cursor + 34], "little")
        local_offset = int.from_bytes(result[cursor + 42 : cursor + 46], "little")
        result[cursor + 42 : cursor + 46] = (local_offset + len(prefix)).to_bytes(4, "little")
        cursor += 46 + filename_length + extra_length + comment_length
    return bytes(result)


class ReleasePrivacyGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = gate.load_rules(RULES_PATH)

    def test_self_test_covers_clean_and_negative_fixtures(self) -> None:
        gate.self_test(self.rules)

    def test_rules_fail_closed_when_missing_corrupt_or_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures = {
                "missing.json": None,
                "corrupt.json": "{",
                "empty.json": "{}",
                "invalid-limit.json": json.dumps({**self.rules, "maximumArchiveMembers": 0}),
                "duplicate.json": json.dumps(
                    {**self.rules, "forbiddenFileNames": ["preferences.json", "PREFERENCES.JSON"]}
                ),
            }
            for name, content in fixtures.items():
                path = root / name
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(gate.PrivacyGateError):
                    gate.load_rules(path)

    def test_paths_are_case_unicode_and_platform_normalized(self) -> None:
        cases = (
            ("PRIVATE_USER_STATE/model.bin", "forbidden-path"),
            ("ＰＲＩＶＡＴＥ＿ＵＳＥＲ＿ＳＴＡＴＥ/model.bin", "forbidden-path"),
            ("Public/PREFERENCES.JSON", "forbidden-name"),
            ("Public/VOICE.WAV", "forbidden-extension"),
            ("../escape.txt", "unsafe-path"),
            ("C:\\private\\escape.txt", "unsafe-path"),
        )
        for path, category in cases:
            with self.subTest(path=path):
                findings = gate.path_findings(path, self.rules)
                self.assertIn(category, {item["category"] for item in findings})

    def test_nested_archive_reports_private_path_without_extracting(self) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("REFERENCE_AUDIO/voice.bin", b"x")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("inner.zip", inner.getvalue())

        findings = gate.scan_zip_bytes(outer.getvalue(), "outer.zip", self.rules, 1)

        private = [item for item in findings if item["category"] == "forbidden-path"]
        self.assertEqual(1, len(private))
        self.assertIn("outer.zip!/inner.zip!/REFERENCE_AUDIO/voice.bin", private[0]["path"])

    def test_private_marker_in_archive_filename_is_rejected(self) -> None:
        marker_name = "public/PRIVATE_" + "USER_STATE: real-user-transcript.bin"
        findings = gate.scan_zip_bytes(make_zip(marker_name), "filename-marker.zip", self.rules, 1)
        self.assertIn("private-marker-path", {item["category"] for item in findings})

    def test_deflate_stream_trailing_payload_is_rejected(self) -> None:
        clean = make_zip("public/payload.bin", b"public fixture")
        payload = bytearray(clean)
        old_eocd = len(payload) - 22
        old_central = int.from_bytes(payload[old_eocd + 16 : old_eocd + 20], "little")
        filename_length = int.from_bytes(payload[26:28], "little")
        extra_length = int.from_bytes(payload[28:30], "little")
        compressed_size = int.from_bytes(payload[18:22], "little")
        data_end = 30 + filename_length + extra_length + compressed_size
        hidden = b"PRIVATE_" + b"USER_STATE: hidden after deflate eof"
        payload[data_end:data_end] = hidden
        new_central = old_central + len(hidden)
        new_eocd = old_eocd + len(hidden)
        new_compressed_size = compressed_size + len(hidden)
        payload[18:22] = new_compressed_size.to_bytes(4, "little")
        payload[new_central + 20 : new_central + 24] = new_compressed_size.to_bytes(4, "little")
        payload[new_eocd + 16 : new_eocd + 20] = new_central.to_bytes(4, "little")

        findings = gate.scan_zip_bytes(bytes(payload), "trailing-deflate.zip", self.rules, 1)
        self.assertIn(
            "archive-compressed-stream-trailing-data",
            {item["category"] for item in findings},
        )

    def test_corrupt_deflate_stream_returns_a_machine_readable_finding(self) -> None:
        payload = bytearray(make_zip("public/payload.bin", b"public fixture" * 1024))
        filename_length = int.from_bytes(payload[26:28], "little")
        extra_length = int.from_bytes(payload[28:30], "little")
        data_offset = 30 + filename_length + extra_length
        payload[data_offset] = 0x07

        findings = gate.scan_zip_bytes(bytes(payload), "corrupt-deflate.zip", self.rules, 1)
        self.assertIn(
            "archive-compressed-stream-invalid",
            {item["category"] for item in findings},
        )

    def test_strict_zip_profile_rejects_prefix_trailer_gap_descriptor_and_mismatch(self) -> None:
        clean = make_zip()
        prefixed = add_canonical_prefix(clean, b"unattributed prefix")
        trailer = clean + b"unattributed trailer"

        eocd = len(clean) - 22
        central = int.from_bytes(clean[eocd + 16 : eocd + 20], "little")
        gapped = bytearray(clean[:central] + b"orphan-gap" + clean[central:])
        new_eocd = len(gapped) - 22
        gapped[new_eocd + 16 : new_eocd + 20] = (central + len(b"orphan-gap")).to_bytes(
            4, "little"
        )

        descriptor = bytearray(clean)
        descriptor[6:8] = (int.from_bytes(descriptor[6:8], "little") | 0x0008).to_bytes(2, "little")
        descriptor[central + 8 : central + 10] = (
            int.from_bytes(descriptor[central + 8 : central + 10], "little") | 0x0008
        ).to_bytes(2, "little")

        mismatch = bytearray(clean)
        mismatch[14:18] = ((int.from_bytes(mismatch[14:18], "little") + 1) & 0xFFFFFFFF).to_bytes(
            4, "little"
        )

        cases = {
            "prefix": (prefixed, "archive-unattributed-bytes"),
            "trailer": (trailer, "archive-eocd-not-at-eof"),
            "gap": (bytes(gapped), "archive-unattributed-bytes"),
            "descriptor": (bytes(descriptor), "archive-data-descriptor-unsupported"),
            "mismatch": (bytes(mismatch), "archive-local-central-mismatch"),
        }
        for name, (payload, expected) in cases.items():
            with self.subTest(name=name):
                categories = {
                    item["category"] for item in gate.scan_zip_bytes(payload, f"{name}.zip", self.rules, 1)
                }
                self.assertIn(expected, categories)

    def test_strict_zip_profile_rejects_comments_unknown_extras_and_nested_polyglots(self) -> None:
        commented_buffer = io.BytesIO()
        with zipfile.ZipFile(commented_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.comment = b"covert channel"
            archive.writestr("public.txt", b"fixture")

        extra_buffer = io.BytesIO()
        with zipfile.ZipFile(extra_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo("public.bin")
            info.extra = struct.pack("<HH", 0x9999, 1) + b"x"
            archive.writestr(info, b"fixture")

        private = b"PRIVATE_" + b"USER_STATE: nested transcript"
        inner = add_canonical_prefix(make_zip("public.txt", private), b"prefix")
        outer = make_zip("asset.bin", inner)

        self.assertIn(
            "archive-eocd-not-at-eof",
            {item["category"] for item in gate.scan_zip_bytes(commented_buffer.getvalue(), "comment.zip", self.rules, 1)},
        )
        self.assertIn(
            "archive-extra-field-unsupported",
            {item["category"] for item in gate.scan_zip_bytes(extra_buffer.getvalue(), "extra.zip", self.rules, 1)},
        )
        nested_categories = {
            item["category"] for item in gate.scan_zip_bytes(outer, "outer.zip", self.rules, 1)
        }
        self.assertIn("archive-unattributed-bytes", nested_categories)

    def test_strict_zip_extra_field_allowlist_and_shapes(self) -> None:
        def archive_with_extra(extra: bytes) -> bytes:
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
                info = zipfile.ZipInfo("public.bin")
                info.extra = extra
                archive.writestr(info, b"fixture")
            return output.getvalue()

        timestamp = struct.pack("<HH", 0x5455, 5) + b"\x01" + b"\x00" * 4
        uid_gid_payload = b"\x01\x01\x01\x01\x01"
        uid_gid = struct.pack("<HH", 0x7875, len(uid_gid_payload)) + uid_gid_payload
        ntfs_payload = b"\x00" * 4 + struct.pack("<HH", 1, 24) + b"\x00" * 24
        ntfs = struct.pack("<HH", 0x000A, len(ntfs_payload)) + ntfs_payload
        self.assertEqual(
            [],
            gate.scan_zip_bytes(
                archive_with_extra(timestamp + uid_gid + ntfs),
                "valid-extra.zip",
                self.rules,
                1,
            ),
        )

        invalid = {
            "zip64": (struct.pack("<HH", 0x0001, 8) + b"\x00" * 8, "archive-zip64-unsupported"),
            "truncated": (b"\x55\x54\x05", "archive-extra-field-malformed"),
            "timestamp": (
                struct.pack("<HH", 0x5455, 2) + b"\x01\x00",
                "archive-extra-field-invalid",
            ),
            "uid-gid": (
                struct.pack("<HH", 0x7875, 3) + b"\x02\x01\x00",
                "archive-extra-field-invalid",
            ),
            "ntfs": (
                struct.pack("<HH", 0x000A, 4) + b"\x00" * 4,
                "archive-extra-field-invalid",
            ),
            "duplicate": (timestamp + timestamp, "archive-extra-field-malformed"),
        }
        for name, (extra, expected) in invalid.items():
            with self.subTest(name=name):
                categories = {
                    item["category"]
                    for item in gate.scan_zip_bytes(
                        archive_with_extra(extra), f"{name}.zip", self.rules, 1
                    )
                }
                self.assertIn(expected, categories)

        marker = b"PRIVATE_" + b"USER_STATE:"
        covert_payload = b"\x00" * 4 + struct.pack("<HH", 1, 24) + marker.ljust(24, b"\x00")
        covert_extra = struct.pack("<HH", 0x000A, len(covert_payload)) + covert_payload
        self.assertIn(
            "private-marker-binary",
            {
                item["category"]
                for item in gate.scan_zip_bytes(
                    archive_with_extra(covert_extra), "covert-extra.zip", self.rules, 1
                )
            },
        )

    def test_disguised_nested_zip_is_detected_by_content(self) -> None:
        marker = b"SVX_PRIVATE_" + b"USER_STATE_PAYLOAD"
        inner = make_zip("public/resource.bin", marker)
        outer = make_zip("asset.bin", inner)
        findings = gate.scan_zip_bytes(outer, "outer.zip", self.rules, 1)
        self.assertIn("private-marker-binary", {item["category"] for item in findings})
        self.assertTrue(any("asset.bin!/public/resource.bin" in item["path"] for item in findings))

    def test_archive_symlink_duplicate_and_resource_limits_are_rejected(self) -> None:
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            symlink = zipfile.ZipInfo("public/link")
            symlink.create_system = 3
            symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(symlink, "target")
            archive.writestr("Readme.TXT", b"one")
            archive.writestr("README.txt", b"two")
            archive.writestr("compressed.bin", b"0" * 4096)

        strict = dict(self.rules)
        strict["maximumCompressionRatio"] = 1
        findings = gate.scan_zip_bytes(archive_bytes.getvalue(), "fixture.zip", strict, 1)
        categories = {item["category"] for item in findings}
        self.assertIn("archive-symlink", categories)
        self.assertIn("archive-duplicate-member", categories)
        self.assertIn("archive-compression-ratio", categories)

        count_limited = dict(self.rules)
        count_limited["maximumArchiveMembers"] = 1
        findings = gate.scan_zip_bytes(archive_bytes.getvalue(), "fixture.zip", count_limited, 1)
        self.assertEqual({"archive-member-count"}, {item["category"] for item in findings})

    def test_private_markers_are_detected_inside_binary_files_and_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "embedded.dll").write_bytes(
                b"prefix private_" + b"user_state: suffix"
            )
            findings = gate.scan(root, self.rules)
            self.assertIn("private-marker-binary", {item["category"] for item in findings})

            archive = root / "embedded.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                output.writestr(
                    "public/resource.bin",
                    b"prefix SVX_PRIVATE_" + b"USER_STATE_PAYLOAD suffix",
                )
            findings = gate.scan(archive, self.rules)
            self.assertIn("private-marker-binary", {item["category"] for item in findings})

            disguised = root / "disguised.bin"
            disguised.write_bytes(b"self-extracting-prefix" + archive.read_bytes())
            findings = gate.scan(disguised, self.rules)
            self.assertIn("archive-central-boundary-invalid", {item["category"] for item in findings})

    def test_non_zip_containers_and_hardlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compressed = root / "payload.bin"
            compressed.write_bytes(b"\x1f\x8b\x08\x00fixture")
            self.assertIn("unsupported-container", {item["category"] for item in gate.scan(compressed, self.rules)})

            hardlink = root / "payload-copy.bin"
            try:
                os.link(compressed, hardlink)
            except (NotImplementedError, OSError):
                return
            self.assertIn("hardlink-root", {item["category"] for item in gate.scan(compressed, self.rules)})

            tree = root / "tree"
            tree.mkdir()
            source = tree / "a.onnx"
            source.write_bytes(b"model")
            os.link(source, tree / "b.onnx")
            directory_findings = {
                item["category"]
                for item in gate.scan(tree, self.rules)
                if item["path"] in {"a.onnx", "b.onnx"}
            }
            self.assertEqual({"hardlink"}, directory_findings)

    def test_unsupported_zip_compression_is_normalized(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("payload.bin", b"fixture")
        payload = bytearray(buffer.getvalue())
        payload[8:10] = (99).to_bytes(2, "little")
        central = payload.index(b"PK\x01\x02")
        payload[central + 10 : central + 12] = (99).to_bytes(2, "little")

        self.assertIn(
            "archive-compression-unsupported",
            {
                item["category"]
                for item in gate.scan_zip_bytes(bytes(payload), "unsupported.zip", self.rules, 1)
            },
        )

    def test_lzma_member_is_rejected_by_strict_profile(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_LZMA) as archive:
            archive.writestr("payload.bin", b"0123456789" * 1000)
        findings = gate.scan_zip_bytes(buffer.getvalue(), "lzma.zip", self.rules, 1)
        self.assertIn("archive-compression-unsupported", {item["category"] for item in findings})

    def test_scan_and_fingerprint_detects_tree_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            file = target / "app.bin"
            file.write_bytes(b"before")
            original_scan = gate.scan

            def mutating_scan(path: Path, rules: dict) -> list[dict[str, str]]:
                findings = original_scan(path, rules)
                file.write_bytes(b"after")
                return findings

            with mock.patch.object(gate, "scan", side_effect=mutating_scan):
                with self.assertRaisesRegex(gate.PrivacyGateError, "target-changed-during-scan"):
                    gate.scan_and_fingerprint(target, self.rules)

    def test_cli_writes_commit_bound_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = root / "staging"
            staging.mkdir()
            (staging / "app.bin").write_bytes(b"public application")
            report = root / "privacy-report.json"
            commit = "a" * 40

            completed = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS_DIR / "release_privacy_gate.py"),
                    str(staging),
                    "--rules",
                    str(RULES_PATH),
                    "--release-commit",
                    commit,
                    "--report",
                    str(report),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("pass", result["status"])
            self.assertEqual(commit, result["releaseCommit"])
            self.assertEqual(1, result["scannedFileCount"])
            self.assertEqual(64, len(result["targetFingerprintSha256"]))
            self.assertEqual(result, json.loads(completed.stdout))

    def test_cli_fails_closed_without_release_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            staging.mkdir()
            (staging / "app.bin").write_bytes(b"public application")

            completed = subprocess.run(
                [sys.executable, str(TOOLS_DIR / "release_privacy_gate.py"), str(staging)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(4, completed.returncode)
            self.assertIn("report-required", completed.stderr)

    def test_report_must_be_outside_the_scanned_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            staging.mkdir()
            (staging / "app.bin").write_bytes(b"public application")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS_DIR / "release_privacy_gate.py"),
                    str(staging),
                    "--release-commit",
                    "b" * 40,
                    "--report",
                    str(staging / "privacy-report.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(4, completed.returncode)
            self.assertIn("report-inside-target", completed.stderr)

    def test_cli_rejects_a_symlink_root_without_resolving_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            (target / "app.bin").write_bytes(b"public application")
            symlink = root / "candidate"
            try:
                symlink.symlink_to(target, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            report = root / "privacy-report.json"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS_DIR / "release_privacy_gate.py"),
                    str(symlink),
                    "--release-commit",
                    "c" * 40,
                    "--report",
                    str(report),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(3, completed.returncode, completed.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("fail", result["status"])
            self.assertEqual({"symlink-root"}, {item["category"] for item in result["findings"]})

    def test_directory_fingerprint_is_deterministic_and_content_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.bin").write_bytes(b"a")
            (root / "b.bin").write_bytes(b"b")
            first = gate.target_fingerprint(root)
            second = gate.target_fingerprint(root)
            self.assertEqual(first, second)

            (root / "b.bin").write_bytes(b"changed")
            changed = gate.target_fingerprint(root)
            self.assertNotEqual(first[0], changed[0])

    def test_stable_name_key_breaks_normalized_name_ties(self) -> None:
        names = ["Ａ.bin", "A.bin"]
        forward = sorted(names, key=gate.stable_name_key)
        reverse = sorted(reversed(names), key=gate.stable_name_key)
        self.assertEqual(forward, reverse)


if __name__ == "__main__":
    unittest.main()
