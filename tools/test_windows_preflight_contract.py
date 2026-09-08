from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import subprocess


TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

import windows_preflight_contract as contract  # noqa: E402
import svx_zip_profile as zip_profile  # noqa: E402


class WindowsPreflightContractTests(unittest.TestCase):
    def test_windows_script_targets_only_the_cross_platform_successor(self) -> None:
        script = (TOOLS_DIR.parent / "packaging" / "build-windows-release.ps1").read_text(encoding="utf-8")
        self.assertIn("SupertonicVox.CrossPlatform.slnx", script)
        self.assertIn("src\\CrossPlatform\\SupertonicVox.Desktop", script)
        self.assertIn("SupertonicSmoke", script)
        self.assertIn("UNSIGNED-NOT-FOR-DISTRIBUTION", script)
        self.assertIn("releaseEligible = $false", script)
        self.assertIn("compare-publish", script)
        self.assertNotIn("src\\DesktopApp", script)
        self.assertNotIn("_internal", script)
        self.assertNotIn("DesktopSmoke", script)

    def test_capture_required_allowlist_cannot_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "target": "win-x64",
                        "dotnetSdkVersion": "10.0.302",
                        "status": "capture-required",
                        "files": [],
                    }
                ),
                encoding="utf-8",
            )
            contract.load_allowlist(path, require_approved=False)
            contract.load_allowlist(
                path,
                require_approved=False,
                expected_sdk_version="10.0.302",
            )
            with self.assertRaisesRegex(
                contract.WindowsPreflightContractError,
                "allowlist-sdk-mismatch",
            ):
                contract.load_allowlist(
                    path,
                    require_approved=False,
                    expected_sdk_version="10.0.303",
                )
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "allowlist-not-approved"):
                contract.load_allowlist(path, require_approved=True)

    def test_allowlist_rejects_paths_order_and_duplicates(self) -> None:
        base = {
            "schemaVersion": 1,
            "target": "win-x64",
            "dotnetSdkVersion": "10.0.302",
            "status": "approved",
        }
        fixtures = (
            (["../escape.dll"], "unsafe-publish-path"),
            (["b.dll", "a.dll"], "allowlist-order-invalid"),
            (["App.dll", "app.dll"], "allowlist-duplicate"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "allowlist.json"
            for files, expected in fixtures:
                with self.subTest(files=files):
                    path.write_text(json.dumps({**base, "files": files}), encoding="utf-8")
                    with self.assertRaisesRegex(contract.WindowsPreflightContractError, expected):
                        contract.load_allowlist(path, require_approved=True)

    def test_publish_inventory_is_exact_and_rejects_forbidden_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publish = root / "publish"
            publish.mkdir()
            (publish / "App.dll").write_bytes(b"assembly")
            allowlist = {
                "schemaVersion": 1,
                "target": "win-x64",
                "dotnetSdkVersion": "10.0.302",
                "status": "approved",
                "files": ["App.dll"],
            }
            records = contract.compare_publish_tree(publish, allowlist)
            self.assertEqual(["App.dll"], [item["path"] for item in records])

            (publish / "unexpected.dll").write_bytes(b"unexpected")
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "inventory-mismatch"):
                contract.compare_publish_tree(publish, allowlist)
            (publish / "unexpected.dll").unlink()

            (publish / "createdump.exe").write_bytes(b"dump helper")
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "publish-file-forbidden"):
                contract.inspect_publish_tree(publish)

    def test_publish_tree_rejects_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "a.dll"
            source.write_bytes(b"assembly")
            try:
                os.link(source, root / "b.dll")
            except OSError:
                self.skipTest("hardlinks are unavailable")
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "publish-file-invalid"):
                contract.inspect_publish_tree(root)

    def test_deterministic_zip_is_repeatable_and_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "package"
            source.mkdir()
            (source / "b.dll").write_bytes(b"b")
            (source / "a.dll").write_bytes(b"a")
            first = root / "first.zip"
            second = root / "second.zip"
            contract.deterministic_zip(source, first, 1_800_000_000)
            contract.deterministic_zip(source, second, 1_800_000_000)
            self.assertEqual(contract.sha256_file(first), contract.sha256_file(second))
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(["a.dll", "b.dll"], archive.namelist())
                self.assertEqual(b"a", archive.read("a.dll"))

            prefixed = root / "prefixed.zip"
            contract.deterministic_zip(source, prefixed, 1_800_000_000, "SupertonicVox/")
            profile = zip_profile.validate_zip_profile(
                prefixed.read_bytes(),
                prefixed.stat().st_size,
                {0x000A, 0x5455, 0x7875},
            )
            self.assertEqual(2, len(profile.records))
            with zipfile.ZipFile(prefixed) as archive:
                self.assertEqual(b"", archive.comment)
                self.assertEqual(
                    ["SupertonicVox/a.dll", "SupertonicVox/b.dll"],
                    archive.namelist(),
                )

    def test_evidence_must_remain_unsigned_and_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "release-evidence.json"
            artifact_name = "SupertonicVox-0.1.0-windows-x64-UNSIGNED-NOT-FOR-DISTRIBUTION.zip"
            artifact_path = root / artifact_name
            artifact_path.write_bytes(b"zip")
            report_path = root / "privacy-report.json"
            report_path.write_bytes(b"report")
            artifact_digest, artifact_size = contract.sha256_file(artifact_path)
            report_digest, report_size = contract.sha256_file(report_path)
            identity = {
                "name": report_path.name,
                "sha256": report_digest,
                "sizeBytes": report_size,
            }
            payload = {
                "schemaVersion": 1,
                "mode": "preflight-unsigned",
                "releaseEligible": False,
                "releaseCommit": "b" * 40,
                "sourceMode": "git-archive",
                "packageVersion": "0.1.0",
                "artifact": {
                    "name": artifact_name,
                    "sha256": artifact_digest,
                    "sizeBytes": artifact_size,
                },
                "toolchain": {"dotnetSdkVersion": "10.0.302", "dotnetExecutableSha256": "d" * 64},
                "evidenceFiles": {"privacyReport": identity},
                "openGates": sorted(contract.REQUIRED_OPEN_GATES),
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            contract.validate_evidence(path)
            contract.validate_evidence(path, root)

            artifact_path.write_bytes(b"swapped")
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "artifact-mismatch"):
                contract.validate_evidence(path, root)
            artifact_path.write_bytes(b"zip")

            (root / "injected.txt").write_bytes(b"untrusted")
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "inventory-mismatch"):
                contract.validate_evidence(path, root)
            (root / "injected.txt").unlink()

            payload["releaseEligible"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "release-state-invalid"):
                contract.validate_evidence(path)

    def test_evidence_rejects_wrong_scalar_and_collection_types(self) -> None:
        identity = {"name": "report.json", "sha256": "a" * 64, "sizeBytes": 1}
        valid = {
            "schemaVersion": 1,
            "mode": "preflight-unsigned",
            "releaseEligible": False,
            "releaseCommit": "b" * 40,
            "sourceMode": "git-archive",
            "packageVersion": "0.1.0",
            "artifact": {
                "name": "SupertonicVox-0.1.0-windows-x64-UNSIGNED-NOT-FOR-DISTRIBUTION.zip",
                "sha256": "c" * 64,
                "sizeBytes": 2,
            },
            "toolchain": {
                "dotnetSdkVersion": "10.0.302",
                "dotnetExecutableSha256": "d" * 64,
            },
            "evidenceFiles": {"privacyReport": identity},
            "openGates": sorted(contract.REQUIRED_OPEN_GATES),
        }
        fixtures = (
            ({**valid, "packageVersion": 1}, "evidence-source-invalid"),
            ({**valid, "openGates": {value: True for value in contract.REQUIRED_OPEN_GATES}}, "evidence-open-gates-invalid"),
            ({**valid, "artifact": {**valid["artifact"], "name": 7}}, "evidence-artifact-invalid"),
            ({**valid, "toolchain": {**valid["toolchain"], "dotnetSdkVersion": 10}}, "evidence-toolchain-invalid"),
            ({**valid, "evidenceFiles": {"bad-role!": identity}}, "evidence-file-identity-invalid"),
            ({**valid, "evidenceFiles": {"privacyReport": {**identity, "sha256": 1}}}, "evidence-file-identity-invalid"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-evidence.json"
            for payload, expected in fixtures:
                with self.subTest(expected=expected):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(contract.WindowsPreflightContractError, expected):
                        contract.validate_evidence(path)

    def test_source_git_modes_reject_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }
            subprocess.run(["git", "-C", str(repo), "init", "--quiet"], check=True, env=environment)
            (repo / "target.txt").write_text("fixture", encoding="utf-8")
            link = repo / "link.txt"
            try:
                link.symlink_to("target.txt")
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True, env=environment)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
                check=True,
                env=environment,
            )
            commit = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True, env=environment
            ).strip()
            with self.assertRaisesRegex(contract.WindowsPreflightContractError, "source-git-mode-rejected:120000"):
                contract.verify_source_git_modes(repo, commit)


if __name__ == "__main__":
    unittest.main()
