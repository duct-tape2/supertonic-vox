from __future__ import annotations

import copy
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import public_staging_contract as contract  # noqa: E402
import release_open_gates  # noqa: E402
import svx_zip_profile  # noqa: E402


class PublicStagingContractTests(unittest.TestCase):
    @staticmethod
    def valid() -> dict:
        identity = {"name": "source.zip", "sha256": "a" * 64, "sizeBytes": 1}
        return {
            "schemaVersion": 1,
            "releaseEligible": False,
            "sourceCommit": "b" * 40,
            "stagingCommit": "c" * 40,
            "bundle": {**identity, "name": "source.bundle"},
            "sourceArchive": identity,
            "openGates": release_open_gates.load_contract()["requiredOpenGateIds"],
        }

    def test_valid_full_commit_and_gate_contract_pass(self) -> None:
        contract.validate_evidence(self.valid(), release_open_gates.DEFAULT_CONTRACT)

    def test_truncated_commit_and_incomplete_gates_fail(self) -> None:
        cases = []
        truncated = copy.deepcopy(self.valid())
        truncated["sourceCommit"] = truncated["sourceCommit"][:12]
        cases.append((truncated, "evidence-commit-invalid"))
        incomplete = copy.deepcopy(self.valid())
        incomplete["openGates"] = incomplete["openGates"][:-1]
        cases.append((incomplete, "evidence-open-gates-invalid"))
        for payload, expected in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(
                contract.PublicStagingContractError,
                expected,
            ):
                contract.validate_evidence(payload, release_open_gates.DEFAULT_CONTRACT)

    def test_source_zip_is_deterministic_strict_and_allows_source_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "tool.py").write_text("print('fixture')\n", encoding="utf-8")
            (source / "README.md").write_text("fixture\n", encoding="utf-8")
            first = root / "first.zip"
            second = root / "second.zip"
            contract.deterministic_source_zip(source, first, 1_800_000_000, "SupertonicVox/")
            contract.deterministic_source_zip(source, second, 1_800_000_000, "SupertonicVox/")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            profile = svx_zip_profile.validate_zip_profile(
                first.read_bytes(),
                first.stat().st_size,
                {0x000A, 0x5455, 0x7875},
                1024 * 1024,
                2 * 1024 * 1024,
            )
            self.assertEqual(2, len(profile.records))
            with zipfile.ZipFile(io.BytesIO(first.read_bytes())) as archive:
                self.assertEqual(b"", archive.comment)
                self.assertEqual(
                    ["SupertonicVox/README.md", "SupertonicVox/tool.py"],
                    archive.namelist(),
                )

    def test_source_zip_rejects_symlinks_and_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            target = source / "target.txt"
            target.write_text("fixture", encoding="utf-8")
            symlink = source / "linked.txt"
            try:
                symlink.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(contract.PublicStagingContractError, "source-file-invalid"):
                contract.deterministic_source_zip(
                    source,
                    root / "symlink.zip",
                    1_800_000_000,
                    "SupertonicVox/",
                )
            symlink.unlink()
            hardlink = source / "hardlink.txt"
            try:
                os.link(target, hardlink)
            except (NotImplementedError, OSError):
                self.skipTest("hardlinks unavailable")
            with self.assertRaisesRegex(contract.PublicStagingContractError, "source-file-invalid"):
                contract.deterministic_source_zip(
                    source,
                    root / "hardlink.zip",
                    1_800_000_000,
                    "SupertonicVox/",
                )

    def test_staging_archives_the_clean_export_before_build_outputs_exist(self) -> None:
        script = (TOOLS.parent / "packaging" / "create-public-release-staging.sh").read_text(
            encoding="utf-8"
        )
        archive = script.index('public_staging_contract.py" create-zip')
        restore = script.index('"$DOTNET" restore')
        build = script.index('"$DOTNET" build')
        self.assertLess(archive, restore)
        self.assertLess(archive, build)

    def test_voxcpm2_release_contract_is_required_allowlisted_and_staged(self) -> None:
        script = (TOOLS.parent / "packaging" / "create-public-release-staging.sh").read_text(
            encoding="utf-8"
        )
        marker = "VOXCPM2_RUNTIME_PACK_RELEASE.md"
        self.assertGreaterEqual(script.count(marker), 3)
        required = script.index(marker, script.index("REQUIRED_INPUTS=("))
        allowlisted = script.index(marker, script.index("ALLOWLIST=("))
        staged = script.index(marker, script.index('git -C "$TREE" add'))
        self.assertLess(required, allowlisted)
        self.assertLess(allowlisted, staged)


if __name__ == "__main__":
    unittest.main()
