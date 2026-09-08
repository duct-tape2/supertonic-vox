from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import repository_privacy_posture as posture  # noqa: E402


class RepositoryPrivacyPostureTests(unittest.TestCase):
    def test_finding_canonicalization_and_hash_are_stable(self) -> None:
        findings = [
            {"path": "b", "object": "2", "category": "forbidden-path"},
            {"category": "forbidden-path", "object": "1", "path": "a"},
        ]
        reversed_findings = list(reversed(findings))
        self.assertEqual(
            posture.canonical_findings(findings),
            posture.canonical_findings(reversed_findings),
        )
        self.assertEqual(
            posture.finding_set_sha256(findings),
            posture.finding_set_sha256(reversed_findings),
        )

    def test_clean_public_fixture_requires_zero_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }
            subprocess.run(["git", "-C", str(repo), "init", "--quiet"], check=True, env=environment)
            (repo / "README.md").write_text("public fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True, env=environment)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
                check=True,
                env=environment,
            )
            result = posture.evaluate(repo)
            self.assertEqual("pass", result["status"])
            self.assertEqual("public-clean-history", result["mode"])
            self.assertEqual(0, result["findingCount"])

    def test_recovery_mode_fails_without_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }
            subprocess.run(["git", "-C", str(repo), "init", "--quiet"], check=True, env=environment)
            (repo / posture.RECOVERY_MARKER).write_text("recovery fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True, env=environment)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "--quiet", "-m", "fixture"],
                check=True,
                env=environment,
            )
            with mock.patch.object(posture, "EXPECTED", repo / "missing-ledger.json"):
                with self.assertRaisesRegex(posture.PostureError, "recovery-ledger-unavailable"):
                    posture.evaluate(repo)


if __name__ == "__main__":
    unittest.main()
