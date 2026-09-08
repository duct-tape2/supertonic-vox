from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import tempfile
import unittest


TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

import release_history_audit as audit  # noqa: E402
import release_privacy_gate as privacy  # noqa: E402


class ReleaseHistoryAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.privacy_rules = privacy.load_rules(audit.DEFAULT_PRIVACY_RULES)
        cls.history_rules = audit.load_history_rules(audit.DEFAULT_HISTORY_RULES)

    def test_negative_history_and_bundle_self_test(self) -> None:
        audit.self_test(self.privacy_rules, self.history_rules)

    def test_secret_pattern_definitions_do_not_match_the_rules_document(self) -> None:
        data = audit.DEFAULT_HISTORY_RULES.read_bytes()
        self.assertEqual([], audit.secret_hits(data, self.history_rules))

    def test_marker_definition_authorization_is_canonical_and_exact(self) -> None:
        self.assertEqual(
            "tools/release_privacy_rules.json",
            self.history_rules["markerDefinitionPath"],
        )
        raw = audit.DEFAULT_PRIVACY_RULES.read_bytes()
        self.assertEqual(64, len(privacy.authorized_rules_definition(raw, self.privacy_rules) or ""))

        parsed = json.loads(raw.decode("ascii"))
        parsed["unexpected"] = "PRIVATE_" + "USER_STATE: actual leaked transcript"
        tampered = (json.dumps(parsed, ensure_ascii=True, indent=2) + "\n").encode("ascii")
        self.assertIsNone(privacy.authorized_rules_definition(tampered, self.privacy_rules))

    def test_former_marker_allowlist_paths_fail_on_actual_transcript(self) -> None:
        targets = (
            "tools/release_privacy_gate.py",
            "tools/release_privacy_rules.json",
            "tools/test_release_privacy_gate.py",
        )
        leak = b"PRIVATE_" + b"USER_STATE: actual leaked user transcript payload\n"
        for target in targets:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary) / "repo"
                (repo / "tools").mkdir(parents=True)
                audit.git(repo, "init", "--quiet")
                (repo / "tools" / "release_privacy_rules.json").write_bytes(
                    audit.DEFAULT_PRIVACY_RULES.read_bytes()
                )
                (repo / "tools" / "release_privacy_gate.py").write_text(
                    "public fixture\n", encoding="ascii"
                )
                (repo / "tools" / "test_release_privacy_gate.py").write_text(
                    "public fixture\n", encoding="ascii"
                )
                audit.git(repo, "add", ".")
                audit.git(repo, "commit", "--quiet", "-m", "clean fixture")
                candidate = repo / target
                if target.endswith("release_privacy_rules.json"):
                    payload = json.loads(candidate.read_text(encoding="ascii"))
                    payload["unexpected"] = leak.decode("ascii").strip()
                    candidate.write_text(
                        json.dumps(payload, ensure_ascii=True, indent=2) + "\n",
                        encoding="ascii",
                    )
                else:
                    candidate.write_bytes(candidate.read_bytes() + leak)
                audit.git(repo, "add", target)
                audit.git(repo, "commit", "--quiet", "-m", "negative fixture")

                result = audit.audit_repository(repo, self.privacy_rules, self.history_rules)
                self.assertEqual("fail", result["status"])
                self.assertTrue(
                    any(
                        item["category"] == "private-marker" and item["path"] == target
                        for item in result["findings"]
                    )
                )

    def test_bundle_snapshot_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bundle"
            source.write_bytes(b"fixture")
            symlink = root / "symlink.bundle"
            try:
                symlink.symlink_to(source)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaises(audit.HistoryAuditError):
                    audit.snapshot_regular_file(symlink, root / "symlink.snapshot")

            hardlink = root / "hardlink.bundle"
            try:
                os.link(source, hardlink)
            except OSError:
                pass
            else:
                with self.assertRaises(audit.HistoryAuditError):
                    audit.snapshot_regular_file(source, root / "hardlink.snapshot")

    def test_git_container_magics_fail_closed(self) -> None:
        self.assertEqual("git-pack", audit.container_kind(b"PACK\x00fixture"))
        self.assertEqual("git-bundle", audit.container_kind(b"# v2 git bundle\nfixture"))


if __name__ == "__main__":
    unittest.main()
