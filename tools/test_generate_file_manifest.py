from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "generate_file_manifest.py"


class GenerateFileManifestTests(unittest.TestCase):
    def test_manifest_is_byte_deterministic_for_source_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            root.mkdir()
            (root / "b.bin").write_bytes(b"b")
            (root / "A.bin").write_bytes(b"a")
            output = Path(temporary) / "manifest.json"
            snapshots: list[bytes] = []
            for _ in range(2):
                subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        str(root),
                        str(output),
                        "--workers",
                        "1",
                        "--source-epoch",
                        "1800000000",
                    ],
                    check=True,
                )
                snapshots.append(output.read_bytes())
            self.assertEqual(snapshots[0], snapshots[1])
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("2027-01-15T08:00:00Z", payload["created_utc"])
            self.assertEqual(["A.bin", "b.bin"], [item["path"] for item in payload["files"]])

    def test_source_epoch_is_required_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            root.mkdir()
            output = Path(temporary) / "manifest.json"
            missing = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, missing.returncode)
            old = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    str(root),
                    str(output),
                    "--source-epoch",
                    "1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, old.returncode)


if __name__ == "__main__":
    unittest.main()
