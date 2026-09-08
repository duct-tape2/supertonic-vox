from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_DIR))

import fetch_supertonic_model as fetcher  # noqa: E402


class FetchSupertonicModelTests(unittest.TestCase):
    def test_committed_catalog_has_exact_pinned_public_artifact_set(self) -> None:
        artifacts = fetcher.load_artifacts(fetcher.DEFAULT_CATALOG)

        self.assertEqual(set(fetcher.EXPECTED_LOCATIONS), {artifact.name for artifact in artifacts})
        self.assertEqual(7, len(artifacts))

    def test_catalog_rejects_revision_host_and_duplicate_drift(self) -> None:
        source = json.loads(fetcher.DEFAULT_CATALOG.read_text(encoding="utf-8"))
        engine = next(item for item in source["engines"] if item["id"] == fetcher.ENGINE_ID)
        mutations = []

        revision = copy.deepcopy(source)
        next(item for item in revision["engines"] if item["id"] == fetcher.ENGINE_ID)["modelRevision"] = "main"
        mutations.append(revision)

        host = copy.deepcopy(source)
        next(item for item in host["engines"] if item["id"] == fetcher.ENGINE_ID)["artifacts"][0][
            "downloadUri"
        ] = "https://example.com/model.onnx"
        mutations.append(host)

        duplicate = copy.deepcopy(source)
        duplicate_engine = next(item for item in duplicate["engines"] if item["id"] == fetcher.ENGINE_ID)
        duplicate_engine["artifacts"][1]["name"] = duplicate_engine["artifacts"][0]["name"]
        mutations.append(duplicate)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, mutation in enumerate(mutations):
                path = root / f"catalog-{index}.json"
                path.write_text(json.dumps(mutation), encoding="utf-8")
                with self.subTest(index=index), self.assertRaises(fetcher.ModelFetchError):
                    fetcher.load_artifacts(path)

    def test_offline_materialization_verifies_every_file(self) -> None:
        artifacts = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (name, directory) in enumerate(fetcher.EXPECTED_LOCATIONS.items()):
                data = f"fixture-{index}".encode()
                target = root / directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                artifacts.append(
                    fetcher.Artifact(
                        name=name,
                        directory=directory,
                        uri=(
                            "https://huggingface.co/Supertone/supertonic-3/resolve/"
                            f"{fetcher.MODEL_REVISION}/{directory}/{name}"
                        ),
                        size=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),
                    )
                )

            report = fetcher.materialize(artifacts, root, offline=True)
            self.assertEqual(7, len(report))

            (root / artifacts[0].directory / artifacts[0].name).write_bytes(b"corrupt")
            with self.assertRaises(fetcher.ModelFetchError):
                fetcher.materialize(artifacts, root, offline=True)

    def test_redirect_allowlist_rejects_non_https_and_unrelated_hosts(self) -> None:
        accepted = (
            "https://cdn-lfs.huggingface.co/file",
            "https://cas-bridge.xethub.hf.co/file",
            "https://us.aws.cdn.hf.co/file",
        )
        rejected = (
            "http://huggingface.co/file",
            "https://huggingface.co.evil.example/file",
            "https://example.com/file",
        )
        for uri in accepted:
            with self.subTest(uri=uri):
                fetcher.validate_redirect_uri(uri)
        for uri in rejected:
            with self.subTest(uri=uri), self.assertRaises(fetcher.ModelFetchError):
                fetcher.validate_redirect_uri(uri)

    def test_partial_symlink_and_hardlink_are_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim.bin"
            victim.write_bytes(b"do-not-touch")
            destination = root / "model.bin"
            partial = root / ".model.bin.partial"
            artifact = fetcher.Artifact(
                name="model.bin",
                directory="onnx",
                uri=(
                    "https://huggingface.co/Supertone/supertonic-3/resolve/"
                    f"{fetcher.MODEL_REVISION}/onnx/model.bin"
                ),
                size=1,
                sha256=hashlib.sha256(b"x").hexdigest(),
            )

            try:
                partial.symlink_to(victim)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(fetcher.ModelFetchError):
                fetcher.download_artifact(artifact, destination)
            self.assertEqual(b"do-not-touch", victim.read_bytes())

            partial.unlink()
            try:
                os.link(victim, partial)
            except (NotImplementedError, OSError):
                self.skipTest("hardlinks are unavailable")
            with self.assertRaises(fetcher.ModelFetchError):
                fetcher.download_artifact(artifact, destination)
            self.assertEqual(b"do-not-touch", victim.read_bytes())

    def test_partial_swap_is_rejected_before_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim.bin"
            victim.write_bytes(b"do-not-truncate")
            partial = root / ".model.bin.partial"
            partial.write_bytes(b"original-partial")
            expected = fetcher.inspect_partial(partial)
            self.assertIsNotNone(expected)
            partial.unlink()
            try:
                os.link(victim, partial)
            except (NotImplementedError, OSError):
                self.skipTest("hardlinks are unavailable")

            with self.assertRaises(fetcher.ModelFetchError):
                fetcher.open_partial(partial, append=False, expected=expected)

            self.assertEqual(b"do-not-truncate", victim.read_bytes())


if __name__ == "__main__":
    unittest.main()
