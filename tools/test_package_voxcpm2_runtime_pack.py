from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("package_voxcpm2_runtime_pack.py")
SPEC = importlib.util.spec_from_file_location("package_voxcpm2_runtime_pack", MODULE_PATH)
assert SPEC and SPEC.loader
packager = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = packager
SPEC.loader.exec_module(packager)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_pack(root: Path, config: bytes = b'{"fixture":true}\n') -> None:
    entrypoint = b"fixture entrypoint\n"
    files = [
        ("bin/fake-sidecar", entrypoint),
        ("config/engine.json", config),
    ]
    for relative, data in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {
        "schemaVersion": 1,
        "protocolVersion": 2,
        "engineId": "voxcpm2",
        "engineVersion": "2.0.3",
        "modelRevision": "bffb3df5a29440629464e5e839f4d214c8714c3d",
        "platform": "MacOS",
        "architecture": "Arm64",
        "backend": "Cpu",
        "entryPoint": "bin/fake-sidecar",
        "launchArguments": ["--fixture"],
        "prelaunchVerifyPaths": ["bin/fake-sidecar", "config/engine.json"],
        "files": [
            {"path": relative, "sizeBytes": len(data), "sha256": sha256(data)}
            for relative, data in files
        ],
    }
    (root / "runtime-pack.json").write_text(
        json.dumps(manifest, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


class RuntimePackPackagingTests(unittest.TestCase):
    def test_archive_and_catalog_metadata_are_deterministic_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_pack = root / "first" / "pack"
            second_pack = root / "second" / "pack"
            first_pack.mkdir(parents=True)
            second_pack.mkdir(parents=True)
            create_pack(first_pack)
            create_pack(second_pack)
            first_archive = root / "first" / "voxcpm2.svxpack.tar"
            second_archive = root / "second" / "voxcpm2.svxpack.tar"
            first_metadata = root / "first" / "artifact.json"
            second_metadata = root / "second" / "artifact.json"
            uri = "https://github.com/example/releases/download/v1/voxcpm2.svxpack.tar"

            first = packager.package(first_pack, first_archive, first_metadata, uri)
            second = packager.package(second_pack, second_archive, second_metadata, uri)

            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assertEqual(first, second)
            self.assertEqual(first_metadata.read_bytes(), second_metadata.read_bytes())
            self.assertEqual(first["downloadUri"], uri)
            self.assertEqual(first["kind"], "RuntimePackTar")
            self.assertEqual(first["runtimePack"]["archiveProfile"], "UstarV1")
            self.assertEqual(first["runtimePack"]["extractedFileCount"], 3)
            self.assertEqual(first["sha256"], packager.sha256_file(first_archive))
            self.assertEqual(first["sizeBytes"], first_archive.stat().st_size)
            self.assertTrue(first_archive.read_bytes().endswith(b"\0" * 1024))

    def test_tamper_unlisted_link_and_unsafe_url_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            create_pack(pack)
            (pack / "config" / "engine.json").write_bytes(b"tampered")
            with self.assertRaises(packager.PackageError):
                packager.package(pack, root / "a.svxpack.tar", root / "a.json", None)
            self.assertFalse((root / "a.svxpack.tar").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            create_pack(pack)
            (pack / "unexpected.bin").write_bytes(b"unexpected")
            with self.assertRaises(packager.PackageError):
                packager.package(pack, root / "a.svxpack.tar", root / "a.json", None)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            create_pack(pack)
            target = pack / "config" / "engine.json"
            target.unlink()
            target.symlink_to(pack / "bin" / "fake-sidecar")
            with self.assertRaises(packager.PackageError):
                packager.package(pack, root / "a.svxpack.tar", root / "a.json", None)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            create_pack(pack)
            with self.assertRaises(packager.PackageError):
                packager.package(
                    pack,
                    root / "a.svxpack.tar",
                    root / "a.json",
                    "https://evil.example/a.svxpack.tar",
                )

    def test_pack_root_symlink_hardlink_and_non_ascii_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            create_pack(pack)
            linked_root = root / "linked-pack"
            linked_root.symlink_to(pack, target_is_directory=True)
            with self.assertRaises(packager.PackageError):
                packager.package(linked_root, root / "a.svxpack.tar", root / "a.json", None)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            create_pack(pack)
            os.link(pack / "config" / "engine.json", root / "external-hardlink")
            with self.assertRaises(packager.PackageError):
                packager.package(pack, root / "a.svxpack.tar", root / "a.json", None)

        with self.assertRaises(packager.PackageError):
            packager.normalize_path("licenses/라이선스.txt")


if __name__ == "__main__":
    unittest.main()
