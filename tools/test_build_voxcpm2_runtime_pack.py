from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_voxcpm2_runtime_pack.py")
SPEC = importlib.util.spec_from_file_location("build_voxcpm2_runtime_pack", MODULE_PATH)
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


def write(path: Path, content: bytes = b"fixture\n", executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PackFixture:
    def __init__(self, root: Path, platform: str = "macos", backend: str = "cpu") -> None:
        self.root = root
        self.source = root / "source"
        self.runtime = root / "runtime"
        self.packages = root / "packages"
        self.model = root / "model"
        self.license = root / "LICENSE.txt"
        self.destination = root / "voxcpm2.partial"
        self.model_contract = {
            "model.safetensors": builder.ModelAsset(11, hashlib.sha256(b"model-data\n").hexdigest()),
            "audiovae.pth": builder.ModelAsset(9, hashlib.sha256(b"vae-data\n").hexdigest()),
        }
        for relative in builder.SOURCE_FILES:
            content = b"fixture\n"
            if relative.endswith("voxcpm2-model-provenance.json"):
                content = json.dumps({"revision": builder.MODEL_REVISION}).encode()
            elif relative == "requirements.lock":
                content = b"psutil==5.9.8\n"
            write(self.source / relative, content)
        if platform == "macos":
            write(self.runtime / "bin" / "python3", b"python\n", executable=True)
        else:
            write(self.runtime / "python.exe", b"python\n")
        write(self.runtime / "python-runtime.txt")
        write(self.packages / "psutil" / "__init__.py", b"__version__='5.9.8'\n")
        write(self.packages / "psutil" / "py.typed", b"")
        write(self.packages / "psutil-5.9.8.dist-info" / "METADATA", b"Name: psutil\nVersion: 5.9.8\n")
        for relative in builder.MODEL_SUPPORT_FILES:
            write(self.model / relative)
        write(self.model / "model.safetensors", b"model-data\n")
        write(self.model / "audiovae.pth", b"vae-data\n")
        write(self.license, b"Approved fixture license\n")
        self.options = builder.BuildOptions(
            platform=platform,
            architecture="arm64" if platform == "macos" else "x64",
            backend=backend,
            source_root=self.source,
            python_runtime=self.runtime,
            site_packages=self.packages,
            model_root=self.model,
            license_files=(self.license,),
            destination=self.destination,
        )


class RuntimePackBuilderTests(unittest.TestCase):
    def test_manifest_limit_is_exactly_eight_mib_and_activation_is_atomic(self):
        self.assertEqual(builder.MAXIMUM_MANIFEST_BYTES, 8 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            original = builder.MAXIMUM_MANIFEST_BYTES
            try:
                builder.MAXIMUM_MANIFEST_BYTES = 1
                with self.assertRaises(builder.PackBuildError):
                    builder.build_pack(fixture.options, model_contract=fixture.model_contract)
            finally:
                builder.MAXIMUM_MANIFEST_BYTES = original
            self.assertFalse(fixture.destination.exists())
            self.assertEqual(list(fixture.root.glob("*.building-*")), [])

    def test_cli_source_root_is_fixed_to_reviewed_repository_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("runtime", "packages", "model"):
                (root / name).mkdir()
            license_file = root / "LICENSE.txt"
            write(license_file)
            options = builder.parse_args(
                [
                    "--platform", "macos",
                    "--architecture", "arm64",
                    "--backend", "cpu",
                    "--python-runtime", str(root / "runtime"),
                    "--site-packages", str(root / "packages"),
                    "--model-root", str(root / "model"),
                    "--license-file", str(license_file),
                    "--destination", str(root / "pack.partial"),
                ]
            )
            self.assertEqual(options.source_root, builder.PRODUCTION_SOURCE_ROOT.resolve())

    def test_build_is_deterministic_and_protocol_v2_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = PackFixture(root / "first")
            second = PackFixture(root / "second")
            manifest_one = builder.build_pack(first.options, model_contract=first.model_contract)
            manifest_two = builder.build_pack(second.options, model_contract=second.model_contract)
            self.assertEqual(manifest_one, manifest_two)
            self.assertEqual((manifest_one["schemaVersion"], manifest_one["protocolVersion"]), (1, 2))
            self.assertEqual(manifest_one["entryPoint"], "python/bin/python3")
            paths = [item["path"] for item in manifest_one["files"]]
            self.assertIn("pkgs/psutil/__init__.py", paths)
            empty = next(item for item in manifest_one["files"] if item["path"] == "pkgs/psutil/py.typed")
            self.assertEqual(empty["sizeBytes"], 0)
            self.assertEqual(empty["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            self.assertIn("models/VoxCPM2/model.safetensors", manifest_one["prelaunchVerifyPaths"])
            disk_manifest = json.loads((first.destination / "runtime-pack.json").read_text())
            self.assertEqual(disk_manifest, manifest_one)

    def test_windows_entrypoint_and_backend_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary), platform="windows", backend="cuda")
            manifest = builder.build_pack(fixture.options, model_contract=fixture.model_contract)
            self.assertEqual((manifest["platform"], manifest["architecture"], manifest["backend"]), ("Windows", "X64", "Cuda"))
            self.assertEqual(manifest["entryPoint"], "python/python.exe")

    def test_model_tamper_and_unexpected_file_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            (fixture.model / "model.safetensors").write_bytes(b"tampered\n")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)

    def test_empty_critical_source_model_and_license_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            (fixture.source / "app" / "server_v2.py").write_bytes(b"")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            (fixture.model / "config.json").write_bytes(b"")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            fixture.license.write_bytes(b"")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            write(fixture.model / "unexpected.bin")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)

    def test_link_hardlink_private_path_and_collision_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            (fixture.runtime / "linked").symlink_to(fixture.runtime / "python-runtime.txt")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            os.link(fixture.runtime / "python-runtime.txt", fixture.runtime / "second.txt")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            write(fixture.packages / "cache" / "secret.bin")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with self.assertRaises(builder.PackBuildError):
            builder.ensure_no_path_collisions(["pkgs/Thing.txt", "pkgs/thing.txt"])
        with self.assertRaises(builder.PackBuildError):
            builder.ensure_no_path_collisions(["pkgs/bad\nname.py"])

    def test_missing_psutil_invalid_matrix_destination_and_overwrite_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            for path in sorted((fixture.packages / "psutil").rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
            (fixture.packages / "psutil").rmdir()
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary), platform="windows", backend="mps")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            bad = builder.BuildOptions(**{**fixture.options.__dict__, "destination": fixture.root / "pack"})
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(bad, model_contract=fixture.model_contract)
            fixture.destination.mkdir()
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)

    def test_dependency_lock_rejects_wrong_missing_and_unexpected_distributions(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            write(fixture.packages / "extra-1.0.dist-info" / "METADATA", b"Name: extra\nVersion: 1.0\n")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            (fixture.packages / "psutil-5.9.8.dist-info" / "METADATA").write_bytes(
                b"Name: psutil\nVersion: 5.9.7\n"
            )
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PackFixture(Path(temporary))
            (fixture.source / "requirements.lock").write_text("psutil>=5.9.8\n")
            with self.assertRaises(builder.PackBuildError):
                builder.build_pack(fixture.options, model_contract=fixture.model_contract)


if __name__ == "__main__":
    unittest.main()
