#!/usr/bin/env python3
"""Build a deterministic VoxCPM2 protocol-v2 runtime pack without networking.

The command consumes already-prepared, licensed native runtime inputs.  It
never downloads packages or models and never mutates an activated pack.
"""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import os
import shutil
import stat
import sys
import unicodedata
import uuid
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


ENGINE_ID = "voxcpm2"
ENGINE_VERSION = "2.0.3"
MODEL_REVISION = "bffb3df5a29440629464e5e839f4d214c8714c3d"
PRODUCTION_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "VoxCPM2Sidecar"
MAXIMUM_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAXIMUM_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAXIMUM_FILES = 50_000
MAXIMUM_MANIFEST_BYTES = 8 * 1024 * 1024
FORBIDDEN_PARTS = {
    "cache",
    "generatedaudio",
    "logs",
    "savedtext",
    "settings",
    "user",
    "voiceprofiles",
    "voicesamples",
    "__pycache__",
}
SOURCE_FILES = (
    "app/protocol_v2.py",
    "app/server_v2.py",
    "app/voxcpm_low_memory.py",
    "requirements.lock",
    "tools/voxcpm2-model-provenance.json",
    "voices/presets.json",
)
MODEL_SUPPORT_FILES = (
    "config.json",
    "special_tokens_map.json",
    "tokenization_voxcpm2.py",
    "tokenizer.json",
    "tokenizer_config.json",
)


class PackBuildError(RuntimeError):
    pass


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


@dataclass(frozen=True)
class ModelAsset:
    size: int
    sha256: str


PRODUCTION_MODEL_ASSETS: Mapping[str, ModelAsset] = {
    "model.safetensors": ModelAsset(
        4_580_080_592,
        "f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d",
    ),
    "audiovae.pth": ModelAsset(
        376_951_122,
        "94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1",
    ),
}


@dataclass(frozen=True)
class BuildOptions:
    platform: str
    architecture: str
    backend: str
    source_root: Path
    python_runtime: Path
    site_packages: Path
    model_root: Path
    license_files: tuple[Path, ...]
    destination: Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def normalize_relative(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise PackBuildError(f"control character in pack path: {value!r}")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackBuildError(f"unsafe pack path: {value}")
    normalized = path.as_posix()
    if any(part.casefold() in FORBIDDEN_PARTS for part in path.parts):
        raise PackBuildError(f"private or mutable pack path: {value}")
    return normalized


def require_regular_source(path: Path, label: str, *, allow_empty: bool = False) -> os.stat_result:
    if not os.path.lexists(path):
        raise PackBuildError(f"missing input: {label}")
    metadata = path.lstat()
    if _is_link_or_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise PackBuildError(f"linked or special input: {label}")
    if metadata.st_nlink != 1:
        raise PackBuildError(f"hard-linked input: {label}")
    if (metadata.st_size == 0 and not allow_empty) or metadata.st_size > MAXIMUM_FILE_BYTES:
        raise PackBuildError(f"empty or oversized input: {label}")
    return metadata


def walk_regular_files(root: Path, label: str, *, allow_empty: bool = False) -> list[Path]:
    if not root.is_absolute() or not root.exists() or not root.is_dir() or _is_link_or_reparse(root.lstat()):
        raise PackBuildError(f"{label} must be an existing absolute regular directory")
    files: list[Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            if _is_link_or_reparse(child.lstat()):
                raise PackBuildError(f"linked directory in {label}: {child.relative_to(root)}")
            normalize_relative(child.relative_to(root).as_posix())
        for name in filenames:
            child = directory_path / name
            normalize_relative(child.relative_to(root).as_posix())
            require_regular_source(
                child,
                f"{label}/{child.relative_to(root)}",
                allow_empty=allow_empty,
            )
            files.append(child)
    return sorted(files, key=lambda path: stable_key(path.relative_to(root).as_posix()))


def ensure_no_path_collisions(paths: Iterable[str]) -> None:
    seen: dict[str, str] = {}
    for path in paths:
        normalized = normalize_relative(path)
        key = stable_key(normalized)
        if key in seen and seen[key] != normalized:
            raise PackBuildError(f"case or Unicode path collision: {seen[key]} / {normalized}")
        seen[key] = normalized


def copy_file(source: Path, destination_root: Path, relative: str, *, allow_empty: bool = False) -> None:
    normalized = normalize_relative(relative)
    require_regular_source(source, normalized, allow_empty=allow_empty)
    destination = destination_root.joinpath(*PurePosixPath(normalized).parts)
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    shutil.copystat(source, destination, follow_symlinks=False)


def _require_model_contract(model_root: Path, contract: Mapping[str, ModelAsset]) -> None:
    expected = set(MODEL_SUPPORT_FILES) | set(contract)
    actual = {path.relative_to(model_root).as_posix() for path in walk_regular_files(model_root, "model")}
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise PackBuildError(f"model inventory mismatch missing={missing} unexpected={unexpected}")
    for name, asset in contract.items():
        path = model_root / name
        metadata = require_regular_source(path, f"model/{name}")
        if metadata.st_size != asset.size or sha256_file(path) != asset.sha256:
            raise PackBuildError(f"model asset integrity mismatch: {name}")


def _validate_provenance(source_root: Path) -> None:
    path = source_root / "tools" / "voxcpm2-model-provenance.json"
    require_regular_source(path, "model provenance")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackBuildError("model provenance is invalid") from exc
    encoded = json.dumps(document, sort_keys=True)
    if MODEL_REVISION not in encoded:
        raise PackBuildError("model provenance does not bind the production revision")


def _canonical_distribution_name(value: str) -> str:
    canonical = re.sub(r"[-_.]+", "-", value).lower()
    if not canonical or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", canonical) is None:
        raise PackBuildError(f"invalid Python distribution name: {value}")
    return canonical


def _locked_distributions(requirements_lock: Path) -> dict[str, str]:
    require_regular_source(requirements_lock, "requirements.lock")
    locked: dict[str, str] = {}
    for line_number, raw in enumerate(requirements_lock.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;]+)", line)
        if match is None:
            raise PackBuildError(f"unsupported requirements.lock line {line_number}")
        name = _canonical_distribution_name(match.group(1))
        version = match.group(2)
        if name in locked:
            raise PackBuildError(f"duplicate locked distribution: {name}")
        locked[name] = version
    if not locked:
        raise PackBuildError("requirements.lock contains no pinned distributions")
    return locked


def _installed_distributions(site_packages: Path) -> dict[str, str]:
    installed: dict[str, str] = {}
    metadata_paths = sorted(site_packages.glob("*.dist-info/METADATA"), key=lambda path: stable_key(path.as_posix()))
    if not metadata_paths:
        raise PackBuildError("site-packages contains no distribution metadata")
    parser = email.parser.Parser()
    for metadata_path in metadata_paths:
        require_regular_source(metadata_path, f"distribution metadata/{metadata_path.parent.name}")
        try:
            document = parser.parsestr(metadata_path.read_text(encoding="utf-8"), headersonly=True)
        except (OSError, UnicodeError) as exc:
            raise PackBuildError(f"distribution metadata is unreadable: {metadata_path.parent.name}") from exc
        raw_name = document.get("Name", "")
        version = document.get("Version", "")
        name = _canonical_distribution_name(raw_name)
        if not version or any(character.isspace() for character in version):
            raise PackBuildError(f"distribution version is invalid: {raw_name}")
        if name in installed:
            raise PackBuildError(f"duplicate installed distribution: {name}")
        installed[name] = version
    return installed


def _validate_dependency_lock(source_root: Path, site_packages: Path) -> None:
    locked = _locked_distributions(source_root / "requirements.lock")
    installed = _installed_distributions(site_packages)
    if installed != locked:
        missing = sorted(set(locked) - set(installed))
        unexpected = sorted(set(installed) - set(locked))
        mismatched = sorted(
            name for name in set(installed) & set(locked) if installed[name] != locked[name]
        )
        raise PackBuildError(
            f"dependency lock mismatch missing={missing} unexpected={unexpected} version={mismatched}"
        )


def _validate_runtime_inputs(options: BuildOptions, model_contract: Mapping[str, ModelAsset]) -> tuple[str, str]:
    platform_values = {"windows": "Windows", "macos": "MacOS"}
    architecture_values = {"x64": "X64", "arm64": "Arm64"}
    backend_values = {"cpu": "Cpu", "cuda": "Cuda", "mps": "Mps"}
    if options.platform not in platform_values or options.architecture not in architecture_values:
        raise PackBuildError("platform or architecture is unsupported")
    if options.backend not in backend_values:
        raise PackBuildError("backend is unsupported")
    if options.platform == "windows" and options.architecture != "x64":
        raise PackBuildError("v1 Windows packs are x64 only")
    if options.platform == "macos" and options.architecture != "arm64":
        raise PackBuildError("v1 macOS packs are arm64 only")
    if options.platform == "windows" and options.backend == "mps":
        raise PackBuildError("MPS is macOS-only")
    if options.platform == "macos" and options.backend == "cuda":
        raise PackBuildError("CUDA is Windows-only")
    if options.destination.suffix != ".partial" or options.destination.exists() or os.path.lexists(options.destination):
        raise PackBuildError("destination must be a new path ending in .partial")
    if not options.destination.is_absolute():
        raise PackBuildError("destination must be absolute")
    if not options.license_files:
        raise PackBuildError("at least one approved external license file is required")
    for license_file in options.license_files:
        require_regular_source(license_file, f"license/{license_file.name}")
    _validate_provenance(options.source_root)
    _require_model_contract(options.model_root, model_contract)
    _validate_dependency_lock(options.source_root, options.site_packages)

    runtime_files = walk_regular_files(options.python_runtime, "python runtime", allow_empty=True)
    package_files = walk_regular_files(options.site_packages, "site-packages", allow_empty=True)
    package_relatives = [path.relative_to(options.site_packages).as_posix() for path in package_files]
    if not any(relative == "psutil/__init__.py" for relative in package_relatives):
        raise PackBuildError("site-packages does not contain pinned psutil")
    if not any(relative.startswith("psutil-5.9.8.dist-info/") for relative in package_relatives):
        raise PackBuildError("site-packages does not contain psutil==5.9.8 metadata")
    entrypoint = "python/python.exe" if options.platform == "windows" else "python/bin/python3"
    runtime_relatives = {f"python/{path.relative_to(options.python_runtime).as_posix()}" for path in runtime_files}
    if entrypoint not in runtime_relatives:
        raise PackBuildError(f"portable Python entrypoint is missing: {entrypoint}")
    if options.platform == "macos":
        executable = options.python_runtime / "bin" / "python3"
        if not executable.stat().st_mode & stat.S_IXUSR:
            raise PackBuildError("macOS portable Python entrypoint is not executable")
    return entrypoint, backend_values[options.backend]


def build_pack(
    options: BuildOptions,
    *,
    model_contract: Mapping[str, ModelAsset] = PRODUCTION_MODEL_ASSETS,
) -> dict[str, object]:
    entrypoint, backend_value = _validate_runtime_inputs(options, model_contract)
    building = options.destination.with_name(f"{options.destination.name}.building-{os.getpid()}-{uuid.uuid4().hex}")
    if building.exists() or os.path.lexists(building):
        raise PackBuildError("temporary build path already exists")
    building.mkdir(mode=0o700, parents=False)
    try:
        planned: list[tuple[Path, str, bool]] = []
        for relative in SOURCE_FILES:
            planned.append((options.source_root / relative, relative, False))
        for path in walk_regular_files(options.python_runtime, "python runtime", allow_empty=True):
            planned.append((path, f"python/{path.relative_to(options.python_runtime).as_posix()}", True))
        for path in walk_regular_files(options.site_packages, "site-packages", allow_empty=True):
            planned.append((path, f"pkgs/{path.relative_to(options.site_packages).as_posix()}", True))
        for name in (*MODEL_SUPPORT_FILES, *model_contract.keys()):
            planned.append((options.model_root / name, f"models/VoxCPM2/{name}", False))
        license_names: set[str] = set()
        for license_file in options.license_files:
            name = unicodedata.normalize("NFC", license_file.name)
            key = stable_key(name)
            if key in license_names:
                raise PackBuildError(f"duplicate license filename: {name}")
            license_names.add(key)
            planned.append((license_file, f"licenses/{name}", False))
        ensure_no_path_collisions(relative for _, relative, _ in planned)
        if len(planned) > MAXIMUM_FILES:
            raise PackBuildError("runtime pack contains too many files")
        for source, relative, allow_empty in planned:
            copy_file(source, building, relative, allow_empty=allow_empty)

        inventory = []
        total = 0
        for path in walk_regular_files(building, "staged pack", allow_empty=True):
            relative = path.relative_to(building).as_posix()
            size = path.stat().st_size
            total += size
            inventory.append({"path": relative, "sizeBytes": size, "sha256": sha256_file(path)})
        if total > MAXIMUM_TOTAL_BYTES:
            raise PackBuildError("runtime pack exceeds 16 GiB")
        inventory.sort(key=lambda item: stable_key(str(item["path"])))
        critical = [
            entrypoint,
            "app/server_v2.py",
            "app/protocol_v2.py",
            "requirements.lock",
            "voices/presets.json",
            "models/VoxCPM2/config.json",
            "models/VoxCPM2/model.safetensors",
            "models/VoxCPM2/audiovae.pth",
            "tools/voxcpm2-model-provenance.json",
            *sorted((f"licenses/{path.name}" for path in options.license_files), key=stable_key),
        ]
        manifest: dict[str, object] = {
            "schemaVersion": 1,
            "protocolVersion": 2,
            "engineId": ENGINE_ID,
            "engineVersion": ENGINE_VERSION,
            "modelRevision": MODEL_REVISION,
            "platform": {"windows": "Windows", "macos": "MacOS"}[options.platform],
            "architecture": {"x64": "X64", "arm64": "Arm64"}[options.architecture],
            "backend": backend_value,
            "entryPoint": entrypoint,
            "launchArguments": ["app/server_v2.py"],
            "prelaunchVerifyPaths": critical,
            "files": inventory,
        }
        declared = {item["path"] for item in inventory}
        if not set(critical).issubset(declared):
            raise PackBuildError("critical prelaunch inventory is incomplete")
        manifest_path = building / "runtime-pack.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        if manifest_path.stat().st_size > MAXIMUM_MANIFEST_BYTES:
            raise PackBuildError("runtime pack manifest exceeds 8 MiB")
        os.replace(building, options.destination)
        return manifest
    except Exception:
        shutil.rmtree(building, ignore_errors=True)
        raise


def parse_args(argv: Sequence[str]) -> BuildOptions:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=("windows", "macos"))
    parser.add_argument("--architecture", required=True, choices=("x64", "arm64"))
    parser.add_argument("--backend", required=True, choices=("cpu", "cuda", "mps"))
    parser.add_argument("--python-runtime", required=True, type=Path)
    parser.add_argument("--site-packages", required=True, type=Path)
    parser.add_argument("--model-root", required=True, type=Path)
    parser.add_argument("--license-file", required=True, action="append", type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args(argv)
    return BuildOptions(
        platform=args.platform,
        architecture=args.architecture,
        backend=args.backend,
        source_root=PRODUCTION_SOURCE_ROOT.resolve(),
        python_runtime=args.python_runtime.resolve(),
        site_packages=args.site_packages.resolve(),
        model_root=args.model_root.resolve(),
        license_files=tuple(path.resolve() for path in args.license_file),
        destination=args.destination.absolute(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    options = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        manifest = build_pack(options)
    except (OSError, PackBuildError) as exc:
        print(f"runtime-pack build failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "destination": str(options.destination),
        "files": len(manifest["files"]),
        "modelRevision": MODEL_REVISION,
        "backend": manifest["backend"],
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
