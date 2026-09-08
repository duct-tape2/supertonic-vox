"""Read-only installation and localhost health diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PKGS = ROOT / "pkgs"
if str(PKGS) not in sys.path:
    sys.path.insert(0, str(PKGS))

REVISION = "bffb3df5a29440629464e5e839f4d214c8714c3d"
EXPECTED_FILES = {
    "model.safetensors": (
        4_580_080_592,
        "f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d",
    ),
    "audiovae.pth": (
        376_951_122,
        "94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1",
    ),
}
EXPECTED_PACKAGES = {
    "voxcpm": "2.0.3",
    "torch": "2.10.0+cpu",
    "torchaudio": "2.10.0+cpu",
    "torchcodec": "0.10.0",
    "transformers": "5.3.0",
    "fastapi": "0.135.1",
    "uvicorn": "0.42.0",
    "soundfile": "0.13.1",
}


class Report:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def passed(self, message: str) -> None:
        print(f"[PASS] {message}")

    def failed(self, message: str) -> None:
        self.failures += 1
        print(f"[FAIL] {message}")

    def warned(self, message: str) -> None:
        self.warnings += 1
        print(f"[WARN] {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_runtime(report: Report) -> None:
    actual_python = platform.python_version()
    if actual_python == "3.12.13":
        report.passed(f"CPython {actual_python}")
    else:
        report.failed(f"CPython 3.12.13 required; found {actual_python}")

    for package, expected in EXPECTED_PACKAGES.items():
        try:
            actual = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            report.failed(f"package missing: {package}=={expected}")
            continue
        if actual == expected:
            report.passed(f"{package}=={actual}")
        else:
            report.failed(f"{package} expected {expected}; found {actual}")

    if PKGS.is_dir():
        report.passed("portable pkgs directory exists")
    else:
        report.failed("portable pkgs directory is missing")


def check_presets(report: Report) -> None:
    path = ROOT / "voices" / "presets.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        profiles = data["profiles"]
        ids = {profile["id"] for profile in profiles}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        report.failed(f"preset configuration unreadable: {exc}")
        return
    expected = {"vox_news_f", "vox_calm_f", "vox_emotive_f", "vox_trust_m"}
    if data.get("schema_version") == 1 and ids == expected and data.get("default_profile_id") == "vox_news_f":
        report.passed("four voice-design presets and default profile")
    else:
        report.failed("preset IDs/default/schema do not match the release contract")


def check_model(report: Report, full_hash: bool) -> None:
    model_dir = ROOT / "models" / "VoxCPM2"
    for name, (expected_size, expected_hash) in EXPECTED_FILES.items():
        path = model_dir / name
        if not path.is_file():
            report.failed(f"model file missing: {name}")
            continue
        actual_size = path.stat().st_size
        if actual_size != expected_size:
            report.failed(f"model file size mismatch: {name} ({actual_size})")
            continue
        if full_hash:
            actual_hash = sha256(path)
            if actual_hash != expected_hash:
                report.failed(f"model SHA-256 mismatch: {name}")
                continue
            report.passed(f"model file hash: {name}")
        else:
            report.passed(f"model file size: {name}")


def check_manifest(report: Report) -> None:
    path = ROOT / "manifest.json"
    if not path.is_file():
        report.warned("manifest.json is not present (installer must create it)")
        return
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("engine") == "voxcpm2" and manifest.get("model", {}).get("revision") == REVISION:
            report.passed("manifest engine and model revision")
        else:
            report.failed("manifest engine or model revision mismatch")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        report.failed(f"manifest unreadable: {exc}")


def check_server(report: Report, port: int) -> None:
    token = os.environ.get("TTS_LOCAL_AUTH_TOKEN")
    if not token:
        report.failed("TTS_LOCAL_AUTH_TOKEN is required for the authenticated health check")
        return
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/health",
            headers={"X-Local-TTS-Token": token},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=5) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        report.failed(f"localhost health request failed: {exc}")
        return
    if (
        payload.get("engine") != "voxcpm2"
        or payload.get("model_revision") != REVISION
        or not payload.get("session_id")
    ):
        report.failed("localhost health fingerprint mismatch")
    elif payload.get("status") != "ready":
        report.failed(f"localhost server is not ready: {payload.get('model_files')}")
    else:
        report.passed(f"localhost server fingerprint and readiness on port {port}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose the portable VoxCPM2 runtime")
    parser.add_argument("--full-hash", action="store_true", help="hash the 4.9 GB required model payload")
    parser.add_argument("--server-port", type=int, choices=range(7800, 7811))
    args = parser.parse_args()

    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    report = Report()
    check_runtime(report)
    check_presets(report)
    check_model(report, args.full_hash)
    check_manifest(report)
    if args.server_port is not None:
        check_server(report, args.server_port)
    print(f"\nResult: failures={report.failures}, warnings={report.warnings}")
    return 1 if report.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
