#!/usr/bin/env python3
"""Fetch the pinned public Supertonic 3 model into a clean verified cache."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


MODEL_REVISION = "3cadd1ee6394adea1bd021217a0e650ede09a323"
ENGINE_ID = "supertonic-3"
DEFAULT_CATALOG = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "CrossPlatform"
    / "SupertonicVox.Desktop"
    / "Assets"
    / "engine-catalog.json"
)
EXPECTED_LOCATIONS = {
    "duration_predictor.onnx": "onnx",
    "text_encoder.onnx": "onnx",
    "vector_estimator.onnx": "onnx",
    "vocoder.onnx": "onnx",
    "tts.json": "onnx",
    "unicode_indexer.json": "onnx",
    "M1.json": "voice_styles",
}
BUFFER_BYTES = 1024 * 1024


class ModelFetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Artifact:
    name: str
    directory: str
    uri: str
    size: int
    sha256: str


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(BUFFER_BYTES):
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        raise ModelFetchError(f"file-unreadable:{path.name}") from exc
    return digest.hexdigest(), total


def validate_initial_uri(uri: str, revision: str, name: str) -> None:
    parsed = urlparse(uri)
    expected_prefix = f"/Supertone/supertonic-3/resolve/{revision}/"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "huggingface.co"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(expected_prefix)
        or Path(parsed.path).name != name
    ):
        raise ModelFetchError(f"artifact-uri-invalid:{name}")


def validate_redirect_uri(uri: str) -> None:
    parsed = urlparse(uri)
    hostname = (parsed.hostname or "").lower()
    allowed = (
        hostname == "huggingface.co"
        or hostname.endswith(".huggingface.co")
        or hostname == "cdn.hf.co"
        or hostname.endswith(".cdn.hf.co")
        or hostname == "xethub.hf.co"
        or hostname.endswith(".xethub.hf.co")
    )
    if parsed.scheme != "https" or not allowed or parsed.username is not None or parsed.password is not None:
        raise ModelFetchError("artifact-redirect-invalid")


class SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        validate_redirect_uri(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_artifacts(catalog_path: Path) -> list[Artifact]:
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ModelFetchError("catalog-unavailable") from exc
    engines = catalog.get("engines")
    if not isinstance(engines, list):
        raise ModelFetchError("catalog-engines-invalid")
    matches = [engine for engine in engines if isinstance(engine, dict) and engine.get("id") == ENGINE_ID]
    if len(matches) != 1:
        raise ModelFetchError("catalog-supertonic-invalid")
    engine = matches[0]
    if engine.get("modelRevision") != MODEL_REVISION or engine.get("isBundled") is not True:
        raise ModelFetchError("catalog-model-revision-invalid")
    raw_artifacts = engine.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != len(EXPECTED_LOCATIONS):
        raise ModelFetchError("catalog-artifacts-invalid")

    artifacts: list[Artifact] = []
    seen: set[str] = set()
    for item in raw_artifacts:
        if not isinstance(item, dict):
            raise ModelFetchError("catalog-artifact-invalid")
        name = item.get("name")
        uri = item.get("downloadUri")
        size = item.get("sizeBytes")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or name not in EXPECTED_LOCATIONS
            or name in seen
            or not isinstance(uri, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ModelFetchError("catalog-artifact-invalid")
        validate_initial_uri(uri, MODEL_REVISION, name)
        seen.add(name)
        artifacts.append(Artifact(name, EXPECTED_LOCATIONS[name], uri, size, digest))
    if seen != set(EXPECTED_LOCATIONS):
        raise ModelFetchError("catalog-artifact-set-invalid")
    return sorted(artifacts, key=lambda artifact: (artifact.directory, artifact.name))


def verify_artifact(path: Path, artifact: Artifact) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    if path.stat().st_size != artifact.size:
        return False
    digest, size = sha256_file(path)
    return size == artifact.size and digest == artifact.sha256


def inspect_partial(path: Path) -> os.stat_result | None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ModelFetchError(f"partial-unreadable:{path.name}") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ModelFetchError(f"partial-file-invalid:{path.name}")
    return details


def open_partial(path: Path, append: bool, expected: os.stat_result | None):
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    if expected is None:
        flags |= os.O_CREAT | os.O_EXCL
    elif append:
        flags |= os.O_APPEND
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ModelFetchError(f"partial-open-failed:{path.name}") from exc
    try:
        actual = os.fstat(descriptor)
        if (
            not stat.S_ISREG(actual.st_mode)
            or actual.st_nlink != 1
            or (
                expected is not None
                and (actual.st_dev != expected.st_dev or actual.st_ino != expected.st_ino)
            )
        ):
            raise ModelFetchError(f"partial-file-invalid:{path.name}")
        if expected is not None and not append:
            os.ftruncate(descriptor, 0)
        return os.fdopen(descriptor, "ab" if append else "wb")
    except Exception:
        os.close(descriptor)
        raise


def download_artifact(artifact: Artifact, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(f".{destination.name}.partial")
    partial_details = inspect_partial(partial)
    starting_size = partial_details.st_size if partial_details is not None else 0
    if starting_size > artifact.size:
        raise ModelFetchError(f"partial-size-invalid:{artifact.name}")

    headers = {"User-Agent": "SupertonicVox-release-builder/1"}
    if starting_size:
        headers["Range"] = f"bytes={starting_size}-"
    request = Request(artifact.uri, headers=headers)
    opener = build_opener(SafeRedirectHandler())
    try:
        response = opener.open(request, timeout=60)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ModelFetchError(f"download-failed:{artifact.name}") from exc

    status = getattr(response, "status", response.getcode())
    append = starting_size > 0 and status == 206
    if append:
        content_range = response.headers.get("Content-Range", "")
        if not content_range.startswith(f"bytes {starting_size}-"):
            response.close()
            raise ModelFetchError(f"download-range-invalid:{artifact.name}")
    elif starting_size:
        starting_size = 0

    total = starting_size
    try:
        with response:
            with open_partial(partial, append, partial_details) as stream:
                while chunk := response.read(BUFFER_BYTES):
                    total += len(chunk)
                    if total > artifact.size:
                        raise ModelFetchError(f"download-size-invalid:{artifact.name}")
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        raise ModelFetchError(f"download-write-failed:{artifact.name}") from exc
    if total != artifact.size:
        raise ModelFetchError(f"download-size-invalid:{artifact.name}")
    digest, size = sha256_file(partial)
    if size != artifact.size or digest != artifact.sha256:
        raise ModelFetchError(f"download-hash-invalid:{artifact.name}")
    os.replace(partial, destination)


def materialize(artifacts: list[Artifact], destination: Path, offline: bool) -> list[dict[str, object]]:
    report: list[dict[str, object]] = []
    for artifact in artifacts:
        target = destination / artifact.directory / artifact.name
        if not verify_artifact(target, artifact):
            if offline:
                raise ModelFetchError(f"artifact-missing-or-invalid:{artifact.name}")
            download_artifact(artifact, target)
        if not verify_artifact(target, artifact):
            raise ModelFetchError(f"artifact-verification-failed:{artifact.name}")
        report.append(
            {
                "path": f"{artifact.directory}/{artifact.name}",
                "sizeBytes": artifact.size,
                "sha256": artifact.sha256,
            }
        )
    return report


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise ModelFetchError("report-unwritable") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        destination = args.destination.resolve()
        report_path = args.report.resolve()
        if report_path == destination or destination in report_path.parents:
            raise ModelFetchError("report-inside-destination")
        artifacts = load_artifacts(args.catalog.resolve())
        verified = materialize(artifacts, destination, args.offline)
        result = {
            "schemaVersion": 1,
            "engineId": ENGINE_ID,
            "modelRevision": MODEL_REVISION,
            "artifactCount": len(verified),
            "artifacts": verified,
        }
        write_json_atomic(report_path, result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except ModelFetchError as exc:
        print(json.dumps({"modelFetchError": str(exc)}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
