from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--source-epoch", type=int, required=True)
    args = parser.parse_args()
    if args.source_epoch < 315_532_800:
        raise SystemExit("--source-epoch must be a Unix timestamp on or after 1980-01-01")
    root = args.root.resolve(strict=True)
    output = args.output.resolve()
    files = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file()
            and path.resolve() != output
            and ".git" not in path.relative_to(root).parts
        ),
        key=lambda path: (
            path.relative_to(root).as_posix().casefold(),
            path.relative_to(root).as_posix(),
        ),
    )

    def record(path: Path) -> dict[str, object]:
        relative = path.relative_to(root).as_posix()
        lower = relative.lower()
        critical = (
            lower.endswith((".exe", ".dll", ".py", ".pth", ".safetensors", ".onnx", ".lock"))
            or "/models/" in f"/{lower}"
            or lower.endswith("requirements.lock")
        )
        stat = path.stat()
        return {
            "path": relative,
            "size": stat.st_size,
            "sha256": sha256(path),
            "critical": critical,
        }

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        records = list(pool.map(record, files))
    payload = {
        "schema_version": 1,
        "algorithm": "SHA-256",
        "root_name": root.name,
        "created_utc": datetime.fromtimestamp(
            args.source_epoch,
            timezone.utc,
        ).isoformat().replace("+00:00", "Z"),
        "manifest_self_excluded": output.name,
        "file_count": len(records),
        "total_bytes": sum(int(item["size"]) for item in records),
        "files": records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as destination:
            json.dump(payload, destination, ensure_ascii=False, indent=2)
            destination.write("\n")
        os.replace(temporary_name, output)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    print(json.dumps({key: payload[key] for key in ("file_count", "total_bytes")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
