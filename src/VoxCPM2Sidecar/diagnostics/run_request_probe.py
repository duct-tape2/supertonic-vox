from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import threading
import time
import urllib.request
import wave
from pathlib import Path

import psutil


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--port", type=int, default=7800)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--text", required=True)
    parser.add_argument("--mode", choices=("preset", "clone"), default="preset")
    parser.add_argument("--profile", default="vox_news_f")
    parser.add_argument("--reference")
    parser.add_argument("--steps", type=int, choices=(6, 8, 10), default=10)
    parser.add_argument("--token", default=os.environ.get("TTS_LOCAL_AUTH_TOKEN"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.token:
        raise SystemExit("Set TTS_LOCAL_AUTH_TOKEN or pass --token.")
    payload = {
        "text": args.text,
        "mode": args.mode,
        "profile_id": args.profile,
        "reference_wav_path": args.reference,
        "cfg_value": 2.0,
        "inference_timesteps": args.steps,
        "seed": 42,
        "response_format": "wav",
    }
    request = urllib.request.Request(
        f"http://127.0.0.1:{args.port}/v1/tts",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Local-TTS-Token": args.token,
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = psutil.Process(args.pid)
    result: dict[str, object] = {}
    completed = threading.Event()

    def send() -> None:
        try:
            with opener.open(request, timeout=1800) as response:
                result["status"] = response.status
                result["headers"] = dict(response.headers.items())
                result["body"] = response.read()
        except BaseException as exc:  # surfaced on the main thread below
            result["error"] = repr(exc)
        finally:
            completed.set()

    started = time.monotonic()
    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    max_rss = 0
    max_vms = 0
    max_peak_wset = 0
    samples = 0
    while not completed.wait(0.2):
        try:
            info = process.memory_info()
        except psutil.Error:
            break
        max_rss = max(max_rss, int(info.rss))
        max_vms = max(max_vms, int(info.vms))
        max_peak_wset = max(max_peak_wset, int(getattr(info, "peak_wset", info.rss)))
        samples += 1
    thread.join(timeout=1)
    elapsed = time.monotonic() - started

    if "error" in result:
        print(json.dumps({"elapsed_s": elapsed, **result}, ensure_ascii=False, indent=2))
        return 1
    body = result.pop("body")
    if not isinstance(body, bytes):
        raise RuntimeError("HTTP response body was not bytes")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(body)
    with wave.open(io.BytesIO(body), "rb") as wav:
        audio = {
            "channels": wav.getnchannels(),
            "sample_width_bytes": wav.getsampwidth(),
            "sample_rate": wav.getframerate(),
            "frames": wav.getnframes(),
            "duration_s": wav.getnframes() / wav.getframerate(),
        }
    summary = {
        "elapsed_s": round(elapsed, 3),
        "status": result["status"],
        "output": str(args.output),
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "audio": audio,
        "memory_samples": samples,
        "max_rss_gib": round(max_rss / 1024**3, 3),
        "max_vms_gib": round(max_vms / 1024**3, 3),
        "max_peak_working_set_gib": round(max_peak_wset / 1024**3, 3),
        "response_headers": result["headers"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
