from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import urllib.error
import urllib.request
import wave
from pathlib import Path


def request(opener, url: str, token: str, data: bytes | None = None):
    headers = {"X-Local-TTS-Token": token}
    method = "GET"
    if data is not None:
        headers["Content-Type"] = "application/json"
        method = "POST"
    return opener.open(
        urllib.request.Request(url, data=data, headers=headers, method=method),
        timeout=1800,
    )


def read_bounded(response, limit: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length and int(length) > limit:
        raise RuntimeError(f"declared response exceeds {limit} bytes")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(128 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError(f"streamed response exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def expect_http_error(
    opener,
    url: str,
    token: str,
    expected_status: int,
    data: bytes | None = None,
) -> None:
    try:
        with request(opener, url, token, data=data) as response:
            response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        try:
            if exc.code != expected_status:
                raise RuntimeError(f"expected HTTP {expected_status}, got {exc.code}: {url}") from exc
            return
        finally:
            exc.close()
    raise RuntimeError(f"expected HTTP {expected_status}, request succeeded: {url}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=("supertonic", "voxcpm2"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token", default=os.environ.get("TTS_LOCAL_AUTH_TOKEN", ""))
    parser.add_argument("--session", default=os.environ.get("TTS_LOCAL_SESSION_ID", ""))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.token) < 64:
        raise RuntimeError("a 256-bit local token is required via environment or --token")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{args.port}"
    wrong_token = "0" * 64 if args.token != "0" * 64 else "1" * 64
    expect_http_error(opener, base + "/v1/health", wrong_token, 401)
    expect_http_error(opener, base + "/docs", args.token, 404)
    request_limit = 256 * 1024 if args.engine == "supertonic" else 16 * 1024
    oversized_body = b'{"text":"' + (b"a" * request_limit) + b'"}'
    expect_http_error(opener, base + "/v1/tts", args.token, 413, data=oversized_body)
    with request(opener, base + "/v1/health", args.token) as response:
        health = json.load(response)
    if health.get("status") != "ready" or health.get("engine") != args.engine:
        raise RuntimeError(f"health fingerprint failed: {health}")

    expected_revision = {
        "supertonic": "0d6a2bed57a1c6ec4f7acf77d688c62337655dd1db2a5582b2b2d55c17f5efae",
        "voxcpm2": "bffb3df5a29440629464e5e839f4d214c8714c3d",
    }[args.engine]
    if health.get("model_revision") != expected_revision:
        raise RuntimeError("health model revision mismatch")
    if args.session and health.get("session_id") != args.session:
        raise RuntimeError("health session fingerprint mismatch")
    if args.engine == "voxcpm2" and health.get("model_loaded") is not True:
        raise RuntimeError("VoxCPM2 health did not confirm a loaded model")

    if args.engine == "supertonic":
        payload = {
            "text": "안녕하세요. 오프라인 보안 점검 음성입니다.",
            "voice": "F1",
            "lang": "ko",
            "steps": 10,
            "speed": 1.0,
            "max_chunk_length": 300,
            "silence_duration": 0.2,
            "response_format": "wav",
        }
        limit = 512 * 1024 * 1024
        expected_sample_rate = 44_100
    else:
        payload = {
            "text": "안녕하세요. 오프라인 보안 점검 음성입니다.",
            "mode": "preset",
            "profile_id": "vox_news_f",
            "reference_wav_path": None,
            "cfg_value": 2.0,
            "inference_timesteps": 6,
            "seed": 42,
            "response_format": "wav",
        }
        limit = 128 * 1024 * 1024
        expected_sample_rate = 48_000

    encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    with request(opener, base + "/v1/tts", args.token, encoded) as response:
        body = read_bounded(response, limit)
    with wave.open(io.BytesIO(body), "rb") as wav:
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        sample_rate = wav.getframerate()
        frames = wav.getnframes()
    duration = frames / sample_rate
    if channels != 1 or sample_width != 2 or sample_rate != expected_sample_rate:
        raise RuntimeError("unexpected WAV format")
    if not 0.05 <= duration <= 120:
        raise RuntimeError("unexpected WAV duration")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(body)
    print(
        json.dumps(
            {
                "engine": args.engine,
                "health": health,
                "output": str(args.output),
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "channels": channels,
                "sample_width": sample_width,
                "sample_rate": sample_rate,
                "duration_seconds": round(duration, 3),
                "security_checks": {
                    "wrong_token_status": 401,
                    "hidden_docs_status": 404,
                    "oversized_request_status": 413,
                    "revision_match": True,
                    "session_match": not args.session or health.get("session_id") == args.session,
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
