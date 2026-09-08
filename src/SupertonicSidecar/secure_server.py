"""Authenticated loopback-only wrapper for the bundled Supertonic server."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import secrets
from typing import Any, Awaitable, Callable

import uvicorn
from supertonic.server import create_app


AUTH_TOKEN = os.environ.get("TTS_LOCAL_AUTH_TOKEN", "")
SESSION_ID = os.environ.get("TTS_LOCAL_SESSION_ID", "")
MODEL_REVISION = os.environ.get("TTS_LOCAL_MODEL_REVISION", "")
ENGINE_VERSION = importlib.metadata.version("supertonic")
MAX_REQUEST_BYTES = 256 * 1024
ALLOWED_REQUESTS = {
    ("GET", "/v1/health"),
    ("POST", "/v1/tts"),
}

AsgiReceive = Callable[[], Awaitable[dict[str, Any]]]
AsgiSend = Callable[[dict[str, Any]], Awaitable[None]]


async def _send_json(send: AsgiSend, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-local-tts-session", SESSION_ID.encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class LocalSecurityMiddleware:
    def __init__(self, app: Callable[..., Awaitable[None]]):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: AsgiReceive, send: AsgiSend) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        host = headers.get(b"host", b"").decode("latin-1").split(":", 1)[0].lower()
        if host not in {"127.0.0.1", "localhost"}:
            await _send_json(send, 400, {"error": {"code": "invalid_host", "message": "loopback host required"}})
            return

        path = str(scope.get("path", ""))
        method = str(scope.get("method", "")).upper()
        if (method, path) not in ALLOWED_REQUESTS:
            await _send_json(send, 404, {"error": {"code": "not_found", "message": "route not available"}})
            return

        supplied = headers.get(b"x-local-tts-token", b"").decode("ascii", errors="ignore")
        if not AUTH_TOKEN or not secrets.compare_digest(supplied, AUTH_TOKEN):
            await _send_json(send, 401, {"error": {"code": "unauthorized", "message": "local token required"}})
            return

        declared = headers.get(b"content-length")
        if declared:
            try:
                if int(declared) > MAX_REQUEST_BYTES:
                    await _send_json(send, 413, {"error": {"code": "request_too_large", "message": "request too large"}})
                    return
            except ValueError:
                await _send_json(send, 400, {"error": {"code": "invalid_content_length", "message": "invalid content length"}})
                return

        request_body = bytearray()
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                continue
            request_body.extend(message.get("body", b""))
            if len(request_body) > MAX_REQUEST_BYTES:
                await _send_json(send, 413, {"error": {"code": "request_too_large", "message": "request too large"}})
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": bytes(request_body), "more_body": False}

        if path == "/v1/health":
            response_start: dict[str, Any] | None = None
            response_body = bytearray()

            async def capture_send(message: dict[str, Any]) -> None:
                nonlocal response_start
                if message["type"] == "http.response.start":
                    response_start = message
                elif message["type"] == "http.response.body":
                    response_body.extend(message.get("body", b""))

            await self.app(scope, replay_receive, capture_send)
            try:
                payload = json.loads(response_body.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                payload = {}
            payload.update(
                {
                    "engine": "supertonic",
                    "engine_version": ENGINE_VERSION,
                    "model": "supertonic-3",
                    "model_revision": MODEL_REVISION,
                    "session_id": SESSION_ID,
                    "status": "ready" if (response_start or {}).get("status") == 200 else "unavailable",
                }
            )
            await _send_json(send, int((response_start or {}).get("status", 503)), payload)
            return

        async def secured_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-local-tts-session", SESSION_ID.encode("ascii")),
                    (b"x-local-tts-engine", b"supertonic"),
                ]
            await send(message)

        await self.app(scope, replay_receive, secured_send)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated Supertonic loopback server")
    parser.add_argument("--port", type=int, choices=range(7788, 7799), required=True)
    return parser.parse_args()


def main() -> int:
    if len(AUTH_TOKEN) < 64 or len(SESSION_ID) < 32 or len(MODEL_REVISION) < 64:
        raise RuntimeError("local token, session ID and model revision are required")
    args = _parse_args()
    upstream = create_app(model="supertonic-3", cors_origins=None)
    secured = LocalSecurityMiddleware(upstream)
    uvicorn.run(
        secured,
        host="127.0.0.1",
        port=args.port,
        workers=1,
        access_log=False,
        log_config=None,
        timeout_keep_alive=5,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
