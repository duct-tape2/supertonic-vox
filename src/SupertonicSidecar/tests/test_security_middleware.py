from __future__ import annotations

import asyncio
import importlib.util
import os
import unittest
from pathlib import Path


os.environ["TTS_LOCAL_AUTH_TOKEN"] = "a" * 64
os.environ["TTS_LOCAL_SESSION_ID"] = "b" * 32
os.environ["TTS_LOCAL_MODEL_REVISION"] = "c" * 64
MODULE_PATH = Path(__file__).resolve().parents[1] / "secure_server.py"
SPEC = importlib.util.spec_from_file_location("secure_server", MODULE_PATH)
if not SPEC or not SPEC.loader:
    raise RuntimeError("could not load secure_server.py for testing")
secure_server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secure_server)


async def fake_app(scope, receive, send):
    await receive()
    body = b'{"status":"ok","model":"supertonic-3"}'
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def invoke(path: str, method: str = "GET", token: str = ""):
    sent = []
    messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [
            (b"host", b"127.0.0.1:7788"),
            (b"x-local-tts-token", token.encode("ascii")),
        ],
    }
    await secure_server.LocalSecurityMiddleware(fake_app)(scope, receive, send)
    return sent


class LocalSecurityMiddlewareTests(unittest.TestCase):
    def test_missing_token_is_rejected(self):
        messages = asyncio.run(invoke("/v1/health"))
        self.assertEqual(messages[0]["status"], 401)

    def test_unused_route_is_hidden(self):
        messages = asyncio.run(invoke("/docs", token="a" * 64))
        self.assertEqual(messages[0]["status"], 404)

    def test_health_is_fingerprinted(self):
        messages = asyncio.run(invoke("/v1/health", token="a" * 64))
        self.assertEqual(messages[0]["status"], 200)
        self.assertIn(b'"session_id":"', messages[1]["body"])
        self.assertIn(b'"model_revision":"', messages[1]["body"])


if __name__ == "__main__":
    unittest.main()
