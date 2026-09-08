from __future__ import annotations

import base64
import io
import os
import sys
import tempfile
import unittest
import wave
from pathlib import Path
from unittest.mock import patch

os.environ["VOXCPM_LOG_TO_FILE"] = "0"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "pkgs"))

import numpy as np
from fastapi.testclient import TestClient
from pydantic import ValidationError

import server_v2 as server
from protocol_v2 import SessionIdentity, build_handshake


TOKEN = bytes(range(32))
SECRET = bytes(range(32, 64))
TOKEN_TEXT = base64.b64encode(TOKEN).decode("ascii")
AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN_TEXT}"}


class FakeTtsModel:
    sample_rate = 24_000


class FakeModel:
    tts_model = FakeTtsModel()

    def __init__(self) -> None:
        self.last_kwargs = None
        self.calls = 0

    def generate(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        t = np.arange(24_000, dtype=np.float32) / 24_000
        return 0.15 * np.sin(2 * np.pi * 220 * t)


class FakeRuntime:
    def __init__(self) -> None:
        self.model = FakeModel()
        self.sample_rate = 24_000
        self.loaded = False

    def ensure_model(self):
        self.loaded = True
        return self.model

    def unload(self):
        self.loaded = False


def fixture_identity(data_directory: Path) -> SessionIdentity:
    return SessionIdentity(
        bearer_token_text=TOKEN_TEXT,
        bearer_token=TOKEN,
        session_secret=SECRET,
        nonce="11" * 32,
        session_id="22" * 16,
        parent_process_id=1234,
        parent_start_utc_ticks=638_000_000_000_000_000,
        data_directory=data_directory,
        backend="Cpu",
    )


def bootstrap(client: TestClient, identity: SessionIdentity, handshake: dict[str, object]):
    challenge = base64.b64encode(bytes(range(64, 96))).decode("ascii")
    response = client.post("/v1/bootstrap-challenge", json={"challenge": challenge})
    assert response.status_code == 200, response.text
    assert response.json()["challenge"] == challenge
    assert len(response.json()["proof"]) == 64
    return response


class ServerUnitTests(unittest.TestCase):
    def test_request_schema_is_strict_and_clone_is_disabled(self):
        with self.assertRaises(ValidationError):
            server.SynthesisRequest(
                text="테스트",
                mode="preset",
                profile_id="vox_news_f",
                inference_timesteps=7,
            )
        with self.assertRaises(ValidationError):
            server.SynthesisRequest(text="테스트", mode="clone")
        with self.assertRaises(ValidationError):
            server.SynthesisRequest(text="테스트", unknown=True)

    def test_preset_control_is_parenthesized_once(self):
        profile = server.PresetCatalog(server.PRESETS_PATH).get("vox_news_f")
        text = server.build_preset_text("안녕하세요.", profile)
        self.assertTrue(text.startswith("(A professional Korean female news anchor"))
        self.assertTrue(text.endswith("안녕하세요."))
        self.assertEqual(text.count("("), 1)
        self.assertEqual(text.count(")"), 1)

    def test_pcm_output_is_48k_mono_pcm16_and_rejects_nonfinite(self):
        source = np.linspace(-0.5, 0.5, 24_000, dtype=np.float32)
        payload, duration_ms = server.encode_pcm16_wav(source, 24_000)
        self.assertEqual(duration_ms, 1000)
        with wave.open(io.BytesIO(payload), "rb") as wav:
            self.assertEqual((wav.getframerate(), wav.getnchannels(), wav.getsampwidth()), (48_000, 1, 2))
        with self.assertRaises(server.SidecarError):
            server.encode_pcm16_wav(np.array([np.nan], dtype=np.float32), 24_000)

    def test_bootstrap_gates_routes_then_returns_closed_health_and_one_shot_404(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = fixture_identity(Path(temporary))
            handshake = build_handshake(identity, 12345, os.getpid(), "voxcpm2", "2.0.3", server.MODEL_REVISION)
            app = server.create_app(identity, handshake, FakeRuntime())
            with patch.object(server, "inspect_model_files", return_value=[]):
                with TestClient(app) as client:
                    self.assertEqual(client.get("/v1/health").status_code, 404)
                    bootstrap(client, identity, handshake)
                    health = client.get("/v1/health", headers=AUTH_HEADERS)
                    replay = client.post("/v1/bootstrap-challenge", json={"challenge": "A" * 44})
            self.assertEqual(replay.status_code, 404)
            self.assertEqual(
                health.json(),
                {
                    "schemaVersion": 1,
                    "engineId": "voxcpm2",
                    "engineVersion": "2.0.3",
                    "modelRevision": server.MODEL_REVISION,
                    "backend": "Cpu",
                    "sessionId": identity.session_id,
                    "processId": os.getpid(),
                    "ready": True,
                },
            )

    def test_bootstrap_has_three_total_attempts_and_strict_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = fixture_identity(Path(temporary))
            handshake = build_handshake(identity, 12345, os.getpid(), "voxcpm2", "2.0.3", server.MODEL_REVISION)
            app = server.create_app(identity, handshake, FakeRuntime())
            with TestClient(app) as client:
                first = client.post("/v1/bootstrap-challenge", content=b"{}", headers={"Content-Type": "text/plain"})
                second = client.post("/v1/bootstrap-challenge", json={"challenge": "not-base64"})
                third = client.post("/v1/bootstrap-challenge", json={"challenge": "A" * 44, "extra": True})
                fourth = client.post("/v1/bootstrap-challenge", json={"challenge": base64.b64encode(b"x" * 32).decode()})
            self.assertEqual((first.status_code, second.status_code, third.status_code, fourth.status_code), (415, 422, 422, 404))

    def test_wrong_token_hidden_route_and_oversize_fail_before_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = fixture_identity(Path(temporary))
            handshake = build_handshake(identity, 12345, os.getpid(), "voxcpm2", "2.0.3", server.MODEL_REVISION)
            runtime = FakeRuntime()
            app = server.create_app(identity, handshake, runtime)
            with TestClient(app) as client:
                bootstrap(client, identity, handshake)
                wrong = client.get("/v1/health", headers={"Authorization": "Bearer wrong"})
                hidden = client.get("/docs", headers=AUTH_HEADERS)
                oversized = client.post(
                    "/v1/tts",
                    headers={**AUTH_HEADERS, "Content-Type": "application/json"},
                    content=b"x" * (server.MAX_REQUEST_BYTES + 1),
                )
                chunked = client.post(
                    "/v1/tts",
                    headers={**AUTH_HEADERS, "Content-Type": "application/json"},
                    content=(b"x" * 8192 for _ in range(3)),
                )
            self.assertEqual(
                (wrong.status_code, hidden.status_code, oversized.status_code, chunked.status_code),
                (401, 404, 413, 413),
            )
            self.assertEqual(runtime.model.calls, 0)

    def test_preset_endpoint_returns_contract_wav(self):
        with tempfile.TemporaryDirectory() as temporary:
            identity = fixture_identity(Path(temporary))
            handshake = build_handshake(identity, 12345, os.getpid(), "voxcpm2", "2.0.3", server.MODEL_REVISION)
            runtime = FakeRuntime()
            app = server.create_app(identity, handshake, runtime)
            with patch.object(server, "set_inference_seed"):
                with TestClient(app) as client:
                    bootstrap(client, identity, handshake)
                    response = client.post(
                        "/v1/tts",
                        headers=AUTH_HEADERS,
                        json={
                            "text": "한국어 테스트입니다.",
                            "mode": "preset",
                            "profile_id": "vox_news_f",
                            "reference_wav_path": None,
                            "cfg_value": 2.0,
                            "inference_timesteps": 10,
                            "seed": 42,
                            "response_format": "wav",
                        },
                    )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["content-type"], "audio/wav")
            with wave.open(io.BytesIO(response.content), "rb") as wav:
                self.assertEqual((wav.getframerate(), wav.getnchannels(), wav.getsampwidth()), (48_000, 1, 2))
            self.assertNotIn("seed", runtime.model.last_kwargs)
            self.assertFalse(runtime.model.last_kwargs["normalize"])
            self.assertIsNone(runtime.model.last_kwargs["reference_wav_path"])


if __name__ == "__main__":
    unittest.main()
