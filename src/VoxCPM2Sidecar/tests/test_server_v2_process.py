from __future__ import annotations

import base64
import concurrent.futures
import http.client
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import psutil

from protocol_v2 import (
    DOTNET_TICKS_PER_SECOND,
    DOTNET_UNIX_EPOCH_TICKS,
    SessionIdentity,
    compute_bootstrap_proof,
)


class ServerProcessTests(unittest.TestCase):
    def _environment(self, data: Path, *, start_offset_seconds: int = 0) -> dict[str, str]:
        environment = os.environ.copy()
        created_seconds = int(psutil.Process(os.getpid()).create_time()) + start_offset_seconds
        environment.update(
            {
                "SVX_LOCAL_AUTH_TOKEN": base64.b64encode(bytes(range(32))).decode(),
                "SVX_SESSION_SECRET": base64.b64encode(bytes(range(32, 64))).decode(),
                "SVX_SESSION_NONCE": "11" * 32,
                "SVX_SESSION_ID": "22" * 16,
                "SVX_PARENT_PID": str(os.getpid()),
                "SVX_PARENT_START_UTC_TICKS": str(
                    DOTNET_UNIX_EPOCH_TICKS + created_seconds * DOTNET_TICKS_PER_SECOND
                ),
                "SVX_DATA_DIRECTORY": str(data),
                "SVX_ENGINE_BACKEND": "Cpu",
                "VOXCPM_LOG_TO_FILE": "0",
            }
        )
        return environment

    def test_real_process_emits_one_handshake_after_listen_and_serves_v2_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            environment = self._environment(data)
            process = subprocess.Popen(
                [sys.executable, str(ROOT / "app" / "server_v2.py")],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert process.stdout is not None
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    line = pool.submit(process.stdout.readline).result(timeout=10)
                handshake = json.loads(line)
                self.assertEqual(handshake["listenerAddress"], "127.0.0.1")
                self.assertEqual(handshake["processId"], process.pid)
                identity = SessionIdentity.from_environment(environment, ROOT)
                challenge = base64.b64encode(bytes(range(64, 96))).decode()
                connection = http.client.HTTPConnection("127.0.0.1", handshake["port"], timeout=5)
                connection.request(
                    "POST",
                    "/v1/bootstrap-challenge",
                    body=json.dumps({"challenge": challenge}),
                    headers={"Content-Type": "application/json"},
                )
                bootstrap = connection.getresponse()
                response = json.loads(bootstrap.read())
                self.assertEqual(bootstrap.status, 200)
                self.assertEqual(response["proof"], compute_bootstrap_proof(identity, handshake, challenge))
                connection.request(
                    "GET",
                    "/v1/health",
                    headers={"Authorization": f"Bearer {environment['SVX_LOCAL_AUTH_TOKEN']}"},
                )
                health = connection.getresponse()
                health_document = json.loads(health.read())
                self.assertEqual(health.status, 200)
                self.assertEqual(health_document["processId"], process.pid)
                self.assertFalse(health_document["ready"])
                connection.close()
            finally:
                process.terminate()
                stdout, _ = process.communicate(timeout=10)
            self.assertEqual(stdout, "")

    def test_parent_start_mismatch_exits_before_handshake(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = subprocess.run(
                [sys.executable, str(ROOT / "app" / "server_v2.py")],
                cwd=ROOT,
                env=self._environment(Path(temporary), start_offset_seconds=1),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout, "")
            self.assertNotIn("SVX_SESSION_SECRET", process.stderr)


if __name__ == "__main__":
    unittest.main()
