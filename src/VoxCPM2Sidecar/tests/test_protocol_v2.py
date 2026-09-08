from __future__ import annotations

import base64
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from protocol_v2 import (
    DOTNET_TICKS_PER_SECOND,
    DOTNET_UNIX_EPOCH_TICKS,
    BootstrapState,
    ProtocolError,
    SessionIdentity,
    bind_loopback_listener,
    build_handshake,
    canonicalize_data_directory,
    compute_bootstrap_proof,
    dotnet_ticks_to_unix_whole_seconds,
    process_matches_parent,
)


def valid_environment(data: Path) -> dict[str, str]:
    return {
        "SVX_LOCAL_AUTH_TOKEN": base64.b64encode(bytes(range(32))).decode(),
        "SVX_SESSION_SECRET": base64.b64encode(bytes(range(32, 64))).decode(),
        "SVX_SESSION_NONCE": "11" * 32,
        "SVX_SESSION_ID": "22" * 16,
        "SVX_PARENT_PID": "1234",
        "SVX_PARENT_START_UTC_TICKS": str(DOTNET_UNIX_EPOCH_TICKS + 1_700_000_000 * DOTNET_TICKS_PER_SECOND + 9_999_999),
        "SVX_DATA_DIRECTORY": str(data),
        "SVX_ENGINE_BACKEND": "Cpu",
    }


class FakeProcess:
    def __init__(self, created: float):
        self._created = created

    def create_time(self) -> float:
        return self._created


class ProtocolV2Tests(unittest.TestCase):
    def test_known_proofs_and_exact_camel_case_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            data = root / "data"
            pack.mkdir()
            data.mkdir()
            identity = SessionIdentity.from_environment(valid_environment(data), pack)
            handshake = build_handshake(identity, 32123, 4567, "voxcpm2", "2.0.3", "bffb3df5a29440629464e5e839f4d214c8714c3d")
            self.assertEqual(
                list(handshake),
                ["schemaVersion", "protocolVersion", "engineId", "engineVersion", "modelRevision", "backend", "parentProcessId", "parentStartUtcTicks", "sessionId", "listenerAddress", "processId", "port", "nonce", "proof"],
            )
            self.assertEqual(handshake["proof"], "4b05c9db2c53c9f247cb2201f66f3e3885533530c2b1185aa03ed7b0fcd71f25")
            challenge = base64.b64encode(bytes(range(64, 96))).decode()
            self.assertEqual(compute_bootstrap_proof(identity, handshake, challenge), "791d561f2379273b05c5c07d9e6a6dfcab76888d988fb9e79bea0668b1ff6f34")
            self.assertLess(len(json.dumps(handshake, separators=(",", ":")).encode()), 16 * 1024)

    def test_environment_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            data = root / "data"
            pack.mkdir()
            data.mkdir()
            for key in valid_environment(data):
                broken = valid_environment(data)
                broken.pop(key)
                with self.subTest(key=key), self.assertRaises(ProtocolError):
                    SessionIdentity.from_environment(broken, pack)
            broken = valid_environment(data)
            broken["SVX_ENGINE_BACKEND"] = "Metal"
            with self.assertRaises(ProtocolError):
                SessionIdentity.from_environment(broken, pack)

    def test_parent_comparison_uses_shared_whole_second_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            data = root / "data"
            pack.mkdir()
            data.mkdir()
            identity = SessionIdentity.from_environment(valid_environment(data), pack)
            expected = dotnet_ticks_to_unix_whole_seconds(identity.parent_start_utc_ticks)
            self.assertTrue(process_matches_parent(identity, lambda _: FakeProcess(expected + 0.999999)))
            self.assertFalse(process_matches_parent(identity, lambda _: FakeProcess(expected + 1.0)))
            self.assertFalse(process_matches_parent(identity, lambda _: FakeProcess(expected - 1.0)))
            self.assertFalse(process_matches_parent(identity, lambda _: (_ for _ in ()).throw(ProcessLookupError())))

    def test_data_root_accepts_symlinked_ancestor_but_rejects_leaf_and_pack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack"
            actual_parent = root / "actual"
            pack.mkdir()
            actual_parent.mkdir()
            data = actual_parent / "data"
            data.mkdir()
            ancestor = root / "ancestor"
            ancestor.symlink_to(actual_parent, target_is_directory=True)
            self.assertEqual(canonicalize_data_directory(str(ancestor / "data"), pack), data.resolve())
            leaf = root / "leaf"
            leaf.symlink_to(data, target_is_directory=True)
            with self.assertRaises(ProtocolError):
                canonicalize_data_directory(str(leaf), pack)
            with self.assertRaises(ProtocolError):
                canonicalize_data_directory(str(pack), pack)

    def test_bootstrap_state_has_three_total_attempts_and_one_completion(self):
        state = BootstrapState()
        self.assertTrue(state.begin_attempt())
        self.assertTrue(state.begin_attempt())
        self.assertTrue(state.begin_attempt())
        self.assertFalse(state.begin_attempt())
        self.assertTrue(state.complete_once())
        self.assertFalse(state.complete_once())
        self.assertFalse(state.begin_attempt())

    def test_listener_is_ipv4_loopback_listening_before_return(self):
        listener = bind_loopback_listener()
        try:
            host, port = listener.getsockname()
            self.assertEqual(host, "127.0.0.1")
            self.assertGreaterEqual(port, 1024)
            with socket.create_connection((host, port), timeout=1):
                pass
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()
