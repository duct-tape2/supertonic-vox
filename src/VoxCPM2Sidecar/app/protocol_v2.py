"""Protocol-v2 primitives for the owner-controlled VoxCPM2 sidecar.

This module deliberately contains no model imports.  It validates the launch
identity supplied by the .NET owner, computes the two protocol proofs, owns the
single-use bootstrap state, and monitors the exact parent identity at the
documented whole-second boundary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping


DOTNET_UNIX_EPOCH_TICKS = 621_355_968_000_000_000
DOTNET_TICKS_PER_SECOND = 10_000_000
HANDSHAKE_DOMAIN = "svx-handshake-v2"
BOOTSTRAP_DOMAIN = "svx-listener-bootstrap-v2"
MAXIMUM_HANDSHAKE_BYTES = 16 * 1024
MAXIMUM_BOOTSTRAP_ATTEMPTS = 3
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_BACKENDS = {"Cpu", "Cuda", "Mps"}


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


class ProtocolError(RuntimeError):
    """Raised before listener activation when the owner contract is invalid."""


def _decode_canonical_base64(name: str, value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProtocolError(f"{name} is not canonical base64") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ProtocolError(f"{name} must encode exactly 32 bytes")
    return decoded


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value or "\x00" in value:
        raise ProtocolError(f"{name} is missing or invalid")
    return value


def _parse_positive_integer(environment: Mapping[str, str], name: str) -> int:
    raw = _required(environment, name)
    if not raw.isascii() or not raw.isdecimal() or raw.startswith("0"):
        raise ProtocolError(f"{name} is not a canonical positive integer")
    value = int(raw)
    if value <= 0:
        raise ProtocolError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class SessionIdentity:
    bearer_token_text: str
    bearer_token: bytes
    session_secret: bytes
    nonce: str
    session_id: str
    parent_process_id: int
    parent_start_utc_ticks: int
    data_directory: Path
    backend: str

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
        pack_root: Path,
    ) -> "SessionIdentity":
        bearer_text = _required(environment, "SVX_LOCAL_AUTH_TOKEN")
        bearer = _decode_canonical_base64("SVX_LOCAL_AUTH_TOKEN", bearer_text)
        secret = _decode_canonical_base64(
            "SVX_SESSION_SECRET", _required(environment, "SVX_SESSION_SECRET")
        )
        nonce = _required(environment, "SVX_SESSION_NONCE")
        session_id = _required(environment, "SVX_SESSION_ID")
        if _LOWER_HEX_64.fullmatch(nonce) is None:
            raise ProtocolError("SVX_SESSION_NONCE must be 64 lowercase hex characters")
        if _LOWER_HEX_32.fullmatch(session_id) is None:
            raise ProtocolError("SVX_SESSION_ID must be 32 lowercase hex characters")
        backend = _required(environment, "SVX_ENGINE_BACKEND")
        if backend not in _BACKENDS:
            raise ProtocolError("SVX_ENGINE_BACKEND is unsupported")
        data_directory = canonicalize_data_directory(
            _required(environment, "SVX_DATA_DIRECTORY"), pack_root
        )
        return cls(
            bearer_token_text=bearer_text,
            bearer_token=bearer,
            session_secret=secret,
            nonce=nonce,
            session_id=session_id,
            parent_process_id=_parse_positive_integer(environment, "SVX_PARENT_PID"),
            parent_start_utc_ticks=_parse_positive_integer(
                environment, "SVX_PARENT_START_UTC_TICKS"
            ),
            data_directory=data_directory,
            backend=backend,
        )

    def token_matches(self, authorization: str) -> bool:
        expected = f"Bearer {self.bearer_token_text}"
        return hmac.compare_digest(authorization, expected)


def canonicalize_data_directory(raw: str, pack_root: Path) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute() or not os.path.lexists(candidate):
        raise ProtocolError("SVX_DATA_DIRECTORY must be an existing absolute path")
    try:
        leaf_metadata = os.lstat(candidate)
    except OSError as exc:
        raise ProtocolError("SVX_DATA_DIRECTORY cannot be inspected") from exc
    if _is_link_or_reparse(leaf_metadata):
        raise ProtocolError("SVX_DATA_DIRECTORY leaf cannot be a symbolic link")
    resolved = Path(os.path.realpath(candidate))
    pack = Path(os.path.realpath(pack_root))
    try:
        common = Path(os.path.commonpath((resolved, pack)))
    except ValueError as exc:
        raise ProtocolError("SVX_DATA_DIRECTORY is on an invalid volume") from exc
    if common == pack:
        raise ProtocolError("SVX_DATA_DIRECTORY cannot be inside the runtime pack")
    return resolved


def dotnet_ticks_to_unix_whole_seconds(ticks: int) -> int:
    if ticks < DOTNET_UNIX_EPOCH_TICKS:
        raise ProtocolError("parent start ticks predate the Unix epoch")
    return (ticks - DOTNET_UNIX_EPOCH_TICKS) // DOTNET_TICKS_PER_SECOND


def process_matches_parent(identity: SessionIdentity, process_factory: Callable[[int], object]) -> bool:
    try:
        process = process_factory(identity.parent_process_id)
        actual_seconds = int(float(process.create_time()))
    except Exception:
        return False
    expected_seconds = dotnet_ticks_to_unix_whole_seconds(identity.parent_start_utc_ticks)
    return actual_seconds == expected_seconds


class ParentIdentityWatcher:
    def __init__(
        self,
        identity: SessionIdentity,
        on_parent_lost: Callable[[], None],
        poll_seconds: float = 1.0,
    ) -> None:
        self._identity = identity
        self._on_parent_lost = on_parent_lost
        self._poll_seconds = poll_seconds
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise ProtocolError("parent watcher was already started")
        try:
            import psutil
        except ImportError as exc:
            raise ProtocolError("psutil==5.9.8 is required") from exc
        self._thread = threading.Thread(
            target=self._run,
            args=(psutil.Process,),
            name="svx-parent-watcher",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopped.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(1.0, self._poll_seconds * 2))

    def _run(self, process_factory: Callable[[int], object]) -> None:
        while not self._stopped.wait(self._poll_seconds):
            if not process_matches_parent(self._identity, process_factory):
                self._on_parent_lost()
                return


def _append_length_prefixed(buffer: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    buffer.extend(len(encoded).to_bytes(4, byteorder="big", signed=False))
    buffer.extend(encoded)


def _proof(secret: bytes, values: list[str]) -> str:
    payload = bytearray()
    for value in values:
        _append_length_prefixed(payload, value)
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _identity_values(handshake: Mapping[str, object]) -> list[str]:
    return [
        str(handshake["schemaVersion"]),
        str(handshake["protocolVersion"]),
        str(handshake["engineId"]),
        str(handshake["engineVersion"]),
        str(handshake["modelRevision"]),
        str(handshake["backend"]),
        str(handshake["parentProcessId"]),
        str(handshake["parentStartUtcTicks"]),
        str(handshake["sessionId"]),
        str(handshake["listenerAddress"]),
        str(handshake["processId"]),
        str(handshake["port"]),
        str(handshake["nonce"]),
    ]


def build_handshake(
    identity: SessionIdentity,
    port: int,
    process_id: int,
    engine_id: str,
    engine_version: str,
    model_revision: str,
) -> dict[str, object]:
    if port < 1024 or port > 65_535 or process_id <= 0:
        raise ProtocolError("listener or process identity is invalid")
    document: dict[str, object] = {
        "schemaVersion": 1,
        "protocolVersion": 2,
        "engineId": engine_id,
        "engineVersion": engine_version,
        "modelRevision": model_revision,
        "backend": identity.backend,
        "parentProcessId": identity.parent_process_id,
        "parentStartUtcTicks": identity.parent_start_utc_ticks,
        "sessionId": identity.session_id,
        "listenerAddress": "127.0.0.1",
        "processId": process_id,
        "port": port,
        "nonce": identity.nonce,
    }
    document["proof"] = _proof(
        identity.session_secret, [HANDSHAKE_DOMAIN, *_identity_values(document)]
    )
    encoded = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAXIMUM_HANDSHAKE_BYTES or b"\n" in encoded or b"\r" in encoded:
        raise ProtocolError("handshake exceeds the protocol limit")
    return document


def compute_bootstrap_proof(
    identity: SessionIdentity,
    handshake: Mapping[str, object],
    challenge: str,
) -> str:
    return _proof(
        identity.session_secret,
        [BOOTSTRAP_DOMAIN, *_identity_values(handshake), challenge],
    )


class BootstrapState:
    """Three total attempts, one successful transition, then permanently closed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempts = 0
        self._complete = False

    @property
    def complete(self) -> bool:
        with self._lock:
            return self._complete

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

    def begin_attempt(self) -> bool:
        with self._lock:
            if self._complete or self._attempts >= MAXIMUM_BOOTSTRAP_ATTEMPTS:
                return False
            self._attempts += 1
            return True

    def complete_once(self) -> bool:
        with self._lock:
            if self._complete or self._attempts < 1:
                return False
            self._complete = True
            return True


def bind_loopback_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        if listener.getsockname()[0] != "127.0.0.1":
            raise ProtocolError("listener escaped IPv4 loopback")
        return listener
    except Exception:
        listener.close()
        raise
