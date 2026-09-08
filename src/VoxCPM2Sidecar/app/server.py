"""Offline localhost sidecar for VoxCPM2 CPU inference.

The desktop application owns this process.  It is deliberately small and
strict: it binds only to loopback, accepts one synthesis job at a time, reads
only the bundled model, and emits 48 kHz mono PCM16 WAV bytes.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import json
import logging
import logging.handlers
import math
import os
import random
import re
import secrets
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal


ROOT_DIR = Path(__file__).resolve().parents[1]
PKGS_DIR = ROOT_DIR / "pkgs"
if str(PKGS_DIR) not in sys.path:
    sys.path.insert(0, str(PKGS_DIR))

# These must be set before transformers/modelscope/voxcpm are imported.
for _name, _value in {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_DATASETS_OFFLINE": "1",
    "MODELSCOPE_OFFLINE": "1",
    "TOKENIZERS_PARALLELISM": "false",
}.items():
    # The packaged runtime must remain offline even if the parent process has
    # conflicting values in its environment.
    os.environ[_name] = _value

import numpy as np  # noqa: E402
import soundfile as sf  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.exceptions import RequestValidationError  # noqa: E402
from fastapi.responses import JSONResponse, Response  # noqa: E402
from fastapi.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402


ENGINE_NAME = "voxcpm2"
ENGINE_VERSION = "2.0.3"
MODEL_ID = "OpenBMB/VoxCPM2"
MODEL_REVISION = "bffb3df5a29440629464e5e839f4d214c8714c3d"
MODEL_DIR = ROOT_DIR / "models" / "VoxCPM2"
PRESETS_PATH = ROOT_DIR / "voices" / "presets.json"
USER_VOICES_DIR = ROOT_DIR / "voices" / "user"
LOG_DIR = ROOT_DIR / "logs"
TARGET_SAMPLE_RATE = 48_000
INTRA_OP_THREADS = 12
INTER_OP_THREADS = 2
ALLOWED_PORTS = range(7800, 7811)
MUTEX_NAME = rf"Local\SupertonicPlusVoxCPM2-{MODEL_REVISION[:16]}"
AUTH_TOKEN = os.environ.get("TTS_LOCAL_AUTH_TOKEN", "")
SESSION_ID = os.environ.get("TTS_LOCAL_SESSION_ID", "")
MAX_REQUEST_BYTES = 16 * 1024
MAX_REFERENCE_WAV_BYTES = 64 * 1024 * 1024

EXPECTED_MODEL_FILES: dict[str, tuple[int, str]] = {
    "model.safetensors": (
        4_580_080_592,
        "f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d",
    ),
    "audiovae.pth": (
        376_951_122,
        "94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1",
    ),
}


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("voxcpm2-sidecar")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(process)d %(threadName)s %(message)s"
    )
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    if os.environ.get("VOXCPM_LOG_TO_FILE", "1") != "0":
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            rotating = logging.handlers.RotatingFileHandler(
                LOG_DIR / "server.log",
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            rotating.setFormatter(formatter)
            logger.addHandler(rotating)
        except OSError:
            logger.exception("Could not initialize rotating file logging")
    return logger


logger = _configure_logging()


class SidecarError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class SynthesisRequest(BaseModel):
    model_config = {"extra": "forbid", "str_strip_whitespace": True}

    text: str = Field(min_length=1, max_length=220)
    mode: Literal["preset", "clone"] = "preset"
    profile_id: str = Field(default="vox_news_f", min_length=1, max_length=64)
    reference_wav_path: str | None = Field(default=None, max_length=1024)
    cfg_value: float = Field(default=2.0, ge=1.0, le=4.0)
    inference_timesteps: Literal[6, 8, 10] = 10
    seed: int = Field(default=42, ge=0, le=2_147_483_647)
    response_format: Literal["wav"] = "wav"


class WindowsNamedMutex:
    """Process-lifetime named mutex preventing duplicate model residency."""

    ERROR_ALREADY_EXISTS = 183

    def __init__(self, name: str):
        self.name = name
        self._handle: int | None = None

    def acquire(self) -> None:
        if os.name != "nt":
            return
        if self._handle is not None:
            return

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_bool

        ctypes.set_last_error(0)
        handle = kernel32.CreateMutexW(None, True, self.name)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == self.ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            raise SidecarError(
                409,
                "model_instance_already_running",
                "다른 VoxCPM2 로컬 서버가 이미 모델을 사용 중입니다.",
            )
        self._handle = int(handle)

    def release(self) -> None:
        if os.name != "nt" or self._handle is None:
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
        kernel32.ReleaseMutex.restype = ctypes.c_bool
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_bool
        handle = ctypes.c_void_p(self._handle)
        kernel32.ReleaseMutex(handle)
        kernel32.CloseHandle(handle)
        self._handle = None


class PresetCatalog:
    def __init__(self, path: Path):
        self.path = path
        self._profiles: dict[str, dict[str, Any]] | None = None
        self.default_profile_id = "vox_news_f"

    def load(self) -> dict[str, dict[str, Any]]:
        if self._profiles is not None:
            return self._profiles
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SidecarError(
                500, "preset_configuration_error", "VoxCPM2 음성 프리셋 파일을 읽을 수 없습니다."
            ) from exc

        if not isinstance(raw, dict) or raw.get("schema_version") != 1 or not isinstance(raw.get("profiles"), list):
            raise SidecarError(
                500, "preset_configuration_error", "VoxCPM2 음성 프리셋 형식이 올바르지 않습니다."
            )
        profiles: dict[str, dict[str, Any]] = {}
        for entry in raw["profiles"]:
            if not isinstance(entry, dict):
                raise SidecarError(500, "preset_configuration_error", "프리셋 항목 형식이 잘못되었습니다.")
            profile_id = entry.get("id")
            control_text = entry.get("control_text")
            label = entry.get("label_ko")
            if (
                not isinstance(profile_id, str)
                or not re.fullmatch(r"[a-z0-9_]{1,64}", profile_id)
                or not isinstance(control_text, str)
                or not control_text.strip()
                or not isinstance(label, str)
                or not label.strip()
                or profile_id in profiles
            ):
                raise SidecarError(500, "preset_configuration_error", "프리셋 항목 값이 잘못되었습니다.")
            profiles[profile_id] = entry

        default_id = raw.get("default_profile_id")
        if default_id not in profiles:
            raise SidecarError(500, "preset_configuration_error", "기본 프리셋을 찾을 수 없습니다.")
        self.default_profile_id = default_id
        self._profiles = profiles
        return profiles

    def get(self, profile_id: str) -> dict[str, Any]:
        profile = self.load().get(profile_id)
        if profile is None:
            raise SidecarError(422, "unknown_profile", "선택한 VoxCPM2 음성 프리셋이 없습니다.")
        return profile


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_model_files(full_hash: bool = False) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    for relative_name, (expected_size, expected_sha) in EXPECTED_MODEL_FILES.items():
        path = MODEL_DIR / relative_name
        if not path.is_file():
            problems.append({"file": relative_name, "problem": "missing"})
            continue
        try:
            actual_size = path.stat().st_size
        except OSError:
            problems.append({"file": relative_name, "problem": "unreadable"})
            continue
        if actual_size != expected_size:
            problems.append({"file": relative_name, "problem": "size_mismatch"})
            continue
        if full_hash and _sha256(path).lower() != expected_sha:
            problems.append({"file": relative_name, "problem": "sha256_mismatch"})
    return problems


def _safe_control_text(value: str) -> str:
    # VoxCPM2 uses one leading parenthesized instruction. Nested parentheses
    # would change that grammar, so preset data cannot introduce them.
    return re.sub(r"[()（）]", "", value).strip()


def build_preset_text(text: str, profile: dict[str, Any]) -> str:
    control = _safe_control_text(str(profile["control_text"]))
    return f"({control}){text}" if control else text


def set_inference_seed(seed: int) -> None:
    """Seed the RNGs used by VoxCPM 2.0.3 before each locked request.

    The 2.0.3 wheel's public README shows a ``seed`` keyword, but its shipped
    ``VoxCPM._generate`` signature does not accept one.  Seeding the three RNGs
    here provides the intended stable per-chunk behavior without passing an
    unsupported keyword into the model.
    """
    random.seed(seed)
    np.random.seed(seed)
    import torch

    torch.manual_seed(seed)


def validate_reference_wav(raw_path: str) -> str:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = ROOT_DIR / candidate
    try:
        resolved = candidate.resolve(strict=True)
        user_root = USER_VOICES_DIR.resolve(strict=True)
        resolved.relative_to(user_root)
    except (OSError, ValueError) as exc:
        raise SidecarError(
            422,
            "invalid_reference_path",
            "참조 WAV는 프로그램의 voices\\user 폴더 안에 있어야 합니다.",
        ) from exc

    if resolved.suffix.lower() != ".wav" or not resolved.is_file():
        raise SidecarError(422, "invalid_reference_wav", "참조 음성은 WAV 파일만 사용할 수 있습니다.")
    try:
        if resolved.stat().st_size > MAX_REFERENCE_WAV_BYTES:
            raise SidecarError(
                413,
                "reference_wav_too_large",
                "참조 WAV 파일은 64MiB를 초과할 수 없습니다.",
            )
    except OSError as exc:
        raise SidecarError(422, "invalid_reference_wav", "참조 WAV 파일 크기를 확인할 수 없습니다.") from exc
    try:
        info = sf.info(str(resolved))
        audio, sample_rate = sf.read(str(resolved), dtype="float32", always_2d=True)
    except Exception as exc:
        raise SidecarError(422, "invalid_reference_wav", "참조 WAV가 손상되었거나 읽을 수 없습니다.") from exc

    if info.format != "WAV" or info.frames <= 0 or sample_rate < 8_000 or sample_rate > 192_000:
        raise SidecarError(422, "invalid_reference_wav", "참조 WAV의 오디오 형식이 올바르지 않습니다.")
    if audio.shape[1] != 1:
        raise SidecarError(422, "reference_not_mono", "참조 WAV는 모노로 정규화되어야 합니다.")
    duration = info.frames / float(info.samplerate)
    if duration < 5.0 or duration > 30.0:
        raise SidecarError(422, "reference_duration", "참조 WAV 길이는 5초 이상 30초 이하여야 합니다.")
    if not np.isfinite(audio).all():
        raise SidecarError(422, "invalid_reference_wav", "참조 WAV에 비정상 샘플이 있습니다.")
    rms = float(np.sqrt(np.mean(np.square(audio, dtype=np.float64))))
    peak = float(np.max(np.abs(audio)))
    if rms < 1.0e-4 or peak < 5.0e-4:
        raise SidecarError(422, "silent_reference_wav", "참조 WAV가 무음이거나 음량이 지나치게 작습니다.")
    return str(resolved)


def _to_mono_float32(waveform: Any) -> np.ndarray:
    if hasattr(waveform, "detach"):
        waveform = waveform.detach().cpu().numpy()
    audio = np.asarray(waveform, dtype=np.float32)
    audio = np.squeeze(audio)
    if audio.ndim == 0:
        audio = audio.reshape(1)
    elif audio.ndim == 2:
        # Handle either channels-first or channels-last conservatively.
        channel_axis = 0 if audio.shape[0] <= 8 else 1
        audio = audio.mean(axis=channel_axis, dtype=np.float32)
    elif audio.ndim != 1:
        raise SidecarError(500, "invalid_model_output", "VoxCPM2가 지원되지 않는 오디오 배열을 반환했습니다.")
    if audio.size == 0 or not np.isfinite(audio).all():
        raise SidecarError(500, "invalid_model_output", "VoxCPM2가 빈 오디오 또는 비정상 샘플을 반환했습니다.")
    return np.clip(audio, -1.0, 1.0).astype(np.float32, copy=False)


def _resample(audio: np.ndarray, source_rate: int, target_rate: int) -> np.ndarray:
    if source_rate == target_rate:
        return audio
    if source_rate <= 0:
        raise SidecarError(500, "invalid_sample_rate", "VoxCPM2 출력 샘플레이트가 올바르지 않습니다.")
    try:
        from scipy.signal import resample_poly

        divisor = math.gcd(source_rate, target_rate)
        converted = resample_poly(audio, target_rate // divisor, source_rate // divisor)
    except ImportError:
        # scipy is pinned in requirements.lock; this fallback keeps diagnostics
        # usable if a partial runtime is being repaired.
        output_length = max(1, round(audio.size * target_rate / source_rate))
        old_x = np.linspace(0.0, 1.0, num=audio.size, endpoint=False)
        new_x = np.linspace(0.0, 1.0, num=output_length, endpoint=False)
        converted = np.interp(new_x, old_x, audio)
    return np.asarray(converted, dtype=np.float32)


def encode_pcm16_wav(waveform: Any, source_rate: int) -> tuple[bytes, int]:
    audio = _to_mono_float32(waveform)
    audio = _resample(audio, int(source_rate), TARGET_SAMPLE_RATE)
    audio = np.clip(audio, -1.0, 1.0).astype(np.float32, copy=False)
    buffer = io.BytesIO()
    sf.write(buffer, audio, TARGET_SAMPLE_RATE, format="WAV", subtype="PCM_16")
    duration_ms = round(audio.size * 1000 / TARGET_SAMPLE_RATE)
    return buffer.getvalue(), duration_ms


class VoxCpmRuntime:
    def __init__(self) -> None:
        self._model: Any | None = None
        self._sample_rate = TARGET_SAMPLE_RATE
        self._load_lock = threading.Lock()
        self._integrity_verified = False

    @property
    def loaded(self) -> bool:
        return self._model is not None

    @property
    def sample_rate(self) -> int:
        return self._sample_rate

    def ensure_model(self) -> Any:
        if self._model is not None:
            return self._model
        with self._load_lock:
            if self._model is not None:
                return self._model
            if not self._integrity_verified:
                logger.info("Verifying required VoxCPM2 model files")
                problems = inspect_model_files(full_hash=True)
                if problems:
                    logger.error("Model integrity check failed: %s", problems)
                    raise SidecarError(
                        503,
                        "model_integrity_error",
                        "VoxCPM2 모델 파일이 없거나 무결성 검증에 실패했습니다.",
                    )
                self._integrity_verified = True

            try:
                import torch

                torch.set_num_threads(INTRA_OP_THREADS)
                try:
                    torch.set_num_interop_threads(INTER_OP_THREADS)
                except RuntimeError:
                    logger.warning("PyTorch inter-op thread count was already initialized")
                from voxcpm_low_memory import install_low_memory_cpu_loader

                install_low_memory_cpu_loader()
                from voxcpm import VoxCPM

                started = time.monotonic()
                logger.info("Loading VoxCPM2 on CPU from local model directory")

                model = VoxCPM.from_pretrained(
                    str(MODEL_DIR),
                    device="cpu",
                    optimize=False,
                    load_denoiser=False,
                    local_files_only=True,
                )
                sample_rate = int(getattr(getattr(model, "tts_model", None), "sample_rate", 0))
                if sample_rate <= 0:
                    raise RuntimeError("model did not expose a valid tts_model.sample_rate")
            except SidecarError:
                raise
            except Exception as exc:
                logger.exception("VoxCPM2 model load failed")
                raise SidecarError(503, "model_load_failed", "VoxCPM2 CPU 모델을 불러오지 못했습니다.") from exc

            self._model = model
            self._sample_rate = sample_rate
            logger.info("VoxCPM2 loaded in %.1f seconds", time.monotonic() - started)
            return self._model

    def unload(self) -> None:
        self._model = None
        try:
            import gc

            gc.collect()
        except Exception:
            logger.exception("Model cleanup failed")


catalog = PresetCatalog(PRESETS_PATH)
runtime = VoxCpmRuntime()
generation_lock = threading.Lock()
process_mutex = WindowsNamedMutex(MUTEX_NAME)


@asynccontextmanager
async def _lifespan(_: FastAPI):
    try:
        process_mutex.acquire()
        USER_VOICES_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(
            "Sidecar startup engine=%s version=%s revision=%s offline=true threads=%s/%s",
            ENGINE_NAME,
            ENGINE_VERSION,
            MODEL_REVISION,
            INTRA_OP_THREADS,
            INTER_OP_THREADS,
        )
        catalog.load()
        if os.environ.get("VOXCPM_PRELOAD", "0") == "1":
            runtime.ensure_model()
        yield
    finally:
        runtime.unload()
        process_mutex.release()
        logger.info("Sidecar shutdown complete")


app = FastAPI(
    title="VoxCPM2 Local Sidecar",
    version=ENGINE_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])


def _request_id(request: Request) -> str:
    existing = getattr(request.state, "request_id", None)
    if existing:
        return existing
    value = uuid.uuid4().hex
    request.state.request_id = value
    return value


@app.middleware("http")
async def _request_context(request: Request, call_next):
    request_id = uuid.uuid4().hex
    request.state.request_id = request_id
    if request.url.path not in {"/v1/health", "/v1/tts"}:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "not_found", "message": "사용할 수 없는 경로입니다.", "request_id": request_id}},
        )
    supplied = request.headers.get("x-local-tts-token", "")
    if not AUTH_TOKEN or not secrets.compare_digest(supplied, AUTH_TOKEN):
        return JSONResponse(
            status_code=401,
            content={"error": {"code": "unauthorized", "message": "로컬 인증 토큰이 필요합니다.", "request_id": request_id}},
        )
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": {"code": "request_too_large", "message": "요청 본문이 너무 큽니다.", "request_id": request_id}},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": {"code": "invalid_content_length", "message": "Content-Length가 올바르지 않습니다.", "request_id": request_id}},
            )
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=413,
            content={"error": {"code": "request_too_large", "message": "요청 본문이 너무 큽니다.", "request_id": request_id}},
        )
    replayed = False

    async def receive():
        nonlocal replayed
        if replayed:
            return {"type": "http.disconnect"}
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Local-TTS-Session"] = SESSION_ID
    response.headers["X-Local-TTS-Engine"] = ENGINE_NAME
    return response


@app.exception_handler(SidecarError)
async def _sidecar_error_handler(request: Request, exc: SidecarError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "request_id": _request_id(request),
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    safe_details = [
        {"location": [str(item) for item in error.get("loc", ())], "type": error.get("type", "invalid")}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "VoxCPM2 요청 값이 올바르지 않습니다.",
                "request_id": _request_id(request),
                "details": safe_details,
            }
        },
    )


@app.exception_handler(Exception)
async def _unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = _request_id(request)
    logger.error(
        "Unhandled request failure request_id=%s",
        request_id,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "VoxCPM2 로컬 서버에서 예기치 않은 오류가 발생했습니다.",
                "request_id": request_id,
            }
        },
    )


@app.get("/v1/health")
def health() -> dict[str, Any]:
    model_problems = inspect_model_files(full_hash=False)
    try:
        profiles = catalog.load()
        preset_status = "ok"
    except SidecarError:
        profiles = {}
        preset_status = "error"
    status = "ready" if not model_problems and preset_status == "ok" else "unavailable"
    return {
        "status": status,
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        "session_id": SESSION_ID,
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "model_loaded": runtime.loaded,
        "model_files": "ok" if not model_problems else model_problems,
        "presets": preset_status,
        "profile_ids": sorted(profiles),
        "device": "cpu",
        "optimize": False,
        "offline": True,
        "sample_rate": TARGET_SAMPLE_RATE,
        "channels": 1,
        "sample_format": "PCM16",
        "busy": generation_lock.locked(),
    }


@app.post("/v1/tts")
def synthesize(payload: SynthesisRequest, request: Request) -> Response:
    request_id = _request_id(request)
    if not generation_lock.acquire(blocking=False):
        raise SidecarError(409, "synthesis_busy", "다른 VoxCPM2 음성을 생성 중입니다.")

    started = time.monotonic()
    try:
        reference_path: str | None = None
        if payload.mode == "preset":
            if payload.reference_wav_path:
                raise SidecarError(
                    422,
                    "unexpected_reference_wav",
                    "프리셋 모드에서는 참조 WAV를 지정할 수 없습니다.",
                )
            profile = catalog.get(payload.profile_id)
            synthesis_text = build_preset_text(payload.text, profile)
        else:
            if not payload.reference_wav_path:
                raise SidecarError(422, "reference_wav_required", "음성 복제에는 참조 WAV가 필요합니다.")
            reference_path = validate_reference_wav(payload.reference_wav_path)
            synthesis_text = payload.text

        model = runtime.ensure_model()
        logger.info(
            "Synthesis start request_id=%s mode=%s profile=%s chars=%d steps=%d seed=%d",
            request_id,
            payload.mode,
            payload.profile_id,
            len(payload.text),
            payload.inference_timesteps,
            payload.seed,
        )
        try:
            set_inference_seed(payload.seed)
            waveform = model.generate(
                text=synthesis_text,
                reference_wav_path=reference_path,
                cfg_value=float(payload.cfg_value),
                inference_timesteps=int(payload.inference_timesteps),
                # The 2.0.3 normalizer treats every non-Chinese string as
                # English, which damages Korean text.  Korean number/abbreviation
                # normalization is performed by the desktop app instead.
                normalize=False,
                denoise=False,
            )
        except MemoryError as exc:
            logger.exception("CPU memory exhausted request_id=%s", request_id)
            raise SidecarError(507, "out_of_memory", "VoxCPM2 생성 중 메모리가 부족해졌습니다.") from exc
        except Exception as exc:
            logger.exception("Synthesis failed request_id=%s", request_id)
            raise SidecarError(500, "synthesis_failed", "VoxCPM2 음성 생성에 실패했습니다.") from exc

        wav_bytes, duration_ms = encode_pcm16_wav(waveform, runtime.sample_rate)
        elapsed = time.monotonic() - started
        logger.info(
            "Synthesis complete request_id=%s audio_ms=%d elapsed_s=%.1f bytes=%d",
            request_id,
            duration_ms,
            elapsed,
            len(wav_bytes),
        )
        return Response(
            content=wav_bytes,
            media_type="audio/wav",
            headers={
                "Content-Disposition": 'inline; filename="voxcpm2.wav"',
                "X-VoxCPM2-Engine": ENGINE_NAME,
                "X-VoxCPM2-Revision": MODEL_REVISION,
                "X-Audio-Sample-Rate": str(TARGET_SAMPLE_RATE),
                "X-Audio-Channels": "1",
                "X-Audio-Format": "PCM16",
                "X-Audio-Duration-Ms": str(duration_ms),
            },
        )
    finally:
        generation_lock.release()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline VoxCPM2 CPU localhost sidecar")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        choices=["127.0.0.1"],
        help="loopback binding only",
    )
    parser.add_argument("--port", type=int, default=7800, choices=ALLOWED_PORTS)
    parser.add_argument(
        "--preload",
        action="store_true",
        help="verify and load the model before the server begins accepting requests",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.preload:
        os.environ["VOXCPM_PRELOAD"] = "1"
    import uvicorn

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=1,
        access_log=False,
        log_config=None,
        timeout_keep_alive=5,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
