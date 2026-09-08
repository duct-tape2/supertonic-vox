# VoxCPM2 local sidecars

이 폴더에는 서로 호환되지 않는 두 호스트 계약이 함께 있습니다.

- `app/server.py`: 복구된 Windows WinForms 후보 전용 legacy 서버. 기존 고정 포트와 `TTS_LOCAL_*` 계약을 보존합니다.
- `app/server_v2.py` + `app/protocol_v2.py`: 새 Avalonia/.NET 10 앱의 immutable runtime-pack 전용 protocol-v2 서버입니다.

두 파일을 서로 바꾸거나 legacy 앱에서 v2 서버를 직접 실행하지 마십시오. 새 앱은 검증된 `runtime-pack.json`의 Python 엔트리포인트와 정적 인수 `app/server_v2.py`만 실행합니다.

## Protocol-v2 보안 계약

v2 서버는 자체적으로 토큰·포트·세션을 만들지 않습니다. 소유자인 .NET 호스트가 매 실행마다 전달한 `SVX_*` 환경을 엄격히 검증합니다.

- OS 할당 `127.0.0.1` 포트를 먼저 LISTEN 상태로 만든 뒤 HMAC-SHA256 핸드셰이크 한 줄만 stdout에 기록
- listener PID 소유권 확인 후 32바이트 challenge로 1회 bootstrap; 전체 시도는 최대 3회
- bootstrap 이후 `Authorization: Bearer ...`만 허용하며 health/tts 이외 경로는 404
- 부모 PID와 시작 시각을 whole-second 경계로 계속 확인하고 불일치/종료 시 즉시 종료
- 요청 16 KiB, 응답 64 MiB, 합성 1개, 출력 48 kHz mono PCM16 WAV
- 로그는 immutable pack이 아니라 `SVX_DATA_DIRECTORY/logs`에 5 MiB × 3개로 순환
- 참조 음성/복제는 private-state 계약이 출시될 때까지 v2에서 비활성화

모델 리비전은 `bffb3df5a29440629464e5e839f4d214c8714c3d`이며 두 대형 파일은 크기와 SHA-256을 모델 적재 전에 다시 검사합니다. CPU는 기존 low-memory loader를 유지합니다. CUDA/MPS는 해당 native pack과 실제 장치 검증 증거가 있을 때만 카탈로그에서 활성화합니다.

## 테스트

최소 서버 테스트 의존성을 격리 경로에 설치한 뒤 실행합니다. release runtime은 `requirements.lock` 전체를 사용합니다.

```sh
PYTHONPATH=/path/to/test-deps python3 -m unittest discover \
  -s src/VoxCPM2Sidecar/tests -p 'test_*.py' -v
python3 -m unittest tools.test_build_voxcpm2_runtime_pack -v
```

실제 pack 생성과 native 합성 명령은 루트의 `VOXCPM2_RUNTIME_PACK_RELEASE.md`를 따릅니다. 모델 가중치, Python runtime, 캐시, 로그와 사용자 상태는 소스 ZIP/Git bundle에 넣지 않습니다.
