# VoxCPM2 모델 다운로드 복구 경로

이 폴더의 스크립트는 사내 WebKeeper가 Hugging Face와 ModelScope의 GET 요청을 차단하는 환경에서 VoxCPM2의 공식 파일을 재현 가능하게 설치한다. 브라우저나 브라우저 자동화는 사용하지 않는다.

## 안전 조건

- Hugging Face 리비전은 bffb3df5a29440629464e5e839f4d214c8714c3d로 고정한다.
- ModelScope 미러 리비전은 04123d1676da3fd7e1f2d4ed847408950c9cf26d로 고정한다.
- ModelScope는 공식 DNS로 IP를 구한 뒤 IP 주소로 직접 요청한다. 이 요청은 호스트명 TLS 검증을 우회하므로 수신 파일을 신뢰하지 않는다.
- 모든 파일은 고정된 크기와 SHA-256을 통과해야만 최종 이름으로 원자적으로 이동한다.
- HF의 HTTPS HEAD에서 목표 리비전과 ETag를 다시 확인한다.
- 대형 파일은 ModelScope를 먼저 속도 측정한다. 기준보다 느리거나 실패하면 HF HEAD가 발급한 cas-bridge.xethub.hf.co 서명 URL로 전환한다.
- HF 서명 URL이 만료되거나 끊기면 새 URL을 발급해 같은 .part 파일에서 이어받는다.

## 쓰기 없는 연결 점검

PowerShell에서 다음 명령을 실행한다.

    Set-ExecutionPolicy -Scope Process Bypass
    .\download_voxcpm2_model.ps1 -ProbeOnly

이 모드는 모델 파일을 만들지 않는다. ModelScope 메타데이터는 메모리에서 검사하고 파일 Range 응답은 NUL로 버린다.

## 실제 설치

다른 다운로드 프로세스가 같은 모델 폴더를 사용하지 않는지 먼저 확인한다. 이후 staging 대상 폴더를 명시한다.

    .\download_voxcpm2_model.ps1 -DestinationDirectory "C:\path\to\VoxCPM2Local\models\VoxCPM2"

기본 ModelScope 속도 기준은 초당 2 MiB다. 필요할 때만 다음처럼 바꿀 수 있다.

    .\download_voxcpm2_model.ps1 -DestinationDirectory "C:\path\to\VoxCPM2Local\models\VoxCPM2" -MinimumModelScopeBytesPerSecond 1048576

설치 파일은 목적지의 .staging 아래에서 먼저 완성된다. 검증을 통과한 일곱 파일만 목적지 루트로 이동한다. 이미 존재하는 최종 파일은 전체 SHA-256이 맞을 때만 재사용하며, 잘못된 최종 파일은 자동으로 덮어쓰지 않는다.

## 필수 런타임 파일

- config.json
- special_tokens_map.json
- tokenization_voxcpm2.py
- tokenizer.json
- tokenizer_config.json
- audiovae.pth
- model.safetensors

합계는 4,960,722,408바이트다. README.md와 .gitattributes는 런타임에 필요하지 않아 받지 않는다.

파일별 출처, 크기, SHA-256, HF Git blob ETag와 Xet 해시는 voxcpm2-model-provenance.json에 고정되어 있다.

## 관측된 네트워크 특성

- ModelScope 도메인 GET은 211바이트 WebKeeper 차단 페이지를 반환했다.
- 2026-07-14 기준 www.modelscope.cn은 47.251.62.57로 해석되었고, IP 직접 파일 API는 정상 동작했다.
- ModelScope 대형 파일 Range는 약 0.31~0.35 MB/s였다.
- HF cas-bridge의 64 MiB Range는 약 4.61 MB/s였고 HTTP 206 및 resume을 지원했다.
- ModelScope 서버는 Range에 Content-Range를 주면서 HTTP 200을 반환하므로 그 서버 자체의 resume은 사용하지 않는다. 부분 파일 이어받기는 HF CAS에서만 수행한다.

## 무결성 근거

ModelScope의 작은 런타임 파일을 메모리로 읽어 계산한 Git blob SHA-1이 목표 HF 리비전의 X-Linked-ETag와 모두 일치했다. 두 가중치는 HF HEAD의 X-Linked-ETag가 계획에 고정된 SHA-256과 일치했다. 실제 설치 시에는 이 교차검증 값에 더해 로컬 전체 파일 SHA-256을 다시 계산한다.
