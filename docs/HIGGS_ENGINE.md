# Higgs Audio v3 Engine Setup

Higgs Audio v3 is the primary TTS engine in SupertonicVox. It requires separate runtime installation.

## Overview

- **Model**: Higgs Audio v3 TTS 4B (GGUF q8_0 quantization, 5.1 GB)
- **Backend**: audio.cpp server (CPU or CUDA GPU)
- **Server**: Loopback-only (127.0.0.1:8088-8098), no cloud connection
- **License**: Boson Higgs TTS 3 Research and Non-Commercial (see Creator Use Grant terms at https://bosonai.com)

## Hardware Requirements

### GPU (CUDA)
- NVIDIA GPU with CUDA Compute Capability 6.0+
- nvidia-smi available on PATH
- CUDA runtime installed
- Peak VRAM: ~7.8 GB on RTX 4060 Ti

### CPU
- Intel/AMD x64 processor
- Minimum 12 GB available commit memory (system paging)
- Generate time: 30-120 seconds per chunk (CPU dependent)

## Installation

### Step 1: Prepare Runtime Directory

By default, the app looks for the Higgs runtime in:

```
%LOCALAPPDATA%\SupertonicVox\higgs\
```

Alternatively, place it next to the executable:

```
SupertonicVox.exe
HiggsAudioV3\
```

### Step 2: Download audio.cpp Server

Download from https://github.com/0xShug0/audio.cpp/releases

1. **For CUDA GPU** (recommended):
   - Download `audio-cpp-<version>-windows-x64-cuda.zip`
   - Extract to `HiggsAudioV3\gpu\` or `HiggsAudioV3\cuda\`
   
2. **For CPU**:
   - Download `audio-cpp-<version>-windows-x64.zip`
   - Extract to `HiggsAudioV3\cpu\`

The app tries GPU first, then CPU fallback.

### Step 3: Download Model

Download the GGUF model:

```
https://huggingface.co/audio-cpp/audio.cpp-gguf/resolve/main/Higgs-Audio-v3-TTS-4B-GGUF/higgs-audio-v3-tts-4b-q8_0.gguf
```

Place in:

```
HiggsAudioV3\models\Higgs-Audio-v3-TTS-4B-GGUF\higgs-audio-v3-tts-4b-q8_0.gguf
```

File size: **5,095,354,048 bytes** (5.1 GB)

### Step 4: Add Voice Reference Audio (Optional)

Custom voices require:
1. Reference audio file: `voices\<voice_id>.wav` (PCM16 mono 24 kHz, 5-20 seconds)
2. Reference text: `voices\<voice_id>.txt` (plain UTF-8 text, under 100 chars for low-memory mode)

Example:

```
voices/alice.wav
voices/alice.txt (contains: "안녕하세요 테스트입니다")
```

The app discovers voices from the `voices\` directory. No hardcoded list required.

## Folder Structure

```
HiggsAudioV3/
  gpu/
    audiocpp_server.exe      (optional, CUDA version)
  cuda/
    audiocpp_server.exe      (optional, alternative CUDA path)
  cpu/
    audiocpp_server.exe      (required for CPU fallback)
  models/
    Higgs-Audio-v3-TTS-4B-GGUF/
      higgs-audio-v3-tts-4b-q8_0.gguf
  voices/                     (optional, user voices)
    alice.wav
    alice.txt
    bob.wav
    bob.txt
  cache/
    samples/                  (auto-created, sample cache)
    voice_anchors/            (auto-created, voice continuity)
  logs/
    higgs_server_integrated.log  (auto-created)
```

## Quality Presets

Three quality/speed trade-offs (in Korean UI: "빠른 생성", "균형", "고품질"):

| Setting | max_tokens | temperature | top_k | top_p | Use case |
|---------|-----------|-------------|-------|-------|----------|
| Fast | 1200 | 0.58 | 16 | 0.72 | Quick preview, real-time |
| Balanced | 1600 | 0.62 | 20 | 0.76 | Default, good quality |
| High Quality | 2048 | 0.66 | 24 | 0.80 | Best quality, slower |

The app automatically retries with `max_tokens * 2` (up to 4096) if the server runs out of context.

## Text Processing

- Chunk size: <=200 characters per API call
- Chunks merged with silent gaps (controllable via UI pause slider)
- Seed: Fixed at 42 by default (deterministic output)
- Voice anchor: First 5-second reference synthesis, cached for voice consistency

## Troubleshooting

### Server won't start
- Check `logs\higgs_server_integrated.log`
- Verify `audiocpp_server.exe` matches your platform (32-bit .exe on 32-bit system = failure)
- Ensure model file is 5,095,354,048 bytes exactly

### "No available port" error
- Ports 8088-8098 are in use. Close other applications or change port range in code.

### Out of memory (CPU)
- Reduce system load (close browser, other apps)
- Restart Windows to reclaim virtual memory pages
- Use Low-Memory reference mode (auto-enabled on fallback)
- Increase Windows pagefile size (System > Advanced > Virtual Memory)

### CUDA errors then CPU fallback
- Normal on first run; GPU memory is allocated and cached
- Subsequent runs reuse cached allocations (no fallback)

### Voice reference validation errors
- Check WAV format: must be PCM16 (16-bit signed), mono, 24000 Hz
- Use ffmpeg to reformat:
  ```bash
  ffmpeg -i input.wav -acodec pcm_s16le -ac 1 -ar 24000 output.wav
  ```
- Check duration: 5-20 seconds required

## Performance Notes

- Peak VRAM (CUDA): ~7.8 GB (RTX 4060 Ti)
- Peak RAM (CPU): depends on model quantization + system pressure
- Warm-up: First chunk slower (GPU upload, model load); subsequent chunks faster
- Seed determinism: Same seed + voice + quality = same output (for anchor consistency)

## License

Higgs Audio v3 model subject to Boson's license. Respect the Creator Use Grant terms:
- Free for credited monetized content ("Boson AI's Higgs Audio" attribution required)
- Products and hosted APIs need separate agreement
- Cloning/fine-tuning without consent prohibited

See https://bosonai.com for full terms.
