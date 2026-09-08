from __future__ import annotations

import json
import os
from pathlib import Path

import torch
from safetensors import safe_open
from transformers import LlamaTokenizerFast

from voxcpm.model.voxcpm2 import AudioVAEV2, VoxCPM2Model, VoxCPMConfig


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models" / "VoxCPM2"


with (MODEL_DIR / "config.json").open("r", encoding="utf-8") as source:
    config = VoxCPMConfig.model_validate_json(source.read())
# Offline diagnostic for the same hash-pinned local model used by the server.
tokenizer = LlamaTokenizerFast.from_pretrained(  # nosec B615
    MODEL_DIR,
    local_files_only=True,
)

with torch.device("meta"):
    audio_vae = AudioVAEV2(config=config.audio_vae_config)
    model = VoxCPM2Model(config, tokenizer, audio_vae, device="cpu")

state = model.state_dict()
model_keys = set(state)
with safe_open(MODEL_DIR / "model.safetensors", framework="pt", device="cpu") as source:
    checkpoint_keys = set(source.keys())
audio_checkpoint = torch.load(MODEL_DIR / "audiovae.pth", map_location="cpu", weights_only=True)
audio_state = audio_checkpoint.get("state_dict", audio_checkpoint)
checkpoint_keys.update(f"audio_vae.{name}" for name in audio_state)

meta_parameters = [name for name, value in model.named_parameters() if value.is_meta]
meta_buffers = [name for name, value in model.named_buffers() if value.is_meta]
cpu_buffers = [name for name, value in model.named_buffers() if not value.is_meta]

print(
    json.dumps(
        {
            "parameter_count": sum(value.numel() for value in model.parameters()),
            "model_state_keys": len(model_keys),
            "checkpoint_keys": len(checkpoint_keys),
            "missing_keys": sorted(model_keys - checkpoint_keys),
            "unexpected_keys": sorted(checkpoint_keys - model_keys),
            "meta_parameter_count": len(meta_parameters),
            "meta_buffer_count": len(meta_buffers),
            "cpu_buffer_count": len(cpu_buffers),
            "meta_buffers": meta_buffers,
            "base_kv_cache_device": str(model.base_lm.kv_cache.kv_cache.device),
            "residual_kv_cache_device": str(model.residual_lm.kv_cache.kv_cache.device),
        },
        ensure_ascii=False,
        indent=2,
    )
)
