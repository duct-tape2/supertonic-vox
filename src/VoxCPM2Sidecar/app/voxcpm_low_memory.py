"""Windows CPU low-memory loader for the pinned VoxCPM 2.0.3 wheel.

The upstream loader first allocates a complete random-initialized model and
then opens a second, memory-mapped copy of the checkpoint.  A 32 GiB Windows
machine with a modest page file can therefore fail before inference even
though the resident model itself fits.  This module keeps the official model
classes and checkpoint format, but constructs parameters on PyTorch's meta
device and assigns the verified checkpoint tensors directly.
"""

from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
from typing import Any


PINNED_VOXCPM_VERSION = "2.0.3"


def install_low_memory_cpu_loader() -> None:
    """Install the guarded loader once for this sidecar process."""

    installed_version = importlib.metadata.version("voxcpm")
    if installed_version != PINNED_VOXCPM_VERSION:
        raise RuntimeError(
            f"low-memory loader requires voxcpm=={PINNED_VOXCPM_VERSION}, "
            f"found {installed_version}"
        )

    import torch
    from safetensors.torch import load_file
    from transformers import LlamaTokenizerFast
    from voxcpm.model.voxcpm2 import (
        AudioVAEV2,
        SAFETENSORS_AVAILABLE,
        VoxCPM2Model,
        VoxCPMConfig,
    )

    if getattr(VoxCPM2Model, "_supertonic_low_memory_loader", False):
        return
    if not SAFETENSORS_AVAILABLE:
        raise RuntimeError("the pinned VoxCPM2 runtime requires safetensors")

    @classmethod
    def from_local_low_memory(
        cls,
        path: str,
        optimize: bool = True,
        training: bool = False,
        device: str | None = None,
        lora_config: Any = None,
    ):
        if training:
            raise RuntimeError("the portable CPU runtime does not support training")
        if lora_config is not None:
            raise RuntimeError("the portable CPU runtime does not support LoRA")
        if (device or "cpu").lower() != "cpu":
            raise RuntimeError("the portable low-memory loader is CPU-only")

        model_dir = Path(path).resolve(strict=True)
        with (model_dir / "config.json").open("r", encoding="utf-8") as source:
            config = VoxCPMConfig.model_validate_json(source.read())
        # The resolved local tree is checked against the pinned release hashes by server.py.
        tokenizer = LlamaTokenizerFast.from_pretrained(  # nosec B615
            str(model_dir),
            local_files_only=True,
        )

        # All persistent parameters and buffers are present in the pinned
        # checkpoints.  Meta construction avoids allocating a disposable
        # float32/random copy of the 2B-parameter model.
        with torch.device("meta"):
            audio_vae = AudioVAEV2(config=config.audio_vae_config)
            model = cls(config, tokenizer, audio_vae, lora_config=None, device="cpu")

        audio_safetensors = model_dir / "audiovae.safetensors"
        audio_pth = model_dir / "audiovae.pth"
        if audio_safetensors.is_file():
            audio_state = load_file(str(audio_safetensors), device="cpu")
        elif audio_pth.is_file():
            audio_checkpoint = torch.load(
                str(audio_pth),
                map_location="cpu",
                weights_only=True,
            )
            audio_state = audio_checkpoint.get("state_dict", audio_checkpoint)
        else:
            raise FileNotFoundError(f"AudioVAE checkpoint not found in {model_dir}")

        model_path = model_dir / "model.safetensors"
        if not model_path.is_file():
            raise FileNotFoundError(f"model.safetensors not found in {model_dir}")
        state = load_file(str(model_path), device="cpu")
        for name, value in audio_state.items():
            state[f"audio_vae.{name}"] = value

        # The pinned model was verified to contain exactly every one of the
        # 889 state entries.  strict=True prevents a future or damaged layout
        # from leaving unusable meta tensors behind.
        model.load_state_dict(state, strict=True, assign=True)

        # Rotary caches are deliberately non-persistent buffers, so they are
        # not part of the otherwise exact checkpoint.  Recreate these three
        # small buffer-only modules normally on CPU after parameter assignment.
        rope_owners = (
            model.base_lm,
            model.feat_encoder.encoder,
            model.feat_decoder.estimator.decoder,
        )
        for owner in rope_owners:
            rope = owner.rope_emb
            owner.rope_emb = rope.__class__(rope.config)

        remaining_meta = [
            name
            for name, value in list(model.named_parameters()) + list(model.named_buffers())
            if value.is_meta
        ]
        if remaining_meta:
            raise RuntimeError(
                "checkpoint did not materialize all model tensors: "
                + ", ".join(remaining_meta[:10])
            )

        return model.eval().optimize(disable=not optimize)

    VoxCPM2Model.from_local = from_local_low_memory
    VoxCPM2Model._supertonic_low_memory_loader = True
