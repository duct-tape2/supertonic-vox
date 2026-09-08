# Model provenance

## VoxCPM2

- Upstream: `OpenBMB/VoxCPM`
- License: Apache-2.0, included as `licenses/VoxCPM_Apache-2.0.txt`
- Fixed revision: `bffb3df5a29440629464e5e839f4d214c8714c3d`
- `model.safetensors`: 4,580,080,592 bytes; SHA-256 `f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d`
- `audiovae.pth`: 376,951,122 bytes; SHA-256 `94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1`
- License source: https://github.com/OpenBMB/VoxCPM/blob/main/LICENSE

## Supertonic 3

- Upstream: `Supertone/supertonic-3`
- Model license: BigScience Open RAIL-M, included as `licenses/Supertonic-3_OpenRAIL-M.txt`
- Python package: supertonic 1.3.1, MIT license included as `licenses/Supertonic-Python_MIT.txt`
- Local model revision: `0d6a2bed57a1c6ec4f7acf77d688c62337655dd1db2a5582b2b2d55c17f5efae`
- The local revision is SHA-256 over sorted `relative-path NUL size NUL sha256 LF` records for the six ONNX/config files and ten voice-style files.
- Model license source: https://huggingface.co/Supertone/supertonic-3/blob/main/LICENSE

The exact Hugging Face download commit of the already-present Supertonic files could not be proven from local metadata. The immutable local hash set, rather than an unverified upstream commit claim, is therefore the release identity.

## Change notice

The model weights were not modified. This project changes the desktop orchestrator and adds authenticated wrappers, manifests and operational restrictions. Any future modified model file must carry a prominent change notice and continue to enforce at least the OpenRAIL-M use restrictions.
