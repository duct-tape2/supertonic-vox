# Third-party notices

## Supertonic source

- Upstream: `supertone-inc/supertonic`
- Pinned tag and commit: `v3.0.0`, `5379cc4e4297cec249a8a71283fc44d55ec327f1`
- License: MIT
- Vendored C# inference source: `src/CrossPlatform/SupertonicVox.Core/ThirdParty/SupertonicV3/Helper.cs`
- Local changes: cancellation propagation, ONNX `RunOptions.Terminate`, maximum predicted duration, and deterministic disposal of inference sessions.

The retained license copy is `licenses/Supertonic-v3.0.0_MIT.txt`.

## Supertonic 3 model

- Upstream: `Supertone/supertonic-3`
- Pinned revision: `3cadd1ee6394adea1bd021217a0e650ede09a323`
- License: OpenRAIL-M
- Required files and SHA-256 values are pinned in `SupertonicModelManifest` and the development-signed embedded engine catalog. This development signature is not production release trust.

The retained license copy is `licenses/Supertonic-3_OpenRAIL-M.txt`. Model distribution must include the license, attribution, use restrictions, and modified-file notices required by OpenRAIL-M. This notice does not resolve ownership or approve public distribution of this repository.

## Other retained components

- VoxCPM/VoxCPM2 source and model materials: Apache License 2.0. See `licenses/VoxCPM_Apache-2.0.txt` and https://github.com/OpenBMB/VoxCPM.
- Legacy Supertonic Python package 1.3.1: MIT. See `licenses/Supertonic-Python_MIT.txt` and https://github.com/supertone-inc/supertonic-py.
- Newtonsoft.Json 13.0.3: MIT.
- HtmlAgilityPack 1.12.2: MIT.
- .NET runtime: Microsoft .NET terms and third-party notices included by self-contained publish.
- Portable Python packages: their license metadata and bundled license files remain in the private offline payload.

## OpenRAIL-M operational notice

Recipients must receive the full model license and Attachment A restrictions. Modified model files must be identified. The model must not be used for prohibited unlawful harm, harmful false information, non-consensual impersonation, discriminatory or exploitative decisions, medical advice, or prohibited justice/law-enforcement uses. Machine-generated material must be disclosed where the license requires it.

This notice is a convenience summary and does not replace the included licenses.
