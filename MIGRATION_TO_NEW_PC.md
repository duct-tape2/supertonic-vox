# Migration to a new PC

1. Place every `.zip.001` through the final numbered part, `PARTS_SHA256.txt`, `PARTS_MANIFEST.json`, `verify_and_extract.ps1` and `압축풀기.cmd` in one local directory.
2. Run `압축풀기.cmd`. The script verifies names, count, sizes and SHA-256 before combining anything.
3. Choose a destination with at least 20 GB free. Korean characters and spaces in the path are supported.
4. Keep the extracted `PRIVATE_USER_STATE` private. It can contain scripts, voice recordings, generated audio and logs.
5. Start `Supertonic + VoxCPM2.exe`. Windows SmartScreen may warn because this release is unsigned.
6. For development, extract the AI handoff ZIP separately and run `git bundle verify project.bundle`.

Hardware baseline: Windows 10/11 x64, CPU execution, at least 32 GB RAM. Windows 11 fully patched is recommended for the .NET 10 hardened executable. GPU/CUDA packaging, public installer, automatic updater and public service hosting are not included.

If baseline restoration is required, run `baseline-overlay/restore_baseline.ps1` from the extracted application root. It removes the listed hardened additions, restores the original files, and verifies the baseline overlay manifest.

For local verification on macOS, keep all files in one directory and run `sh restore_001_on_mac.sh`, followed by `sh verify_and_extract_mac.sh`. This verifies custody and extraction only; Windows build, execution, signing and real-engine synthesis still require Windows 10/11 x64, with fully patched Windows 11 recommended.
