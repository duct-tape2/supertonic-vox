baseline-overlay
================

This directory contains only the original files that the hardened release replaced.
Run restore_baseline.ps1 from this directory after closing the application.

The script restores each original file atomically, removes files listed in
ADDED_HARDENED_FILES.txt, and verifies size and SHA-256 against
BASELINE_OVERLAY_MANIFEST.json.

The original executable is version 2.0.0.0 and has SHA-256:
1DBA58535C8B45B0980E9B0537DA08A80C646A577D442A3120CDE582FE3C2516

The overlay itself remains after restoration so the operation is recoverable.
