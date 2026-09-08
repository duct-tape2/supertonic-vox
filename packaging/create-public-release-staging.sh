#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 [--output PATH]" >&2
  exit 2
}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
OUTPUT_ROOT=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || usage
      OUTPUT_ROOT=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

for command in cmp git python3 tar; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 4
  }
done

cd "$REPO_ROOT"
SOURCE_COMMIT=$(git rev-parse HEAD)
SHORT_COMMIT=$(git rev-parse --short=12 HEAD)
if [ -z "$OUTPUT_ROOT" ]; then
  OUTPUT_ROOT="$REPO_ROOT/artifacts/public-release-staging/$SHORT_COMMIT"
fi
OUTPUT_ROOT=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT_ROOT")

[ -z "$(git status --porcelain --untracked-files=no)" ] || {
  echo "Tracked changes are not committed; refusing commit-bound staging." >&2
  exit 4
}

REQUIRED_INPUTS=(
  PUBLIC_README.md
  PUBLIC_BUILD_AND_RELEASE.md
  VOXCPM2_RUNTIME_PACK_RELEASE.md
  FINAL_RELEASE_EVIDENCE.md
  SOURCE_LICENSE_PENDING.md
  packaging/create-public-release-staging.sh
  tools/release_history_audit.py
  tools/release_history_rules.json
  tools/svx_zip_profile.py
  tools/release_open_gates.py
  tools/final_release_evidence.py
  tools/public_staging_contract.py
  packaging/release-open-gates.json
  packaging/release-gate-traceability.json
  packaging/final-release-signing-policy.json
  tools/windows_msi_contract.py
  packaging/windows-installer-contract.json
  packaging/windows-signing-policy.json
  tools/macos_release_contract.py
  packaging/macos-release-contract.json
  packaging/macos-signing-policy.json
)
for tracked_input in "${REQUIRED_INPUTS[@]}"; do
  git cat-file -e "$SOURCE_COMMIT:$tracked_input" 2>/dev/null || {
    echo "Staging input is not present in the audited commit: $tracked_input" >&2
    exit 4
  }
done

[ ! -e "$OUTPUT_ROOT" ] || {
  echo "Output already exists: $OUTPUT_ROOT" >&2
  exit 4
}

DOTNET="$REPO_ROOT/.tools/dotnet/dotnet"
[ -x "$DOTNET" ] || DOTNET=$(command -v dotnet || true)
[ -n "$DOTNET" ] && [ -x "$DOTNET" ] || {
  echo "The pinned .NET SDK is unavailable." >&2
  exit 4
}
EXPECTED_DOTNET_VERSION=$(python3 -c 'import json; print(json.load(open("global.json", encoding="utf-8"))["sdk"]["version"])')
[ "$("$DOTNET" --version)" = "$EXPECTED_DOTNET_VERSION" ] || {
  echo "The active .NET SDK does not match global.json." >&2
  exit 4
}

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/svx-public-staging.XXXXXX")
WORK_ROOT=$(cd "$WORK_ROOT" && pwd -P)
snapshot_custody() {
  python3 - "$REPO_ROOT" "$1" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unicodedata

repo = Path(sys.argv[1])
output = Path(sys.argv[2])
completed = subprocess.run(
    ["git", "-C", str(repo), "ls-files", "-z", "--others", "--exclude-standard", "--",
     "project.bundle", "packaging/payload_support"],
    check=True,
    capture_output=True,
)
records = []
for raw in completed.stdout.split(b"\0"):
    if not raw:
        continue
    relative = raw.decode("utf-8", errors="strict")
    normalized = unicodedata.normalize("NFC", relative).casefold()
    if normalized != "project.bundle" and not normalized.startswith("packaging/payload_support/"):
        raise SystemExit(f"Unexpected custody path: {relative}")
    path = repo / relative
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    records.append({"path": relative, "sha256": digest.hexdigest(), "sizeBytes": size})
output.write_text(
    json.dumps(sorted(records, key=lambda item: unicodedata.normalize("NFC", item["path"]).casefold()),
               ensure_ascii=False, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}
CUSTODY_BEFORE="$WORK_ROOT/custody-before.json"
CUSTODY_AFTER="$WORK_ROOT/custody-after.json"
snapshot_custody "$CUSTODY_BEFORE"
cleanup() {
  rm -rf "$WORK_ROOT"
  if [ "${PUBLISHED:-0}" != "1" ]; then
    rm -rf "$OUTPUT_TEMP"
  fi
}
trap cleanup EXIT INT TERM

TREE="$WORK_ROOT/source"
VALIDATION_TREE="$WORK_ROOT/validation"
EVIDENCE="$WORK_ROOT/evidence"
OUTPUT_PARENT=$(dirname "$OUTPUT_ROOT")
OUTPUT_NAME=$(basename "$OUTPUT_ROOT")
OUTPUT_TEMP="$OUTPUT_PARENT/.${OUTPUT_NAME}.partial"
mkdir -p "$TREE" "$VALIDATION_TREE" "$EVIDENCE" "$OUTPUT_PARENT"
[ ! -e "$OUTPUT_TEMP" ] || {
  echo "Partial output already exists: $OUTPUT_TEMP" >&2
  exit 4
}

ALLOWLIST=(
  .gitignore
  .config/dotnet-tools.json
  .github/workflows/cross-platform-foundation.yml
  .github/workflows/windows-release.yml
  .github/workflows/macos-release.yml
  Directory.Build.props
  global.json
  SupertonicVox.CrossPlatform.slnx
  src/CrossPlatform
  src/VoxCPM2Sidecar/README.md
  src/VoxCPM2Sidecar/app/protocol_v2.py
  src/VoxCPM2Sidecar/app/server_v2.py
  src/VoxCPM2Sidecar/app/voxcpm_low_memory.py
  src/VoxCPM2Sidecar/requirements.lock
  src/VoxCPM2Sidecar/tests
  src/VoxCPM2Sidecar/tools/voxcpm2-model-provenance.json
  src/VoxCPM2Sidecar/voices/presets.json
  tests/SupertonicVox.Core.Tests
  tools/DesktopSmoke
  tools/SupertonicSmoke
  tools/DevelopmentCatalogSigner
  tools/CatalogReleaseVerifier
  tools/FakeVoxSidecar
  tools/VoxRuntimePackSmoke
  tools/build_voxcpm2_runtime_pack.py
  tools/package_voxcpm2_runtime_pack.py
  tools/test_build_voxcpm2_runtime_pack.py
  tools/test_package_voxcpm2_runtime_pack.py
  tools/fetch_supertonic_model.py
  tools/release_privacy_gate.py
  tools/release_privacy_rules.json
  tools/svx_zip_profile.py
  tools/test_fetch_supertonic_model.py
  tools/test_release_privacy_gate.py
  tools/release_history_audit.py
  tools/release_history_rules.json
  tools/test_release_history_audit.py
  tools/release_open_gates.py
  tools/test_release_open_gates.py
  tools/final_release_evidence.py
  tools/test_final_release_evidence.py
  tools/public_staging_contract.py
  tools/test_public_staging_contract.py
  tools/repository_privacy_posture.py
  tools/test_repository_privacy_posture.py
  tools/test_generate_file_manifest.py
  tools/test_version_contract.py
  tools/windows_preflight_contract.py
  tools/test_windows_preflight_contract.py
  tools/windows_msi_contract.py
  tools/test_windows_msi_contract.py
  tools/macos_release_contract.py
  tools/test_macos_release_contract.py
  packaging/build-macos-release.sh
  packaging/build-macos-signed-release.sh
  packaging/macos-release-contract.json
  packaging/macos-signing-policy.json
  packaging/macos-release-evidence.schema.json
  packaging/build-windows-release.ps1
  packaging/build-windows-msi.ps1
  packaging/generate_file_manifest.py
  packaging/windows-publish-allowlist.json
  packaging/windows-installer-contract.json
  packaging/windows-signing-policy.json
  packaging/windows-msi-evidence.schema.json
  packaging/windows
  packaging/release-open-gates.json
  packaging/release-gate-traceability.json
  packaging/final-release-signing-policy.json
  packaging/create-public-release-staging.sh
  packaging/macos
  PUBLIC_README.md
  PUBLIC_BUILD_AND_RELEASE.md
  MACOS_RELEASE_CHECKLIST.md
  CATALOG_TRUST_ROOT_RELEASE.md
  RUNTIME_PACK_SECURITY.md
  VOXCPM2_RUNTIME_PACK_RELEASE.md
  FINAL_RELEASE_EVIDENCE.md
  SOURCE_LICENSE_PENDING.md
  THIRD_PARTY_NOTICES.md
  licenses/Supertonic-v3.0.0_MIT.txt
  licenses/Supertonic-3_OpenRAIL-M.txt
  licenses/Supertonic-Python_MIT.txt
  licenses/VoxCPM_Apache-2.0.txt
)
python3 - "$REPO_ROOT" "$SOURCE_COMMIT" <<'PY'
import os
from pathlib import Path
import subprocess
import sys

environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
completed = subprocess.run(
    ["git", "--no-replace-objects", "-c", "core.quotepath=false", "-C", sys.argv[1],
     "ls-tree", "-rz", "--full-tree", sys.argv[2]],
    check=False,
    capture_output=True,
    env=environment,
)
if completed.returncode != 0:
    raise SystemExit("Unable to inspect source commit modes")
for record in completed.stdout.split(b"\0"):
    if not record:
        continue
    metadata, path = record.split(b"\t", 1)
    mode = metadata.split(b" ", 1)[0]
    if mode in {b"120000", b"160000"}:
        shown = path.decode("utf-8", errors="backslashreplace")
        raise SystemExit(f"Source commit contains prohibited Git mode {mode.decode()}: {shown}")
PY
git archive --format=tar "$SOURCE_COMMIT" "${ALLOWLIST[@]}" | tar -xf - -C "$TREE"
mv "$TREE/PUBLIC_README.md" "$TREE/README.md"
mv "$TREE/PUBLIC_BUILD_AND_RELEASE.md" "$TREE/BUILD_AND_RELEASE.md"

FORBIDDEN_ROOTS=(
  AI_START_HERE.md
  CURRENT_STATE_INVENTORY.md
  project.bundle
  packaging/payload_support
  offline_extracted
)
for forbidden in "${FORBIDDEN_ROOTS[@]}"; do
  { [ ! -e "$TREE/$forbidden" ] && [ ! -L "$TREE/$forbidden" ]; } || {
    echo "Forbidden recovery path entered public staging: $forbidden" >&2
    exit 4
  }
done

python3 - "$TREE" <<'PY'
import os
from pathlib import Path
import stat
import sys
import unicodedata

root = Path(sys.argv[1])
forbidden = {
    "project.bundle",
    "packaging/payload_support",
}
for current, directories, files in os.walk(root, followlinks=False):
    for name in [*directories, *files]:
        path = Path(current) / name
        relative = path.relative_to(root).as_posix()
        normalized = unicodedata.normalize("NFC", relative).casefold()
        if any(normalized == value or normalized.startswith(value + "/") for value in forbidden):
            raise SystemExit(f"Forbidden normalized recovery path entered staging: {relative}")
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise SystemExit(f"Unsafe staged filesystem entry: {path.relative_to(root)}")
PY

git -C "$TREE" init --quiet --initial-branch=main
git -C "$TREE" add -- \
  .gitignore \
  .config \
  .github \
  Directory.Build.props \
  global.json \
  SupertonicVox.CrossPlatform.slnx \
  src \
  tests \
  tools \
  packaging \
  README.md \
  BUILD_AND_RELEASE.md \
  MACOS_RELEASE_CHECKLIST.md \
  CATALOG_TRUST_ROOT_RELEASE.md \
  RUNTIME_PACK_SECURITY.md \
  VOXCPM2_RUNTIME_PACK_RELEASE.md \
  FINAL_RELEASE_EVIDENCE.md \
  SOURCE_LICENSE_PENDING.md \
  THIRD_PARTY_NOTICES.md \
  licenses
SOURCE_DATE=$(git show -s --format=%cI "$SOURCE_COMMIT")
SOURCE_EPOCH=$(git show -s --format=%ct "$SOURCE_COMMIT")
GIT_AUTHOR_NAME="SupertonicVox Release Engineering" \
GIT_AUTHOR_EMAIL="release-engineering@example.invalid" \
GIT_COMMITTER_NAME="SupertonicVox Release Engineering" \
GIT_COMMITTER_EMAIL="release-engineering@example.invalid" \
GIT_AUTHOR_DATE="$SOURCE_DATE" \
GIT_COMMITTER_DATE="$SOURCE_DATE" \
  git -C "$TREE" commit --quiet -m "public staging from $SHORT_COMMIT"
STAGING_COMMIT=$(git -C "$TREE" rev-parse HEAD)
[ -z "$(git -C "$TREE" status --porcelain)" ] || {
  echo "Frozen staging commit is dirty." >&2
  exit 4
}

git -C "$TREE" archive --format=tar "$STAGING_COMMIT" | tar -xf - -C "$VALIDATION_TREE"
BUNDLE="$WORK_ROOT/SupertonicVox-public-staging.bundle"
SOURCE_ARCHIVE="$WORK_ROOT/SupertonicVox-public-staging-source.zip"
python3 "$VALIDATION_TREE/tools/public_staging_contract.py" create-zip \
  --source "$VALIDATION_TREE" \
  --output "$SOURCE_ARCHIVE" \
  --epoch "$SOURCE_EPOCH" \
  --prefix SupertonicVox/
python3 "$VALIDATION_TREE/tools/release_privacy_gate.py" "$SOURCE_ARCHIVE" \
  --release-commit "$SOURCE_COMMIT" \
  --report "$EVIDENCE/source-archive-privacy-report.json"
python3 "$VALIDATION_TREE/tools/release_privacy_gate.py" --self-test
python3 "$VALIDATION_TREE/tools/release_history_audit.py" --self-test
python3 "$VALIDATION_TREE/tools/repository_privacy_posture.py" --repo "$TREE"
python3 -m unittest discover -s "$VALIDATION_TREE/tools" -p 'test_*.py' -v \
  | tee "$EVIDENCE/python-tests.txt"
"$DOTNET" restore "$VALIDATION_TREE/SupertonicVox.CrossPlatform.slnx" --locked-mode
"$DOTNET" build "$VALIDATION_TREE/SupertonicVox.CrossPlatform.slnx" --configuration Release --no-restore \
  | tee "$EVIDENCE/build.txt"
"$DOTNET" test "$VALIDATION_TREE/tests/SupertonicVox.Core.Tests/SupertonicVox.Core.Tests.csproj" \
  --configuration Release --no-build \
  | tee "$EVIDENCE/tests.txt"
[ -z "$(git -C "$TREE" status --porcelain)" ] || {
  echo "Validation modified the frozen staging repository." >&2
  exit 4
}

git -C "$TREE" bundle create "$BUNDLE" refs/heads/main
python3 "$VALIDATION_TREE/tools/release_history_audit.py" "$TREE" \
  --bundle "$BUNDLE" \
  --report "$EVIDENCE/history-audit.json"

python3 - "$EVIDENCE/staging-evidence.json" "$EVIDENCE/history-audit.json" "$SOURCE_COMMIT" "$STAGING_COMMIT" "$SOURCE_ARCHIVE" "$VALIDATION_TREE/packaging/release-open-gates.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

def identity(path):
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"name": path.name, "sha256": digest.hexdigest(), "sizeBytes": size}

payload = {
    "schemaVersion": 1,
    "releaseEligible": False,
    "sourceCommit": sys.argv[3],
    "stagingCommit": sys.argv[4],
    "bundle": json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))["bundle"] | {"audit": None},
    "sourceArchive": identity(sys.argv[5]),
    "openGates": json.loads(Path(sys.argv[6]).read_text(encoding="ascii"))["requiredOpenGateIds"],
}
payload["bundle"].pop("audit")
Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "$VALIDATION_TREE/tools/release_open_gates.py" validate-evidence \
  --contract "$VALIDATION_TREE/packaging/release-open-gates.json" \
  --evidence "$EVIDENCE/staging-evidence.json"
python3 "$VALIDATION_TREE/tools/release_open_gates.py" validate-traceability \
  --contract "$VALIDATION_TREE/packaging/release-open-gates.json" \
  --traceability "$VALIDATION_TREE/packaging/release-gate-traceability.json"
python3 "$VALIDATION_TREE/tools/public_staging_contract.py" \
  validate-evidence \
  --gate-contract "$VALIDATION_TREE/packaging/release-open-gates.json" \
  --evidence "$EVIDENCE/staging-evidence.json"

mkdir "$OUTPUT_TEMP"
cp -p "$BUNDLE" "$SOURCE_ARCHIVE" "$OUTPUT_TEMP/"
cp -p "$EVIDENCE"/* "$OUTPUT_TEMP/"
python3 - "$OUTPUT_TEMP/staging-evidence.json" "$OUTPUT_TEMP" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

def identity(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size

evidence = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(sys.argv[2])
for key in ("bundle", "sourceArchive"):
    expected = evidence[key]
    actual_hash, actual_size = identity(root / expected["name"])
    if (actual_hash, actual_size) != (expected["sha256"], expected["sizeBytes"]):
        raise SystemExit(f"Delivered {key} identity mismatch")
PY
DELIVERED_REPOSITORY="$WORK_ROOT/delivered-repository"
git clone --quiet "$OUTPUT_TEMP/$(basename "$BUNDLE")" "$DELIVERED_REPOSITORY"
python3 "$VALIDATION_TREE/tools/release_history_audit.py" "$DELIVERED_REPOSITORY" \
  --bundle "$OUTPUT_TEMP/$(basename "$BUNDLE")" \
  --report "$OUTPUT_TEMP/delivered-history-audit.json"
snapshot_custody "$CUSTODY_AFTER"
cmp -s "$CUSTODY_BEFORE" "$CUSTODY_AFTER" || {
  echo "User-owned custody artifact identity changed during staging." >&2
  exit 4
}
mv "$OUTPUT_TEMP" "$OUTPUT_ROOT"
PUBLISHED=1

echo "Clean public-source staging created: $OUTPUT_ROOT"
echo "Release eligible: false"
