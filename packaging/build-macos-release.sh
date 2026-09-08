#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 --preflight-unsigned [options] | --capture-signing-policy [options] | --build-signed-candidate [options]" >&2
  exit 2
}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
if [ "${1:-}" = "--capture-signing-policy" ] || [ "${1:-}" = "--build-signed-candidate" ]; then
  exec "$SCRIPT_DIR/build-macos-signed-release.sh" "$@"
fi
MODE=""
OFFLINE_MODELS=0
MODEL_CACHE="$REPO_ROOT/artifacts/model-cache/supertonic-3"
OUTPUT_ROOT=""
PACKAGE_VERSION=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --preflight-unsigned)
      MODE="preflight-unsigned"
      shift
      ;;
    --offline-models)
      OFFLINE_MODELS=1
      shift
      ;;
    --model-cache)
      [ "$#" -ge 2 ] || usage
      MODEL_CACHE=$2
      shift 2
      ;;
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

[ "$MODE" = "preflight-unsigned" ] || {
  echo "Release mode is intentionally unavailable until the production trust root and signing identities exist." >&2
  usage
}
[ "$(uname -s)" = "Darwin" ] || {
  echo "macOS packaging requires a macOS build host." >&2
  exit 4
}
[ "$(uname -m)" = "arm64" ] || {
  echo "This package target requires an Apple Silicon build host." >&2
  exit 4
}

for command in git python3 hdiutil plutil shasum tar /usr/libexec/PlistBuddy; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 4
  }
done

cd "$REPO_ROOT"
PACKAGE_VERSION=$(python3 -c '
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
values = [node.text.strip() for node in root.findall(".//Version") if node.text and node.text.strip()]
if len(values) != 1:
    raise SystemExit("Directory.Build.props must contain exactly one Version")
print(values[0])
' "$REPO_ROOT/Directory.Build.props")
if [ -n "${SVX_PACKAGE_VERSION:-}" ] && [ "$SVX_PACKAGE_VERSION" != "$PACKAGE_VERSION" ]; then
  echo "SVX_PACKAGE_VERSION must match Directory.Build.props ($PACKAGE_VERSION)." >&2
  exit 4
fi
DOTNET="$REPO_ROOT/.tools/dotnet/dotnet"
[ -x "$DOTNET" ] || DOTNET=$(command -v dotnet || true)
[ -n "$DOTNET" ] && [ -x "$DOTNET" ] || {
  echo "The pinned .NET SDK is unavailable." >&2
  exit 4
}

RELEASE_COMMIT=$(git rev-parse HEAD)
SHORT_COMMIT=$(git rev-parse --short=12 HEAD)
BUILD_NUMBER=$(git rev-list --count HEAD)
if [ -z "$OUTPUT_ROOT" ]; then
  OUTPUT_ROOT="$REPO_ROOT/artifacts/macos-preflight/$SHORT_COMMIT"
fi
OUTPUT_ROOT=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT_ROOT")
MODEL_CACHE=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$MODEL_CACHE")

TRACKED_DIRTY=$(git status --porcelain --untracked-files=no)
[ -z "$TRACKED_DIRTY" ] || {
  echo "Tracked changes are not committed; refusing commit-bound packaging." >&2
  exit 4
}
for tracked_input in \
  packaging/build-macos-release.sh \
  packaging/macos/Info.plist \
  Directory.Build.props \
  tools/fetch_supertonic_model.py \
  tools/release_privacy_gate.py \
  tools/release_privacy_rules.json \
  tools/release_open_gates.py \
  packaging/release-open-gates.json \
  packaging/release-gate-traceability.json \
  packaging/final-release-signing-policy.json; do
  git cat-file -e "$RELEASE_COMMIT:$tracked_input" 2>/dev/null || {
    echo "Release input is not present in the audited commit: $tracked_input" >&2
    exit 4
  }
done

EXPECTED_DOTNET_VERSION=$(python3 -c 'import json; print(json.load(open("global.json", encoding="utf-8"))["sdk"]["version"])')
ACTUAL_DOTNET_VERSION=$("$DOTNET" --version)
[ "$ACTUAL_DOTNET_VERSION" = "$EXPECTED_DOTNET_VERSION" ] || {
  echo "Expected .NET SDK $EXPECTED_DOTNET_VERSION but found $ACTUAL_DOTNET_VERSION." >&2
  exit 4
}
DOTNET_SHA256=$(shasum -a 256 "$DOTNET" | awk '{print $1}')
python3 -c 'import re,sys; raise SystemExit(0 if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", sys.argv[1]) else 1)' "$PACKAGE_VERSION" || {
  echo "SVX_PACKAGE_VERSION is invalid." >&2
  exit 4
}

[ ! -e "$OUTPUT_ROOT" ] || {
  echo "Output already exists: $OUTPUT_ROOT" >&2
  exit 4
}

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/svx-macos-preflight.XXXXXX")
WORK_ROOT=$(cd "$WORK_ROOT" && pwd -P)
MOUNT_POINT="$WORK_ROOT/mount"
MOUNTED=0
cleanup() {
  if [ "$MOUNTED" = "1" ]; then
    hdiutil detach "$MOUNT_POINT" -quiet || true
  fi
  rm -rf "$WORK_ROOT"
}
trap cleanup EXIT INT TERM

PUBLISH_DIR="$WORK_ROOT/publish"
SOURCE_ROOT="$WORK_ROOT/source"
APP_DIR="$WORK_ROOT/SupertonicVox.app"
MACOS_DIR="$APP_DIR/Contents/MacOS"
RESOURCES_DIR="$APP_DIR/Contents/Resources"
MODEL_DIR="$RESOURCES_DIR/Models/Supertonic3"
EVIDENCE_DIR="$WORK_ROOT/evidence"
DMG_SOURCE="$WORK_ROOT/dmg-source"
DMG_PATH="$WORK_ROOT/SupertonicVox-${PACKAGE_VERSION}-macos-arm64-UNSIGNED-NOT-FOR-DISTRIBUTION.dmg"
mkdir -p "$PUBLISH_DIR" "$SOURCE_ROOT" "$MACOS_DIR" "$MODEL_DIR" "$EVIDENCE_DIR" "$DMG_SOURCE"
git archive --format=tar "$RELEASE_COMMIT" | tar -xf - -C "$SOURCE_ROOT"
python3 "$SOURCE_ROOT/tools/release_open_gates.py" validate-contract \
  --contract "$SOURCE_ROOT/packaging/release-open-gates.json"
python3 "$SOURCE_ROOT/tools/release_open_gates.py" validate-traceability \
  --contract "$SOURCE_ROOT/packaging/release-open-gates.json" \
  --traceability "$SOURCE_ROOT/packaging/release-gate-traceability.json"

FETCH_ARGS=(
  --destination "$MODEL_CACHE"
  --report "$EVIDENCE_DIR/model-fetch-report.json"
)
if [ "$OFFLINE_MODELS" = "1" ]; then
  FETCH_ARGS+=(--offline)
fi
python3 "$SOURCE_ROOT/tools/fetch_supertonic_model.py" "${FETCH_ARGS[@]}"

"$DOTNET" restore "$SOURCE_ROOT/SupertonicVox.CrossPlatform.slnx" --locked-mode
"$DOTNET" build "$SOURCE_ROOT/SupertonicVox.CrossPlatform.slnx" \
  --configuration Release \
  --no-restore \
  | tee "$EVIDENCE_DIR/build.txt"
"$DOTNET" test "$SOURCE_ROOT/tests/SupertonicVox.Core.Tests/SupertonicVox.Core.Tests.csproj" \
  --configuration Release \
  --no-build \
  | tee "$EVIDENCE_DIR/tests.txt"
"$DOTNET" publish "$SOURCE_ROOT/src/CrossPlatform/SupertonicVox.Desktop/SupertonicVox.Desktop.csproj" \
  --configuration Release \
  --runtime osx-arm64 \
  --self-contained true \
  --no-restore \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -o "$PUBLISH_DIR"

while IFS= read -r -d '' candidate; do
  relative=${candidate#"$PUBLISH_DIR"/}
  [ ! -L "$candidate" ] || {
    echo "Publish output contains a symlink: $relative" >&2
    exit 4
  }
  case "$relative" in
    createdump)
      continue
      ;;
    SupertonicVox.Desktop|*.dll|*.dylib|SupertonicVox.Desktop.deps.json|SupertonicVox.Desktop.runtimeconfig.json)
      ;;
    *)
      echo "Publish output is outside the executable allowlist: $relative" >&2
      exit 4
      ;;
  esac
  mkdir -p "$MACOS_DIR/$(dirname "$relative")"
  cp -p "$candidate" "$MACOS_DIR/$relative"
done < <(find "$PUBLISH_DIR" -type f -print0)

[ -x "$MACOS_DIR/SupertonicVox.Desktop" ] || {
  echo "Published application executable is missing." >&2
  exit 4
}
[ ! -e "$MACOS_DIR/createdump" ] || {
  echo "Crash dump helper must not be distributed." >&2
  exit 4
}

MODEL_FILES=(
  onnx/duration_predictor.onnx
  onnx/text_encoder.onnx
  onnx/vector_estimator.onnx
  onnx/vocoder.onnx
  onnx/tts.json
  onnx/unicode_indexer.json
  voice_styles/M1.json
)
for relative in "${MODEL_FILES[@]}"; do
  source_path="$MODEL_CACHE/$relative"
  [ -f "$source_path" ] && [ ! -L "$source_path" ] || {
    echo "Verified model cache file is missing: $relative" >&2
    exit 4
  }
  mkdir -p "$MODEL_DIR/$(dirname "$relative")"
  cp -p "$source_path" "$MODEL_DIR/$relative"
done
python3 "$SOURCE_ROOT/tools/fetch_supertonic_model.py" \
  --destination "$MODEL_DIR" \
  --report "$EVIDENCE_DIR/bundled-model-report.json" \
  --offline

mkdir -p "$RESOURCES_DIR/Licenses"
cp "$SOURCE_ROOT/packaging/macos/Info.plist" "$APP_DIR/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $PACKAGE_VERSION" "$APP_DIR/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP_DIR/Contents/Info.plist"
plutil -lint "$APP_DIR/Contents/Info.plist"
cp "$SOURCE_ROOT/THIRD_PARTY_NOTICES.md" "$RESOURCES_DIR/THIRD_PARTY_NOTICES.md"
cp "$SOURCE_ROOT/licenses/Supertonic-v3.0.0_MIT.txt" "$RESOURCES_DIR/Licenses/Supertonic-v3.0.0_MIT.txt"
cp "$SOURCE_ROOT/licenses/Supertonic-3_OpenRAIL-M.txt" "$RESOURCES_DIR/Licenses/Supertonic-3_OpenRAIL-M.txt"
printf '%s\n' \
  'This artifact is unsigned, not notarized, and NOT FOR DISTRIBUTION.' \
  'It exists only to verify deterministic contents and privacy controls; DMG bytes are not reproducible.' \
  > "$RESOURCES_DIR/UNSIGNED-NOT-FOR-DISTRIBUTION.txt"
chmod 0755 "$MACOS_DIR/SupertonicVox.Desktop"

python3 "$SOURCE_ROOT/tools/release_privacy_gate.py" --self-test
python3 "$SOURCE_ROOT/tools/release_privacy_gate.py" "$APP_DIR" \
  --release-commit "$RELEASE_COMMIT" \
  --report "$EVIDENCE_DIR/app-privacy-report.json"

SVX_SUPERTONIC_MODEL_ROOT="$MODEL_DIR" \
  "$DOTNET" run --project "$SOURCE_ROOT/tools/DesktopSmoke/DesktopSmoke.csproj" \
  --configuration Release \
  --no-build \
  --no-restore \
  > "$EVIDENCE_DIR/desktop-smoke.txt"

mv "$APP_DIR" "$DMG_SOURCE/SupertonicVox.app"
hdiutil create \
  -quiet \
  -fs APFS \
  -format UDZO \
  -volname "Supertonic Vox Preflight" \
  -srcfolder "$DMG_SOURCE" \
  "$DMG_PATH"

mkdir -p "$MOUNT_POINT"
hdiutil attach -quiet -readonly -nobrowse -mountpoint "$MOUNT_POINT" "$DMG_PATH"
MOUNTED=1
python3 "$SOURCE_ROOT/tools/release_privacy_gate.py" "$MOUNT_POINT" \
  --release-commit "$RELEASE_COMMIT" \
  --report "$EVIDENCE_DIR/dmg-mounted-privacy-report.json"
hdiutil detach "$MOUNT_POINT" -quiet
MOUNTED=0

DMG_SHA256=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
DMG_SIZE=$(stat -f %z "$DMG_PATH")
python3 - "$EVIDENCE_DIR/release-evidence.json" "$RELEASE_COMMIT" "$PACKAGE_VERSION" "$DMG_SHA256" "$DMG_SIZE" "$ACTUAL_DOTNET_VERSION" "$DOTNET_SHA256" "$SOURCE_ROOT/packaging/release-open-gates.json" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
open_gates = json.loads(Path(sys.argv[8]).read_text(encoding="ascii"))["requiredOpenGateIds"]
payload = {
    "schemaVersion": 1,
    "mode": "preflight-unsigned",
    "releaseEligible": False,
    "releaseCommit": sys.argv[2],
    "sourceMode": "git-archive",
    "packageVersion": sys.argv[3],
    "artifact": {
        "name": f"SupertonicVox-{sys.argv[3]}-macos-arm64-UNSIGNED-NOT-FOR-DISTRIBUTION.dmg",
        "sha256": sys.argv[4],
        "sizeBytes": int(sys.argv[5]),
    },
    "toolchain": {
        "dotnetSdkVersion": sys.argv[6],
        "dotnetExecutableSha256": sys.argv[7],
    },
    "openGates": open_gates,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
python3 "$SOURCE_ROOT/tools/release_open_gates.py" validate-evidence \
  --contract "$SOURCE_ROOT/packaging/release-open-gates.json" \
  --evidence "$EVIDENCE_DIR/release-evidence.json"

OUTPUT_PARENT=$(dirname "$OUTPUT_ROOT")
OUTPUT_NAME=$(basename "$OUTPUT_ROOT")
OUTPUT_TEMP="$OUTPUT_PARENT/.${OUTPUT_NAME}.partial"
mkdir -p "$OUTPUT_PARENT"
[ ! -e "$OUTPUT_TEMP" ] || {
  echo "Partial output already exists: $OUTPUT_TEMP" >&2
  exit 4
}
mkdir "$OUTPUT_TEMP"
cp -p "$DMG_PATH" "$OUTPUT_TEMP/"
cp -p "$EVIDENCE_DIR"/* "$OUTPUT_TEMP/"
mv "$OUTPUT_TEMP" "$OUTPUT_ROOT"

echo "Unsigned privacy-gated macOS preflight created: $OUTPUT_ROOT"
echo "Release eligible: false"
