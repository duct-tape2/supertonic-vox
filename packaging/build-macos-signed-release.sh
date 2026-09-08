#!/bin/bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  build-macos-signed-release.sh --capture-signing-policy [options]
  build-macos-signed-release.sh --build-signed-candidate [production options]

Common options:
  --model-cache PATH --output PATH --offline-models

Signed-candidate options:
  --certificate-sha1 HEX40 --notary-profile NAME --notary-keychain PATH
  --production-catalog-assets PATH
  --first-production-catalog | --catalog-baseline PATH
  --source-license-approval PATH --model-redistribution-approval PATH
  --first-release | --prior-signed-dmg PATH
EOF
  exit 2
}

MODE=""
OFFLINE_MODELS=0
MODEL_CACHE=""
OUTPUT_ROOT=""
CERTIFICATE_SHA1=""
NOTARY_PROFILE=""
NOTARY_KEYCHAIN=""
CATALOG_ASSET_ROOT=""
CATALOG_BASELINE=""
FIRST_PRODUCTION_CATALOG=0
SOURCE_LICENSE_APPROVAL=""
MODEL_REDISTRIBUTION_APPROVAL=""
FIRST_RELEASE=0
PRIOR_SIGNED_DMG=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --capture-signing-policy) MODE="capture"; shift ;;
    --build-signed-candidate) MODE="signed"; shift ;;
    --offline-models) OFFLINE_MODELS=1; shift ;;
    --model-cache) [ "$#" -ge 2 ] || usage; MODEL_CACHE=$2; shift 2 ;;
    --output) [ "$#" -ge 2 ] || usage; OUTPUT_ROOT=$2; shift 2 ;;
    --certificate-sha1) [ "$#" -ge 2 ] || usage; CERTIFICATE_SHA1=$2; shift 2 ;;
    --notary-profile) [ "$#" -ge 2 ] || usage; NOTARY_PROFILE=$2; shift 2 ;;
    --notary-keychain) [ "$#" -ge 2 ] || usage; NOTARY_KEYCHAIN=$2; shift 2 ;;
    --production-catalog-assets) [ "$#" -ge 2 ] || usage; CATALOG_ASSET_ROOT=$2; shift 2 ;;
    --catalog-baseline) [ "$#" -ge 2 ] || usage; CATALOG_BASELINE=$2; shift 2 ;;
    --first-production-catalog) FIRST_PRODUCTION_CATALOG=1; shift ;;
    --source-license-approval) [ "$#" -ge 2 ] || usage; SOURCE_LICENSE_APPROVAL=$2; shift 2 ;;
    --model-redistribution-approval) [ "$#" -ge 2 ] || usage; MODEL_REDISTRIBUTION_APPROVAL=$2; shift 2 ;;
    --first-release) FIRST_RELEASE=1; shift ;;
    --prior-signed-dmg) [ "$#" -ge 2 ] || usage; PRIOR_SIGNED_DMG=$2; shift 2 ;;
    *) usage ;;
  esac
done

[ "$MODE" = "capture" ] || [ "$MODE" = "signed" ] || usage
[ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ] || {
  echo "Signed macOS packaging requires an Apple Silicon macOS host." >&2
  exit 4
}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
cd "$REPO_ROOT"
MODEL_CACHE=${MODEL_CACHE:-"$REPO_ROOT/artifacts/model-cache/supertonic-3"}

for command in git python3 hdiutil plutil shasum stat tar lipo codesign security ditto xcrun spctl openssl xcodebuild /usr/libexec/PlistBuddy; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required command: $command" >&2
    exit 4
  }
done
if [ "$MODE" = "signed" ]; then
  xcodebuild -version >/dev/null 2>&1 || {
    echo "A complete Xcode installation is required for signed release work." >&2
    exit 4
  }
fi

require_regular_file() {
  local path=$1
  [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -f %l "$path")" = "1" ] || {
    echo "Expected a regular single-link file: $path" >&2
    exit 4
  }
}

file_identity_json() {
  python3 - "$1" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
data=p.read_bytes()
print(json.dumps({"name":p.name,"sha256":hashlib.sha256(data).hexdigest(),"sizeBytes":len(data)},sort_keys=True))
PY
}

extract_signer_json() {
  local target=$1
  local prefix=$2
  local details=$3
  local output=$4
  codesign -d --verbose=4 --extract-certificates="$prefix" "$target" 2> "$details"
  require_regular_file "${prefix}0"
  local leaf_sha256 subject team_id
  leaf_sha256=$(shasum -a 256 "${prefix}0" | awk '{print $1}')
  subject=$(openssl x509 -inform DER -in "${prefix}0" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
  team_id=$(sed -n 's/^TeamIdentifier=//p' "$details" | tail -1)
  grep -q '^Timestamp=' "$details" || { echo "Secure timestamp missing: $target" >&2; exit 4; }
  python3 - "$output" "$leaf_sha256" "$subject" "$team_id" <<'PY'
import json,pathlib,sys
payload={"leafCertificateSha256":sys.argv[2],"subject":sys.argv[3],"teamId":sys.argv[4],"secureTimestamp":True,"certificateKind":"Developer ID Application"}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload,indent=2)+"\n",encoding="ascii")
PY
}

verify_signer_against_contract() {
  python3 - "$1" "$CONTRACT" <<'PY'
import json,sys
signer=json.load(open(sys.argv[1])); identity=json.load(open(sys.argv[2]))["identity"]
expected={
 "leafCertificateSha256":identity["leafCertificateSha256"],
 "subject":identity["subject"],
 "teamId":identity["teamId"],
 "secureTimestamp":True,
 "certificateKind":"Developer ID Application",
}
if signer != expected: raise SystemExit("Actual signer does not match the owner-approved contract")
PY
}

RELEASE_COMMIT=$(git rev-parse HEAD)
SHORT_COMMIT=$(git rev-parse --short=12 HEAD)
BUILD_NUMBER=$(git rev-list --count HEAD)
PACKAGE_VERSION=$(python3 -c '
import sys,xml.etree.ElementTree as ET
values=[n.text.strip() for n in ET.parse(sys.argv[1]).getroot().findall(".//Version") if n.text and n.text.strip()]
if len(values)!=1: raise SystemExit("Directory.Build.props must contain exactly one Version")
print(values[0])
' "$REPO_ROOT/Directory.Build.props")
python3 -c 'import re,sys; raise SystemExit(0 if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",sys.argv[1]) else 1)' "$PACKAGE_VERSION" || {
  echo "A signed candidate requires a three-field numeric package version." >&2
  exit 4
}

COMMIT_INPUTS=(
  .github/workflows/macos-release.yml
  Directory.Build.props
  global.json
  packaging/build-macos-release.sh
  packaging/build-macos-signed-release.sh
  packaging/macos-release-contract.json
  packaging/macos-release-evidence.schema.json
  packaging/macos-signing-policy.json
  packaging/macos
  packaging/release-open-gates.json
  packaging/release-gate-traceability.json
  packaging/final-release-signing-policy.json
  tools/CatalogReleaseVerifier
  tools/fetch_supertonic_model.py
  tools/macos_release_contract.py
  tools/release_open_gates.py
  tools/release_privacy_gate.py
  tools/release_privacy_rules.json
)
for input in "${COMMIT_INPUTS[@]}"; do
  git cat-file -e "$RELEASE_COMMIT:$input" 2>/dev/null || {
    echo "macOS release input is not present in the release commit: $input" >&2
    exit 4
  }
done
python3 "$REPO_ROOT/tools/release_open_gates.py" validate-traceability \
  --contract "$REPO_ROOT/packaging/release-open-gates.json" \
  --traceability "$REPO_ROOT/packaging/release-gate-traceability.json"
INPUT_STATUS=$(git status --porcelain --untracked-files=all -- "${COMMIT_INPUTS[@]}")
[ -z "$INPUT_STATUS" ] || {
  echo "macOS release inputs differ from the release commit or include untracked files." >&2
  exit 4
}

DOTNET="$REPO_ROOT/.tools/dotnet/dotnet"
[ -x "$DOTNET" ] || DOTNET=$(command -v dotnet || true)
[ -n "$DOTNET" ] && [ -x "$DOTNET" ] || { echo "Pinned .NET SDK unavailable." >&2; exit 4; }
EXPECTED_DOTNET=$(python3 -c 'import json; print(json.load(open("global.json"))["sdk"]["version"])')
[ "$($DOTNET --version)" = "$EXPECTED_DOTNET" ] || { echo "Unexpected .NET SDK." >&2; exit 4; }

CONTRACT="$REPO_ROOT/packaging/macos-release-contract.json"
POLICY="$REPO_ROOT/packaging/macos-signing-policy.json"
CONTRACT_TOOL="$REPO_ROOT/tools/macos_release_contract.py"
CONTRACT_ARGS=(validate-contract)
if [ "$MODE" = "signed" ]; then CONTRACT_ARGS+=(--production); fi
python3 "$CONTRACT_TOOL" "${CONTRACT_ARGS[@]}"
if [ "$MODE" = "signed" ]; then
  python3 "$CONTRACT_TOOL" validate-policy --production
else
  python3 "$CONTRACT_TOOL" validate-policy
fi

if [ "$MODE" = "signed" ]; then
  [[ "$CERTIFICATE_SHA1" =~ ^[0-9A-Fa-f]{40}$ ]] || { echo "Certificate SHA-1 selector is required." >&2; exit 4; }
  [ -n "$NOTARY_PROFILE" ] && [ -n "$NOTARY_KEYCHAIN" ] || { echo "Explicit ephemeral notary keychain/profile required." >&2; exit 4; }
  require_regular_file "$NOTARY_KEYCHAIN"
  [ -d "$CATALOG_ASSET_ROOT" ] || { echo "Production catalog assets are required." >&2; exit 4; }
  require_regular_file "$SOURCE_LICENSE_APPROVAL"
  require_regular_file "$MODEL_REDISTRIBUTION_APPROVAL"
  if [ "$FIRST_PRODUCTION_CATALOG" = "1" ]; then
    [ -z "$CATALOG_BASELINE" ] || { echo "Choose one catalog baseline mode." >&2; exit 4; }
  else
    require_regular_file "$CATALOG_BASELINE"
  fi
  if [ "$FIRST_RELEASE" = "1" ]; then
    [ -z "$PRIOR_SIGNED_DMG" ] || { echo "Choose one app release baseline mode." >&2; exit 4; }
  else
    require_regular_file "$PRIOR_SIGNED_DMG"
  fi
fi

if [ -z "$OUTPUT_ROOT" ]; then
  if [ "$MODE" = "capture" ]; then
    OUTPUT_ROOT="$REPO_ROOT/artifacts/macos-signing-policy/$SHORT_COMMIT"
  else
    OUTPUT_ROOT="$REPO_ROOT/artifacts/macos-signed-candidate/$SHORT_COMMIT"
  fi
fi
OUTPUT_ROOT=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT_ROOT")
MODEL_CACHE=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$MODEL_CACHE")
[ ! -e "$OUTPUT_ROOT" ] || { echo "Output already exists: $OUTPUT_ROOT" >&2; exit 4; }
OUTPUT_PARENT=$(dirname "$OUTPUT_ROOT")
OUTPUT_NAME=$(basename "$OUTPUT_ROOT")
OUTPUT_TEMP="$OUTPUT_PARENT/.${OUTPUT_NAME}.partial"
[ ! -e "$OUTPUT_TEMP" ] || { echo "Partial output exists: $OUTPUT_TEMP" >&2; exit 4; }

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/svx-macos-signed.XXXXXX")
WORK_ROOT=$(cd "$WORK_ROOT" && pwd -P)
MOUNT_POINT="$WORK_ROOT/mount"
PRIOR_MOUNT="$WORK_ROOT/prior-mount"
MOUNTED=0
PRIOR_MOUNTED=0
PUBLISHED=0
cleanup() {
  [ "$MOUNTED" = "0" ] || hdiutil detach "$MOUNT_POINT" -quiet || true
  [ "$PRIOR_MOUNTED" = "0" ] || hdiutil detach "$PRIOR_MOUNT" -quiet || true
  [ "$PUBLISHED" = "1" ] || rm -rf "$OUTPUT_TEMP"
  rm -rf "$WORK_ROOT"
}
trap cleanup EXIT INT TERM

SOURCE_ROOT="$WORK_ROOT/source"
PUBLISH_DIR="$WORK_ROOT/publish"
APP_DIR="$WORK_ROOT/SupertonicVox.app"
MACOS_DIR="$APP_DIR/Contents/MacOS"
RESOURCES_DIR="$APP_DIR/Contents/Resources"
MODEL_DIR="$RESOURCES_DIR/Models/Supertonic3"
EVIDENCE_DIR="$WORK_ROOT/evidence"
DMG_SOURCE="$WORK_ROOT/dmg-source"
mkdir -p "$SOURCE_ROOT" "$PUBLISH_DIR" "$MACOS_DIR" "$MODEL_DIR" "$EVIDENCE_DIR" "$DMG_SOURCE"
git archive --format=tar "$RELEASE_COMMIT" | tar -xf - -C "$SOURCE_ROOT"

CATALOG_REPORT=""
if [ "$MODE" = "signed" ]; then
  CATALOG_REPORT="$EVIDENCE_DIR/production-catalog-verification.json"
  VERIFIER="$SOURCE_ROOT/tools/CatalogReleaseVerifier/CatalogReleaseVerifier.csproj"
  "$DOTNET" restore "$VERIFIER" --locked-mode > "$EVIDENCE_DIR/catalog-restore.txt"
  CATALOG_ARGS=(
    run --project "$VERIFIER" --configuration Release --no-restore --
    "$CATALOG_ASSET_ROOT/engine-catalog.json"
    "$CATALOG_ASSET_ROOT/engine-catalog.signature.json"
    "$CATALOG_ASSET_ROOT/engine-catalog.trust.json"
    "$CATALOG_ASSET_ROOT/engine-catalog.bootstrap.json"
    "$CATALOG_ASSET_ROOT/engine-catalog.trust-manifest.json"
    "$CATALOG_ASSET_ROOT/engine-catalog.trust-manifest.signature.json"
    "$CATALOG_REPORT"
  )
  if [ "$FIRST_PRODUCTION_CATALOG" = "1" ]; then
    CATALOG_ARGS+=(--first-production-release)
  else
    CATALOG_ARGS+=("$CATALOG_BASELINE")
  fi
  "$DOTNET" "${CATALOG_ARGS[@]}" > "$EVIDENCE_DIR/catalog-verifier.txt"
fi

FETCH_ARGS=(--destination "$MODEL_CACHE" --report "$EVIDENCE_DIR/model-fetch-report.json")
[ "$OFFLINE_MODELS" = "0" ] || FETCH_ARGS+=(--offline)
python3 "$SOURCE_ROOT/tools/fetch_supertonic_model.py" "${FETCH_ARGS[@]}"
"$DOTNET" restore "$SOURCE_ROOT/SupertonicVox.CrossPlatform.slnx" --locked-mode
"$DOTNET" build "$SOURCE_ROOT/SupertonicVox.CrossPlatform.slnx" --configuration Release --no-restore | tee "$EVIDENCE_DIR/build.txt"
"$DOTNET" test "$SOURCE_ROOT/tests/SupertonicVox.Core.Tests/SupertonicVox.Core.Tests.csproj" --configuration Release --no-build | tee "$EVIDENCE_DIR/tests.txt"
PUBLISH_ARGS=(
  publish "$SOURCE_ROOT/src/CrossPlatform/SupertonicVox.Desktop/SupertonicVox.Desktop.csproj"
  --configuration Release --runtime osx-arm64 --self-contained true --no-restore
  -p:DebugType=None -p:DebugSymbols=false -o "$PUBLISH_DIR"
)
if [ "$MODE" = "signed" ]; then
  PUBLISH_ARGS+=( -p:CatalogProductionAssets=true "-p:CatalogAssetRoot=$CATALOG_ASSET_ROOT" )
fi
"$DOTNET" "${PUBLISH_ARGS[@]}" > "$EVIDENCE_DIR/publish.txt"

while IFS= read -r -d '' candidate; do
  relative=${candidate#"$PUBLISH_DIR"/}
  [ ! -L "$candidate" ] || { echo "Publish symlink rejected: $relative" >&2; exit 4; }
  case "$relative" in
    createdump) continue ;;
    SupertonicVox.Desktop|*.dll|*.dylib|SupertonicVox.Desktop.deps.json|SupertonicVox.Desktop.runtimeconfig.json) ;;
    *) echo "Publish output outside allowlist: $relative" >&2; exit 4 ;;
  esac
  mkdir -p "$MACOS_DIR/$(dirname "$relative")"
  cp -p "$candidate" "$MACOS_DIR/$relative"
done < <(find "$PUBLISH_DIR" -type f -print0)

MODEL_FILES=(
  onnx/duration_predictor.onnx onnx/text_encoder.onnx onnx/vector_estimator.onnx
  onnx/vocoder.onnx onnx/tts.json onnx/unicode_indexer.json voice_styles/M1.json
)
for relative in "${MODEL_FILES[@]}"; do
  require_regular_file "$MODEL_CACHE/$relative"
  mkdir -p "$MODEL_DIR/$(dirname "$relative")"
  cp -p "$MODEL_CACHE/$relative" "$MODEL_DIR/$relative"
done
python3 "$SOURCE_ROOT/tools/fetch_supertonic_model.py" --destination "$MODEL_DIR" --report "$EVIDENCE_DIR/bundled-model-report.json" --offline
mkdir -p "$RESOURCES_DIR/Licenses"
cp "$SOURCE_ROOT/packaging/macos/Info.plist" "$APP_DIR/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $PACKAGE_VERSION" "$APP_DIR/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP_DIR/Contents/Info.plist"
plutil -lint "$APP_DIR/Contents/Info.plist" >/dev/null
cp "$SOURCE_ROOT/THIRD_PARTY_NOTICES.md" "$RESOURCES_DIR/THIRD_PARTY_NOTICES.md"
cp "$SOURCE_ROOT/licenses/Supertonic-v3.0.0_MIT.txt" "$RESOURCES_DIR/Licenses/Supertonic-v3.0.0_MIT.txt"
cp "$SOURCE_ROOT/licenses/Supertonic-3_OpenRAIL-M.txt" "$RESOURCES_DIR/Licenses/Supertonic-3_OpenRAIL-M.txt"
chmod 0755 "$MACOS_DIR/SupertonicVox.Desktop"

PRE_NORMALIZATION_INVENTORY="$EVIDENCE_DIR/pre-normalization-inventory.json"
NORMALIZED_INVENTORY="$EVIDENCE_DIR/normalized-inventory.json"
NORMALIZATION_REPORT="$EVIDENCE_DIR/architecture-normalization.json"
python3 "$SOURCE_ROOT/tools/macos_release_contract.py" normalize-arm64 --root "$APP_DIR" --pre-inventory "$PRE_NORMALIZATION_INVENTORY" --inventory "$NORMALIZED_INVENTORY" --report "$NORMALIZATION_REPORT"

if [ "$MODE" = "capture" ]; then
  CANDIDATE="$EVIDENCE_DIR/macos-signing-policy-candidate.json"
  CAPTURE_EVIDENCE="$EVIDENCE_DIR/capture-evidence.json"
  python3 "$SOURCE_ROOT/tools/macos_release_contract.py" create-policy-candidate --inventory "$NORMALIZED_INVENTORY" --output "$CANDIDATE"
  python3 - "$CAPTURE_EVIDENCE" "$RELEASE_COMMIT" "$PACKAGE_VERSION" "$CONTRACT" "$CANDIDATE" "$PRE_NORMALIZATION_INVENTORY" "$NORMALIZED_INVENTORY" "$NORMALIZATION_REPORT" "$SOURCE_ROOT/packaging/release-open-gates.json" <<'PY'
import hashlib,json,pathlib,sys
def identity(value):
 p=pathlib.Path(value); data=p.read_bytes()
 return {"name":p.name,"sha256":hashlib.sha256(data).hexdigest(),"sizeBytes":len(data)}
contract=pathlib.Path(sys.argv[4])
gates=json.load(open(sys.argv[9]))["requiredOpenGateIds"]
payload={
 "schemaVersion":1,
 "mode":"macos-signing-policy-capture",
 "releaseEligible":False,
 "sourceCommit":sys.argv[2],
 "packageVersion":sys.argv[3],
 "contractSha256":hashlib.sha256(contract.read_bytes()).hexdigest(),
 "artifacts":{
  "policyCandidate":identity(sys.argv[5]),
  "preNormalizationInventory":identity(sys.argv[6]),
  "normalizedInventory":identity(sys.argv[7]),
  "architectureNormalization":identity(sys.argv[8]),
 },
 "openGates":gates,
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload,ensure_ascii=True,indent=2)+"\n",encoding="ascii")
PY
  python3 "$SOURCE_ROOT/tools/release_open_gates.py" validate-evidence --contract "$SOURCE_ROOT/packaging/release-open-gates.json" --evidence "$CAPTURE_EVIDENCE"
  mkdir -p "$OUTPUT_PARENT" "$OUTPUT_TEMP"
  cp -p "$CANDIDATE" "$PRE_NORMALIZATION_INVENTORY" "$NORMALIZED_INVENTORY" "$NORMALIZATION_REPORT" "$CAPTURE_EVIDENCE" "$OUTPUT_TEMP/"
  mv "$OUTPUT_TEMP" "$OUTPUT_ROOT"
  PUBLISHED=1
  echo "macOS signing-policy candidate created for review: $OUTPUT_ROOT"
  echo "Release eligible: false"
  exit 0
fi

python3 "$SOURCE_ROOT/tools/macos_release_contract.py" verify-signing-transition --policy "$POLICY" --inventory "$NORMALIZED_INVENTORY" --phase pre-sign --report "$EVIDENCE_DIR/pre-sign-transition.json"
python3 - "$POLICY" <<'PY' > "$WORK_ROOT/signing-paths.txt"
import json,sys
p=json.load(open(sys.argv[1]))
paths=[e["path"] for e in p["entries"] if e["action"]=="owner-sign"]
for path in sorted(paths,key=lambda value:(value.count("/"),value),reverse=True): print(path)
PY
while IFS= read -r relative; do
  codesign --force --sign "$CERTIFICATE_SHA1" --keychain "$NOTARY_KEYCHAIN" --options runtime --timestamp "$APP_DIR/$relative"
done < "$WORK_ROOT/signing-paths.txt"
codesign --force --sign "$CERTIFICATE_SHA1" --keychain "$NOTARY_KEYCHAIN" --options runtime --timestamp --entitlements "$SOURCE_ROOT/packaging/macos/SupertonicVox.entitlements" "$APP_DIR"
codesign --verify --strict --verbose=4 "$APP_DIR" 2> "$EVIDENCE_DIR/signed-app-codesign.txt"

SIGNED_INVENTORY="$EVIDENCE_DIR/signed-inventory.json"
SIGNING_REPORT="$EVIDENCE_DIR/signing-transition.json"
python3 "$SOURCE_ROOT/tools/macos_release_contract.py" capture-inventory --root "$APP_DIR" --output "$SIGNED_INVENTORY" --require-arm64-only
python3 "$SOURCE_ROOT/tools/macos_release_contract.py" verify-signing-transition --policy "$POLICY" --inventory "$SIGNED_INVENTORY" --phase signed --report "$SIGNING_REPORT"

extract_signer_json "$APP_DIR" "$WORK_ROOT/app-cert" "$EVIDENCE_DIR/app-signature-details.txt" "$EVIDENCE_DIR/app-signer.json"
verify_signer_against_contract "$EVIDENCE_DIR/app-signer.json"
TEAM_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["teamId"])' "$EVIDENCE_DIR/app-signer.json")
codesign -d --entitlements :- "$APP_DIR" > "$EVIDENCE_DIR/extracted-entitlements.plist" 2> "$EVIDENCE_DIR/entitlements-extract.txt"
python3 - "$EVIDENCE_DIR/extracted-entitlements.plist" <<'PY'
import plistlib,sys
value=plistlib.load(open(sys.argv[1],"rb"))
if value != {"com.apple.security.cs.allow-jit": True}: raise SystemExit("Unexpected signed entitlements")
PY

APP_ZIP="$WORK_ROOT/SupertonicVox.app.zip"
ditto -c -k --keepParent "$APP_DIR" "$APP_ZIP"
xcrun notarytool submit "$APP_ZIP" --keychain-profile "$NOTARY_PROFILE" --keychain "$NOTARY_KEYCHAIN" --wait --output-format json > "$EVIDENCE_DIR/app-notary.json"
python3 - "$EVIDENCE_DIR/app-notary.json" <<'PY'
import json,re,sys
p=json.load(open(sys.argv[1]))
if p.get("status")!="Accepted" or not re.fullmatch(r"[0-9a-fA-F-]{36}",str(p.get("id",""))): raise SystemExit("App notarization was not Accepted")
PY
xcrun stapler staple "$APP_DIR" > "$EVIDENCE_DIR/app-staple.txt"
xcrun stapler validate "$APP_DIR" > "$EVIDENCE_DIR/app-staple-validate.txt"
codesign --verify --strict --verbose=4 "$APP_DIR" 2> "$EVIDENCE_DIR/stapled-app-codesign.txt"
STAPLED_INVENTORY="$EVIDENCE_DIR/stapled-inventory.json"
python3 "$SOURCE_ROOT/tools/macos_release_contract.py" capture-inventory --root "$APP_DIR" --output "$STAPLED_INVENTORY" --require-arm64-only

ditto "$APP_DIR" "$DMG_SOURCE/SupertonicVox.app"
DMG_PATH="$WORK_ROOT/SupertonicVox-${PACKAGE_VERSION}-macos-arm64-SIGNED-NOT-RELEASE-ELIGIBLE.dmg"
hdiutil create -quiet -fs APFS -format UDZO -volname "Supertonic Vox" -srcfolder "$DMG_SOURCE" "$DMG_PATH"
file_identity_json "$DMG_PATH" > "$EVIDENCE_DIR/dmg-unsigned-identity.json"
codesign --force --sign "$CERTIFICATE_SHA1" --keychain "$NOTARY_KEYCHAIN" --timestamp "$DMG_PATH"
codesign --verify --verbose=4 "$DMG_PATH" 2> "$EVIDENCE_DIR/signed-dmg-codesign.txt"
extract_signer_json "$DMG_PATH" "$WORK_ROOT/dmg-cert" "$EVIDENCE_DIR/dmg-signature-details.txt" "$EVIDENCE_DIR/dmg-signer.json"
verify_signer_against_contract "$EVIDENCE_DIR/dmg-signer.json"
file_identity_json "$DMG_PATH" > "$EVIDENCE_DIR/dmg-signed-identity.json"
xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --keychain "$NOTARY_KEYCHAIN" --wait --output-format json > "$EVIDENCE_DIR/dmg-notary.json"
python3 - "$EVIDENCE_DIR/dmg-notary.json" <<'PY'
import json,re,sys
p=json.load(open(sys.argv[1]))
if p.get("status")!="Accepted" or not re.fullmatch(r"[0-9a-fA-F-]{36}",str(p.get("id",""))): raise SystemExit("DMG notarization was not Accepted")
PY
xcrun stapler staple "$DMG_PATH" > "$EVIDENCE_DIR/dmg-staple.txt"
xcrun stapler validate "$DMG_PATH" > "$EVIDENCE_DIR/dmg-staple-validate.txt"
file_identity_json "$DMG_PATH" > "$EVIDENCE_DIR/dmg-stapled-identity.json"

mkdir -p "$MOUNT_POINT"
hdiutil attach -quiet -readonly -nobrowse -mountpoint "$MOUNT_POINT" "$DMG_PATH"
MOUNTED=1
MOUNTED_APP="$MOUNT_POINT/SupertonicVox.app"
codesign --verify --strict --verbose=4 "$MOUNTED_APP" 2> "$EVIDENCE_DIR/mounted-app-codesign.txt"
spctl --assess --type execute --verbose=4 "$MOUNTED_APP" 2> "$EVIDENCE_DIR/mounted-app-gatekeeper.txt"
spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG_PATH" 2> "$EVIDENCE_DIR/dmg-gatekeeper.txt"
python3 "$SOURCE_ROOT/tools/release_privacy_gate.py" "$MOUNT_POINT" --release-commit "$RELEASE_COMMIT" --report "$EVIDENCE_DIR/mounted-dmg-privacy-report.json"
hdiutil detach "$MOUNT_POINT" -quiet
MOUNTED=0
python3 "$SOURCE_ROOT/tools/release_privacy_gate.py" "$DMG_PATH" --release-commit "$RELEASE_COMMIT" --report "$EVIDENCE_DIR/final-dmg-privacy-report.json"

PRIOR_HASH=""
UPGRADE_STATE="not-applicable-first-release"
if [ "$FIRST_RELEASE" = "0" ]; then
  mkdir -p "$PRIOR_MOUNT"
  codesign --verify --verbose=4 "$PRIOR_SIGNED_DMG" 2> "$EVIDENCE_DIR/prior-dmg-codesign.txt"
  PRIOR_DMG_TEAM=$(codesign -dvv "$PRIOR_SIGNED_DMG" 2>&1 | sed -n 's/^TeamIdentifier=//p' | tail -1)
  [ "$PRIOR_DMG_TEAM" = "$TEAM_ID" ] || { echo "Prior DMG Team ID mismatch." >&2; exit 4; }
  xcrun stapler validate "$PRIOR_SIGNED_DMG" > "$EVIDENCE_DIR/prior-dmg-staple-validate.txt"
  hdiutil attach -quiet -readonly -nobrowse -mountpoint "$PRIOR_MOUNT" "$PRIOR_SIGNED_DMG"
  PRIOR_MOUNTED=1
  PRIOR_APP="$PRIOR_MOUNT/SupertonicVox.app"
  codesign --verify --strict --verbose=4 "$PRIOR_APP" 2> "$EVIDENCE_DIR/prior-app-codesign.txt"
  xcrun stapler validate "$PRIOR_APP" > "$EVIDENCE_DIR/prior-app-staple-validate.txt"
  PRIOR_BUNDLE=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$PRIOR_APP/Contents/Info.plist")
  PRIOR_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$PRIOR_APP/Contents/Info.plist")
  PRIOR_TEAM=$(codesign -dvv "$PRIOR_APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | tail -1)
  [ "$PRIOR_BUNDLE" = "io.github.supertonicvox.desktop" ] && [ "$PRIOR_TEAM" = "$TEAM_ID" ] || { echo "Prior baseline identity mismatch." >&2; exit 4; }
  python3 - "$PRIOR_VERSION" "$PACKAGE_VERSION" <<'PY'
import sys
def v(x): return tuple(map(int,x.split('.')))
if v(sys.argv[1]) >= v(sys.argv[2]): raise SystemExit("Prior version must be lower")
PY
  hdiutil detach "$PRIOR_MOUNT" -quiet
  PRIOR_MOUNTED=0
  PRIOR_HASH=$(shasum -a 256 "$PRIOR_SIGNED_DMG" | awk '{print $1}')
  UPGRADE_STATE="missing"
fi

python3 - "$EVIDENCE_DIR" "$CONTRACT" "$POLICY" "$SOURCE_LICENSE_APPROVAL" "$MODEL_REDISTRIBUTION_APPROVAL" "$CATALOG_REPORT" "$APP_ZIP" "$RELEASE_COMMIT" "$PACKAGE_VERSION" "$EXPECTED_DOTNET" "$PRIOR_HASH" "$UPGRADE_STATE" <<'PY'
import hashlib,json,pathlib,platform,shutil,subprocess,sys
root=pathlib.Path(sys.argv[1])
def load(name): return json.load(open(root/name))
def identity(path):
 p=pathlib.Path(path); data=p.read_bytes(); return {"name":p.name,"sha256":hashlib.sha256(data).hexdigest(),"sizeBytes":len(data)}
def report_identity(name): return identity(root/name)
contract=json.load(open(sys.argv[2])); policy=json.load(open(sys.argv[3]))
app_notary=load("app-notary.json"); dmg_notary=load("dmg-notary.json")
pre_normalization=load("pre-normalization-inventory.json"); normalized=load("normalized-inventory.json"); signed=load("signed-inventory.json"); stapled=load("stapled-inventory.json")
payload={
 "schemaVersion":2,"releaseEligible":False,"sourceCommit":sys.argv[8],"packageVersion":sys.argv[9],
 "contractSha256":hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest(),
 "signingPolicySha256":hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest(),
 "identityMode":"owner-approved","preNormalizationInventory":pre_normalization,"normalizationDecisions":load("architecture-normalization.json")["decisions"],
 "normalizedInventory":normalized,"signingDecisions":load("signing-transition.json")["decisions"],
 "signedInventory":signed,"stapledInventory":stapled,
 "appStages":{"normalizedInventorySha256":normalized["inventorySha256"],"signedInventorySha256":signed["inventorySha256"],"submissionZip":identity(sys.argv[7]),"stapledInventorySha256":stapled["inventorySha256"]},
 "dmgStages":{"unsigned":load("dmg-unsigned-identity.json"),"signed":load("dmg-signed-identity.json"),"stapled":load("dmg-stapled-identity.json")},
 "signers":{"app":load("app-signer.json"),"dmg":load("dmg-signer.json")},
 "entitlements":{"file":identity(pathlib.Path(sys.argv[2]).parent/"macos"/"SupertonicVox.entitlements"),"extracted":True,"allowedKeys":["com.apple.security.cs.allow-jit"]},
 "notarization":{"app":{"submissionId":app_notary["id"],"status":app_notary["status"],"logFile":report_identity("app-notary.json")},"dmg":{"submissionId":dmg_notary["id"],"status":dmg_notary["status"],"logFile":report_identity("dmg-notary.json")}},
 "verifications":{"signedAppCodesignStrict":True,"stapledAppCodesignStrict":True,"appStaplerValidate":True,"signedDmgCodesign":True,"dmgStaplerValidate":True,"mountedAppCodesignStrict":True,"mountedAppGatekeeper":True,"dmgGatekeeperPrimarySignature":True},
 "privacyEvidence":[report_identity("mounted-dmg-privacy-report.json"),report_identity("final-dmg-privacy-report.json")],
 "externalApprovals":{"sourceLicense":identity(sys.argv[4]),"modelRedistribution":identity(sys.argv[5]),"productionCatalogVerification":identity(sys.argv[6])},
 "toolchain":{"dotnetSdkVersion":sys.argv[10],"macosVersion":platform.mac_ver()[0],"xcodeVersion":subprocess.check_output(["xcodebuild","-version"],text=True).splitlines()[0],"codesignExecutableSha256":hashlib.sha256(pathlib.Path(shutil.which("codesign")).read_bytes()).hexdigest(),"notarytoolVersion":subprocess.check_output(["xcrun","notarytool","--version"],text=True).strip()},
 "nativeChecks":{"quarantineApplied":"missing","cleanAccountFirstLaunch":"missing","offlineSynthesis":"missing","saveRestart":"missing","uninstall":"missing","userDataPreserved":"missing","noOrphanProcesses":"missing","upgrade":sys.argv[12],"priorBaselineSha256":sys.argv[11] or None},
 "openGates":contract["openGates"],
}
(root/"macos-release-evidence.json").write_text(json.dumps(payload,ensure_ascii=True,indent=2)+"\n",encoding="ascii")
PY
python3 "$SOURCE_ROOT/tools/macos_release_contract.py" validate-evidence --contract "$CONTRACT" --policy "$POLICY" --evidence "$EVIDENCE_DIR/macos-release-evidence.json"

mkdir -p "$OUTPUT_PARENT" "$OUTPUT_TEMP"
cp -p "$DMG_PATH" "$OUTPUT_TEMP/"
cp -R "$EVIDENCE_DIR" "$OUTPUT_TEMP/evidence"
mv "$OUTPUT_TEMP" "$OUTPUT_ROOT"
PUBLISHED=1
echo "Signed, notarized, stapled but noneligible macOS candidate created: $OUTPUT_ROOT"
echo "Release eligible: false"
