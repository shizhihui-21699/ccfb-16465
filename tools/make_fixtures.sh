#!/usr/bin/env bash
# Builds the synthetic APK corpus used by the test suite and the demo.
#
# Requires: javac + d8 + aapt2 (Android build-tools). The generated APKs are
# committed to fixtures/ so the test suite itself needs no Android toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${ROOT}/fixtures"
BT="${ANDROID_BUILD_TOOLS:-/opt/homebrew/share/android-commandlinetools/build-tools/35.0.0}"
PLATFORM="${ANDROID_JAR:-/opt/homebrew/share/android-commandlinetools/platforms/android-35/android.jar}"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}"
PATH="$JAVA_HOME/bin:$PATH"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

build_apk() {
  local name="$1"; local srcdir="$2"; local manifest="$3"
  local w="$WORK/$name"
  mkdir -p "$w/cls" "$w/dex" "$w/apk"
  find "$srcdir" -name '*.java' -print0 | xargs -0 javac --release 11 -nowarn -d "$w/cls" -cp "$PLATFORM"
  find "$w/cls" -name '*.class' -print0 | xargs -0 d8 --release --min-api 21 --lib "$PLATFORM" --output "$w/dex"
  cp "$w/dex/classes.dex" "$w/apk/classes.dex"
  aapt2 link -o "$w/apk/base.apk" -I "$PLATFORM" --manifest "$manifest" \
    --min-sdk-version 21 --target-sdk-version 30 2>/dev/null || true
  if [ ! -f "$w/apk/base.apk" ]; then
    # aapt2 link needs a resource dir; fall back to a static manifest copy.
    cp "$HERE/manifest/AndroidManifest.xml.bin" "$w/apk/AndroidManifest.xml"
  else
    cd "$w/apk" && unzip -o -q base.apk AndroidManifest.xml && cd - >/dev/null
  fi
  ( cd "$w/apk" && zip -q -X -r "$OUT/$name.apk" classes.dex AndroidManifest.xml )
  echo "built $OUT/$name.apk"
}
