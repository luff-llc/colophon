#!/usr/bin/env bash
# Build the Colophon test app for Android (apps/test-android): a debug APK.
#
#   scripts/build-test-android.sh            the debug APK (and the instrumented test APK)
#   scripts/build-test-android.sh --test     also run the instrumented UI test on the running emulator or device
#                                            (adb), against a local home (apps/test-home and the relay, started and
#                                            stopped here, reached from the emulator through `adb reverse`)
#
# Needs JDK 17, the Android SDK, and the JNI libraries in sdk/android/native/jni (the cargo-ndk step of
# scripts/build-android.sh). Build defaults can be overridden with COLOPHON_HOME_PREFIX, COLOPHON_HOME_REACH,
# COLOPHON_PROVISIONER, COLOPHON_RELYING_PARTY, COLOPHON_STAGING_PREFIX and COLOPHON_STAGING_PROVISIONER.
# The debug APK is signed with the Android debug key on this machine; nothing is signed from the repository.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
if [[ -z "${ANDROID_HOME:-}" && -d "$HOME/.local/share/luff/android-sdk" ]]; then export ANDROID_HOME="$HOME/.local/share/luff/android-sdk"; fi
: "${ANDROID_HOME:?Set ANDROID_HOME to the installed Android SDK}"
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
export ANDROID_SDK_ROOT="$ANDROID_HOME"
for abi in arm64-v8a x86_64; do
  [[ -f "sdk/android/native/jni/$abi/libcolophon_ffi.so" ]] || {
    echo "build-test-android: missing sdk/android/native/jni/$abi/libcolophon_ffi.so (cargo ndk, see scripts/build-android.sh)" >&2; exit 1; }
done
props=()
for name in COLOPHON_HOME_PREFIX COLOPHON_HOME_REACH COLOPHON_PROVISIONER COLOPHON_RELYING_PARTY COLOPHON_STAGING_PREFIX COLOPHON_STAGING_PROVISIONER; do
  if [[ -n "${!name:-}" ]]; then props+=("-P$name=${!name}"); fi
done
echo "sdk.dir=$ANDROID_HOME" > apps/test-android/local.properties
gradle=(sdk/android/gradlew -p apps/test-android --no-daemon ${props[@]+"${props[@]}"})
"${gradle[@]}" :app:assembleDebug :app:assembleDebugAndroidTest
apk=apps/test-android/app/build/outputs/apk/debug/app-debug.apk
echo "build-test-android: $apk ($(wc -c < "$apk" | tr -d ' ') bytes)"

if [[ "${1:-}" == --test ]]; then
  adb="$ANDROID_HOME/platform-tools/adb"
  "$adb" get-state >/dev/null || { echo "build-test-android: no emulator or device on adb" >&2; exit 1; }
  cargo build --locked --quiet --target wasm32-unknown-unknown --release -p colophon-home-wasm
  data="$(mktemp -d "${TMPDIR:-/tmp}/colophon-test-home.XXXXXX")"
  swift build --package-path apps/test-home -c debug >/dev/null
  apps/test-home/.build/debug/colophon-test-home --data "$data" > "$data/out" 2> "$data/log" &
  home=$!
  cleanup() {
    kill "$home" 2>/dev/null || true; wait "$home" 2>/dev/null || true
    "$adb" reverse --remove tcp:8790 2>/dev/null || true; "$adb" reverse --remove tcp:8791 2>/dev/null || true
    rm -rf "$data"
  }
  trap cleanup EXIT
  for _ in $(seq 50); do grep -q listening "$data/out" 2>/dev/null && break; sleep 0.2; done
  token=$(sed -nE 's/.*"token":"([0-9a-f]+)".*/\1/p' "$data/out")
  [[ -n "$token" ]] || { echo "build-test-android: the home service did not start" >&2; cat "$data/log" >&2; exit 1; }
  "$adb" reverse tcp:8790 tcp:8790
  "$adb" reverse tcp:8791 tcp:8791
  set +e
  "${gradle[@]}" -Pandroid.testInstrumentationRunnerArguments.token="$token" :app:connectedDebugAndroidTest
  status=$?
  set -e
  echo "build-test-android: home service log:"; cat "$data/log"
  exit "$status"
fi
