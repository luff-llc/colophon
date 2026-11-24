#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# Prerequisites: JDK 17, Android command-line SDK + NDK, cargo-ndk, and these Rust targets.
# ANDROID_HOME / ANDROID_NDK_HOME default to the machine's installed SDK when present.
if [[ -z "${ANDROID_HOME:-}" && -n "${ANDROID_SDK_ROOT:-}" ]]; then
  export ANDROID_HOME="$ANDROID_SDK_ROOT"
fi
if [[ -z "${ANDROID_HOME:-}" ]]; then
  for sdk in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    if [[ -d "$sdk" ]]; then export ANDROID_HOME="$sdk"; break; fi
  done
fi
: "${ANDROID_HOME:?Set ANDROID_HOME to the installed Android SDK}"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  if [[ -d "$ANDROID_HOME/ndk/30.0.16248370" ]]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/30.0.16248370"
  else
    ndk_dir=$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1 || true)
    [[ -n "${ndk_dir:-}" ]] || { echo 'Set ANDROID_NDK_HOME to the installed Android NDK' >&2; exit 1; }
    export ANDROID_NDK_HOME="$ndk_dir"
  fi
fi
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
if [[ -z "${JAVA_HOME:-}" && -x /usr/libexec/java_home ]]; then
  java_home=$(/usr/libexec/java_home -v 17 2>/dev/null || true)
  if [[ -n "$java_home" ]]; then export JAVA_HOME="$java_home"; fi
fi
# Homebrew's opt prefix points at bin/java but is not a JDK home. Gradle needs the release file.
if [[ -n "${JAVA_HOME:-}" && ! -f "$JAVA_HOME/release" && -f "$JAVA_HOME/libexec/openjdk.jdk/Contents/Home/release" ]]; then
  export JAVA_HOME="$JAVA_HOME/libexec/openjdk.jdk/Contents/Home"
fi
# scripts/package-release.sh records the NDK and JDK actually used.
if [[ -n "${BUILD_INFO_FILE:-}" ]]; then
  printf 'ndk=%s\njava_home=%s\n' "$ANDROID_NDK_HOME" "${JAVA_HOME:-}" >"$BUILD_INFO_FILE"
fi
command -v cargo-ndk >/dev/null || { echo 'Install cargo-ndk: cargo install cargo-ndk --locked' >&2; exit 1; }
: "${GRADLE_USER_HOME:=$PWD/.gradle-home}"
export GRADLE_USER_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
if [[ "${RELEASE_NO_INSTALL:-0}" == 1 ]]; then
  # scripts/package-release.sh: a missing target is a failure, never an install.
  for t in aarch64-linux-android x86_64-linux-android; do
    rustup target list --installed | grep -qx "$t" || { echo "build-android: Rust target $t is not installed" >&2; exit 1; }
  done
else
  rustup target add aarch64-linux-android x86_64-linux-android
fi
# The host generator and generated sources must match the native library exactly.
bash scripts/generate-bindings.sh
# Staged outside Gradle build/ so clean cannot package an AAR with no JNI libraries.
jni="$PWD/sdk/android/native/jni"
mkdir -p "$jni"
cargo ndk -t arm64-v8a -t x86_64 --platform 33 -o "$jni" build --locked -p colophon-ffi --release
sdk/android/gradlew -p sdk/android --no-daemon assembleRelease
aar_src="sdk/android/build/outputs/aar/colophon-android-release.aar"
if [[ ! -f "$aar_src" ]]; then
  echo 'Gradle did not produce the release AAR' >&2
  exit 1
fi
mkdir -p sdk/android/build
# The Android project declares its own package version (it does not read Cargo.toml).
version=$(sed -nE 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"([^"[:space:]]+)"[[:space:]]*$/\1/p' sdk/android/build.gradle.kts)
[[ -n "$version" && "$version" != *$'\n'* && "$version" != *'/'* ]] || { echo 'Cannot read Android package version' >&2; exit 1; }
aar="sdk/android/build/colophon-android-$version.aar"
cp "$aar_src" "$aar"
# Keep the compatibility alias used by earlier packaging docs.
cp "$aar" "sdk/android/build/colophon-$version.aar"
echo "Built $aar"
unzip -l "$aar" | sed -n '1,80p'
echo 'App dependencies: org.jetbrains.kotlin:kotlin-stdlib:2.2.21, net.java.dev.jna:jna:5.18.1@aar, org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2'
