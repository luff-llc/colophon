#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# Prerequisites: JDK 17, Android command-line SDK + NDK, cargo-ndk, and these Rust targets.
# ANDROID_HOME / ANDROID_NDK_HOME default to the machine's installed SDK when present.
if [[ -z "${ANDROID_HOME:-}" && -d /Users/mikelxc/.local/share/luff/android-sdk ]]; then
  export ANDROID_HOME=/Users/mikelxc/.local/share/luff/android-sdk
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
# Homebrew's opt prefix points at bin/java but is not a JDK home. Gradle needs the release file.
if [[ -n "${JAVA_HOME:-}" && ! -f "$JAVA_HOME/release" && -f "$JAVA_HOME/libexec/openjdk.jdk/Contents/Home/release" ]]; then
  export JAVA_HOME="$JAVA_HOME/libexec/openjdk.jdk/Contents/Home"
fi
command -v cargo-ndk >/dev/null || { echo 'Install cargo-ndk: cargo install cargo-ndk --locked' >&2; exit 1; }
: "${GRADLE_USER_HOME:=$PWD/.gradle-home}"
export GRADLE_USER_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
rustup target add aarch64-linux-android x86_64-linux-android
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
cp "$aar_src" sdk/android/build/colophon-android-0.2.0.aar
# Keep a stable name matching earlier packaging docs.
cp sdk/android/build/colophon-android-0.2.0.aar sdk/android/build/colophon-0.2.0.aar
echo "Built sdk/android/build/colophon-android-0.2.0.aar"
unzip -l sdk/android/build/colophon-android-0.2.0.aar | sed -n '1,80p'
echo 'App dependencies: org.jetbrains.kotlin:kotlin-stdlib:2.2.21, net.java.dev.jna:jna:5.18.1@aar, org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2'
