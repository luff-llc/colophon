#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# Prerequisites: JDK 17, Android command-line SDK + NDK, cargo-ndk, and these Rust targets.
# Set ANDROID_HOME and ANDROID_NDK_HOME. Android ECDH Keystore requires API 31+.
: "${ANDROID_HOME:?Set ANDROID_HOME to the installed Android SDK}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the installed Android NDK}"
command -v cargo-ndk >/dev/null || { echo 'Install cargo-ndk: cargo install cargo-ndk --locked' >&2; exit 1; }
: "${GRADLE_USER_HOME:=$PWD/.gradle-home}"
export GRADLE_USER_HOME
rustup target add aarch64-linux-android x86_64-linux-android
# The host generator and generated sources must match the native library exactly.
bash scripts/generate-bindings.sh
stage="$PWD/sdk/android/build/aar"
mkdir -p "$stage/jni"
cargo ndk -t arm64-v8a -t x86_64 -p 31 -o "$stage/jni" build --locked -p colophon-ffi --release
sdk/kotlin/gradlew -p sdk/kotlin --no-daemon jar
cp sdk/kotlin/build/libs/colophon-kotlin-0.2.0.jar "$stage/classes.jar"
cat > "$stage/AndroidManifest.xml" <<'MANIFEST'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.luff.colophon">
  <uses-sdk android:minSdkVersion="31" />
</manifest>
MANIFEST
cat > "$stage/proguard.txt" <<'RULES'
-keep class com.luff.colophon.** { *; }
-keep class com.sun.jna.** { *; }
RULES
(cd "$stage" && zip -qr ../colophon-0.2.0.aar AndroidManifest.xml classes.jar jni proguard.txt)
echo "Built sdk/android/build/colophon-0.2.0.aar"
echo 'App dependencies: Kotlin stdlib 2.2.21 and net.java.dev.jna:jna:5.18.1@aar (includes Android libjnidispatch).'
