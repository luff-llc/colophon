#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
if [[ -z "${ANDROID_HOME:-}" && -d /Users/mikelxc/.local/share/luff/android-sdk ]]; then
  export ANDROID_HOME=/Users/mikelxc/.local/share/luff/android-sdk
fi
: "${ANDROID_HOME:?Set ANDROID_HOME to the installed Android SDK}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
if [[ -n "${JAVA_HOME:-}" && ! -f "$JAVA_HOME/release" && -f "$JAVA_HOME/libexec/openjdk.jdk/Contents/Home/release" ]]; then
  export JAVA_HOME="$JAVA_HOME/libexec/openjdk.jdk/Contents/Home"
fi
: "${GRADLE_USER_HOME:=$PWD/.gradle-home}"
export GRADLE_USER_HOME
cargo build --locked -p colophon-ffi --release
sdk/android/gradlew -p sdk/android --no-daemon testDebugUnitTest "$@"
