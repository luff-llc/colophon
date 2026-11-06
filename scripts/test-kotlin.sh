#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$PWD/.gradle-home}"
# Override JAVA_HOME explicitly on hosts whose default JDK is too new for Gradle 8.
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
cargo build --locked -p colophon-ffi --release
sdk/kotlin/gradlew -p sdk/kotlin --no-daemon test "$@"
