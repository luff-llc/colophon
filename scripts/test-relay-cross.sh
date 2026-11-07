#!/usr/bin/env bash
# An Apple session and an Android (JVM) session share one library through one reference relay:
# Apple creates and writes, Android joins, Apple approves, Android writes, both verify.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
if [[ -z "${ANDROID_HOME:-}" && -d /Users/mikelxc/.local/share/luff/android-sdk ]]; then
  export ANDROID_HOME=/Users/mikelxc/.local/share/luff/android-sdk
fi
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
: "${GRADLE_USER_HOME:=$PWD/.gradle-home}"
export GRADLE_USER_HOME ANDROID_SDK_ROOT="${ANDROID_HOME:-}"
export COLOPHON_SOFTWARE_KEYS=1

work="$(mktemp -d "${TMPDIR:-/tmp}/colophon-cross.XXXXXX")"
token="cross-$(openssl rand -hex 16)"
COLOPHON_RELAY_PORT=0 COLOPHON_RELAY_DATA="$work/relay" COLOPHON_RELAY_TOKENS="home=$token" \
  node relay/server.js > "$work/relay.out" &
relay_pid=$!
trap 'kill $relay_pid 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 1 50); do grep -q listening "$work/relay.out" 2>/dev/null && break; sleep 0.1; done
port="$(sed -n 's/.*"port":\([0-9]*\).*/\1/p' "$work/relay.out" | head -1)"
export COLOPHON_CROSS_DIR="$work" COLOPHON_CROSS_URL="http://127.0.0.1:$port/v1/libraries/home" COLOPHON_CROSS_TOKEN="$token"

cargo build --locked -p colophon-ffi --release ${CARGO_OFFLINE:+--offline} >/dev/null
apple() { echo "== apple: $1"; COLOPHON_CROSS_STEP="$1" swift test --filter CrossPlatformRelayTests 2>&1 | grep -E "✔|✘|error:" ; }
android() {
  echo "== android: $1"
  COLOPHON_CROSS_STEP="$1" sdk/android/gradlew -p sdk/android --no-daemon -q ${GRADLE_OFFLINE:+--offline} \
    testDebugUnitTest --tests org.luff.colophon.CrossPlatformRelayTest --rerun-tasks
  echo "✔ android $1"
}
set -o pipefail
apple create
android join
apple approve
android write
apple verify
android verify
echo "Cross-platform relay journey passed."
