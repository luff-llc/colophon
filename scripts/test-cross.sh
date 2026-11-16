#!/usr/bin/env bash
# macOS host proof of the Swift and Kotlin SDKs sharing one account through real signed-call homes.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
export PATH="$HOME/.rustup/toolchains/1.99.1-aarch64-apple-darwin/bin:$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin:$PATH"
command -v bun >/dev/null || { echo 'test-cross: bun is required' >&2; exit 1; }
command -v swift >/dev/null || { echo 'test-cross: Swift on macOS is required' >&2; exit 1; }
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
# A private target per invocation. No shared Cargo build locks or build output survive this script.
mkdir -p "$root/target"
export CARGO_TARGET_DIR
CARGO_TARGET_DIR="$(mktemp -d "$root/target/cross-XXXXXX")"
export COLOPHON_CROSS_TAG="$$-$(date +%s)"
export COLOPHON_CROSS_PID_FILE="$CARGO_TARGET_DIR/relay-pids.txt"
touch "$COLOPHON_CROSS_PID_FILE"
runner=""
relays() {
  local pid
  while IFS= read -r pid; do
    if kill -0 "$pid" 2>/dev/null; then echo "$pid"; fi
  done < "$COLOPHON_CROSS_PID_FILE"
}
finish() {
  local status=$? left
  trap - EXIT INT TERM
  if [[ -n "$runner" ]]; then kill -TERM "$runner" 2>/dev/null || true; wait "$runner" 2>/dev/null || true; fi
  left="$(relays)"
  if [[ -n "$left" ]]; then
    echo "test-cross: relay left behind ($left); killing it" >&2
    echo "$left" | xargs kill -9 2>/dev/null || true
    status=1
  fi
  rm -rf "$CARGO_TARGET_DIR"
  if [[ "$status" == 0 ]]; then
    echo 'test-cross: PASS — 10 cross-SDK tests, 5 Kotlin pairing tests, 4 revoked-reopen cases, no relay left behind'
  else
    echo "test-cross: FAIL (exit $status); no surviving relay from this run" >&2
  fi
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
wait_for_load() {
  local load report
  while true; do
    report="$(uptime)"
    echo "$report"
    load="$(printf '%s\n' "$report" | awk '{ gsub(/,/, "", $(NF-2)); print $(NF-2) }')"
    [[ "$load" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo 'test-cross: cannot read load' >&2; exit 1; }
    if awk -v load="$load" 'BEGIN { exit !(load <= 14) }'; then return; fi
    echo "test-cross: load $load exceeds 14; waiting" >&2
    sleep 20
  done
}
wait_for_load
cargo build --locked -j 4 --release -p colophon-ffi
wait_for_load
cargo build --locked -j 4 --target wasm32-unknown-unknown --release -p colophon-home-wasm
export COLOPHON_HOME_WASM="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/colophon_home_wasm.wasm"
if [[ ! -d sdk/apple/ColophonFFI.xcframework ]]; then
  wait_for_load
  APPLE_TOOLCHAIN=1.99.1 SKIP_VISIONOS=1 bash scripts/build-apple.sh
fi
export CLANG_MODULE_CACHE_PATH="$root/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$root/.build/module-cache"
export COLOPHON_SOFTWARE_KEYS=1
mkdir -p "$CLANG_MODULE_CACHE_PATH"
wait_for_load
swift build --disable-sandbox -j 4 --product ColophonCrossDevice
wait_for_load
swift test --disable-sandbox -j 4 --filter RevokedReopenTests
# SwiftPM's Xcode and native build systems use different product directories.
bin="$(swift build --disable-sandbox --show-bin-path)"
export COLOPHON_CROSS_SWIFT="$bin/ColophonCrossDevice"
[[ -x "$COLOPHON_CROSS_SWIFT" ]] || { echo "test-cross: driver missing at $COLOPHON_CROSS_SWIFT" >&2; exit 1; }
wait_for_load
sdk/kotlin/gradlew -p sdk/kotlin --no-daemon --max-workers=2 crossDeviceClasspath test --rerun \
  --tests com.luff.colophon.session.PairingTest --tests com.luff.colophon.session.RevokedReopenTest
bun test tests/cross &
runner=$!
status=0
wait "$runner" || status=$?
runner=""
exit "$status"
