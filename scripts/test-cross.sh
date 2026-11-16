#!/usr/bin/env bash
# macOS host proof of the Swift and Kotlin SDKs sharing one account through real signed-call homes.
# Run through pressroom; its grant controls build concurrency.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
export PATH="$HOME/.rustup/toolchains/1.99.1-aarch64-apple-darwin/bin:$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin:$PATH"
umask 077
command -v bun >/dev/null || { echo 'test-cross: bun is required' >&2; exit 1; }
command -v swift >/dev/null || { echo 'test-cross: Swift on macOS is required' >&2; exit 1; }
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
jobs="${PRESSROOM_THREADS:-4}"
# A private target per invocation. The caller can supply its private run target to reuse builds.
mkdir -p "$root/target"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(mktemp -d "$root/target/cross-XXXXXX")}"
case "$CARGO_TARGET_DIR" in "$root"/target/*) ;; *) echo 'test-cross: CARGO_TARGET_DIR must be private to this worktree under target/' >&2; exit 1 ;; esac
mkdir -p "$CARGO_TARGET_DIR"
export COLOPHON_CROSS_RUN_DIR
COLOPHON_CROSS_RUN_DIR="$(mktemp -d "$CARGO_TARGET_DIR/devices-XXXXXX")"
runner=""
swift_count=0 kotlin_count=0 bun_count=0
finish() {
  local status=$?
  trap - EXIT INT TERM
  # runner is our unreaped direct child. Relay handles belong to Bun's World, which handles TERM.
  if [[ -n "$runner" ]]; then kill -TERM "$runner" 2>/dev/null || true; wait "$runner" 2>/dev/null || true; fi
  rm -rf "$CARGO_TARGET_DIR"
  if [[ "$status" == 0 ]]; then
    echo "test-cross: PASS — $bun_count Bun tests, $swift_count Swift tests, $kotlin_count Kotlin tests; owned children closed"
  else
    echo "test-cross: FAIL (exit $status)" >&2
  fi
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_logged() {
  local log="$1" status=0; shift
  "$@" > "$log" 2>&1 &
  runner=$!
  wait "$runner" || status=$?
  runner=""
  cat "$log"
  return "$status"
}
source_hash="$(bash scripts/apple-provenance.sh "$root" hash)"
cargo build --locked -j "$jobs" --release -p colophon-ffi
cargo build --locked -j "$jobs" --target wasm32-unknown-unknown --release -p colophon-home-wasm
export COLOPHON_HOME_WASM="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/colophon_home_wasm.wasm"
[[ "$source_hash" == "$(bash scripts/apple-provenance.sh "$root" hash)" ]] || { echo 'test-cross: sources changed during native build' >&2; exit 1; }
if bash scripts/apple-provenance.sh "$root" check; then
  echo "test-cross: reusing Apple framework; source hash $source_hash matches"
else
  echo "test-cross: rebuilding Apple framework; source hash $source_hash (stamp missing or stale)"
  APPLE_TOOLCHAIN=1.99.1 SKIP_VISIONOS=1 bash scripts/build-apple.sh
fi
bash scripts/apple-provenance.sh "$root" check || { echo 'test-cross: framework provenance changed during build' >&2; exit 1; }
export CLANG_MODULE_CACHE_PATH="$root/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$root/.build/module-cache"
export COLOPHON_SOFTWARE_KEYS=1
mkdir -p "$CLANG_MODULE_CACHE_PATH"
swift build --disable-sandbox -j "$jobs" --product ColophonCrossDevice
run_logged "$CARGO_TARGET_DIR/swift.log" swift test --disable-sandbox -j "$jobs" --filter 'RevokedReopenTests|PairingTests'
swift_count="$(bun scripts/cross-results.ts swift "$CARGO_TARGET_DIR/swift.log")"
bin="$(swift build --disable-sandbox --show-bin-path)"
export COLOPHON_CROSS_SWIFT="$bin/ColophonCrossDevice"
[[ -x "$COLOPHON_CROSS_SWIFT" ]] || { echo "test-cross: driver missing at $COLOPHON_CROSS_SWIFT" >&2; exit 1; }
sdk/kotlin/gradlew -p sdk/kotlin --no-daemon --max-workers="$jobs" crossDeviceClasspath test --rerun \
  --tests com.luff.colophon.session.PairingTest --tests com.luff.colophon.session.RevokedReopenTest
kotlin_count="$(bun scripts/cross-results.ts kotlin sdk/kotlin/build/test-results/test)"
run_logged "$CARGO_TARGET_DIR/bun.log" bun test tests/cross
bun_count="$(bun scripts/cross-results.ts bun "$CARGO_TARGET_DIR/bun.log")"
[[ "$source_hash" == "$(bash scripts/apple-provenance.sh "$root" hash)" ]] && bash scripts/apple-provenance.sh "$root" check
