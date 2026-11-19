#!/usr/bin/env bash
# Builds what the Kotlin SDK's JVM tests need and runs them (sdk/kotlin): the release library, the generated
# bindings (checked against the committed ones), the relay's home module, then every test, the 0.4 wrappers and the
# 0.5 session, including the journeys against the real relay (Bun with the Rust home module). Without Bun or the
# module the journeys fail; they never pass by skipping. Extra arguments go to Gradle (for example
# `--tests 'com.luff.colophon.session.*'`).
#
# It leaves no relay process behind: each test stops its relays (and a shutdown hook kills them if the JVM dies),
# and this script fails if a new relay remains. It never kills a process it did not start.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$root/.gradle-home}"
# Gradle 8.14 runs on JDK 17 to 24; the Homebrew default may be newer.
if [[ -z "${JAVA_HOME:-}" && -d /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home ]]; then
  export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
target="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_TARGET_DIR="$target"
command -v bun >/dev/null || { echo "test-kotlin: bun is required for the relay journeys" >&2; exit 1; }

cargo build --locked -p colophon-ffi --release
# The committed bindings must be what the generator makes from this library (nothing hand-edited).
cargo build --locked -p colophon-ffi --features bindgen --bin uniffi-bindgen
generated="$(mktemp -d)"
"$target/debug/uniffi-bindgen" generate --library "$target/release/libcolophon_ffi.dylib" --language kotlin \
  --config crates/colophon-ffi/uniffi.toml --out-dir "$generated" --no-format >/dev/null
if ! cmp -s "$generated/com/luff/colophon/colophon_ffi.kt" sdk/kotlin/src/main/kotlin/com/luff/colophon/colophon_ffi.kt; then
  rm -rf "$generated"
  echo "test-kotlin: sdk/kotlin's generated bindings are stale; run LANGUAGES=kotlin scripts/generate-bindings.sh" >&2
  exit 1
fi
rm -rf "$generated"
echo "test-kotlin: generated bindings match the library"

cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
export COLOPHON_HOME_WASM="${COLOPHON_HOME_WASM:-$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm}"
echo "test-kotlin: home module $(wc -c < "$COLOPHON_HOME_WASM" | tr -d ' ') bytes"

# The tests' relays run with a data directory named colophon-kotlin-relay-<JVM pid>-...; remember any that were
# already running (another checkout's run) so only this run's are judged.
relays() { pgrep -f "colophon-kotlin-relay-" 2>/dev/null | sort || true; }
before="$(relays)"
leftover() { comm -13 <(printf '%s\n' "$before") <(relays) | sed '/^$/d'; }
status=0
# --rerun: a test run is never skipped as up to date.
sdk/kotlin/gradlew -p sdk/kotlin --no-daemon test --rerun "$@" || status=$?
left="$(leftover)"
if [[ -n "$left" ]]; then
  echo "test-kotlin: relay processes were left behind: $(echo $left); their owning test must stop them" >&2
  status=1
else
  echo "test-kotlin: no relay process left behind"
fi
exit "$status"
