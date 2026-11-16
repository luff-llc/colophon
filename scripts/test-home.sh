#!/usr/bin/env bash
# Build the home module (wasm32, release) and run every test of the relay as a Colophon 0.5
# home: the Rust tests that start the relay as a process, and the Bun tests. CI runs this
# script. With CI set (or COLOPHON_REQUIRE_RELAY=1) a missing Bun or module fails the run
# instead of being skipped.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
export COLOPHON_REQUIRE_RELAY=1
target="${CARGO_TARGET_DIR:-$root/target}"
command -v bun >/dev/null || { echo "test-home: bun is required" >&2; exit 1; }
cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
wasm="$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm"
echo "test-home: module $(wc -c < "$wasm" | tr -d ' ') bytes"
export COLOPHON_HOME_WASM="$wasm"
cargo test --locked -p colophon-home-wasm --no-fail-fast
# The kill loop (at least 200 SIGKILLs, about 9 minutes): ignored in the workspace run, run here.
cargo test --locked -p colophon-home-wasm --test v05_relay_kill -- --ignored --nocapture 2>&1 | grep -v '^trace '
cargo test --locked -p colophon-core --test v05_home --test v05_home_h1 --test v05_home_h2 --test v05_home_h2_succession --test v05_engine_home
(cd relay && bun test)
