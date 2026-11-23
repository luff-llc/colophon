#!/usr/bin/env bash
# The idle cost of home slots (relay/test/bench-idle.js): builds the home module, builds a
# realistic slot with the real relay (crates/colophon-home-wasm/tests/v05_relay_idle_fixture.rs)
# when the fixture directory holds none, then runs N copies of it with nobody connected and
# prints, per N, the CPU seconds the relay used per wall-clock minute and the module calls it
# made. Then the cost of single module calls on that slot, for the module built here.
#
#   scripts/bench-home-idle.sh [fixture-dir] [extra bench-idle.js arguments, e.g. --slots 1,8]
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
target="${CARGO_TARGET_DIR:-$PWD/target}"
fixture="${1:-$target/bench-home-idle}"
shift || true
command -v bun >/dev/null || { echo "bench-home-idle: bun is required" >&2; exit 1; }
cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
wasm="$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm"
if [[ ! -f "$fixture/meta.json" ]]; then
  mkdir -p "$fixture"
  COLOPHON_HOME_WASM="$wasm" COLOPHON_REQUIRE_RELAY=1 COLOPHON_IDLE_FIXTURE="$fixture" \
    cargo test --locked -p colophon-home-wasm --test v05_relay_idle_fixture -- --ignored 2>&1 | grep -v '^trace '
fi
bun relay/test/bench-idle.js --wasm "$wasm" --fixture "$fixture" "$@" 2>/dev/null
bun relay/test/bench-idle.js --micro --wasm "$wasm" --fixture "$fixture"
