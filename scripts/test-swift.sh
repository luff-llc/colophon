#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Cache paths stay inside this worktree. --disable-sandbox avoids nested sandbox-exec on
# restricted builders; it does not grant access to filecoordinationd or backup services.
mkdir -p .build/module-cache
export CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"
export COLOPHON_SOFTWARE_KEYS=1
# The relay journeys (RelayJourneyTests) start the real relay: they need Bun and the home module, built here.
target="${CARGO_TARGET_DIR:-$PWD/target}"
cargo build --locked --quiet --target wasm32-unknown-unknown --release -p colophon-home-wasm
export COLOPHON_HOME_WASM="${COLOPHON_HOME_WASM:-$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm}"
swift test --disable-sandbox "$@"
