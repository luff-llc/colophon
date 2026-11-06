#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
expected=0.2.130
actual="$(wasm-bindgen --version)"
if [[ "$actual" != "wasm-bindgen $expected" ]]; then
  echo "Expected wasm-bindgen $expected; found $actual" >&2
  exit 1
fi
cargo build --locked -p colophon-wasm --target wasm32-unknown-unknown --release
mkdir -p js/dist/wasm
wasm-bindgen --target web --out-dir js/dist/wasm --out-name colophon_wasm "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/colophon_wasm.wasm"
cd js
./node_modules/.bin/tsc -p tsconfig.json
