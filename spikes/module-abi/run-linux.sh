#!/usr/bin/env bash
# Reproduce native/Bun/Chromium baselines; requires tools listed in README.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
cd "$REPO"
mkdir -p "$ROOT/out"
{
  rustc --version
  cargo --version
  node --version
  npm --version
  bun --version
  python3 --version
  wasm2wat --version
  wat2wasm --version
} | tee "$ROOT/out/tool-versions-linux.txt"
cargo test --release --manifest-path "$ROOT/Cargo.toml"
# wasm-ld encodes a 64 MiB *maximum*, not just an initial memory size.
RUSTFLAGS="-C link-arg=--max-memory=67108864" cargo build --release \
  --target wasm32-unknown-unknown --manifest-path "$ROOT/Cargo.toml" --lib
cargo run --release --manifest-path "$ROOT/Cargo.toml" --bin fixture -- "$ROOT/out"
cp "$ROOT/target/wasm32-unknown-unknown/release/colophon_module_abi_spike.wasm" "$ROOT/out/notes.wasm"
python3 "$ROOT/audit.py" "$ROOT/out/notes.wasm" "$ROOT/out/wasm-audit.json"
python3 "$ROOT/instrument.py" "$ROOT/out/notes.wasm" "$ROOT/out/notes-metered.wasm"
python3 "$ROOT/audit.py" "$ROOT/out/notes-metered.wasm" "$ROOT/out/wasm-metered-audit.json"
bun "$ROOT/hosts/bun.mjs" "$ROOT/out/notes.wasm" "$ROOT/out" "$ROOT/out/notes-metered.wasm"
npm install --prefix "$ROOT" --no-audit --no-fund --save=false
npx --prefix "$ROOT" playwright install chromium
python3 -m http.server 8765 --bind 127.0.0.1 > "$ROOT/out/http-server.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 2
node "$ROOT/hosts/browser-runner.mjs" http://127.0.0.1:8765 "$ROOT/out" "out/notes-metered.wasm"
echo "All executable Linux-host comparisons finished. Results in $ROOT/out/"
