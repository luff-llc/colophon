#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DST="$ROOT/hosts/swift/Tests/ModuleSpikeSimulatorTests/Resources"
mkdir -p "$DST"
WASM="$ROOT/out/notes.wasm"
if [ ! -f "$WASM" ]; then
  WASM="$ROOT/target/wasm32-unknown-unknown/release/colophon_module_abi_spike.wasm"
fi
cp "$WASM" "$DST/notes.wasm"
cp "$ROOT/out/notes-metered.wasm" "$DST/notes-metered.wasm"
cp "$ROOT/out/operations.jsonl" "$DST/operations.jsonl"
for N in 1 1000 10000; do
  cp "$ROOT/out/expected-$N.json" "$ROOT/out/expected-query-$N.json" "$DST/"
done
echo "Prepared iOS Simulator test resources in $DST"
