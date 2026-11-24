#!/usr/bin/env bash
# Builds what the 0.6 host tests need and runs them (js/test06): the web05 wasm exports and their glue (the shipped
# module), the conformance module and its glue (test-only, into js/.conformance/, never into dist/ or the package),
# the relay's home module, the strict TypeScript build, then `bun test test06`: the stream and cell host unit tests,
# the conformance replay, and the end-to-end journeys against the real relay over WebSockets. Without Bun or the
# modules it fails; nothing passes by skipping. Extra arguments go to `bun test` (for example `-t handoff`).
#
# Set COLOPHON_SKIP_BUILD=1 to reuse modules already built (CARGO_TARGET_DIR, or COLOPHON_HOME_WASM for the home).
set -euo pipefail
cd "$(dirname "$0")/../.."
root="$PWD"
export PATH="$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
target="${CARGO_TARGET_DIR:-$root/target}"
for tool in bun node npm wasm-bindgen; do
  command -v "$tool" >/dev/null || { echo "test-hosts: $tool is required" >&2; exit 1; }
done
expected=0.2.130
[[ "$(wasm-bindgen --version)" == "wasm-bindgen $expected" ]] || { echo "test-hosts: wasm-bindgen $expected is required; found $(wasm-bindgen --version)" >&2; exit 1; }

if [[ "${COLOPHON_SKIP_BUILD:-}" != 1 ]]; then
  cargo build --locked --target wasm32-unknown-unknown --profile release-wasm -p colophon-wasm
  cargo build --locked --target wasm32-unknown-unknown --profile release-wasm -p colophon-conformance-wasm
  cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
fi
export COLOPHON_HOME_WASM="${COLOPHON_HOME_WASM:-$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm}"
[[ -f "$COLOPHON_HOME_WASM" ]] || { echo "test-hosts: the home module is missing: $COLOPHON_HOME_WASM" >&2; exit 1; }
mkdir -p js/dist/wasm js/.conformance
wasm-bindgen --target web --out-dir js/dist/wasm --out-name colophon_wasm "$target/wasm32-unknown-unknown/release-wasm/colophon_wasm.wasm"
wasm-bindgen --target web --out-dir js/.conformance --out-name colophon_conformance "$target/wasm32-unknown-unknown/release-wasm/colophon_conformance_wasm.wasm"
[[ -d js/node_modules ]] || npm ci --prefix js --no-audit --no-fund
(cd js && ./node_modules/.bin/tsc -p tsconfig.json && ./node_modules/.bin/tsc -p test06/tsconfig.json)
echo "test-hosts: TypeScript built (strict), tests typechecked"
cd js && bun test test06 "$@"
