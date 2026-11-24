#!/usr/bin/env bash
# Builds what the JavaScript SDK's tests need and runs them (js/): the web05 wasm exports and their wasm-bindgen glue,
# the test-only session conformance module and its glue (js/.conformance/, never part of the package), the relay's
# home module, the TypeScript build (strict; the 0.4 package, the 0.5 session and the 0.6 hosts), then every test: the
# 0.4 package's own, the 0.5 session's unit tests and its journeys against the real relay under Bun (bun test), the 0.6
# hosts' tests (js/test06: stream and cell host unit tests, the session conformance replay, and the handoff and session
# journeys against the real relay over WebSockets), and the 0.5 journeys, IndexedDB, WebCrypto key handles and a
# WebAuthn passkey with PRF in a real browser engine (headless Chrome, driven by js/test05/run-browser.ts). Without
# Bun, Chrome, openssl or the modules it fails; nothing passes by
# skipping. Extra arguments go to `bun test` (for example `-t quorum`).
#
# It leaves no relay and no browser behind: each run stops what it started (and an exit hook kills the relays if the
# run dies), and this script then looks for any relay or browser started during the run, kills it and fails.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
export PATH="$HOME/.cargo/tools/wasm-bindgen-0.2.130/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
target="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_TARGET_DIR="$target"
for tool in bun node npm openssl wasm-bindgen; do
  command -v "$tool" >/dev/null || { echo "test-js: $tool is required" >&2; exit 1; }
done
expected=0.2.130
[[ "$(wasm-bindgen --version)" == "wasm-bindgen $expected" ]] || { echo "test-js: wasm-bindgen $expected is required; found $(wasm-bindgen --version)" >&2; exit 1; }

cargo build --locked --target wasm32-unknown-unknown --profile release-wasm -p colophon-wasm
cargo build --locked --target wasm32-unknown-unknown --profile release-wasm -p colophon-conformance-wasm
cargo build --locked --target wasm32-unknown-unknown --release -p colophon-home-wasm
export COLOPHON_HOME_WASM="${COLOPHON_HOME_WASM:-$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm}"
echo "test-js: home module $(wc -c < "$COLOPHON_HOME_WASM" | tr -d ' ') bytes"
rm -rf js/dist
mkdir -p js/dist/wasm
wasm-bindgen --target web --out-dir js/dist/wasm --out-name colophon_wasm "$target/wasm32-unknown-unknown/release-wasm/colophon_wasm.wasm"
rm -rf js/.conformance
mkdir -p js/.conformance
wasm-bindgen --target web --out-dir js/.conformance --out-name colophon_conformance "$target/wasm32-unknown-unknown/release-wasm/colophon_conformance_wasm.wasm"
npm ci --prefix js --no-audit --no-fund
(cd js && ./node_modules/.bin/tsc -p tsconfig.json && ./node_modules/.bin/tsc -p test05/tsconfig.json && ./node_modules/.bin/tsc -p test06/tsconfig.json)
echo "test-js: TypeScript built (strict), tests typechecked"

# The tests' relays run with a data directory named colophon-js-relay-<pid>-..., the browser with a profile under
# colophon-js-browser-...; remember any already running (another checkout's run) so only this run's are judged.
strays() { pgrep -f "colophon-js-relay-|colophon-js-browser-" 2>/dev/null | sort || true; }
before="$(strays)"
leftover() { comm -13 <(printf '%s\n' "$before") <(strays) | sed '/^$/d'; }
status=0
npm --prefix js test || status=$?
(cd js && bun test test05 "$@") || status=$?
(cd js && bun test test06 "$@") || status=$?
(cd js && bun test05/run-browser.ts) || status=$?
left="$(leftover)"
if [[ -n "$left" ]]; then
  echo "test-js: processes were left behind: $(echo $left); killing them" >&2
  echo "$left" | xargs kill -9 2>/dev/null || true
  status=1
else
  echo "test-js: no relay or browser process left behind"
fi
exit "$status"
