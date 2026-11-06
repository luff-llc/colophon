#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# Keep CLI features out of the shipped library. Build it first, then the generator separately.
cargo build --locked -p colophon-ffi --release
cargo build --locked -p colophon-ffi --features bindgen --bin uniffi-bindgen
mkdir -p swift/Sources/ColophonKit/Generated sdk/kotlin/src/main/kotlin
for language in swift kotlin; do
  if [[ "$language" == swift ]]; then out=swift/Sources/ColophonKit/Generated; else out=sdk/kotlin/src/main/kotlin; fi
  target/debug/uniffi-bindgen generate --library target/release/libcolophon_ffi.dylib \
    --language "$language" --config crates/colophon-ffi/uniffi.toml --out-dir "$out" --no-format
done
