#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# The generated Swift (swift/Sources/ColophonKit/Generated) is committed; the XCFramework is not.
# CARGO_TARGET_DIR is honoured (default: ./target). LANGUAGES selects what to generate
# (default "swift kotlin"; a Swift-only change passes LANGUAGES=swift and leaves sdk/kotlin alone).
tdir="${CARGO_TARGET_DIR:-$PWD/target}"
languages="${LANGUAGES:-swift kotlin}"
# Keep CLI features out of the shipped library. Build it first, then the generator separately.
# The default features of colophon-ffi include native05 (the 0.5 exports) and zero-on-free.
CARGO_TARGET_DIR="$tdir" cargo build --locked -p colophon-ffi --release
CARGO_TARGET_DIR="$tdir" cargo build --locked -p colophon-ffi --features bindgen --bin uniffi-bindgen
for language in $languages; do
  if [[ "$language" == swift ]]; then out=swift/Sources/ColophonKit/Generated; else out=sdk/kotlin/src/main/kotlin; fi
  mkdir -p "$out"
  "$tdir/debug/uniffi-bindgen" generate --library "$tdir/release/libcolophon_ffi.dylib" \
    --language "$language" --config crates/colophon-ffi/uniffi.toml --out-dir "$out" --no-format
done
