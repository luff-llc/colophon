#!/usr/bin/env bash
# The Swift 0.6 hosts' tests (docs/hosts-06.md section 6): ColophonHostsTests (the unit suites and the end-to-end
# journeys against the real relay) and the conformance replay in swift/Conformance06, which links the conformance
# crate's artifact. Builds a macOS slice only. Each library is built here unless given:
#   COLOPHON_FFI_LIB            libcolophon_ffi.a (release)
#   COLOPHON_CONFORMANCE_LIB    libcolophon_conformance.a (release; its .dylib beside it is read for the bindings)
#   COLOPHON_HOME_WASM          colophon_home_wasm.wasm (the relay's home module)
#   UNIFFI_BINDGEN              uniffi-bindgen (colophon-ffi --features bindgen)
# Private copies are kept in .build/hosts06, so another checkout sharing the cargo target cannot swap them mid-run.
set -euo pipefail
cd "$(dirname "$0")/.."
target="${CARGO_TARGET_DIR:-$PWD/target}"
work="$PWD/.build/hosts06"
mkdir -p "$work"

ffi="${COLOPHON_FFI_LIB:-}"
conformance="${COLOPHON_CONFORMANCE_LIB:-}"
home="${COLOPHON_HOME_WASM:-}"
bindgen="${UNIFFI_BINDGEN:-}"
if [[ -z "$ffi" ]]; then cargo build --locked --quiet --release -p colophon-ffi; ffi="$target/release/libcolophon_ffi.a"; fi
if [[ -z "$conformance" ]]; then cargo build --locked --quiet --release -p colophon-conformance; conformance="$target/release/libcolophon_conformance.a"; fi
if [[ -z "$home" ]]; then
  cargo build --locked --quiet --target wasm32-unknown-unknown --release -p colophon-home-wasm
  home="$target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm"
fi
if [[ -z "$bindgen" ]]; then cargo build --locked --quiet -p colophon-ffi --features bindgen --bin uniffi-bindgen; bindgen="$target/debug/uniffi-bindgen"; fi
for f in "$ffi" "$conformance" "${conformance%.a}.dylib" "$home" "$bindgen"; do
  [[ -f "$f" ]] || { echo "missing: $f" >&2; exit 1; }
done
[[ "$ffi" == "$work/libcolophon_ffi.a" ]] || cp "$ffi" "$work/libcolophon_ffi.a"
[[ "$conformance" == "$work/libcolophon_conformance.a" ]] || cp "$conformance" "$work/libcolophon_conformance.a"
[[ "$home" == "$work/colophon_home_wasm.wasm" ]] || cp "$home" "$work/colophon_home_wasm.wasm"

# The shipping XCFramework (macOS slice) from the committed headers.
rm -rf "$work/headers" sdk/apple/ColophonFFI.xcframework
mkdir -p "$work/headers"
cp swift/Sources/ColophonKit/Generated/ColophonFFI.h "$work/headers/"
cp swift/Sources/ColophonKit/Generated/ColophonFFI.modulemap "$work/headers/module.modulemap"
xcodebuild -create-xcframework -library "$work/libcolophon_ffi.a" -headers "$work/headers" \
  -output sdk/apple/ColophonFFI.xcframework >/dev/null

# The conformance artifact and its Swift, for the test-only package.
rm -rf "$work/gen" "$work/conformance-headers" swift/Conformance06/Artifacts swift/Conformance06/Generated
mkdir -p "$work/gen" "$work/conformance-headers" swift/Conformance06/Generated
"$bindgen" generate --library "${conformance%.a}.dylib" --language swift --out-dir "$work/gen" --no-format >/dev/null
cp "$work/gen/colophon_conformance.swift" swift/Conformance06/Generated/
cp "$work/gen/colophon_conformanceFFI.h" "$work/conformance-headers/"
cp "$work/gen/colophon_conformanceFFI.modulemap" "$work/conformance-headers/module.modulemap"
xcodebuild -create-xcframework -library "$work/libcolophon_conformance.a" -headers "$work/conformance-headers" \
  -output swift/Conformance06/Artifacts/ColophonConformanceFFI.xcframework >/dev/null

mkdir -p .build/module-cache
export CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"
export COLOPHON_SOFTWARE_KEYS=1
export COLOPHON_HOME_WASM="$work/colophon_home_wasm.wasm"
swift test --disable-sandbox --filter ColophonHostsTests "$@"
swift test --disable-sandbox --package-path swift/Conformance06
