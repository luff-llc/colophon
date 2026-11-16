#!/usr/bin/env bash
# Builds sdk/apple/ColophonFFI.xcframework (macOS, iOS device and simulator, visionOS device and
# simulator) from the 0.5 exports in crates/colophon-ffi, with the zero-on-free allocator on (the
# crate's default features: native05 + zero-on-free; never pass --no-default-features here).
# The framework is a local build product (it is git-ignored); the generated Swift is committed.
#
#   APPLE_TARGET_ROOT  where the per-slice target directories go (default: $CARGO_TARGET_DIR/apple,
#                      else ./target/apple). Delete it when done.
#   APPLE_TOOLCHAIN    a rustup toolchain that has the macOS and iOS targets (e.g. 1.97.0); default:
#                      the rustup default.
#   VISIONOS_TOOLCHAIN nightly toolchain with rust-src for -Zbuild-std (default: nightly).
#   SKIP_VISIONOS=1    an explicit fallback for machines without nightly/rust-src or the SDK.
#   RELEASE_NO_INSTALL=1  fail on a missing target, toolchain or rust-src instead of installing it
#                      (scripts/package-release.sh sets it).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
source_hash="$(bash scripts/apple-provenance.sh "$PWD" hash)"
root="${APPLE_TARGET_ROOT:-${CARGO_TARGET_DIR:-$PWD/target}/apple}"
tc=()
cargo_cmd=(cargo)
if [[ -n "${APPLE_TOOLCHAIN:-}" ]]; then
  tc=(--toolchain "$APPLE_TOOLCHAIN")
  cargo_cmd=(rustup run "$APPLE_TOOLCHAIN" cargo)
fi
# The host build for the bindings uses the same toolchain; its target dir is the caller's.
if [[ -n "${APPLE_TOOLCHAIN:-}" ]]; then export RUSTUP_TOOLCHAIN="$APPLE_TOOLCHAIN"; fi
LANGUAGES=swift bash scripts/generate-bindings.sh
unset RUSTUP_TOOLCHAIN
out="$PWD/sdk/apple"
staging="$root/headers"
mkdir -p "$out" "$staging"
cp swift/Sources/ColophonKit/Generated/ColophonFFI.h "$staging/"
cp swift/Sources/ColophonKit/Generated/ColophonFFI.modulemap "$staging/module.modulemap"
args=()
for target in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim; do
  if ! rustup target list --installed ${tc[@]+"${tc[@]}"} | grep -qx "$target"; then
    [[ "${RELEASE_NO_INSTALL:-0}" != 1 ]] || { echo "build-apple: Rust target $target is not installed" >&2; exit 1; }
    rustup target add "$target" ${tc[@]+"${tc[@]}"}
  fi
  # One target directory per slice, and no MACOSX_/IPHONEOS_DEPLOYMENT_TARGET: on macOS 27
  # those variables also reach the host proc-macro link and produce dylibs dyld refuses to
  # load ("mis-aligned LINKEDIT string pool"). The toolchain's default minimums (macOS 11,
  # iOS 14 or lower) are below the SDK's floors, so the static slices link cleanly into apps.
  CARGO_TARGET_DIR="$root/$target" \
    "${cargo_cmd[@]}" build --locked -p colophon-ffi --release --target "$target"
  args+=(-library "$root/$target/$target/release/libcolophon_ffi.a" -headers "$staging")
done
if [[ "${SKIP_VISIONOS:-0}" != 1 ]]; then
  nightly="${VISIONOS_TOOLCHAIN:-nightly}"
  if ! rustup run "$nightly" rustc --version >/dev/null 2>&1 || \
     [[ ! -d "$(rustup run "$nightly" rustc --print sysroot)/lib/rustlib/src/rust/library" ]]; then
    [[ "${RELEASE_NO_INSTALL:-0}" != 1 ]] || { echo "build-apple: $nightly with rust-src is not installed" >&2; exit 1; }
    rustup toolchain install "$nightly" --component rust-src
  fi
  for target in aarch64-apple-visionos aarch64-apple-visionos-sim; do
    if [[ "$target" == *-sim ]]; then sdk=xrsimulator; else sdk=xros; fi
    SDKROOT="$(xcrun --sdk "$sdk" --show-sdk-path)" XROS_DEPLOYMENT_TARGET=26.0 \
      CARGO_TARGET_DIR="$root/$target" rustup run "$nightly" cargo build --locked -Zbuild-std=std,panic_abort \
        -p colophon-ffi --release --target "$target"
    args+=(-library "$root/$target/$target/release/libcolophon_ffi.a" -headers "$staging")
  done
fi
# Refuse to attest to slices built while their sources changed.
[[ "$source_hash" == "$(bash scripts/apple-provenance.sh "$PWD" hash)" ]] || { echo 'build-apple: sources changed during build' >&2; exit 1; }
# Only replace a previous artifact after all slices built successfully.
rm -rf "$out/ColophonFFI.next.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$out/ColophonFFI.next.xcframework"
rm -f "$out/ColophonFFI.source-hash"
rm -rf "$out/ColophonFFI.xcframework"
mv "$out/ColophonFFI.next.xcframework" "$out/ColophonFFI.xcframework"
printf '%s\n' "$source_hash" > "$out/ColophonFFI.source-hash"
echo "build-apple: recorded source hash $source_hash"
du -sh "$out/ColophonFFI.xcframework"
