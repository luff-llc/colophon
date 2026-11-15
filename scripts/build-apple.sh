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
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
root="${APPLE_TARGET_ROOT:-${CARGO_TARGET_DIR:-$PWD/target}/apple}"
tc=()
if [[ -n "${APPLE_TOOLCHAIN:-}" ]]; then tc=("+$APPLE_TOOLCHAIN"); fi
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
  if ! rustup ${tc[@]+"${tc[@]}"} target list --installed | grep -qx "$target"; then
    rustup ${tc[@]+"${tc[@]}"} target add "$target"
  fi
  # One target directory per slice, and no MACOSX_/IPHONEOS_DEPLOYMENT_TARGET: on macOS 27
  # those variables also reach the host proc-macro link and produce dylibs dyld refuses to
  # load ("mis-aligned LINKEDIT string pool"). The toolchain's default minimums (macOS 11,
  # iOS 14 or lower) are below the SDK's floors, so the static slices link cleanly into apps.
  CARGO_TARGET_DIR="$root/$target" \
    cargo ${tc[@]+"${tc[@]}"} build --locked -p colophon-ffi --release --target "$target"
  args+=(-library "$root/$target/$target/release/libcolophon_ffi.a" -headers "$staging")
done
if [[ "${SKIP_VISIONOS:-0}" != 1 ]]; then
  nightly="${VISIONOS_TOOLCHAIN:-nightly}"
  if ! rustup run "$nightly" rustc --version >/dev/null 2>&1 || \
     [[ ! -d "$(rustc +"$nightly" --print sysroot)/lib/rustlib/src/rust/library" ]]; then
    rustup toolchain install "$nightly" --component rust-src
  fi
  for target in aarch64-apple-visionos aarch64-apple-visionos-sim; do
    if [[ "$target" == *-sim ]]; then sdk=xrsimulator; else sdk=xros; fi
    SDKROOT="$(xcrun --sdk "$sdk" --show-sdk-path)" XROS_DEPLOYMENT_TARGET=26.0 \
      CARGO_TARGET_DIR="$root/$target" cargo +"$nightly" build --locked -Zbuild-std=std,panic_abort \
        -p colophon-ffi --release --target "$target"
    args+=(-library "$root/$target/$target/release/libcolophon_ffi.a" -headers "$staging")
  done
fi
# Only replace a previous artifact after all slices built successfully.
rm -rf "$out/ColophonFFI.next.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$out/ColophonFFI.next.xcframework"
rm -rf "$out/ColophonFFI.xcframework"
mv "$out/ColophonFFI.next.xcframework" "$out/ColophonFFI.xcframework"
du -sh "$out/ColophonFFI.xcframework"
