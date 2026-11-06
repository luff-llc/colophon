#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# SKIP_VISIONOS=1 is an explicit fallback for machines without nightly/rust-src or the SDK.
# RUSTUP_TOOLCHAIN can select a pinned stable toolchain; VISIONOS_TOOLCHAIN defaults to nightly.
bash scripts/generate-bindings.sh
out="$PWD/sdk/apple"
staging="$PWD/target/apple-headers"
mkdir -p "$out" "$staging"
cp swift/Sources/ColophonKit/Generated/ColophonFFI.h "$staging/"
cp swift/Sources/ColophonKit/Generated/ColophonFFI.modulemap "$staging/module.modulemap"
args=()
for target in aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim; do
  if ! rustup target list --installed | grep -qx "$target"; then rustup target add "$target"; fi
  MACOSX_DEPLOYMENT_TARGET=14.0 IPHONEOS_DEPLOYMENT_TARGET=17.0 \
    cargo build --locked -p colophon-ffi --release --target "$target"
  args+=(-library "$PWD/target/$target/release/libcolophon_ffi.a" -headers "$staging")
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
      cargo +"$nightly" build --locked -Zbuild-std=std,panic_abort \
        -p colophon-ffi --release --target "$target"
    args+=(-library "$PWD/target/$target/release/libcolophon_ffi.a" -headers "$staging")
  done
fi
# Only replace a previous artifact after all slices built successfully.
rm -rf "$out/ColophonFFI.next.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$out/ColophonFFI.next.xcframework"
rm -rf "$out/ColophonFFI.xcframework"
mv "$out/ColophonFFI.next.xcframework" "$out/ColophonFFI.xcframework"
du -sh "$out/ColophonFFI.xcframework"
