#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/module-cache
export CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache"
for entry in \
  'iphoneos arm64-apple-ios17.0 ios-arm64' \
  'iphonesimulator arm64-apple-ios17.0-simulator ios-arm64-simulator' \
  'xros arm64-apple-xros26.0 xros-arm64' \
  'xrsimulator arm64-apple-xros26.0-simulator xros-arm64-simulator'; do
  read -r sdk target slice <<< "$entry"
  xcrun swiftc -typecheck -parse-as-library -swift-version 6 -module-name ColophonKit \
    -target "$target" -sdk "$(xcrun --sdk "$sdk" --show-sdk-path)" \
    -I "sdk/apple/ColophonFFI.xcframework/$slice/Headers" \
    swift/Sources/ColophonKit/Generated/ColophonBindings.swift \
    swift/Sources/ColophonKit/Keys.swift swift/Sources/ColophonKit/Library.swift
  echo "ColophonKit typechecked: $target"
done
