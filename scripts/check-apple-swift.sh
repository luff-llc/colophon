#!/usr/bin/env bash
# Builds every Swift product of the package for the iOS and visionOS simulators in Swift 6 mode and fails on any
# warning. Needs sdk/apple/ColophonFFI.xcframework (scripts/build-apple.sh). Derived data stays in the worktree.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .build/module-cache
export CLANG_MODULE_CACHE_PATH="$PWD/.build/module-cache"
for entry in 'iOS Simulator' 'visionOS Simulator'; do
  log=".build/check-apple-swift-${entry// /-}.log"
  rm -rf ".build/check-derived"
  xcodebuild -scheme ColophonSDK-Package -destination "generic/platform=$entry" -derivedDataPath .build/check-derived \
    -skipPackagePluginValidation build > "$log" 2>&1 || { tail -40 "$log"; echo "build failed for $entry"; exit 1; }
  warnings=$(grep -c "warning:" "$log" || true)
  echo "$entry: build succeeded, $warnings warning(s)"
  if [[ "$warnings" != 0 ]]; then grep -E "warning:" "$log" | sort -u | head -20; exit 1; fi
done
