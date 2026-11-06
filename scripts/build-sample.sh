#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
project=examples/ColophonSample/ColophonSample.xcodeproj
flags=()
if [[ "${1:-}" == --restricted ]]; then
  # Avoid nested sandbox-exec for manifest/macro subprocesses. The enclosing sandbox remains.
  python3 examples/ColophonSample/generate-project.py --standalone
  project=.build/sample-project/ColophonSample.xcodeproj
  flags+=(OTHER_SWIFT_FLAGS=-disable-sandbox)
  mkdir -p .build/xcode-home
  export CFFIXED_USER_HOME="$PWD/.build/xcode-home"
else
  python3 examples/ColophonSample/generate-project.py
fi
for platform in macOS 'iOS Simulator'; do
  xcodebuild -project "$project" -scheme ColophonSample -configuration Debug \
    -destination "generic/platform=$platform" -derivedDataPath .build/sample \
    CODE_SIGN_IDENTITY=- ARCHS=arm64 ${flags[@]+"${flags[@]}"} build
done
