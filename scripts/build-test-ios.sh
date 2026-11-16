#!/usr/bin/env bash
# Build the Colophon test app for iPhone (apps/test-ios).
#
#   scripts/build-test-ios.sh                 simulator build (Debug, arm64)
#   scripts/build-test-ios.sh --test SIM      also run the UI tests on the simulator named SIM (by name or UDID),
#                                             against a local home (apps/test-home and the relay, started and
#                                             stopped here); boots SIM if it is shut down and shuts it down after
#   scripts/build-test-ios.sh --device        also a device build, only when COLOPHON_TEAM_ID is set (signing comes
#                                             from the environment, never from the repository)
#
# Needs the XCFramework at sdk/apple/ColophonFFI.xcframework (scripts/build-apple.sh) and, for --test, Bun and the
# home module (cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm). Build defaults can be
# overridden with COLOPHON_HOME_PREFIX, COLOPHON_HOME_REACH, COLOPHON_PROVISIONER and COLOPHON_RELYING_PARTY.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
project=apps/test-ios/ColophonTest.xcodeproj
derived="$root/.build/test-ios"
[[ -d sdk/apple/ColophonFFI.xcframework ]] || { echo "build-test-ios: build sdk/apple/ColophonFFI.xcframework first (scripts/build-apple.sh)" >&2; exit 1; }

overrides=()
for name in COLOPHON_HOME_PREFIX COLOPHON_HOME_REACH COLOPHON_PROVISIONER COLOPHON_RELYING_PARTY; do
  if [[ -n "${!name:-}" ]]; then overrides+=("$name=${!name}"); fi
done

mode="${1:-}"
xcodebuild -project "$project" -scheme ColophonTest -configuration Debug -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$derived" CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual ${overrides[@]+"${overrides[@]}"} build | tail -n 3
echo "build-test-ios: $derived/Build/Products/Debug-iphonesimulator/ColophonTest.app"

if [[ "$mode" == --device ]]; then
  if [[ -z "${COLOPHON_TEAM_ID:-}" ]]; then
    echo "build-test-ios: no device build: set COLOPHON_TEAM_ID (and sign in to Xcode with that team)"
  else
    xcodebuild -project "$project" -scheme ColophonTest -configuration Debug -destination 'generic/platform=iOS' \
      -derivedDataPath "$derived" DEVELOPMENT_TEAM="$COLOPHON_TEAM_ID" -allowProvisioningUpdates \
      ${overrides[@]+"${overrides[@]}"} build | tail -n 3
  fi
fi

if [[ "$mode" == --test ]]; then
  sim="${2:?build-test-ios: --test needs a simulator name or UDID}"
  udid=$(xcrun simctl list devices available | grep -F "$sim (" | head -n 1 | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/')
  [[ -n "$udid" ]] || { echo "build-test-ios: no available simulator named $sim" >&2; exit 1; }
  cargo build --locked --quiet --target wasm32-unknown-unknown --release -p colophon-home-wasm
  data="$(mktemp -d "${TMPDIR:-/tmp}/colophon-test-home.XXXXXX")"
  swift build --package-path apps/test-home -c debug >/dev/null
  apps/test-home/.build/debug/colophon-test-home --data "$data" > "$data/out" 2> "$data/log" &
  home=$!
  booted=0
  cleanup() {
    kill "$home" 2>/dev/null || true; wait "$home" 2>/dev/null || true
    if [[ $booted == 1 ]]; then xcrun simctl shutdown "$udid" || true; fi
    rm -rf "$data"
  }
  trap cleanup EXIT
  for _ in $(seq 50); do grep -q listening "$data/out" 2>/dev/null && break; sleep 0.2; done
  token=$(sed -nE 's/.*"token":"([0-9a-f]+)".*/\1/p' "$data/out")
  [[ -n "$token" ]] || { echo "build-test-ios: the home service did not start" >&2; cat "$data/log" >&2; exit 1; }
  if xcrun simctl list devices | grep -F "$udid" | grep -q Shutdown; then xcrun simctl boot "$udid"; booted=1; fi
  set +e
  TEST_RUNNER_COLOPHON_PROVISIONER_TOKEN="$token" xcodebuild -project "$project" -scheme ColophonTest -configuration Debug -destination "id=$udid" \
    -derivedDataPath "$derived" CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual ${overrides[@]+"${overrides[@]}"} \
    -only-testing:ColophonTestTests -only-testing:ColophonTestUITests/ColophonTestUITests/${COLOPHON_UI_TEST:-testOneDeviceJourney} test 2>&1 \
    | tee "${COLOPHON_TEST_LOG:-/dev/null}" | grep -E "Test Case|Test run|✘|error:|passed|failed|TEST (SUCCEEDED|FAILED)"
  status=${PIPESTATUS[0]}
  set -e
  echo "build-test-ios: home service log:"; cat "$data/log"
  exit "$status"
fi
