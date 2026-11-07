#!/usr/bin/env bash
# Run after build-apple.sh; do not run other builds/benchmarks concurrently.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
export COLOPHON_SESSION_FIXTURE="$PWD/target/engine-sessions"
mkdir -p "$COLOPHON_SESSION_FIXTURE"
if [[ ! -f "$COLOPHON_SESSION_FIXTURE/100k.records" ]]; then
  cargo run --release -p colophon-core --example bench -- 100000 "$COLOPHON_SESSION_FIXTURE/100k.records"
fi
cargo run --release -p colophon-core --example session_fixture -- "$COLOPHON_SESSION_FIXTURE"
for mode in legacy engine; do
  export COLOPHON_SESSION_BENCH="$mode"
  bash scripts/test-swift.sh -c release --filter SessionPerformanceTests \
    > "$COLOPHON_SESSION_FIXTURE/swift-$mode.log" 2>&1
  rg 'SESSION_BENCH|SESSION_WORK' "$COLOPHON_SESSION_FIXTURE/swift-$mode.log"
  bash scripts/test-android.sh --tests org.luff.colophon.SessionPerformanceTest --rerun-tasks \
    > "$COLOPHON_SESSION_FIXTURE/kotlin-$mode.log" 2>&1
  cp sdk/android/build/test-results/testDebugUnitTest/TEST-org.luff.colophon.SessionPerformanceTest.xml \
    "$COLOPHON_SESSION_FIXTURE/kotlin-$mode.xml"
  rg SESSION_BENCH "$COLOPHON_SESSION_FIXTURE/kotlin-$mode.xml"
done
