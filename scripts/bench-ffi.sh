#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# Run build-apple.sh first so the static library and generated sources match this revision.
cargo run --locked --release -p colophon-ffi --example ffi_bench
COLOPHON_FFI_BENCH=1 bash scripts/test-swift.sh -c release --filter PerformanceTests
COLOPHON_FFI_BENCH=1 bash scripts/test-kotlin.sh --tests '*PerformanceTest' --rerun-tasks
