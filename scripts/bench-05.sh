#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
# Fresh directory prevents a prior measurement's stores contaminating another run.
root="${1:-target/bench-05-$(date +%Y%m%d-%H%M%S)}"
output="${2:-docs/benchmarks/v05-2026-11-16.json}"
# BENCH05_LOCAL_TARGET=1 is the sandbox fallback when the pressroom lane is unwritable.
if [[ "${BENCH05_LOCAL_TARGET:-0}" == 1 ]]; then
  pressroom run --threads 4 --memory-gb 8 --class gate --lane colophon --label "0.5 perf" -- \
    env CARGO_TARGET_DIR="$PWD/target" cargo run --locked --release -p colophon-core --example bench05 -- all "$root" "$output"
else
  pressroom run --threads 4 --memory-gb 8 --class gate --lane colophon --label "0.5 perf" -- \
    cargo run --locked --release -p colophon-core --example bench05 -- all "$root" "$output"
fi
