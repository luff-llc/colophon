# Module ABI cross-runtime experiment (Colophon 0.5 / Brief C)

A **disposable, independent spike**, not a version of Colophon's production
module interface. All files live in this folder. It uses the unmodified
`colophon_core::domains::notes::{Notes, NotesState}` reducer and query.

Source requirement: [Galley handoff](https://github.com/luff-llc/galley/blob/main/docs/handoff/2026-11-10-module-spike.md),
[spec §11.2 and §15](https://github.com/luff-llc/galley/blob/main/docs/spec/colophon-0.5-draft.md).

## Experimental ABI

One `wasm32-unknown-unknown` module, zero imports, linear-memory maximum 64 MiB
(set by wasm-ld in the build script). It exports:

| Function | Core WebAssembly signature |
| --- | --- |
| `alloc` | `(i32 len) -> i32 ptr` |
| `release` | `(i32 ptr, i32 len) -> ()` |
| `initial` | `() -> i64 packed` |
| `apply` | `(i32 state_ptr, i32 state_len, i32 operation_ptr, i32 operation_len) -> i64 packed` |
| `query` | `(i32 state_ptr, i32 state_len, i32 name_ptr, i32 name_len, i32 args_ptr, i32 args_len) -> i64 packed` |

`packed = (result_byte_length << 32) | result_pointer`. A zero packed
result signals failure and is not a valid state. Caller must release **both**
input and returned buffers with exactly their respective lengths. `initial`
and `release` are additions needed to make the underspecified §11.2 testable.
There is no `propose` or `check` since Brief C specifically asks only for
the notes `apply`/`query` path. No host imports, clock, randomness, or threads.

All input and output objects are encoded by Colophon's own
`records::canonical` (not JSON.stringify): sorted keys at every depth. The
host passes unchanged operation JSONL bytes. In this spike `apply` receives
**already admitted** `OperationView` values, as the existing trait requires;
it does not re-implement signature verification or authority.

**Safety warning:** this is not a hardened hostile-code ABI: a host passing a
bad pointer/length to `apply` is undefined behavior in this scratch adapter;
a returned 0 is not the spec's `refused:moduleLimit`. Do not deploy.

## Run

Linux (Rust, Bun, Chromium):

```sh
rustup toolchain install 1.91.0 --profile minimal --target wasm32-unknown-unknown
sudo apt-get install wabt
# Bun 1.3.2, Node.js 22, npm, Python 3 and Playwright 1.56.1 installed:
bash spikes/module-abi/run-linux.sh
```

The script builds and tests the separate Rust crate, generates native
`out/operations.jsonl` and `out/expected-{1,1000,10000}.json`, builds a
WASM using the **same** reducer, audits float opcodes and imports, rewrites it
with an internal basic-block/loop budget, then runs Bun and a real Chromium
page via Playwright. It fails on the first byte mismatch. It also compares
`query("noteCounts", {})` byte-for-byte. Native, Bun and browser timings
and memory readings are emitted to `out/*.json`.

macOS (WasmKit 0.4.2 / Swift 6.3):

```sh
cd spikes/module-abi
swift run --package-path hosts/swift -c release module-spike-swift \
  "$PWD/out/notes.wasm" "$PWD/out" "$PWD/out/notes-metered.wasm"
```

The Swift code explicitly enables WasmKit's **own** fuel metering as a separate
test, and also measures the identically rewritten module used by JS hosts.

iOS Simulator (NOT a physical device): after `prepare-ios-resources.sh`,
the workflow executes the **same** Swift `ModuleSpike.run` and
`ModuleSpike.probe` functions in optimized `Release` mode (not the Xcode
test scheme's Debug default). Reproduce on Xcode 27.1 / Swift 6.4 with:

```sh
cd spikes/module-abi/hosts/swift
xcodebuild test -scheme ModuleABISpikeHost-Package \
  -configuration Release \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro,OS=27.0' \
  -parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO
```

The CI command additionally logs to `out/ios-simulator-release.log`.
`extract-ios-results.py` turns explicit XCTest measurement markers into
`ios-release-{1,1000,10000}.json` and `ios-release-meter.json`.
`evidence.py` records original/instrumented SHA-256, verifies all
downloaded inputs and asserts equality and adjacent meter budgets across
all four WASM hosts. Unlike a Debug XCTest run, this is a release-mode
measurement. It is **still not a physical-device benchmark**.

## Metering experiment

`instrument.py` round-trips the *built binary* through WABT's linear
`wasm2wat`/`wat2wasm`, adding a module-local global with one decrement
at each function and `loop` entry. `fuel_reset` and `fuel_left` are new
exports (not imports), so it remains import-free. Each host binary-searches
the minimum budget that completes **the first apply call**. Budget `N-1`
must trap and `N` must return. The failure does not overwrite the host's
prior state. A fresh instance is created for each budget to avoid trying to
resume a trapped interpreter.

This metering is **not an adequate production cost model**: it misses long
straight-line code, bulk memory charges, allocation and, without strict
validation, future bytecode constructs. It establishes whether a *single
instrumented wasm binary* can share a cut-off, not whether a sensible
budget can be applied to arbitrary modules.

## Constraints and outputs

- No files under `crates/colophon-core/src` are modified.
- No production Cargo workspace files, tests, public API or formats change.
- No GPL dependency intentionally added. See [REPORT.md](REPORT.md) for
  versions and licences, [WASMKIT-LICENSE.txt](WASMKIT-LICENSE.txt) for the
  exact upstream WasmKit 0.4.2 licence.
- `out/` is generated, must not be committed (already ignored via `target/`,
  plus the experiment's `.gitignore`).
- An iOS **simulator** cannot provide on-device energy/thermal/real-phone
  performance results. Real iPhone measurements require a device and consent.

## Constitution-first decision boundary

See [W0-GUIDANCE.md](W0-GUIDANCE.md) for nonbinding, evidence-backed ABI
recommendations. They do not modify or freeze W0, account/key proofs or the
Galley board. See [REPORT.md](REPORT.md) for the run/commit/artifact ledger.
