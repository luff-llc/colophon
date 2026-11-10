# Colophon 0.5 module ABI — experiment report

**Scope:** Brief C, 2026-11-10. Built on `colophon` main; all changes confined to
`spikes/module-abi/` except an isolated GitHub Actions workflow. Original
notes reducer and query source are unmodified. This document distinguishes
an implementation from an actual measurement.

## Execution status

**Run-by-run verified CI evidence, 2026-11-10 (UTC):**
[Linux CI #42781933617](https://github.com/luff-llc/colophon/actions/runs/42781933617)
ended **FAILURE overall** at source commit `82fe2a53fb216dfed12ae1a3b8bfd6cb97ccbf7c`: its Linux native/Bun/headless Chromium job passed, but the Apple job failed to compile Swift (`Decodable` error). Do not call this a passing workflow.
[Follow-up CI #42782846059](https://github.com/luff-llc/colophon/actions/runs/42782846059)
ended **SUCCESS overall** at source commit `a6da27407cfb300605d38d837b4b24066037252b`: Linux, macOS WasmKit 0.4.2 CLI (Release) and iPhone 18 Pro iOS Simulator XCTest (Debug) all passed.
The artifact ZIPs contain machine-readable measurements and tool versions.

| Host | Execution | Parity 1 / 1,000 / 10,000 |
| --- | --- | --- |
| Native Rust directly invoking Notes | Passed on Linux | Reference canonical output generated |
| Bun WASM | Passed on Linux | **All three pass**; state and query bytes identical |
| Chromium 141 browser WASM | Passed on Linux | **All three pass**; state and query bytes identical |
| WasmKit 0.4.2 macOS CLI | CLI step passed on Xcode 27 runner | All three checks in the CLI complete without mismatch |
| WasmKit 0.4.2 iOS Simulator | Completed **Debug** XCTest successfully in run 42782846059 | All three state/query checkpoints passed |
| Physical iPhone | Not attempted | **Not measured** |

No claim is made that an iOS Simulator is a physical iPhone. No on-device
temperature, battery, thermal or energy consumption can be inferred.

## Bytes

The native fixture produces the *same* `OperationView` shape as
`crates/colophon-core/tests/domain_notes.rs` with `createNotebook`,
`putEntry`, `putCell`, followed by valid CAS edits. All hosts use the same
**830,884-byte** original WASM module (SHA-256 `933950a2579bf961de89416a9d7ac2141627ef293bd4d3cc5c44122db817791a`). After 1, 1,000 and 10,000 operations,
they compare **raw canonical JSON bytes**, not parsed JSON values, for the
state and the result of `query("noteCounts", {})`.

**Measured:** Bun and Chromium match the native Rust reference at **every
byte, at all three counts**, for both state and query. The
`state_first_difference` and `query_first_difference` fields are `null`
in all six JS results. The macOS CLI and historical **Debug iOS Simulator** from successful run 42782846059 both completed all checks successfully. A mismatch would fail the corresponding job.
Result SHA-256s and exact first-difference diagnostics are preserved in the
Linux artifact ZIP.

## Limits

**Import and memory audit:** `notes.wasm` has **zero imports** and declares
`(memory 18 1024)`: an initial allocation of 18 × 64 KiB, with a hard
maximum of **1,024 pages / 64 MiB**. The measured peak JS linear-memory
size was **1,310,720 bytes** across all six JS runs, far below this ceiling.
The WAT-rewritten module remains import-free, with the same declaration.

**Portable fuel experiment:** `instrument.py` round-trips the compiled
module with WABT 1.0.34, inserting a decrement at function/loop entry. Its
own `fuel_reset` and `fuel_left` exports need no imports. For the same instrumented binary (SHA-256 `4c9ae1ba6da2a4b6cda9c03cee06ba85f4a767b7181213a89d34e2ba9cc3c429`) and first `apply` call:

| Engine | Minimum successful budget | Adjacent failed budget | Failure |
| --- | ---: | ---: | --- |
| Bun 1.3.2 | **58,051** | **58,050** | WebAssembly unreachable trap |
| Chromium 141 | **58,051** | **58,050** | WebAssembly unreachable trap |
| WasmKit macOS Release | **58,051** | **58,050** | WebAssembly unreachable trap |
| WasmKit iOS Simulator Debug | **58,051** | **58,050** | WebAssembly unreachable trap |

All four WASM hosts reached the same adjacent internal-meter boundary for this exact binary. WasmKit's separate **native** fuel probe on the original binary found 8,719,833 failing / 8,719,834 passing; its fuel unit differs from the rewritten counter. The verifier's 57,420 failing / 57,421 passing measurement was reported for a different build without module digests, so its 630-unit discrepancy cannot be attributed or treated as contradictory evidence for these exact binaries.

**Not production gas:** the rewriter charges only at function and loop
entries. Long straight-line code, bulk memory copies and allocations are
underpriced; the method is inadequate for adversarial modules. Nor is
WasmKit's runtime-native fuel the same accounting unit as the rewritten
module's fuel. A production `module.fuel` requirement needs a versioned,
verified per-opcode gas transform and atomic failure semantics.

## Floating point

The **actual released notes WASM contains 170 floating-point opcodes**
in its 830,884-byte build. The WABT audit found f32/f64 loads, stores,
arithmetic, comparisons, reinterpretations and conversions, including
`f32.div` and `f64.div`. The rewritten WASM has the same count.
This is concrete evidence that an **opcode-level ban** on all floating-point
instructions cannot apply to the current reducer binary.

The chosen benchmark payloads use integer logical clocks and text, so their
byte equality is **not** evidence that floats cannot enter the output.
The notes domain's payload schema allows extra properties and retains
`extensions` (see `domains/notes/validation.rs`); Serde JSON can
represent fractional numbers. Therefore `no float reaches output`
does **not** hold by construction. Enforcing it would require explicit
recursive input, extension and output validation (and a defined canonical
number policy) before accepting state. Static presence of f32/f64 alone
does not prove that a given operation uses floats.

## Cost: 1, 1,000 and 10,000 operations

**Measured release figures on GitHub-hosted Ubuntu 24.04**, not device
benchmarks. Columns show milliseconds **per operation**. WASM host figures
include canonical input/output buffer allocation, JSON decoding/encoding
and an ordinary reducer call; native Rust times call the in-memory reducer
directly and exclude this boundary cost, so this is **not** a controlled
head-to-head speedup comparison.

| Host | 1 op | 1,000 ops | 10,000 ops | Module load | Memory |
| --- | ---: | ---: | ---: | --- | --- |
| Native Rust direct | 0.1533 | 0.01041 | 0.009743 | N/A | RSS not measured |
| Bun 1.3.2 | 7.489 | 0.1142 | 0.05366 | compile 6.59 ms; instantiate 0.15–0.28 ms | 1.31 MB guest linear; process RSS 73–127 MB at each checkpoint |
| Chromium 141 | 3.400 | 0.0801 | 0.05312 | compile 1.3–2.9 ms; instantiate 0–0.2 ms | 1.31 MB guest linear; browser process peak RSS unavailable |
| WasmKit macOS (Release) | 18.81175 | 0.98451 | 0.93208 | parse 0.60–4.48 ms; instantiate 0.43–2.38 ms | Darwin lifetime-process peak RSS 17.8–18.4 MB |
| WasmKit iOS Simulator (Debug; historical) | 2,506.02 | 162.49 | 108.55 | parse 4.93–12.69 ms; instantiate 3.83–6.95 ms | Darwin lifetime-process peak RSS 211.9–256.4 MB |
| WasmKit iOS Simulator (Release) | Pending new optimized CI | Pending | Pending | Pending | Pending |

**Total apply-only time at 10,000 ops:** native Rust **97.43 ms**;
Bun **536.60 ms**; Chromium **531.20 ms**. The old Bun `peak_rss_bytes` field was mislabeled: it was a **process RSS snapshot**, now renamed `rss_snapshot_bytes` in the updated harness. Chromium's `js_heap_bytes` is a JS heap snapshot, not process peak RSS. Apple `ru_maxrss` is the **process-lifetime high-water RSS in bytes** (including the test harness), not per-operation RSS. Guest linear memory is separately measured in WebAssembly pages.

The baseline WASM file is **830,884 bytes**; after WABT round-trip and
instrumentation the metered WASM is **659,831 bytes**. The size difference
includes WABT's re-encoding and must not be interpreted as compression
caused by metering. All exact numbers are available as `out/*.json` in
the [successful run 42782846059 Linux artifact](https://github.com/luff-llc/colophon/actions/runs/42782846059/artifacts/13747510602). The latest source run [42891978817](https://github.com/luff-llc/colophon/actions/runs/42891978817) additionally records SHA-256 provenance and cross-host fuel checks.

## Versions and licences

The code and workflow intentionally select these tools/dependencies; actual
build identifiers for platform-installed tools are captured in
`out/tool-versions-*.txt` by the workflow:

| Component | Version / source | Licence |
| --- | --- | --- |
| Colophon core | workspace `0.4.0`, main commit of PR base | Apache-2.0 |
| Rust compiler and Cargo | requested 1.91.0 | MIT OR Apache-2.0 |
| `serde_json` | pinned 1.0.145 | MIT OR Apache-2.0 |
| `WasmKit` | **0.4.2**, `swiftwasm/WasmKit` tag | MIT; full text is provided separately in [WASMKIT-LICENSE.txt](WASMKIT-LICENSE.txt), not below |
| Swift | manifest tools 6.3; observed Xcode 27.1 (27A9275) / Apple Swift 6.4 / macOS Darwin 27 ARM64 hosted VM | Apache-2.0 with Runtime Library Exception |
| Bun | requested 1.3.2 | MIT |
| Node.js | requested 22.x | MIT |
| Playwright | pinned 1.56.1 | Apache-2.0 |
| Chromium | browser revision bundled by Playwright 1.56.1 | BSD-style Chromium licence with its own third-party notices |
| Python | CPython 3.x, stdlib only | Python Software Foundation License v2 |
| WABT (`wasm2wat`, `wat2wasm`) | 1.0.34 (Ubuntu 24.04) | Apache-2.0 |
| GitHub `actions/checkout`, `upload/download-artifact`, `setup-node` | v4 releases | MIT |
| `oven-sh/setup-bun` | v2 | MIT |

All of Colophon core's existing transitive Rust dependencies are resolved
through a separate experiment Cargo workspace; inspect the generated
`Cargo.lock` for the exact resolved set. No GPL dependency was introduced
intentionally. Toolchain and Chromium third-party notices still need checking
before product redistribution.

**Exact WasmKit 0.4.2 LICENSE text**, fetched from
`https://raw.githubusercontent.com/swiftwasm/WasmKit/0.4.2/LICENSE`,
is included verbatim in [WASMKIT-LICENSE.txt](WASMKIT-LICENSE.txt).

## Proposed edits to specification §11.2

1. **Freeze actual core-WASM signatures.** Specify `i32` pointer/length
   pairs, output length (e.g. packed `i64`), endianness, max buffer size
   and ownership; provide `release` and a deterministic way to get initial
   state. Define malformed pointer/error/refusal responses.
2. **Specify canonical input and output validation**, not just “canonical
   JSON bytes.” Pin Colophon's canonicalization algorithm, include
   integer/float policy and behavior for retained/unknown extension values.
3. **Don't define `module.fuel` as runtime-native fuel.** Define a versioned
   gas instrumentation transform, its per-opcode weights, error/trap semantics,
   proof that it is present, and commit the transformed bytes in the release
   digest. Alternatively defer portable fuel to a later ABI.
4. **Define atomic host behavior on trap.** Admit/fold only if the call
   returns valid state, result size and memory usage are in bounds; otherwise
   discard the instance, retain the previous state, and record
   `refused:moduleLimit`. Distinguish trap/invalid module from ordinary
   domain refusals.
5. **Require a max-memory declaration of 1,024 64-KiB pages**, validation
   of actual instance memory and hard 16 MiB input/state/result caps. Forbid
   shared memory and imports, and describe host enforcement for allocations.
6. **Clarify `propose` and `check`** signatures/semantics separately
   from this notes-only experiment, and state whether `initial`/`release`
   count toward metered work.
7. **Add cross-host conformance vectors** with identical raw state/query
   bytes, the exact gas boundary (`N-1` fails/`N` passes) and a float input
   case; require CI evidence from every supported host and report native vs
   ABI-overhead benchmark separately.
8. **Specify platform support based on verified results.** WasmKit version,
   minimum Swift/iOS version, supported opcode features, simulator-vs-device
   benchmarks and the required upstream licence notices must be explicit.

## Known caveats / work not performed

- No real device run. No claim about energy consumption or phone throughput.
- Native Rust direct timing is not a like-for-like ABI boundary benchmark.
- The WAT counter is intentionally **not sufficient for secure fuel**.
- The prototype uses unsafe pointer decoding under a trusted-host contract;
  that must never be copied into a hostile-module interface.
- No release artefact is published/adopted or signed; `propose` and
  `check` are out of this spike's Brief C scope.
- The historic Simulator timing is Debug; optimized Release measurements are collected by the updated workflow, not inferred from Debug.
- No browser outside headless GitHub-hosted Chromium CI has been measured.

## Constitution-first, nonbinding W0 advice

[W0-GUIDANCE.md](W0-GUIDANCE.md) separates test evidence from proposed choices on buffer ownership, errors, numerics, trap atomicity, memory and metering. It changes or freezes **none** of W0, the account/key foundation, Galley board #25 or production formats.
