# Colophon 0.5 module ABI — experiment report

**Scope:** Brief C, 2026-11-10. Built on `colophon` main; all changes confined to
`spikes/module-abi/` except an isolated GitHub Actions workflow. Original
notes reducer and query source are unmodified. This document distinguishes
an implementation from an actual measurement.

## Execution status

**Verified CI evidence, 2026-11-10:**
[Linux CI #42781933617](https://github.com/luff-llc/colophon/actions/runs/42781933617)
completed **successfully** on Ubuntu 24.04, with native Rust, Bun 1.3.2,
real Chromium 141, import/float audit and rewritten fuel probes.
[Follow-up CI #42782846059](https://github.com/luff-llc/colophon/actions/runs/42782846059)
again passed Linux, and its **macOS WasmKit CLI step passed**; the
iOS Simulator XCTest step was still running when this report revision was made.
The artifact ZIPs contain machine-readable measurements and tool versions.

| Host | Execution | Parity 1 / 1,000 / 10,000 |
| --- | --- | --- |
| Native Rust directly invoking Notes | Passed on Linux | Reference canonical output generated |
| Bun WASM | Passed on Linux | **All three pass**; state and query bytes identical |
| Chromium 141 browser WASM | Passed on Linux | **All three pass**; state and query bytes identical |
| WasmKit 0.4.2 macOS CLI | CLI step passed on Xcode 27 runner | All three checks in the CLI complete without mismatch |
| WasmKit 0.4.2 iOS Simulator | Test active in follow-up run | **Not yet verified** |
| Physical iPhone | Not attempted | **Not measured** |

No claim is made that an iOS Simulator is a physical iPhone. No on-device
temperature, battery, thermal or energy consumption can be inferred.

## Bytes

The native fixture produces the *same* `OperationView` shape as
`crates/colophon-core/tests/domain_notes.rs` with `createNotebook`,
`putEntry`, `putCell`, followed by valid CAS edits. All hosts use the same
**830,884-byte** original WASM module. After 1, 1,000 and 10,000 operations,
they compare **raw canonical JSON bytes**, not parsed JSON values, for the
state and the result of `query("noteCounts", {})`.

**Measured:** Bun and Chromium match the native Rust reference at **every
byte, at all three counts**, for both state and query. The
`state_first_difference` and `query_first_difference` fields are `null`
in all six JS results. The macOS Swift CLI step has also completed all its
comparison checks successfully. A mismatch would fail the corresponding job.
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
own `fuel_reset` and `fuel_left` exports need no imports. For the first
`apply` call, independently running on Bun and Chromium:

| Engine | Minimum successful budget | Adjacent failed budget | Failure |
| --- | ---: | ---: | --- |
| Bun 1.3.2 | **58,051** | **58,050** | WebAssembly unreachable trap |
| Chromium 141 | **58,051** | **58,050** | WebAssembly unreachable trap |

This is evidence that both JS engines reach the **same** internal meter
boundary for this specific binary. The macOS CLI also successfully ran both
a native WasmKit store-fuel probe and the rewritten-fuel probe. Their
numerical values are in the Apple run artifact once uploaded.

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
| WasmKit macOS | See Apple artifact | See Apple artifact | See Apple artifact | See Apple artifact | See Apple artifact |
| WasmKit iOS Simulator | Not yet verified | Not yet verified | Not yet verified | Not yet verified | Not yet verified |

**Total apply-only time at 10,000 ops:** native Rust **97.43 ms**;
Bun **536.60 ms**; Chromium **531.20 ms**. Bun's
`peak_rss_bytes` field presently records a **process RSS snapshot at the
end of each run**, *not* the maximum over the entire run; do not treat it
as a true peak. Chromium's `js_heap_bytes` is not OS process RSS.

The baseline WASM file is **830,884 bytes**; after WABT round-trip and
instrumentation the metered WASM is **659,831 bytes**. The size difference
includes WABT's re-encoding and must not be interpreted as compression
caused by metering. All exact numbers are available as `out/*.json` in
the [passing Linux artifacts](https://github.com/luff-llc/colophon/actions/runs/42781933617).

## Versions and licences

The code and workflow intentionally select these tools/dependencies; actual
build identifiers for platform-installed tools are captured in
`out/tool-versions-*.txt` by the workflow:

| Component | Version / source | Licence |
| --- | --- | --- |
| Colophon core | workspace `0.4.0`, main commit of PR base | Apache-2.0 |
| Rust compiler and Cargo | requested 1.91.0 | MIT OR Apache-2.0 |
| `serde_json` | pinned 1.0.145 | MIT OR Apache-2.0 |
| `WasmKit` | **0.4.2**, `swiftwasm/WasmKit` tag | MIT; exact LICENSE reproduced below |
| Swift | manifest tools 6.3; observed Xcode 27.1 / Apple Swift 6.4 | Apache-2.0 with Runtime Library Exception |
| Bun | requested 1.3.2 | MIT |
| Node.js | requested 22.x | MIT |
| Playwright | pinned 1.56.1 | Apache-2.0 |
| Chromium | browser revision bundled by Playwright 1.56.1 | BSD-style Chromium licence with its own third-party notices |
| Python | CPython 3.x, stdlib only | Python Software Foundation License v2 |
| WABT (`wasm2wat`, `wat2wasm`) | Ubuntu package, exact version logged at run | Apache-2.0 |
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
- Report completion depends on CI execution and inserting observed values,
  rather than substituting plausible numbers.
