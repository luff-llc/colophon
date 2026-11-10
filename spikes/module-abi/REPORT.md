# Colophon 0.5 module ABI — experiment report

**Scope:** Brief C, 2026-11-10. Built on `colophon` main; all changes confined to
`spikes/module-abi/` except an isolated GitHub Actions workflow. Original
notes reducer and query source are unmodified. This document distinguishes
an implementation from an actual measurement.

## Execution status

At authoring time the available interactive machine was an isolated Linux
container without Cargo/Rust, Bun, macOS, Xcode or iOS Simulator, and without
network access for installing them. **No WASM artifact has been compiled or
executed here. No cross-runtime byte equality, time, fuel cut-off or memory
measurement is claimed yet.** The GitHub Actions workflow runs the tests on
hosted machines; attach its run ID and numeric `out/*.json` artifacts after
successful execution. This report must not be read as a passing test before
those artifacts exist.

| Required runtime | Implementation | Verified in this session | Exact result |
| --- | --- | --- | --- |
| Native Rust `Notes.apply` and `query` | `src/bin/fixture.rs` | No toolchain | Not measured |
| Bun WebAssembly | `hosts/bun.mjs` | Bun absent | Not measured |
| Chromium browser WebAssembly | `hosts/browser.html`, Playwright runner | Browser absent | Not measured |
| macOS CLI WasmKit | `hosts/swift` | No macOS | Not measured |
| iOS Simulator using **same Swift** | `ModuleSpikeSimulatorTests` | No Xcode/Simulator | Not measured |
| Real iPhone | Not offered without owner device | **Not run** | Not measured |

## Bytes

Native fixtures use the identical `OperationView` fields and seed operations
from `crates/colophon-core/tests/domain_notes.rs`: `createNotebook`,
`putEntry`, `putCell`, followed by deterministic CAS edits to the same
cell. For 1/1,000/10,000 operations, `fixture` records canonical state
and `noteCounts` query results. Each WASM host compares **raw output bytes**
with these files, reporting the **first differing offset** and byte values.
The WASM adapter uses `colophon_core::records::canonical` on each returned
state/view; the host does not reserialize JSON. This is more restrictive
than comparing JSON semantic values.

**Result:** awaiting executable run. No first difference can be reported.

## Limits

The **native runtime** capabilities are not interchangeable:

- Bun and the browser expose no standard synchronous per-call WebAssembly
  execution-fuel API. A max-memory declaration can limit pages, not CPU work.
  Neither host can reliably terminate arbitrary synchronous execution from
  the same JS thread at an exact instruction boundary.
- WasmKit **0.4.2** supports store fuel (introduced 0.4.1), enabled using
  `EngineConfiguration(fuelMetering: true)` and
  `store.fuel = Fuel(remaining: N)`. Its unit is approximately an executed
  WebAssembly operator plus bulk-memory charges (1 per 64 bytes), which is
  not a fuel budget the JS hosts can enforce.
- The experiment's WAT rewriter inserts an **internal** global budget and
  `unreachable` trap at every function and loop entry, with no imports.
  Every runtime therefore executes the same decrements and should stop
  at the same entry/loop boundary. The host binary-searches the exact minimum
  passing value for the first `apply`. A trap leaves the host's state bytes
  unchanged, because it accepts a return value only after success.
  **This is a weak accounting scheme**, not adequate for sandboxing.
  Real instruction/basic-block-weighted metering and verified instrumentation
  are needed before `module.fuel` can be a contract.

**Result:** both native and rewritten fuel thresholds await execution.
A shared cut-off is a hypothesis until the `*-meter.json` files agree.

## Floating point

The notes operations chosen for the fixture use only integer logical clocks,
strings and booleans, but the reducer retains open JSON `extensions` and
`serde_json` supports noninteger JSON numbers. The current Colophon workspace
pins `serde_json 1.0.145` with `float_roundtrip`, and
`domain::validate_input` explicitly uses `Value::as_f64`; an
integer-only **fixture** is not proof of an integer-only **module**.

`audit.py` disassembles the actual release WASM and records every f32/f64
opcode, including f32/f64 conversions. **Result:** opcode count unmeasured.
Regardless of that count, “no float reaches output” requires a defined
validation of input numbers (including retained extensions) and output before
serializing; the current ABI does not supply such a rule. Serde's canonical
JSON output alone is not a float ban.

## Cost: 1, 1,000 and 10,000 operations

Values are explicitly **not measured** until matching `out/*.json` files
are attached. The scripts capture release WASM module size, compile/parse
time, instantiate time, per-op time (with full JSON state round-trip) and
linear-memory high-water mark. Bun reports process RSS, WasmKit reports
Darwin `ru_maxrss` in bytes, and Chromium reports JS heap when exposed
(***not*** a process peak RSS). Native Rust measures in-memory reducer time,
excluding JSON boundary overhead, deliberately distinct from WASM time.

| Host | 1 op | 1,000 ops | 10,000 ops | Load | Peak memory |
| --- | --- | --- | --- | --- | --- |
| Native Rust | — | — | — | N/A | Not measured |
| Bun | — | — | — | Not measured | Not measured |
| Chromium | — | — | — | Not measured | Not measured |
| WasmKit macOS | — | — | — | Not measured | Not measured |
| WasmKit iOS Simulator | — | — | — | Not measured | Not measured |

Do **not** infer real iPhone performance or thermal impact from Simulator runs.

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
| Swift | required 6.3 | Apache-2.0 with Runtime Library Exception |
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
