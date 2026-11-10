# Colophon 0.5 module ABI — experiment report

**Scope:** Brief C, 2026-11-10. Built on `colophon` main; all changes confined to
`spikes/module-abi/` except an isolated GitHub Actions workflow. Original
notes reducer and query source are unmodified. This document distinguishes
an implementation from an actual measurement.

## Execution status — source commits and complete CI conclusions

The baseline from which the spike was branched is Colophon `main`
commit `455baa90c389eaefaf323fb138499603c9fe8c86`. This PR is
**evidence only**: no production code, W0, account/key or Galley board changes.

| GitHub Actions run | Workflow source commit | Verified conclusion |
| --- | --- | --- |
| [42781933617](https://github.com/luff-llc/colophon/actions/runs/42781933617) | `82fe2a53fb216dfed12ae1a3b8bfd6cb97ccbf7c` | **Failure overall:** Ubuntu native/Bun/headless Chromium succeeded; Apple Swift compile failed (`Decodable`). Simulator not run. |
| [42782846059](https://github.com/luff-llc/colophon/actions/runs/42782846059) | `a6da27407cfb300605d38d837b4b24066037252b` | **Success overall:** Ubuntu, macOS WasmKit **Release**, iOS Simulator XCTest **Debug**. |
| [42891651264](https://github.com/luff-llc/colophon/actions/runs/42891651264) | `12dff1d5b6746f71ac2be54b4856724a9e00ef8a` | **Failure overall:** optimized Simulator test-target module import issue; Linux and macOS CLI succeeded. |
| **[42893777284](https://github.com/luff-llc/colophon/actions/runs/42893777284)** | **`2ac3ce271f5996e57475f97e79201160f7129b0f`** | **Success overall:** Linux native/Bun/Chromium and macOS **Release** / iPhone 18 Pro iOS 27.0 **Simulator Release** all passed. The iOS job ran **2 XCTest cases, 0 failures**. |

The passing final run's [Linux ZIP artifact](https://github.com/luff-llc/colophon/actions/runs/42893777284/artifacts/13799442693)
and [Apple ZIP artifact](https://github.com/luff-llc/colophon/actions/runs/42893777284/artifacts/13800896473)
include the original and rewritten modules, reference fixture hashes,
numeric JSON per host, toolchain versions, binary provenance, and the
result of `evidence.py all`. The artifact's `ci_source_commit` is
`2ac3ce271f5996e57475f97e79201160f7129b0f`. A subsequent
**documentation-only** report commit does not change those tested bytes.

The final tested hosts are native Rust on Ubuntu 24.04; Bun 1.3.2;
headless Chromium 141 via Playwright in **GitHub Linux CI only**;
WasmKit 0.4.2 in a macOS CLI Release build; and WasmKit 0.4.2
in a **Release-built iPhone 18 Pro iOS 27.0 Simulator**. These are
five execution environments, four of which execute the same WASM.

**Not run:** any physical iPhone, Safari or an interactive browser outside
CI; power, battery, sustained thermal or real-device throughput tests.
An iOS Simulator is not a physical iPhone and its numbers are not
device-performance forecasts.

## Bytes — exact binary identity and conformance

The fixture uses the existing `OperationView` format and the
`createNotebook`, `putEntry` and `putCell` paths in Colophon's
unchanged Notes reducer. The native reference generator writes canonical
JSON state and `query("noteCounts", {})` outputs after 1, 1,000, and
10,000 admitted operations. This is a finite fixture, not an exhaustive
proof of reducer equivalence.

**Final run result:** byte-for-byte state **and query** equality for
every checkpoint in Bun, headless Chromium, macOS WasmKit Release and
iOS Simulator WasmKit Release versus the same native Rust reference.
No differing byte offsets were observed. The comparison checks fail
CI on any mismatch. The `cross-host-evidence.json` manifest verifies
those results against identical WASM bytes, rather than equating source
commits with binary identity.

| Compiled binary | Size | SHA-256 (verified in both final-run artifact ZIPs) |
| --- | ---: | --- |
| Original `notes.wasm` | 830,884 bytes | `933950a2579bf961de89416a9d7ac2141627ef293bd4d3cc5c44122db817791a` |
| Rewritten `notes-metered.wasm` | 659,831 bytes | `4c9ae1ba6da2a4b6cda9c03cee06ba85f4a767b7181213a89d34e2ba9cc3c429` |

The size difference reflects a WABT disassembly/reassembly plus
instrumentation; it is not an optimization or compression result.
The [final Linux artifact](https://github.com/luff-llc/colophon/actions/runs/42893777284/artifacts/13799442693)
contains the canonical expected outputs and `binary-provenance.json`,
including their SHA-256 hashes.

## Limits and fuel: original versus instrumented binary

**Memory and imports.** Both binaries have **zero imports** and an
initial **18 pages** with declared maximum **1,024 pages × 64 KiB =
64 MiB** (`(memory 18 1024)`). Their observed guest linear-memory
high-water mark in this fixture was **1,310,720 bytes** (20 pages),
not a limit on total host RSS. The existing adapter accepts up to
16 MiB per JSON input, state or result, but its trusted-host pointer
contract is not a hardened public ABI.

**Rewritten, inside-module fuel.** `instrument.py` uses WABT 1.0.34
to insert a counter on every function and loop entry and exports
`fuel_reset` / `fuel_left` without importing anything. For **one
`apply` call**, after preparing inputs and initial state outside the
budget, the same instrumented digest above produced:

| Host / configuration | Adjacent **fails** | Adjacent **passes** |
| --- | ---: | ---: |
| Bun 1.3.2 | **58,050** | **58,051** |
| Headless Chromium 141 in CI | **58,050** | **58,051** |
| WasmKit 0.4.2, macOS Release | **58,050** | **58,051** |
| WasmKit 0.4.2, iOS 27.0 Simulator Release | **58,050** | **58,051** |

For comparison, **WasmKit's own native fuel on the original module**,
not the instrumented one, failed at **8,719,833** and passed at
**8,719,834**. Its units are runtime-specific and must not be
compared numerically to the inside-module function/loop count.

A separate verifier's review comment
[6763404426](https://github.com/luff-llc/colophon/pull/2#issuecomment-6763404426)
reported **57,420 fails / 57,421 passes**, i.e., a 630-count
difference. The review did not provide SHA-256s for the exact original
and instrumented binaries or all build/transform flags. Therefore
its result cannot be attributed to or reconciled numerically with
the two artifact digests here; the next valid comparison requires those
bytes and provenance, not just a similar source revision. Do not assume
the runtimes disagree on the *same* binary.

**Production limitation:** this function/loop counter ignores long
straight-line sequences, allocation, and bulk-memory cost. It
does not establish a secure, general, cross-platform gas unit.
Neither this counter nor WasmKit-native fuel is a production-grade
definition of `module.fuel`. A versioned, audited and independently
validated instrumentation/weighting scheme or a deliberate deferral
remains for W0 consideration.

## Floating point

The **Release-profile compiled experimental notes WASM contains 170 floating-point opcodes**
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

## Cost: 1, 1,000 and 10,000 operations — final Release CI measurements

The following are the measured **milliseconds per operation** from
[successful run 42893777284](https://github.com/luff-llc/colophon/actions/runs/42893777284)
at `2ac3ce271f5996e57475f97e79201160f7129b0f`, not values
extrapolated from the older Debug test. Each host starts a new instance
for each count. WASM host timings include boundary buffer copies,
JSON serialization/deserialization and reducer execution; the native
Rust baseline times only the reducer itself. Thus native versus WASM
numbers **are not a controlled like-for-like speed comparison**.

| Host / build | 1 op | 1,000 ops | 10,000 ops |
| --- | ---: | ---: | ---: |
| Native Rust direct (Ubuntu Release) | 0.272651 | 0.017234 | 0.016848 |
| Bun 1.3.2 WASM (Ubuntu) | 7.703150 | 0.228340 | 0.100756 |
| Headless Chromium 141 WASM (Ubuntu CI) | 5.000000 | 0.144600 | 0.113330 |
| WasmKit macOS CLI (Swift Release) | 17.501084 | 0.849456 | 0.882273 |
| **WasmKit iPhone 18 Pro iOS 27.0 Simulator (Swift Release)** | **219.464833** | **56.580415** | **8.520657** |

At 10,000 operations, total apply times were native Rust
**168.48 ms**, Bun **1,007.56 ms**, Chromium **1,133.30 ms**,
macOS WasmKit **8,822.73 ms**, and Release iOS Simulator
**85,206.57 ms**. The large variance between the 1,000- and
10,000-operation Simulator averages demonstrates that this hosted
VM result must **not** be used as a stable phone throughput claim.
The prior successful run's iOS **Debug XCTest** measurement
was approximately **108.55 ms/op** at 10,000 operations; it is
a separate configuration and cannot be substituted for Release.

**Load/instantiation, same final run:** Bun compiled in **11.50 ms**;
its per-case instantiation was **0.24–0.40 ms**. Chromium compiled in
**2.00–4.30 ms**, instantiated in **0.10–0.20 ms**. WasmKit macOS
parsed in **0.54–2.08 ms** and instantiated in **0.38–0.81 ms**.
Release iOS Simulator parsed in **0.72–1.44 ms** and instantiated
in **0.57–1.27 ms**. These separately instrumented phases are
not a uniform end-to-end cold load measurement.

**Memory, with different meanings (do not conflate them):**
- The maximum observed **guest linear memory** was **1,310,720
  bytes** on each WASM host. It is not total app memory or a
  whole-process memory limit.
- Bun's `rss_snapshot_bytes` rose from **70,516,736** to
  **121,085,952 bytes** across checkpoint *snapshots*; they are
  **not a peak**. The original misleading `peak_rss_bytes` name
  was corrected in the harness.
- Chromium reported a JS heap reading of 10,000,000 bytes.
  Browser process peak RSS was **not measured**.
- Apple `ru_maxrss` is the **process-lifetime high-water RSS**
  (includes the Swift host / XCTest), not an isolated guest peak
  or per-operation measurement. Final macOS CLI: **18,644,992
  bytes**; final optimized iOS Simulator: **216,285,184 bytes**.
- Native Rust peak RSS was **not measured**.

The iOS Simulator was **Release-built**, using Xcode **27.1
(27A9275)**, Apple Swift **6.4**, WasmKit **0.4.2**,
on a hosted macOS **Darwin 27.0.0 arm64 VM** with an
**iPhone 18 Pro iOS 27.0 Simulator**. `ios-simulator-release.log`
records `Release-iphonesimulator` and **2 passed tests, 0 failed**.
The exact `ios-release-{1,1000,10000}.json` and
`ios-release-meter.json` results, plus `cross-host-evidence.json`,
are in the [Apple artifact](https://github.com/luff-llc/colophon/actions/runs/42893777284/artifacts/13800896473).
**No real iPhone was tested.**

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

## Proposed, nonbinding edits for future specification §11.2 review

1. **Specify concrete core-WASM signatures when W0 is ready.** Specify `i32` pointer/length
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
- Historical Simulator numbers used Debug; optimized Simulator Release numbers are separately measured in the final successful CI run, not inferred from Debug.
- No browser outside headless GitHub-hosted Chromium CI has been measured.

## Constitution-first, nonbinding W0 advice

[W0-GUIDANCE.md](W0-GUIDANCE.md) separates test evidence from proposed choices on buffer ownership, errors, numerics, trap atomicity, memory and metering. It changes or freezes **none** of W0, the account/key foundation, Galley board #25 or production formats.


## Exact reproduction commands and attached evidence

The final successful workflow was evaluated on source commit
`2ac3ce271f5996e57475f97e79201160f7129b0f`. All command outputs
are in the artifact ZIPs linked above.

```sh
# Ubuntu 24.04: rustc/cargo 1.91.0, Bun 1.3.2, Node 22.23.4,
# Python 3.12.3, WABT 1.0.34 and Playwright 1.56.1 with Chromium 141
bash spikes/module-abi/run-linux.sh
python3 spikes/module-abi/evidence.py record
python3 spikes/module-abi/evidence.py linux

# Hosted macOS arm64: Xcode 27.1, Apple Swift 6.4, WasmKit 0.4.2
python3 spikes/module-abi/evidence.py verify
swift run --package-path spikes/module-abi/hosts/swift -c release module-spike-swift \
  "$PWD/spikes/module-abi/out/notes.wasm" \
  "$PWD/spikes/module-abi/out" \
  "$PWD/spikes/module-abi/out/notes-metered.wasm"
bash spikes/module-abi/prepare-ios-resources.sh

# From spikes/module-abi/hosts/swift; redirect/tee output to
# spikes/module-abi/out/ios-simulator-release.log
xcodebuild test -scheme ModuleABISpikeHost-Package -configuration Release \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro,OS=27.0' \
  -parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO

# From repository root, using the recorded xcodebuild log
python3 spikes/module-abi/extract-ios-results.py \
  spikes/module-abi/out/ios-simulator-release.log spikes/module-abi/out
python3 spikes/module-abi/evidence.py all
```

The user-facing output in this PR is a **spike**, not a module
publication or an authorization policy. Review the separately linked
[W0-GUIDANCE.md](W0-GUIDANCE.md) for distinctions between measured
evidence and possible account-first choices. No W0, account/key
foundation, board #25, production interface, deployment or merge
was changed here.
