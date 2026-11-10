# Proposed interface guidance for W0 (informational; NOT a W0 decision)

**Scope and status:** This is an independent, public ABI evidence handoff for the
constitution-first family of personalOS, LUFF companyOS, Galley projectOS and
devOS. It **does not** change or freeze the W0 constitution, account/key work,
Galley board, any production format, or the 0.5 specification. Its tests fold
already-admitted Notes operations; they do not establish authority or key
semantics. Treat the recommendation below as an input to W0 deliberation,
not as a normative amendment. No deployment or merge is implied.

## What was actually measured

- Original Notes WASM: 830,884 bytes, zero imports, one memory
  declaration with initial 18 pages and maximum 1,024 pages (64 MiB).
  Instrumented WASM: 659,831 bytes after WABT round-trip, **not** a
  mechanically comparable code-size optimization.
- Rust native, Bun 1.3.2, real headless Chromium 141 in GitHub CI,
  WasmKit 0.4.2 on macOS, and an iOS **Simulator** reproduced the exact
  canonical state and query bytes at 1, 1,000, and 10,000 operations.
  These tests are a bounded sample, not a general proof.
- For one specific instrumented binary, the inserted function/loop fuel
  counter had adjacent budgets 58,050 failing and 58,051 passing on all
  four WASM hosts. WasmKit's own native fuel uses a different unit
  and a much larger budget; neither is a certified cross-platform
  resource schedule. A verifier reported 57,420/57,421 on an unspecified
  build, so **that number must not be assigned to these exact binaries**.
- Static audit found 170 f32/f64 opcodes in the compiled module; the
  integer-only fixture did not prove float exclusion. The Notes reducer
  retains unknown/extension JSON values. The observed comparison is
  not a theorem about fractional inputs or future versions.
- CI used hosted infrastructure. No physical iPhone, sustained
  thermal, battery or energy result was measured. Individual timing
  and RSS definitions are in [REPORT.md](REPORT.md) and the run artifacts.

## Options for W0, explicitly proposed rather than measured

| Area | Proposed W0-interface choice | Evidence / unresolved decision |
| --- | --- | --- |
| **Account first** | Keep authority, membership, revocation and scoped key proofs in each account's signed constitutional history. Admit the operation **before** invoking a module; a module may only fold admitted values, never mint or expand authority. | Current spike receives an already-admitted `OperationView`. W0 must separately decide the proof/head interfaces. |
| **Buffer ownership** | Pin a core-WASM `i32` (ptr,len) convention. Guest allocates input slots; host copies canonical bytes, calls pure functions, copies returned bytes, releases all guest allocations. Specify initial state and a length-bearing result, with a nonzero result for valid empty JSON. | Current spike uses `alloc`, `release`, `initial`, `apply`, `query` and packed `i64`. Ownership works for a trusted host but isn't yet a hardened public ABI. W0 need not choose packed `i64` over two return slots. |
| **Errors and refusals** | Reserve distinct machine-readable categories: admission/authority refusal (before WASM); expected domain refusal (data, no trap); malformed-input or ABI-contract error (host rejects); deterministic resource/trap refusal (one operation only). Never treat a zero result or arbitrary exception as proof of a domain refusal. | Spike's zero return loses error detail; the spec's `refused:moduleLimit` must not swallow unrelated errors. Exact error envelope and whether retry is allowed remain open. |
| **Numeric handling** | Define a versioned canonical numeric domain for state, inputs, query outputs, **including recursively retained extension fields**. Until a cross-runtime float vector is validated, avoid binary floating-point in authority-relevant canonical outputs: use integers within an explicitly selected range or fixed-point decimal strings. | Existing WASM includes float instructions; Serde can handle fractional JSON. A raw opcode ban would reject the measured module. W0 must decide how large integer clocks and decimals are represented without silently losing precision in JavaScript. |
| **Trap atomicity** | Host commits new state **only** after a successful return, valid canonical encoding, schema/size checks and all resource checks. Otherwise retain old state, record a stable refusal and discard/reinstantiate trapped guest memory. | Current hosts keep previous state buffers until return; this is limited evidence, not a transactional protocol or crash-recovery test. |
| **Memory** | Proposed starting caps: one nonshared 32-bit linear memory with a declared maximum of 1,024 pages (64 MiB), and at most 16 MiB each for state/input/result; enforce both before and after a call. Explicitly deny imports/threads unless a later version specifies them. | Compiled Notes module has no imports and has the 64 MiB limit. Host RSS/heap and guest linear memory are different quantities; 64 MiB is not a host-process peak bound. |
| **Metering** | **Do not freeze `module.fuel` as native WasmKit fuel or as the current function/loop counter.** Consider a versioned, audited instruction/basic-block instrumentation transform and pinned gas schedule, meter initialization/allocations, sign/hash the transformed module, verify at load and test adjacent budget thresholds across hosts. Alternatively defer portable deterministic fuel in W0. | Identical function/loop threshold was measured for one digest, not arbitrary modules. Native host fuel units are not portable. Schedule, transform verifier and which work is charged are unresolved. |

The same distinctions apply regardless of which OS holds the account: personalOS
user-owned contexts; companyOS organizational contexts; projectOS shared
project decisions; devOS development operations. Modules should not become
the keeper of identity or a substitute for the constitutional proof chain.

**Decision boundary:** W0 should reserve enough vocabulary to distinguish
admission, pure fold, refusal and host resource enforcement, but the evidence
here does **not** justify locking the detailed module ABI, error wire format,
numeric policy or gas weights before the account/key work and board interface
are independently reviewed. Keep the tracks parallel; do not stack this
spike onto them.
