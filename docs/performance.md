# Engine performance, November 6, 2026

Local writes meet the measured desktop target. Verified full rebuild, verified cold open, and
memory proportional to projection state do **not** meet the migration targets yet. Checkpoint
restoration is correct and skips reducer applications, but it does not skip record verification
or decrypting/validating the admitted history. No iPhone measurements were available in this
worktree; desktop results must not be treated as mobile proof.

## Reproduction

The benchmark is `crates/colophon-core/examples/bench.rs`, using `std::time::Instant` and the
existing pinned dependencies. It generates deterministic, genuinely signed and encrypted 0.2
records. There is no Criterion dependency, synthetic bypass of verification, or protocol change.
Fixture generation is excluded from reported engine timings.

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo build --release -p colophon-core --example bench
target/release/examples/bench 100000 /tmp/colophon-engine-100k.records --profile
```

The optional second argument caches the fixture in a small length-prefixed binary container.
Delete that file to regenerate it; omit the argument to generate every run. The first argument
is the operation count (default 100,000; minimum 100). An existing file must have the requested
operation count. `--profile` adds isolated measurements on 2,000 actual operation records.
These deterministic keys and nonces are exclusively for the benchmark, never app libraries.

On macOS, measure peak process RSS without another Rust dependency:

```sh
python3 - <<'PY'
import resource, subprocess
subprocess.run([
    'target/release/examples/bench', '100000',
    '/tmp/colophon-engine-100k.records', '--profile'
], check=True)
print('peak RSS bytes:', resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
PY
```

Darwin reports `ru_maxrss` in bytes. `/usr/bin/time -l` could not report memory in this sandbox
because `sysctl kern.clockrate` was denied; Python's `getrusage` measurement succeeded.

## Machine and fixture

- MacBook Pro, Apple M3 Max, 16 CPU cores (12 performance, 4 efficiency), 64 GB RAM, arm64.
- macOS 27.0.1; rustc 1.91.1 (`ed61e7d7e`); release profile with LTO, optimization level **3**
  supplied by `CARGO_PROFILE_RELEASE_OPT_LEVEL`. The repository's default remains `opt-level="s"`
  for the existing WASM build. No target-CPU override, extra crate, or platform crypto backend.
- Exactly 100,000 operations: 89,999 podcast positions, 4,000 episode updates, 4,000 saved links,
  1,999 note edits, one notebook and one initial note. Four writers, three member grants, and one
  revocation preserving the revoked member's 25,000 already admitted writes. All namespaces rotate
  on that revocation. Tests separately exercise revocation removing unpreserved writes.
- 89,681,974 stored record bytes, including authority and requests. Three exported checkpoints
  total 1,539,944 bytes. The projection has about 940 episodes, 4,000 saved links and one notebook
  with one note; most operations repeatedly update existing objects.
- Timed record input is already in memory; filesystem fixture loading and input-map clones occur
  before the cold-open/full-rebuild timers. Both startup measurements include signature checks,
  authority replay, admission and host software ECDH. Unlock uses `finish_unlock_many`.

## Results

One complete run of the final implementation, with profiling enabled. These are elapsed
measurements, not p50/p99 latency promises; periodic snapshot copies and larger projection
objects can make individual writes more expensive.

| Measurement | Result | Migration target |
| --- | ---: | --- |
| Full rebuild, including unlock and projection | 17,798.004 ms | < 1,500 ms — unmet |
| Of that: verify records and admit headers | 17,121.382 ms | — |
| Of that: unlock, decrypt, validate IDs, reduce | 675.937 ms | — |
| Cold open with checkpoints, including unlock | 18,201.985 ms | < 100 ms — unmet |
| Of that: verify records and admit headers | 17,530.157 ms | — |
| Of that: unlock, validate prefix and restore | 671.766 ms | — |
| Cold-open reducer applications | **0** | Checkpoint skips projection replay |
| Single local podcast write, including software sign, verify and merge | **0.595 ms** | < 2 ms — met on this Mac |
| Single local write to quieter `notes` namespace | **0.479 ms** | < 2 ms — met on this Mac |
| Podcast write reducer applications | **1** | Append does not replay history |
| Insert at logical clock 2 near history's start | 190.413 ms | No numeric target specified |
| Podcast reducer replay (93,999 admitted operations) | 68.001 ms | — |
| Warm restoration of all checkpoints, already verified/decrypted library | 71.468 ms | **Not** a cold-open result |
| Serialize all checkpoints | 6.153 ms | — |
| 1,000 single-episode queries combined | 0.439 ms | — |
| Peak process RSS | 653,508,608 bytes (623.2 MiB) | State-proportional memory — unmet |

The RSS peak covers the entire benchmark process, including its source record map, a library,
compatibility `view` copies for the independent replay comparison, and profiling samples. It is
not an isolated steady-state library heap measurement. The benchmark retains the input map so
full and cold starts can use identical records. The core's retained history is nevertheless
explicitly O(history), independent of this measurement overhead.

## Profiling and changes made

Isolated profiles of 2,000 records on the same run:

| Stage | Elapsed |
| --- | ---: |
| Envelope/header JSON and base64 decode | 2.442 ms |
| P-256 signature verification, with parsed signing keys | **327.546 ms** |
| AES-GCM decryption, parsed headers and prebuilt AAD | 4.262 ms |
| Plaintext JSON parsing | 0.671 ms |

The signature-only sample corresponds to roughly **16.4 seconds per 100,000** records, explaining
the startup total. Header parsing and decryption are not responsible for the order-of-magnitude
miss. These samples are isolated diagnostics; summing/extrapolating them is not a substitute for
the complete measured startup path above.

Optimizations implemented and checked against byte-identical conformance vectors:

1. Verify each immutable operation once per replica, and decrypt/validate it once per key
   availability. Authority changes reuse these results but rerun admission. Unknown authors are
   retried when authority arrives. Reads use stored domain state.
2. Appends avoid cloning the record map or replaying authority. Separate namespace and capped
   author ordering dependencies keep a quiet namespace's append cheap despite a much larger
   clock in another namespace. Middle inserts still rerun global budget/admission safely.
3. Cache parsed signing public keys within ingest and operation schemas across reducer calls.
   Store authenticated operation projections once and borrow them during replay, rather than
   cloning every payload for each unlocked epoch. Drop duplicate ciphertext buffers after opening.
4. Serialize operation-ID preimages and AAD directly from borrowed, canonically ordered fields,
   eliminating intermediate JSON trees and payload copies. Hex encoding uses one allocation per
   digest instead of formatting/allocating for every byte. Existing fractional-number and exact
   record vector tests continue to pass.
5. Batch key unlock validates all ECDH results before installing any and refreshes admission once.
   Staged checkpoints also avoid premature projection replay with sequential unlock.
6. Retain bounded automatic snapshots and restored snapshots for prefix-safe suffix replay;
   single-object queries avoid copying any operation history.

The first incremental implementation, before those refinements and using the default size-focused
release profile, measured 24,233 ms full rebuild, 24,046 ms checkpoint cold open, and 0.940 ms local
write. Its sequential unlock path initially replayed projections before the checkpoint's epoch
key was available. The final path applies zero reducers on the checkpoint cold start. Comparing
these runs includes both implementation and compiler-profile changes, not a controlled estimate
of any single optimization's impact.

## What blocks the remaining targets

**Cold open under 100 ms:** A domain-state checkpoint is not an authenticated persistent cache of
signature, payload and admission evidence. This implementation verifies the supplied signed
records on every fresh `Library`, reconstructs current admission, and validates the checkpoint
against that admitted prefix. Accepting the checkpoint without those checks would hide revoked,
held or changed-prefix operations. A future host-backed, recipient-authenticated verified-record
index could avoid repeated cryptographic work for unchanged bytes, but needs its own versioning,
record-set binding, authority invalidation and hostile-cache tests. It must still fully validate
new records and admission changes. That feature is not implemented here.

**Full rebuild under 1.5 s:** The pinned portable P-256 verifier alone takes about 16.4 s on this
fixture. JSON/allocation tuning cannot bridge that gap. Reaching this target requires a measured
strategy for parallel verification or a faster native verification backend, with the same strict
stored-byte semantics, a WASM fallback and any dependency change reviewed/recorded in architecture.
The present core remains single-threaded, portable, and within the existing dependency allow-list.

**Memory proportional to state:** `Library::records() -> &Records`, ledger/view compatibility,
late-arrival replay, duplicate handling and grant-wide budgets currently retain the complete
signed record map, parsed metadata, admitted order/prefix hashes and authenticated plaintext.
Reducer states do not contain that journal, but `Library` does. Removing it transparently would
break the existing borrowed `records()` contract or require loading records from a host store.
A separate storage-backed engine API plus bounded verified/decrypted caches is needed; neither
that API nor an eviction policy is implemented. Snapshot retention is bounded independently,
with a default of four per namespace. Large conflict/invalid projections can themselves grow
with history, and collection-page lookup currently sorts projection references.

These remaining gates are recorded in the migration plan, not waived by the fast local-write
measurement. iPhone hardware and platform-keystore measurements remain required before rollout.

# Performance

## FFI

Measured November 6, 2026 on the arm64 macOS host in the `ffi` worktree. Rust stable 1.91.1,
Swift 6.4.2 / Xcode 27.2, JDK 17, Kotlin 2.2.21, JNA 5.18.1, UniFFI 0.32.2. CPU model access
is denied by this sandbox. Rust uses the workspace release profile (`opt-level = "s"`, LTO);
Swift uses `-c release`. These measurements use the pre-incremental public core currently in
this worktree; rerun after merging the engine worker's changes.

| Path | Query median | Write median | Query difference vs Rust | Write difference vs Rust |
| --- | ---: | ---: | ---: | ---: |
| Native Rust + query JSON | 5.067 ms | 10.860 ms | +0.000 ms / +0.0% | +0.000 ms / +0.0% |
| Rust binding facade (no language ABI) | 5.073 ms | 10.920 ms | +0.006 ms / +0.1% | +0.061 ms / +0.6% |
| Swift generated ABI | 5.473 ms | 11.606 ms | +0.405 ms / +8.0% | +0.746 ms / +6.9% |
| Kotlin/JNA ABI | 5.525 ms | 11.755 ms | +0.457 ms / +9.0% | +0.895 ms / +8.2% |

Each cell is the median of three independent run medians. Each run uses 100 queries and 50
writes against the same fixed history: one notebook and 20 notes. Query is `notes__read`,
including JSON serialization on both native Rust and FFI paths. Write is prepare `addNote`,
verify/commit a precomputed valid signature, and retrieve the admitted operation. Every write
starts with a freshly restored, unlocked copy of the fixture; restoration is outside timing.
The seed and signature are deliberately reused only on those independent benchmark copies,
never on a continuing production library. Assertions and result inspection are outside timing.

Host ECDSA signing, ECDH, entropy generation, clocks, disk I/O, cold open, and UI work are
excluded. The same Rust signature verification, sealing, admission, and domain evaluation
remain inside the measured work. This isolates the transport path from differing Rust,
CryptoKit, Keystore, and JCA signing implementations. The Swift sample measures actual
UniFFI calls, not an in-Rust stand-in; the JVM sample crosses JNA after 200 query warmups and
10 discarded write warmups. It does not include an app coroutine dispatcher or Swift actor hop.

Observed per-run query medians ranged 5.061–5.326 ms in native Rust, 5.467–5.694 ms in Swift,
and 5.503–5.537 ms in Kotlin. Write medians ranged 10.847–11.044 ms, 11.586–11.886 ms, and
11.743–11.770 ms respectively. Treat the deltas as costs of the complete wrapper/ABI path,
including conversion and build/code-generation differences, rather than an isolated foreign
function call instruction. The host was shared with other work, so small differences are
noise-sensitive; these are not mobile-device latency claims.

At this history size the complete Swift/JVM paths add about 0.4–0.5 ms per query and
0.7–0.9 ms per write. The much smaller in-Rust facade delta separates adapter work from the
actual foreign-language transport. The current core's repeated full evaluation dominates;
these results neither establish the engine's future 100k-operation targets nor measure its
planned narrow query/checkpoint API. Small domain queries should replace whole namespace
reads when that public API is available.

Reproduce after `bash scripts/build-apple.sh`:

```sh
bash scripts/bench-ffi.sh
```

The harness is `crates/colophon-ffi/examples/ffi_bench.rs`, Swift's `PerformanceTests`, and
Kotlin's `PerformanceTest`. It writes only `target/ffi-bench/`. To repeat without recompiling,
run the Rust example binary, then `COLOPHON_FFI_BENCH=1 bash scripts/test-swift.sh --skip-build
-c release --filter PerformanceTests` and `COLOPHON_FFI_BENCH=1 bash scripts/test-kotlin.sh
--tests '*PerformanceTest' --rerun`. The three measured run medians are preserved in
`crates/colophon-ffi/benchmarks/2026-11-06.json`; build/test logs are local artifacts under
`target/ffi-validation/`.

<!-- End FFI measurements; keep engine sections separate when merging. -->
