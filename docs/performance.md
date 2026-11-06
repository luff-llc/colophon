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
