# Engine handoff — stage 2, November 6, 2026

Completed in the `engine` worktree on branch `engine`, based on committed stage 1 **302db73**.
All stage-2 changes are intentionally **uncommitted**. No `.git` writes, commits, pushes or
external deployments were attempted. `crates/colophon-ffi`, domain-worker files, dependency pins,
Cargo.lock and conformance record/expected-output bytes were not changed. This handoff is the
requested stop point.

## Result

The storage-backed engine meets the measured 100k desktop timing gates. Three recorded runs:

| Measurement | Median | Observed range | Target |
| --- | ---: | ---: | ---: |
| Full verified rebuild, including unlock | **1,111.243 ms** | 1,061.620–1,344.308 ms | <1,500 ms |
| Fresh-process disk-backed checkpoint open + 1,000 new records | **78.245 ms** | 76.984–78.718 ms | <100 ms |
| Local write, software signing, in-memory host persistence and application | **0.746 ms** | 0.683–0.751 ms | <2 ms |
| Unchanged checkpoint open | **60.098 ms** | 58.744–62.150 ms | <100 ms |

An additional final confirmation after the audit-progress regression checks measured **1,169.611
ms** full rebuild, **82.040 ms** fresh-process disk cold open with 1% new records, and **0.754 ms**
local write. Every timing gate passed in that run too.

An unchanged restored engine fetches, verifies, decrypts and reduces **zero historical operations**.
The 1% suffix case fetches/verifies/decrypts/applies exactly **1,000** new operations. It does not
silently re-verify or decrypt the 100k prefix. The first 50-operation history page builds its
ordering index and fetches/decrypts only those 50 records (4.123 ms median in the three-run series).

Peak process RSS with a disk-backed host source: **91.5 MiB** for unchanged cold open, **98.2 MiB**
for cold open with 1% new records, and **167.5 MiB** for full rebuild. The host-source/listing and
authority-setup baseline is 47.6 MiB. These are whole-process peaks, including checkpoint input,
allocator retention and comparisons, not isolated live engine heap figures. The old compatibility
benchmark was 623.2 MiB in stage 1 and 659.5 MiB in this stage; `Library` intentionally still keeps
its original borrowed-record/history contract. The new engine retains indexes, authority and
reducer state plus bounded content and batch buffers, rather than complete record bytes/views.
Indexes still scale with record count; strictly state-only memory is not claimed.

See [performance.md](performance.md) for exact before/after values, fixture composition, profiling,
RSS methodology, all timing boundaries and the distinction between fresh engine and fresh process.
Host listing/index construction and reading the checkpoint file are outside the engine timers;
new-record fetches are included in the disk-backed fresh-process result. Filesystem caches are warm.
These are desktop observations, not total app-launch or mobile/tail-latency guarantees.

## Implementation

### Verified-prefix trust and explicit invalidation

`engine::Engine<S: RecordSource>` owns a host source, compact record/admission indexes and reducer
state. Its library-wide version-2 checkpoint authenticates a sorted path/exact-envelope-digest
index, authority, identity, admission evidence, key-availability names, per-namespace prefix
counts/digests and reducer states with an explicit host-supplied device-local 32-byte secret.
It persists no epoch secret keys. Reducer state is plaintext, so the host must protect the cache.
The format is a device-local optimization only; [spec section 7.1](../spec/colophon-0.2.md#71-device-local-verified-prefix-optimization-no-wire-change)
documents the shared-folder attacker model and required integrity behavior. There is no wire change.

Missing, unauthenticated, wrong-version/identity/library caches fall back to full verification.
Missing covered listing paths, authority-listing changes, earlier arrivals affecting admission,
and changed epoch-key availability explicitly invalidate admission/projections. Surviving paths
from an authenticated but invalidated cache retain their digest expectations during the rebuild:
changing authority cannot be used to hide an immutable-record rewrite. Ordinary invalid records
remain rejection evidence; indexing them never promotes them to admitted content.

A path-only fast open trusts previously verified bytes until the host fetches/audits them. A
folder attacker can hide unseen suffixes or rewrite a listed covered file, but cannot forge the
local projection/admission cache or admit a new unsigned operation. A later digest/signature
mismatch or missing still-listed bytes is a clear, sticky integrity error, never empty content
or a silent replacement. Global freshness and rollback of old local caches are not solved.

`verify_batch(limit)` checks exact envelopes and independently re-verifies signatures using the
standard RustCrypto path. It returns checked/remaining counts; hosts schedule it and surface errors.
An active audit preserves its last path across appends so continuous writes do not restart it.
Earlier newly inserted paths are covered on the next pass; a full invalidation restarts auditing
following full verification. Failures poison query/write/refresh/unlock/checkpoint operations.

### Lazy content and storage ownership

The core opens no files and performs no directory enumeration, clock reads or entropy generation.
`RecordSource::read(path)` executes synchronously through the host, on the caller's thread.
Already-read batches alone enter worker threads, so the source need not be Send/Sync. `Records`
and `Arc<T: RecordSource>` adapters are included. The duplicate-ID hash index deliberately uses
fixed keys, avoiding the OS randomness implicit in `RandomState`.

Historical payloads are fetched and decrypted only by requested history/full-view operations.
History uses a byte-bounded LRU cache, including zero-capacity and oversized-entry bypass. Query
rendering only reads reducer state. A lazy ordering index is invalidated on record changes.
Raw authority envelopes used for coherent-read checks are dropped after processing too.

New records are handled in batches of at most 8,192, with ordered admission/reduction after
independent verification and payload opening. Numeric clocks are parsed once for sorting;
payload buffers are opened in place. Individual records and projected objects are not size-capped.

### Faster portable verification and host seam

The pinned `p256 0.13.2`/`primeorder 0.13.6` sources have no precomputed-table or alternate faster
field-arithmetic feature to enable. The optimized foreground verifier reuses fixed-base four-bit
public-point tables and computes the standard ECDSA equation with those pinned crates' scalar
and point operations. Secret signing/ECDH implementations and dependency pins are unchanged.

`parallel` is a default core feature. Native builds use `std::thread::scope` with up to 16
workers; disabling the feature or targeting wasm32 keeps a serial path. Standard-verifier
profiling still takes about 328 ms per 2,000 signatures. A serial cached-table run took 5.55 s
for 100k verification/header admission; the final parallel compatibility run took 0.549 s.
The compatible `Library` full rebuild also passes the desktop gate at 1.279 s.

An optional `Arc<dyn verification::BatchVerifier>` receives exact body bytes, raw P-256 signatures
and authority-selected public keys. It returns one ordered boolean per input. Wrong result counts
or backend errors fail closed. The core still decides path/library binding, payload authentication,
IDs, ordering, epochs, grants, budgets and final admission. The callback is synchronous on the
caller thread; FFI providers must own copies if they cross asynchronous boundaries. No CryptoKit
or Android implementation is included. Background audits use the independent standard verifier.

The new public-input arithmetic composition is differential-tested, but remains a review-sensitive
crypto change. Do not treat performance success as an external security audit.

## Public API and binding-worker guidance

All existing public `Library` method signatures and outcome shapes remain unchanged, including
`records()`, `view`, `begin_write`, `finish`, unlock APIs, tools and version-1 namespace checkpoints.
`Library` keeps its in-memory implementation and shares verification, payload validation,
authorization and admission rules with `Engine`. Its existing `open_with_checkpoints` remains
cryptographically eager (1.227 s in the final compatibility run); it does not silently acquire
a new trust model. No WASM export signature changed. The separate UniFFI branch was not built
or edited here.

Native bindings should opt into the following additive API, fully specified in [engine.md](engine.md):

- `Engine::open(source, listing, identity, EngineOptions, checkpoint)` or `open_with_verifier`.
  Options include expected library ID, protected device-local checkpoint key and content-cache budget.
- `begin_unlock()` and `finish_unlock_many(results)`. Supply all available ECDH results together;
  call the latter even with an empty vector before using a newly opened engine. Queries still
  require current permissions and authenticated epoch keys. Checkpoint state does not bypass access.
- `query`, `history`, `view`, `revision`, `stats`, `open_mode`, `authority`, and `source`.
- `begin_write(...) -> Outcome<PendingBatch>`. Host signs; `PendingBatch::finish` yields records;
  host persists atomically, then calls `apply_paths(new_paths)`. The engine never writes storage.
- `apply_paths` for explicit persisted deltas, or `refresh(full_listing)` for reconciliation
  including removals. Both return namespace change summaries. Authority changes can yield new
  unlock tasks. Malformed listings fail before mutation; processing failures poison the instance
  so partially applied batches cannot become visible.
- `checkpoint()` for host-persisted version-2 bytes; `verify_batch(limit)` for scheduled audits.
- `materialize_library()` explicitly fetches/digest-checks and fully verifies all records,
  returning a caller-owned unlocked `Library` for ledger/member counts and administrative actions.
  Use it for approval/revocation/handover/recovery until those administrative paths are separately
  indexed. Drop it after preparing actions, persist signed output, and feed new paths to Engine.
  This deliberately costs O(history) temporarily; Engine does not retain the allocation.

Implementation locations:

- `src/verification.rs`: prepared portable verifier, scoped workers and host batch contract.
- `src/storage.rs`: source-backed Engine, version-2 checkpoints, invalidation, history and audits.
  It is a private child of `library` to reuse trusted internal rules, publicly exported by `engine`.
- `src/library.rs`, `src/authority.rs`, `src/engine.rs`: shared verification integration, cache
  serialization support, and additive public exports.
- `tests/storage.rs`: nine storage/trust/invalidation regressions; verifier differential tests
  live in `verification.rs`. `examples/storage_bench.rs` supplies the new reproducible harness.
- `docs/engine.md`, `docs/performance.md`, `docs/app-migration.md`, and spec section 7.1 document
  the implemented stage and remaining host responsibilities.

Paths above are relative to `crates/colophon-core` for Rust files. No domain semantics changed.
A future reducer/admission/cache schema change must bump the local cache version before accepting
old states; the device-local cache is not a stable interchange format.

## Validation

Passed on the final implementation:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
cargo test
cargo test -p colophon-core --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
npm --prefix js run build
npm --prefix js test
git diff --check
```

37 unique Rust tests pass in both native feature configurations: the previous 27 plus one
prepared-verifier differential test and nine storage-engine tests. Coverage includes zero-read
cold restoration; suffix-only work; auth/key/version/identity fallback; partial unlock; earlier
arrivals; grant-wide budgets; future authority; revocation; invalid duplicate/payload/signature
behavior; exact compatibility views including rejection ordering; lazy cache hits/eviction/zero
and oversized budgets; no-op refreshes; backend count failures; sticky missing/modified-record
errors; preserved integrity evidence across invalidation; audit progress across appends; and
explicit compatibility materialization. Existing protocol and randomized reducer tests remain green.
Node security/smoke tests pass with exact Rust/WASM fixture parity. No vector regeneration was used.

## Reproduction and artifacts

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo build --release -p colophon-core --examples
target/release/examples/bench 100000 /tmp/colophon-engine-100k.records --profile
target/release/examples/storage_bench /tmp/colophon-engine-100k.records
target/release/examples/storage_bench /tmp/colophon-engine-100k.records --cold-suffix
```

The original 100k fixture is reused. Normal storage benchmark mode writes the synthetic
version-2 checkpoint, 1,000-record suffix and expected projection under `/tmp/colophon-engine-v2*`;
run it before `--cold-suffix` with the same fixture. `--source-only`, `--cold-memory` and
`--disk-memory` support independent-process memory measurement; see performance.md's Python
`resource` wrapper. Scratch logs are `/tmp/colophon-stage2-final-*`, with an additional
`/tmp/colophon-stage2-confirmation.log` and `/tmp/colophon-stage2-fresh-confirmation.log`.
They are not committed fixtures. The release binaries and JS build outputs remain available.

Removed **727.6 MiB** of regenerable `target/debug/incremental` data after checks. Build outputs
are approximately 1.3 GiB; no mobile archives or distribution bundles were generated. Dependency
caches and the reusable signed fixture were retained. No cleanup touched source or git metadata.

## Remaining limits and next integration work

1. Wire and existing Library compatibility are preserved, but storage-backed Engine is not yet
   wrapped in UniFFI/JS. Native hosts must implement a coherent source, protected checkpoint/key
   persistence, lifecycle/error handling, background audits and the optional platform verifier.
2. Memory is indexes plus state and bounded content/batches. It is not strictly independent of
   history count. Authority keep sets and reducer conflicts/invalid entries can grow intrinsically;
   record/object sizes are uncapped. Administrative materialization deliberately allocates history.
3. The shared-folder trust window is explicit: path-only opens defer detecting changed covered
   bytes until a fetch/audit. No global freshness or local-cache anti-rollback mechanism is added.
   Hosts must surface sticky integrity failures and resolve the source before reopening.
4. Authority changes, removed prefixes, earlier ordering dependencies and different key
   availability conservatively rebuild. The sub-100 ms gate is for unchanged authority with an
   appendable suffix, not those invalidation cases. Incremental administration/indexing could
   reduce future rebuilds, but must preserve admission and immutability evidence.
5. iPhone/Android performance, total filesystem/iCloud startup, battery cost, tail latency and
   platform-keystore behavior are unmeasured. Review the public-input verification optimization
   before production rollout; no upstream dependency upgrade or platform backend was hidden here.

## Intended commits

Changes remain uncommitted. Suggested dependency-ordered subjects:

1. `Reuse P-256 verification tables and parallelize native record verification`
2. `Add a host-backed engine with authenticated prefixes and lazy integrity-checked history`
3. `Benchmark 100k engine startup and document the storage and trust contracts`

Include verifier tests with the first change, storage regressions with the second, and benchmark,
specification, API, migration-status and performance/handoff documentation with the third.
