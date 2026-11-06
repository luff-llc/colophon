# Engine handoff — November 6, 2026

Implemented in the `engine` worktree, left uncommitted as requested. No `.git` writes, commits,
pushes or deployments were attempted. `crates/colophon-ffi` and `docs/domains/` were not touched.
No crates or dependency pins changed. All 0.2 conformance record and expected-output bytes are
unchanged; the specification edits document additive reducer/query APIs, not wire changes.

## What changed

- Ported saved reading, podcasts and notes to `Reducer` with associated serializable state,
  single-operation `apply`, single-object queries and bounded collection pages. Existing
  `DomainModule::fold` remains a from-scratch replay wrapper. Conflict, extension, tombstone,
  passive-position/seek, attribution and invalid-payload semantics are preserved.
- `Library` caches signature verification, authenticated operation projections and admission.
  Each namespace retains admitted order, rolling prefix hashes, reducer state and a local revision.
  Appends apply only new content, including writes to a quiet namespace behind another namespace's
  clock. Capped-author ordering still respects grant-wide budgets. Earlier arrivals, authority
  changes and unlocks rerun admission from cached evidence and replay only changed projection
  suffixes from the nearest retained valid checkpoint.
- Added change summaries, configurable bounded automatic snapshots and explicit checkpoint bytes.
  Checkpoints bind version, library, recipient, namespace, epoch, state and admitted-prefix digest.
  A recipient-specific key derived from authenticated HPKE ECDH authenticates the cache body;
  another member's namespace AES key is not enough to forge this recipient's cache. Tampering,
  changed prefixes and version/identity mismatches fall back to record replay. Suffix operations
  always undergo normal admission checks. These are local caches, never signed/shared records.
- Added atomic batched key unlock, cached schema/signing-key parsing, borrowed canonical ID/AAD
  serialization, allocation-efficient digest encoding and borrowed replay inputs. Removed duplicate
  ciphertext buffers after opening. The core still performs no I/O, clock reads or RNG calls.
- Added a deterministic 100k-operation benchmark and eight engine regression/property-style tests.
  Updated only the engine portion of the migration plan and supporting architecture/spec notes.

Implementation: `crates/colophon-core/src/{domain,engine,library,records}.rs`.
API and cache format: [engine.md](engine.md).
Measurements and precise blockers: [performance.md](performance.md).

## API compatibility and binding integration

Every existing public `Library` method signature and outcome shape is unchanged. `merge` is now
an adapter around `merge_with_changes` that discards the summary. `begin_write`, `finish`, `view`,
`records`, `begin_unlock`, `finish_unlock` and existing tool names continue to work. Full `view`
and the `namespace__read` tool retain their old history-bearing shape. No WASM export signature
changed; rebuilt JavaScript can use the additive query tools through its existing `call` method.

Additive Rust APIs for the binding worker:

- `query(namespace, name, args, now) -> Result<Outcome<Value>>`
- `merge_with_changes(records)` and `finish_with_changes(pending, signatures)` returning
  `ChangeSummary { namespaces: BTreeMap<String, u64> }`
- `changes()`, `revision(namespace)`, and diagnostic `applied_operations(namespace)`
- `checkpoint(namespace)`, `restore_checkpoint(namespace, bytes)` and
  `open_with_checkpoints(records, identity, checkpoints)`
- `set_checkpoint_policy(CheckpointPolicy { every, retain })`
- `finish_unlock_many(Vec<(String, u64, Vec<u8>)>)`, tuples containing namespace, epoch and host
  ECDH shared secret; validates all results before installing keys and refreshes once

Use `getEpisode` and `getQueue` for podcast reads; `episode` and `queue` remain writes. Pages
return `{items, nextOffset}`, default 50, maximum 200. Reset paging when the namespace revision
changes. Collect changes after both merge and unlock. Revisions are local observation tokens,
not checkpoint identities. Prefer batching unlock on cold start; the old sequential API remains
correct, including staged checkpoint restoration. Domain version changes must bump cache format
version before accepting old states.

The new Rust APIs have not been wrapped in the separately owned UniFFI crate. No same-identity
regrant was introduced: 0.2's immutable grants still require fresh-identity re-enrollment.

## Validation

All passed on the final Rust implementation:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
npm --prefix js run build
npm --prefix js test
git diff --check
```

27 Rust tests: the original 19 plus eight engine tests. Added coverage includes fixed-seed
randomized reducer orders and shuffled record arrival, comparison with fresh rebuild after each
scripted step, held-to-admitted transitions, removal of unpreserved writes on revoke, fresh-identity
re-enrollment, cross-namespace budget displacement, quiet-namespace appends, no-op merges,
nearest-checkpoint replay counts, checkpoint tamper/identity/version/digest/length mismatch,
suffix admission, sequential and atomic batch unlock, restored-snapshot reuse, query/write-name
separation, paging bounds and an independently computed rolling digest. Existing protocol tests
continue to cover hostile clocks, invalid duplicates, fractional IDs and authority failures.

JavaScript dependencies were installed with `npm ci --prefix js`; WASM and TypeScript were rebuilt.
Node key-security, smoke and exact Rust/WASM fixture parity all pass. Generated `js/dist` and build
caches remain ignored. No vector-regeneration flag was used.

## Benchmark and results

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 cargo build --release -p colophon-core --example bench
target/release/examples/bench 100000 /tmp/colophon-engine-100k.records --profile
```

The example generates the deterministic signed fixture on first run and reuses the optional file
on later runs. Remove the file to regenerate it. It needs no new dependency or benchmark harness.
The benchmark and local scratch fixture/logs are separate from conformance vectors. Build output
is about 1 GB; no mobile archives or other large distribution artifacts were generated.

Final measured run: Apple M3 Max, 16 cores, 64 GB, macOS 27.0.1, rustc 1.91.1, release/LTO with
`opt-level=3`. The existing default size-focused WASM release profile is unchanged.

| Operation | Result |
| --- | ---: |
| Single local podcast write, including signing/merge | **0.595 ms**, one reducer application |
| Single local write to quieter notes namespace | **0.479 ms** |
| Full verified rebuild | **17.798 s** |
| Verified cold open with checkpoints | **18.202 s**, zero reducer applications |
| Warm restore with history already verified/decrypted | 71.468 ms |
| Near-start out-of-order insertion | 190.413 ms |
| Peak benchmark-process RSS | 623.2 MiB |

## Known gaps and next gates

The write target is met on this Mac. Full rebuild (<1.5 s), true cold open (<100 ms), and
state-proportional memory are **not** met. This is an incremental-engine milestone, not completion
of the app migration's performance proof gates.

Signature verification dominates: the isolated 2,000-record sample took 327.546 ms, approximately
16.4 s per 100k before the rest of startup. Header parsing took 2.442 ms and decrypting took
4.262 ms for the same sample. Projection checkpoints cannot remove that verification cost. A
separately authenticated persistent verified-record index needs explicit binding and invalidation
rules; a faster/parallel verifier needs measured platform and WASM contracts. Neither is present.

The public borrowed `records()` API, full compatibility views/ledger, replay evidence and budget
indexes still retain O(history) data. Reducer state and checkpoint retention are bounded by their
projections/policy, but library memory is not. A new host-storage-backed engine with bounded caches
is needed to change this without breaking the existing API. Peak RSS also includes benchmark
record copies and compatibility view allocations, so it is not a steady-state library-only number.

Object pages currently sort projection references before slicing; large text/extensions are not
size-capped. Automatic snapshot creation can add latency at cadence boundaries. Desktop measurements
are single-run observations, not tail-latency guarantees. iPhone/platform-keystore performance is
untested and remains required before rollout. See [performance.md](performance.md) for reproducible
commands, phase timings, baseline comparison and the full explanation of each blocker.

## Intended commits

Changes are intentionally uncommitted. Suggested commit subjects:

1. Refactor built-in domains into incremental reducers and bounded queries
2. Cache verified admission and maintain namespace state and revisions
3. Add authenticated local checkpoints and prefix-safe replay
4. Optimize operation decoding and add a deterministic 100k engine benchmark
5. Test incremental histories and document performance proof gates

Suggested trailer: `Co-Authored-By: Codex <noreply@openai.com>`.
