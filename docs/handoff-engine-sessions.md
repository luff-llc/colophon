# Native engine sessions handoff

Worktree: `engine-sessions`, based on Colophon 0.3 at `f5839c2`. Changes are uncommitted.
The Swift and Android sessions now use the storage engine. This is a functional migration;
performance acceptance and remaining limits are recorded below rather than inferred from Rust-only timings.

## Design and changes

- Added `NativeEngine` and synchronous `EngineRecordSource` callbacks in `colophon-ffi`.
  A batched binary inventory carries scoped paths and optional provider versions without
  redundant generated string/map marshaling. Callbacks only fetch bytes; host signing/ECDH
  remain outside the engine lock. Reentry fails instead of deadlocking. Signing actions are
  bound to the originating session and revision.
- Added opaque checkpoint preparation/opening/key handles. Signed, member-bound HPKE tickets
  protect an AES-GCM private checkpoint. The binary `COLOPRV3` envelope avoids large base64
  allocations; opening still accepts the earlier JSON envelope. The inner authenticated
  engine checkpoint is unchanged. No epoch keys are persisted, and no cache enters sync.
- BindingSessionCore in both languages opens the engine with the host source, scope and local
  `CheckpointCache`. It authenticates authority/layout before requesting content. Valid prefix
  restoration skips covered operation bodies; suffixes undergo normal admission. Wrong identity,
  altered provider versions, changed authority, missing covered records, unsupported layout and
  integrity failures retain the existing fail-closed behavior. Explicit rejoin discards the old
  identity's acceleration cache after validating the replacement key provider.
- Worker snapshots carry readiness, authority metadata and namespace revision tokens. Named
  queries replace eager views. Write receipts fetch only their operation; passive playback
  preparation copies one episode and its ordering barrier, not the entire podcast namespace.
  The engine retains bounded signed live heads so a deliberate action can preserve predecessors.
  Blob encryption/decryption and current access checks use the same engine.
- Publication still journals intent, appends history before live state, conditionally replaces
  the slot, reads exact bytes back, then acknowledges provider versions and clears the pending
  journal. Source callbacks switch to actual durable storage after creation/publication.
  Checkpoints run after one idle second; additive `flushCheckpoint()` is a lifecycle/test barrier.
  Each save performs a bounded 128-record integrity audit before persisting.
- Swift's known-path journal now uses an append-only sidecar (backward compatible with inline
  paths), and both journals track new paths incrementally. Optional complete provider deltas
  avoid full listings for memory stores. Folder stores keep conservative metadata enumeration.
  Swift's read callback uses a lock-protected memory store or safe filesystem reads; custom
  actor-only stores retain a snapshot fallback. Memory-store versions are content digests,
  stable across a newly constructed store, rather than coincidentally equal counters.
- Enabled the pinned RustCrypto libraries' ARM AES/POLYVAL backends in `.cargo/config.toml`.
  These use the libraries' CPU feature detection and constant-time software fallback. This
  affects all ARM builds in this workspace, including the compatibility benchmark adapter.
- Regenerated Swift/Kotlin bindings and rebuilt the macOS/iOS-device/iOS-simulator XCFramework.
  visionOS was explicitly omitted with `SKIP_VISIONOS=1`; the artifact is not a five-platform release.

## Public API and compatibility costs

Existing session, namespace-store, operation, revision, access and blob API types are retained.
The complete compatibility ledger is lazy. Swift reads it synchronously on property access;
Kotlin's List materializes on inspection. A custom StateFlow wrapper publishes snapshot identity
without triggering List equality and historical loading on every session update. Named app
queries do not inspect the ledger. Large explicit ledger reads can block the caller. A retained
Kotlin lazy ledger that has never been inspected reads the engine at first inspection, so it
is not an immutable historical snapshot. This behavioral difference needs app-review attention
where a consumer stores ledger Lists across revisions. Administrative approval/revocation also
materialize compatibility history; they are not optimized in this work.

## Benchmarks

See [performance.md](performance.md#native-session-engine-migration) for the measured table,
methodology, counter assertions, targets and reproduction command. The harness runs actual
`ColophonSession.restore()` and `perform()` on Swift/macOS and Kotlin/JVM. Its compatibility
mode uses test-only copies of the previous BindingSessionCore, with the current worker/provider
and current Rust crypto build held constant. This is a controlled adapter comparison, not a
checkout-wide replay of the untouched f5839c2 binary. Previous release measurements remain in
the performance document for that historical boundary.

## Checks

All required checks passed on the final implementation:

| Check | Result |
| --- | --- |
| `cargo test` | 154 passed; one existing explicit 100k performance test ignored by default |
| `cargo clippy --all-targets -- -D warnings` | Passed |
| `cargo fmt --all --check` | Passed |
| `COLOPHON_SOFTWARE_KEYS=1 swift test` via `bash scripts/test-swift.sh` | 88 tests passed; opt-in benchmarks/cross journey run separately |
| `node --test relay/` | 12 passed |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed |
| `bash scripts/test-android.sh` | 59 passed; benchmark/cross tests opt-in, run separately |
| `bash scripts/test-relay-cross.sh` | Passed: Apple create, Android join, Apple approve, Android write, both verify records/blobs |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Passed; bindings regenerated and three-slice XCFramework rebuilt |
| `bash scripts/bench-sessions.sh` | Both languages/modes passed, including zero-prefix-work and 1,000-suffix-work assertions |

SwiftPM's nested `sandbox-exec` is unavailable in this managed sandbox, so the repository's
`test-swift.sh` uses `--disable-sandbox` and workspace module caches while retaining software
keys. This is the existing restricted-builder equivalent, not skipped Swift tests. SDK/Gradle
and simulator-service warnings did not fail builds. No simulator/device execution is claimed.
UniFFI's generated files retain its whitespace formatting; handwritten changes pass diff checks.
Logs are copied to `target/engine-sessions/validation/`; benchmark logs/XML remain alongside.
New tests cover FFI stale actions and provider-version changes, protected binary cache tampering,
Swift/JVM prefix/suffix restoration, current query results and wrong checkpoint recipient.

## Remaining gaps

- **The Mac performance gates are not met.** Swift checkpoint open/passive write measured
  **776.420 / 5.911 ms**; Kotlin measured **436.082 / 14.966 ms**, against **150 / 5 ms**.
  The migration removes historical crypto and eager projection/ledger work from the ordinary
  path, but this is not performance acceptance. Next work should profile host inventory/journal
  construction and protected-cache decode, then publication/JVM first-write overhead. Avoid
  weakening admission, provider-version validation or durable receipts to meet the numbers.

- The under-500-ms oldest-supported-iPhone launch goal is unmeasured. These tests use software
  keys on a Mac, local private-cache files and in-memory record bodies. Physical devices,
  secure hardware keys, real Taupe/Later/Shelf/Scribenda stores and filesystem hydration need
  separate launch measurements. No Android device/AAR release or app migration was performed.
- The complete path/version inventory, private checkpoint decoding and known-path log still
  scale with record count. Folder providers still enumerate metadata before writes; only
  providers supplying complete change tokens have the O(delta) host refresh path.
- Explicit ledger and admin compatibility calls still decrypt history. Legacy `read` queries
  serialize a full namespace state; use bounded named queries for large screens.
- A successful `perform()` persists records and publication receipts, not a fresh full checkpoint.
  Hosts needing a deterministic cache before exit should await `flushCheckpoint()`. Failed or
  unavailable cache writes surface through session error handling; they are not silently trusted.
- Providers without content versions retain the engine's verified-prefix trust contract and
  require independent audits to detect later disk damage. Tokens never establish global freshness.
- Background audit/checkpoint serialization is bounded in audit count but checkpoint size remains
  O(index + projection). It is not on the timed write path, and can contend with a later operation.

## Merge with v03 review fixes

Resolved the working-tree conflicts with v03 review commit `17aaa41` on November 7, 2026.
Both parents' Rust test functions are retained, together with the native review tests. No Git
write commands were run: the index intentionally still reports the five conflicted paths as
unmerged until the user stages the resolved files. Existing staged changes were left intact.
This section supersedes the earlier validation and timing summary for the merged implementation.

### Security and engine integration

- The storage engine retains v03's authenticated live-generation/envelope-digest witnesses across
  checkpoint restoration and replay invalidation. Signature, library/path/stamp, grant, epoch,
  decrypted payload and admission checks precede live promotion. Malformed, forged, rolled-back,
  conflicting same-generation and inadmissible replacements fail closed; a failed engine cannot
  publish a checkpoint. Expiring or budget-capped writers cannot admit live-stamped records,
  including copies retained under immutable operation paths.
- Live generations obey the 1,024 forward-clock bound. Live samples do not advance durable
  admission clocks or namespace/author replay tails; periodic immutable anchors retain their
  predecessors. The engine's member-write index remains bounded to durable IDs and current heads.
- Engine writes use the shared bounded episode preparer and fetch exact predecessor envelopes
  through the source callback, checking their indexed digests before adding `PendingBatch.copies`.
  Targeted episode heads and explicit revision references survive deliberate actions without
  retaining unrelated heads or replaying the immutable prefix.
- Native operation receipts now accept verified/authenticated live heads without requiring the
  durable `SPENT` flag. Retaining that old receipt requirement after v03 stopped live clock
  spending would have made valid engine-backed passive writes appear unavailable.
- `COLOENG4` metadata version 4 and reducer schema 7 remain in force. Checkpoint restore validates
  author signing-key digests and authority/epoch bindings; lazy payload reads and independent
  audits validate exact envelope/header bindings. The session's protected binary `COLOPRV3`
  outer envelope, member-bound key ticket and provider-version checks remain unchanged.
- Swift/Kotlin workers retain `openStorage`, version-aware merges, complete provider deltas,
  named queries, lazy ledgers, bounded preparation and delayed checkpoint saves. Cold open sets
  `opened` only after host live/request reads complete. Authority is not merged twice, and live
  publication compares against observed provider bytes rather than pending journal replacements.
  Kotlin translates unsupported layouts at both engine-open and delta authority barriers.
- Swift retains v03's fractional/whole-second expiry parsing, refresh deadline strictly after
  inclusive expiry, task cancellation ownership, and retained-content query/readiness fixes.

The new `merged_engine_playback_receipts_anchors_and_retention` regression executes 1,030 engine
samples, checks every live receipt, requires only two immutable anchor applications and bounded
member counts, then restores a checkpoint and retains the exact referenced head for a seek
without prefix replay. A fresh full reopen must show the seek. Both native playback tests now
check exact predecessor bytes, a saved seek receipt, two immutable records and checkpoint reopen.
The Kotlin counting-core test observes the engine's `mergeObserved` path as well as `merge`.
Both native benchmark harnesses explicitly assert record-read counts and zero immutable passive
applications, in addition to their signature/decryption/application restoration checks.

### Validation

Logs are under `target/engine-sessions/merge-validation/`; the full Android XML results were
preserved there before benchmark/cross-test filtering replaced Gradle's active report directory.

| Check | Merged result |
| --- | --- |
| `cargo test` | 165 passed, 0 failed; one existing opt-in 100k test ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo fmt --all --check`, `git diff --check`, conflict-marker scan | Passed; no markers in resolved files |
| `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` | All five products passed: 29 + 39 + 1 + 9 + 12 reported tests; three opt-in cases skipped |
| `node --test relay/` | 12 passed |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed; WASM rebuilt again after the final Rust receipt change |
| `bash scripts/test-android.sh` | 60 passed, 0 failed; two opt-in cases skipped |
| `bash scripts/test-relay-cross.sh` | All six Apple/Android stages passed, including live replacement, deliberate rewind and blobs |
| `CARGO_PROFILE_RELEASE_OPT_LEVEL=3 SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Passed; bindings regenerated without source changes, 193 MiB macOS/iOS-device/iOS-simulator XCFramework rebuilt |
| `bash scripts/bench-sessions.sh` | Swift/Kotlin compatibility and engine runs passed, including zero-prefix-work and exactly 1,000-suffix-work assertions |

Swift uses the existing workspace-cache/`--disable-sandbox` wrapper for this restricted builder.
JDK 17, the supplied Android SDK/NDK paths and the writable shared Gradle/Cargo homes were used.
Existing SDK XML, FSEvents, Gradle/Kotlin and unavailable CoreSimulator warnings did not fail the
checks. No visionOS, simulator/device execution or new Android AAR build is claimed.

### Merged measurements and remaining limits

The four native runs were sequential after validation/build work. Current engine checkpoint-open /
first-passive-write timings are **757.398 / 5.333 ms in Swift** and **463.756 / 11.411 ms in Kotlin**.
The **<150 / <5 ms gates remain missed on both platforms**. The independent 1,000-operation suffix
opens are **789.140 ms / 456.958 ms**; notes writes are **4.099 ms / 8.188 ms** respectively.
These are single warm-process/filesystem Mac runs using software keys and memory providers;
physical-device launch and tail latency remain unmeasured.

[performance.md](performance.md#native-session-engine-migration) now retains the original native
session table and v03's reviewed Rust tables as explicitly separate historical measurements, and
adds the merged native table. [Merged result data](benchmarks/engine-sessions-v03-merge.json)
records all four columns. Raw current native logs/XML remain at
`target/engine-sessions/{swift,kotlin}-{legacy,engine}.{log,xml}`; prior native logs are archived
under `target/engine-sessions/pre-merge-benchmarks/`.

The regenerated 10,000-sample native Taupe fixture has 20 immutable operations, one live slot,
9,991 history records and three authority records. Its 21 opening operation/state paths include
nine bounded-clock anchors and their predecessors. Unlike v03's separate Rust Taupe benchmark,
this native fixture has no final seek, so its count must not be confused with that table's 22
immutable operations. All earlier API/ledger, inventory scaling, folder-provider, background
checkpoint and mobile-measurement limitations still apply.

