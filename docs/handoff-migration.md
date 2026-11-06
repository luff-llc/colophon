# Migration handoff — November 6, 2026

The worktree now has a Rust-to-native import bridge, a root-owned Swift migration target,
durable import receipts, encrypted local evidence, rollout phases, fixture tests, and explicit
retryable key failures. Changes are **uncommitted**. No `colophon-core` files were changed.

This is **not yet a production-complete converter for arbitrary libraries from all four
shipping apps**. Supported projections migrate and resume; missing codecs, inaccessible data,
earlier-history changes and native identity collisions stop or remain visible as unresolved
evidence. The release blockers below must be closed before enabling automatic rollout.

## Implemented

### Pure import bridge and native artifacts

`crates/colophon-ffi/src/migration.rs` exports `import_legacy_batch` and
`bind_legacy_import_state`, with generated Swift and Kotlin counterparts. Inputs include the
full source identity tuple, exact signed-body SHA-256, author label, kind/version, raw payload
JSON, admitted order, original date JSON, admission, evaluated source outcome and domain context.
The bridge exposes **all four existing domain importers**, with commands, stable child/output
keys, evidence, blob writes, publication-barrier flags and opaque books import state.

The FFI does not verify old signatures or substitute admission for old effectiveness. Context
defaults fail closed. Unknown notes outcomes become unresolved rather than an invented no-op.
Batches are bounded to 1,024 operations and checked for increasing source order. Tests cover
all namespaces, held history, ordered batches, output-ID binding and duplicate import.

Swift/Kotlin bindings and headers were regenerated with the repository script. The local
`sdk/apple/ColophonFFI.xcframework` was rebuilt with **`SKIP_VISIONOS=1`**: macOS arm64, iOS arm64
and iOS simulator arm64. It is about 148 MiB. visionOS/nightly slices were intentionally omitted
to limit build time and disk use; this is not a five-platform release artifact. Generated files
retain UniFFI's existing whitespace style; hand-authored diffs pass `git diff --check`.

### Swift migration and source preservation

The root package exports `ColophonMigration`. `LibraryMigration` takes the existing Swift
`RecordStore`, the app's existing reader identity, the current source root identity, a dedicated
new `ColophonSession`, a private migration directory, an independently persisted AES key and
a shared rollout-marker URL. `ColophonStore.FolderStore(oldURL)` supplies the folder adapter.

`SourceReader` copies source records into a reference `MemoryStore`, verifies authority with
the shipped Swift stack and requires a fresh signature from the current root. It reads ordered
reference views and checks each operation against its exact source envelope, signer, namespace,
epoch key and decrypted operation. Signed-body digests hash the original authenticated bytes;
original payload/date JSON and all source envelopes remain available. Refused, unreadable,
unsupported-namespace and invalid-signature envelopes receive unresolved archive dispositions,
not trusted domain effects. The source store is never written. No optional moved marker is made.

Private files use AES-GCM and the existing durable atomic-file writer:

- `migration-progress.aesgcm`: source/destination IDs, full ordered source fingerprints,
  transform/component maps, output bindings, last imported operation per namespace, archived
  record digests, unresolved reasons and members needing to rejoin.
- `source-archive/`: exact source record bytes, encrypted locally and keyed by envelope digest.
- `import-evidence-local/`: encrypted per-operation manifests, original fields, historical
  attribution, domain evidence, actual signed output IDs and any pending blob bytes.
- `migration.lock`: a nonblocking process lock; the actor also rejects overlapping runs.

These files are durable migration data, not caches. The host must retain/protect their AES key
independently. Wrong keys, wrong source libraries and missing/changed known immutable records
fail closed. `evidence()` provides the local review fallback; it is not an engine sidecar query.

`run(batchSize:)` processes a bounded number of source records and checkpoints every completed
source unit. Its writes use `ColophonSession.performMigration`, the normal worker gate,
signing, durable outbox and publication/readback path. Non-expiring receipts bind each stable
source output key and command digest to the signed operation ID. The receipt and pending signed
bytes are journaled together before publication. A crash after publication but before saving
migration progress reuses the exact receipt instead of signing another effective operation.

### Rollout and catch-up

All suite apps must configure the same `migrationMarker` URL outside the library record tree.
An active marker yields `.migrating` before absence, enrollment or ordinary writes can appear.
Only the dedicated root migration session sets `migrationWriter: true`; it must not be used as
the product UI session during import. Marker changes are observed on session refresh/foreground;
there is no separate cross-device marker protocol or remote-completeness oracle.

Old members are listed as “needs to rejoin”; their grants, agents and capabilities are never
recreated. Sibling apps use the existing normal enrollment path, including the explicit
same-device App Group starter policy when the host supplies the new root under that policy.

Subsequent runs reread source authority, admission and complete ordered history. Appended
operations use persisted imported component heads, so native 0.2 edits become conditional
conflicts rather than being overwritten. Import is keyed by source tuple and transform output,
not just the largest clock. Earlier insertion, changed admission or changed duplicate-ID legacy
receipt semantics stop for reconciliation. Native object/tombstone identity collisions stop
before signing, rather than silently treating a failed create as a successful import.
Unresolved entries keep the shared marker active. The old library stays readable throughout.

### Key-provider failures and sample

`SessionKeys` classifies failures at the public-key, sign and agreement boundaries as
`SessionFailure.keysUnavailable(detail:)`. Create, restore and automatic signed enrollment
request failures now enter `.failed` with an actionable reason. `retry()` remembers failed
creation and otherwise retries restoration/enrollment with the same identity. It does not
regenerate keys. Other failures use `.other(detail:)` or the existing access/storage phases.

`KeyFailureTests` exercises failure and recovery for all three paths. The sample displays the
reason and Retry, plus the upgrading state. Launching with `--demo-key-failure` uses a fresh
temporary demo library and a provider that fails its first access; Create then Retry demonstrates
the flow without Keychain entitlements or modifying an existing sample library. Both sample
targets compile. Interactive launch was attempted, but this restricted host returned
LaunchServices `kLSNoExecutableErr` (-10827), despite the executable being present. No visual or
physical-device acceptance is claimed. `docs/followups.md` item 1 records the SDK fix and this gate.

## Fixture evidence and checks

`swift/Tests/ColophonMigrationTests/MigrationTests.swift` contains eight passing tests. The
main fixture is built using the actual Swift authority, identities, replicas and service APIs:
three members, four namespaces, stale alternatives, revocation/held history, a legacy feed
bridge, saved podcast-state baseline, podcast source publication, a historical worker request
and an unsupported saved-reading archive record. It compares query fields with the old folds,
checks importer-only authenticated authorship, original signed-body digests, durable evidence,
no copied grants, no resumed worker job, idempotent reruns and unchanged source bytes.

Other tests cover interruption immediately after signed publication, restart/resume without
duplicates, appended catch-up after native edits, earlier offline arrival, non-root rejection,
bad signatures, lost evidence keys/wrong source, and native identity collisions. This is
synthetic fixture evidence, not inspection or acceptance of private production libraries.

Validation logs are retained in `.build/migration-validation/`:

| Check | Result |
| --- | --- |
| `cargo test --workspace` | Pass: 101 tests; one existing ignored test |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass |
| `cargo fmt --all -- --check` | Pass |
| `npm --prefix js test` | Pass after `npm ci` and `npm run build`; initial worktree lacked `js/dist` |
| Swift migration target | 8 tests pass |
| Swift session target | 18 tests pass, including two new key/barrier tests |
| Swift binding target | 9-test run passes; opt-in FFI benchmark remains skipped |
| `bash scripts/test-kotlin.sh` | Pass: existing journeys plus new generated-ABI migration test; benchmark skipped |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Pass, three stable Apple slices |
| `bash scripts/build-sample.sh --restricted` | Pass for macOS and iOS simulator |
| Full software-key Swift run | **Not green in this sandbox:** same 13 reference-suite coordination/backup failures documented in `handoff-session.md` |

Swift commands used `scripts/test-swift.sh`, which sets `COLOPHON_SOFTWARE_KEYS=1`, uses local
module caches and disables only nested SwiftPM sandboxing. The latest targeted run includes
all eight migration tests. The full run's 368-test reference runner reported these 13 failures:

- `pendingAuthorityFileIsNotTheHead`
- `signedBatchSurvivesFolderReconstructionSyncAndReplay`
- `placeholderArrivingAfterPreflightStillReportsPending`
- `placeholderReadThrowsPendingWithoutCoordinating`
- `vectorsStillHold`
- `keyringVectorsStillHold`
- `folderStoreCarriesALibrary`
- `newIdentityIsLeftOutOfBackups`
- `existingIdentityIsMovedOutOfBackupsWithoutChanging`
- `readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld`
- `ubiquitousClaimTimeoutThrowsPending`
- `timedOutWaitingWriteDoesNotLandLater`
- `writeAlreadyInsidePerformWaitsForItsResult`

Their failures are file-coordination/backup-service access and coordination-claim timeouts.
No production coordination fallback, weakened assertion or additional test skip was introduced.
Rerun the full command on an unrestricted host before merging.

## Gaps and engine-facing requests

1. **Complete old app projections/codecs.** The reference saved-reading module in this tree
   contains only `SavedLinks.swift`, `SavedShelf.swift` and `SavedLinks+Spec.swift`; its fold
   handles capture, state and metadata. Later's full content/source/annotation/review/feed/
   magazine/archive folds and original codecs are not here. Their operations remain unresolved.
   The Swift evaluator also still needs the remaining podcast preferences, queue-retention,
   natural-end, playlist, chapter/transcript/answer/capture service adapters, and notes
   attachment/proposal/review custody adapters. The FFI can already carry the contexts expected
   by their Rust mappings. Wire actual old projections; do not infer success from a signature
   or reimplement them as generic last-write-wins. Current Swift round-trip coverage is a subset
   of the disposition tables; existing Rust every-kind vectors are not a substitute.
2. **Encrypted, grant-checked import evidence and historical alternatives.** Replace the
   explicitly local encrypted fallback with the engine sidecar and bounded `importEvidence`
   query. Preserve original attribution, full losing candidates, all output-ID bindings and
   trusted baseline receipts. Do not infer baseline privileges from user payload extensions.
   Historical resolutions requiring a materialized alternative set remain pending until the
   overlay exists. Local evidence is not synchronized and is not available to sibling apps via
   their namespace grants.
3. **Earlier-prefix reconciliation.** The current implementation deliberately stops when old
   admission/order changes behind the imported tail. It does not yet import every possible
   late offline arrival. The engine needs an additive reconciliation interface for changed old
   outcomes against persisted imported component heads, producing explicit alternatives while
   preserving native edits and immutable signed destination history. Tests prove safe stopping,
   not automatic reconciliation. Unresolved markers currently have no user-facing repair flow.
4. **Atomic import publication, identity reservation and precise write outcomes.** Provide a
   transaction that durably binds source receipts, evidence, blob descriptors and all signed
   children before exposing a source unit. The shared marker currently hides partial units
   from ordinary sessions; storage itself is atomic per record. Reserve destination identities,
   including native objects and tombstones, and return deterministic occurrence mappings for
   collisions during catch-up. Currently those collisions stop. Expose effective/no-op/conflict/
   invalid results and actual component heads so hosts need not infer them from snapshot JSON.
5. **Blobs and role-sensitive effects.** Archive preservation is implemented; destination blob
   re-encryption, grant-aware storage and verified anchor/source closure are not. Notes output
   blob bytes are retained encrypted locally and flagged. Copy-loan/proposal-review authority
   remains subject to `followups.md` item 2. Do not mark an unavailable original as verified or
   recreate historical agent acceptance as fresh authority.
6. **Scale and platform acceptance.** Reference prefix evaluation and current session snapshots
   still perform whole-history work. Batches bound source units, not a single native engine
   transaction. Progress and permanent receipts grow with history and currently share local
   64 MiB read bounds; there is no 100k-library benchmark or large-blob acceptance claim. Adopt
   incoming incremental/checkpoint APIs and scalable receipt storage. Exercise actual App Group,
   iCloud hydration, marker visibility, identity custody, hardware and shipping-app UI journeys.
   Build visionOS slices and run the unrestricted Swift suite before a release.

## Intended commits

1. `Expose verified legacy domain import plans through UniFFI`
   — FFI adapter, transport types, Rust tests, generated Swift/Kotlin/header files and JVM test.
2. `Add migration-aware sessions and explicit retryable key failures`
   — phase/marker, durable source-output receipts, identity-collision guard, provider error
   classification, retry behavior, sample demo and session tests.
3. `Add root-owned Swift library migration with encrypted evidence and resume`
   — package target, verified source snapshot, source evaluation, local progress/archive/evidence,
   catch-up safety and eight Swift fixture tests.
4. `Document migration contracts, verification and remaining rollout gates`
   — app migration, native bindings, session contracts, follow-up fix and this handoff.

Git was only read; nothing was committed, merged or published. Cargo cleanup removed about
2.9 GiB of rebuildable outputs, including the host test dylib; `scripts/test-kotlin.sh` rebuilds
it automatically. Generated sources, the XCFramework, JavaScript distribution, sample products,
Swift cache and validation logs remain. Approximately **15 GiB** was free after cleanup.

Work stopped after writing this handoff, as requested.

## Merge into `integrate2` — 2026-11-06

Resolved `docs/native-bindings.md` and `docs/session.md`, preserving both the named-query
contracts and migration/key-failure contracts. Main's engine remains unchanged: verified-prefix
checkpoints, authenticated reducer schema generation 3, parallel verification/reduction, and
lazy host `RecordSource` history. The already-integrated Swift domain helpers still query
projection state directly; no whole-history reads were added to query paths. All-four-domain
zero-read query and bounded lazy-history regressions pass. The native session still uses the
compatibility snapshot adapter for refresh/write operations; bridging the storage-backed
engine into that adapter remains separate work, as do the migration gaps listed above.

Regenerated Swift/Kotlin bindings and headers from the combined query/import FFI; they match
the merged generated sources. Rebuilt the 159 MiB XCFramework with `SKIP_VISIONOS=1` for macOS
arm64, iOS arm64 and iOS simulator arm64; visionOS remains omitted.

Validation logs are in `.build/merge-validation/`:

- `cargo test`: 119 passed, one existing ignored; doc tests passed.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`: passed.
- `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test`: passed.
- `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` (`swift test --disable-sandbox`):
  migration (8), session (18), domain (10), and native-binding (9, including the existing
  skipped opt-in benchmark) runs passed. The reference run had exactly the same 13 known
  sandbox-only failures listed above, with no additional failures.
- `bash scripts/test-kotlin.sh`: three tests passed, including the migration ABI test;
  the existing opt-in benchmark was skipped. Working-tree whitespace checks passed.

After validation, `cargo clean` removed 3.6 GiB of disposable outputs. The rebuilt XCFramework,
JavaScript distribution, Swift cache and validation logs remain; about 14 GiB is free.
No Git-writing commands ran. Conflict markers are removed from the working files; the index
intentionally still lists the two paths as unmerged until the resolutions are staged.
