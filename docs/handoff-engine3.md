# Engine3 handoff — November 6, 2026

Work is uncommitted on `engine3`, based on `250538e8534188a39b6f9c6ecb7fa4f12d11acad`.
Git was used only for reads. No source library, production data, cloud service or app deployment
was touched. This handoff records engine capabilities and synthetic acceptance; it does not
claim that all four shipping apps' codecs and production migrations are complete.

## Done

1. **Authenticated reducer context.** Confirmed schema 3 already delivered verified member
   kinds. Schema 4 adds the immutable grant, root role and destination library context. Append,
   full replay, checkpoint suffixes and storage-backed parallel reducers share it. Books loans
   and notes reviews accept app/device identities and reject other kinds before signing and on
   replay. Saved protected commands use real kind too. Payload role claims cannot grant authority.
2. **Synchronized encrypted evidence.** `colophon.importBatch` uses ordinary namespace encryption,
   signatures, admission and revocation. Common bounded `importEvidence` and `importReceipt`
   queries retain original attribution/date/payload evidence, losing candidates, output bindings
   and authenticated baseline receipts. Every read checks current namespace access. Swift migration
   now uses these queries; it no longer writes or reads `import-evidence-local` as its evidence store.
3. **Historical alternatives.** Materialized labelled historical sets have stable IDs and bounded
   queries. Exact-set, revision-checked acknowledgment cannot silently make rejected old writes
   effective. Original candidates remain in immutable import receipts after acknowledgment.
4. **Earlier-prefix reconciliation.** The additive comparator reports inserted, removed and changed
   old outcomes with prior/current candidates and persisted imported heads. Swift re-evaluates old
   outcomes, publishes reconciliation alternatives and preserves native state/signed history. It
   keeps the migration marker active pending review rather than automatically choosing a correction.
5. **Blobs.** Plaintext descriptors, encrypted content-addressed 64 KiB chunks, signed manifests,
   current grant checks, explicit availability, streaming verification and idempotent live reference
   counts are implemented. `RecordSource`, native `BlobSource`, and Swift `BlobStore` separate lazy
   bytes from record snapshots. Migration persists and reads back chunks before publication.
6. **Atomic publication and reservations.** One complete signed parent publishes a bounded source
   unit's ordered virtual children, evidence, identity bindings and manifests. Partial/invalid
   envelopes expose no partial effects. Stable source keys prevent duplicate effects across retries.
   Category-scoped reservations check the domain object indexes, including retained tombstones;
   deterministic occurrence IDs are available for native collisions and old lifecycles.

Swift and Kotlin bindings/headers were regenerated with the owning script. The XCFramework was
rebuilt for macOS arm64, iOS arm64 and iOS simulator arm64 using `SKIP_VISIONOS=1` (about 165 MiB).
No visionOS or Android release packaging is claimed. See the [full API/wire contract](engine.md#engine3-authenticated-import-storage-and-blobs)
and the [spec extension](../spec/colophon-0.2.md#72-authenticated-import-and-blob-extension-engine3).

## Checks

Final logs and source hashes are retained in `.build/engine3-validation/`.

| Check | Result |
| --- | --- |
| `cargo test --workspace` | 129 passed, one existing ignored 100k shape test; doc tests passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo fmt --all -- --check` | Passed |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed; key-security, smoke and Rust/WASM conformance parity |
| `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` | 0.2 migration 9, session 18, domain 10 and binding 9 runs passed; existing opt-in binding benchmark skipped |
| Full Swift reference suite | Exactly the 13 known sandbox-only failures below; no new failures |
| Kotlin/JVM tests | Four passed; existing opt-in benchmark skipped; new ABI test covers imports, blobs and callback reentry |
| Native binding generation / three-slice Apple rebuild | Passed |
| Hand-authored whitespace check | Passed; generated UniFFI files retain the generator's existing whitespace style |

Ten new Rust integration tests cover atomic/torn publication, conflicting/equivalent retries,
namespace grants/revocation, forged importer roles, loan/review authority, replay/checkpoint
suffixes, historical alternatives and resolution, baseline precedence, category-scoped native
collisions, invalid children, chunk authentication, missing/corrupt blobs, reference counts and
zero-read checkpoint restoration. Existing full-domain replay/role/conformance tests remain green.

Swift migration adds a large-output fixture that publishes two encrypted chunks, verifies exact
plaintext through the native reader, confirms snapshots exclude blob bytes, queries synchronized
evidence and retries without new records. Existing fixtures now inspect signed parent children
and additive reconciliation evidence. A published source unit's receipt is checked again after
refreshed admission before migration progress advances.

Known sandbox-only reference failures: `pendingAuthorityFileIsNotTheHead`,
`signedBatchSurvivesFolderReconstructionSyncAndReplay`, `placeholderArrivingAfterPreflightStillReportsPending`,
`placeholderReadThrowsPendingWithoutCoordinating`, `vectorsStillHold`, `keyringVectorsStillHold`,
`folderStoreCarriesALibrary`, `newIdentityIsLeftOutOfBackups`,
`existingIdentityIsMovedOutOfBackupsWithoutChanging`,
`readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld`, `ubiquitousClaimTimeoutThrowsPending`,
`timedOutWaitingWriteDoesNotLandLater`, and `writeAlreadyInsidePerformWaitsForItsResult`.
The script sets software keys, local module caches and `swift test --disable-sandbox`; it does not
bypass file-coordination/backup-service restrictions. No assertions were weakened or skips added.

## Performance

The existing four-domain 100k fixture and both compatibility/storage-backed harnesses were rerun
with `CARGO_PROFILE_RELEASE_OPT_LEVEL=3`. See [performance measurements](performance.md) and the
retained benchmark logs for exact final timings, work counters and process RSS. The unchanged
checkpoint fetches/verifies/decrypts/applies zero records; the suffix path processes exactly 1,000.
The desktop timing gates apply to the storage-backed engine. They are synthetic warm-filesystem
measurements, not mobile timing, real-library evidence or a 100k-import/large-blob throughput claim.

## Intended commits

1. `Supply authenticated grant and role context to engine reducers`
   — schema generation, context delivery, local fences, indexed identity checks and role regressions.
2. `Publish encrypted import evidence and historical alternatives atomically`
   — source-unit records, output/baseline receipts, reservations, bounded queries and prefix comparator.
3. `Add encrypted streaming blob manifests and host storage interfaces`
   — chunks/descriptors, integrity/availability, explicit reference counts and regression tests.
4. `Bridge engine import storage to native migration hosts`
   — UniFFI APIs/generated Swift/Kotlin, baseline transport, Swift blob stores, migration batches,
   synchronized evidence/receipt checks and native fixture coverage.
5. `Document engine3 contracts, validation and remaining acceptance gates`
   — spec, follow-ups, engine/domain/native/session docs, performance and this handoff.

## Gaps and boundaries

- Earlier 0.2 clients skip the new unknown engine operations. All participating apps must upgrade
  before enabling import batches. Virtual children are authenticated by the parent signature;
  they are not independently signed envelopes. A receipt proves publication, not that every
  child CAS became effective. There is no new dedicated per-child effective/no-op/conflict enum;
  callers use existing domain heads/conflicts/invalid queries with the bound virtual revisions.
- Historical sets are queried separately from native domain conflicts. Acknowledgment does not
  itself edit native content. The app repair UI and application of explicit corrected commands
  remain host work. Swift's orchestrator still stops on identity collisions; the engine supplies
  reservations and deterministic occurrence IDs, but the host must apply typed reference mappings.
- The old-reader codec/projection gaps described in `handoff-migration.md` remain. Unresolved
  source envelopes are archive dispositions under saved-reading scope and never trusted effects.
  Exact original envelopes and resume progress remain protected local archive data; their key
  must survive independently. Cross-device source-archive custody is not added by this extension.
- The ordinary import record is capped at 1 MiB, with at most 1,024 children/alternatives/manifests.
  Larger originals/evidence require blob references or explicitly partitioned units. Blob manifests
  have a maximum of 8,192 chunks and may hit the metadata ceiling earlier. Filtered evidence totals
  scan retained metadata; no large-import throughput/scalable migration-journal claim is made.
- Blob reference counts are explicit live references. Neither zero counts nor tombstones authorize
  deleting retained originals/immutable evidence. No automatic garbage collection runs. Hosts must
  synchronize chunks and verify complete hashes, formats, anchors and source closure; the core
  never certifies those properties merely from a descriptor or starts old jobs.
- Actual iCloud hydration, App Group custody, hardware keys, app UI, mobile performance, visionOS
  slices and Android packaging still need platform acceptance. Rerun Swift outside the sandbox
  before release. The native session remains the compatibility Library adapter; storage-backed
  Engine adoption in session refresh/write paths is separate from these additive engine APIs.

## Final measured results

Storage-backed 100k rebuild: **1,391.915 ms** (<1,500). Fresh-process disk open with 1% suffix:
**95.297 ms** (<100). Local write including signing/persistence/application: **0.872 ms** (<2).
Unchanged cold open: 73.696 ms; in-memory 1% suffix: 90.937 ms. The cold disk process peaked at
128,581,632 bytes. Checkpoint size is 19,249,071 bytes. All projection and work-counter assertions
passed. The compatibility Library's separate rebuild was 1,644.314 ms; it does not implement the
storage-backed cold-open optimization. See the performance document for timing scope and limits.

## Cleanup and retained evidence

After validation, `cargo clean` removed 22,465 files (5.9 GiB); the volume reported 21 GiB
available. Generated bindings and the rebuilt Apple XCFramework remain available. Logs,
benchmark measurement helper and final source hashes are retained in the ignored
`.build/engine3-validation/` directory. Rebuilding Rust requires recreating `target/`.
Git was used only for inspection; all changes remain uncommitted. Work stopped after this handoff.
