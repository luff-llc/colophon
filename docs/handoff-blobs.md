# Handoff: blobs, relay blob sync, proportional sync and Taupe query gaps (branch `blobs`)

November 7, 2026. Closes the Colophon 0.2 SDK gaps that blocked Later offline reading, Taupe
transcripts and Taupe 1.2 cross-platform sync, plus the Taupe Apple migration's query gaps.
Not pushed. No app, relay deployment or production library was touched.

## Commits

| Commit | What |
| --- | --- |
| `1edebc3` | Core blob `required` hint + `blobs` query, listening note `created`, reducer schema 5, FFI `openBlobChunk`/`recordsAt`, regenerated bindings; Swift session blobs and incremental `RelaySync` |
| `9ab90c2` | Android session blobs, incremental `RelaySync`, proportional writes/refresh, known-paths log, `Migrating` + migration writer; cross-platform blob journey |
| `5f43d61` | Taupe query gaps (preferences, recordings, chapter `origin`, imported history, importer normalization, notes dates) and the revision-keyed Swift query cache |
| `f1f6d99` | Settles two timing-dependent Swift session tests |
| (this commit) | Spec, engine, sync, session, Android, domain and performance docs; this handoff |

## Core and FFI

- `colophon.blobPublish {manifest,reference,required?}` and `colophon.blobReference
  {digest,reference,retain,required?}`: `required` is a synchronized eager-download hint, validated
  as a boolean before signing. `blob({digest})` reports it; new `blobs({after?,limit?,required?})`
  pages manifests in digest order without chunk metadata. Reducer schema 5 invalidates older caches.
- FFI: `NativeLibrary.openBlobChunk(namespace,digest,index,ciphertext,now)` authenticates fetched
  ciphertext without a callback (same grant/address/AEAD/digest checks as `readBlobChunk`);
  `recordsAt(paths)` copies only named records. Swift and Kotlin bindings regenerated.
- Listening: `preferences(scope?,target?)` and `recordings(episode?,kind?)` pages; `setChapters`
  accepts `origin` (provenance claim, returned as `contentOrigin` beside the authenticated
  `origin`); `history(mode: importedSession)` pages baseline-imported episodes instead of
  `unavailable`; notes carry `created` (claimed `addNote` date). The importer normalizes legacy
  `null` optionals (where the 0.2 field does not accept null) and Unix-second `published` dates
  before validating children; evidence keeps the original payload.
- Notes domain: notebooks, entries and cells carry claimed `created`/`updated` dates beside the
  logical order (the 0.1 spec already specified timestamps). Content comparisons ignore them.
- Vectors regenerated (`listening.podcasts.*`, `notes.json`, `expected.json`); Rust, WASM, Swift
  and JS parity pass. `conformance.rs` gained a `COLOPHON_UPDATE_VECTORS` path for `notes.json`.

## Swift SDK

```swift
let blob = try await session.putBlob(contentsOf: file, namespace: "notes", mediaType: "application/pdf",
                                     reference: attachmentID, required: false)   // streamed, ≤250 MiB
let payload = blob.descriptor                                 // {digest,size,mediaType} for commands
await session.blobAvailability(namespace: "notes", digest: blob.digest)
// .unpublished | .missing(present,total) | .downloading(done,total) | .available | .inaccessible
let url = try await session.blobFile(namespace: "notes", digest: blob.digest)  // verified temp file
for try await chunk in session.blobStream(namespace: "notes", digest: blob.digest) { … }
try await session.setBlobReference(blob, reference: attachmentID, retain: false)
try await session.collectBlobGarbage()                        // local copies only
```

- Uploads hash first (identical content only gains a reference), then seal 64 KiB chunks through
  the native writer, persist and read back each chunk before reading the next (one chunk in memory),
  then publish through the ordinary journaled write path (`receipt` `.saved`/`.queued`). Blob
  publications may be up to 1 MiB (other commands keep 256 KiB): 4,000 chunks, 250 MiB per blob.
- Reads fetch missing chunks lazily from the relay, verify each chunk in the core under current
  grants and the whole descriptor at the end (`BlobError.digestMismatch`). A revoked member cannot
  open chunks it still holds. `blobFile` appears only after verification.
- `syncNow` downloads `required` blobs after passes that pulled records (and once per launch);
  progress is published in `session.blobDownloads`.
- GC removes chunks of zero-reference blobs and, after a grace period (24 h), unpublished uploads,
  but only chunks listed in this session's private `blob-index.log`, so a shared App Group store
  never loses another app's chunks. `evictReplicated: true` also evicts non-required chunks the
  relay holds. Nothing is deleted if a configured namespace is unreadable.
- `BlobStore` gained `hasBlob`, `removeBlob`, `blobPaths`; `RecordStore` gained `paths()` and
  `read(paths:)` (defaults keep third-party stores compiling). `FolderRecordStore` enumerates without
  reading bytes.
- `RelaySync`: persisted cursor, append-only `relay-remote.log` (legacy `relay.json` maps migrate
  once), path enumeration, reads only records to push or compare, conflicts persisted, chunks pushed
  before records, `fetchBlob` verifies the content address. `Report` adds `pushedBlobs`,
  `localRecordReads`, `listed`.
- `NamespaceStore` is revision-keyed: `cached` returns only current values, `latest` keeps the last
  value while reloading, only re-requested queries are read again, concurrent loads share a read,
  stale entries are evicted first. Generated `*Store` types expose `latest`.

## Android SDK

```kotlin
val blob = session.putBlob(file, "listening.podcasts", "application/json", episodeID, required = true)
when (session.blobAvailability("listening.podcasts", blob.digest)) {
    BlobAvailability.Available -> render(session.blobBytes("listening.podcasts", blob.digest))
    is BlobAvailability.Missing, is BlobAvailability.Downloading -> showDownloading()
    else -> showUnavailable()
}
session.readBlob(ns, digest) { chunk -> sink.write(chunk) }   // verified, chunk by chunk
session.collectBlobGarbage()
```

- Same API and guarantees as Swift (`readBlob` takes a suspending consumer instead of a stream).
  `FileRecordStore`/`MemoryRecordStore` implement `BlobStore` (`<folder>/blobs/<hex>`).
- Proportional writes (the Taupe report's "every write copies the whole record store"): a write
  collects its signed record paths and copies only those from the core (`recordsAt`); refresh merges
  only paths the core has not seen (`FileRecordStore` keeps a path index after one walk);
  publication reads back only pending records; snapshots copy only `requests/` records and detect
  change by native revision; known paths go to an append-only `session-known.log` (older journals
  migrate on first save). Approve/revoke/create still diff the whole map (rare).
- `RelaySync` mirrors Swift (cursor + remote log, path enumeration, chunk push first, lazy fetch).
- `SessionConfiguration.migrationMarker`/`migrationWriter` and `MigrationMarker`: an active marker
  yields `SessionPhase.Migrating` (no create, no writes) except for the writer, which alone may
  publish `colophon.importBatch` (≤1 MiB): the imported-baseline write mode for upgrades.

## Checks and results

| Check | Result |
| --- | --- |
| `cargo test --workspace --offline --locked` | 131 passed, 1 existing ignored 100k shape test |
| `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check` | Passed |
| `COLOPHON_SOFTWARE_KEYS=1 swift test` | Exit 0, 79 Swift Testing tests (28 UI, 29 session incl. 5 blob tests, 1, 9, 12 domain); skipped as before: `crossPlatformStep` (script only), `ffiPerformance`, `enclaveRequiresExplicitFallback`. Five consecutive full runs clean after `f1f6d99` |
| `node --test relay/` | 11/11 (relay unchanged: it already stored and verified chunks) |
| `npm --prefix js ci && run build && test` | key-security, Node smoke with Rust/WASM fixture parity, Books parity passed |
| `bash scripts/test-android.sh --offline` | BUILD SUCCESSFUL, 55 JVM tests, 0 failures (SessionBlobTest 6 incl. real-relay two-device blobs; cross step skipped outside the script) |
| `bash scripts/test-relay-cross.sh` (`CARGO_OFFLINE=1 GRADLE_OFFLINE=1`) | All six steps passed, Android steps ran (`skipped="0"`): Apple's lazy blob read on Android, Android's required blob already available on Apple |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Rebuilt twice (FFI change, then core change); macOS/iOS/iOS-simulator slices, 165 MiB, in `sdk/apple/ColophonFFI.xcframework/` (ignored). No visionOS slices |
| Sync benchmark (100k) | Warm incremental pass 26 ms Swift / 21 ms Kotlin; new-process pass 577 / 228 ms; 1 record read, 0 whole-store reads ([performance](performance.md#relay-sync-benchmark)) |
| Storage-backed 100k gates | No regression vs. the previous commit's binary run alternately on the same loaded machine; cold disk + 1% 99.5–107 ms for both (95.3 ms on the quieter Nov 6 run), rebuild ~1.4 s, write <1 ms |

Two Swift tests were timing-dependent under full parallel load (`twoIndependentSessionsOnOneFolder`
saw a late NSFilePresenter refresh between observing and writing; `automaticSyncDeliversWithoutBarriers`
sampled a transient `syncing` state). Both now settle explicitly; no assertion was weakened.

## Gaps and deferred work

- Swift session refresh/write still collect full record/view snapshots off-main (unchanged design
  until the storage-backed engine is adopted); only the Android write path was made proportional.
  Android still serializes namespace views per refresh and has no named-query API.
- Extensions (Safari, share) still cannot write blobs: the ingress envelope is 32 KiB and carries no
  blob path. Later's Safari checkpoints remain link-only.
- No background scheduling (BGTask/WorkManager) for required downloads; they run during sync passes
  while the process lives. Chunks are the resume unit (64 KiB).
- A blob is at most 250 MiB per manifest; larger media must be split into application parts.
- GC of a zero-reference blob on a device without a relay deletes the only copy; the release of the
  last reference is the app's decision. Relay copies are never deleted; the relay has no blob GC.
- iCloud-placeholder blob chunks surface as `inaccessible`/missing, not hydrated automatically.
- Android imported-baseline mode is a write gate only: no Android `LegacyLibrarySource`, receipt
  journal or `performMigration` equivalent; idempotence relies on the core's stable source keys.
- `importedSession` history lists baseline-imported episodes, not 0.1 per-session rows
  (`started/ended/elapsed`); those remain in import evidence.
- Not addressed from the reports: Android recovery-key persistence/export, the `published`
  date-time format check at write time, Later's search/host index, cross-app source resolution,
  host relocation/recovery/leave protocols, visionOS slices and Android release packaging.
