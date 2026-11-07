# Moving LUFF's apps onto the Rust core

Status: proposed, November 6, 2026. Goal: Taupe, Later, Shelf and Scribenda (Apple), and the
Android client, run on Colophon 0.2's Rust core, with a shared app SDK that makes the next app
mostly product work. Two things drive it: performance on long histories, and integration code
that each app currently re-assembles.

The integration guide in the Marginalia repo
(`docs/colophon/guides/app-integration-and-sdk-extraction.md`) records what building Later and
Taupe taught. Its warnings shape this plan: no hidden broad grants, no silent emptiness for
missing data, explicit cache invalidation, and every shared seam proven by two real apps.

## What is slow or repeated today

- `Replica.state(of:)` refolds a domain from all decrypted operations on every call; decrypted
  operations are cached, domain state is not. Long podcast and reading histories make every
  read proportional to the whole journal.
- There are no checkpoints: every cold start replays everything.
- Each app wires restoration, phase and revision observation, membership errors, ingress and
  widget publication by hand (`SuiteLibrary`, `SuiteLaunch`, `LibrarySession`, app entry
  points). The fourth app would copy it again.
- Domain semantics exist only in Swift, so Android re-implements them (the legacy journal port).

## Architecture

```
            app (SwiftUI / Compose): product UI only
   ┌──────────────────────────────────────────────────────┐
   │ ColophonSession (Swift @Observable / Kotlin StateFlow)│  lifecycle, phases, membership,
   │                                                      │  typed domain stores, ingress
   ├──────────────────────────────────────────────────────┤
   │ platform adapters: folder/App Group/iCloud store,     │  file coordination, watching,
   │ key providers (Secure Enclave, Keystore, software)    │  local checkpoint cache
   ├──────────────────────────────────────────────────────┤
   │ colophon-ffi (UniFFI): Swift and Kotlin bindings      │
   ├──────────────────────────────────────────────────────┤
   │ colophon-core (Rust): verification, authority,        │  pure; no I/O
   │ admission, incremental engine, domain reducers,       │
   │ queries, checkpoints, 0.1 import model                │
   └──────────────────────────────────────────────────────┘
```

### The incremental engine

- Domains are **reducers**: `apply(state, admitted operation)`, not whole-view folds. The engine
  keeps each namespace's state and the admitted order.
- Appending operations that sort after the tail costs time proportional to the new operations.
  An operation that sorts earlier (offline work, held operations later admitted, authority
  changes) invalidates affected evidence. `Library` can replay from the nearest retained
  projection checkpoint; storage-backed `Engine` conservatively verifies/rebuilds on such changes.
- **Checkpoints** are device-local caches: a serialized domain state plus a rolling digest of the
  admitted prefix (`H(n) = SHA-256(H(n-1) || operation digest)`). A checkpoint is used only if
  the current prefix at that position has the same digest. This is the explicit invalidation
  contract the guide asks for; nothing is inferred from a revision counter. The storage-backed
  cache additionally authenticates the record-path/digest index and admission evidence so an
  unchanged covered prefix need not be fetched, verified or decrypted on open.
- **Queries** return small, typed slices (an episode, a page of a shelf), so apps never copy a
  whole domain state across the FFI boundary per render. Change notifications carry the changed
  namespaces and a new revision.
- Targets, measured with a 100k-operation fixture on an M-series Mac and an iPhone:
  cold open from a checkpoint under 100 ms; a local write to updated state under 2 ms; a full
  rebuild of 100k operations under 1.5 s; memory proportional to state, not history.

Engine stage 2 (November 6, 2026): reducers, bounded queries, revisions and existing `Library`
APIs remain compatible. Native hosts can opt into `Engine<RecordSource>` for authenticated
verified-prefix checkpoints, lazy bounded history content and explicit admission invalidation.
Portable native verification uses cached public-key tables and scoped parallel workers; an
optional host batch-verification seam is ready for bindings. The 100k desktop timing gates now
pass, including a checkpoint open with 1% new operations. See [engine API](engine.md) and
[measured performance](performance.md). The engine retains lightweight history indexes plus
state and bounded content, rather than full record bytes/views; strictly state-only memory is
not claimed. iPhone measurements, platform crypto integration and real-app storage/lifecycle
validation remain proof gates before migration is complete. The version-1 `Library` checkpoint
path remains cryptographically eager; bindings must opt into the storage-backed API for fast opens.

### Domains

Rust reducers reach parity with what the apps actually use: `reading.books` (Shelf),
`listening.podcasts` (Taupe: follows, episodes, positions, queue, playlists, chapters,
transcripts, notes, playback history), `reading.saved` (Later: captures, state, metadata,
deletion, content, feeds, annotations, magazines), and `notes` (Scribenda). Each domain gets a
spec in `docs/domains/` and vectors in `conformance/0.2/`.

### The app SDK (Swift first, Kotlin mirrors it)

- `ColophonKit`: the generated bindings plus Swift idioms (async, `Sendable`, errors as typed
  outcomes) and key providers.
- `ColophonKitStorage`: folder, App Group and iCloud Drive stores with file coordination and
  change watching, plus the local checkpoint cache. Ported from the proven `FolderStore`.
- `ColophonSession`: the one lifecycle seam. Configuration (member label, kind, requested
  scopes, storage) in; observable phase out (`opening`, `creating`, `waitingForApproval`,
  `denied`, `unavailable(reason)`, `ready`); typed domain stores; writes through domain commands
  with the revision observed when the action began; a destination-bound ingress inbox for
  extensions. Never shows an inaccessible library as empty.
- Domain modules (`ColophonKitBooks`, `…Listening`, `…Reading`, `…Notes`): typed commands
  and `Codable` projections over the core's queries.
- `ColophonUI` (pairing, members, recovery kit) moves onto `ColophonSession`.

A new app then declares its namespaces and commands, picks a storage configuration, and builds
its product UI.

### Moving existing libraries (0.1 to 0.2)

People already have 0.1 libraries (Taupe testers included). On first launch of the new version:

1. The app holding the root reads the 0.1 library with the existing Swift stack, verifies it,
   and writes a new 0.2 library beside it, recording each imported operation's 0.1 ID, author
   label and digest as provenance. New signatures don't claim to authenticate old authors.
2. Sibling suite apps on the device re-enroll in the 0.2 library through the same-device path
   they use today; other members are listed as "needs to rejoin".
3. The 0.1 library becomes read-only history. A catch-up pass imports any 0.1 operations
   written later by not-yet-updated devices, so nothing written during rollout is lost.
4. Until migration completes, other apps show "Your library is being upgraded" rather than an
   empty library.

### Order of work and proof gates

1. Engine: reducers, incremental apply, checkpoints, benchmarks (this repo).
2. Bindings: UniFFI Swift and Kotlin, XCFramework (iOS, simulator, macOS, visionOS) and a
   host JVM test; Android AAR once an SDK and NDK are installed.
3. Domain inventory and specs, then Rust domain parity, each with vectors.
4. `ColophonKit`, storage and `ColophonSession`, proven by a sample app in this repo.
5. 0.1 importer with round-trip evidence on copies of real-shaped fixture libraries.
6. Apps, smallest first, on a Marginalia experiment branch: Shelf, then Scribenda, Later and
   Taupe. Each keeps its UI tests and gets an isolated simulator journey: create, join, allowed
   and denied scopes, restart, revoke, rejoin, and upgrade from a 0.1 library.
7. Android on the Kotlin SDK.
8. Merge plan in Marginalia's `QUESTIONS.md`; merge only after it's agreed.

### Bindings implementation status (November 6, 2026)

The `ffi` worktree implements `colophon-ffi`, the async `ColophonKit` facade and CryptoKit
providers, generated Kotlin/JNA bindings, and the shared consent/write/revoke/reopen journeys.
All five arm64 Apple slices build, including nightly-built visionOS, and the host JVM journey
passes. The `android` worktree turns that AAR script into a Gradle library
(`org.luff.colophon:colophon-android`) with both JNI ABIs, `ColophonSession`, Keystore keys,
and a private file store. See [Android session](android.md).
See [native bindings](native-bindings.md), [FFI measurements](performance.md#ffi), and the
[bindings handoff](handoff-ffi.md) for the exact build gates and sandbox limitations.

### App SDK implementation status (November 6, 2026)

The `ffi` worktree adds `ColophonKitStorage`, `ColophonSession`, revision-keyed typed query
stores, destination-bound extension ingress and the macOS/iOS `examples/ColophonSample`.
See [new app](new-app.md), [session contracts](session.md), and [session handoff](handoff-session.md).
The internal `SessionCore` protocol isolates the current binding API for the incoming engine.
Checkpoint byte storage is present; verified-prefix use waits for that engine and bindings.
These are SDK/sample and synthetic multi-session checks, not migration acceptance for the
four shipping apps. Their product journeys and real provider/hardware behavior remain gates.

### Migration implementation in this worktree

The root **ColophonSDK** package includes `ColophonMigration`, independent of the 0.1 modules.
Construct `LibraryMigration` with a host-owned `LegacyLibrarySource`, an explicit namespace
scope, a dedicated 0.2 migration session, private journal directory, persistently protected AES
key and scope-specific marker URL. Marginalia implements the protocol over its existing full
0.1 stack; `ColophonLegacyAdapter` in `reference/swift/` is for the reference implementation.

See [migration.md](migration.md) for the complete verification, evaluation, catch-up and
persistence contract, including migrating books from a mixed suite library and importing a later
scope into an explicitly identified shared destination. See [native bindings](native-bindings.md#package-identity-and-coexistence-with-01)
for the `packages/ColophonSDK` dependency path needed to coexist with `packages/Colophon`.

`run(batchSize:)` checkpoints complete source units and supports restart and appended catch-up.
Unresolved evidence keeps only this scope's marker active. Exact source bytes remain unchanged;
old grants are not recreated. Evidence is synchronized through the engine's grant-checked
queries. Full shipping-app codecs, automatic historical reconciliation and actual provider/UI
acceptance remain host integration work, as described in the migration handoff.
