# Swift package restructure handoff — November 6, 2026

Implemented in the `restructure` worktree, uncommitted. Git was read only; no staging, commits,
branch changes, merges or publication occurred. This addresses the SDK-side package coexistence
and scoped-migration blockers in items 1 and 2 of Marginalia's Shelf pilot report. It does not
claim that Marginalia's application integration or acceptance journeys have been completed.

## What moved

The root `Package.swift` is now named **ColophonSDK** and exports only:

- `ColophonFFI` (binary), `ColophonKit`, `ColophonKitStorage`;
- `ColophonSession`, `ColophonSessionUI`;
- `ColophonBooksKit`, `ColophonListeningKit`, `ColophonSavedKit`, `ColophonNotesKit`;
- `ColophonMigration`.

Its sources and tests remain under `swift/`. It has no package dependency on the reference and
no 0.1 target or product. `ColophonMigration` depends only on `ColophonSession`.

The following source directories moved from `swift/Sources/` to `reference/swift/Sources/`:
`ColophonCore`, `ColophonStore`, `ColophonAuthority`, `ColophonReplica`, `ColophonSaved`,
`ColophonBooks`, `ColophonListening`, `ColophonNotes`, `ColophonMCP`, and `colophon`.
`swift/Tests/ColophonTests` moved to `reference/swift/Tests/ColophonTests`.
`reference/swift/Package.swift` owns those unchanged module/product names and the 0.1 CLI.

All 193 moved legacy source/test files were compared against HEAD. They are byte-identical
except `ConformanceTests.swift`, whose repository-root traversal gained one parent component.
The 0.1 and keyring conformance vectors stay in root `conformance/`; no vector bytes changed.
The test logs confirm both vector suites reach those root paths. Actual filesystem moves were
used. Until someone stages the work, Git reports tracked deletions and untracked destination
files; rename detection can pair them when the eventual commit is prepared.

The real-library migration tests also moved into the nested package, at
`reference/swift/Tests/ColophonMigrationTests`. The old `SourceReader.swift` and source-fold
portion of `SourceEvaluation.swift` now belong to the new **ColophonLegacyAdapter** target.
Destination component bindings remain in root `ColophonMigration/ImportBindings.swift`.
The nested package depends locally on the root SDK for this optional adapter and its tests;
the root does not depend on the nested package.

## Migration API and behavior

`LibraryMigration` now accepts `source: any LegacyLibrarySource` and an explicit
`namespaces: Set<String>`. The source protocol returns an immutable `LegacyLibrarySnapshot`
with verified library/member/root identity, complete ordered scoped operations, exact archive
bytes, unresolved records, change detection, and evaluated legacy outcomes. The operation value
includes source ID, author/label, original kind/version/payload/date, exact signed-body SHA-256,
admission/detail, source path and semantic fingerprint. Its types contain no 0.1 modules.

The reference adapter still verifies authority, proves current source-root possession, verifies
signatures, decrypts operations and evaluates the actual old folds. Authenticated operations
outside the requested scope are excluded without requiring their domain codecs or keys.
Untrusted envelopes cannot escape review through an unverified namespace field. Shared
source authority/requests/blobs are conservatively retained. No source records are mutated.

The SDK scopes publication, remaining/imported counts, evidence queries and completion. A
books-only migration can finish against a mixed 0.1 library while unsupported Later records
remain untouched. Unknown-envelope evidence is published within the selected scope rather
than requiring an unrelated saved-reading grant. Unresolved and reconciliation receipt keys
include source library and namespace so separate scoped imports do not alias those keys.

Journals bind source ID, destination ID and a fixed sorted namespace set. Complete prefix
comparison detects order/admission/semantic changes; appended history resumes normally and
native destination edits retain their conditional-write protection. Adapter semantic changes
produce historical reconciliation evidence, not silent native rewrites. Original held reasons
remain in evidence. Missing archived records and scope/source changes fail closed.

A first run still defaults to requiring an empty destination. For a later scope in an existing
shared destination, provide its exact `destinationLibraryID` and a separate journal. The
shared destination must already declare the namespace and the migration writer must be its
root. Each independent scope needs its own marker/journal; serialize writers sharing a
destination. Completion of books does not declare the entire source library migrated.

The precise adapter contract, context schemas, marker rules, examples and limitations are in
[migration.md](migration.md). README, native-bindings, new-app, app-migration, architecture and
session docs describe the new layout/API. The earlier migration handoff has a supersession note.

## Consumer changes

1. Keep the app's own local `packages/Colophon` package. Check out or add this SDK as a submodule
   at **`packages/ColophonSDK`**, build its local XCFramework, and reference that local path in
   SwiftPM/Xcode/project generators. The dependency identities then become `colophon` and
   `colophonsdk`. Changing `Package(name:)` alone does not change identity; a direct dependency
   on the existing `.../colophon.git` URL still collides. Exact checkout/submodule and manifest
   instructions are in [native-bindings.md](native-bindings.md#package-identity-and-coexistence-with-01).
2. Add only root 0.2 products to migrated app targets. Do not add the nested reference or its
   adapter to a graph that already contains Marginalia's 0.1 module names.
3. Implement `LegacyLibrarySource` over Marginalia's actual complete 0.1 stack, including
   Later's codecs/service outcomes. Pass that source and, for Shelf, `["reading.books"]` to
   the migration constructor. The reference adapter is a working example and fixture adapter,
   not a replacement for the shipping app's complete source implementation.
4. Use separate fixed-scope migration state and marker URLs. Ordinary app sessions keep their
   own narrowly granted identities. Existing destination import requires an explicitly expected
   destination ID; no old grants or agents are automatically recreated.
5. Reference/CLI consumers use `reference/swift/Package.swift`, for example
   `swift run --package-path reference/swift colophon ...`. This is still the **0.1 CLI** and
   must not be used to manipulate 0.2 libraries.

## Checks

Logs are retained in `.build/restructure-validation/`.

| Check | Result |
| --- | --- |
| `cargo test` | 129 passed, 0 failed, 1 existing ignored; doc tests passed. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed. |
| `cargo fmt --check` | Passed. |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed; key security, smoke and Rust/WASM parity. Install used the worktree-local npm cache. |
| `bash scripts/test-swift.sh` | Root SDK passed: SessionUI 28, Session 18, migration contract 1, native binding 9, domains 10; existing opt-in FFI benchmark skipped. |
| `bash scripts/test-swift.sh --package-path reference/swift` | All 368 reference tests discovered; exactly the 13 known sandbox failures below. All 13 migration integration tests passed. Existing opt-in/hardware/vector-writing skips unchanged. |
| `bash scripts/build-sample.sh --restricted` | macOS and iOS Simulator builds both succeeded. |
| Coexistence consumer build | Passed importing all nine 0.1 library modules and all nine nonbinary 0.2 products in one consumer target. Resolved graph explicitly reports `colophon` and `colophonsdk`. |
| Source-move comparison, documentation file links, `git diff --check` | Passed. No conformance, Rust, JS or generated FFI source changes. |

The Swift helper sets `COLOPHON_SOFTWARE_KEYS=1`, local module caches and
`swift test --disable-sandbox`; it runs the requested suites without nested `sandbox-exec`.
It does not weaken tests or bypass the enclosing sandbox. The coexistence probe remains in
`.build/coexistence/`: a local `Colophon` package copied from the real reference modules with
no SDK dependency, a `ColophonSDK` path pointing to this root, and a consumer importing both.
Its build log and resolved dependency JSON are retained; its disposable build cache was removed.
This is package/module evidence, not a build of Marginalia's actual suite.

The four added real-library regressions cover mixed-library books-only migration and scoped
catch-up, later notes migration into a separate or explicit shared destination, scope/ID refusal,
invalid signatures with only the books namespace available, and adapter semantic changes with
idempotent reconciliation. Existing interruption, native-edit, blob/evidence, source-root,
source-integrity and historical-prefix tests still pass.

The accepted reference failures are unchanged:

- `pendingAuthorityFileIsNotTheHead`
- `signedBatchSurvivesFolderReconstructionSyncAndReplay`
- `placeholderArrivingAfterPreflightStillReportsPending`
- `placeholderReadThrowsPendingWithoutCoordinating`
- `newIdentityIsLeftOutOfBackups`
- `existingIdentityIsMovedOutOfBackupsWithoutChanging`
- `keyringVectorsStillHold`
- `vectorsStillHold`
- `folderStoreCarriesALibrary`
- `writeAlreadyInsidePerformWaitsForItsResult`
- `readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld`
- `timedOutWaitingWriteDoesNotLandLater`
- `ubiquitousClaimTimeoutThrowsPending`

These are sandbox file-coordination/backup-service failures and coordination-claim timeouts.
No new skips or assertion changes were made to that suite. Run it unrestricted before merging.

## Artifacts and disk

The supplied five-slice XCFramework was initially unpacked directly under `sdk/apple/`.
Its existing Info.plist and slice folders were moved into the manifest's expected ignored
`sdk/apple/ColophonFFI.xcframework/` directory. No native ABI change or binary rebuild was needed.
macOS and iOS Simulator were exercised; visionOS slices were not independently built or tested.

`cargo clean` removed 1.8 GiB of disposable outputs. Coexistence build products and sample
intermediates were also removed. The XCFramework, JS distribution, sample app products, Swift
caches and validation logs remain. About 34 GiB was free after cleanup. Cargo tests will rebuild
on the next run.

## Gaps and intended commit

- Marginalia still needs its app-owned adapter, dependency/project-generator changes, and its
  actual all-app builds and migration/UI acceptance. This worktree did not modify Marginalia.
- The reference does not acquire Later's missing full codecs. Unimplemented service, source
  closure, blob custody and component-binding cases remain unresolved until integrated/tested.
- Pre-restructure journals lack namespace scope and are deliberately not resumed by this API.
  Preserve their original code, journal and evidence for reconciliation; do not delete a journal
  and replay into an already-populated destination as a workaround.
- Earlier-prefix changes remain reviewable reconciliation evidence, not automatic correction.
  Multi-scope app barriers and serialization across independent migration sessions are host
  responsibilities. Shared authority/blob availability can still block a scoped snapshot.
- Unrestricted reference tests, real provider/hardware behavior, large-library performance and
  shipping app acceptance remain required beyond these synthetic fixtures and compile checks.

Intended commit message:

`refactor(swift): split ColophonSDK from the 0.1 reference and scope legacy migration`

No commit was created. Work stopped after writing this handoff as requested.
