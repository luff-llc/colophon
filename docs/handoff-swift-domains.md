# Swift domain modules handoff

Completed 2026-11-06 in the `swift-domains` worktree. Changes are **uncommitted**; no Git
mutation was attempted. No production library or consuming Apple app was changed.

## Done

Four root-package products/targets depend **only on ColophonSession**:

| Product | Namespace | Typed commands | Documented named queries |
| --- | --- | ---: | ---: |
| ColophonBooksKit | reading.books | 10 | 8 |
| ColophonListeningKit | listening.podcasts | 30 | 17 |
| ColophonSavedKit | reading.saved | 24 | 19 |
| ColophonNotesKit | notes | 13 | 10 |

There are 77 command structs and 59 query structs total: the 54 documented named queries plus
five diagnostic query surfaces (`invalid` in each module and notes `conflicts`). Compatibility
whole-state queries and old notes command aliases are not exposed by these products.

- Commands are Codable, Hashable, Sendable values with `domainCommand()`. Payload types come
  from the current Rust schemas, including nested descriptors and discriminated variants.
  `DomainNullable` preserves omitted/null/value semantics; unknown fields survive round trips
  through `additionalFields`. Core validation remains authoritative for bounds, identities,
  referenced heads, graphs, and authenticated roles. Dates/revisions/IDs retain their exact
  string wire representations.
- Query arguments are typed, Codable, Hashable and Sendable. Result rows/details are plain
  Codable, Equatable, Sendable values. Dynamic JSON is retained for extension/evidence fields.
  Result models match actual core outputs, including saved-reading `{text,truncated}` previews,
  nullable positions, source-version/image/metadata variants, and contribution page/detail forms.
- BooksStore, ListeningStore, SavedStore and NotesStore are small `@Observable @MainActor`
  wrappers over NamespaceStore. Named reads and result decoding occur off-main. Render paths
  use cached values; they never decode/fold whole state. Caches are bounded (64 queries by
  default), scoped by arguments and namespace revision, and retained across unrelated writes.
  Context/readiness changes invalidate them. `close()` fences in-flight completions and prevents
  subsequent reload. Capacity eviction is separate from revision invalidation.
- Paging helpers preserve filters, continue explicit cursors, and restart explicitly after
  staleCursor. Missing/deleted/unavailable/invalid outcomes do not become empty pages.
- Swift Testing exercises every command against Rust-backed ColophonSession instances with
  in-memory stores; compares typed query results with all four signed conformance fixtures;
  checks nonempty evidence queries, actual enrolled-agent service flows, independent heads,
  null patches, paging, stale cursors, namespace-only invalidation, cold-load completion,
  bounded cache eviction, suspended-load fencing and read-only dispatch.
- docs/new-app.md has five-line usage for each module and common cache/paging/patch guidance.
  docs/session.md and docs/native-bindings.md describe the additive query boundary.

Generation is reproducible:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:/Users/mikelxc/.cargo/bin:$PATH"
cargo run -q -p colophon-core --example swift_schema > /tmp/schemas.json
python3 scripts/generate-swift-domains.py /tmp/schemas.json
```

The generator contains the explicit result contracts as well as the input-schema mapping.
Generated Swift sources are checked-in source candidates; no generation runs in app builds.

## Necessary integration changes

**Read-only query binding.** Added `NativeLibrary.query` returning JsonOutcome and regenerated
Swift/header/Kotlin bindings together. Library.query and the session/core/worker query methods
forward this read without preparing/signing a command. This is necessary because podcast
`episode`/`queue` and saved `position` are also command names; `getEpisode` is a legacy preview
shape, not the documented episode detail. No existing FFI method was removed or changed.

**Authenticated reducer context.** Real-core integration tests exposed a missing engine link:
State/Namespace previously called reducers without the signer's authenticated member kind.
Valid owner copy-loan updates, proposal reviews and podcast service requests consequently failed
closed. Append, full replay, and checkpoint-suffix replay now obtain kind from verified authority
membership and call the existing context-aware reducers. Server/person-origin operations remain
refused where app/device authority is required; an engine regression covers this and an enrolled
agent response across replay/checkpoint restoration.

The local engine checkpoint format is now **version 2**. Version-1 caches are rejected/replayed;
otherwise they could retain the old incomplete role-sensitive projection. This is a disposable
cache-format change, not a protocol-record rewrite. Updated only the affected expectations in
`conformance/0.2/notes.json` and `conformance/0.2/reading.books/expected.json`; signed records did
not change. Owner proposal reviews now produce kept proposals, and owner loans take effect.

**Coordination with `migration`.** Session edits are limited to the additive query bridge,
shared typed-domain values, and the NamespaceStore loader/completion fence. No migrating phase,
import API, migration journal or importer was added/edited. When combining branches, preserve
both workers' SessionCore/SessionWorker/ColophonSession additions and regenerate the native
bindings/XCFramework from the combined FFI. Check for independently introduced query-method names.
The default SessionCore query implementation leaves existing internal test adapters source-compatible.

## Checks

Toolchain: Apple Swift 6.4.2, Swift 6 language mode; rustc 1.91.1; Node 24.12.0.

| Check | Result |
| --- | --- |
| `SKIP_VISIONOS=1 bash scripts/build-apple.sh` | Passed. Rebuilt current macOS arm64, iOS arm64 and iOS simulator arm64 XCFramework; **visionOS deliberately omitted**. |
| Final focused Swift domain suite via `bash scripts/test-swift.sh --filter 'DomainConformanceTests\|DomainCommandTests\|ListeningCommandTests\|SavedCommandTests\|DomainStoreTests'` | **10 tests / 5 suites passed**, including four conformance parameter cases, all 77 commands and all documented named queries. |
| `bash scripts/test-swift.sh` (sets `COLOPHON_SOFTWARE_KEYS=1`) | 0.2 ColophonSessionTests, ColophonKitTests and domain tests passed. Full command exits 1 due to the same **13 existing 0.1 sandbox failures** documented in handoff-session/handoff-ffi. |
| `cargo test --workspace` | **100 passed, 1 existing ignored test**, plus passing doc tests. Includes role-context replay/checkpoint regression. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed. |
| `cargo fmt --all -- --check` | Passed, including final check after cleanup. |
| `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test` | Passed after building WASM/TypeScript. Security regressions, Node smoke and Rust/WASM fixture parity passed. |
| Generator reproduction | No Swift source differences after regeneration. |
| Diff whitespace | Handwritten/generated-domain source clean; UniFFI output retains its generator's trailing whitespace. |

Logs are outside the repository at `/tmp/colophon-domain-final.log`,
`/tmp/colophon-swift-full.log`, `/tmp/colophon-cargo-test.log`, `/tmp/colophon-clippy.log`,
`/tmp/colophon-fmt.log`, `/tmp/colophon-js-build.log`, `/tmp/colophon-js-test.log`, and
`/tmp/colophon-apple-build.log`.

The unchanged legacy failures are:

- pendingAuthorityFileIsNotTheHead; signedBatchSurvivesFolderReconstructionSyncAndReplay.
- placeholderArrivingAfterPreflightStillReportsPending; placeholderReadThrowsPendingWithoutCoordinating.
- vectorsStillHold; keyringVectorsStillHold; folderStoreCarriesALibrary.
- newIdentityIsLeftOutOfBackups; existingIdentityIsMovedOutOfBackupsWithoutChanging.
- readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld; ubiquitousClaimTimeoutThrowsPending;
  timedOutWaitingWriteDoesNotLandLater; writeAlreadyInsidePerformWaitsForItsResult.

These require macOS coordination/backup services unavailable in the enclosing sandbox. No tests
or production paths were weakened/skipped to disguise them. The existing opt-in/hardware tests
remain unchanged. `scripts/test-swift.sh` disables only SwiftPM's nested sandbox and uses local
module caches; it cannot enable blocked OS services. The last added cache-fencing test passed
in both its focused run and the final 10-test domain run.

## Intended commits

1. **Pass authenticated member roles through domain replay and invalidate old checkpoints**
   — core State/Namespace/Library routing, engine regression, two expectation updates, engine docs.
2. **Expose read-only named queries through native bindings and ColophonSession**
   — additive FFI method, regenerated bindings, Library/session worker bridge, NamespaceStore
   async loader and close/invalidation completion fence, session/native docs.
3. **Add typed 0.2 Swift domain kits and real-core integration tests**
   — Package.swift, DomainValues, four new module directories, schema exporter/generator,
   ColophonDomainKitTests.
4. **Document typed domain onboarding and integration handoff**
   — new-app examples and this handoff.

Keep the native binary ignored. Rebuild from merged sources before running consumers.

## Gaps and limits

- The full Swift suite still needs an unrestricted macOS run with working coordination and
  backup services. All new domain tests and existing 0.2 targets pass here.
- The reduced XCFramework is not a visionOS release artifact. Build all slices before shipping
  a visionOS consumer. No simulator/device UI acceptance or consuming-app migration was performed.
- Session snapshot/write/refresh handling still gathers full views off-main. Named domain loads
  avoid that path, and cached rendering does no whole-library work, but this is not a claim that
  the complete session pipeline meets 100k-operation app latency targets. No new Instruments
  measurement was performed; existing core performance/regression tests passed.
- Podcast `history(mode: importedSession)` reports unavailable until the host import-evidence
  adapter exists. Host blob availability, citation/anchor byte verification, transcript search,
  player/scroll state, and migration orchestration remain outside these pure domain modules.
- SDK encoders do not duplicate every core validation rule. Invalid bounds/references are
  rejected by the real core; callers must handle domain outcomes and session/access failures.

After checks, Cargo's targeted cleanup removed **3.7 GiB** of redundant compilation output
(including shared host intermediates). Retained the **143 MiB XCFramework**, Swift package build
cache and JS distribution. Approximately **20 GiB free** at the final disk check. Cargo will
recompile cleaned intermediates on the next run. Work stopped after writing this handoff.

## Merge into `integrate2` — 2026-11-06

Resolved `library.rs` and `docs/engine.md` while retaining main's verified-prefix engine,
parallel verification/reduction and lazy host-backed history. Authenticated member kinds now
accompany bounded storage-engine reduction batches as well as compatibility Library replay.
Named queries continue to read reducer state without fetching history. Regressions cover
role-sensitive append/full replay/checkpoint suffixes, parallel device-role reduction,
zero-read queries across all four domains, and rejection of generation-2 caches.

This supersedes the checkpoint-version statement above: keep main's version-1 Library and
version-2 `COLOENG2` containers; advance their shared authenticated `reducer_schema` to **3**.
Old role-incomplete projections fall back to replay without changing the wire format.
The additive `NativeLibrary.query` and all four Swift domain modules are preserved.
Swift/header/Kotlin bindings were regenerated and match the incoming generated sources.

Verification on the merged working tree:

- `cargo test --workspace`: **117 passed, 1 existing ignored**, doc tests passed.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`: passed.
- `npm --prefix js ci`, `npm --prefix js run build`, `npm --prefix js test`: passed.
- `SKIP_VISIONOS=1 bash scripts/build-apple.sh`: passed; rebuilt macOS arm64, iOS arm64
  and iOS simulator arm64. VisionOS was intentionally omitted.
- `COLOPHON_SOFTWARE_KEYS=1 bash scripts/test-swift.sh` (runs `swift test --disable-sandbox`):
  all 35 session/native-kit/domain tests passed; the reference suite had exactly the same
  13 sandbox-only failures listed above, with no additional failures.

Logs: `/tmp/colophon-integrate2-{cargo-test,clippy,fmt,npm-ci,js-build,js-test,apple,swift,clean}.log`.
After validation, `cargo clean` removed 3.5 GiB of disposable outputs. The 154 MiB XCFramework,
Swift build cache and JS distribution remain; approximately 14 GiB is free.
No Git-writing commands ran. Conflict markers are removed from the working files; the merge
index intentionally still records the two unmerged paths until the user stages the resolutions.
