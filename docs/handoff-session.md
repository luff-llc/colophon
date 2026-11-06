# App SDK handoff — November 6, 2026

Implemented in `/Users/mikelxc/projects/colophon-wt/ffi`, branch `ffi`, based on committed
bindings `85f7a21`. Changes are **uncommitted**; no Git mutations, merges, pushes or publication
were attempted. No Rust, generated bindings, existing 0.1 Swift implementation/tests, or
Marginalia files were changed. Work stops with this handoff.

## Delivered

- Root-package products **ColophonKitStorage** and **ColophonSession**, explicitly Swift 6
  language mode, strict concurrency, Observation and Swift Testing; no new dependencies.
- Folder and memory record stores. Production folder writes use NSFileCoordinator, private
  staging, fsync and immutable atomic link publication; equal records are idempotent and
  conflicting bytes stop. NSFilePresenter supplies bounded change hints. Reads and writes
  classify iCloud placeholders/non-current downloads as unavailable, request hydration and
  never reinterpret provider errors as empty data. Path/symlink checks and record size bounds
  are enforced. Observed missing paths remain unavailable across restart.
- Private-container, App Group and iCloud policies. Container access is resolved for this
  process before reading. No fallback to an empty private library. Opaque, bounded,
  library-ID-keyed private checkpoint storage with backup exclusion; see engine gap below.
- One process-owned `@Observable @MainActor ColophonSession`: restoration barrier, all requested
  phases, create/pair/approve/revoke, leave/rejoin, expiry rechecks, external-change batching,
  global and per-namespace revisions, cached ledger/member/request presentation, and writes
  fenced by the context/revision observed when the action began. Fresh write preflight publishes
  access loss immediately. Retry cannot bypass a corrupt persisted selection.
- Background `SessionWorker` with a suspension-aware operation gate, and one internal
  **SessionCore** protocol. `BindingSessionCore` is the only adapter to today's ColophonKit
  engine surface. Storage, keys, FFI, folds and query decoding do not run on the main actor.
- `NamespaceStore<Query, Result>`: bounded cached query results, cold-load completion state,
  namespace-only invalidation, context/revision completion fencing, automatic registration
  disposal; a typed saved-link query and capture command demonstrate the pattern.
- `KeychainKeys`: explicit Secure Enclave or software backend, ThisDeviceOnly persistence,
  separately named member/recovery identities, no replacement keys on read/authentication
  failures. The sample explicitly uses software identities for simulator portability.
- `IngressInbox`: bounded App Group envelopes bound to both library and member, expiry and
  command bounds, nonblocking cross-process queue locking, foreground grant validation/signing,
  private durable publication journal, exact-byte retry/readback and acknowledgement afterward.
  Queued differs from saved. Durable receipts prevent duplicate signing after restart/lost ack,
  including a simulated provider failure after core commit; admitted evidence is checked before
  acknowledging that retry. Ambiguous publication remains queued for review.
- `examples/ColophonSample`: SwiftUI macOS/iOS app importing only ColophonSession. Creates a
  library, displays cached links and the colophon ledger, saves links, imports a real signed
  agent pairing request, shows code/kind/scope/access for review, approves and revokes members.
  A 91-line Python generator creates the normal local-SwiftPM Xcode project and an optional
  standalone build project for restricted hosts. `scripts/build-sample.sh` builds both platforms.
- Short onboarding in `docs/new-app.md`; full storage/session/security/performance boundaries
  in `docs/session.md`; owned status updates in migration, architecture and native-bindings docs.

## Exactly what is automatic

Default behavior restores/discovers, submits the current ungranted identity's signed request,
observes approval and retries previously signed publication. It **does not approve requests**.

The opt-in `deviceOnlyAppGroup(starterKeys:)` policy matches the existing Marginalia device-only
starter case. Only app-kind requesters at an App Group location qualify. The caller supplies
that device's actual starter root, and must stop supplying it on protection/move. Creation
uses a separate starter root; the app still signs/persists a real pairing request. Current
core root authority must approve exactly the requested scopes/access. A retired starter is
refused and normal pairing remains. Agents/servers never auto-enroll; labels and App Group
membership alone grant nothing. No starter secrets are copied/discovered by this SDK.

Without this explicit starter policy, the creating key is the core's root/device identity;
`memberKind` describes enrollment requests, not a change to the core's root semantics. New
library namespaces are deliberately configured separately from requested member namespaces.

## Checks actually run

Environment: Xcode **27.2 (27B52)**, Apple Swift **6.4.2** on Apple Silicon. Rust commands used
`PATH=/opt/homebrew/opt/rustup/bin:/Users/mikelxc/.cargo/bin:$PATH` and the worktree caches.
Final logs are retained under ignored `target/session-validation/`.

| Check | Result |
| --- | --- |
| `bash scripts/test-swift.sh --filter ColophonSessionTests` | All **16 tests in 6 suites** passed; actual Rust-backed sessions, software keys. |
| `bash scripts/test-swift.sh` | New 16-test target passes; existing ColophonKit functional tests pass (9 declarations, benchmark skipped). Existing 0.1 target reports **the same 13 baseline sandbox failures** among 368 declarations. Full command exits 1. |
| `cargo test` | All **19 Rust tests** passed, plus workspace/doc-test targets. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo fmt --all --check` | Passed. |
| `npm --prefix js test` | Passed key-security regressions and Node/Rust-WASM smoke parity. |
| `bash scripts/build-sample.sh --restricted` | **Both xcodebuild builds succeeded**, macOS arm64 and iOS Simulator arm64, unsigned Debug apps. |
| `bash -n scripts/build-sample.sh`, Python generator compilation/regeneration, `git diff --check` | Passed. |

`test-swift.sh` exports **COLOPHON_SOFTWARE_KEYS=1**, sets local module caches and executes
`swift test --disable-sandbox`. Bare SwiftPM/Xcode package resolution is blocked by the enclosing
sandbox's prohibition on nested `sandbox-exec`. The normal sample local-package build was
attempted and hit that restriction (initially also the unwritable user manifest cache).
The restricted generator compiles the **same SDK and sample sources** as separate Swift modules,
links the existing matching XCFramework slice, and avoids a package manifest subprocess.
It does not relax the enclosing filesystem sandbox or change production coordination behavior.

The successful sample commands, executed by the script for each platform, were:

```sh
python3 examples/ColophonSample/generate-project.py --standalone
export CFFIXED_USER_HOME="$PWD/.build/xcode-home"
xcodebuild -project .build/sample-project/ColophonSample.xcodeproj \
  -scheme ColophonSample -configuration Debug -destination 'generic/platform=macOS' \
  -derivedDataPath .build/sample CODE_SIGNING_ALLOWED=NO ARCHS=arm64 \
  OTHER_SWIFT_FLAGS=-disable-sandbox build
xcodebuild -project .build/sample-project/ColophonSample.xcodeproj \
  -scheme ColophonSample -configuration Debug -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .build/sample CODE_SIGNING_ALLOWED=NO ARCHS=arm64 \
  OTHER_SWIFT_FLAGS=-disable-sandbox build
```

No simulator or app launch was attempted. CoreSimulator service access is unavailable here;
that diagnostic did not prevent generic-destination compilation/linking. Xcode also emits the
expected “no AppIntents.framework dependency” metadata-extraction warning. No new Swift source
concurrency/compiler warnings were reported. App products remain in
`.build/sample/Build/Products/Debug/ColophonSample.app` and
`.build/sample/Build/Products/Debug-iphonesimulator/ColophonSample.app`.

The 13 unchanged 0.1 failures match `docs/handoff-ffi.md`:
`pendingAuthorityFileIsNotTheHead`, `signedBatchSurvivesFolderReconstructionSyncAndReplay`,
`placeholderArrivingAfterPreflightStillReportsPending`,
`placeholderReadThrowsPendingWithoutCoordinating`, `vectorsStillHold`, `keyringVectorsStillHold`,
`folderStoreCarriesALibrary`, `newIdentityIsLeftOutOfBackups`,
`existingIdentityIsMovedOutOfBackupsWithoutChanging`,
`readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld`,
`ubiquitousClaimTimeoutThrowsPending`, `timedOutWaitingWriteDoesNotLandLater`,
`writeAlreadyInsidePerformWaitsForItsResult`. These exercise inaccessible coordination/backup
services. Nothing was skipped or weakened to hide them. The existing five opt-in/hardware/fixture
cases and the FFI benchmark remain explicitly skipped in the normal run, separate from passes.

## Coverage and remaining gates

The 16 tests cover opening/noLibrary/creating/ready/unavailable/denied, a suspended signer while
the main actor remains responsive, pairing/revocation/fresh rejoin and expired grants, exact-scope
starter approval and no automatic agent approval, namespace cache warming/invalidation, stale
commands, external-change batching, private permissions/immutable conflicts/path rejection,
first-launch cloud placeholders, missing-known-record/corrupt-selection restoration, ingress
limits/destination/read-only-grant/expiry checks, offline publication/restart/lost-ack retry,
post-commit failure, and two independent sessions/keys/private homes on one real folder.

Remaining gates are explicit:

1. **Incoming engine:** `docs/engine.md` is not present at this base. The new verified-prefix
   engine/RecordSource/bindings are not merged. Replace BindingSessionCore and connect validated
   checkpoints/deltas; currently snapshots and per-namespace evidence comparisons still do
   whole-history work off-main. No incremental-engine or 100k-operation performance claim.
   Checkpoint cache bytes are implemented but deliberately not trusted/consumed by the session.
2. **Unrestricted Swift gate:** rerun the full software-key suite with working coordination and
   backup services. The two-session folder test uses a clearly internal uncoordinated test
   initializer plus explicit batch barriers. Production always coordinates. This proves SDK
   lifecycle/durable folder behavior, not actual OS presenter delivery or cross-process claims.
3. **Device/provider acceptance:** App Group entitlements/bootstrap, iCloud hydration and first
   install, real presenter delivery, Keychain/Secure Enclave/protected-data failures, hardware
   presence UI, and real Share/Safari/widget hosting remain unexecuted. No fake device claims.
4. **Product migration:** no shipping app was changed. The four app migrations, two-real-consumer
   extraction proof, 0.1 import, full domain parity and recovery UI remain separate work. Only
   reading.saved has a concrete typed projection convenience here; other domains use the generic
   pattern until their new reducer/query contracts arrive.
5. **Host policies:** arbitrary security-scoped library bookmarks, live profile selection,
   extension route publication/product review UI, starter-to-protected-root migration and
   recovery-kit export are outside this template. Configure persistent recovery keys (the sample
   does); if omitted, save the returned generated recovery provider independently. Rejoin after
   revocation needs a fresh persistent key provider also selected on subsequent launches.
6. **Storage semantics:** atomicity is per immutable file, not a multi-record cross-process
   transaction. Authority conflicts stop and require review; no silent rebasing. “Saved” is
   durable local readback, not remote iCloud upload confirmation. Unknown/unseen remote history
   cannot be inferred from a local directory. Record/query/inbox/receipt bounds are documented.

## Intended commits

1. `Add coordinated Colophon 0.2 Apple storage and private checkpoint cache`
   — ColophonKitStorage, immutable/private I/O, memory store, location policies and package wiring.
2. `Add observable sessions with replaceable core and scoped pairing lifecycle`
   — SessionCore adapter, background worker, durable journal, keys, phases/revisions, typed caches.
3. `Add destination-bound ingress with durable retry and session regression tests`
   — inbox/receipts, post-commit handling and all Swift Testing journeys.
4. `Add macOS and iOS Colophon sample and new-app guide`
   — sample/project generator/build script, concise onboarding, contracts and owned documentation.

Discarded this task's Python bytecode and sample intermediate/module/index caches after checks;
retained app products, root Swift build cache, existing XCFramework and validation logs. About
**18 GiB free** at the final check. All source edits remain available for review, uncommitted.
