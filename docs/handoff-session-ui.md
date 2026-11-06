# ColophonSessionUI handoff

Worktree: `session-ui`. Base: `250538e8534188a39b6f9c6ecb7fa4f12d11acad`.
Changes are intentionally uncommitted. No Git writes, Rust changes, 0.1 changes or
ColophonSession/ColophonMigration edits were made. The explicitly requested docs and sample
integration are narrow exceptions to the otherwise additive Package.swift/new UI/test scope.

## Done

- Added the `ColophonSessionUI` product/target, with **ColophonSession as its only package
  dependency**, plus a Swift Testing target. Implementation uses Apple system frameworks
  (SwiftUI, Foundation, Observation and UniformTypeIdentifiers); no legacy ColophonUI dependency.
- `LibraryGate` restores and refreshes on foreground entry, renders all nine session phases,
  and invokes its content builder only when ready. Welcome copy and artwork belong to the app.
  Failure reasons are visible; Retry uses the existing lifecycle retry API. Pairing codes are
  selectable and spoken character by character. Migration shows real host-supplied progress
  when present, otherwise indeterminate progress; it never fabricates progress.
- Shared settings: request-file import, explicit code comparison, narrowing of namespaces,
  read-only access, expiry and write budget; member kinds and grant summaries; confirmed
  revocation with the “past contributions stay attributed” explanation; the attributed ledger;
  connection location selection; recovery kit export/import screens; confirmed local leave and
  explicit-provider rejoin; a locally reviewable and explicitly shared support report.
- Approval/revocation models refresh and check captured context/revision and the reviewed value
  before calling the session. They do not silently retry stale authority decisions. The engine
  still enforces authority. There is no invented delegation for post-migration app members.
- `LibraryHostActions` describes host-owned connection/profile, identity and recovery operations.
  Missing handlers produce explicit unavailable states. Folder security scope lasts through the
  connection callback. Recovery text is transient and cleared on exit; asynchronous export
  cannot repopulate a dismissed screen; recovery errors never echo arbitrary provider text.
- Support JSON allowlists schema, system version, phase, failure category and three counts.
  No content, member labels, IDs, paths, pairing codes, arbitrary errors, keys, kit text or
  library records are exported. Nothing is uploaded by the library.
- Native grouped forms/navigation, semantic colors and type, scrolling and flexible text.
  No custom motion; decorative gate artwork is hidden at accessibility sizes and from VoiceOver.
  Controls have textual accessible labels and stable identifiers. All flow screens have
  `#Preview`s backed by an observable in-memory UI source. Gate previews cover every phase,
  light/dark welcome and accessibility text; detailed approval has an accessibility-size preview.
- Sample now uses the gate and one shared settings destination, replacing its duplicate phase,
  request/member and ledger UI. Its generator links SessionUI in both package and restricted
  standalone modes. Local rejoin uses the sample’s configured provider. `docs/new-app.md` has
  a short integration example and the host callback contracts.

## Read before implementing

Read `docs/session.md`, `docs/new-app.md`, all `swift/Sources/ColophonSession` files, and item 4
of the pilot’s “What prevents calling the pilot complete” section. Marginalia was read only via
committed `git show HEAD:<path>`: onboarding, gate, pairing, settings, approval, access/member,
recovery, add-device and support flows; suite onboarding design; root `DESIGN.md`.
`apps/apple/DESIGN.md` does not exist at that committed revision. The design references inform
native structure and app-supplied identity; no 0.1 root/passkey/keyring behavior was copied into 0.2.

## Accessibility identifiers

Identifiers are independent of displayed/localized labels. Dynamic suffixes use complete opaque
request/member IDs, namespace names, ledger sequences or host-supplied stable container IDs;
these are UI test hooks, never support-report fields. Hosts must provide unique container IDs.
System-owned file-picker, navigation-back and share-sheet controls keep their system identifiers.

| Screen | Identifiers |
| --- | --- |
| Gate welcome | `library.createLocal`, `library.join` |
| Gate state/progress | `library.opening`, `library.creating`, `library.migrating`, `library.migrationProgress`, `library.denied`, `library.unavailable`, `library.failed` |
| Pairing and lifecycle | `library.pairingCode`, `library.retryPairing`, `library.cancelPairing`, `library.retry`, `library.rejoin`, `library.recoverFromPairing` |
| Shared feedback/sheets | `library.actionError`, `library.sheet.close`, `library.bugReport` |
| Settings | `library.settings`, `library.request.import`, `library.request.<requestID>`, `library.member.<memberID>`, `library.ledger.open`, `library.addDevice`, `library.recovery.open`, `library.leaveFromSettings` |
| Approval | `library.approve.codeMatches`, `library.approve.namespace.<namespace>`, `library.approve.readOnly`, `library.approve.limitExpiry`, `library.approve.expiry`, `library.approve.limitBudget`, `library.approve.budget`, `library.approve` |
| Member and revocation | `library.member.grant`, `library.access.end`, `library.access.end.confirm`, `library.access.end.cancel` |
| Colophon | `library.ledger`, `library.ledger.entry.<sequence>` |
| Connection | `addDevice.folder`, `addDevice.iCloud.<choiceID>`, `addDevice.appGroup.<choiceID>`, `addDevice.unavailable`, `addDevice.next` |
| Recovery export | `library.kitExport`, `library.recoveryKit`, `library.kitShare`, `library.keptKit`, `library.kitDone` |
| Recovery import | `library.recoveryKitField`, `library.kitImport`, `library.kitImport.confirm`, `library.kitImport.cancel`, `library.kitImported` |
| Leave | `library.leave.confirm`, `library.leave.cancel` |
| Support | `support.report.preview`, `support.report.share`, `support.report.refresh` |
| Sample entry | `sample.librarySettings` |

The old welcome/recovery/pairing identifiers called out in the suite design remain. This is not
an assertion that every legacy 0.1 keyring/passkey identifier or UI-test route is compatible.

## Checks

- `COLOPHON_SOFTWARE_KEYS=1` via `bash scripts/test-swift.sh` (which runs
  `swift test --disable-sandbox` with worktree-local module caches): the reference suite reports
  exactly **13 known sandbox issues**, covering file coordination/read-write availability and
  backup exclusion. No failure in SessionUI or the other 0.2 suites.
- `bash scripts/test-swift.sh --filter ColophonSessionUITests`: **28 tests in 7 suites pass**.
  Snapshot-free checks cover grant narrowing, explicit code comparison, expiry/budget validation,
  stale context/revision/request/phase, authority refusal, duplicate action exclusion,
  cancellation, rejoin provider failures, connection callback success/failure and device-local App Group instructions, recovery secrecy,
  dismiss-during-export, all-phase support-report privacy and member grant presentation.
  A real Rust-backed memory-store integration pairs two sessions, approves read-only access,
  revokes it, verifies denial/ledger evidence, leaves and rejoins with the saved owner provider.
- `bash scripts/build-sample.sh --restricted`: **macOS arm64 and iOS Simulator arm64 builds pass**
  with the gate/settings wiring. The standard generated project is also regenerated from its
  source generator; no handwritten project edits.
- `git diff --check`: clean.
- Native artifact: APFS clone of the ignored XCFramework from `/Users/mikelxc/projects/colophon`.
  Both checkouts were at the same base commit; Rust/generated bindings there were unmodified,
  and generated Swift bindings matched. No Rust rebuild or extra Cargo target directory needed.
- Runtime visual checks are **not verified**. Launch Services failed to open the built macOS app
  (`-10827`); direct launch exited 134 without diagnostics. Xcode reported unavailable Simulator
  services, though generic Simulator compilation/linking succeeded. No screenshot or VoiceOver
  runtime acceptance is claimed. Previews compiled in the Swift package debug build.
- Final build/test logs are retained in `.build/session-ui-validation/`. Sample intermediate
  outputs, indexes and module caches were removed after validation; final app products and the
  Swift test cache remain for follow-up. No new Cargo build outputs were created.

## Intended commits

1. `feat(session-ui): add shared library gate and settings flows` — additive manifest entries,
   UI source, models, host contracts and previews.
2. `test(session-ui): cover authority reviews and lifecycle flows` — Swift Testing model/privacy
   suites and actual two-session memory-store integration.
3. `docs(sample): adopt shared session UI and document host integration` — sample/generator/
   generated project, new-app guide and this handoff.

These are suggested review boundaries only; nothing is staged or committed.

## Gaps and acceptance still needed

1. **Full connection/recovery parity is blocked by the existing session API.** Session location
   is immutable; there is no profile switch/relocation transaction, security-scoped bookmark
   persistence API, recovery kit format/export, or root-recovery command. The shared UI supplies
   typed host adapters and complete presentation/validation, not an invented recovery protocol.
   A consuming app must implement reviewed handlers, or SDK follow-up must provide these APIs.
   Without those handlers (including in the sample), location/recovery screens explain that the
   operation is unavailable. This does not close the pilot’s whole item-4 product gap by itself.
2. An App Group is device-local, not a cross-device transport. Container choices must come from
   actual host entitlements. Bookmark lifetime, authenticated recovery, durable profile/key
   persistence, safe relocation and process-wide session/store replacement belong to the host.
   Recovery handlers must validate the kit against the selected library, bind work to that
   profile, and not return success until durable recovery completes. No callback is auto-approval.
3. Numeric migration progress needs the migration coordinator. The base session exposes only
   `.migrating`. UI approval freshness is a preflight check; the session’s existing authority
   methods have no observed-revision parameter and do not offer cross-process CAS.
4. Local rejoin can reuse a saved identity. Revoked identities require separately persisted fresh
   keys and subsequent-launch configuration. The sample reuses its provider and does not perform
   that profile replacement. A `.noLibrary` phase does not distinguish “left” from “empty”; the
   gate offers rejoin when configured, while core creation checks still reject overwriting an
   existing library. Hosts should supply their profile/connection policy.
5. Verify actual iPhone/iPad/Mac layouts, both appearances, accessibility Dynamic Type, VoiceOver
   and keyboard traversal on an unrestricted host. Exercise Files security scope/bookmarks,
   iCloud hydration, App Group entitlements, Keychain/authentication failure/retry, cross-device
   pairing, non-owner approval refusal, recovery validation, and explicit share destinations.
   The new screens use English default operational copy; a localization catalog is future work.
