# The Apple session on Colophon 0.5

`ColophonSession` is the one object an Apple app holds over a Colophon 0.5 account. It is an `@Observable @MainActor`
facade: it publishes state and never does work on the main actor. Everything else (engine calls, key ceremonies, file I/O,
HTTP) runs in `SessionWorker`, an actor that serialises complete operations (a key prompt in the middle of a write cannot
let a refresh read an engine that is ahead of its files). The engine itself is `ColophonEngine` (ColophonKit): one
`AccountEngine` on its own `DispatchSerialQueue`, never on the main actor and never on the cooperative pool.

What the session decides: nothing about the account. Every verdict (phase, access, notices, deadlines, who may veto) is the
engine's; the session only chooses what to show and what to call next. The contract it is written against is
[bindings-05.md](bindings-05.md).

## The pieces

| Module | What it is |
| --- | --- |
| `ColophonFFI` / `ColophonKit` | The XCFramework (built locally, git-ignored) and the generated Swift (committed). Wrappers: `ColophonError` (the typed `AccountError`), `ColophonEngine`, `KeyCustody` (answers the engine's signing steps, PRF requests, unlock inputs and epoch agreements through `AsyncKeyProvider`), `SecretBytes` (secret memory the SDK owns and zeroes) and `withEntropy`. |
| `ColophonKitStorage` | `RecordMedium`: the synchronous record store the engine reads (`listing()` with versions in one batch, `read`, `readBlob`, `write` all-or-none, `changes()`). `FolderMedium` (private container, App Group, iCloud: each `write` is published through a journal in `.colophon.nosync/` (staged and synchronised files, a synchronised batch record as the commit point, then links and renames into place) under an exclusive `flock` inside file coordination, so a batch is all or none across a kill at any step and any process's later open completes or discards it; listings and reads take the same lock shared, so an app extension never lists half a batch; every path is opened component by component with `O_NOFOLLOW` from a directory handle; iCloud placeholders are `unavailable`, never absence) and `MemoryMedium` (tests, with fault injection). |
| `ColophonKeys` | Passkeys (`PasskeyProvider`, `SecurityKeyProvider`) with `authorityOrigins` at registration, the protocol descriptor (`KeyDescriptor.view`), `user.id` per spec §17.4 (`PasskeyProvider.userID(account:)`), Secure Enclave owner keys. |
| `ColophonSession` | The session, the gate's source, blobs, the in-flight exchange loop, the owner operations. |
| `ColophonSessionUI` | `LibraryGate` and its states, `NoticesView`. |
| `ColophonSavedKit`, `ColophonBooksKit`, `ColophonListeningKit`, `ColophonNotesKit` | Typed commands and queries over `session.perform` and `session.query`. Unchanged by 0.5. |
| `ColophonMigration` | The session-level steps of the Swift move (below). |

## Configuration

```swift
let session = ColophonSession(configuration: .init(
    memberLabel: "Later", namespaces: ["reading.saved"],
    location: .appGroup(identifier: "group.org.luff.later", libraryName: "Library"),
    privateContainer: privateURL,
    keys: KeychainKeys(service: "org.luff.later"),                 // this app's member key (Secure Enclave)
    ownerController: passkeyProvider,                              // the person's passkey: approve, veto, add a device
    recoveryKeys: nil,
    homes: [HomeConfiguration(endpoint: url, request: { account in try await service.memberRequest(for: account) })]))
```

* `keys` is the content member: it signs records and opens the member's epoch shares (an ECDH, silent for a Secure
  Enclave key). `ownerController` is a controller of the account (the person's passkey or an owner key). It is asked only for
  owner operations: creation, approving a member, revoking, adding a controller, veto, seed transfer.
* **Homes (spec §18).** A host MUST create every account with at least one home and MUST warn when there is none.
  `create()` therefore refuses with `SessionError.noHome` unless `homes` is non-empty or `createWithoutHome` is set. A home's
  signed member request names the account, which does not exist before creation, so `HomeConfiguration.request` is a closure
  the session calls with the new account ID; the home service answers with its request. The session appoints the home in a
  transition signed by the owner and records its activation at once.
* `additionalControllers` creates the account with more control keys (the §18 reference has several). `recoveryKeys` adds a
  `recover`-only controller with its own slot.
* `deviceSecrets` holds the 32-byte device key that seals saved state (Keychain by default; it is a cache key, not an identity).
* `now` is the clock the engine judges by; tests move it.

## Phases

`opening`, `noLibrary`, `creating`, `waitingForApproval(code:)`, `ready`, `refreshing`, `waitingForDownload`, `retry`,
`denied`, `unavailable(reason:)`, `updateRequired`, `failed`, `migrating` (kept for apps), and **`locked`** (new).
`updateRequired` is the engine's `newerFormat`: nothing is lost and nothing is changed. A revoked member is `denied`. A storage
error is `retry` or `waitingForDownload`, never an empty library.

## Creating, opening, joining

* `create()` runs the creation (the owner's PRF for its slot, the genesis, the first rekey), appoints the homes, records their
  activation, and approves this device's member. **A passkey owner is asked more than once at first run**: the core's creation
  leaves the session locked, so a second PRF ceremony unlocks the controller that sets the device up. That step is one function
  (`SessionWorker.unlockCreatedAccount`) and goes when the core exports an engine constructor over a created account.
* `restore()` lists the medium, discovers the account ID from its verified history (cached in the private journal), opens the
  member's engine from the sealed saved state when it can, and opens the member's epoch shares. A member that is not approved
  yet is `waitingForApproval(code:)`; its engine is loaded without keys so the exchange can bring the approval in.
* **A device that asks for access** publishes its signed request (`requests/<id>.json` in the library folder, or
  `exportRequest()` bytes for a file, AirDrop or a code) and shows a code derived from its key ID. An owner device lists
  `requests`, compares the code, and calls `approve(_:grant:)` (the owner key signs). `importRequest(_:)` takes a request that came
  out of band.
* **Adding a device by pairing and seed transfer** (a second controller): `addController(_:label:roles:immediate:)` names the new
  key; both screens run the ceremony (`AccountPairing`, six digits); the existing device calls `transferSeed(pairing:)`; the new
  device calls `acceptSeedTransfer(key:pairing:sealed:label:)`, which opens a controller engine from the seed and builds its own
  slot, so it unlocks alone afterwards.

## Refresh and the exchange with each home

`refresh()` lists the medium and gives the engine the listing with versions (`advance`, `refresh`, `record_due`). The folder
watcher, foreground entry and `flushExternalChanges()` call it.

`syncNow()` is one exchange per home (passes are never concurrent: callers queue). The loop is the engine's: `exchange_next`
returns a request, a "needs a call", waiting or done; the session performs the request through the home's `HomeTransport`
(`URLSessionHomeTransport` by default: no cookies, no cache, redirects refused so the engine reports them), builds a fresh
`Authorization: Colophon` call for exactly the request that needs one (signed by the member key), answers it, and writes the
stores of the report before the next step. `More` and every other fault are the engine's: faults are published as `homeFaults`.
A transport failure aborts the pass (`exchange_abort`) and the loop backs off (capped, jittered); a local change or
`requestSync()` cuts the wait short. Passes repeat until one moves nothing (at most four), because the engine plans the next
stage from what the home just said.

`record_due` runs on every refresh and on a 60-second schedule. The background loop polls every 20 s on success (spec §17.5:
at least every `recoveryDelay / 6`).

## Writes, reads, blobs

`perform(_:observed:)` is 0.4's call: refresh, require `observed == revision`, prepare, sign, finish, **write the stores all
or none**, then publish the new state. `.saved(operationID:)` means durable in this device's medium; homes receive it on the next
exchange. If the disk refuses the stores, the engine is ahead of the disk: it is discarded and reopened from what is really
stored, and the error is thrown. Reads are `query(namespace:name:arguments:)` and the typed stores of the domain kits.

The blob API keeps 0.4's names (`putBlob`, `blobAvailability`, `blobData`, `blobFile`, `blobStream`, `prefetchBlob`,
`downloadRequiredBlobs`, `setBlobReference`). Chunks are written before the manifest is published; a required blob arrives with
the exchange, an optional one on `prefetchBlob`. `collectBlobGarbage` does nothing: the core collects none.

No file work runs on the main actor or inside the session's gate. `putBlob(contentsOf:)` reads the file twice, 64 KiB at a
time, on a background executor (once to address it, once to encrypt and store each chunk); only `begin_blob` and the final
publish take the gate. `blobFile` is `@concurrent`: it pulls verified chunks one at a time (`blobStream` reads the next chunk
only when asked, so a slow consumer never makes it buffer) and writes them to a private file that is moved into place after
the digest checks. Both take an optional `progress` callback (`BlobProgress`: stage, bytes done, total), called off the main
actor. `importRequest(from:)` reads the file off the main actor too, at most 40 MiB. The session's worker runs on its own
serial queue, so the medium's synchronous record I/O never occupies the main actor or a cooperative-pool thread. The test
`MainActorTests` moves a 200 MiB blob in and out with a 5 ms main-actor timer running (worst lateness about 6 ms, footprint
growth about 35 MiB), and the blob executor stops on `dispatchPrecondition` if it is ever called on the main thread.

## What a person must see (spec §17.5, §18)

`session.notices` (`SessionNotices`):

* `pending`: each transition not yet shown, with its signers' labels and key IDs, first-seen seq, veto deadline, and
  `vetoable` (this device holds an owner key that may veto and the engine's deadline has not passed). `veto(_:)` is the one call:
  the owner signs, the veto is stored, and the session submits it to every home, retrying until each has receipted it or 300 s
  have passed.
* `unseenActivations`: every activation since this host last showed the history that no key on this device signed, with when
  each home receipted it. `acknowledgeNotices()` records that the person saw them (kept in the private journal).
* `noHome`: the warning of guide §5. `NoticeWords` holds the words the specification asks for.

## Lock

`lock()` overwrites the engine's keys and opened plaintext, drops it, and publishes `locked`; call it when the app enters the
background. `unlock()` opens it again (silent for a Secure Enclave member key); `LibraryGate` calls it when the scene becomes active. `restore()` and `refresh()` leave a locked session locked.

## The Swift move

`ColophonSession.swiftSuccession()`, `vetoSwiftSuccession()`, `acceptPredecessorEntry(_:)` and `swiftMoveNextStep()` (ColophonMigration)
are the session-level steps. The successor genesis, the copy with the app's own translator and the migration are driven with the
generated objects (`SwiftSuccessorCreation`, `SwiftSource`, `SwiftCopyPlan`) by the app, which has the record translators and
can write the freezing entry to its Swift library. Not built here: translators, and a passkey ceremony with two PRF salts
(the Swift move needs one assertion with the new salt first and the old second; `AsyncKeyProvider.assert` takes one).

## Errors

Every engine error is a `ColophonError` with `code`, `detail` and, for `refused`/`denied`, `reason`. Key failures are
`KeyProviderError` (cancelled, presence, unsupported, missing, hardware) and `KeyCustodyError`. A refused write leaves nothing
on disk.

## Secrets

Every secret the Swift side handles lives in a `SecretBytes`: memory the SDK allocates, writes once and overwrites with
zeros when the last reference goes. PRF outputs, ECDH results, epoch shares, the device-held sealed-state key, action entropy
and (debug and simulator builds only) software private scalars are taken into one at the moment the platform hands them over,
inside the platform's own `withUnsafeBytes` (CryptoKit's `SharedSecret`, the PRF `SymmetricKey`, the Keychain's `CFData`), and
reach an export only through `withUnsafeData`, which lends a `Data` over that memory for the one call (no Swift copy). The key
providers return `SecretBytes` (`AsyncKeyProvider.sharedSecret(peer:)`, `prf(salt:)`, `KeyAssertion.prf`).

What the SDK cannot reach, exactly: the copies a platform API keeps before it hands the value over (AuthenticationServices'
credential object, CryptoKit's own key and secret storage, which CryptoKit zeroes on release, the `CFData` a Keychain read
returns and the Keychain's own buffers), registers and stack slots during the copy-in, swapped pages, and the UniFFI lowering
copy (the Rust side overwrites that one through the zero-on-free allocator, which the XCFramework has on). The 0.4 exports
(`Library`, `StorageLibrary`) take `Data` in expression position; their secrets are single allocations zeroed on release.
`PrfAnswer`, `UnlockSecret`, `EpochAnswer`, `SecretBytes` and the `Host…` answers print as redacted. No secret is in an error,
a `description` or a `Codable` output.

`KeychainKeys` is a Secure Enclave identity in production. Its software backend exists only in debug and simulator builds
(`#if DEBUG || targetEnvironment(simulator)`), keeps the scalars in a fixed binary layout (never JSON) and decodes them per
operation (nothing cached).

## Public differences from the 0.4 session

An app written against 0.4's session reads the same where the meaning is unchanged. Everything else:

* `SessionConfiguration`: removed `relay`, `migrationMarker`, `migrationWriter`, `importExpires`, `importedFrom`. Added `homes`,
  `createWithoutHome`, `additionalControllers`, `deviceSecrets`, `recoveryDelay`, `now`. (`RelayConfiguration` is
  `HomeConfiguration`; `RelayToken` is unchanged and unused by the session.)
* `StorageLocation.memory` takes a `MemoryMedium`. `RecordStore`, `FolderRecordStore`, `MemoryRecordStore`, `BlobStore`,
  `RelayClient`, `RelaySync`, `RecordPath` are gone: `RecordMedium`, `FolderMedium`, `MemoryMedium`, `RecordPaths`.
  `CheckpointCache` takes a 64-hex account ID.
* `ColophonSession`: `members` is `[AccountMember]`; `ledger` (a property) is `ledger()` returning JSON; `requests` holds the new
  `AccessRequest` (`id`, `label`, `kind: AccountMemberKind`, `termsJSON`, `pairingCode` `XXXX-XXXX`, `record`, and `namespaces` /
  `access` read from its terms). `syncConflicts` is `homeFaults`. `syncState` is `HomeSyncState` (`RelaySyncState` is an alias).
  Removed: `performMigration`, `migrationBlob`, `restoreDevice(using:)`, `recoveryKeys()`. New: `notices`, `homes`, `lock()`,
  `unlock()`, `veto(_:)`, `acknowledgeNotices()`, `addController`, `transferSeed`, `acceptSeedTransfer`, `exportRequest()`,
  `importRequest(_ data:)`, `receipts(for:)`.
* `SessionPhase.locked`; `SessionError.noHome`, `.ownerRequired`; `SessionKeyFailure` is public.
* `IngressEnvelope.libraryID` is the 64-hex account ID.
* `AsyncKeyProvider.keyDescriptor()` is a requirement with a default (raw keys). `KeyDescriptor.view` is the 0.5 form.
* `LibrarySessionSource` gains `notices`, `veto`, `acknowledgeNotices`, `unlock` and loses `ledger`; `ColophonLedgerView` and
  `SupportReport.ledgerEntryCount` are removed.
* `ColophonMigration`: the 0.4 clean copy (`LibraryMigration`, `LegacyLibrarySource`, `MigrationState`) is removed (its engine, the
  0.4 session, is gone). The 0.4 `NativeEngine`/`Library` wrappers in ColophonKit remain for tools that read a 0.4 library.
