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
* **Homes (spec §18).** A host creates every account with at least one home, unless the account syncs only through a
  shared folder, in which case it may have none. One home is the supported configuration in 0.5; more than one is
  experimental (spec §13.1). `create()` refuses with `SessionError.noHome` unless `homes` is non-empty or
  `createWithoutHome` is set.
* **Folder-only libraries.** `createWithoutHome` is the supported path for a library that syncs only through a shared
  folder; it keeps working until the person wants the library on another platform, and a hosted home can be appointed
  then. A host that creates an account this way MUST warn the person before it does (spec §6.4: with no home there is no
  witness of time or order; `notices.noHome` repeats it afterwards) and SHOULD offer a second unit when a home is later
  appointed. It SHOULD NOT add a separate recovery unit (a controller with `recover` but not `control`: `recoveryKeys`, or an
  `additionalControllers` entry with `recover` and not `control`) without also appointing a home; if it does, it MUST give the
  spec §6.4 warning (no theft safety: nothing delays a recovery key). `create()` accepts `recoveryKeys` with
  `createWithoutHome`, which is allowed. The owner controller `create()` makes holds `recover` beside `control`; that is not a
  separate recovery unit. The session gives these warnings only after creation (the known gap below), so the app warns
  before it calls `create()`. A verifier judges a call on an account with no home
  `unavailable` (spec §12.3 step 4), so `signCall` and grants to services need a home.
* A home's signed member request names the account, which does not exist before creation, so `HomeConfiguration.request`
  is a closure the session calls with the new account ID; the home service answers with its request. The session appoints the home in a
  transition signed by the owner and records its activation at once.
* `additionalControllers` creates the account with more control keys (the §18 reference has several). `recoveryKeys` adds a
  `recover`-only controller with its own slot.
* `deviceSecrets` holds the 32-byte device key that seals saved state (Keychain by default; it is a cache key, not an identity).
* `now` is the clock the engine judges by; tests move it.

## Phases

`opening`, `noLibrary`, `creating`, `waitingForApproval`, `ready`, `refreshing`, `waitingForDownload`, `retry`,
`denied`, `unavailable(reason:)`, `updateRequired`, `stopped(seq:layout:)`, `failed`, `migrating` (kept for apps), and **`locked`** (new).
`updateRequired` is the engine's `newerFormat`: nothing is lost and nothing is changed. A revoked member is `denied`. A storage
error is `retry` or `waitingForDownload`, never an empty library.

**A namespace this member was never granted.** A session is `denied` only when its own member has lost access it was
granted, never because the library declares namespaces this member was never granted (`libraryNamespaces` wider than
`namespaces`). For each namespace in `libraryNamespaces` the session asks the engine's `access`: no denial, the namespace
is readable; `notReadable` or `unavailable`, the phase is `unavailable(reason)`; `notGranted` for a namespace that the
member's verified grant (`me().member.grant.namespaces`) does not name, while the member is not provisional, is not this
member's namespace and is skipped (neither denied nor published); anything else (`revoked`, `expired`, `budgetSpent`,
`notGranted` while provisional or on a granted namespace) is `denied`. Revisions are published only for the library
namespaces whose `access` has no denial. Tests: `LibraryNamespacesTests` and `GrantedNamespacesTests` (Swift), `LibraryNamespacesTest` and
`GrantedNamespacesTest` (Kotlin), `library-namespaces.test.ts` and `granted-namespaces.test.ts` (JS).

### A stopped account, a home's refusals, waiting for approval (freeze package)

**Stopped.** When a layout raise (spec §20) becomes final in the history this device verified, or it judges an authority
entry `newerFormat`, the engine's status carries `stopped` and the session's phase is **stopped** (Swift
`.stopped(seq:layout:)`, Kotlin `SessionPhase.Stopped(seq, layout)`, JS `{ kind: 'stopped', seq, layout? }`): this app must
be updated to continue with this account. It comes only from the verified status, never from a home's answer or a
refusal. What the device holds stays readable (`hasUsableContent` is true, as of the stop); every write is refused by the
core (`newerFormat`) and the phase stays, with no fault shown; no exchange runs (`syncState` is disabled, the loop waits
for an event with no timer or backoff, and no home is contacted); it persists across relaunch; lock, unlock and sign-out
work. The gate shows the content with a status line, or the screen `library.stopped` ("Update to continue"), with no retry.
While stopped the session does not refresh content: what it held when the stop was verified stays readable, and records
that arrive later are not admitted (the engine ignores them as well). The session persists the stop in its sealed saved
state the moment it sees it, so a relaunch whose store has lost the raise is still stopped (see `docs/bindings-05.md`).
The existing `updateRequired` remains for an account the engine cannot open at all.

**A home's refusals.** A home's error answer is read for its `result` only, validated against the §1 grammar (a named
result, or `refused:` and a reason of a lower-case letter then letters and digits, at most 48 characters) from a JSON body
of at most 64 KiB; no other byte of the body is kept (`HomeRefusal`, JS `homeRefusal`). A `refused:<name>` the session does
not know, the reserved `refused:overQuota`, `refused:noEntitlement`, `refused:closed` and `refused:notProvisioned`
included, is the existing home issue `remoteCallRefused`, now with the name as given and the home's `Retry-After`: it
refuses only that request (the pass goes on), except a refusal of this device's signed call (403), which ends the pass as
before; a 403 that names a refusal for a request that carried no call is not retried with a call. It is never a state of
the account. A `Retry-After` (whole seconds, 1 to 86,400) is honoured, as session policy (0.5 specifies it only for 429 and a home that
cannot sign a due head): the home is not
contacted again before then, and its refusal stays shown meanwhile. `503 {"result":"unavailable"}`, which a stopped home
answers (§13.6), is the issue `homeUnavailable`: the sync state is offline with "The home is not available right now"
(`HomeWords`), the loop backs off, and the device is not stopped. The retry signal of a refusal body is deferred (§16 of
the design), so `Retry-After` is the only signal honoured.

**Waiting for approval.** 0.5 keeps `refused:revoked` for a call by a member no grant names (`refused:notGranted` is
reserved). A device that asked to join and holds no grant for itself (its standing is unknown) shows a home's or its own
check's `refused:revoked` as the issue `waitingForApproval`, not as revoked; its phase is `waitingForApproval`. A device
that holds its own verified revocation is `denied`, as before.

## Creating, opening, joining

* `create()` runs the creation (the owner's PRF for its slot, the genesis, the first rekey), appoints every configured home in
  one transition and records its activation, and approves this device's member, all with the creation's own engine
  (`ColophonEngine.openCreated`, over `AccountCreation.open_engine`): it is unlocked as the creation left it, so **a passkey
  owner is asked once at first run**. `SessionConfiguration.history` and `headQuorum` set `policy.history` and
  `policy.headQuorum` of a new account.
* `restore()` lists the medium, discovers the account ID from its verified history (cached in the private journal), opens the
  member's engine from the sealed saved state when it can, and opens the member's epoch shares. A member that is not approved
  yet is `waitingForApproval` (it carries no code); its engine is loaded without keys so the exchange can bring the approval in.
* **A device that asks for access** publishes its signed request (`requests/<id>.json` in the library folder) and shows it
  as a QR code (`exportRequest()`, the canonical request envelope). Approving it spends a **confirmed pairing** for exactly its
  key (spec §7.3, §9.1); no code is derived from a key ID and a listed request cannot be approved by itself. Two ways:
  * **Scan:** the owner device's camera reads the request from the joining device's screen; `scanRequest(_:)` returns the
    request and its confirmed pairing (nothing is stored), and `approve(_:pairing:grant:)` spends it.
  * **Six-digit code:** the joining device calls `beginJoinPairing()` and sends `commitment()` (with its request); the owner
    device's person starts the ceremony with `beginApproval(commitment:)` and sends back its `nonce`; the joining device's
    `receiveNonce(na:)` gives the reveal; `approvalCode(pairing:e:nb:)` gives the owner's digits; both screens show the same
    six digits, the person confirms (`pairing.confirm()`) and the owner calls `approve(_:pairing:grant:)`. Different digits:
    `rejectPairing(_:)` on both devices. `abandonApproval(_:)` ends a ceremony the person cancelled.
  * **One ceremony at a time, five failures an hour.** The core keeps the owner device's ledger: while one ceremony is live
    (not confirmed, rejected or abandoned, and younger than ten minutes) another start is refused (`pairing:busy`), and every
    start counts toward five an hour until it confirms (`pairing:limit`). A ceremony starts only when the person starts it;
    traffic alone burns nothing. The session keeps the ledger sealed under the device key (`pairing-ledger.bin`, its
    generation in `pairing-ledger.generation`) and persists it before the nonce exists: if it cannot, no nonce is produced. A
    missing, edited or older ledger opens as a spent budget. Every session and process over the same private container takes one lock
    (`flock` on `pairing-ledger.lock`) and reloads the ledger under it, so two instances never hold two live ceremonies.
    A clock outside 1970 to 9999 starts nothing (`pairing:clock`); a forward clock mistake clears an hour after the
    clock is corrected. **Residual limit:** a host or backup that restores the whole
    private container (the ledger and its recorded generation together) restores the budget; the device key in the Keychain
    is not a counter, so this cannot be detected.
* **Adding a device by pairing and seed transfer** (a second controller): `addController(_:label:roles:immediate:)` names the new
  key; both screens run the ceremony (`AccountPairing`, six digits); the existing device calls `transferSeed(pairing:)`; the new
  device calls `acceptSeedTransfer(key:pairing:sealed:label:)`, which opens a controller engine from the seed and builds its own
  slot, so it unlocks alone afterwards.
* **Appointing homes later, with a new controller** (`appointHomes(_:adding:)`): an account created with `createWithoutHome`
  (its one controller the device's owner key) gets its homes, and optionally a second controller such as a passkey, in **one**
  transition (spec §8.7): `try await session.appointHomes([home], adding: (key: passkey, label: "Passkey", roles: [.control, .recover]))`.
  For each home not yet current it calls `HomeConfiguration.request(account)` and appoints that request with its terms; the
  owner signs under the control rule, and the added key signs its own possession proof (one assertion for a passkey). With no
  home in the state before it the transition is due at `issued` and recorded at once, final (§13.1); the added controller then
  builds its own slot (a PRF slot for a passkey), so it unlocks alone, and the running session starts its exchange and sync
  loop with the homes at once (no relaunch; pass the same homes in `SessionConfiguration.homes` from the next launch). The
  answer is `HomesAppointment.done`.
  * **With a home already current** the transition has a delay: the call submits it like `proposeTransition` and answers
    `.pending(transitions:)` with the digests of every pending transition of this owner that carries what was asked
    (sorted; each is submitted). Call it again with the same arguments after they activate to build the slot.
  * **Idempotent, and bound to what was asked.** What is done is read from the account, never from local memory: a call
    after a crash between any two steps, or after `.pending`, finishes the rest and never signs any part twice. A home is
    done when a current home, or an appointment in a pending transition of this owner, names its configured endpoint,
    whatever member the home answers with later; its `request` is called only while none does, and a request that names
    another account or does not name the configured endpoint is refused before anything is signed. The controller is done
    when the keyring, or a pending transition of this owner, holds exactly the requested one: the same key with another
    label or roles is refused, not skipped. The slot is done when a slot has exactly the new key as its holder (a combined
    slot does not count). `insecureHome` for a home that is not `https`; `invalidCommand` for a home that is not current
    and has no `request`, for a request bound elsewhere, and for a key already present with another label or roles.
  * The controller JSON in the change comes from the export `accountControllerJson(controller:)`, the same JSON
    `beginAddController` uses. The Kotlin session has the same call, taking an `AdditionalController`
    (`appointHomes(homes, AdditionalController(passkey, "Passkey", listOf(CONTROL, RECOVER)))`) and answering
    `HomesAppointment.Done` or `HomesAppointment.Pending(transitions)`. Not in the JS session yet.

## Refresh and the exchange with each home

`refresh()` lists the medium and gives the engine the listing with versions (`advance`, `refresh`, `record_due`). The folder
watcher, foreground entry and `flushExternalChanges()` call it.

`syncNow()` is one exchange per home (passes are never concurrent: callers queue). The loop is the engine's: `exchange_next`
returns a request, a "needs a call", waiting or done; the session performs the request through the home's `HomeTransport`
(`URLSessionHomeTransport` by default: no cookies, no cache, redirects refused so the engine reports them), answers it, and
writes the stores of the report before the next step. For a "needs a call" the engine has already built the request: the
session asks it for the call (`exchange_begin_call`: audience the home's base, purpose by the method, `args` the method, the
path relative to the base and the body digest), signs it with the member key, and the core judges it with the home's own rule
before returning it (a call the core refuses is `HomeProblem.callRefused`, and nothing is sent). A pass starts with the public
head (at `headQuorum` above 1 also the other homes' heads, each sent to the home its URL names). A device that holds a copy of
the history from before its approval learns the approval through the home even under `policy.history: members`: its call is
judged at what it holds, and the home decides. A brand-new device with nothing can fetch only the head under `members` (it
cannot name an `asOf`): it needs the history from the shared folder or another source. `More` and every other fault are the engine's: faults are published as `homeFaults`.
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
actor. Request scans arrive as bytes from the host's camera; nothing reads a request file. The session's worker runs on its own
serial queue, so the medium's synchronous record I/O never occupies the main actor or a cooperative-pool thread. The test
`MainActorTests` moves a 200 MiB blob in and out with a 5 ms main-actor timer running (worst lateness about 6 ms, footprint
growth about 35 MiB), and the blob executor stops on `dispatchPrecondition` if it is ever called on the main thread.

## Services and calls: provisioning a test rig by grant

A session may ask for **services** (spec §10.1) beside or instead of namespaces: `services: [ServiceTerms(audience:
purposes:)]` in `SessionConfiguration`. Its member request then carries them (`records` too when `namespaces` is not
empty; a rig that only signs calls passes `namespaces: []`). An approver sees them as `AccessRequest.services` and grants
them with `approve(_:pairing:services:grant:)` and a `ServiceGrant`: the services granted (each an audience the request
names, with purposes it asks; nil: as requested), `expires`, and `conditionsJSON` (a JSON array of §10.4 predicates).
A grant wider than the request is `SessionError.invalidCommand`, and the pairing is not spent. The `GrantOptions`
given with it are checked against the request as signed first: an expiry later than a requested one, or a write budget
larger than a requested one, is refused the same way (the core does not compare these with the request: the approver
sets them).

`signCall(audience:purpose:argsJSON:)` returns a call (§12.2) signed by this device's member key, base64url, for
`Authorization: Colophon <call>`. The signer's own check runs first: a service the session did not ask for is
`refused:outOfScope` before the key is asked, and the core then judges the signed call by §12.3 over the history the
device holds (the grant's services, expiry and conditions, a revocation it holds) and returns it only when that is
`ok`; a refused call never leaves the device. Sign one per request: a home refuses a replay.

`provisionRequest(door:audience:slot:base:account:transport:)` provisions a slot at a reference home whose gate is
`"grant"` (relay/README.md, "Provisioning by a grant"): it signs a fresh call with purpose `home.provision` and args
exactly the body `{"account","base","slot"}`, POSTs the body with `Content-Type: application/json`, its
`Content-Length` and the call, and returns the home's signed member request. A refusal is a `ProvisionRefusal` with
the door's `status` and `code` (403 is final). It plugs into `HomeConfiguration.request`:

```swift
let app = HomeConfiguration(endpoint: URL(string: base + "/")!, request: { account in
    try await rig.provisionRequest(door: door, audience: audience, slot: slot, base: base, account: account)
})
```

The slot condition holds where there is no slot: a grant's `conditions` bind **every** call its member signs (spec
§12.3 step 7), its reads of the operator account's history at the home too, whose args name no slot, and a missing path
makes `prefix` false (§10.4). A bare `{"prefix":["args.slot","ci-"]}` would leave the rig unable to sync the operator
account from the home. Write it as "the slot starts with `ci-`, or the call names none":
`{"any":[{"prefix":["args.slot","ci-"]},{"not":{"prefix":["args.slot",""]}}]}`.

Revoking the rig's member in the operator account (uploaded to the home) stops it: its next call is `403
refused:revoked` at the door, or refused by its own check once it has synced the revocation. Proven in
`ProvisionGrantTests` against the real relay.

## What a person must see (spec §17.5, §18)

`session.notices` (`SessionNotices`):

* `pending`: each transition not yet shown, with its signers' labels and key IDs, first-seen seq, veto deadline, and
  `vetoable` (this device holds an owner key that may veto and the engine's deadline has not passed). `veto(_:)` is the one call:
  the owner signs, the veto is stored, and the session submits it to every home, retrying until each has receipted it or 300 s
  have passed.
* `unseenActivations`: every activation since this host last showed the history that no key on this device signed, with when
  each home receipted it. `acknowledgeActivation(seq:)` records that the person saw that one activation (kept in the private journal); it never dismisses a pending transition, which stays until it is vetoed, activates or is dead.
* `noHome`: the warning of guide §5. `NoticeWords` holds the words the specification asks for.
* `duties.removals` (§17.5 removal follow-up): when a controller's removal activates, what it admitted since the transition's
  anchor and the removal did not remove (members whose grant it signed, `approve`/`sign` keys it added by immediate entries),
  from the core's `removal_follow_up`. `removeFollowUp(seq:)` revokes and removes them in one action (signed by the owner);
  `keepFollowUp(seq:)` keeps them. Either is remembered in the private journal and the card goes.
* `pending` carries `dueMs`: the session rebuilds `notices` after every sync, so each pending change is shown with its
  due time on every sync (spec §17.5 "Showing on sync"). 0.5 defines no notice delivery.

**Known gap: the spec §6.4 warnings before creation.** This session does not yet give the §6.4 warnings before the genesis is written: it exposes `soleDevice` after creation. The warnings stay normative for a host (a person must see them before an account is created). Until the session gives them, an app checks these conditions from the creation parameters: no home, a separate recovery unit and no home, one home, every control key on one device, exactly one recovery unit and warns before it calls create. Spec §21.1 lists this among what 0.5.0 does not do.

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
  `AccessRequest` (`id`, `label`, `kind: AccountMemberKind`, `termsJSON`, `record`, and `namespaces` /
  `access` read from its terms; no code). `syncConflicts` is `homeFaults`. `syncState` is `HomeSyncState` (`RelaySyncState` is an alias).
  Removed: `performMigration`, `migrationBlob`, `restoreDevice(using:)`, `recoveryKeys()`. New: `notices`, `homes`, `lock()`,
  `unlock()`, `veto(_:)`, `acknowledgeActivation(seq:)`, `addController`, `transferSeed`, `acceptSeedTransfer`, `exportRequest()`,
  `scanRequest(_:)`, `beginJoinPairing()`, `beginApproval(commitment:)`, `approvalCode(pairing:e:nb:)`, `rejectPairing(_:)`,
  `abandonApproval(_:)`, `approve(_:pairing:grant:)`, `receipts(for:)`. Removed in the freeze package: `importRequest`.
* `SessionPhase.locked`; `SessionError.noHome`, `.ownerRequired`; `SessionKeyFailure` is public.
* `IngressEnvelope.libraryID` is the 64-hex account ID.
* `AsyncKeyProvider.keyDescriptor()` is a requirement with a default (raw keys). `KeyDescriptor.view` is the 0.5 form.
* `LibrarySessionSource` gains `notices`, `veto`, `acknowledgeActivation`, `unlock` and loses `ledger`; `ColophonLedgerView` and
  `SupportReport.ledgerEntryCount` are removed.
* `ColophonMigration`: the 0.4 clean copy (`LibraryMigration`, `LegacyLibrarySource`, `MigrationState`) is removed (its engine, the
  0.4 session, is gone). The 0.4 `NativeEngine`/`Library` wrappers in ColophonKit remain for tools that read a 0.4 library.

## Proven against the real relay

`RelayJourneyTests` (in `swift/Tests/ColophonSessionTests`) start the real relay (`bun relay/server.js --test-clock` with a
temporary data directory, on loopback, the home module in WebAssembly) as one home, and as two homes at `headQuorum` 2, and run
two devices of one person through it under `policy.history: members` and `public`: creation with the home, a second device
approved and syncing, writes and reads through `ColophonSavedKit` with a required and an optional blob, a third device
approved then revoked and refused, and a pending change shown on the other device and vetoed. The relay requires a call for
everything §13.4 and §14 say needs one. `scripts/test-swift.sh` builds the home module first; without Bun or the module these
tests fail. `SimHome` remains only for unit tests that need a home the test controls (offline, over its bound, not `https`,
route registration, a change that goes dead). The same journey through the Rust exports is
`crates/colophon-ffi/tests/v05_relay_journey.rs`.
