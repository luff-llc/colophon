# Colophon 0.6 device admission: attempts, promotion and passkey-authorised adding

**Status:** design draft, 2026-11-26, for review. Proposed for Colophon 0.6. It changes no 0.5
object, verdict, path or wire format. It adds an SDK layer (admission attempts and account
generations) to the Swift, Kotlin and JavaScript sessions. §4.8 proposes two optional
clarifications to the 0.5 text. Neither is needed for the design to work.

**Goal.** Any device can add another device to an account if a controller passkey of the account
signs the approval. The newly added device can also register a passkey of its own. This removes
two failures. A person no longer depends on one device or one passkey to get back in. A passkey
can be added or rotated from any device the person holds, without sharing storage with a live
account.

**Conclusions in brief.**

1. Adding a device with a passkey signature can already be expressed in 0.5 history. It is an
   ordinary `grant` (§9.2), signed under the single rule (§8.4) by a WebAuthn controller holding
   `approve`, after a confirmed pairing (§9.1). The 0.5.7 calls produce exactly this entry. Adding
   a new passkey on the added device is an ordinary immediate `keyring` entry (§8.4, §17.3).
   **No protocol change is required.**
2. The defect is in the SDK, not the protocol. In 0.5.7 a join or recovery attempt creates its
   member keys and writes its files in whatever storage and key names the app configured, and
   those are the live account's. No layer can tell attempt state from live state, so any cleanup
   is a guess. The fix: give each attempt its own **generation** of device-local state, and make
   a durable pointer the only thing that marks a generation as live. Promotion then means
   atomically replacing the pointer, and nothing is renamed. This works the same on every
   platform, including Android Keystore, where aliases cannot be renamed.
3. #115 should be split. Its live-session parts (removal, completing key changes, `restoreSlot`,
   cosigners, the entropy fix) can go forward unchanged. Its second-passkey and replacement paths
   should be reworked on top of attempts (§7).

---

## 1. Problem

### 1.1 What 0.5.7 provides (verified in code)

- `ColophonJoin.readHistoryWithPasskey` (Kotlin
  `sdk/kotlin/src/main/kotlin/com/luff/colophon/session/ColophonJoin.kt`; Swift
  `swift/Sources/ColophonSession/ColophonJoin.swift`) reads and verifies the history with
  `colophon.history.read` calls signed by a passkey, as spec §13.4 "A device with a passkey"
  allows. It stores nothing.
- `ColophonJoin.approveOwnJoinWithPasskey(passkey, ownerKeyId, open)` does the following:
  1. calls `request()`, which creates this device's signed request through `OwnRequest.ensure`
     and writes it to `requests/<member ID>.json` in `configuration.medium`. On first use it also
     creates the member key, `configuration.keys`;
  2. reads the history with the passkey;
  3. writes the history files and the request into the same `configuration.medium`
     (`ColophonJoin.store`);
  4. calls the app's `open` closure to build a session whose owner controller is the passkey;
  5. checks that the session's store holds exactly the verified history;
  6. calls `ColophonSession.approveOwnRequest`, which scans the device's own request envelope
     (the §9.1 scan path) and signs a `grant` through `SessionWorker.approve`, opening the
     passkey's own slot by PRF in `withOwner`/`unlockOwner`;
  7. syncs up to `ATTEMPTS` times, and throws `unavailable` with the grant stored if the home
     does not confirm it.
- `ColophonJoin.recoverWithPasskey` is `recovery(...)` (seq 1, the account ID as head) followed
  by `approveOwnJoinWithPasskey`.
- The JavaScript session (`js/src/session/`) has no join-at-head or passkey-join surface. No
  file there calls `verify_at_head` or `verify_with_passkey`.

### 1.2 What an attempt creates, and where it lives

| State | Created by | Where (0.5.7) | Shared with a live account of the same app? |
| --- | --- | --- | --- |
| Member signing and agreement keys | first use of `configuration.keys` | Android: Keystore aliases `<prefix>.signing` and `<prefix>.agreement` (`KeystoreKeys.materialize`), where the app picks `<prefix>` and `openOrCreate` creates the keys when they are missing. Apple: one Keychain item `service`/`account` (`KeychainKeys`, default account `"member"`), created on first use when absent. Browser: `WebCryptoKeyStore` record by `id`. | Yes, whenever the app passes its usual key configuration. Nothing in the SDK names keys per attempt. |
| Own request | `OwnRequest.ensure` | `requests/<member ID>.json` in `configuration.medium` | Same medium. `ensure` regenerates the request when the file is missing, so a lost file silently yields new bytes. |
| Authority history | `ColophonJoin.store` | `authority/<seq>.json` in `configuration.medium` | Same medium |
| Session journal, saved state, pairing ledger | the session opened by `open` | `configuration.privateDirectory` (`session.json`, `saved-<account>.bin`, `pairing-ledger.*`) | Same directory |
| Device key that seals saved state | `DeviceSecretStore.key(account)` (also in `withOwner`) | keyed **by account ID** only: Android a file per account under one directory, wrapped by one Keystore alias (`KeystoreDeviceSecrets`); Apple a Keychain item whose `account` is the account ID (`KeychainDeviceSecrets`); browser `salt:<account>` (`WebCryptoDeviceSecrets`). Swift `CheckpointCache` is also keyed by library ID. | Always, for an attempt on an account already present on the device |
| The passkey descriptor that the app persists so it can rebuild `PasskeyController` | the app, inside `open` | the app's settings | The app's own state |
| A signed grant | `approveOwnRequest` | the medium, then the home | Live authority once published |

`ColophonSession.leave()` only sets `journal.left` (`SessionWorker.leave`), and the SDK has no
call that removes an account. Every deletion is therefore written by the app, against paths and
aliases the app shares between attempts and live accounts.

### 1.3 Failure sequences found in practice

An app built join approval and recovery on these calls, and two security reviews of its rollback
logic found the same class of fault each time. In general terms:

- **F1. Missing metadata reads as "no account".** The app decided whether the device held an
  account from its own settings file. When that file was missing or unreadable, defaults said
  "no account", even though the record folder and Keystore aliases of a live account were
  intact. A recovery attempt started, the person dismissed the passkey prompt, and rollback
  deleted the record folder and every key alias. Those were the live account's. A local-only
  account would have been lost for good.
- **F2. A screen-owned task cancelled mid-approval.** The provisional session was published as
  soon as it opened. The session restored to "waiting for approval" before the passkey signed
  the grant, the interface replaced the screen, and the cancelled coroutine triggered rollback.
  A person who paused at the final prompt with the correct passkey hit this.
- **F3. Process death between steps.** Member keys and the signed request exist before the first
  passkey prompt. If the process died there, a request was left behind that conflicted with a
  later attempt on another account (`JoinError.OtherRequest`). If it died at the final prompt,
  the app had already saved the verified descriptor and slot, and the next launch reopened an
  unadmitted account on a screen that could not retry.
- **F4. Committed grant, failed confirmation.** The grant reached the home, the connection then
  dropped during the confirmation read, and the transport error bypassed the `unavailable` path.
  Rollback deleted the member keys of a member the history now admits, and a retry made a new
  member identity.
- **F5. Recovery over a pending join.** Starting a recovery deleted the request and keys of a
  pending code-path join before the passkey was checked, because both used the same aliases and
  folder. An approval already issued for that member became unusable.
- **F6. Approving the wrong request.** A queued self-approval read whichever request was stored
  when it ran. A concurrent replacement of the pending join could make it approve another
  account's request if one passkey controlled both. When the request file was missing,
  `OwnRequest.ensure` produced new request bytes that nobody had seen.
- **F7. A marker cannot prove ownership.** The fix added a durable "attempt in progress" marker
  and treated it at restore as permission to undo. If deleting the marker failed after
  admission, and the settings later became unreadable, restore deleted an admitted account. The
  marker said that an attempt had existed, not which files and keys belonged to it.
- **F8. Expiry deleted by census.** Expiring a pending join deleted "every key alias and the
  whole account folder", because a join and a live account have identical aliases and folders.
  The guard being written for it has to prove by inventory that nothing but the join's artefacts
  exists: settings present and parseable, no file outside `requests/`, `session/` and the device
  keys, no alias outside the join's set, and an unreadable store counted as "keys present". It
  also had to run before a lookup that could itself trigger the deletion.

### 1.4 Why the app could not fix it from outside the SDK

- The SDK writes into the app's live storage (`configuration.medium`, `privateDirectory`) and
  creates keys under the app's live names on first use. An app can only avoid the collision by
  building a parallel configuration with other paths and aliases, then moving it into place
  itself. Android Keystore cannot rename an alias, so "moving it into place" means the app
  re-points its own settings at the attempt's alias. That is the app inventing generations
  without the SDK's help.
- Some collisions cannot be avoided from outside. The device-secret store, `withOwner`'s use of
  it and Swift's `CheckpointCache` are keyed by account ID alone, so an attempt on an account
  already present shares that state whatever paths the app picks.
- Whether a grant exists is known only to the engine. `approveOwnRequest` writes the grant
  before reconciling, so a storage or lifecycle failure can hide a committed grant from the
  snapshot the app checks (F4).
- Each app repeats the same hazardous logic (inventories, markers, non-cancellable sections) on
  each platform, and gets it wrong in the same way.

The lesson: an attempt that has not been admitted must live in storage and key names scoped to
that attempt, must be promoted atomically on admission, and must be owned by the SDK, so that no
app ever writes destructive cleanup.

---

## 2. Requirements

- **R1. Disjoint state.** No path, Keychain item, Keystore alias, IndexedDB record or
  device-secret entry that an attempt creates is ever shared with a live account, another
  attempt or a pending join. This holds even when all of them are for the same account.
- **R2. Abandoning cannot touch live state.** Abandoning, failing, expiring or crashing an
  attempt leaves the live generation byte-identical: files, key aliases and their public points,
  device-secret entries and the pointer.
- **R3. Deletion by ownership, never by inference.** The SDK deletes only what a durable record
  lists as owned by a non-live generation, after re-reading the pointer under a lock. Missing or
  unreadable metadata never permits a deletion. An unreadable pointer stops every deletion.
- **R4. Atomic promotion.** Promotion has a single commit point: one atomic replacement of a
  small file, or one database transaction. Where keys cannot be renamed, they are never renamed.
  Before the commit point the old generation is live. After it the new one is. Every step after
  the commit is idempotent and rolls forward.
- **R5. Durable, resumable attempts.** An attempt survives process death in every state. Caller
  cancellation never triggers cleanup. An attempt that has signed a grant is never discarded
  without the person's action (F4).
- **R6. Several attempts at once.** Attempts for different accounts, and several for one account,
  can coexist. Passkey ceremonies and promotions are serialised per account root.
- **R7. An attempt over a live account.** A re-join or recovery over an existing install creates
  a new generation and a new member (§3.3 forbids reusing member points). The old generation is
  retired only by the SDK, after the new one is ready (§3.7).
- **R8. Bound inputs.** An attempt binds its account, home, invite checkpoint `(seq, head)` when
  there is one, member key and the exact request bytes at creation. Nothing regenerates the
  request later (F6). Approving acts on an attempt handle, never on "whatever is stored".
- **R9. No destructive API for apps.** Apps never call a delete. The only discard call takes an
  attempt and can reach only that attempt's generation. No call takes a path or alias.
- **R10. Listing and expiry.** Apps can list attempts with their state and age. The SDK expires
  attempts that never signed anything, after a bounded time.
- **R11. Rollback safety.** An attempt for an account that is already live is promoted only if
  its verified history is not behind the live generation's verified high-water mark (§5).
- **R12. Parity.** The same states, layout rules and calls in Swift, Kotlin (JVM and Android) and
  TypeScript (browser and Node).

---

## 3. Design

### 3.1 Terms

- **Account root.** A directory (or IndexedDB database) plus a key namespace, which the app gives
  the SDK once. The SDK owns everything under it.
- **Generation.** One complete set of device-local state for one account on this device: records
  medium, private directory, member keys, device secret, checkpoint. It is identified by a
  random 128-bit ID in lowercase hex. Every name a generation uses contains its ID.
- **Pointer.** The one durable record, per account root, that names the live generation of each
  account. Nothing else makes a generation live.
- **Attempt.** A generation that is not yet named by the pointer, together with its attempt
  record. A pending code-path join, a passkey self-approval and a recovery are all attempts.

### 3.2 The attempt record and its lifecycle

`attempts/<gen>/attempt.json` is written atomically (sibling, sync, rename, directory sync), as
`AtomicFile` does in both SDKs:

```json
{"format":1,"generation":"<32 hex>","account":"<64 hex>","kind":"join|recovery|selfApproval",
 "home":"https://…","checkpoint":{"seq":12,"head":"<digest>"},"created":"…","expires":"…",
 "owns":{"paths":["generations/<gen>/"],"keys":["<ns>.g.<gen>.member.signing","<ns>.g.<gen>.member.agreement"],
         "deviceSecret":"<account>.<gen>"},
 "member":"<member ID>","request":"<SHA-256 of the request envelope>",
 "state":"…","grant":{"seq":40,"digest":"…"},"owner":{"keyId":"…","descriptor":{…}},
 "passkeys":[{"keyId":"…","state":"registered|added|slotted"}]}
```

`owns` is written **before** anything it lists is created (write-ahead). A crash between writing
the record and creating a key leaves a listed key that does not exist. Discarding it is then a
no-op. No key or path can exist that no record lists.

| State | Meaning | Leaves by |
| --- | --- | --- |
| `created` | record written, nothing else yet | keys made, then `requested` |
| `requested` | member keys exist, request signed and stored in the generation | code path: `waiting`; passkey: `reading` |
| `waiting` | code-path join waiting for another device's grant | grant seen, then `granted`; expiry, then `expired` |
| `reading` | passkey history read and verification under way, nothing signed | verified, then `verified`; failure, then `requested`, still retryable |
| `verified` | history verified and stored in the generation; signer recorded | grant signed, then `granted` |
| `granted` | a grant naming this member from its exact request is in the generation's verified history (signed here or received) | home confirms, then `admitted`; displaced (§8.6), then `verified` to sign again |
| `admitted` | the home serves a fresh head over a history holding the grant (§3.4 P0) | promotion commit, then `promoted` |
| `promoted` | the pointer names this generation; the record is kept only until post-commit steps finish | record removed |
| `superseded` | another attempt for the same account was promoted first | person's choice: revoke its member (§3.7), then `discarding` |
| `expired` | past `expires` and never signed a grant | `discarding` (automatic) |
| `discarding` | tombstone: deletion of `owns` in progress | record removed |

Two rules close F2, F3 and F4:

- **Cancellation is not failure.** Cancelling a caller's task leaves the attempt in its last
  durable state. Only `abandon()` or expiry moves an attempt to `discarding`, and expiry applies
  only to attempts that never reached `granted`.
- **Signed means kept.** From `granted` on, a grant for the attempt's member may be live
  authority. The SDK never discards such an attempt automatically. An abandon of a `granted`,
  `admitted` or `superseded` attempt first offers to revoke its member (one passkey signature),
  and keeps the generation if the person declines.

### 3.3 Layout and names per platform

```text
<root>/pointer                       the live generation per account (atomic replace)
<root>/lock                          advisory lock: flock / FileChannel.lock / Web Lock
<root>/generations/<gen>/records/    the generation's RecordMedium (FolderMedium or FileMedium)
<root>/generations/<gen>/session/    journal, saved-<account>.bin, checkpoints
<root>/attempts/<gen>/attempt.json   present while <gen> is an attempt or is being discarded
<root>/accounts/<account>/ledger/    pairing-failure ledger (outlives generations; §3.6)
```

A generation's directory sits under `generations/` from birth. Promotion moves nothing on disk.

`pointer` is canonical JSON with a SHA-256 of its own body:
`{"format":1,"accounts":{"<account>":{"live":"<gen>","previous":["<gen>"]}},"digest":"…"}`. A
pointer that fails to parse or match its digest is **unreadable**. The SDK then opens nothing
destructively, refuses promotion and discard, and reports `storageDamaged`.

| Platform | Files | Member keys | Device secret | Promotion means |
| --- | --- | --- | --- | --- |
| Apple (iOS, macOS, visionOS) | app container or App Group (extensions must see the pointer); excluded from backup | Keychain generic password, `service` = app namespace, `account` = `g.<gen>.member` (Secure Enclave handles, as `KeychainKeys` stores today), `ThisDeviceOnly`, not synchronisable | `KeychainDeviceSecrets` item `account` = `<account>.<gen>` | replace `pointer` by `rename(2)` within one volume |
| Android | `noBackupFilesDir/colophon/<root>/` | Keystore aliases `<ns>.g.<gen>.member.signing` and `.agreement` (fits `KeystoreKeys`' `[A-Za-z0-9._-]`, under 80 characters) | `KeystoreDeviceSecrets` file `<account>.<gen>`, wrapped by the existing alias | replace `pointer` (`Files.move` with `ATOMIC_MOVE`, then directory sync, as `AtomicFile` does) |
| JVM | as Android, plain directory | as configured by the host (software keys in tests) | as configured | as Android |
| Browser | IndexedDB `colophon-root-<root>`, stores `pointer`, `attempts`; records medium `IndexedDBMedium` named `<root>.<gen>` | `WebCryptoKeyStore` record id `<gen>/member` | `WebCryptoDeviceSecrets` salt `salt:<account>.<gen>` | one `readwrite` transaction on `pointer` |
| Node | as Apple, `FileMedium` / `FilePrivateStore` | host-provided | host-provided | `fs.renameSync` of `pointer` |

**Android, in detail.** Keystore aliases cannot be renamed, and Keystore deletions are not
transactional with the file system. So an alias is never asked to change meaning. A generation's
aliases are created once, carry the generation ID, and are deleted only when that generation is
discarded or retired. The pointer, a file, decides which aliases are live. A missing alias in
the live generation is reported as `keysLost`, never re-created, and never treated as "no
account". The live generation's aliases are opened with an open-only call, because
`KeystoreKeys.openOrCreate` creates any pair it does not find. Today an app has to guard this by
hand: a census of aliases and files, settings that must be readable, and an unreadable store
counted as holding every alias. Under this design those checks become structural. A deletion
names one generation's aliases from its own record, and it is refused when the pointer names
that generation or cannot be read.

**Apple, in detail.** `SecItemUpdate` could rename a Keychain item atomically, but that is not
needed and not used. As on Android, the pointer chooses. The live generation's items are opened
with an open-only call, because `KeychainKeys.withKey` creates an identity when its item is
absent. A backup restored to a new device brings the files back without the `ThisDeviceOnly`
items. The SDK reports `keysLost`, and the person recovers into a new generation. Nothing is
deleted.

**Shared media.** When the app's records medium is shared between devices (an iCloud or shared
folder location, `StorageLocation.iCloud` or `.folder`), only device-private state is
generation-scoped. The attempt stages its history and request in a private generation medium.
After the commit point, it writes them to the shared medium with the write-if-absent and
same-bytes check that `ColophonJoin.store` already uses. The SDK never deletes from a shared
medium. An abandoned attempt's request, if it was ever written there, stays as an immutable
unused file.

### 3.4 Promotion

**Precondition P0 (admitted).** The attempt's generation verifies, from seq 1, a history holding
a current grant of its member from its exact request. Either the home served a fresh head over
that history, read with the member's own key (the `fetchHistory` acceptance, `account_verify_at_head`), or the account has no
home. When the pointer already names a live generation for this account, the attempt's verified
`(seq, digest)` must also not be behind the live generation's persisted high-water mark (§17.2),
or promotion is refused `refused:rollback`.

All steps run under the root lock. Each step after C is idempotent.

| Step | Action |
| --- | --- |
| P1 | Take the lock. Re-read `pointer` and `attempt.json`; both must be readable. The attempt must be `admitted`. |
| P2 | Close any session open on the attempt's generation. Flush the generation's medium (complete any committed batch). |
| P3 | Write the new pointer to a sibling: `live` = the attempt's generation, the old live generation appended to `previous`. Sync it. |
| **C** | **Rename it over `pointer`, then sync the directory. This is the commit point.** Browser: the transaction commits. |
| P4 | Set the attempt record to `promoted`. |
| P5 | Shared medium only: copy the generation's request and history into it, write-if-absent. |
| P6 | Mark every other attempt for this account `superseded`. |
| P7 | Remove `attempt.json`. Release the lock. Open the session on the new generation. |

**Crash table.**

| Crash after | On next open | Which state wins |
| --- | --- | --- |
| P1, P2 | attempt is `admitted`; pointer unchanged | old live (if any). The SDK resumes promotion at the next `open` without asking again, because the person already chose it. |
| P3 (sibling written, not renamed) | stray sibling removed; attempt `admitted` | old live; promotion resumes |
| C before the directory sync | the pointer shows old or new | whichever the file system kept. Both are consistent: old means resume, new means continue at P4. |
| C, P4, P5, P6 | pointer names the attempt's generation | new. The record is `admitted` or `promoted`; P4–P7 roll forward. |
| P7 | done | new |

The Android and browser rows are the same. On Android the commit point is still a file rename,
and Keystore is not touched during promotion.

### 3.5 Discard, expiry and retirement: the only deletions

The SDK deletes through one routine, `discard(gen)`:

| Step | Action | Crash after it |
| --- | --- | --- |
| D1 | Take the lock. Re-read `pointer`. Refuse if it is unreadable, or if `gen` is `live` or in `previous` while retention applies (§3.7). | nothing changed |
| D2 | Write the record state `discarding` (tombstone). | the sweeper resumes at D3 |
| D3 | Delete each key in `owns.keys`, by exact name. A missing key is a no-op. | resumes at D3 |
| D4 | Delete the `owns.deviceSecret` entry. | resumes at D4 |
| D5 | Rename `generations/<gen>` to `trash/<gen>`, then delete it recursively. | the sweeper empties `trash/` |
| D6 | Remove `attempt.json`. | done |

The **sweeper** runs at `open`. It finishes `discarding` tombstones, empties `trash/`, and expires
attempts past `expires` that never reached `granted`. It never deletes anything that is not
listed in a record or under `trash/`. An alias or directory that no record lists is reported by
`diagnostics()` and left alone (R3, F7).

### 3.6 Concurrency

- One root lock serialises promotion, discard and the sweeper. Across processes this is `flock`
  in Swift, `FileChannel.lock` behind a JVM-wide monitor in Kotlin, and a Web Lock in browsers,
  as the pairing ledger already does.
- At most one passkey ceremony per root at a time. A second one is refused `busy`. Attempts in
  other states proceed.
- By default at most four live attempts per account root (open question Q8).
- The pairing-failure ledger (§7.3's five failed sessions an hour) lives under
  `accounts/<account>/ledger/`, outside every generation. Discarding an attempt cannot reset the
  budget. Today the ledger is in `privateDirectory`, so a fresh directory per attempt would reset
  it.

### 3.7 An attempt over a live account

A re-join or recovery on a device that already has a live generation for the account (keys lost
to a lock-screen change, a revoked member, a damaged store):

1. The attempt gets a new generation and a new member key. The live generation is untouched and
   keeps working if it still can.
2. On promotion, the old generation goes into `pointer.previous`.
3. The old generation is **retired** (`discard`) only when the new generation is `Ready` at a
   fresh head, and either the old generation has no unpublished writes, or its member key cannot
   sign, or a retention window has passed (Q3). Until then the old generation stays readable, for
   export.
4. If the old member is still current in the history, the SDK offers to revoke it with `kept`
   covering everything (§9.5). The revoke is signed by the controller that approved the new
   member (`approve`, single rule). This follows the §17.5 removal follow-up pattern. Declining
   leaves a current member whose keys this device deletes at retirement. That is harmless, but it
   is shown.

An existing install from 0.5.x is adopted as a generation named `legacy`. Its pointer entry
records the app's configured medium, private directory and key configuration. The SDK never
deletes a `legacy` generation's app-provided locations by itself (Q11).

### 3.8 API sketch

All three languages expose the same types. Names follow each language's conventions.

**Kotlin**

```kotlin
class ColophonAccounts(root: AccountRoot)            // AccountRoot: directory, key namespace, key and secret factories
    suspend fun live(account: String): GenerationInfo?
    suspend fun open(account: String, template: SessionTemplate): ColophonSession   // the live generation
    suspend fun attempts(account: String? = null): List<AttemptInfo>
    suspend fun beginJoin(invite: JoinTarget, template: SessionTemplate): AdmissionAttempt
    suspend fun beginRecovery(target: RecoveryTarget, template: SessionTemplate): AdmissionAttempt
    suspend fun attempt(id: String): AdmissionAttempt?
    fun diagnostics(): RootDiagnostics                  // unowned names, damaged pointer; read-only

class AdmissionAttempt                                  // a handle; every call re-reads the durable record
    val id: String; val account: String; val kind: AttemptKind
    val state: StateFlow<AttemptState>
    suspend fun request(): ByteArray                    // the bound bytes, never regenerated
    suspend fun joinPairing(): AccountPairing           // code path to another device
    suspend fun approveWithPasskey(passkey: PasskeyAuthenticator, ownerKeyId: String? = null): AttemptState
    suspend fun addPasskey(registrar: PasskeyRegistrar, label: String): AttemptState   // §4.6
    suspend fun promote(): ColophonSession              // P0–P7
    suspend fun abandon(revokeIfGranted: PasskeyAuthenticator? = null)

// On any live session (§4.2): approve another device's request with a passkey that is not this session's owner.
suspend fun ColophonSession.approve(request: AccessRequest, pairing: AccountPairing, passkey: PasskeyAuthenticator, ownerKeyId: String? = null)
```

`SessionTemplate` holds what `SessionConfiguration` holds today, except storage, keys and device
secrets, which the root supplies per generation: member label and kind, namespaces, access,
services, homes and the clock.

**Swift**

```swift
public actor ColophonAccounts {
    public init(root: AccountRoot)
    public func live(_ account: String) async throws -> GenerationInfo?
    @MainActor public func open(_ account: String, template: SessionTemplate) async throws -> ColophonSession
    public func attempts(for account: String? = nil) async throws -> [AttemptInfo]
    public func beginJoin(_ invite: JoinTarget, template: SessionTemplate) async throws -> AdmissionAttempt
    public func beginRecovery(_ target: RecoveryTarget, template: SessionTemplate) async throws -> AdmissionAttempt
}
public actor AdmissionAttempt {
    public nonisolated let id: String
    public var state: AttemptState { get async }
    public var updates: AsyncStream<AttemptState> { get }
    public func request() async throws -> Data
    public func approve(with passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil) async throws -> AttemptState
    public func addPasskey(_ registrar: any PasskeyRegistrar, label: String) async throws -> AttemptState
    @MainActor public func promote() async throws -> ColophonSession
    public func abandon(revokingWith passkey: (any PasskeyAuthenticator)? = nil) async throws
}
extension ColophonSession {
    public func approve(_ request: AccessRequest, pairing: AccountPairing, with passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil) async throws
}
```

**TypeScript**

```ts
class ColophonAccounts {
  static open(root: AccountRoot): Promise<ColophonAccounts>;
  live(account: string): Promise<GenerationInfo | undefined>;
  open(account: string, template: SessionTemplate): Promise<ColophonSession>;
  attempts(account?: string): Promise<AttemptInfo[]>;
  beginJoin(invite: JoinTarget, template: SessionTemplate): Promise<AdmissionAttempt>;
  beginRecovery(target: RecoveryTarget, template: SessionTemplate): Promise<AdmissionAttempt>;
}
interface AdmissionAttempt {
  readonly id: string; readonly account: string; readonly kind: AttemptKind;
  state(): Promise<AttemptState>; onState(listener: (s: AttemptState) => void): () => void;
  request(): Promise<Uint8Array>;
  approveWithPasskey(passkey: PasskeyAuthenticator, ownerKeyId?: string): Promise<AttemptState>;
  addPasskey(registrar: PasskeyRegistrar, label: string): Promise<AttemptState>;
  promote(): Promise<ColophonSession>;
  abandon(options?: { revokeWith?: PasskeyAuthenticator }): Promise<void>;
}
```

No call takes a path, an alias or a generation ID to delete.

### 3.9 How the 0.5.7 calls map

| 0.5.7 call | 0.6 |
| --- | --- |
| `ColophonJoin.readHistoryWithPasskey` | Unchanged and pure (stores nothing). Used inside `approveWithPasskey`. |
| `ColophonJoin(configuration, …).request()`, `fetchHistory()` | Kept, source-compatible, over the given configuration. `AdmissionAttempt.request()` and the attempt's waiting loop replace them for new code. |
| `approveOwnJoinWithPasskey(passkey, ownerKeyId, open)` | Kept, source-compatible, deprecated. With a configuration that a `ColophonAccounts` attempt produced, it becomes a thin wrapper over `approveWithPasskey` then `promote`, and the `open` closure is called only to build the template. With an app-built configuration it behaves as in 0.5.7, and its documentation states the shared-storage hazard. |
| `recoverWithPasskey` | Same treatment: `beginRecovery`, `approveWithPasskey`, `promote`. |
| `ColophonSession.approveOwnRequest(expected)` | Unchanged; called by the attempt with `expected` set to the bound request (R8). |
| `ColophonSession.leave()` / `rejoin(keys)` | `leave` unchanged (non-destructive). `rejoin` becomes `beginJoin` for the same account, a new generation, as §3.3 requires a new member anyway. |
| `SessionConfiguration` | Unchanged. `ColophonAccounts` builds one per generation. |
| JavaScript | No 0.5.7 passkey join exists. The attempt API and a port of `ColophonJoin` are added natively. |

Behaviour that changes for wrapped calls: failure never deletes anything, an
`unavailable` after a signed grant leaves the attempt `granted` and resumable, and caller
cancellation does not roll back.

---

## 4. Adding another device with a controller passkey

### 4.1 What "the library's first passkey" is in protocol terms

0.5 has no notion of a "first" passkey. Verified:

- The reference sessions create a genesis keyring whose owner controller is the person's passkey,
  with roles `approve`, `control` and `recover`, `verification: true` for a passkey, and a `prf`
  slot (Swift `SessionWorker.swift`, the genesis `ControllerSpec(… roles: [.approve, .control,
  .recover], verification: isPasskey …)`; Kotlin mirrors it). §18's reference setup gives
  passkeys `approve` and `control`.
- The protocol gives that controller exactly the authority of its roles (§6.1, §8.4). "First"
  appears only as the display "first-seen seq" (§6.1, §17.5).

So in this design, "the first passkey" means **any current WebAuthn controller that holds
`approve` (or `control` where `memberRule` is `control`) and has a slot of its own**. Usually that
is the genesis passkey. The SDK selects by those properties, never by seq. The 0.5.7 self-approval
already checks the same properties (`signerController.roles`, `ownSlot`).

### 4.2 Flow A: a device that already holds the account adds a new device

Device A is a current member, for example a tablet. Device B is new. The passkey is available on
A: synced to A's platform, or reached by a cross-device (hybrid) ceremony from a phone.

1. **B** calls `beginJoin` with A's invite. Its attempt makes member keys and a request in its own
   generation, then shows the pairing QR or commitment (§7.3, §9.1).
2. **A** pairs with B's request. The person compares the six-digit code, or A scans B's request
   envelope. A's core issues the confirmed pairing for B's exact `member.signing`.
3. **A** calls `session.approve(request, pairing, passkey)`. A opens a controller engine over its
   own store with the passkey as signer, as `withOwner` does today, but with the passkey given per
   call. It unlocks the passkey's own `prf` slot with one assertion that evaluates PRF. It then
   prepares the `grant` (terms covered by the request, `shares` sealing every historical epoch of
   each granted namespace to B's agreement key, §9.2), and the passkey signs it with UV in a
   second assertion.
4. **A** publishes the grant to the primary home, then every home (§17.5).
5. **B**'s attempt reads the history with its member key, sees the grant (`granted`, then
   `admitted` at a fresh head), and promotes.

No step needs A to be a controller. A only hosts the ceremony.

### 4.3 Flow B: the new device approves itself

This is the 0.5.7 behaviour, now on an attempt. B holds the passkey, or reaches it by a hybrid
ceremony. `approveWithPasskey` does the following:

1. reads the history with the passkey (§13.4), and records the signer in the attempt;
2. stores the history in the attempt's generation (`verified`);
3. scans its own bound request envelope to get the confirmed pairing (the scan path, §9.1);
4. opens the passkey's slot, signs the grant (`granted`) and syncs;
5. waits for the home to confirm (`admitted`), then the app calls `promote()`.

### 4.4 Who signs what, what the home sees, what history records

| Step | Signed by | Sent to the home | Recorded |
| --- | --- | --- | --- |
| History read (flow B only) | passkey, `colophon.history.read` calls, one per 64-entry page (§12.2) | `GET /authority` pages | nothing (calls are replay-checked, §12.4) |
| Request | B's member key, `raw` | nothing until the grant | embedded in the grant |
| Slot unlock | passkey PRF (UV per §7.2) | nothing | nothing |
| Grant | passkey, `webauthn`, from an authority origin (§4.3); UV because `verification: true` | `POST /authority` | `grant` at seq n: `by` = passkey key ID, `request`, `terms`, `shares` |
| Member's reads | B's member key, `colophon.history.read` / `colophon.home.read` | ordinary calls | nothing |

The home sees an ordinary immediate entry charged to the passkey's rate budget (`policy.rate`,
64 entries a day by default). It learns nothing it does not learn from any approval.

### 4.5 Rules, roles and thresholds

- `memberRule` `single` (the person default): the **single rule**, exactly one signer holding
  `approve` (§8.4). UV is required because the reference passkey has `verification: true`
  (§4.3 step 3, §8.4 "UV").
- `memberRule` `control` (the company default): the **control rule**, at least `threshold`
  control units. A grant then needs the other holders' signatures, which this flow collects as
  `cosignatures` from other devices. This needs the cosigner plumbing from #115.
- `recover`-only passkeys cannot sign a grant. 0.5.7 already refuses them (`refused:outOfScope`)
  before storing or signing anything. Recovery with them is a pending transition, outside this
  flow (§7, W11).
- `import` is never granted this way (§9.3 needs the control rule and a `device` or `app`
  member).
- The pairing is required on both flows. The core refuses a grant without a confirmed pairing
  (§9.1, §17.1), so flow A cannot approve a member ID typed in or relayed.

### 4.6 Adding a new passkey on the added device

After admission, or as the last step before promotion while the passkey is still at hand, B
registers a passkey P2 of its own platform (UV required, attestation none, `authorityOrigins`
set; §17.3 step 1).

1. **Immediate `approve`, with a slot.** B prepares one `keyring` entry that adds P2 with roles
   `["approve"]` and a `prf` slot for P2 in the same entry. The existing control passkey P1 signs
   it (`addThreshold` control units, UV, §8.4). P2 signs the possession proof in `additions`,
   with PRF evaluated in the same assertion (§7.2 "Building a PRF route"). P1's slot was opened in
   the same attempt, so B holds the seed for this session and builds P2's slot without the §7.4
   transfer. This entry is immediate.
2. **`control` later.** Giving P2 `control` is a pending transition under the control rule (§8.4),
   due after `recoveryDelay` (72 hours by default). It is immediate only as a full set, with at
   least two signing units (§8.7), so a person whose only control key is P1 waits out the delay.
   The SDK proposes it right away, records it as `passkeys[].state` in the attempt (or, after
   promotion, in the session journal), and shows it as pending (§17.5).
3. **On a device admitted by code path** (flow A, where B never opened P1's slot), B gets the seed
   by §7.4 from A during the same pairing, or adds P2 by transition and builds its slot with a
   self-slot `keyring` entry once final (§17.3 step 2).

If P2 is registered but the entry fails, P2 exists only in the person's credential manager. It is
listed in the attempt as `registered` so the host can show "a passkey was created but not added",
and retry with the same credential. Credential managers offer no programmatic delete, so it is
never "cleaned up".

### 4.7 When the first passkey is lost or has been replaced

- **Replaced** (by #115's `replaceController`, or by any transition that removed P1 and added P2):
  P1 is no longer current. Its history reads are answered `refused:revoked` (§13.4), and the SDK
  selects P2 by the rule in §4.1. Nothing in this design refers to P1 by identity.
- **Lost, with another approving controller**: any current passkey or device owner key with
  `approve` and its own slot can run flow A or flow B. Then remove P1 (#115 `removeController`,
  pending, with the vault retiring and rotating, §8.3).
- **Lost, with only recovery keys left**: a recovery transition (§8.4 recovery rule, pending
  unless it is a full set). The device proposing it holds an attempt in a new state,
  `awaitingActivation`, that is durable for the whole delay. When the activation is final, the
  attempt's new controller signs its own grant and the attempt promotes. This is the main reason
  for R5. It is staged as W11.
- **Lost, with nothing else**: the account cannot be recovered. The §6.4 warnings already cover
  this, and the new-passkey step in §4.6 exists to keep it from happening.

### 4.8 Does this need a spec change?

**No.** The grant (§9.2), the single and control rules (§8.4), the self-scan pairing (§9.1, as
§13.4 already anticipates "to approve its own request"), the immediate `keyring` with a slot and
possession proof (§8.4), and the pending `control` addition (§8.4, §8.7) are all 0.5 rules. The
reference already produces and verifies them. Two optional clarifications would make the 0.5.7
behaviour explicit for other implementers:

```diff
 ### 9.1 Membership request
 …
 the call consumes a **confirmed pairing**: an opaque token the core issues once when §7.3 completes
 (the code confirmed; or, on the scan path, exactly one payload: the canonical request envelope
 scanned from the requester's screen, whose `member.signing` is the key), bound to this account and
 to the exact `member.signing` of the request, and spent by that one approval.
+A device approving its **own** request with a controller key it holds (§13.4) obtains the
+confirmed pairing from its own stored request envelope, as the scan path does; no other device
+takes part, so §7.3's failure limit does not apply to it. A host MUST bind that envelope when the
+request is made and MUST NOT make a new request in its place before the approval.
```

```diff
 ### 17.3 Adding a key
 …
 3. An existing control key signs the transition that adds it with `control`. …
+
+**Adding a passkey on a device a passkey just admitted.** A device whose grant was signed by a
+controller passkey that opened its own slot in the same session MAY add a new passkey of its own
+platform as `approve` at once: one `keyring` entry that adds it with its slot, signed by that
+passkey, with the new key's possession proof and PRF from one assertion (§7.2). `control` follows
+by an ordinary transition.
```

---

## 5. Security analysis

**A stolen, unlocked device.** The thief holds the member key and whatever the local
authenticator unlocks. If the passkey is on the device and the device unlock satisfies UV, the
thief can sign grants, which are immediate under `memberRule` `single`, and add an `approve`
passkey. That is 0.5's existing exposure for any device holding a passkey, and this design
neither widens nor narrows it. Flow A adds one requirement: a confirmed pairing with the new
device. `control` additions still wait out the delay and can be vetoed. Recommendation: the SDK
shows every new grant and every immediate `keyring` entry on the person's other devices at their
next sync, alongside the §17.5 activations. Today §17.5 requires only activations.

**A malicious or buggy app layer.** Through the SDK it cannot delete live state: no call takes a
path or alias, and `discard` refuses the live generation after re-reading the pointer under the
lock. It cannot make the SDK approve the wrong request: approval takes an attempt handle whose
request bytes are bound (R8), and the pairing token binds the key (§9.1). It can still call the
platform's own delete APIs directly, which is out of the SDK's reach. It can show the person a
misleading label, which the pairing code and §17.5 display limit.

**A crash at each step.** Covered by the state table (§3.2) and the crash tables (§3.4, §3.5). In
every row the live generation is unchanged before C and is the attempt's after C. Signed grants
are never lost to a crash, because `granted` is persisted with the entry before the publish.

**A replayed or stale attempt.** History-read and member calls carry `created`, a call window and
a replay ID (§12.3, §12.4), so a recorded call is refused. An attempt past `expires` that never
signed is discarded. A stale invite checkpoint is caught by `account_verify_at_head`
(`refused:fork`, `refused:rollback`). An attempt verified against an older history than the live
generation's high-water mark is refused promotion (R11). An attempt for account X cannot be
promoted into account Y, because the pointer entry is keyed by the account ID the attempt
verified.

**A hostile home.** It can withhold the grant (the attempt stays `granted`, durable and
retryable), serve a cut-short history in which a removed passkey is still current (the known
§13.4 limit: a grant signed there is a fork other readers refuse, and R11 catches it on a device
that holds a newer state), refuse every call, and learn the account ID, the controller key ID and
timing. It cannot forge a grant, read the vault, or make the SDK delete anything. At
`headQuorum` above 1, the SDK should verify the other homes' heads before signing (§13.4 SHOULD,
not yet done by the SDKs; W4).

**What UV guarantees.** That the authenticator verified its user (biometric or PIN) for this
assertion over SHA-256 of the exact body (§4.3 step 1). It does not show the person what is being
approved, because authenticators display only the relying party. The host must show the request's
label, kind, custody and terms, and the pairing code, before the ceremony.

**Phishing and the relying party.** Every origin a browser allows for the `rp` can obtain that
passkey's signatures and PRF outputs (§3.2), so it can read `prf` slots. `authorityOrigins`
limits which origins' signatures count for authority entries, including grants and `keyring`
entries. It does not limit vault access. Native apps are bound by platform origin: Android
`apk-key-hash`, which `PasskeyController` adds to `origins`; Apple apps through associated
domains. A cross-device ceremony is bound to proximity by the platform. Recommendations: register
passkeys with `authorityOrigins` set (§17.3), offer `combined` slots for people who want no single
web origin able to open the vault (§7.2), and never run a non-production build against a
production `rp` (§3.2).

---

## 6. Test plan

### 6.1 Invariant

For every injected fault, take a **fingerprint** of the live generation before and after: the
pointer bytes; every file under its records and session directories, by path and SHA-256; the
set of its key names with their public points; and its device-secret entry, present or absent.
After any abandoned, failed, expired or crashed attempt that did not reach C, the fingerprints are
byte-identical. After C, the new generation is live and the old one is unchanged until
retirement.

### 6.2 Failure-injection matrix

Each step gets a hook, `AttemptHooks.before(step)`, following the existing `FolderMedium`
step hooks (Kotlin `FolderMedium` test hook, Node `FileMediumOptions.onStep`). At each hook, every
fault in the columns is injected, in each language (Swift, Kotlin JVM, Kotlin Android
instrumented, TypeScript in Node and in a browser).

| Step | throw | process kill (child-process kill as in `js/test05/kill-child.ts`; Android `Process.killProcess` in an instrumented test) | caller cancellation | storage full or read-only | key store failure | network drop after the server committed |
| --- | --- | --- | --- | --- | --- | --- |
| record written (`created`) | ✓ | ✓ | ✓ | ✓ | – | – |
| keys created | ✓ | ✓ | ✓ | – | ✓ (StrongBox refusal, Secure Enclave unavailable) | – |
| request stored (`requested`) | ✓ | ✓ | ✓ | ✓ | – | – |
| each history page / head read | ✓ | ✓ | ✓ | – | ✓ (passkey cancelled, wrong credential) | ✓ |
| history stored (`verified`) | ✓ | ✓ | ✓ | ✓ | – | – |
| slot unlock (PRF) | ✓ | ✓ | ✓ | – | ✓ (no PRF) | – |
| grant signed and stored (`granted`) | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| grant publish | ✓ | ✓ | ✓ | – | – | ✓ (the case F4 describes) |
| home confirmation (`admitted`) | ✓ | ✓ | ✓ | – | – | ✓ |
| P1–P7 | ✓ | ✓ | ✓ | ✓ | – | – |
| D1–D6 and the sweeper | ✓ | ✓ | ✓ | ✓ | ✓ (delete refused) | – |
| §4.6 keyring entry and P2 possession | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### 6.3 Scenario tests

- Every F1–F8 sequence from §1.3 as a regression test. Examples: an unreadable app settings file
  plus a dismissed prompt; cancellation at the final prompt; a grant committed and then a dropped
  confirmation; recovery started over a pending join; the request file deleted between display
  and approval; a stale attempt record next to an admitted generation; an expired join next to a
  live account.
- An unreadable or digest-mismatched pointer: no deletion, no promotion, `storageDamaged`.
- Two attempts for one account, both admitted: the first promotes, the second becomes
  `superseded`, and the revoke offer signs one `revoke`.
- Recovery over a live install, with and without unpublished writes in the old generation.
  Retirement waits as §3.7 says.
- R11: a home that serves an older fresh-signed history to an attempt over a live account
  (`refused:rollback`).
- Flow A against the reference relay with a software WebAuthn passkey (as the 0.5.7 tests do),
  then flow B, then §4.6 with P2's `control` transition pending and activated after a simulated
  delay.
- Migration: a 0.5.7 layout adopted as `legacy`, opened, used, then superseded by a recovery.
  `legacy` paths are never deleted.

### 6.4 Conformance vectors

There is no new history format, so no new required vectors. Add positive vectors under
`conformance/0.5/rules/` for the exact entries these flows produce, if they are not already
covered:

1. A `grant` by a WebAuthn controller from a platform authority origin.
2. A `grant` under `memberRule` `control` with `cosignatures`.
3. An immediate `keyring` that adds an `approve` passkey with its `prf` slot and possession proof.
4. The same with a possession proof from an origin outside `authorityOrigins` (`badSignature`).

The attempt record and pointer are local SDK formats. Each SDK checks them with golden-file
tests, and they share one JSON schema in `docs/` so that diagnostics are consistent.

---

## 7. Work breakdown

Sizes: S is up to 2 days, M up to a week, L up to two weeks, per language unless stated.

| # | Work | Size | Depends on |
| --- | --- | --- | --- |
| W1 | Account root, pointer, lock, generation layout; `legacy` adoption | M (each of Swift, Kotlin, TS) | – |
| W2 | Generation-scoped key and secret factories with open-only semantics (Keychain, Keystore, WebCrypto); device secrets and checkpoints keyed per generation; ledger moved to account scope | M | W1 |
| W3 | Attempt record, state machine, `discard`, sweeper, `diagnostics` | M | W1, W2 |
| W4 | Join and recovery on attempts; `approveWithPasskey`; 0.5.7 wrappers; other homes' heads at `headQuorum` above 1 | M | W3 |
| W5 | Promotion, supersession, retirement, revoke offer | M | W3 |
| W6 | `ColophonSession.approve(…, passkey)` (flow A) | S | – (any time) |
| W7 | `addPasskey` (§4.6) on attempts and sessions | M | W4, #115 part (a) |
| W8 | Failure-injection harness and the §6 matrix | L (all languages) | W3–W5 |
| W9 | JS port of `ColophonJoin` (join at head, passkey read) | M | – |
| W10 | Optional spec clarifications (§4.8), guide text | S | – |
| W11 | Recovery-transition attempts (`awaitingActivation`) | M | W5, #115 |

**Order.** W6 and W9 first: they are independent and unblock flow A everywhere. Then W1 to W3,
W4 and W5 with W8 alongside, then W7, then W11. **Everything here ships without a protocol
change.** W10 is editorial.

**What #115 should become: split.**

- **(a) Forward as is**, retargeted at `main`: `removeController`, `completeKeyChanges`,
  `restoreSlot`, `checkRemoval`, the `cosigners:` parameter, `HostDuties` additions and the
  `removeFollowUp` entropy fix. These act on a live, admitted session and touch no pre-admission
  state. The entropy fix should also go to `release/0.5` as a bug fix. Add the JS session parity
  it lacks.
- **(b) Rework on attempts**: `replaceController`'s staged path and the second passkey added on a
  joining device. Registering a new key while the device is not yet admitted must be
  attempt-scoped (§4.6), so it belongs in W7. On a live session, `replaceController` can stay as
  #115 wrote it.
- #115 notes that a one-transition replacement of the only slotted control key would need a
  transition's `vault` component to carry a slot for a controller it adds. That is open question
  Q7, and the staged path is enough without it.

---

## 8. Open questions for the protocol owner

- **Q1. Should "first passkey" have any protocol status?** *Recommendation: no.* The SDK selects
  any current WebAuthn controller with `approve` (or control under `memberRule` `control`) and its
  own slot (§4.1). Privileging seq-order would break after a replacement.
- **Q2. Must the home confirm before promotion?** *Recommendation: yes for any account with a
  home. Local verification is enough only for accounts with none.* Promoting on a grant the home
  has not accepted risks a displaced entry (§8.6) after the switch.
- **Q3. How long is a superseded generation kept?** *Recommendation: until the new generation is
  `Ready` and the old one's unpublished writes are flushed or unflushable, and at most 30 days.*
- **Q4. Revoke the superseded member automatically?** *Recommendation: offer it, signed by the
  same controller right after promotion. Never sign it silently.*
- **Q5. Let a passkey without a slot approve, using the approving member's epoch handles for
  `shares`?** *Recommendation: not in 0.6.* It needs a new core surface. The approving member
  must hold every historical epoch of every granted namespace (§9.2), and the default reference
  passkey has a slot.
- **Q6. Adopt the §4.8 clarifications?** *Recommendation: adopt both as editorial text in the 0.5
  revision that 0.6 references. They state existing behaviour.*
- **Q7. Let a transition's `vault` component carry a slot for a controller it adds?** (raised in
  #115) *Recommendation: defer.* The staged replacement is correct, and the change touches §8.3's
  slot-drop rule.
- **Q8. Attempt limits.** *Recommendation: four live attempts per root, one passkey ceremony at a
  time, and expiry of unsigned attempts after 24 hours (a code-path join after its invite's
  lifetime).*
- **Q9. Require UV for a passkey grant even when a controller lacks `verification`?**
  *Recommendation: yes, as SDK policy (`PasskeyAuthenticator` already demands UV).* The protocol
  stays as it is.
- **Q10. Show immediate grants and `keyring` entries as notices on other devices?**
  *Recommendation: yes, as a 0.6 SHOULD next to §17.5's activations.* Immediate entries are where
  a thief acts without a delay.
- **Q11. May the SDK delete a `legacy` generation's app-provided locations?** *Recommendation:
  never automatically.* Report it as retained, and let the app remove its own legacy paths after
  0.6 is adopted.

---

## Appendix: what was verified and what is inferred

**Verified in code at this revision:**

- In both SDKs, `ColophonJoin` writes requests and history into `configuration.medium` and uses
  `configuration.keys` (`OwnRequest.ensure`, `ColophonJoin.store`).
- `KeystoreKeys.openOrCreate` and `materialize` create a missing alias pair. `KeychainKeys.withKey`
  creates a missing item.
- Device secrets are keyed by account ID only, in all three languages.
- `SessionWorker.withOwner` and `unlockOwner` open the owner's slot and sign with the configured
  `ownerController`. `approveOwnRequest` uses the scan path.
- `leave()` deletes nothing.
- The genesis owner passkey has roles `approve`, `control`, `recover` with `verification`.
- The JS session has no passkey join.
- The pairing ledger lives in the private directory.
- `FolderMedium` (Swift, Kotlin) and Node `FileMedium` commit batches through a journal record.

**Inferred, not verified:**

- Behaviour of specific Android OEM Keystore implementations under process kill during deletion.
- `rename(2)` atomicity on every volume an App Group can be placed on.
- Whether existing conformance vectors already cover §6.4 items 1–3.
- The exact app-side sequences in §1.3, which come from review findings on an app's code, not
  from this repository.
