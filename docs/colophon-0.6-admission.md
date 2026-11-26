# Colophon 0.6 device admission: attempts, promotion and passkey-authorised adding

**Status:** design draft, revision 3, 2026-11-26, for review. Proposed for Colophon 0.6. It
changes no 0.5 wire object, verifier verdict, home route or path. It adds an SDK layer (admission
attempts and account generations) to the Swift, Kotlin and JavaScript sessions, and it makes
**two normative changes to the 0.5 host and core rules** (§4.9). Revisions 2 and 3 follow two
security design reviews. Their changes are listed in Appendices B and C.

**Goal.** Any device can add another device if a controller passkey of the account signs the
approval. The new device can then register a passkey of its own. This removes two failures. A
person no longer depends on one device or one passkey to get back in. A passkey can be added or
rotated from any device, without that device sharing storage with a live account.

**Conclusions in brief.**

1. **No new wire object, and no verifier or home change.** The approval is an ordinary `grant`
   (§9.2), signed under the single rule (§8.4) by a WebAuthn controller holding `approve`, after
   a confirmed pairing (§9.1). The new device's passkey is an ordinary immediate `keyring` entry.
   That entry needs `addThreshold` units holding `control` (§8.4), so the signing passkey must
   hold `control`.
2. **Two host and core rules are needed.** §9.1 does not yet authorise a device to approve its
   own stored request, which 0.5.7 does in code. And a confirmed pairing has no expiry, so an
   approval can arrive after the joining device has given up. The core must expire confirmed
   pairings, and approver hosts must drop approvals they could not deliver in time (§3.9, §4.9).
   Neither rule affects verification, the wire format or homes.
3. **The defect is in the SDK.** In 0.5.7 an attempt writes into the live account's storage and
   creates keys under the live account's names (§1). The fix:
   - each attempt gets its own **generation** of device-local state;
   - every name a generation uses is **derived** from the root and the generation ID, never read
     from metadata;
   - an **authenticated, transactional admission store** names the live generation, and its
     **epoch** fences every process;
   - promotion is one transaction, made only after the new generation has been reopened and
     exercised;
   - deletion acts only on a generation that the store's immutable manifest, re-read inside the
     transaction, shows is not live and was never admitted.
4. **Split the pending key-change work (#115)** (§7). Its pre-admission passkey parts move onto
   attempts. Its live removal and rotation parts are rebased and audited separately.

### Scope: what this delivers for the goal

**Admitting this device without another device.** This works when all of these hold:

- the person holds a current, non-suspended WebAuthn controller passkey with `approve`;
- that passkey has a vault slot of its own;
- its signature comes from an origin its descriptor allows for authority signatures (§4.3);
- the hosts are updated to 0.6;
- the account's `memberRule` is `single`.

That is sufficient. The same passkey admits a device from any other member device too (flow A).

**Limits.**

- Under `memberRule` `control`, the grant needs `threshold` control units, so cosigners may be
  required.
- A passkey that holds `approve` but not `control` cannot add a second passkey at once (§4.5). It
  can admit the device, and a control key adds the passkey later.
- Accounts are not covered when the first passkey lacks `approve`, lacks a slot of its own, or is
  registered without the app's platform origin in `authorityOrigins`. Such an account first needs
  a transition, signed by its existing control keys:
  - to add or grant a suitable passkey with a slot;
  - or to update the passkey's `authorityOrigins` (§8.4, the descriptor row).

  If the account has only recovery keys, it first needs a recovery transition (§4.8).

---

## 1. Problem

### 1.1 What 0.5.7 provides (verified in code)

- `ColophonJoin.readHistoryWithPasskey`, in Kotlin
  `sdk/kotlin/src/main/kotlin/com/luff/colophon/session/ColophonJoin.kt` and Swift
  `swift/Sources/ColophonSession/ColophonJoin.swift`, reads and verifies the history with
  `colophon.history.read` calls signed by a passkey (§13.4 "A device with a passkey"). It stores
  nothing.
- `ColophonJoin.approveOwnJoinWithPasskey(passkey, ownerKeyId, open)` runs these steps:
  1. `request()`: `OwnRequest.ensure` writes `requests/<member ID>.json` to `configuration.medium`,
     and the first use of `configuration.keys` creates the member key;
  2. it reads the history with the passkey;
  3. `ColophonJoin.store` writes the history and the request into the same medium;
  4. the app's `open` builds a session whose owner controller is the passkey;
  5. it checks that the store holds exactly the verified history;
  6. `ColophonSession.approveOwnRequest` scans the device's own stored request envelope, opens the
     passkey's own slot by PRF (`SessionWorker.withOwner`, `unlockOwner`) and signs a `grant`
     (`SessionWorker.approve`);
  7. it syncs up to `ATTEMPTS` times, then throws `unavailable` with the grant stored.
- `recoverWithPasskey` is `recovery(...)` (seq 1, the account ID as head) followed by the same
  steps.
- The JavaScript session (`js/src/session/`) has no join-at-head or passkey-join surface.
  Nothing there calls `verify_at_head` or `verify_with_passkey`.

### 1.2 What an attempt creates, and where

| State | Created by | Where (0.5.7) | Shared with a live account of the same app? |
| --- | --- | --- | --- |
| Member signing and agreement keys | first use of `configuration.keys` | Android: Keystore `<prefix>.signing` and `.agreement`, with the prefix chosen by the app; `KeystoreKeys.materialize` creates a missing pair. Apple: one Keychain item (`KeychainKeys`, default account `"member"`), which `withKey` creates when absent. Browser: a `WebCryptoKeyStore` record. | Yes, with the app's usual key configuration |
| Own request | `OwnRequest.ensure` | `requests/<member ID>.json` in the medium; regenerated when missing | Same medium |
| Authority history | `ColophonJoin.store` | `authority/<seq>.json` in the medium | Same medium |
| Journal, saved state, pairing ledger | the session `open` returns | `configuration.privateDirectory` | Same directory |
| Device key that seals saved state | `DeviceSecretStore.key(account)`, also in `withOwner` | keyed **by account ID only** (`KeystoreDeviceSecrets`, `KeychainDeviceSecrets`, `WebCryptoDeviceSecrets` `salt:<account>`); Swift `CheckpointCache` by library ID | Always, for an attempt on an account already present |
| Passkey descriptor used to rebuild the session | the app, inside `open` | the app's settings | The app's own state |
| A signed grant | `approveOwnRequest` | the medium, then the home | Live authority once published |

`ColophonSession.leave()` only sets `journal.left` (`SessionWorker.leave`), and the SDK has no
call that removes an account. Every deletion is therefore the app's, against paths and aliases
that attempts and live accounts share. The JVM `AtomicFile` helper (`PrivateState.kt`) falls back
to a non-atomic move when `ATOMIC_MOVE` is unsupported, and it ignores a failed directory sync.

### 1.3 Failure sequences found in practice

An app built join approval and recovery on these calls. Two security reviews of its rollback
logic found one class of fault each time:

- **F1. Missing metadata reads as "no account".** The app's settings file was missing, so its
  defaults said "no account" while the live record folder and key aliases survived. A recovery
  started, the person dismissed the prompt, and rollback deleted the live folder and aliases.
- **F2. A screen-owned task cancelled mid-approval.** The provisional session was published
  before the grant was signed. The interface replaced the screen, and the cancelled task rolled
  back.
- **F3. Process death between steps.** Keys and the request exist before the first prompt. Dying
  there left a request that conflicted with a later attempt. Dying at the last prompt left a
  saved descriptor, and the next launch reopened an unadmitted account on a screen that could
  not retry.
- **F4. A committed grant, then a failed confirmation.** The grant reached the home, the
  confirmation read failed in transport, and rollback deleted the keys of a member the history
  now admits.
- **F5. Recovery over a pending join.** A recovery deleted a pending join's keys and request
  (same aliases, same folder) before it checked the passkey.
- **F6. Approving the wrong request.** A queued self-approval approved whatever request was
  stored when it ran, and `ensure` silently made new request bytes when the file was missing.
- **F7. A marker cannot prove ownership.** An "attempt in progress" marker outlived admission.
  When the settings later became unreadable, restore treated the marker as permission and deleted
  an admitted account.
- **F8. Expiry deleted by census.** Expiring a pending join deleted every alias and the whole
  folder, because a join and a live account look identical. The guard had to prove by inventory
  that nothing else existed, and it had to run before a lookup that could itself delete.
- **F9. Late approval.** Another device can still hold a confirmed pairing, or an unpublished
  approval, after the joining device has given up and deleted its keys. When that grant arrives,
  it admits a member whose keys no longer exist.

### 1.4 Why an app cannot fix it from outside the SDK

- The SDK writes into the configured live storage and creates keys under live names on first
  use.
- Keystore aliases cannot be renamed, so an app that stages an attempt elsewhere has to build its
  own generations and pointer.
- Device-secret and checkpoint caches are keyed by account ID, so an attempt on an account
  already present collides with the live account whatever paths the app chooses.
- Only the engine knows whether a grant exists, and it writes the grant before it reconciles.
- Each app re-implements the same deletion logic on each platform, with the same mistakes.

---

## 2. Requirements

- **R1. Disjoint, derived names.** Every path, Keychain item, Keystore alias, IndexedDB record and
  device-secret entry of a generation is a pure function of the root and the generation ID. No
  name is ever read from metadata. Generation IDs match `^[0-9a-f]{32}$`. Creating a generation
  fails if any of its derived names already exists.
- **R2. Abandoning cannot touch live state.** After any abandoned, failed, expired or crashed
  attempt, the live generation's fingerprint (§6.1) is byte-identical.
- **R3. Deletion by authenticated ownership.** The SDK deletes only a generation that meets all
  of these:
  - its immutable manifest exists, authenticates under the root key and is re-read in the
    deleting transaction;
  - it is not live and never was;
  - its own contents show no admission (§3.8).

  Missing, unreadable or unauthenticated metadata never permits a deletion.
- **R4. Durable, validated promotion.** Promotion is one transaction in a store that is durable
  when it reports success. Before that transaction, the new generation is reopened from storage
  and must sign with its member key, open its device secret and decrypt its own epoch shares. A
  backend without atomic, durable commits is refused.
- **R5. Post-commit repair.** If the live generation is unusable after promotion, the previous
  generation is kept. There is no automatic switch back, and never a switch to a generation whose
  member is revoked in the latest verified history.
- **R6. Durable attempts; non-cancellable signing.** Cancellation never causes cleanup. Signing a
  grant and recording `granted` form one non-cancellable unit. A grant for the attempt's own
  member, signed on this device, is never discarded without the person's action. §4.9's delivery
  bound applies only to grants of another device's request.
- **R7. Fencing.** Every mutation of admission state is a versioned compare-and-set. No signature
  is stored or sent until a compare-and-set made after signing confirms that the epoch is
  unchanged (§3.6). Leases are judged by observation on monotonic clocks, never by wall-clock
  expiry.
- **R8. Late approval is bounded, then tombstoned.** Approvals are signed within a bounded time of
  pairing. A joining device keeps a disclosed request's keys for exactly 24 hours and 600 s after
  it last disclosed it, then deletes them and keeps a permanent tombstone. Withdrawal is advisory
  to conforming hosts. A late grant is detected, and a controller revokes it (§3.9).
- **R9. Bound inputs.** An attempt binds its account, home, invite checkpoint `(seq, head)`,
  member key and exact request bytes at creation. Nothing regenerates them.
- **R10. No destructive API for apps.** No call takes a path, an alias or a generation to delete.
  Discarding takes an attempt handle. App-provided legacy locations are never deleted.
- **R11. Rollback safety.** An attempt for an account already live on this device is promoted only
  if its verified history is not behind the live generation's persisted high-water mark (§17.2).
- **R12. Several attempts at once, and attempts over live accounts.**
- **R13. Parity:** Swift, Kotlin (JVM and Android), and TypeScript (browser and Node).

---

## 3. Design

### 3.1 Terms

- **Account root.** A directory, or an IndexedDB database, and a key namespace that the app gives
  the SDK. The SDK owns everything under it.
- **Generation.** One complete set of device-local state for one account: records medium, private
  directory, member keys, device secret and checkpoints. Its ID is 128 random bits in hex.
- **Admission store.** A transactional store under the root holding manifests, attempts, the
  pointer, leases and withdrawn requests (§3.4).
- **Live generation.** The generation that the store's `pointer` row names for an account.
- **Attempt.** A generation that is not live, together with its attempt row.

### 3.2 The admission store and the root key

The store must meet the contract the hosts' claim stores meet (`docs/hosts-06.md` §3a):

- compare-and-set, linearizable across every process and extension of the root;
- success reported only once the commit is durable;
- no commit visible before it is irrevocable;
- anything it does not recognise fails closed.

The claim-store work rejected file-and-lock designs, because a stealable lock and a commit
visible before it is irrevocable were both unsafe. They are rejected here for the same reasons.

| Platform | Store | Root key (MACs every row) | Created | If lost |
| --- | --- | --- | --- | --- |
| Apple | SQLite, the system library, with WAL and `synchronous=FULL`, in the app container or an App Group (as `SQLiteClaimStore`) | 32 random bytes in a Keychain generic-password item: `ThisDeviceOnly`, `AfterFirstUnlock`, not synchronisable, in the access group extensions share | at bootstrap by `SecItemAdd`; a duplicate means read it | §3.11 "Root key lost" |
| Android | platform SQLite (`android.database.sqlite`) with WAL, in `noBackupFilesDir` | Android Keystore HMAC-SHA256 key: non-exportable, no user authentication, StrongBox first then the TEE | at bootstrap; there is no software fallback | same |
| JVM | a host-supplied `AdmissionStore` meeting the contract (the JDK has no embedded SQLite) | host-supplied `RootKey` | host | same |
| Browser | IndexedDB through `AtomicPrivateStore.update`, one `readwrite` transaction (as `privateClaimStore`) | a non-extractable HMAC `CryptoKey` in IndexedDB, as `WebCryptoDeviceSecrets` keeps its master key | at bootstrap with `add`; a `ConstraintError` means read it | same |
| Node | a host-supplied `AdmissionStore`, or `node:sqlite` where the runtime has it; `FilePrivateStore` is refused, as `privateClaimStore` refuses it | host-supplied | host | same |

Each row is MACed as `HMAC(rootKey, table ‖ primary key ‖ version ‖ canonical row bytes)`. A
row that fails its MAC or cannot be parsed is **damaged**. Every operation on its account then
fails with `storageDamaged`, and nothing is deleted. What the MAC does and does not protect is in
§5.

**Creating the root key when several processes race.** Creation must never replace a key another
process made.

- **Apple.** `SecItemAdd` is atomic: a duplicate fails, and the loser reads the winner's item.
- **Browser.** `add` fails with `ConstraintError`, and the loser reads the existing key.
- **Android.** Keystore key generation **replaces** an existing alias silently. Two processes that
  both see "absent" and generate under one alias would each believe they hold the key. So the
  root key is never generated under a fixed alias:
  1. Each contender generates its own candidate `<N>.root.<c>`, where `c` is 128 random bits in
     hex.
  2. It then tries to insert the `root` row naming `c` in one store transaction. The row is MACed
     under that candidate key.
  3. The insert that commits wins. A loser deletes only its own candidate alias, by its own `c`,
     and adopts the winner's.

  The alias is derived from the validated `c` in the `root` row, under the same regex rule as
  generation IDs. The sweeper deletes a `<N>.root.*` alias only if it is one this process created
  and lost with.

**Host-supplied root keys (JVM and Node).** The guarantee here rests entirely on the host. A
host-supplied `RootKey` MUST be held where code that can write the store's files cannot read it.
For example: an operating-system key store, a hardware token, or a key file under another user
or another protection domain. It MUST NOT be a file beside the store or under the account root.
Without that isolation, the MAC detects corruption only. **On these platforms the SDK then gives
no protection against local tampering**, and the document claims none.

### 3.3 Derived names

Given the root `R` (its canonical, link-free path or database name), the app namespace `N` and the
generation ID `g`:

```text
records        R/generations/g/records/
private        R/generations/g/session/
trash          R/trash/g/
member keys    Keychain service N, account "g.<g>.member"   |  Keystore "<N>.g.<g>.member.signing" and ".agreement"
                                                            |  WebCryptoKeyStore id "<g>/member"
device secret  "<account>.<g>"   (KeychainDeviceSecrets account, KeystoreDeviceSecrets file, WebCrypto salt name)
records (web)  IndexedDBMedium "<R>.<g>"
```

`N` matches `^[A-Za-z0-9._-]{1,40}$`, which keeps Keystore aliases under 80 characters. Every
file operation resolves `R` once, opens each component without following links (`O_NOFOLLOW`;
`LinkOption.NOFOLLOW_LINKS` on the JVM), and refuses any symbolic link, linked directory or
unexpected kind of entry. A tree is deleted by descending without following links. No metadata
row holds a path, alias or item name.

### 3.4 Rows

| Row | Key | Fields | Mutability |
| --- | --- | --- | --- |
| `root` | – | format, created, store ID (random) | written once, at bootstrap |
| `manifest` | `g` | account, origin (`join`, `recovery`, `selfApproval`, `legacy`), created, member ID | **immutable** after insert, except that the member ID is set once; kept until the generation's deletion completes (D7) |
| `attempt` | `g` | state (§3.5), version, home, checkpoint, request digest, disclosed-at, grant `(seq, digest)`, signer key ID, passkeys added, expires | versioned compare-and-set |
| `pointer` | account | live `g`, previous `[g]`, **epoch** (raised by every promotion, retirement and repair), high-water `(seq, digest)` | versioned compare-and-set |
| `lease` | (`g`, holder) | boot ID, incarnation, heartbeat counter, epoch seen | the holder increments the counter; observers judge expiry (§3.6) |
| `outbox` | (`g`, digest) | kind, epoch, delivered | inserted only by the post-sign compare-and-set (§3.6); removed once its effect is stored and, if it is to be published, receipted |
| `withdrawn` | (account, member ID) | request digest, disclosed-at, withdrawn-at, keys-deleted-at, late grant seen `(seq, digest)`, revoked | versioned; a **permanent tombstone**, removed only with the account root |

### 3.5 Attempt lifecycle

| State | Meaning | Leaves by |
| --- | --- | --- |
| `created` | rows written; no key exists | keys made, then `requested` |
| `requested` | member keys exist; the request is signed and stored in the generation | code path: `disclosed` on the first show, send or scan; passkey path: `reading` |
| `disclosed` | another device may hold the request or a confirmed pairing for it | a grant seen: `granted`; abandoned: `withdrawn`, never directly `discarding` |
| `reading` | passkey history read under way; nothing signed | `verified`; on failure, `requested` |
| `verified` | history verified and stored; signer recorded | one non-cancellable unit (sign, store, record), then `granted` |
| `granted` | a grant of this member from its exact request is in the generation's verified history | P0 (§3.7): `admitted`; displaced (§8.6): `verified` |
| `admitted` | P0 holds | the promotion transaction removes the row; the manifest stays |
| `superseded` | another generation was promoted for this account | the person revokes the member (§3.10), then `discarding`; or keeps it |
| `withdrawn` | a disclosed request was abandoned; files deleted; keys kept for the bound in §3.9 | a grant seen within the bound: the person chooses between reviving it as `granted` and revoking it; the bound passes: keys deleted, then `discarding`. The `withdrawn` tombstone row stays. |
| `awaitingActivation` | a recovery transition is pending (W11) | final: `verified`; vetoed: `requested` |
| `discarding` | tombstone: deletion under way (§3.8) | rows removed |

Automatic expiry applies only to `created`, `requested` and `reading`: attempts that were never
disclosed and never signed. Every transition is a compare-and-set on `attempt.version`, made
under the epoch the caller holds.

### 3.6 Leases and fencing

A check made before signing cannot fence a signature. A process can read the epoch, be
suspended, and resume after a promotion has committed, still holding an open Keychain or Keystore
key. So the fence sits **after** signing, at the one point where a signature can take effect.

- **The outbox commit.** A signature can take effect in three ways: stored in a medium, sent to a
  home, or handed to another device. Before any of these, the session commits one store
  transaction that:
  1. compares the `pointer` epoch with the epoch it opened under;
  2. compares the generation's `attempt` or session version;
  3. inserts an `outbox` row: generation, digest, kind, epoch.

  This covers authority entries, transitions, vetoes, `suspend`, record headers and live values,
  seed transfers, and links. If the compare fails, the signature is **discarded**, its bytes are
  wiped, and nothing is stored or sent.
- **The commit is the point of effect.** A medium write and a publish happen only for a committed
  `outbox` row, and roll forward from it. Promotion is a transaction on the same store, so the two
  are totally ordered:
  - an outbox row committed before promotion is the old generation's work, done while it was
    live, and is kept (§3.10);
  - one attempted after promotion fails its compare.
- **Calls are exempt.** Calls carry their own window and replay protection (§12.3), and they
  authenticate reads. They need no outbox row.
- **Leases.** A lease holder is identified by a boot ID, a process incarnation and a random value:
  `kern.bootsessionuuid` on Apple, `/proc/sys/kernel/random/boot_id` on Android and Linux, and a
  value in session storage per page or worker in browsers.
  - The holder increments a heartbeat counter in its `lease` row every 15 s of its own monotonic
    time.
  - An observer treats a lease as expired only after 60 s of the **observer's own monotonic
    clock** with no change to the counter, or when the boot ID differs from its own.
  - Wall-clock time is never compared.
  - Leases only delay deletion. The outbox commit, not the lease, fences signing.
- **App extensions.** An extension is an ordinary lease holder, and it makes the same outbox commit
  in the shared App Group store. The system can suspend an extension indefinitely. While it is
  suspended its heartbeat stops, its lease expires by observation, and the previous generation may
  be retired. When it resumes, it opens with the old epoch:
  - its next outbox compare fails, so any signature it made is discarded;
  - its medium writes are refused, because every write needs a committed outbox row;
  - deletion renames the directory before removing it, so any open handle reaches only unlinked
    files.
- **What is still lost.** Nothing signed is ever lost unnoticed. Only local work that never
  reached an outbox commit is lost, such as an edit typed in a suspended extension, and the
  session reports it as `superseded`.
- Promotion and deletion are single store transactions that compare the pointer and attempt
  versions. There is no lock for another process to steal.

### 3.7 Promotion

**P0, admitted.** All of these must hold:

- the generation's own store verifies, from seq 1, a history holding a current grant of its member
  from its exact request;
- durable home state confirms the grant: fresh heads covering it from the homes Q3 settles, read
  with the member's own key (the `fetchHistory` acceptance);
- if a generation is already live for the account, the attempt's verified tip is not behind
  `pointer.high-water`, or promotion fails with `refused:rollback`.

An account with no home cannot be promoted by an attempt. It joins through its shared folder, as
0.5 provides.

**Durability capability.** Each backend reports `atomicCommit` and `durableSync` for the store and
the media. If either is missing, promotion is refused (`unsupported`). The SDK's file helpers never
fall back from `ATOMIC_MOVE`, and they fail on a failed directory sync.

| Step | Action |
| --- | --- |
| V1 | Close the attempt's own sessions. Complete committed medium batches. Sync the generation's tree. |
| V2 | Open a fresh engine on the generation from storage alone, with the member identity. Verify the history again: `ok`, and the grant current. |
| V3 | Open the member keys by derived name with an **open-only** call, through **the exact key factory the live session will use**: the same Keychain access group, `kSecAttrAccessible` class and access-control flags; on Android, the same `KeystorePresence`/user-authentication and StrongBox settings. Sign a fresh challenge and verify it against the member signing point in the grant. ECDH with the agreement key, and open one epoch share sealed to it when the grant has `records`. |
| V4 | Open the device secret through the live factory. Save and reload sealed state (§17.2) once. |
| V4a | **Check the live access path, not only this foreground process.** Read back each key's and secret's attributes (Apple: access group, accessibility class, access control; Android: `KeyInfo` user-authentication requirement, validity window, StrongBox) and compare them with what `SessionTemplate` declares: background sync, and, where the app has an extension, the extension's access group. Refuse promotion (`unsupported`) when a declared path cannot open the keys without the person, for example `WhenUnlocked` items for a background sync, or an item outside the extension's group. Where the platform lets the SDK run the extension's or the background task's open (a test hook, an app-declared probe), run it. A prompt shown during validation never counts as proof for a path that cannot show one. |
| V5 | Shared medium only (iCloud or shared-folder locations): write the generation's request and history there with write-if-absent and a same-bytes check (as `ColophonJoin.store`), then sync. These files are immutable and belong to this member, so writing them before the commit is safe. |
| **C** | **One store transaction:** compare the pointer and attempt versions; set `pointer.live = g`; append the old live generation to `previous`; raise `epoch` by 1; set `high-water`; remove the attempt row; mark the account's other attempts `superseded`. It reports success only when durable. |
| P1 | Open the session on the new generation under the new epoch. |

If anything in V1 to V5 fails, nothing changes and the attempt stays `admitted`.

If P1 fails after C (a key lost after the commit, for example), the account enters **repair**.
The previous generation is kept whatever its retention, and the SDK reports `repairNeeded` with
three choices:

- retry the validation;
- start a recovery into a new attempt;
- switch back to the previous generation. This is offered only when its member is current in the
  latest verified history any of this account's generations holds, and only by the person's
  choice. Switching back is itself a promotion, through V1 to V4a.

**Crash table.**

| Crash during | On next open | Which state wins |
| --- | --- | --- |
| V1–V5 | attempt `admitted`, pointer unchanged | the old live generation. Promotion resumes on `attempt.promote()`. Any shared-medium files are immutable copies. |
| C | the transaction committed or it did not (SQLite and IndexedDB guarantee one or the other) | old if not committed, new if committed |
| P1 | the pointer names the new generation | new; P1 retried, then repair |

### 3.8 Deletion: discard and retirement

`discard(g)` is the only deletion routine. Its targets are derived (§3.3), never read.

| Step | Action | Crash after it |
| --- | --- | --- |
| D1 | In one transaction: the `manifest` and `attempt` rows of `g` authenticate; `g` is neither `pointer.live` nor in `previous` (except for retirement, §3.10); no unexpired lease on `g` (judged as §3.6 says); no undelivered `outbox` row of `g` (for a retirement: or its member can no longer sign, or the retention has passed, §3.10); its state is eligible (§3.5). Set it to `discarding`, version + 1. | nothing deleted; resumes |
| D2 | **Content check.** Open `g`'s medium read-only. If it holds a grant of the manifest's member, stop with `storageDamaged`, unless this is a retirement or a `superseded` or `withdrawn` attempt whose reconciliation is recorded. A store rolled back to an older copy therefore cannot get an admitted generation deleted (§5). | resumes at D2 |
| D3 | Delete the derived member keys (a missing one is a no-op). | resumes |
| D4 | Delete the derived device-secret entry. | resumes |
| D5 | Rename `generations/g` to `trash/g` (refused if that exists), then delete it without following links. | the sweeper finishes `trash/g` only for a `g` whose manifest says `discarding` |
| D6 | Browser: delete `IndexedDBMedium` `<R>.<g>`. | resumes |
| D7 | In one transaction, remove the `attempt` row and then the `manifest` row. | done |

The sweeper runs at `open`. It finishes `discarding` generations, expires eligible attempts, and
empties `trash/<g>` only for a `g` whose manifest says `discarding`. A directory, alias or item it
finds without a manifest is reported by `diagnostics()` and left alone.

### 3.9 Late approval

**What 0.5 allows today.**

- A request (§9.1) has `created` but no expiry, and its field set is closed (§2.3). A new field
  would make it `malformed` for every 0.5 reader.
- A confirmed pairing has no expiry after confirmation. The ten-minute timeout covers the reveal
  (`docs/bindings-05.md`, `pairing:timeout`). That the token lives only in memory and does not
  survive the process is inferred.
- A grant can be signed and stored, then published days later (§17.5 "Submitting").
- A home serves no withdrawal, and a non-member cannot sign one.
- Any `approve` controller can revoke a member (§9.5, single rule).

**Discarding is not cancelling.** Nothing in 0.5 lets a joining device cancel its request. A
grant of it remains valid authority whenever it is published, and every verifier accepts it.
Withdrawal is therefore **advisory**. Conforming hosts honour it, by the two rules below. A buggy
or dishonest approver can still publish a grant weeks later. The design bounds what conforming
hosts do, then detects and repairs what others do.

**Design.**

1. **Bound when an approval is signed** (core rule, normative, §4.9). The core refuses to finish a
   grant, or a `grant` component, that consumes a confirmed pairing more than 600 s after the
   pairing was confirmed (on the scan path, after the scan). The pairing is never persisted.
2. **Bound when an approval is delivered** (host rule, normative, §4.9). An approving host does not
   publish a grant **of another device's request** that no home has accepted 24 hours after its
   `issued`. It discards the grant, which as an unpublished local entry no home holds, and tells the
   person. A device's grant of its own request is exempt (R6): its keys exist, so no orphan can
   arise.
3. **Bounded key retention, then a tombstone.** Abandoning a `disclosed` attempt makes it
   `withdrawn`. Its records and private files are deleted at once. Its member keys are kept for
   **exactly 24 hours and 600 s after the last disclosure**, the longest a conforming approver can
   take under rules 1 and 2.
   - **During that time**, the device checks in the background with the member key, with no passkey
     prompt. It reads the history at the home with `colophon.history.read`, which the home answers
     `refused:revoked` until a grant names the key (§13.4). If a grant appears, the person chooses
     between "Open it", which revives the attempt as `granted`, and "Remove it", which revokes the
     member (item 5).
   - **When the bound passes**, the keys are deleted (§3.8 D3) and the generation is discarded. The
     `withdrawn` row stays as a **permanent tombstone**: member ID, request digest, the times, and
     `keys-deleted-at`.
4. **A late grant after the tombstone.** Only a non-conforming approver can produce one.
   - **Effect.** The device does not become a member in practice. Nothing holds the member's private
     keys, so no one can sign as it or open the shares sealed to it. On the reference platforms
     those keys were non-exportable. A software key copied before deletion is the exception, and
     the rest of this item still applies to it.
   - **Detection.** Any device that verifies the account's history detects the grant:
     - a later generation of this account on this device, against its tombstones;
     - every member and controller device, through the new-grant notice (Q4).
   - **Shown as.** "A device that withdrew its request was added later", with the approver's key
     ID and label.
5. **Revoking the orphan member.** A revocation (§9.5) by any current controller holding `approve`
   (single rule), or `control` units meeting `threshold` when `memberRule` is `control` (control
   rule), with UV when the controller has `verification`. The member cannot revoke itself.
   - **Its own key.** It signs only its own `endSessions` (§9.7), and a deleted key cannot sign even
     that.
   - **What the SDK does.** On every device that holds such a controller, it shows a one-tap
     "Remove" that builds the `revoke` with `kept` covering everything. Where the approver key
     belongs to the person, the revocation counts as the §17.5 removal follow-up.

**Option not adopted: a binding withdrawal.** This is an owner decision (Q5). Withdrawal could be
made binding on every verifier, so that a deliberate discard is cryptographically final. There
are two ways:

- an expiry inside the request (for example `notAfter`), with verifiers refusing a grant whose
  `issued` is later;
- a withdrawal object signed by the request's member key, which homes store and serve, and which
  verifiers apply by refusing a later grant of that request.

Either one costs all of the following:

- **A format change.** Requests have closed field sets (§2.3), and a new object kind is unknown to
  0.5 readers, so either is `malformed` there.
- **A layout raise per account.** Authority must agree across readers, so either needs a raise
  (§8.2): a pending transition with consent that stops every 0.5 reader of the account once it is
  final (§1). Every device of the account must upgrade first.
- **Home work.** For the withdrawal object, a new home route and storage, with history-read rules
  for it.
- **Verification and tests.** A new verifier rule and conformance vectors.
- **Clock judgement.** With `notAfter`, each verifier judges `issued` against the request's
  `notAfter`. Approvers can backdate `issued` only within §8.1's ordering, so the bound is
  approximate.

Against that cost, the option removes only the residual of items 4 and 5: an approver that ignores
the rules. Such an approver controls `approve` and can admit any key it likes anyway.
**Recommendation:** do not adopt it for 0.6; reconsider at the next layout raise.

### 3.10 An attempt over a live account, and retirement

A re-join or recovery on a device that already has a live generation for the account (lost keys,
a revoked member, a damaged store) gets a new generation and a new member, because §3.3 forbids
reusing member points. The old generation keeps running until C. From then the epoch fences it
(§3.6), and it moves to `previous`. It is **retired** with `discard` when all of these hold:

- the new generation is `Ready` at a fresh head;
- the old generation holds no lease;
- its outbox is empty, its member key cannot sign, or the retention period has passed (Q1);
- it is not needed for repair (§3.7).

Until then it can be **exported** read-only (`exportRetained`). If its member is still current,
the SDK offers to revoke it, with `kept` covering everything (§9.5), signed by the controller that
approved the new member. It never revokes silently.

### 3.11 Migration and bootstrap

**Bootstrap order.** Bootstrap runs in a fixed order, so every interrupted state can be told apart:

1. Create the store, with a single unauthenticated `bootstrap` row, `{"state":"creating"}`. This
   row authorises nothing.
2. Create the root key, by the race rules in §3.2.
3. Insert the MACed `root` row, in one transaction. Once it commits, the store is bootstrapped.

**Generation storage** means any of these:

- a `R/generations/` or `R/trash/` entry;
- a Keystore alias `<N>.g.*`;
- a Keychain item `g.*` under service `N`;
- an IndexedDB database `<R>.*`.

The SDK probes for each of them before treating a root as new.

| Store | Root key | Generation storage | Meaning | Action |
| --- | --- | --- | --- | --- |
| absent | absent | none | **first run, never migrated** | bootstrap when the app asks |
| absent | absent | present | a reset or deletion that left generations behind | **`storageDamaged`, never treated as a fresh install**; nothing deleted; `repair()` |
| absent | present | any | the store was lost | `storageDamaged`; `repair()` |
| `bootstrap` row only | absent, or one candidate | none | interrupted at step 2 or 3 | resume the bootstrap |
| `bootstrap` row only | any | present | inconsistent | `storageDamaged`; `repair()` |
| `root` row, rows authenticate | present | any | normal | – |
| a row fails its MAC | present | any | damaged | `storageDamaged` for that account |
| `root` row | absent or unusable | any | root key lost | see "Root key lost" below |

**Bootstrapping a 0.5.x install.** `ColophonAccounts.adoptLegacy(configuration)` adopts it, since
only the app can say a configuration is a live account. It is one store transaction that creates
three rows:

- `root`;
- a `manifest` with origin `legacy` and the member ID read from the journal or request;
- a `pointer` naming that manifest.

A `legacy` generation's locations are the app's own. The SDK records a fingerprint of them, and it
**never deletes, moves or writes outside them**. `adoptLegacy` runs after the bootstrap, as its own
transaction. If it did not commit, the app calls it again. An app-provided legacy location never
counts as generation storage, because only the app can vouch for it.

**Upgrading with a 0.5.7 attempt in flight.** The SDK cannot see attempts the app built itself.
The app adopts only the configuration it holds as live, and a grant that its earlier flow stored
there is picked up by the legacy session's ordinary reconciliation. Staging directories the app
built stay the app's.

**Root key lost** (Keystore wiped, a restore to another device, a cleared site key). No row
authenticates, so nothing is deleted or promoted. `repair()` lists the generations found under the
derived names. For each it verifies the history held there and checks the member key against a
current member. The person then picks the live generation, and the SDK writes a new root key and
store, with a fresh `manifest` for each generation found. Generations not picked are kept until the
person discards them.

### 3.12 API sketch

All three languages expose the same types. Names follow each language's conventions.

**Kotlin**

```kotlin
class ColophonAccounts(root: AccountRoot)       // directory, namespace, AdmissionStore, RootKey, key and secret factories
    suspend fun adoptLegacy(configuration: SessionConfiguration)
    suspend fun open(account: String, template: SessionTemplate): ColophonSession
    suspend fun attempts(account: String? = null): List<AttemptInfo>
    suspend fun beginJoin(invite: JoinTarget, template: SessionTemplate): AdmissionAttempt
    suspend fun beginRecovery(target: RecoveryTarget, template: SessionTemplate): AdmissionAttempt
    suspend fun attempt(id: String): AdmissionAttempt?
    suspend fun repair(): RepairReport                  // deletes nothing without the person's choice
    suspend fun exportRetained(generation: String, into: RecordMedium)
    fun diagnostics(): RootDiagnostics

class AdmissionAttempt
    val id: String; val account: String; val kind: AttemptKind
    val state: StateFlow<AttemptState>
    suspend fun request(): ByteArray                    // the bound bytes; marks the attempt disclosed
    suspend fun joinPairing(): AccountPairing           // marks it disclosed
    suspend fun approveWithPasskey(passkey: PasskeyAuthenticator, ownerKeyId: String? = null): AttemptState
    suspend fun addPasskey(registrar: PasskeyRegistrar, label: String): AttemptState   // §4.6
    suspend fun promote(): ColophonSession
    suspend fun abandon()                               // discarding, or withdrawn when disclosed
    suspend fun revokeMember(passkey: PasskeyAuthenticator)   // superseded, or withdrawn and granted

suspend fun ColophonSession.approve(request: AccessRequest, pairing: AccountPairing, passkey: PasskeyAuthenticator, ownerKeyId: String? = null)
```

**Swift**

```swift
public actor ColophonAccounts {
    public init(root: AccountRoot)
    public func adoptLegacy(_ configuration: SessionConfiguration) async throws
    @MainActor public func open(_ account: String, template: SessionTemplate) async throws -> ColophonSession
    public func attempts(for account: String? = nil) async throws -> [AttemptInfo]
    public func beginJoin(_ invite: JoinTarget, template: SessionTemplate) async throws -> AdmissionAttempt
    public func beginRecovery(_ target: RecoveryTarget, template: SessionTemplate) async throws -> AdmissionAttempt
    public func repair() async throws -> RepairReport
    public func exportRetained(_ generation: String, into medium: any RecordMedium) async throws
}
public actor AdmissionAttempt {
    public nonisolated let id: String
    public var state: AttemptState { get async }
    public var updates: AsyncStream<AttemptState> { get }
    public func request() async throws -> Data
    public func approve(with passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil) async throws -> AttemptState
    public func addPasskey(_ registrar: any PasskeyRegistrar, label: String) async throws -> AttemptState
    @MainActor public func promote() async throws -> ColophonSession
    public func abandon() async throws
    public func revokeMember(with passkey: any PasskeyAuthenticator) async throws
}
extension ColophonSession {
    public func approve(_ request: AccessRequest, pairing: AccountPairing, with passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil) async throws
}
```

**TypeScript**

```ts
class ColophonAccounts {
  static open(root: AccountRoot): Promise<ColophonAccounts>;   // root.store: IndexedDB, or host-supplied in Node
  adoptLegacy(configuration: SessionConfiguration): Promise<void>;
  open(account: string, template: SessionTemplate): Promise<ColophonSession>;
  attempts(account?: string): Promise<AttemptInfo[]>;
  beginJoin(invite: JoinTarget, template: SessionTemplate): Promise<AdmissionAttempt>;
  beginRecovery(target: RecoveryTarget, template: SessionTemplate): Promise<AdmissionAttempt>;
  repair(): Promise<RepairReport>;
  exportRetained(generation: string, into: RecordMedium): Promise<void>;
}
interface AdmissionAttempt {
  readonly id: string; readonly account: string; readonly kind: AttemptKind;
  state(): Promise<AttemptState>; onState(listener: (s: AttemptState) => void): () => void;
  request(): Promise<Uint8Array>;
  approveWithPasskey(passkey: PasskeyAuthenticator, ownerKeyId?: string): Promise<AttemptState>;
  addPasskey(registrar: PasskeyRegistrar, label: string): Promise<AttemptState>;
  promote(): Promise<ColophonSession>;
  abandon(): Promise<void>;
  revokeMember(passkey: PasskeyAuthenticator): Promise<void>;
}
```

`SessionTemplate` is today's `SessionConfiguration` without storage, keys and device secrets,
which the root supplies per generation.

### 3.13 What happens to the 0.5.7 calls

The aim is that apps never clean up. Unsafe forms are therefore removed in 0.6, not kept as
deprecated wrappers.

| 0.5.7 call | 0.6 |
| --- | --- |
| `ColophonJoin.readHistoryWithPasskey` | Kept. It is pure and stores nothing. |
| `ColophonJoin(configuration, …)`: `request()`, `fetchHistory()` | **Removed** from the public surface. They write to the configured live storage and create live keys (F5, F6). Use `beginJoin`. |
| `approveOwnJoinWithPasskey`, `recoverWithPasskey` | **Removed** as calls that take a configuration. They exist only on attempts. A final 0.5.x release marks them deprecated and states the hazard. |
| `ColophonSession.approveOwnRequest(expected)` | Internal; the attempt passes the bound request. |
| `leave()` / `rejoin(keys)` | `leave` is unchanged (it deletes nothing). `rejoin` is replaced by `beginJoin`. |
| `SessionConfiguration` | Unchanged, for `adoptLegacy` and apps that do not use attempts. |
| JavaScript | Attempts and a port of the passkey read are added. |

### 3.14 How each failure sequence is prevented

| Sequence | Prevented by |
| --- | --- |
| F1 | Liveness comes from the authenticated `pointer`, never from app settings. Names are derived. Deletion is refused for the live generation and for any generation whose contents show admission (D1, D2). |
| F2 | Cancellation is never cleanup. Sign, store and record `granted` is one non-cancellable unit. Nothing is shown as the account before C. |
| F3 | Every state is durable and listed by `attempts()`. An unadmitted generation is never live. |
| F4 | `granted` is persisted with the entry before publishing. Signed attempts are never discarded automatically. P0 waits for durable home state. |
| F5 | A pending join is its own generation, unreachable by other attempts' names. |
| F6 | Approval takes an attempt handle with bound request bytes. Nothing regenerates a request. |
| F7 | No marker grants deletion. Deletion needs an authenticated manifest, a never-live check in one transaction, and the content check. |
| F8 | Expiry discards the derived names of one non-live generation. No inventory is needed. |
| F9 | Bounded for conforming approvers by the pairing and delivery rules (§3.9 items 1 and 2). A grant arriving within the key-retention bound can be used (item 3). After that, a permanent tombstone, notices and a controller's revocation handle it (items 4 and 5). It is **not prevented** for a non-conforming approver; only the binding option (Q5) would prevent that. Until the §4.9 rules ship, the bounds hold only for grants signed by updated hosts. |

---

## 4. Adding another device with a controller passkey

### 4.1 What "the library's first passkey" is

0.5 has no notion of a first passkey. The reference sessions create the genesis owner controller
with roles `approve`, `control` and `recover`, with `verification: true` for a passkey, and with a
`prf` slot. See Swift `SessionWorker.swift`, the genesis `ControllerSpec(… roles: [.approve,
.control, .recover], verification: isPasskey …)`; Kotlin mirrors it. Its authority is exactly that
of its roles (§6.1, §8.4).

This design therefore selects "the passkey" by capability, never by seq:

- **to approve:** a current, non-suspended WebAuthn controller with `approve` (or `control` when
  `memberRule` is `control`) and a slot of its own;
- **to add a passkey at once:** the same, and it must hold `control`.

### 4.2 Flow A: a device that holds the account adds a new device

Device A is a current member, and device B is new. The passkey is available on A, synced there or
reached by a cross-device (hybrid) ceremony.

1. B calls `beginJoin`. The attempt becomes `disclosed` when the request or its commitment is
   shown.
2. A and B pair on B's member signing key (§7.3, §9.1), and A's core issues the confirmed pairing.
3. A calls `session.approve(request, pairing, passkey)`. A controller engine opens over A's store
   with the passkey as signer, as `withOwner` does, but the passkey is given per call.
   - One assertion with PRF opens the passkey's slot.
   - The core prepares the `grant`: terms covered by the request, and `shares` sealing every
     historical epoch of each granted namespace to B's agreement key (§9.2).
   - A second assertion, with UV, signs it within 600 s of the pairing (§3.9).
4. A publishes the grant to the primary home, then to every home (§17.5).
5. B's attempt sees the grant (`granted`), waits for P0 (`admitted`), and promotes.

### 4.3 Flow B: the new device approves itself

`approveWithPasskey` on B runs these steps:

1. read the history with the passkey (§13.4);
2. store it (`verified`);
3. take the confirmed pairing from its own bound request envelope, as §4.9 authorises;
4. open the passkey's slot;
5. sign and record `granted`, as one non-cancellable unit;
6. sync, wait for P0, and promote.

### 4.4 Who signs what, and what the home and history see

| Step | Signed by | Sent to the home | Recorded |
| --- | --- | --- | --- |
| History read (flow B) | passkey, one `colophon.history.read` call per 64-entry page | `GET /authority` | nothing; replay-checked (§12.4) |
| Request | B's member key, `raw` | nothing | embedded in the grant |
| Slot unlock | passkey PRF | nothing | nothing |
| Grant | passkey, from an authority origin (§4.3), UV because `verification: true` | `POST /authority` | `grant`: `by` is the passkey key ID; `request`, `terms`, `shares` |

The home sees an ordinary immediate entry, charged to the passkey's rate (`policy.rate`).

### 4.5 Rules, exactly

| Change | Rule (0.5) | Immediate? |
| --- | --- | --- |
| Grant, `memberRule` `single` | single rule: exactly one signer holding `approve` (§8.4); UV when the controller has `verification` (§4.3 step 3, §8.4 "UV") | yes |
| Grant, `memberRule` `control` | control rule: at least `threshold` `control` units, with UV (§8.4) | yes; cosignatures come from other devices |
| Add an `approve` passkey with its slot | immediate `keyring` entry: `addThreshold` units holding `control`, with UV, plus the new key's possession proof in `additions`; at most four controllers per entry (§8.4) | yes. An `approve`-only signer cannot make it. |
| Add `control` to that passkey | pending transition under the control rule (§8.4). Recovery-set consent is needed only if it also raises `threshold` or touches `recover` (§8.4 "Recovery-set consent"). | Only as a **full set (b)** (§8.7): at least two signer units; meets the control rule; **every current `control` controller** signed, including any it removes; every current `recover` controller signed if consent is needed. Possession proofs never count. Otherwise it is due after `recoveryDelay`. |
| Replace control controllers through recovery | recovery rule: every signer holds `recover`, at least `recoverThreshold` units; may remove any controllers and add replacements with `approve` and `control`, never `recover` (§8.4, first transition row) | Only as a **full set (a)**: at least two units and every current `recover` controller (§8.7). Otherwise pending, vetoable and subject to escalation. |
| `import` | control rule; a `device` or `app` member (§9.3) | never through this flow |

A `recover`-only passkey cannot sign a grant. 0.5.7 refuses it, with `refused:outOfScope`, before
it stores or signs anything.

### 4.6 Adding a new passkey on the added device

B registers a passkey P2 on its platform, with UV, attestation none and `authorityOrigins` set
(§17.3 step 1).

1. **Add P2 at once as `approve`, with a slot.** This needs the approving passkey P1 to hold
   `control`, and B to hold the seed in this session. In flow B the seed comes from P1's slot, opened
   on B. In flow A it comes from a §7.4 transfer (§4.7). One `keyring` entry adds P2 with
   `["approve"]` and a `prf` slot built from P2's possession assertion with PRF (§7.2 "Building a
   PRF route"). P1 signs it.
2. **Give P2 `control`.** This follows §4.5. With P1 as the only control unit, it waits out
   `recoveryDelay`. If the account has a second control key, such as a device owner key, both
   signing make a full set, and it is immediate. The SDK proposes it, records it, and shows it as
   pending (§17.5).
3. **Mind the planter rule.** Keys P1 added by immediate entries can be removed together with P1.
   This happens when a later transition removes P1 while the vault is retiring, and P2 was added
   after that transition's anchor (§8.3 "Keys the removed key planted go too"), unless `keep`
   names P2 (recovery rule). Hosts list such keys for removal by default (§8.4 "Removal
   follow-up", §17.5). They also list the devices P1 admitted, for revocation (§17.5). So before P1
   is retired, the SDK makes sure that:
   - P2 holds `control`, activated and final;
   - the person keeps P2 and the devices P1 admitted out of the follow-up.
4. **A passkey that was never added.** If P2 was registered but never added, it stays in the
   person's credential manager. The attempt lists it as `registered`, and the host retries with the
   same credential. Credential managers offer no programmatic delete.

### 4.7 Moving the seed in flow A

The admission pairing binds B's member signing key. §7.4 instead seals the seed to a fresh
ephemeral agreement key `E`, under a label that carries that pairing's nonces. The admission
pairing cannot be reused for this: its key is a member signing key, and §3.3 forbids using a point
for more than one principal or usage.

Flow A therefore runs a **second pairing** (§7.3, with `E` the transfer key) while A's session
still holds the seed it opened from P1's slot. B opens the seed, checks the vault, builds P2's slot
and erases `E`. The other option is to ask for P1 once more, on B. Extending §7.4 so that one
pairing binds both keys is not proposed.

### 4.8 When the first passkey is lost or replaced

- **Replaced:** a transition removed P1 and added or promoted P2. P1's history reads are then
  answered `refused:revoked` (§13.4), and §4.1 selects P2.
- **Lost, with another approving controller:** run flow A or flow B with that controller, then
  remove P1 by transition. The vault retires and rotates (§8.3). Apply §4.6 item 3.
- **Lost, with only recovery keys:** a recovery transition (§4.5). The proposing device's attempt
  waits durably in `awaitingActivation` (W11).
- **Lost, with nothing else:** the account cannot be recovered. The §6.4 warnings and §4.6 exist to
  prevent this.

### 4.9 Spec changes

These change no wire object and no verifier verdict. They are normative changes to host and core
rules, proposed for the 0.5 revision that 0.6 references.

```diff
 ### 9.1 Membership request
 …
 to the exact `member.signing` of the request, and spent by that one approval. No interface approves a
 member from a member ID, a prefix of one or any other code.
+**Approving one's own request.** A device that holds a controller key permitted to approve
+(§8.4) MAY approve its own request without a second device. The confirmed pairing is then issued
+from the request envelope the device stored when it made the request, as if scanned from its own
+screen; the host MUST bind that envelope at creation and MUST NOT make another request for the same
+member before the approval. No other party takes part, so §7.3's failure limit does not apply.
+**Expiry.** A confirmed pairing expires 600 seconds after it is confirmed (on the scan path, after
+the scan) and is never persisted; the core refuses to finish a `grant`, or a `grant` component,
+that consumes an expired one.
```

```diff
 ### 17.5 Notices
 …
 - **Submitting.** Hosts MUST submit every transition, veto and `suspend` to every current home
   directly, and retry until each has receipted it or 300 s have passed; and publish entries to the
   primary home and then every home.
+- **Late approvals.** A host holding a signed `grant` of a request made by **another** device,
+  that no home has accepted 24 hours after its `issued`, MUST NOT publish it; it discards it and
+  tells the person the device was not added. A joining host that withdraws a request it has
+  shown or paired SHOULD keep its member keys for 24 hours and 600 s after it last did so, and
+  offer the person a grant of it seen in that time; it then deletes them and keeps a record of the
+  withdrawal. Withdrawal does not bind other hosts or verifiers: a grant of a withdrawn request
+  stays valid, and a host that sees one MUST show it with the offer to revoke the member (§9.5).
```

---

## 5. Security analysis

**A stolen, unlocked device.** If the passkey is on the device and the device unlock satisfies
UV, the thief can sign grants, which are immediate under `single`. With a `control` passkey, they
can also add an `approve` passkey. That is 0.5's existing exposure for any device holding such a
passkey. Flow A additionally needs a confirmed pairing within 600 s. `control` additions stay
pending and can be vetoed, unless the thief holds every control unit. Other devices should be
notified of new grants and immediate `keyring` entries (Q4).

**A buggy app or tampered files.** No SDK call takes a deletion target, targets are derived, and
links are refused. A record therefore cannot steer deletion onto live names, or onto anything
outside one generation's derived set. MACed rows cannot be forged by anything that writes files
without being able to use the root key: a backup restore, corruption, an app editing files
directly, another SDK version.

**Limit.** Code running with the app's full privileges can use the root key, the Keystore and
the Keychain itself, and can delete live keys without going through the SDK. The MAC does not
defend against it, and the design does not claim that it does.

**Store rollback or redirection.** An older genuine copy of the store has valid MACs. It could
name an older generation as live, or show a now-live generation as an attempt that may expire.
What limits this:

- D2's content check refuses to delete any generation whose medium holds a grant of its member;
- R11 refuses promotion behind the high-water mark;
- on Apple, the epoch is mirrored in a Keychain item beside the root key, so a file-only restore
  shows as `storageDamaged`.

On Android, the JVM, browsers and Node, the epoch shares storage with the store, so a full
rollback by privileged code is not detected. The content check still protects admitted
generations.

**A crash at each step.** Covered by §3.5, §3.7 and §3.8. Before C the live generation is
unchanged. After C the new one is live and has already been validated, and the previous one is
kept for repair.

**Stale processes and extensions.** An old epoch cannot promote or delete, because both are
compare-and-set operations. A process can still produce a signature after C, using a key it already
had open. That signature takes effect only through an outbox commit, which compares the epoch and
fails, so it is discarded (§3.6). Unsigned local work in a suspended process can be lost; it is
reported as `superseded`.

**A replayed or stale attempt.**

- Calls carry `created`, a window and a replay ID (§12.3, §12.4).
- Invite checkpoints are checked (`refused:fork`, `refused:rollback`).
- R11 refuses an attempt that is behind the live generation.
- Attempt transitions are versioned, so a replayed transition fails its compare.
- Pointer rows are keyed by the account the attempt verified.

**A hostile home.** It can withhold a grant (the attempt stays `granted`), refuse calls, and learn
the account ID, the controller key ID and timing. As 0.5 states (§13.4, known limit), a hostile
sole home can show a **first verifier** (a device with no earlier state) a valid stale fork in
which a removed passkey is still current. A grant signed there is a fork that other readers
refuse. Mitigations:

- an invite's checkpoint;
- R11, on a device that holds newer state;
- at `headQuorum` above 1, checking the other homes' heads, which §13.4 says a device SHOULD do and
  the SDKs do not yet (W4).

With one home and no earlier state, nothing detects it. A home cannot forge a grant, read the
vault, or cause any deletion.

**What pairing authenticates.** It shows that both screens hold the same account ID and the same
key `E`. It does not establish:

- the account's identity to the person: the host shows the account fingerprint, and the account
  label is the account's own text;
- the truth of the requester's `label`, `kind` and `custody`, which the requester asserts itself;
- the approver's intent: the host shows the terms before the ceremony;
- the passkey's relying party: the operating system shows it, and the core checks it against the
  descriptor.

**What UV guarantees.** The authenticator verified its user for an assertion over SHA-256 of the
exact body (§4.3 step 1). It shows only the relying party, so the host must show what is being
approved.

**Phishing and the relying party.** Every origin allowed for the `rp` can obtain the passkey's
signatures and PRF outputs, and so can read its `prf` slots (§3.2). `authorityOrigins` limits who
can sign grants and `keyring` entries; it does not limit vault access. Native apps are bound by
platform origin (`android:apk-key-hash`, which `PasskeyController` adds to `origins`; associated
domains on Apple). Hybrid ceremonies require proximity. Hosts should:

- set `authorityOrigins` (§17.3);
- offer `combined` slots (§7.2);
- never run non-production builds against a production `rp` (§3.2).

---

## 6. Test plan

### 6.1 Invariant

A generation's **fingerprint** is:

- its `pointer` and `manifest` rows;
- every file under its records and session trees, by path and SHA-256;
- its derived key names, with their public points;
- its device-secret entry, present or absent;
- the store epoch.

The live generation's fingerprint must be byte-identical after any abandoned, failed, expired or
crashed attempt that did not reach C, and after every attack in §6.3. After C, the previous
generation's fingerprint must stay unchanged until it is retired.

### 6.2 Failure-injection matrix

Hooks follow the existing step hooks (Kotlin `FolderMedium`'s test hook, Node
`FileMediumOptions.onStep`). The matrix runs in Swift, Kotlin on the JVM, Kotlin as an Android
instrumented test, and TypeScript in Node and in a browser.

| Step | throw | process kill (as `js/test05/kill-child.ts`; `Process.killProcess` instrumented) | cancellation | storage full or read-only | key store failure | network drop after server commit |
| --- | --- | --- | --- | --- | --- | --- |
| manifest and attempt rows | ✓ | ✓ | ✓ | ✓ | – | – |
| keys created | ✓ | ✓ | ✓ | – | ✓ | – |
| request stored, disclosed | ✓ | ✓ | ✓ | ✓ | – | – |
| each history page and head | ✓ | ✓ | ✓ | – | ✓ | ✓ |
| `verified` | ✓ | ✓ | ✓ | ✓ | – | – |
| slot unlock | ✓ | ✓ | ✓ | – | ✓ | – |
| sign, store, `granted` | ✓ | ✓ | ✓ (must not interrupt) | ✓ | ✓ | – |
| grant publish | ✓ | ✓ | ✓ | – | – | ✓ |
| P0 confirmation | ✓ | ✓ | ✓ | – | – | ✓ |
| V1–V5, C, P1 | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| D1–D7, sweeper | ✓ | ✓ | ✓ | ✓ | ✓ | – |
| withdrawn reconciliation | ✓ | ✓ | ✓ | – | – | ✓ |
| §4.6 entry, P2 possession, §4.7 transfer | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### 6.3 Attacks and boundaries

**Regressions.** F1 to F9, one test each.

**Malicious metadata.** Each case below must be refused and delete nothing:

- a row of valid shape without a valid MAC;
- a MACed row replayed from an older store;
- an attempt row carrying the live generation's ID;
- a non-hex generation ID.

**Forced collisions.** A repeating random source, and directories, aliases or items already
present under derived names. Creation is refused.

**Links.** Symbolic and hard links at `R`, `generations/`, `trash/` and inside a generation,
pointing into the live generation. They are refused, and the live fingerprint is unchanged.

**Store rollback and deletion.**

- An older store restored while a newer generation is live.
- The store deleted with the root key present.
- The root key deleted with the store present.

The states in §3.11 hold, and so does the D2 check.

**Unsupported durability.** No atomic move, or a directory sync that fails. Promotion is refused.

**Key loss after C.** Keys deleted between C and P1. The account enters repair, the previous
generation is kept, and there is no switch back to a revoked member.

**Stale signers.** In each of these, no signature made under the old epoch is ever stored, sent
or handed over. Only signatures that reached an outbox commit before C exist.

- A process and an app extension each read the epoch, open the member key, and are paused by a
  hook just before signing. C commits, then they resume and sign. The post-sign compare fails and
  the signature is discarded.
- The same pause placed between signing and the outbox commit, between the outbox commit and the
  medium write, and between the medium write and publishing.
- An extension suspended past its lease while its generation is retired, then resumed.

**Lease timing.**

- Clocks are stepped forward and back by hours, without a reboot. No lease expires early and none
  lives for ever.
- A reboot is simulated by a new boot ID, which expires every lease from before it.
- A frozen holder's lease expires after 60 s of the observer's monotonic clock.

**Root key races.**

- Two or more processes bootstrap one root at once, on Android, Apple and in a browser. Exactly one
  `root` row and one root key survive. On Android, the losing candidate aliases are deleted and no
  winner's alias is ever replaced.
- Generation storage present while the store and key are absent: `storageDamaged`, never a fresh
  install.
- On the JVM and Node, a host `RootKey` that lives beside the store is reported by
  `diagnostics()`, and the documentation says what protection is lost.

**Live access path.** Promotion is followed by a background task open and, where the app has
one, an extension open, both with the screen locked.

- Keys made with `WhenUnlocked`, outside the extension's access group, or with a user-presence
  gate the background path cannot satisfy must be refused at V4a, before C.
- Android user-authentication keys, and a lock screen added or removed between V3 and P1. If this
  invalidates the keys, the account enters repair.

**Late approval.**

- Sign at 599 s, and at 601 s, which is refused.
- Publish another device's grant at 23 h, and at 25 h, which is dropped. A self-approval grant
  unpublished at 25 h is still kept.
- A withdrawn request granted within the retention bound, then resolved by "Open it" and by
  "Remove it".
- Keys deleted at exactly 24 h + 600 s.
- A grant published a week after the tombstone. It is detected by a later generation on this
  device and by other devices' notices, and revoked by a controller under `single`. Under
  `control` it needs `threshold` units.

**Migration.**

- `adoptLegacy` killed mid-transaction.
- A legacy generation superseded, and never deleted.
- An upgrade that finds a grant left in the legacy medium.

**Shared medium.** A failure at V5, then a retry. The shared medium never loses a file.

**Trash and legacy boundaries.** `trash/<g>` without a `discarding` manifest is left alone. A legacy
fingerprint mismatch blocks every write outside its locations.

**Flows.**

- Flows A and B against the reference relay with a software WebAuthn passkey.
- §4.6 with `control` pending, then activated.
- A full set made with a second control key.
- The planter rule, after a later removal of P1.

### 6.4 Conformance vectors

There is no new history format. Add positive and negative vectors under `conformance/0.5/rules/`,
unless they are already covered:

- a `grant` by a WebAuthn controller from a platform authority origin;
- a `grant` under `memberRule` `control` with `cosignatures`;
- an immediate `keyring` adding an `approve` passkey with its `prf` slot and possession proof;
- the same entry signed by an `approve`-only controller, which is refused;
- a possession proof from outside `authorityOrigins` (`badSignature`);
- a `control` addition with two control units, a full set (b);
- the same with one control unit, which is pending.

The §4.9 rules are tested in core unit tests (pairing expiry) and in the session tests (the
delivery bound). The admission store rows are an SDK format. They get golden tests, and the three
SDKs share one JSON schema for them.

---

## 7. Work breakdown

Sizes: S is up to 2 days, M up to a week, L up to two weeks, per language unless stated.

| # | Work | Size | Depends on |
| --- | --- | --- | --- |
| W1 | `AdmissionStore` contract and stores (Swift SQLite, Android SQLite, IndexedDB; host-supplied on the JVM and Node), root key per platform, MACs, epoch | L | – |
| W2 | Derived names; link-refusing file helpers with a durability capability; open-only key and secret factories; ledger at account scope | M | W1 |
| W3 | Attempt state machine, leases and fencing, `discard`, sweeper, `diagnostics` | M | W1, W2 |
| W4 | Join and recovery on attempts; `approveWithPasskey`; other homes' heads at `headQuorum` above 1; removal of the unsafe 0.5.7 forms | M | W3 |
| W5 | Promotion with V1 to V5, repair, supersession, retirement, export, revoke offers | M | W3 |
| W6 | `ColophonSession.approve(…, passkey)` (flow A) | S | – |
| W7 | Late approval: the core pairing expiry (Rust and every binding), the delivery bound, withdrawn reconciliation | M | the core part: none; the rest: W3 |
| W8 | `addPasskey` (§4.6), and the second pairing for the seed transfer (§4.7) | M | W4, W12 |
| W9 | Failure injection and the §6 attacks | L (all languages) | W3–W7 |
| W10 | JS port of the passkey read and join at head | M | – |
| W11 | Recovery-transition attempts (`awaitingActivation`) | M | W5, W12 |
| W12 | The key-change work from #115, rebased and audited (below) | M | – |
| W13 | §4.9 spec text, guide, migration notes | S | – |

**Order.**

1. W6, W10, W13 and the core half of W7. They are independent, and the bounds must exist before
   apps rely on them.
2. W1, W2 and W3.
3. W4, W5 and W7, with W9 alongside.
4. W12, then W8 and W11.

Nothing changes a wire object, a verifier verdict or a home route. The §4.9 rules land with W7 and
W13.

**What #115 should become.** Split it, and merge none of it unchanged.

- **Live removal and rotation:** `removeController`, `checkRemoval`, `completeKeyChanges`,
  `restoreSlot`, cosigners and the `HostDuties` additions. Rebase them onto `main`. Audit them
  separately: vault retirement and rotation, the planter rule and `keep`, owed rekeys, and
  full-set cosigning. Add the missing JavaScript parity.
- **The `removeFollowUp` entropy fix:** on its own, with a test, to `release/0.5` and `main`.
- **Pre-admission passkey work:** the second passkey added on a joining device, and the staged
  `replaceController` path when it starts on a device that is not yet admitted. These move onto
  attempts (W8). `replaceController` on a live session stays with the live removal work.
- #115's question, whether a transition's `vault` component may carry a slot for a controller the
  transition adds, is deferred (§8.1).

---

## 8. Decisions and open questions

### 8.1 Decided, with reasons

- **No special status for a "first passkey".** The SDK selects a passkey by its roles and slot
  (§4.1). Selection by seq order would break after any replacement, and the protocol has no such
  notion.
- **Durable home state is required before promotion.** A grant the home has not accepted can be
  displaced (§8.6) after the switch. Accounts without a home do not use attempts.
- **Never revoke silently.** Every revoke of a superseded or withdrawn member is offered to the
  person and signed only on their choice.
- **Approval by a passkey without a slot is deferred.** It would need a new core surface that
  builds `shares` from the approving member's epoch handles, and those handles would have to cover
  every historical epoch (§9.2). The reference passkey has a slot.
- **Both spec clarifications are adopted, as normative rules** (§4.9).
- **The SDK never deletes app-provided legacy locations** (§3.11).
- **No one-transition replacement of the sole slotted control key in 0.6** (raised in #115). The
  staged path is correct, and a one-transition replacement would touch §8.3's slot-drop rule.

### 8.2 For the owner

- **Q1. Retention and resource limits.** *Recommendation:*
  - A replaced generation is kept until the new one is `Ready`, its outbox is delivered or
    unflushable, and no lease remains. It is kept at most 30 days, and never while repair is open.
  - Four live attempts per root, and one passkey ceremony at a time.
  - Attempts that were neither disclosed nor signed expire after 24 hours.
  - A withdrawn request's keys are kept for exactly 24 hours and 600 s.
  - Tombstones are permanent. They take about 200 bytes each, and the SDK warns once more than 1,000
    exist.
- **Q2. Is user verification always required?** *Recommendation:* yes, as SDK policy, for every
  grant, `keyring` entry and slot unlock, even for a controller without `verification`.
  `PasskeyAuthenticator` already requires it.
- **Q3. The home confirmation quorum.** *Recommendation:* fresh heads covering the grant from
  `headQuorum` distinct current homes, the quorum §12.3 uses for calls. A head from the primary
  home alone is not enough.
- **Q4. Notices to other devices.** *Recommendation:* every new grant, every immediate `keyring`
  entry and every grant of a tombstoned request, shown at the next sync beside §17.5's
  activations, with revoke one tap away. Make it a 0.6 SHOULD.
- **Q5. Is a cryptographically binding discard worth a layout raise?** (§3.9, "Option not
  adopted") *Recommendation:* not for 0.6. It costs a format change, a per-account layout raise that
  stops 0.5 readers, home storage and new vectors. It only removes the risk from approvers that
  ignore conforming rules, and those already hold `approve`.

---

## Appendix A: verified and inferred

**Verified in code at this revision:**

- `ColophonJoin` writes into `configuration.medium` and uses `configuration.keys`
  (`OwnRequest.ensure`, `ColophonJoin.store`), in both SDKs.
- `KeystoreKeys.materialize` and `KeychainKeys.withKey` create missing keys.
- Device secrets are keyed by account ID, in all three languages.
- `withOwner` and `unlockOwner` sign with the configured `ownerController`.
- `approveOwnRequest` uses the scan path.
- `leave()` deletes nothing.
- The genesis passkey has the roles `approve`, `control` and `recover`, with `verification`.
- The JS session has no passkey join.
- The pairing ledger is in the private directory.
- The JVM `AtomicFile` falls back from `ATOMIC_MOVE` and ignores a failed directory sync.
- `privateClaimStore` refuses `FilePrivateStore`.

**Inferred, not verified:**

- That a confirmed `AccountPairing` lives only in memory and has no expiry after confirmation.
- How Keystore behaves under a process kill during deletion on specific devices.
- SQLite durability on every volume that can hold an App Group.
- Whether existing conformance vectors cover §6.4.
- The app-side sequences in §1.3. They come from review findings on an app's code, not from this
  repository.

## Appendix B: changes in revision 2

- **Ownership.** Each generation has a permanent, MACed, immutable manifest, kept until its
  deletion completes.
- **Deletion targets.** They are derived, never read. Links and collisions are refused.
- **Metadata.** It lives in a transactional admission store (SQLite or IndexedDB), MACed with a
  per-platform root key, with a defined path when that key is lost.
- **Promotion.** It requires a durability capability and the V1 to V5 validation, and it has a
  repair state. It never switches back to a revoked member.
- **Late approval (F9).** Two normative rules, retained disclosed keys, reconciliation and orphan
  detection. Revision 3 corrects this: key retention is bounded and followed by a tombstone, and
  withdrawal is advisory (Appendix C).
- **Fencing.** An epoch fences processes and extensions, and every transition is a
  compare-and-set.
- **Spec and rules.** The spec clarifications are now normative. The rules, full sets and the
  planter rule are stated exactly. Moving the seed needs a second pairing.
- **Threat model.** The limits are stated, including the stale fork shown to a first verifier and
  what pairing does not authenticate.
- **Migration and API.** Bootstrap is defined, and the unsafe 0.5.7 forms are removed.
- **#115.** Split, rebased and audited separately.
- **Tests.** The plan now covers the attacks and boundaries.
- **Open questions.** Each is either recorded as decided or left for the owner.

## Appendix C: changes in revision 3

- **Scope.** A section near the top states what is sufficient to admit a device without another
  device, and what is not covered.
- **Signing is fenced after signing (§3.6).** A post-sign compare-and-set in the store commits an
  `outbox` row. A signature made under a stale epoch is discarded and never stored, sent or handed
  over. Leases are judged on the observer's monotonic clock, with a boot ID and process
  incarnation. App extensions are covered explicitly.
- **Late approval made consistent (§3.9, §4.9, R6, R8).**
  - Withdrawal is advisory.
  - Key retention is bounded at exactly 24 h + 600 s, followed by a permanent tombstone.
  - It is stated what a late grant does and who revokes it, under which rule.
  - The delivery bound applies only to grants of another device's request.
  - A binding withdrawal is described as an option not adopted, with its cost.
- **Root key (§3.2, §3.11).**
  - Android creation uses a candidate alias per contender, so no process ever replaces a winner's
    key.
  - Bootstrap has a fixed order, and surviving generation storage is never treated as a fresh
    install.
  - Host-supplied keys on the JVM and Node carry a mandatory isolation requirement, and without it
    the SDK claims no tamper protection there.
- **Validation of the live access path (V3, V4, V4a).** It uses the same factories, access groups,
  accessibility classes and authentication gates as the live session, including background and
  extension paths.
- **Tests.** New tests cover all of the above.
- **Owner questions.** Restated as five.
