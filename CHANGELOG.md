# Changelog

## Unreleased (0.5.6)

No format or reader-rule change. The spec stays Colophon 0.5, revision 18.

- **Operator delete** (reference home, `relay/`): with gate `token`, `DELETE /v1/operator/slots/<slot>?generation=` removes a provisioned slot's data and its row through the release path, an appointed slot included, and answers 204. It requires the slot's current generation (409 `refused:staleGeneration`) and a suspension first (409 `refused:notSuspended`); a configured slot is refused (409 `refused:configured`), and a name not held answers 404 `refused:notProvisioned`. The name can then be provisioned again with a new generation.
- **A home's standing**: `GET /v1/operator/slots/<slot>` also reports `standing`, this home as the account's verified history names it (`unappointed`, `home`, `revocationPending`, `revoked`, `notHome`, or `unknown`), so an operator can act on an account's own removal of the home.
- **Swift session**: the due loop's update and the update after a sync pass that changed nothing are built only after the member has opened any epoch shares sealed to it, as a refresh does; with no engine open (locked, or discarded since the pass began) they reconcile, so a locked library is reported `.locked`, never `.noLibrary`.

## 0.5.5 — 2026-11-24

No format or reader-rule change. The spec stays Colophon 0.5, revision 18.

- **Operator API and read-only slots** (reference home, `relay/`): with gate `token`, the provisioning token also authorizes `GET /v1/operator/slots/<slot>` (`{"slot","provisioned","suspended","generation"}`) and `POST /v1/operator/slots/<slot>/suspend` and `/resume` (204), which require `?generation=` (400 without it, 409 `refused:staleGeneration` when the name has since been released and provisioned again). Without gate `token` the paths answer 404.
  - A suspended slot serves every read (the head, history, pending objects, records, blob chunks, the change feed and its long poll) and refuses every data write with 403 `{"result":"refused:subscriptionLapsed"}`: record, live value, blob chunk and predecessor puts, and forwarded heads. History uploads and pending objects (transitions, vetoes, receipts) are still taken and receipted, so the account can appoint another home and revoke this one. It deletes nothing.
  - The suspension is stored as `<slot>/suspended.json`, written atomically, and survives a restart. If writing it fails part way, data writes stay refused until the state is reconciled from disk, and a retry is acknowledged only once the intended state is durable. A suspended slot is never released as unclaimed.
  - The token is checked first. Authenticated operator requests share `provision.operatorPerMinute` (default 600) for the whole home; refused ones count per address against `provision.operatorRefusedPerMinute` (default 10), and never spend or crowd out the operator's share.
- **`GET /v1/operator/slots`** lists every home slot (`{slot, provisioned, suspended, generation}`), paginated by `after` and `limit`, behind the same token and share as the other operator routes.
- **Slot quota at a home slot**: `limits.slotBytes` counts data only (records, live values, blob chunks) and refuses a data write over it with 507 `{"result":"refused:overQuota"}`; the account's history and reads are never refused.
- **History quota at a home slot**: `limits.historyBytes` (default 64 MiB, `COLOPHON_SLOT_HISTORY_BYTES`) bounds a slot's history; an upload, pending objects, a forwarded head or a predecessor entry past it answers 507 `{"result":"refused:historyQuota"}` before anything commits. Reads are never refused.
- **Forwarding is bounded and fair**: a peer's answer is streamed and cancelled past `limits.peerAnswerBytes` (1 MiB); passes run at most `limits.forwardPeersPerSlot` (8) per slot and `limits.forwardPasses` (64) per home; peers take turns within a slot, and each scheduler pass starts from the next slot.
- **Door shares**: provisioning the same slot again for the same account spends no new-slot share and is never refused by one. A grant call sweeps unclaimed slots only once it passes the module's judgement over the operator slot's current state.
- **Private listener** (`COLOPHON_PRIVATE_LISTEN=unix:/path` or `host:port`, or `privateListen` in the config): serves `/v1/provision` and `/v1/operator/*` only; the public listener then answers 404 for both. A Unix socket is made mode 0600; a host must be loopback or private unless `COLOPHON_PRIVATE_LISTEN_ALLOW_PUBLIC=1`.
- **The door's 200 carries `Colophon-Slot-Generation`**, the slot's generation from the same decision; the body (the member request) is unchanged.
- **Hosted mode** (container): `COLOPHON_HOSTED=1`, or a private listener, requires `COLOPHON_PROVISION_TOKEN_SHA256` with gate `token`, and never makes or prints a token.
- **The door and releases**: a token request is authenticated, and a grant call judged without state, before any sweep of unclaimed slots. A release drains the work in flight on its slot outside the door's lock, checks the slot is still the one it started from, never releases a slot whose suspension marker is on disk or whose state is uncertain, and renames the directory aside under the lock and removes it after. A full home waits for releases under way before answering 507.
- **`refused:subscriptionLapsed`** is listed with the reserved home refusals (spec §14). The Swift, Kotlin and JS sessions already show any `refused:` result as received; their documentation now names it.

## 0.5.4 — 2026-11-24

No format or reader-rule change. The spec stays Colophon 0.5, revision 18; 0.5.x homes and apps
continue to interoperate, and a home's data directory opens unchanged. There is no 0.5.3 release.

**Home (`relay/`, `colophon-home-wasm`)**

- **Container image**: `relay/Dockerfile` and `relay/container-entry.js` package the home as an image configured by environment, with its key, token and data on one volume, for amd64 and arm64. CI builds it and publishes it on a final tag. See [`docs/self-hosting/docker.md`](docs/self-hosting/docker.md).
- **Idle cost**: the module tells the scheduler when something can next come due, and the relay makes no module calls for a quiet slot until then. Eight idle libraries went from a full core to about 1% on a small machine.
- **Writes ordered against revocation**: a record or predecessor write is judged under the slot's lock, so a write that arrives while its author's revocation is being applied is refused. Change-feed pages, history pages and history files are judged and selected over one state, and a long poll ends when the home's state changes.
- **Replay log**: compaction is durable and keeps unfinished writes pending; a failed write stays pending for recovery and each row keeps its real outcome; a log that cannot be read whole refuses to open; durable files are written whole; a checkpoint is acknowledged only after a strict directory sync.
- **Shutdown**: the relay waits for a home's own work, aborts waits on other homes, and answers 503 with `Retry-After` while closing; a released slot still answers 404.
- **Container safety**: the entry point refuses to start a new home beside an existing data directory and leaves another relay's lock alone. Moving an existing home into the container is an offline handover.
- CI now runs on pushes and pull requests to release lines.

**Core**

- `record_due` no longer copies the held state when nothing is due, and restores the live set when a recording fails part-way.

**Swift**

- **Folder writes**: a session's writes name its own file presenter when coordinating, so a signed write no longer waits on it (about 0.5 s to a few milliseconds per write on a folder store). Per-open and per-batch work in `FolderMedium` is cut.
- **Batched writes**: `perform(_ commands:observed:)` signs and stores up to 256 commands under one reconcile and one snapshot. A failure part-way returns the durable prefix in `BatchInterruption`.
- A write builds one snapshot instead of two, and the pre-write reconcile hands the engine only what changed in the folder.
- Sync coalesces watcher refreshes and re-checks the folder before each later home.
- Fixed: a store error after a write became durable no longer reports failure, and a receipt for a command that keeps a live head now names the new operation.

Known limits of the reference home, unchanged in this release: exclusive use of a data directory relies on lock files and a heartbeat rather than a kernel-held lock; keep the machine's clock synchronised, since a clock set far ahead and then back can let an old call through; never restore part of a data directory.

## 0.5.2

No format or reader-rule change. The spec stays Colophon 0.5, revision 18;
0.5.0 and 0.5.1 homes and apps continue to interoperate.

- **Join at an invite's history head** (#60): Swift and Kotlin `ColophonJoin` can request membership with only an account ID, a home base and a history head, then fetch and verify the history after approval. The accepted history must include the invite head, the exact membership request's grant and a fresh head from a current home serving that base. The core's **"no current home serves this base" case now returns `badSignature`, not `malformed`**. History reads are bounded; controller descriptors come only from accepted history.
- **Keep imported dates** (#64): `perform(_:observed:claimed:)` in Swift and `perform(command, observed, claimedMs)` in Kotlin carry an earlier signed operation date through the core and bindings. Future dates are refused, and authorization and clocks still use the real time.
- **Appoint homes after account creation** (#66): Swift and Kotlin `appointHomes` can appoint homes and optionally add a controller, including its own unlock slot, in one transition. A home-less account records it immediately; an account with a current home reports the pending transitions. Calls resume safely after interruption and check the requested endpoints, controller roles and slot holder. Adds `account_controller_json` to the FFI.
- **Wipe secrets and fix core/FFI correctness** (#67): AES-GCM key schedules and owned secrets use real zeroization. Schema validation handles signed integers, type arrays and exact integer bounds; advertised import query tools are callable; native-engine locking handles concurrency and callback reentry without deadlocking.
- **Harden the reference relay** (#68): clean up disconnected long polls, filter wakeups and cap waiters; avoid body reads for HEAD/304 while verifying GET integrity; enforce If-Match before identical-byte shortcuts; fix immutable-write races, symlink/staging handling, cross-process data-directory locking and graceful shutdown.
- **Speed up verification and resumed opens** (#69): bounded prepared-key reuse and native parallel verification preserve signature checks. Imported plaintext memos survive partial resumed opens, and pending-veto verification no longer grows quadratically.
- **Optimize native release builds** (#70): Apple, Android and home-module builds use `opt-level = 3`; browser WASM keeps size optimization through the separate `release-wasm` profile.
- **Fix multi-home state and forwarding** (#71): persist covering-home candidate-slot ownership, bound standing candidates, forward matching history/head snapshots, suppress heads after failed history uploads and enforce the 15-second pass deadline. Several homes remain experimental; deep-fork paging gaps are listed in [docs/multi-home-open-issues.md](docs/multi-home-open-issues.md).
- **Batch reads for plain relay slots** (#73): `POST /records/batch` reads 1–256 unique record paths with existing bearer authorization, integrity checks, a 64 KiB request bound and a 4 MiB encoded response budget. Home slots do not support this endpoint.
- **Require discoverable passkeys** (#62): Android and JS registration send `residentKey: "required"` and `requireResidentKey: true`. A security key that cannot store a discoverable passkey is refused at creation. This is the likely fix for the observed Google Password Manager registration/sign-in failure, but has not been proven on the device.
- **Wait briefly for a newly created Android passkey** (#59): on Android 14+, the adapter probes readiness every 400 ms for up to 15 seconds; older versions wait 2.5 seconds. The hybrid sign-in entry can satisfy the probe immediately, so this did not fix the observed Google Password Manager failure.
- **Clarify folder-only accounts and ask-first joins** (#58, #63): an account may be created without a home for shared-folder sync, with host-provided warnings. A new member may request admission first and fetch history after approval from the invite's head.

## 0.5.1 — 2026-11-20

0.5.0 plus the fixes and additions below, with no format or reader-rule change: 0.5.0 homes and
apps interoperate with 0.5.1. The spec stays Colophon 0.5, revision 18.

- **Provisioning by grant** (reference home, `relay/`): the new gate `grant` provisions a slot when the request carries a 0.5 call (`Authorization: Colophon <call>`, purpose `home.provision`) signed by a member of an operator account held in one of the home's own slots. No shared secret is needed.
  - Revoking or expiring the member stops it at once.
  - Each member is bounded by its grant's terms, by `grantMaxSlots` and by a durable `grantPerHour`.
  - The gate may be a list, for example `["grant","token"]`.
  - Provisioned rows record `by`, and `bun relay/server.js provisioned <config>` lists them.
  - No format and no reader rule changes. Core gains `Call::verify_possession`, the existing possession step moved out unchanged.
  - Settings and the issuing and revoking steps are in [relay/README.md](relay/README.md).
- **Fixed:** the home module's `record_due` grew quadratically slower with an account's history (reference home, `relay/`): when nothing was due, building its log note tried every transition and veto ever held, and verified the whole history again for each. It now shares one verification across all its `prepare_*` attempts and skips transitions already recorded and their vetoes; what remains is the linear parsing and replay of the state every call does (see [docs/performance.md](docs/performance.md)). The note no longer has parts about recorded transitions; what the home records, answers and refuses is unchanged, and no format or reader rule changes. Core gains `VerifiedObjects` (the held objects verified once, bound to them and the clock, with `prepare_activate`, `prepare_vetoed` and `prepare_final` methods), `State::is_recorded`, and a `work-counters` feature for tests. The bug is in 0.5.0.
- **Sessions use a grant** (JS, Swift, Kotlin): `SessionConfiguration.services` asks for service terms (§10.1), approving with a `ServiceGrant` can only narrow them, `signCall(audience, purpose, args)` signs a call with the member's own key, and `provisionRequest(door, audience, slot, base, account)` provisions a slot by grant and plugs into `HomeConfiguration.request`. A grant's slot condition must also allow calls naming no slot, since conditions bind the member's own history reads (see the session guides). No format, binding or core change.
- **Fixed:** a session could stay in the `refreshing` phase after a cancelled refresh (Swift, Kotlin) or a cancelled key prompt during one (JS), and an older refresh finishing late could overwrite a newer one's result. A refresh now restores `ready` on every exit and publishes only while it is the newest; a command failure that set a phase keeps it. The bug is in 0.5.0.

### Known issues

- On a device, opening an account that holds many vetoes is quadratic in their number
  (`derived::effective_objects` calls `check_pending_veto` for each). Not fixed.
- At head quorum two, a device one forward ahead of a home can get one refused sync pass before
  the next one succeeds.

The rest are in [docs/known-issues.md](docs/known-issues.md).

## 0.5.0 — 2026-11-19

Frozen on 2026-11-16 (spec revision 18) and released on 2026-11-19. Nothing was published in
between, so the fixes found in that time are part of 0.5.0 rather than a 0.5.1; none changes a
format. They are listed under "Fixed before release".

**One portable identity: an account.** An account is a keyring of controllers whose identifier is
the digest of its first authority record. Members (apps, devices, agents, servers) act under
grants, sessions act for members through links and calls, and a home keeps and vouches for the
history. Changes that weaken an account wait as pending transitions that can be vetoed. 0.4
libraries upgrade in place; libraries of the shipped Swift apps move by a verified succession.
Spec: [colophon-0.5.md](spec/colophon-0.5.md), frozen at revision 18 (provisionally;
see §21); [changes from 0.4](spec/colophon-0.5-changes.md);
[guide](spec/colophon-0.5-guide.md).

### Protocol

- Authority history `/5` (§8): immediate entries for changes that add or tighten, and pending
  transitions with a recovery delay, a veto window, escalation and suspension for everything else.
  Finality is recorded in the history (`activate`, `vetoed`, `final`), so every verifier reaches
  the same verdict from the same objects, in any order.
- Conflicts: evidence, forks with and without homes, and `resolve`, which keeps one branch.
- Dropping a lost home (§8.7): a full set needs no receipt from the homes it revokes, so a home
  that is gone or refuses cannot block it. An account with two units (for example one control key
  and one separate recovery key) can drop the home, appoint another and continue.
- Vault and slots (§7): removing a slotted controller retires the vault, and a `vault` entry and a
  `rekey` follow. Pairing by code or by scanning the request; the seed moves to a new device under
  its own label.
- Member approval consumes a confirmed pairing (§9.1). The SDKs no longer approve by a 32-bit
  ID-prefix code.
- One current-principal check (§8.5): an expired or provisional member's `endSessions` is
  refused.
- Members, terms and records (§9 to §11): renew, revoke with `kept` and up to 16 heads,
  `endSessions`, `/5` operation headers, author chains and proposals.
- Links and calls (§12) with a replay store; heads, rollback marks per home and equivocation
  evidence (§13).
- The upgrade door (§8.2, §20): a later format version reaches an existing account in place, by one
  transition that raises its layout. A 0.5 reader stops at a final raise, trusts nothing new and
  keeps reading what it holds (§1); a stopped home follows the table in §13.6.
- Upgrade from 0.4 in place (§16.1) and succession from the Swift keyring format (§15, §16.3),
  with a `migration` entry.
- Text-only reservations: paid-home refusals, `colophon.` names, `account` and `organisation`,
  the export and close purposes, `layouts`, `refused:notGranted`.

### Homes

- The account engine syncs with a home: head, then authority, records, live state and blobs.
- The home module (`colophon-home-wasm`) admits only what verifies, receipts transitions and
  vetoes, records due transitions and signs heads. One home is supported per account.
- A home keeps and serves every pending transition and veto until it is settled, and a host shows
  each pending change with its due time on every sync. Delivering notices is not part of 0.5.
- Several homes per account are experimental: exchange between homes is informative in 0.5. The
  two-home tests pass; the open issues are in
  [docs/multi-home-open-issues.md](docs/multi-home-open-issues.md).

### SDKs

- **Rust core:** `colophon_core::v05`: the verifier, the write side (prepare, then finish), and
  the account engine with checkpoints and resumption. The 0.4 engine stays beside it.
- **FFI and WASM:** the UniFFI and WASM `AccountEngine` exports, including moving a Swift library;
  secrets are wiped and lists are bounded.
- **Swift:** the Swift SDK session.
- **Kotlin and Android:** the same session model.
- **JavaScript:** the session layer over the web exports.
- One iPhone and one Android device on one account, and test apps for both. The SDKs show a
  stopped account and a home's refusals.

### Fixed before release

- **Sessions (Swift, Kotlin, JS):** a session whose `libraryNamespaces` is wider than its member's
  grant is ready, after `create()` and after an approval that granted fewer namespaces than it
  asked for; it came out `denied`. A session is `denied` only for access its member lost, and
  publishes revisions only for the namespaces it can read.
- **Sessions (Swift, Kotlin, JS):** the owner's engine reads every namespace the device holds, not
  only the app's `libraryNamespaces`, so a revoke from an app with a narrower library keeps what
  the revoked member wrote in the other namespaces held there.
- **Swift:** `approve(_:pairing:grant:)` narrows the request's own terms. It rebuilt them, so a
  grant that changed only the expiry or budget lost per-namespace access and kinds, and the core
  refused it after spending the pairing.
- **JS:** a revoked member reopening cold is `denied`; it came out `failed` because its engine was
  never loaded.
- **Repository:** internal working notes left the tree, the scripts no longer name a build
  machine's paths, and [docs/known-issues.md](docs/known-issues.md) lists the implementation gaps
  beside spec §21.1.

### The reference relay

- The relay serves as a home (`relay/home.js`), one account per slot.
- CORS for a configured list of origins (off by default), and uncompressed answers.
- Provisioning: `POST /v1/provision` creates a slot at run time, bounded, with an open or token
  gate (off by default). A slot not claimed within 24 hours is released.

### Packaging

- `scripts/package-release.sh` builds the Apple XCFramework, the Android AAR, the JS package and
  the home bundle from one commit into `dist/release/<version>/` with `SHA256SUMS`
  ([docs/release-packaging.md](docs/release-packaging.md)).

### Performance

From [docs/performance.md](docs/performance.md): the native engine, software keys, an M3 Max on a
loaded machine; median / worst of five runs.

| Operation records | Cold open | Resumed open | One stored write | Peak RSS (cold) |
| --- | ---: | ---: | ---: | ---: |
| 2,000 | 0.857 / 1.011 s | 0.221 / 0.227 s | 17.11 / 41.85 ms | 87.2 MB |
| 10,000 | 4.962 / 7.102 s | 1.047 / 1.210 s | 30.86 / 88.76 ms | 408.2 MB |
| 100,000 | 47.377 / 54.048 s | 19.622 / 25.794 s | 179.83 / 184.28 ms | 4,422.2 MB |

The 2,000-record case meets the Mac limits it was measured against.

### Conformance

- `conformance/0.5/`: the 0.5 vectors, replayed by the Rust verifier. The README indexes what
  covers each required item and names the items that nothing covers yet.
- Spec §21 records each freeze condition as met or open, and the owner's decisions: the freeze is
  provisional, two complete replayers are deferred to v1.0, and the open gaps are closed in 0.5.x
  without changing any format.

### Limits

What 0.5.0 does not do is one list, in
[spec §21.1](spec/colophon-0.5.md#211-what-050-does-not-do). It starts with the lock-in limit: an
account whose control and recovery controllers all sit in one unit cannot drop a home that is lost
or refuses (a full set takes two units); its way out is a new, unrelated account and an import of
the records the person's devices hold.

**Known gap: the §6.4 warnings.** The reference sessions (Swift, Kotlin and Android, JavaScript) do
not yet give the §6.4 warnings before the genesis is written; they expose `soleDevice` afterwards.
The warnings stay normative for hosts. Until the sessions give them, an app checks the creation
parameters (one home, every control key on one device, exactly one recovery unit) and warns before
it calls create.

### Withdrawn to 0.6

Designed in the freeze package and deferred by revision 17
([design](docs/design-freeze-package.md), "Deferred to 0.6"; changes §A.12):

- Behind the upgrade door: F1 (unknown content, one rule), F4 (raisable limits and
  `witnessWindow`), F5 (namespaces after genesis, a live-rule registry), F6 (opaque members), F7
  (location statements).
- Needing no door: F8 (invites).

## 0.4.0 — 2026-11-08

**Keys and the keyring.** A clean break from 0.3's authority: no 0.1 or 0.3 authority record is
interpreted. Older libraries move to 0.4 by clean copy. Spec: [colophon-0.4.md](spec/colophon-0.4.md),
[colophon-0.4-keys.md](spec/colophon-0.4-keys.md).

### Protocol

- A keyring of controllers replaces the root and the recovery identity. Controllers are
  passkeys, security keys, device owner keys and recovery kits, with `approve`, `control`
  and `recover` roles, a control threshold and a recovery threshold.
- Authority records carry `raw` or `webauthn` signatures and cosignatures. WebAuthn checks are
  exact: challenge, origin (with an allowlist for Android app origins), RP hash, flags, strict
  DER, and high-S accepted.
- Epochs are sealed to a vault, which opens through `sealed`, `prf` or `combined` slots. New
  PRF routes are built only from a credential-restricted assertion, and are bound to the
  published descriptors.
- Recovery only adds. It can't manufacture control below the control threshold.
- Removing a controller, demoting one, or changing its agreement key or slots rotates the vault.
- Controllers aren't members, and no key serves two principals. Agents can never hold authority.
- The root import role becomes an expiring `grant.import`.
- `reshare`, `handover` and `recover` are removed.

### SDK

- **Rust core:** `keys`, `vault` and `slots` modules; authority 4; keyring actions; WebAuthn
  registration parsing.
- **FFI and WASM:** the full key surface, including `begin_create_with` with a recovery kit in
  genesis and `importedFrom`.
- **Swift:** sessions with a separate owner controller and member, kit restore, and the new
  `ColophonKeys` product (passkeys, security keys and Secure Enclave owner keys).
- **Kotlin and Android:** the same session model, Credential Manager passkeys and Keystore
  owner keys.
- **JavaScript:** `Library.createWith`, WebAuthn and WebCrypto providers, and the playground
  on 0.4.
- **Clean copy:** `colophon-clean-copy` in `reference/swift`. It reads an old library as a
  member, without its root; imports into a fresh 0.4 library; and verifies by accounting plus
  an independent reference import.

### Conformance and review

- `conformance/0.4/`: 98 key cases and a complete library fixture.
- Two specification review rounds and an independent implementation security review. Two
  medium findings were fixed, and the final pass reported "Ready to ship: yes".
- Known deviation D-F2-1: a cold 200-entry keyring replay takes about 55 ms, against a 20 ms
  budget.

### Fixes along the way

- The Apple build script no longer leaks deployment-target variables into host proc-macro
  links (which broke on macOS 27), and builds each slice in its own target directory.
- Swift sessions serialize blob scans with refreshes, which fixes intermittent `notReady`.
- Android sessions compute kept digests from the full snapshot on revocation, and keep the
  original engine until rejoin succeeds.
