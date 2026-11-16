# Colophon 0.5 bindings (packages B1 and B2)

The UniFFI (`colophon-ffi`) and wasm-bindgen (`colophon-wasm`) exports of the 0.5 Rust core. This is the
contract the Swift, Kotlin/Android and JavaScript SDK layers are written against. The 0.4 exports are
untouched and keep working (an in-place upgrade reads a 0.4 library first, and the SDKs move over one at a
time).

**One source, two crates.** The surface is written once, in `crates/colophon-ffi/src/v05/api/`.
`colophon-ffi` compiles it with the `native05` feature (UniFFI attributes); `colophon-wasm` includes the same
files by `#[path]` with the `web05` feature (wasm-bindgen attributes). The list of exported names, records,
fields and enum variants is `crates/colophon-ffi/src/v05/surface-names.txt`; each crate has a test that
computes its own list from the sources and fails if it differs. The two features cannot be on together:
`--all-features` is refused by a `compile_error!` that says to build each crate with its own feature.

## 1. Shape

Everything that crosses is **typed**: records, C-like enums, bytes, strings, integers, booleans, options and
lists. Every binary field is bytes (`Data` / `ByteArray` / `Uint8Array`), never base64. JSON appears only
where the protocol or a domain leaves the value open, as in 0.4: terms, the policy document, the `change` of
a transition, built slots, record payloads, import batches, blob manifests, and `view`,
`query`, `history`, `operation_at`, `ledger`, `proposals` and `tools` results. Those fields and calls are
named `*_json`. Async is the SDK layer's concern (as in 0.4): every call is synchronous.

An action is one method per action (`begin_approve`, `begin_revoke`, ...), each with typed arguments. (The
spec asked for an enum with one variant per action; wasm-bindgen cannot export data-carrying enums, and one
method per action carries exactly the same typed fields on both platforms, as 0.4's `begin_*` did.)

**Naming.** Methods and fields are `snake_case` in Rust and on the web (as 0.4's wasm exports); the Swift and
Kotlin generators camel-case them. Enum variants are UpperCamel (`Cold`; Swift `.cold`, Kotlin `COLD`, web
numeric `OpenMode.Cold`). Record names that 0.4's UniFFI namespace already has carry an `Account` prefix: `AccountSigningStep`,
`AccountMember`, `AccountMemberKind`, `AccountGrant`, `AccountDenial` and (new in B2) `AccountIdentity` and
`AccountIdentityKind`. The generic names `Status`, `Report`, `Signature`, `Policy`, `Home`, `Header` and
`Conflict` share one namespace with 0.4's; an SDK that imports both qualifies them.
On the web, a record is a class with a constructor taking every field in order and a getter and a setter per
field; `u64` and `i64` are `bigint`; `optional<T>` is `undefined`.

## 2. Objects and calls

| Object | What it is |
| --- | --- |
| `AccountEngine` | The session: reads the host's record source; unlock; refresh; reads; every action; live state; blobs; imports; saved state; the exchange. The only object a session needs. |
| `AccountAction` | A prepared action held in Rust. One-shot. |
| `AccountCreation` | Creation before any store exists: PRF, genesis, first `rekey`; the result is the account ID and the stores; `open_engine(source, listing, namespaces, batch, key, now_ms)` then opens the session over the stored result, unlocked as the creation left it (the owner is asked once at first run). |
| `SwiftSuccessorCreation` | The genesis of the account that succeeds a Swift library: the carried controllers, the rebuilt slots (one passkey assertion each), the `handover`; the result is the account ID and the stores. Every other step of the Swift move needs an account made this way. |
| `AccountRequest` | A device's membership request before it is a member (public values only). |
| `AccountPairing`, `PairingFailureLimiter`, `PairingTransferKey` | The pairing ceremony (§7.3). A confirmed `AccountPairing` is also what approving a member spends (§9.1): see "Approving a member" below. |
| `AccountMove` | A prepared move step: the 0.4 upgrade, a Swift veto, F, a copier's shares, the migration. |
| `SwiftSource`, `SwiftCopyPlan`, `SwiftCopyDestination`, `SwiftCopyResult`, `AccountCopyWrite` | The Swift record copy: the predecessor library with its vault and keys, the plan with the host's translator, the import writes, the finished copy. |
| `AccountBlobWriter`, `AccountLiveWrite` | A streaming blob upload; a prepared live write. |
| free `account_*` | The standalone verifiers and helpers. |
| `HostSource` | The host callback: `read(path)`, `read_blob(path)`. |
| `SwiftTranslator` | The host callback of the copy: `translate(SwiftOpInfo) -> SwiftBatch`. |
| `AccountError` | The error of every call. |

### Prepare, sign, finish

`begin_*(..., entropy)` returns an `AccountAction`. A write refused for access reasons returns an action whose
`denial()` is set (a value, as in 0.4). `AccountAction.steps()` is `list<AccountSigningStep>`: copies of the
exact bodies and who signs them; `prf_requests()` is `list<PrfRequest>` (answer them with
`AccountEngine.provide_prf(action, list<PrfAnswer>)`, after which `steps()` is non-empty). The host signs
each `body` with the key named by `signer` and calls `AccountEngine.finish(action, list<Signature>)`: the core
assembles the bytes from its own state, verifies them under the history verifier, then changes. `Written`
holds `stores` to persist exactly as given, in order, and the typed `Changes`. A failed finish changes
nothing and consumes the action; prepare again with fresh entropy. An action finished on another session is
`WrongObject` (and not consumed).

| `begin_*` | Arguments (besides `entropy`) | Entropy |
| --- | --- | --- |
| `begin_approve` | `request: bytes`, `terms_json`, `signers`, `pairing: AccountPairing` (confirmed; spent) | 32 |
| `begin_renew` / `begin_renew_shares` | `member`, `expires_ms` (renew only), `signers` | 32 |
| `begin_revoke` | `member`, `keep: RevokeKeep`, `signers` | 32 |
| `begin_end_sessions` / `begin_end_my_sessions` | `member`, `signers` / none | 0 |
| `begin_rekey` | `namespaces`, `signers` | 32 |
| `begin_keyring` | `add_controllers: list<ControllerSpec>`, `add_slots_json: list<string>` (at most 1 MiB in all), `policy_json`, `signers` | 0 |
| `begin_add_controller` | `controller: ControllerSpec`, `mode: AddMode`, `signers`, `rule: RuleKind` | 0 |
| `begin_add_slot` | `signer`, `plan: SlotPlan` | 32 |
| `begin_rotate_vault` | `signer`, `has_plans: bool`, `plans: list<SlotPlan>` | 64 (new seed, entropy) |
| `begin_remove_controller` | `remove`, `keep`, `signers`, `rule`, `rotate: bool` | 64 if `rotate`, else 0 |
| `begin_transition` | `change_json`, `signers`, `rule` (a change with a `grant` is `refused:outOfScope`) | 0 |
| `begin_grant_transition` | `change_json` with a `grant`, `signers`, `rule`, `pairing: AccountPairing` (confirmed; spent) | 0 |
| `begin_veto` / `begin_suspend` / `begin_resolve` | as the core | 0 |
| `begin_write` / `begin_propose` | `namespace`, `kind`, `payload_json` | 32 |
| `begin_resolution` | `namespace`, `accept`, `proposals` | 32 |
| `begin_import` | `namespace`, `batch_json` | 32 |

### Approving a member

The core prepares a `grant` (or a transition's `grant` component) only by spending a confirmed
pairing for exactly the request's key (spec §9.1, §17.1). No call approves a member from its ID or a
code made from it. Exactly two pairings approve:

1. **The code (§7.3).** The joining device calls `AccountPairing.join(account, e, nb)` with `e` its
   request's `member.signing` and sends `commitment()`; the approving device calls
   `existing_receive_commitment(account, commitment, limiter, now_ms)` and `send_nonce(na)`; the joiner's
   `receive_nonce(na)` returns the reveal; the approving device's `receive_reveal(e, nb, limiter, now_ms)`
   returns the six digits, which both screens show (`digits()`). The person confirms they match:
   `confirm()` on the approving device. A mismatch is `reject(limiter, now_ms)` on either device and,
   on the approving one, counts as a failure; five failures in an hour close the limiter.
2. **The request scanned**, the scan path's one payload (§9.1): the approving device scans the
   canonical request envelope from the joining device's screen:
   `AccountPairing.scan_request(account, request, limiter, now_ms)` is confirmed for that request's
   `member.signing` (a request that does not verify is `pairing:invalidRequest`, another account
   `pairing:wrongAccount`; each counts as a failure). It carries no nonces and cannot move the seed.

`begin_approve(request, terms_json, signers, pairing, entropy)` and `begin_grant_transition(change_json,
signers, rule, pairing, entropy)` then spend it. A pairing that is not `Confirmed` (or already `Spent`) is
`Consumed` and left as it was. A confirmed one is spent whatever the answer: for another account or
another key, confirmed on the joining device, or confirmed by the pairing QR (`existing_scan_qr`,
which moves the seed only), `refused:outOfScope`; more than ten minutes after the
approving device's session began, or before it (a clock moved back), `refused:expired`. The joining device's
own confirmed pairing never approves. Appointing a home (`homes.appoint`) is outside this rule: its request
comes from the home's own base (a stated limit of §9.1).

**The approving device's ledger: one ceremony at a time, every start counted.** Every session the existing
device starts (`existing_receive_commitment`, `existing_scan_qr`, `scan_request`) comes from its
`PairingFailureLimiter`:

- Starting one **reserves** one of the five an hour; only a confirmed pairing gives it back (`confirm`, the
  pairing QR's `send_nonce`, a valid `scan_request`). Abandoning (`AccountPairing.abandon(now_ms)`), rejecting
  (`reject`), a mismatch, a reveal after the ten-minute timeout (`pairing:timeout`), dropping the object or
  restarting the device all leave it counted. Five counted in an hour: `pairing:limit`.
- **One ceremony is live at a time**: while one is (not ended, younger than ten minutes) another start is
  refused, `pairing:busy`, and never yields a nonce. A relay therefore cannot run sessions with its own keys
  beside the honest one and pick the one whose code matches. Start a ceremony only when the person asks; a
  commitment that arrives unasked is shown or dropped, never started.
- **Persist before the nonce.** `send_nonce` is refused, `pairing:unsealed`, until the host took
  `limiter.seal(device_key, account, entropy)` after the start; the host writes the sealed bytes and
  `limiter.generation()` beside them, and only then asks for the nonce. A host that cannot write sends none.
- **Open on start**: `PairingFailureLimiter.open(sealed, device_key, account, floor, now_ms)`, with the
  generation recorded beside it as `floor` (0 when none). Missing bytes with a floor, an edited or foreign
  ledger, another device key, or a generation below the floor open as a spent budget.
  `PairingFailureLimiter.fresh()` is an in-memory ledger (tests; a device's own request). `is_live(now_ms)`
  and `may_start(now_ms)` answer without changing anything.
- **Every instance over one store.** One limiter object coordinates only itself. The session layers take a lock that
  every instance sharing the private store takes (Swift: `flock` on `pairing-ledger.lock`; Kotlin: `FileChannel.lock` on
  it, behind a JVM-wide monitor; JavaScript: a Web Lock, or a process-wide lock where the platform has none), reload the
  ledger under it whenever the stored generation is not the one they hold, and write before releasing it. A host that
  uses the bindings directly must do the same: two limiters opened from one store must never start ceremonies apart.
- **Clock.** A start on a clock outside 1970 to 9999 is refused (`pairing:clock`); nothing the ledger keeps can then
  overflow its timeout or its hour. A clock moved back is floored (the ledger keeps the latest time it saw) until it has
  stayed more than five minutes behind that floor for an hour of its own time; the ledger then re-anchors at it, dropping
  what was stamped in the future. A forward mistake therefore clears an hour after the clock is corrected, and moving the
  clock back gains nothing the hour would not have given.
- `fresh()` is for a device that keeps no ledger (a test, a device's own request at creation): a host must never call
  it for an account whose ledger exists, or the budget is gone. `seal` takes 32 bytes of fresh entropy on every call:
  the GCM nonce comes from it, so entropy must never be reused under one device key.
- **Residual limit:** a host or backup that restores the private store wholesale (the sealed ledger and its
  recorded generation together) restores the budget; the device key is not a counter, so the core cannot see
  it. Within one process the ledger never goes back.

### `AccountEngine`

`open(source, listing: list<ListedPath>, identity: AccountIdentity, account, namespaces, batch, saved:
SavedState, key, now_ms)` (`identity` is a record: `kind` Controller or Member and the 32-hex key `id`;
`listing` carries each path's content version in one batch, an empty version meaning none; empty
`SavedState` means none). Reads: `id identity status head_seq
head_digest controllers homes policy pending owed_shares notices(shown_seq, shown_transitions, local_keys)
slots is_unlocked begin_unlock_slot(index) begin_unlock_epochs fork_candidates suggest_signers(available, need)
latest_epoch write_denial record_verdict verdict_of (each `optional<RecordVerdict>`) live_heads open_info stats access revision revisions removal_follow_up me
members`, and JSON: `proposals_json tools_json ledger_json view_json query_json history_json
operation_at_json blob_manifest_json`. Progress: `load refresh(listing) apply_paths(list<ListedPath>) advance
finish_unlock_slot(index, list<UnlockSecret>) finish_unlock_epochs(list<EpochAnswer>) apply_live stale_live
live_verdicts missing_covered budget_scope_unavailable rejudged save(nonce_seed) verify_batch(limit)`. Blobs:
`begin_blob open_blob_chunk blob_chunk read_blob blob_availability required_blob_fetches`. Live: `begin_live_write
finish_live_write`. Exchange: `exchange_homes exchange_set_bearer exchange_next(home) exchange_begin_call exchange_provide_call
exchange_answer(home, ticket, HttpAnswer) exchange_want_blob receipted_by`. Session: `record_due set_read_scope lock is_locked
transfer_seed accept_seed_transfer accept_predecessor_entry exchange_abort source_faults version_paths
begin_link begin_call` (a link or call's envelope is `Written.artifact`). Move: `swift_succession
swift_predecessor begin_swift_veto begin_swift_freeze begin_swift_copier_shares begin_swift_migration
finish_move swift_copy_destination begin_swift_copy_write finish_swift_copy_write finish_swift_copy`.

The exchange: `exchange_next` returns an `ExchangeStep`: `Request` (with `request: HttpRequest`: ticket, home,
method, url, headers, body), `NeedCall` (with `need: CallNeed`: ticket, home, audience, purpose, method, url,
path, body_sha256), `Waiting` or `Done`. The host performs the request and answers it; the `Report` has `store`
(persist), `changes` and `faults: list<ExchangeFault>`.

A call for a `NeedCall`: the engine has already built the request, so the need carries everything the host signs.
`exchange_begin_call(home, ticket, key, entropy)` prepares it (audience `need.audience`, the home's base; purpose
`need.purpose`, `colophon.home.read` for GET, `colophon.home.write` otherwise; `args` exactly
`{"method","path","body"}` = the method, `need.path` (path and query relative to the base, as sent) and
`need.body_sha256` (lowercase hex SHA-256 of the body, of the empty string when none)). The host signs its one step
with the session's key and calls `finish`: the core judges the call with the home's own rule
(`colophon_core::v05::calls::check_home_call_as_signer`, the same code a home runs) over what the account holds,
and returns the envelope as `artifact`; give it to `exchange_provide_call(home, ticket, artifact)`. The next
`exchange_next` returns the request carrying it. A host that builds calls itself uses the same fields. A pass
starts with the public head (and, at `headQuorum` above 1, the other homes' public heads: a `Request` whose URL is
at another home of the account, sent to that home, answered with this home) so a call can be built for what
follows. A signer behind a home's fresh head is judged at what it holds; one that does not find itself there may
still read with its own key at a home it is behind (an approval it has not fetched), and the home decides.

Standalone: `account_verify_history`, `account_webauthn_check(KeyDescriptorView, body, der_signature,
authenticator_data, client_data, WebauthnMode)`, `account_verify_swift_predecessor`, `account_key_id`,
`account_webauthn_prf_input`, `account_vault_public`, `account_format_date`, `account_request_info`,
`account_default_policy`.

### Key descriptors and controllers

One encoding on the whole surface, input and output: `KeyDescriptorView` is the protocol descriptor of §3.1
(`form`, `signing`, and `agreement` for raw, or `rp`, `credential`, `origins`, `authority_origins` for
webauthn). A step carries it as `descriptor`; `account_webauthn_check` takes it; a controller to create is a
`ControllerSpec` (`key: KeyDescriptorView`, `label`, `roles: list<ControllerRole>`, `verification`, `holder`,
`audiences`) in `CreateParams.controllers`, `begin_keyring` and `begin_add_controller`: no SDK writes base64
protocol JSON. `SignForm.Unknown` is a key of a form a newer writer made (it is shown, never created or
checked). The `Controller` record carries its `key: KeyDescriptorView`, so a second device can show a
passkey's `rp` and build the descriptor `account_webauthn_check` takes.

### The Swift move: store paths

Every step of a move hands the host exactly what it must store, with the path, and a host that stores
exactly that reopens cold at the same stage. Paths are in the account's own store (the host's record store):

| Step | Returned in | Stored at |
| --- | --- | --- |
| Successor genesis | `SwiftSuccessorCreation.take_result().stores` | `authority/00000001.json`, and the predecessor entries at `predecessor/authority/<seq>.json` |
| Veto | `AccountMove.finish` `stores` (and `veto`, `veto_path`) | `vetoes/<sha256 of the body>.json` |
| F | `finish_move` `stores` (and `frozen_entry`, `frozen_seq`) | `predecessor/authority/<seq>.json` in the account's store; **and** `frozen_entry` is the exact Swift bytes the Swift side appends to the library's own `authority/<seq>.json` through the Swift code |
| A copier's shares | `finish_move` `stores` | `authority/<seq>.json` |
| The migration | `finish_move` `stores` | `transitions/<digest>.json` (it activates after its delay: `record_due` returns the activation's stores) |
| An import write of the copy | `finish_swift_copy_write` `stores` | the record's `ops/...` path |

`<seq>` is eight digits. Homes' receipts, heads and the `successionVetoed` entry are the home's and arrive
through the exchange. A reopen over these objects reports the same `swift_succession().stage`: after F it is
`Frozen`, never `Due`, and a second, different F is refused (by `begin_swift_freeze` in stage `Frozen`, and by
`finish_move` when another F was held between prepare and finish).

**Every move step refuses a stale or repeated step**, as ordinary actions do. A copier-shares or migration
step finishes only while the head is still the head it was prepared on: a second one prepared at the same
head is `Refused` with reason `fork` at `finish_move`, with nothing returned, stored or changed. At prepare:
a second `begin_swift_copier_shares` once the member owes nothing, a second `begin_swift_migration` while a
`migration` transition is pending (a twin prepared earlier does not finish either), and a second
`begin_swift_veto` while a veto of this succession is held, are refused. The successor genesis runs every
check that does not need the built slots before it asks for a passkey assertion (the signers and the
handover keys are controllers, no key twice, the dates, `earlier_attempts`): a genesis that cannot succeed
fails at `begin`.

**`earlier_attempts` and a live attempt.** An earlier freezing entry's successor blocks a new genesis
unless it can no longer verify: it is **vetoed**, or its F was written before it was due (**premature**:
the window never opened, or F is dated before the due time).
An attempt that is merely not yet verified, waiting for a home's head, is live and blocks (`still live`);
one that has verified makes the predecessor final. The rule sits in `write::succession::check_earlier_attempts`.

## 3. Errors

Every call returns `AccountError` or succeeds. A host branches on the variant or on `code`; `detail` is for
logs and never carries key material. `Refused` carries the §19 reason; `Denied` the access reason.

| Variant | `code` | Meaning |
| --- | --- | --- |
| `Malformed` | `malformed` | A rule is broken; also an argument that is not valid JSON. Pairing aborts: `pairing:commitmentMismatch`, `pairing:invalidPoint`, `pairing:wrongAccount`, `pairing:invalidRequest` (a scanned request that does not verify), `pairing:timeout` (a reveal after the ten-minute ceremony timeout). |
| `BadSignature` | `badSignature`; from `account_webauthn_check` `badSignature:<check>`, with `check: SignatureCheck` | A signature, assertion, possession proof or key binding failed. Checks: `point rawLength scalar der verify clientData clientDataBound unknownForm type challenge origin crossOrigin relyingParty userPresence userVerification form callOrigin`. |
| `NewerFormat` | `newerFormat` | Authenticated content of a newer format. |
| `Unavailable` | `unavailable` | Something needed could not be obtained. |
| `Refused` | `refused:<reason>`, `reason` | `audience window replay conflict fork revoked expired ended notNarrower outOfScope origin rollback notGranted wrongEpoch clockJump budgetSpent wrongFormat invalidPayload caveatedLive vaultLocked`; also `pairing:limit` (reason `pairingLimit`), `pairing:busy` (`pairingBusy`: another ceremony is live), `pairing:clock` (`pairingClock`: an implausible clock), `pairing:unsealed` (`pairingUnsealed`: the ledger was not sealed since the start). |
| `Denied` | `denied:<reason>`, `reason` | `notGranted revoked expired budgetSpent notReadable unavailable`. |
| `Host` | `host` | A host callback failed; `detail` is the host's own message (a foreign exception arrives here too). |
| `Reentered` | `reentered` | A callback called back into the object that was calling it, on the same thread; or a call from another thread waited more than 30 s for an object whose holder was inside a host callback (see "Threads and callbacks"). |
| `Consumed` | `consumed` | A one-shot object was used up, or a pairing step is in the wrong stage (nothing consumed then). A creation (or a successor genesis) whose step failed or was out of order is spent: the failure ended it, and every later step is `Consumed`. |
| `WrongObject` | `wrongObject` | An action was finished on another session. |
| `Bound` | `bound` | An argument exceeded a bound or has the wrong length. |
| `Integrity` | `integrity` | The engine found its source or home inconsistent and is unusable; discard it. Every later call on that engine is `Integrity`, reads included. Not a mistake in the call. |
| `Locked` | `locked` | `lock` was called. The engine refuses to unlock, load, save, prepare an action or finish one (a prepared action is not consumed by the refusal); the verified history can still be read. Open a new engine. |
| `Internal` | `internal` | A panic was caught; discard the object. |

On the web the thrown `AccountFault` (a real `Error` subclass) has `kind`, `code`, `detail` and `reason`
(the §19 reason of a `Refused` or `Denied`, else `undefined`), as the native variants do. Errors that
wasm-bindgen raises itself before a call reaches Rust (a wrong class passed, an object that was already
consumed, an invalid enum value) are plain `Error`s with no `kind`: they are bugs in the SDK, not
protocol results.

## 3a. Threads and callbacks

**The rule.** A host callback (`HostSource.read`, `HostSource.read_blob`, `SwiftTranslator.translate`) is
synchronous. It must not call into the engine (or any object) that is calling it, and it must not block on
anything that does. A callback may do its own I/O, and it may be slow.

What is enforced and what is not:

* A callback that calls the object that is calling it, **on the same thread**, fails at once with
  `Reentered`; nothing is changed.
* A call from **another thread** waits for the engine (as 0.4's does), and keeps waiting for as long as
  the holder makes progress: a long `load` or `refresh` made of many short callbacks never fails a waiter.
  It fails with `Reentered` (its detail says why) only when **one single host callback of the holder has
  itself run for more than 30 seconds** while it waited: the clock is the current callback's, not the
  waiter's total wait. A slow disk read that takes 31 s is such a callback; a thousand reads of 0.1 s are
  not. The limit is `set_callback_wait_ms` in Rust test builds; there is no host setting. A failed wait
  changes nothing and **never consumes a prepared action or move step** (`finish`, `finish_move` and
  `finish_swift_copy_write` take the action only once they hold the engine, in the same step that checks
  `lock`), so a `Reentered` or `Locked` finish is retryable with the same signatures. On `wasm32` there is
  no second thread and no clock (`std::time::Instant` does not exist there), so the timed wait is compiled
  out: a waiter blocks on the lock.
* What cannot be detected: a callback that waits on something else that waits on the engine (a lock, a
  queue, a main-thread hop). The 30-second bound applies to every call that waits on the engine, but the
  callback's own wait is the host's. On the web there are no threads: a callback that returns a `Promise`
  is refused (below), and an `await` inside a callback cannot be written.
* `SwiftSource` holds its lock while `SwiftCopyPlan.read` runs the translator; the same rule applies to the
  translator, and the 30-second bound does **not** apply to the source's lock (the translator is the host's
  own code on the same call).

A callback that throws is `Host` with its message. On the web a callback must return a `Uint8Array`
**synchronously**: a `Promise` (an IndexedDB host that did not read ahead), `undefined`, `null`, an `Array`, a
string or a number is a `Host` error whose detail names the callback (`JsSource.read`, `JsSource.readBlob`,
`JsTranslator.translate`); nothing is coerced, and an empty `Uint8Array` still means "not held" for
`readBlob`. A translator must return a fresh `SwiftBatch`, not one already passed to a call.

## 3b. Lifecycle

Which objects hold secrets or locks, and when each is released:

| Object | Holds | Released when |
| --- | --- | --- |
| `AccountEngine` | The vault seed and epoch keys once unlocked, the device key, the opened plaintext; one lock. | `lock()` overwrites the keys and the opened plaintext; the object itself is freed when dropped. **Call `lock()` before dropping** whenever the session ends with secrets open: dropping erases the core's keys too (best effort), but only `lock` also clears the opened plaintext at a moment you choose. |
| `AccountAction`, `AccountMove`, `AccountCopyWrite`, `AccountLiveWrite` | A prepared action's retained state (entropy-derived seeds and bodies). | The call that finishes or consumes it, or its drop. A prepared action does not finish after `lock`: `Locked`, and the action is not consumed. Prepare again on a new engine. |
| `AccountCreation`, `SwiftSuccessorCreation` | The new vault seed until `take_result` (`AccountCreation`: until `open_engine`, which hands it to the engine, or drop; or a failed step, which ends it). The creation parameters erase the seeds they held when they drop. | `take_result`, a failed step, or drop. |
| `SwiftSource` | The opened Swift vault and namespace keys. | Drop. There is no wipe call: drop it as soon as the copy is finished. |
| `AccountBlobWriter` | An epoch key. | `finish`, or drop. |
| `PairingTransferKey`, `AccountPairing` | The transfer key's private scalar; the pairing's session secrets. | Consumed by the call that uses them, or drop. |
| `SwiftCopyPlan`, `SwiftCopyResult`, `SwiftCopyDestination` | Public and decrypted records of the copy. | `finish_swift_copy` consumes the plan; drop. |

* **Kotlin/Android:** every object has `close()` (and `AutoCloseable`): use `use { }`. Without it a Cleaner
  frees the object at no fixed time, and the secrets stay until then.
* **Swift:** an object is freed when its last reference goes (ARC). Hold it no longer than the session.
* **JavaScript:** a wasm-bindgen object is freed by `.free()`; without it a `FinalizationRegistry` frees it
  at no fixed time (not at all on some runtimes). Call `.free()` on every object you are done with, and
  `lock()` before it for an engine. After `.free()` the object is dead: using it throws a plain `Error`.
* **Web records are consumed when passed to a call.** A record or a list of records passed **by value** to
  an export (a `SavedState`, a `ListedPath[]`, a `CreateParams`, a `Signature[]`, an `AuthorityObjects`, a
  `SwiftBatch` returned from a translator) is moved into Rust: the JS object is dead after the call and
  using it again throws. Build a new one per call. Every getter of a record field that is a list or bytes
  returns a **copy** (a `Vec<Store>` getter deep-copies): read it once into a variable. The three secret
  records (`PrfAnswer`, `UnlockSecret`, `EpochAnswer`) are wiped by the call that consumes them; the
  `Uint8Array` you built the secret from is yours and is not wiped by the binding: overwrite it yourself.
  Native (Swift, Kotlin) records are values: the foreign copy is the host's to overwrite.

## 4. What crosses, and what never does

**Never returned, logged, or serialized:** vault seed bytes; epoch key bytes; a PRF output or ECDH result read
back; the sealed-state key; a prepared action's retained state; a transfer key's private scalar. No type here
has a `Debug`, `Clone` or serial form that includes one: the three records that carry a host secret
(`PrfAnswer`, `UnlockSecret`, `EpochAnswer`) have no `Clone` even on the web build.

**Crosses in, consumed and wiped by the binding:** PRF outputs, ECDH results and epoch shares (fields of the
three secret records), entropy (`Vec<u8>`), the nonce seed of `save`, and the device-held sealed-state key.
The binding overwrites **every copy its own code makes**, on every path including refusals:

* the vault seed and the action entropy cut into 32-byte seeds (`seeds32`) are held in one block that is
  overwritten when it drops, so `begin_rotate_vault`'s new vault seed and every `begin_*` seed are wiped
  also when the call is refused;
* the epoch shares given to `finish_unlock_epochs` are wiped on every path, including a failure before they
  are converted (`Reentered`, a poisoned lock), and `finish_unlock_slot`, `provide_prf` and
  `SwiftSource.finish_open_slot` convert first;
* the creation parameters (`CreateParams`, in the core) overwrite the vault seed and the two entropy seeds
  when they drop.

**The class that code cannot reach, and what closes it.** Every secret that crosses the native boundary
(a `Vec<u8>` argument, or a record that holds one) arrives in a transfer buffer the UniFFI scaffolding
allocates, copies out of, and frees without overwriting; the same holds for any value the compiler moves out
of a `Box`. `colophon-ffi` and `colophon-wasm` therefore install a **global allocator that overwrites every
block it frees with zeros** (`src/v05/zero_alloc.rs`, about 120 lines over the system allocator, no
dependency; feature `zero-on-free`, on by default; `realloc` is allocate, copy, zero the old block, free, so
a grown buffer leaves nothing behind). `v05_secrets.rs` calls the real exported scaffolding symbols
(`uniffi_colophon_ffi_fn_method_accountengine_finish_unlock_slot`, `...finish_unlock_epochs`,
`...accountcreation_begin`, `...accountcreation_provide_prf`, `...swiftsource_finish_open_slot`) and scans
every freed block for the secret in raw, base64, base64url and hex form, at two moments: before the wipe and
after it. Measured (debug, this repository):

| What | Freed blocks holding the secret, before the wipe | After the allocator's wipe |
| --- | --- | --- |
| Every Rust-API path (unlock slot, epochs, PRF, Swift slot, `begin_*` entropy, creation, refused calls) | 0 | 0 |
| The same call through the real scaffolding symbol | 1 each (the transfer buffer) | 0 |
| A full creation to `take_result` | 2 (the core's by-value move of `Creation` out of its box) | 0 |
| A control: a `Vec` holding the secret dropped, and one grown by `realloc` | 1 and 2 | 0 |

**Not covered, exactly:** a block that is still allocated (a live copy is its owner's to wipe: a `PrfAnswer`
the host still holds; the core's engine keeps the device key and the opened keys until `lock`, drop or
`Engine` erase); the stack and registers (a `[u8; 32]` seed copied by value lives in a frame until it is
overwritten); copies the host language makes in its own heap (`Data`, `ByteArray`, `Uint8Array`, a JS
string); memory the operating system pages out, or a core dump, while a block is live; a process killed
before the free; and the folded domain state of each namespace (freed, not overwritten, until the block is
freed and the allocator wipes it). With the feature off (see "Cost") the transfer-buffer copy stays in freed
memory as it does in 0.4.

**Who installs it.** The allocator is the `#[global_allocator]` of the **library crate**, so it applies to
the cdylib and staticlib the Swift and Kotlin hosts load, and also to the rlib: a Rust binary that depends
on `colophon-ffi` (or `colophon-wasm`) with default features gets this allocator and cannot define its own
(a second one is a link error). A Rust user of the rlib that needs its own allocator depends on the crate
with `default-features = false, features = ["native05"]` (for `colophon-wasm`, `["web05"]`), which also
turns the wipe off; `zero_alloc::ZeroOnFree<A>` is public so that it can wrap its own allocator instead.

**Cost of the allocator.** One `memset` per free and a copy per `realloc` (no in-place growth). Measured with
`tests/v05_alloc_bench.rs` (release build, through the exports: a cold open over 1,000 records, 1,000 writes
and a refresh, the best of three rounds, run with and without the allocator, two runs each):

| Run | Allocator | 1,000 writes | Cold open (1,000 records) | Refresh | Total |
| --- | --- | --- | --- | --- | --- |
| 1 | zero-on-free | 785.5 ms | 293.8 ms | 0.97 ms | 1,080.2 ms |
| 1 | system | 776.7 ms | 288.3 ms | 0.94 ms | 1,066.0 ms |
| 2 | zero-on-free | 787.6 ms | 288.5 ms | 0.95 ms | 1,077.0 ms |
| 2 | system | 797.6 ms | 297.3 ms | 0.98 ms | 1,095.9 ms |

The difference is +1.3 percent in run 1 and -1.7 percent in run 2: inside the run-to-run noise, and far under
the 10 percent line, because the work is dominated by P-256 verification and signing, not by freeing memory
(the engine cost test, which runs in `colophon-core` and does not use the allocator, measures the same
engine).

The allocator stays **on by default**; `--no-default-features --features native05` (or
`default-features = false` for the wasm crate) turns it off.

The host is trusted with these secrets exactly as the core's header says.

**Never accepted from the host:** verified state, a `PendingAction` or `SigningStep`, a keyring, terms, a
fold, a seed. Saved state is accepted only sealed under the device key; one that fails its seal is ignored
and the history replays (`open_info` says so).

## 5. Bounds

Every bound is checked on the raw length, and for a list on the sum of the raw lengths, before anything that
scales with it is parsed or allocated.

* **JSON documents** (`*_json` arguments): a domain document (record payload, import batch, a translated
  child) is at most **1 MiB**; an authority-protocol document (policy, terms, a `change`, a built slot) is at
  most **1 MiB**. The numbers are the protocol's own: a record payload is at most 1 MiB canonical in the core
  (`domains/saved`, `Engine::begin_import`), an import batch at most `MAX_BATCH_BYTES` = 1 MiB, an authority
  body at most 1 MiB (§2.4). The bound was 4 MiB; one 4 MiB item then peaked at 192 MiB.
* **A cost budget, never a shape rule.** The text is scanned once with a running cost count (32 bytes
  per value, a string its bytes, 64 per object entry), abandoned the moment the count passes, and refused
  `Bound` only when it passes **32 MiB**, which no document within the length bounds can: the costliest 1
  MiB documents (a million one-digit numbers' worth, `[0,0,...]`, or the densest object) cost about 17 MiB by
  that count. So a compact array of 600 small numbers (1.2 KB), 100,000 of them, one 1 MiB string and an
  import batch at the core's own maximum are all accepted; a text with spaces and the same value without
  are alike. (An earlier rule of one structural element per 8 bytes refused ordinary app values and, in the
  Swift copy, the core's own re-serialized output; it is gone.) A value the core itself produced and the
  host passes back (`CopyItem.payload_json`) is checked on length only, never on cost.
* **A list of JSON documents** (`add_slots_json`, `SwiftBatch.alternatives_json` and `blobs_json`, a batch's
  `children`) is at most 256 items (4,096 for a translated batch) and the items together are at most 1 MiB,
  checked on the raw lengths before any item is parsed. A translated batch's payloads, alternatives, blob
  manifests and evidence together are at most 1 MiB. Controllers are typed, at most 64.
* **Measured** (`v05_secrets.rs`, debug build; "peak" is the bytes live above the call's own text).
  Refusals: eight 4 MiB items to `begin_keyring` and one 4 MiB item are `Bound` with **195 bytes** of peak
  (before the bound: 1,088 MiB and 192 MiB); a 64 MiB argument is refused with **296 bytes**.
  **Valid 1 MiB writes taken to completion** (prepared, signed, finished; the core validates, canonicalizes
  and seals the payload, which makes several copies of it): 600 small numbers (1 KiB) 182 KiB; 100,000 small
  numbers (195 KiB) 24.1 MiB (126 times); one 1,023 KiB string 17.3 MiB (17 times); an array of 6-byte
  strings 39 MiB (39 times); the densest object of short keys, 1,023 KiB, **82 MiB (82 times its text)**.
  The binding itself holds the text and one parsed value (at most about 17 MiB by the budget's count);
  the rest is the core's, whose files this package does not change. **So a 1 MiB write may peak near 85
  MiB; a host with a smaller cap (an iOS share extension) keeps payloads small, and an authority
  `change` of 1 MiB peaks at about 37 MiB.** The earlier figure of 40 MiB was measured up to a refusal
  by the validator, not to completion.
* Binary argument: 40 MiB (a `ListedPath`, `ByteString`, `Store` list: 262,144 items; the objects of
  `AuthorityObjects` and `earlier_attempts` 40 MiB in all). Name lists (signers, namespaces, slot
  controllers, shown transitions, local keys): 256. Entropy: exactly the 32, 64 or 96 bytes the call says;
  the sealed-state key 32. Signatures list 256; signature or assertion field 64 KiB. Bearer token 8 KiB;
  call 16 KiB; HTTP response body 128 MiB; headers 256; blob chunk 64 KiB (writer) and 1 MiB (open); QR
  payload 4 KiB; limiter state 64 KiB; a request or entry blob 40 MiB. The core adds its own bounds.

A callback that returns garbage is judged by the core. A callback that fails is `Host` with its message. A
callback that re-enters is `Reentered` (see "Threads and callbacks"). A finish that fails changes nothing.

## 6. Types

Enums are C-like. A record's `optional` field is set only as its doc says.

| Enum | Variants | Meaning |
| --- | --- | --- |
| `StepRole` | `Primary`, `Cosignature`, `Possession`, `Handover` | What a signature is for in a batch. |
| `SignForm` | `Raw`, `Webauthn`, `Unknown` | The signature form a signer uses. `Unknown` is a form a newer writer made: shown, never created or checked. |
| `ControllerRole` | `Approve`, `Control`, `Recover`, `Sign`, `Unknown` | A controller's role (§6.1); `Unknown` a role a newer writer made. |
| `ActionKind` | `Approve`, `Renew`, `RenewShares`, `Revoke`, `EndSessions`, `EndMySessions`, `Rekey`, `Keyring`, `AddController`, `AddSlot`, `RotateVault`, `RemoveController`, `Transition`, `Veto`, `Suspend`, `Resolve`, `Write`, `Propose`, `Resolution`, `Import`, `Link`, `Call` | What kind of action a prepared action is (`AccountAction.kind`). |
| `MoveKind` | `Upgrade`, `SwiftVeto`, `SwiftFreeze`, `SwiftMigration`, `RenewShares`, `Finished` | What step of a move a prepared `AccountMove` is; `Finished` once finished or consumed. |
| `SlotKind` | `Sealed`, `Prf`, `Combined`, `Unknown` | How a vault slot opens (`SlotInfo.kind`, `SwiftSlotInfo.kind`). |
| `HomeStatus` | `Home`, `RevocationPending`, `Unknown` | Whether a home is serving, or its removal has not activated finally. |
| `AccountDenialReason` | `NotGranted`, `Revoked`, `Expired`, `BudgetSpent`, `NotReadable`, `Unavailable`, `Unknown` | Why access was refused (§19 access reasons). |
| `SignatureCheck` | `Point`, `RawLength`, `Scalar`, `Der`, `Verify`, `ClientData`, `ClientDataBound`, `UnknownForm`, `Type`, `Challenge`, `Origin`, `CrossOrigin`, `RelyingParty`, `UserPresence`, `UserVerification`, `Form`, `CallOrigin` | The WebAuthn check of §4.3 that failed: `BadSignature.check`. |
| `CountBy` | `Keys`, `Holders` | How a threshold counts signers (`UpgradeParams.count_by`). |
| `AccountIdentityKind` | `Controller`, `Member` | The kind of a session's identity. |
| `StatusKind` | `Ok`, `Held`, `Refused`, `Malformed`, `BadSignature`, `NewerFormat`, `Unavailable` | The §1 result of a verification without the refusal's reason (`Status.kind`, `HistoryReport.kind`; the reason after `refused:` is `reason`). |
| `VerdictKind` | `Admitted`, `Held`, `Refused`, `NewerFormat`, `Malformed`, `BadSignature`, `Unavailable` | What the engine judged a record to be (§11.5), without the reason (`RecordVerdict.kind`). |
| `AccountMemberKind` | `Device`, `App`, `Agent`, `Server`, `Unknown` | A member's kind. |
| `HttpMethod` | `Get`, `Post`, `Put` | An HTTP method. |
| `OpenMode` | `Cold`, `Resumed`, `Invalidated` | How an engine open treated saved state. |
| `ExchangeStepKind` | `Request`, `Waiting`, `NeedCall`, `Done` | What the exchange asks the host to do next. |
| `ExchangeFaultKind` | `Rollback`, `Fork`, `BadObject`, `ForeignAccount`, `NoProgress`, `Mismatch`, `Refused`, `Conflict`, `Race`, `Unauthorized`, `Redirect`, `Malformed`, `CursorReset`, `More`, `HeadAhead`, `Status` | What a home did that the engine did not follow. |
| `LiveVerdictKind` | `Current`, `Superseded`, `Retained`, `Equivocation`, `Quarantined`, `Refused`, `Invalid` | What became of a live candidate. |
| `BlobState` | `Complete`, `Partial`, `Missing`, `Inaccessible` | How much of a blob is held locally. |
| `StandingKind` | `Controller`, `Member`, `Unknown` | What a session is in the verified history. |
| `KeepMode` | `Everything`, `Nothing`, `Explicit` | Which of a revoked member's records a revocation keeps. |
| `UnlockKind` | `Ecdh`, `Prf` | The route of a slot an unlock needs the host to answer. |
| `CreateStage` | `Prf`, `Genesis`, `Rekey`, `Done`, `Spent` | Where a creation stands. |
| `PairingStage` | `Joiner`, `Revealed`, `QrJoiner`, `Waiting`, `AwaitingReveal`, `Code`, `Scanned`, `Confirmed`, `Spent` | Where a pairing session stands. |
| `RuleKind` | `Control`, `Recovery` | The rule a transition is counted under. |
| `AddMode` | `Immediate`, `Transition` | How a controller is added. |
| `SignerNeed` | `Member`, `Rekey`, `Control`, `Recovery`, `KeyringAdd`, `Veto` | Which rule a set of signers is chosen for. |
| `CheckKind` | `Authority`, `Call`, `SwiftPredecessor` | Which check `account_webauthn_check` applies. |
| `AuthorityRuleKind` | `Control`, `Recovery`, `KeyringEntry`, `Transition`, `Veto`, `Handover`, `Single`, `Suspend`, `Possession` | The authority rule a signature is checked for. |
| `WriteLevel` | `Write`, `Propose` | Whether a write may be levelled as a write or a proposal. |
| `AccessKind` | `Read`, `Write` | The access a grant gives. |
| `MoveStage` | `WindowNotOpen`, `Waiting`, `Due`, `Frozen`, `Verified`, `Vetoed`, `Migrated` | Where a Swift succession stands. |

| Record | Fields (name: type) | Meaning |
| --- | --- | --- |
| `Store` | `path: String`, `bytes: bytes` | Exact bytes the host stores at a path. |
| `ListedPath` | `path: String`, `version: optional<String>` | A listed path with the provider's content-version token (none for none). |
| `ByteString` | `bytes: bytes` | One byte string (a list of them cannot be a field on every platform). |
| `AccountIdentity` | `kind: AccountIdentityKind`, `id: String` | Who a session is: a controller or a member with its 32-hex key ID. |
| `ControllerSpec` | `key: KeyDescriptorView`, `label: String`, `roles: list<ControllerRole>`, `verification: bool`, `holder: optional<String>`, `audiences: list<String>` | A controller to add, typed (§6.1). `verification` only for a `webauthn` key; `audiences` only for a `sign` controller. |
| `RecordVerdict` | `kind: VerdictKind`, `reason: optional<String>` | The verdict on a record the engine holds or would hold; `reason` is the text after `held:` or `refused:`. |
| `OriginsFor` | `controller: String`, `origins: list<String>` | The `authorityOrigins` (1 to 32 ascending) of one carried WebAuthn controller. |
| `AgreementFor` | `controller: String`, `agreement: bytes` | The agreement point of one carried raw controller the predecessor does not show. |
| `SwiftSuccessorParams` | `label: String`, `namespaces: list<String>`, `include_stewards: bool`, `authority_origins: list<OriginsFor>`, `agreements: list<AgreementFor>`, `threshold: optional<u64>`, `recover_threshold: optional<u64>`, `add_threshold: optional<u64>`, `count_by_holders: bool`, `policy_json: String`, `signers: list<String>`, `handover: list<String>`, `issued_ms: i64`, `earlier_attempts: list<AuthorityObjects>` | What the host chooses for the successor genesis of a Swift library (§15.1, §16.2). `signers` sign the genesis (the first is `by`); `handover` are predecessor controllers whose `handover` signature the host can obtain; `earlier_attempts` is, for each freezing entry already in the predecessor, the objects of the successor it named (§15.1 "Competing attempts"). |
| `SwiftCeremony` | `request: u64`, `old_slot: u64`, `controller: String`, `rp: String`, `credential: bytes`, `old_salt: bytes`, `new_salt: bytes`, `challenge: bytes`, `user_verification: bool` | One passkey ceremony that rebuilds one slot (§7.2): ONE assertion over `challenge` evaluating `new_salt` first and `old_salt` second, with user verification. Its first output answers `prf_requests[request]`; its second opens the Swift slot `old_slot` (`SwiftSource.finish_open_slot`). |
| `KeyDescriptorView` | `form: SignForm`, `signing: bytes`, `agreement: optional<bytes>`, `rp: optional<String>`, `credential: optional<bytes>`, `origins: list<String>`, `authority_origins: list<String>` | A key as the protocol writes it (§3.1), the one form the surface uses everywhere. `raw` keys have `agreement`; `webauthn` keys have `rp`, `credential` and `origins`. |
| `AccountSigningStep` | `path: String`, `body: bytes`, `signer: String`, `role: StepRole`, `form: SignForm`, `descriptor: optional<KeyDescriptorView>`, `signing_key: bytes`, `challenge: optional<String>`, `uv: bool` | The exact body and signer of one signature the host makes. |
| `Signature` | `signature: bytes`, `authenticator_data: optional<bytes>`, `client_data: optional<bytes>` | A signature the host made over a step's body: raw `r||s`, or DER with the assertion. |
| `PrfRequest` | `controller: String`, `rp: String`, `credential: bytes`, `salt: bytes`, `challenge: bytes` | The assertion the host must make for a new PRF route (§7.2). |
| `PrfAnswer` (secret input, wiped) | `authenticator_data: bytes`, `client_data: bytes`, `signature: bytes`, `output: bytes` | The host's answer to a `PrfRequest`. `output` is the 32-byte `results.first`: a secret, consumed and wiped by the call it is passed to. |
| `UnlockInput` | `kind: UnlockKind`, `controller: String`, `enc: bytes`, `salt: bytes` | One route of a slot the host answers: `Ecdh` against `enc`, or `Prf` with `salt`. |
| `UnlockSecret` (secret input, wiped) | `kind: UnlockKind`, `secret: bytes` | The host's raw result for one `UnlockInput`, in input order: a secret, consumed and wiped. |
| `EpochAgreement` | `namespace: String`, `epoch: u64`, `recipient: String`, `recipient_point: bytes`, `peer: bytes` | One ECDH a member's host performs to open a share. |
| `EpochAnswer` (secret input, wiped) | `namespace: String`, `epoch: u64`, `shared: bytes` | The host's raw ECDH result for one share: a secret, consumed and wiped. |
| `SlotController` | `id: String`, `label: String` | A controller a slot names. |
| `SlotInfo` | `index: u64`, `kind: SlotKind`, `kind_raw: optional<String>`, `label: String`, `controllers: list<SlotController>` | One slot of the current vault, as a chooser shows it. |
| `SlotPlan` | `controllers: list<String>`, `label: String` | What a slot is built for: its controllers and label. |
| `Status` | `seq: u64`, `code: String`, `kind: StatusKind`, `reason: optional<String>`, `stop_seq: optional<u64>`, `detail: optional<String>`, `rollback: bool` | The verdict on the verified history. |
| `EntryChange` | `seq: u64`, `kind: String` | An entry that joined the verified branch. |
| `NamespaceRevision` | `namespace: String`, `revision: u64` | A namespace whose fold changed, with its new revision. |
| `RefusedHead` | `home: String`, `code: String` | A head a home sent that was refused. |
| `Changes` | `authority_from_seq: u64`, `authority_to_seq: u64`, `entries: list<EntryChange>`, `members_added: list<String>`, `members_revoked: list<String>`, `controllers_added: list<String>`, `controllers_removed: list<String>`, `vault_changed: bool`, `policy_changed: bool`, `reorganized: bool`, `namespaces: list<NamespaceRevision>`, `pending_added: list<String>`, `pending_gone: list<String>`, `pending_now: list<String>`, `heads_accepted: list<String>`, `heads_refused: list<RefusedHead>`, `foreign: u64`, `status: optional<Status>` | What a call changed in the account. |
| `Written` | `stores: list<Store>`, `changes: Changes`, `artifact: optional<bytes>` | What a finished action produced: store these bytes at these paths, in order. `artifact` is the envelope of a link or a call (§12), which is not stored: for the host to use. |
| `Controller` | `id: String`, `label: String`, `roles: list<ControllerRole>`, `roles_raw: list<String>`, `key: KeyDescriptorView`, `form: SignForm`, `verification: bool`, `holder: optional<String>`, `has_slot: bool`, `provisional: bool`, `suspended: bool`, `added_seq: u64`, `added_by: list<String>` | A controller of the verified keyring; `added_by` the controllers that signed the entry that added it (empty for the genesis or a recording entry), for the removal follow-up (§17.5). |
| `AccountGrant` | `namespaces: list<String>`, `access: list<AccessKind>`, `expires: optional<String>`, `write_budget: optional<u64>`, `import: bool` | What a grant allows (the 0.4 shape). |
| `AccountMember` | `id: String`, `label: String`, `kind: AccountMemberKind`, `kind_raw: optional<String>`, `grant: optional<AccountGrant>`, `since: u64`, `revoked_at: optional<u64>`, `writes: u64`, `expires_ms: optional<i64>`, `provisional: bool`, `home: bool`, `session: u64`, `granted_by: list<String>` | A member with its standing; `granted_by` the controllers that signed its grant (empty for a recording entry), for the removal follow-up (§17.5). |
| `Standing` | `kind: StandingKind`, `controller: optional<Controller>`, `member: optional<AccountMember>`, `unknown_id: optional<String>` | What this session is. Exactly one of `controller`, `member`, `unknown_id` is set, by `kind`. |
| `Home` | `id: String`, `label: String`, `status: HomeStatus`, `status_raw: optional<String>`, `endpoints: list<String>`, `primary: bool` | A home the account names. |
| `Policy` | `threshold: u64`, `recover_threshold: u64`, `add_threshold: u64`, `count_by_holders: bool`, `call_window: u64`, `head_max_age: u64`, `head_quorum: u64`, `link_max_age: u64`, `member_rule: String`, `recovery_delay: u64`, `primary_home: optional<String>` | The effective policy (§6.3). |
| `Signer` | `id: String`, `label: String` | A signer with its label. |
| `Pending` | `digest: String`, `by: String`, `signers: list<Signer>`, `issued_ms: i64`, `anchor_seq: u64`, `first_seen_seq: optional<u64>`, `due_ms: optional<i64>`, `veto_deadline_ms: optional<i64>`, `full_set: optional<bool>`, `components: list<String>`, `removes: list<String>`, `adds: list<String>`, `vetoes: list<String>`, `vetoable: bool` | A pending transition, as §17.5 says it must be shown. |
| `Receipted` | `home: String`, `received_ms: i64` | When a home receipted an object. |
| `SeenActivation` | `seq: u64`, `transition: String`, `signers: list<String>`, `components: list<String>`, `receipted: list<Receipted>` | An activation the person has not seen. |
| `Owed` | `member: String`, `namespace: String`, `epoch: u64`, `provisional: bool` | A share a member is owed (§9.4). |
| `Notices` | `pending: list<Pending>`, `activations: list<SeenActivation>`, `owed: list<Owed>`, `controllers_without_slot: list<String>`, `vault_retiring: bool`, `no_home: bool` | What the person must be shown (§17.5). |
| `AccountDenial` | `reason: AccountDenialReason`, `reason_raw: optional<String>`, `detail: String` | A write refused for access reasons: `reason` is one of notGranted, revoked, expired, budgetSpent, notReadable, unavailable. |
| `HeadRef` | `namespace: String`, `digest: String` | Facts about a prepared action a host may show or follow up on. |
| `ActionInfo` | `name: String`, `rekey_owed: bool`, `owed_namespaces: list<String>`, `walk_incomplete: bool`, `kept: list<String>`, `heads: list<HeadRef>` | Facts about a prepared action. |
| `EngineStats` | `records_read: u64`, `signatures_verified: u64`, `payloads_decrypted: u64`, `walked_last: u64`, `folds_applied_last: u64`, `ignored_paths: u64`, `held_paths: u64`, `unread_paths: u64` | Work the engine did. |
| `OpenInfo` | `mode: OpenMode`, `reason: optional<String>` | How the open treated saved state: `mode`, and why when it was invalidated. |
| `SavedPart` | `namespace: String`, `bytes: bytes` | One sealed part of saved state. |
| `SavedState` | `verifier: bytes`, `checkpoint: bytes`, `parts: list<SavedPart>` | The sealed state a host stores between sessions (caches sealed under the device key). An empty `verifier` and `checkpoint` mean "no saved state". |
| `ForkCandidate` | `seq: u64`, `first: String`, `second: String` | Two candidates at a seq a `resolve` may choose between. |
| `Header` | `name: String`, `value: String` | A header of an HTTP message. |
| `HttpRequest` | `ticket: u64`, `home: String`, `method: HttpMethod`, `url: String`, `headers: list<Header>`, `body: bytes` | A request for the host to send. |
| `RemovalFollowUp` | `seq: u64`, `anchor_seq: u64`, `removed: list<String>`, `members: list<String>`, `controllers: list<String>` | `AccountEngine.removal_follow_up()`: per activation that removed controllers, the current members whose grant a removed key signed and the `approve`/`sign` controllers it added by immediate entries since the transition's anchor (§17.5). |
| `CallNeed` | `ticket: u64`, `home: String`, `audience: String`, `purpose: String`, `method: HttpMethod`, `url: String`, `path: String`, `body_sha256: String` | A request that needs a fresh `Authorization: Colophon` call built for exactly it: audience, purpose and `args` `{"method","path","body"}` from these fields (`exchange_begin_call`). |
| `ExchangeStep` | `kind: ExchangeStepKind`, `request: optional<HttpRequest>`, `need: optional<CallNeed>` | The next step of an exchange pass. `request` is set for `Request`, `need` for `NeedCall`. |
| `HttpAnswer` | `status: u32`, `headers: list<Header>`, `body: bytes` | What the host got back. |
| `ExchangeFault` | `kind: ExchangeFaultKind`, `home: String`, `path: optional<String>`, `feed: optional<String>`, `code: optional<String>`, `what: optional<String>`, `why: optional<String>`, `purpose: optional<String>`, `audience: optional<String>`, `endpoints: list<String>`, `status: optional<u32>` | A fault of a home. Which fields are set depends on `kind`: `path` (Mismatch, Conflict, Race), `feed` (NoProgress, More), `code` (BadObject, Refused), `what` (Refused), `why` (Malformed), `purpose` and `audience` (Unauthorized), `endpoints` (Redirect), `status` (Status). |
| `Report` | `store: list<Store>`, `changes: Changes`, `faults: list<ExchangeFault>` | What one answer produced. |
| `LiveVerdict` | `path: String`, `kind: LiveVerdictKind`, `detail: optional<String>` | The verdict on a live candidate; `detail` carries the `Quarantined` or `Refused` reason code or the `Invalid` explanation. |
| `StaleLive` | `path: String`, `generation: u64` | A live candidate refused for being below its slot's witness. |
| `LiveHead` | `path: String`, `digest: String`, `author: String`, `namespace: String`, `slot: String`, `generation: u64` | A live head the verifier accepted. |
| `Replaces` | `path: String`, `sha256: String` | The slot a live replacement is conditional on (`If-Match`): the sha256 of its bytes. |
| `LiveWritten` | `stores: list<Store>`, `replaces: optional<Replaces>`, `changes: Changes` | A finished live write. |
| `BlobAvailability` | `state: BlobState`, `present: u64`, `total: u64`, `detail: optional<String>` | How much of a blob is held locally. |
| `BlobChunk` | `path: String`, `bytes: bytes` | A sealed chunk to store before the manifest is published. |
| `VerifyProgress` | `checked: u64`, `remaining: u64` | Progress of the integrity audit. |
| `RevokeKeep` | `mode: KeepMode`, `kept: list<String>`, `heads: list<HeadRef>` | Which of a revoked member's records a revocation keeps (§9.5). |
| `CreateParams` | `label: String`, `namespaces: list<String>`, `controllers: list<ControllerSpec>`, `slots: list<SlotPlan>`, `threshold: optional<u64>`, `recover_threshold: optional<u64>`, `add_threshold: optional<u64>`, `count_by_holders: bool`, `policy_json: String`, `signers: list<String>`, `rekey_signers: list<String>` | What to create. `controllers` are typed (§6.1); `policy_json` the §6.3 policy document (empty: the §18 person default). |
| `Created` | `account: String`, `stores: list<Store>` | A created account: its ID and everything to store. |
| `RequestSpec` | `account: String`, `signing: bytes`, `agreement: bytes`, `label: String`, `kind: AccountMemberKind`, `terms_json: String`, `created: String`, `custody: optional<String>`, `operator: optional<String>`, `endpoints: list<String>` | A member's request (§9.1). |
| `RequestInfo` | `raw: bytes`, `member: String`, `label: String`, `kind: AccountMemberKind`, `kind_raw: optional<String>`, `terms_json: String` | A verified request as an approver sees it. |
| `AuthorityObjects` | `entries: list<ByteString>`, `pending: list<ByteString>`, `heads: list<ByteString>`, `predecessor: list<ByteString>` | The authority objects of an account, for the history verifier. |
| `Conflict` | `seq: u64`, `standing: String`, `losing: list<String>` | A conflict the verifier decided (§8.6). |
| `HistoryReport` | `code: String`, `kind: StatusKind`, `reason: optional<String>`, `seq: u64`, `detail: optional<String>`, `rollback: bool`, `account: optional<String>`, `branch: list<String>`, `conflicts: list<Conflict>`, `held_until_ms: optional<i64>` | The history verifier's verdict, with no host identity. |
| `WebauthnMode` | `kind: CheckKind`, `rule: AuthorityRuleKind`, `verification: bool`, `sign_controller: bool`, `origins: list<String>`, `uv_required: bool` | How `account_webauthn_check` judges a signature. `kind` selects the fields used: `rule`, `verification`, `sign_controller` for Authority; `origins`, `uv_required` for Call; `uv_required` for SwiftPredecessor. |
| `WebauthnOk` | `uv: bool`, `origin: String`, `counter: u32` | A verified WebAuthn assertion. |
| `SwiftEntry` | `seq: optional<u64>`, `digest: String`, `issued_ms: i64`, `layout: optional<u64>` | An entry of a verified Swift predecessor. |
| `SwiftPredecessor` | `account: String`, `entries: list<SwiftEntry>` | A verified Swift predecessor history. |
| `UpgradeParams` | `policy_json: String`, `add_threshold: u64`, `count_by: CountBy`, `issued_ms: i64`, `signers: list<String>` | The 0.5 settings an in-place upgrade adds (§16.1). |
| `LegacyHistory` | `records: list<Store>` | The 0.4 account's authority records, by path. |
| `PairingReveal` | `e: bytes`, `nb: bytes` | The pairing reveal a joiner sends: its ephemeral point and nonce. |
| `SuccessionTiming` | `window_start_ms: i64`, `window_end_ms: i64`, `recovery_delay_s: u64`, `veto_deadline_ms: i64`, `due_ms: i64`, `quorum: u64`, `homes: list<String>`, `vetoers: list<String>`, `keys_needed: u64` | The succession window and the times derived from it. |
| `SwiftSuccession` | `stage: MoveStage`, `format: String`, `predecessor: String`, `head_seq: u64`, `head_digest: String`, `genesis_digest: String`, `handover_count: u64`, `authorized: bool`, `vetoed: bool`, `verified_seq: optional<u64>`, `verified_digest: optional<String>`, `timing: optional<SuccessionTiming>` | The Swift succession an account claims (§15.1). |
| `MoveResult` | `stores: list<Store>`, `veto: optional<bytes>`, `veto_path: optional<String>`, `frozen_entry: optional<bytes>`, `frozen_seq: optional<u64>`, `succession_verified: bool`, `changes: optional<Changes>` | What a finished step of a move produced: `stores` to store as given (paths in "The Swift move: store paths"); a veto's `veto` and `veto_path`; for F the exact Swift entry (`frozen_entry`) the host appends to the predecessor. |
| `SealedSeed` | `enc: bytes`, `ciphertext: bytes` | A sealed seed (an HPKE box): public, only the paired device can open it. |
| `SourceFault` | `path: String`, `what: String` | A fault of the record source the host must show: it changed bytes it must never change. |
| `CallOrigin` | `rp: String`, `origins: list<String>` | The origins a call-ceremony `rp` may use. |
| `CallTarget` | `audiences: list<String>`, `call_origins: list<CallOrigin>`, `controller_purposes: list<String>`, `home_endpoints: list<String>` | What the verifier of a call is configured with (§12.3). |
| `SwiftSlotInfo` | `index: u64`, `kind: SlotKind`, `kind_raw: optional<String>`, `label: String`, `controller: optional<String>`, `problem: optional<String>` | One slot of a Swift keyring. `controller` is the one it names, `problem` why it cannot be read. |
| `SwiftEpoch` | `namespace: String`, `epoch: u64`, `seq: u64` | An epoch of a Swift namespace and the seq of the entry that introduced it. |
| `SwiftMemberInfo` | `id: String`, `label: String`, `role: optional<String>`, `revoked: bool`, `budget: bool` | A Swift predecessor member as the fold has it at the head. |
| `SwiftOpInfo` | `source_library: String`, `author_id: String`, `author_label: String`, `operation_id: String`, `signed_body_digest: String`, `kind: String`, `version: u64`, `payload_json: String`, `admitted_order: u64` | A Swift operation as the source reader judged it, for the host's translator. |
| `SwiftChild` | `key: String`, `kind: String`, `payload_json: String`, `baseline: bool` | An output of a translated record: a destination module operation and its clean payload. `baseline` is a trusted importer receipt, never inferred from a payload. |
| `SwiftIdentity` | `source_key: String`, `category: String`, `destination_id: String` | A source occurrence key reserved as `(category, destination id)`. |
| `SwiftBatch` | `children: list<SwiftChild>`, `alternatives_json: list<String>`, `identities: list<SwiftIdentity>`, `blobs_json: list<String>`, `outcome: String`, `evidence_json: String` | What the host's translator says about one admitted Swift operation: everything an import batch can carry. The core adds the batch key and the evidence binding it to its source; a translator can change the representation, never add a record or drop one silently. |
| `SwiftOmission` | `namespace: String`, `source_digest: String`, `reason: String` | A source record the plan omitted, with the reason. |
| `NamespaceCount` | `namespace: String`, `count: u64` | How many source records a namespace holds. |
| `CopyItem` | `namespace: String`, `source_digest: String`, `key: String`, `payload_json: String` | An import write of a copy plan, to be signed by the copying member. |
| `MigratedNamespace` | `namespace: String`, `source: u64`, `copied: list<String>`, `omitted: u64` | One namespace of a migration (§15.4). |
| `Omitted` | `source_digest: String`, `reason: String` | A source record not copied. |
| `CopyOutcome` | `namespaces: list<MigratedNamespace>`, `omitted: list<Omitted>`, `blobs_not_copied: list<String>` | What a finished copy holds. |
| `MigratedMemberInput` | `id: String`, `label: String`, `kind: AccountMemberKind`, `dropped: optional<String>` | A predecessor member's fate in a migration: `dropped` empty means it rejoins. |

### Faults

The exchange's `ExchangeFault.kind`: `More` carries `feed`: `authority`, `pending`, `remote`, `records`,
`live` or `predecessor` (a page the pass did not finish: the rest is for the next pass). `SourceFault`
(`AccountEngine.source_faults`) names a path the record source changed bytes at that it must never change.

## 7. The Swift move through the exports

```text
SwiftSource.read(entries) -> slots() -> begin_open_slot / finish_open_slot (host ECDH or PRF)
  -> open_namespace_keys()                         (keys stay inside)
SwiftSuccessorCreation.begin(source, SwiftSuccessorParams, now_ms, entropy 64)      the successor genesis
  -> prf_requests() / ceremonies()  one passkey assertion per slot rebuilt: provide_prf(answers), and
     source.finish_open_slot(old_slot, [second output]) opens the Swift slot with the same assertion
  -> steps() (genesis, possession proofs, handover) -> host signs -> provide_signatures -> take_result() -> stores
AccountEngine.open(over the stored objects) -> swift_succession()
  -> begin_swift_veto (during the wait) -> AccountMove.finish -> MoveResult.veto, veto_path, stores
  -> begin_swift_freeze(signers, issued_ms, earlier_attempts) (when due) -> AccountMove.steps() -> host signs
     -> AccountEngine.finish_move() -> MoveResult.stores (F at predecessor/authority/<seq>.json), frozen_entry
  -> the host appends frozen_entry to the Swift library; another device takes it in with accept_predecessor_entry(entry)
AccountEngine.swift_copy_destination(library) -> SwiftCopyPlan.read(source, files, translator, destination)
  loop: plan.next_batch(n) -> begin_swift_copy_write(plan, item, entropy) -> sign -> finish_swift_copy_write -> stores
  -> finish_swift_copy(plan) -> SwiftCopyResult
  -> begin_swift_copier_shares (stores: the shares entry; the copier opens them from the host's own store)
  -> begin_swift_migration(copy, members, drain..., signers) -> finish_move (stores: the transition)
```

The successor genesis carries every predecessor controller with its roles and rebuilds one slot per controller
that had one. A passkey's slot needs **one** assertion: first PRF input the new salt, second input the old
salt (a host that passes one input cannot do it); the answer to the new request and the opened Swift slot
come from that one assertion. A controller whose new request has no old PRF route (`unpaired()`) is asked a
plain assertion for the new salt only. The genesis, its possession proofs and the `handover` are checked by
the history verifier over the predecessor before `provide_signatures` returns. `v05_swift_move.rs` runs the
whole journey, the veto branch and the unvetoed branch, with a cold reopen from the host's store at each
stage; the home's receipts, heads and `successionVetoed` entry are simulated there with core code and marked.

The translator mirrors `swift_copy::Batch`: `SwiftBatch` has `children` (`SwiftChild`: key, kind,
`payload_json`, `baseline`), `alternatives_json`, `identities` (`SwiftIdentity`), `blobs_json`, `outcome` and
`evidence_json`; the core adds the batch key and the evidence binding it to its source and validates every
result against the destination's cumulative projection. A translator that errors omits the record with its
message.

## 8. The 0.4 calls and their 0.5 exports

The 0.4 exports stay (an in-place upgrade reads a 0.4 library with them first). Each, with its 0.5 answer:

| 0.4 export | 0.5 |
| --- | --- |
| `BindingError` | `AccountError` |
| `KeyProvider` (`signing_public_key`, `agreement_public_key`, `sign`, `agree`) and `ControllerProvider` | none: the core never calls a key provider; the host reads `AccountSigningStep` and signs |
| `HostAction::signing_steps`, `finish`, `record_paths`, `sign_with` | `AccountAction.steps`, `AccountEngine.finish` (returns `Written.stores`); `sign_with`: none |
| `HostAction::advance_create`, `begin_create`, `begin_create_with` | `AccountCreation` |
| `NativeLibrary::open`, `NativeEngine::open`, `open_inventory` | `AccountEngine.open` (the listing carries versions) |
| `set_read_scope`, `id`, `revision`, `revisions`, `me`, `members`, `ledger`, `query`, `view`, `access` | `set_read_scope`, `id`, `revision`, `revisions`, `me`, `members`, `ledger_json`, `query_json`, `view_json`, `access` |
| `records`, `records_at` | none: the host owns the store; `stores` of every action and report say what to persist |
| `merge`, `merge_observed`, `commit`, `update_versions`, `set_source` | `apply_paths`, `refresh`, `finish`, `AccountEngine.open(listing)` |
| `begin_unlock`, `finish_unlock`, `finish_unlock_many`, `ready_with` | `begin_unlock_epochs`, `finish_unlock_epochs` |
| `begin_unlock_slots`, `finish_unlock_slot`, `keyring`, `select_controller`, `eligible_signers`, `prepare_authority`, `finish_authority`, `sign_controller_with` | `slots`, `begin_unlock_slot`, `finish_unlock_slot`; the caller names signers; `suggest_signers` |
| `build_sealed_slot`, `begin_prf_slot`, `finish_prf_slot`, `begin_combined_slot`, `finish_combined_slot`, `PrfAction`, `CombinedSlotAction`, `CombinedSlotPart` | `begin_add_slot` with `prf_requests` and `provide_prf` |
| `begin_approve`, `begin_revoke`, `begin_rekey`, `begin_write`, `begin_call` | the same names, typed |
| `begin_layout` | none: a 0.5 account is at layout 2 from genesis |
| `begin_add_controller`, `begin_recovery_add`, `begin_add_passkey` | `begin_add_controller`, `AccountPairing`, `transfer_seed`, `accept_seed_transfer` |
| `begin_remove_controller`, `begin_keyring` | `begin_remove_controller`, `begin_rotate_vault`, `begin_keyring`, `begin_transition` |
| `begin_import_grant`, `begin_import`, `import_output_id`, `import_occurrence_id`, `import_identity_category`, `reconcile_import_prefix` | `begin_grant_transition` with a `grant` whose terms carry `import` (§9.3: an import grant is a transition); `begin_import` |
| `live_generation`, `written_operation`, `written_operation_json`, `operation_at` | `record_verdict`, `operation_at_json`, `live_heads`, `begin_live_write` |
| `tools` | `tools_json` |
| `begin_request`, `request_info`, `AccessRequest`, `PublicKeys` | `AccountRequest`, `account_request_info` |
| `NativeEngine::checkpoint`, `NativeCheckpointKey`, `NativeCheckpointPreparation`, `NativeCheckpointOpening` | `save` and `open(saved)`; sealed under the device key (no member-signed ticket) |
| `work`, `EngineWork`, `verify_batch` | `stats`, `open_info`, `verify_batch` |
| `begin_blob`, `open_blob_chunk`, `read_blob_chunk`, `NativeBlobWriter`, `BlobChunkWrite`, `BlobSource`, `BlobWriteOutcome`, `BlobReadOutcome` | `begin_blob`, `AccountBlobWriter`, `open_blob_chunk`, `blob_chunk`, `read_blob` (errors are typed: `Unavailable`, `Denied`) |
| `EngineRecordSource` | `HostSource` |
| `parse_registration` | unchanged 0.4 export, still right for 0.5 |
| `vault_public`, `webauthn_prf_input` | `account_vault_public`, `account_webauthn_prf_input` |
| `import_legacy_batch`, `bind_legacy_import_state`, `LegacyImport*` | none: upgrade tooling, not the account |
| `UnlockResult`, `AgreementStep`, `SlotOption`, `SlotInput`, `SlotSecret`, `SigningStep`, `SignatureResult`, `WebauthnResult`, `KeyForm`, `Records`, `ChangeSummary`, `Member`, `Grant`, `Denial` and the other 0.4 records | `UnlockInput`, `UnlockSecret`, `SlotInfo`, `AccountSigningStep`, `Signature`, `SignForm`, `Store`, `Changes`, `AccountMember`, `AccountGrant`, `AccountDenial` |
| (0.5 only) | the §15 `/5` succession (`begin_successor`) is not built in the core |

## 9. What was run, and what was not

Native (UniFFI crate), all through the exports:

* `v05_journeys` (5): create with a passkey-like controller and a device key; the controller's engine
  appoints a home and records its activation (`record_due`); approves a member; adds a laptop; the pairing
  ceremony then `transfer_seed` and `accept_seed_transfer`; the member writes and reads; two engines synced
  through an in-memory home built from the exchange values; read scope, `lock`, `exchange_abort`,
  `version_paths`, saved-state resume; the 0.4 in-place upgrade; a prepared action cannot be altered,
  replayed or finished elsewhere; a hostile source (garbage, a throwing callback, a re-entering callback, a
  second thread); a record changed under the engine is `Integrity`.
* `v05_swift_move` (3): **the Swift move through the exports only** (the repository's conformance keyring):
  the successor genesis with the one-assertion passkey ceremony, `swift_succession`, the veto branch
  (`finish_move` refuses a veto by name; the veto and its path come back; stage `Vetoed`; F refused), the
  unvetoed branch (two F's prepared, one finished, the second refused; F's store; `accept_predecessor_entry`
  on another device; the copier opens its shares from the host's own store; the copy with a test translator;
  `finish_swift_copy`; the migration; the migration pending across a restart; `Migrated`), and a **cold
  reopen from the host's store at every stage** (`Waiting`, `Due`, `Frozen`, `Verified`, `Vetoed`,
  `Migrated`). The home (its receipts, heads, `successionVetoed`) is simulated with core code and marked.
* `v05_swift` (1): the keyring opened through `SwiftSource`, planned with a typed translator.
* `v05_rules` (4): a callback that waits on a thread that calls the engine is refused, not deadlocked;
  `Locked` and the unconsumed prepared action; `Integrity` stays; the typed identity, kinds, verdicts,
  status and controllers.
* `v05_secrets` (4): the freed-memory scans of §4 (through the real scaffolding symbols, before and after
  the wipe, with a positive control), the 64 MiB refusal, and the JSON bounds with the worst accepted peak.
* `v05_alloc_bench` (ignored; run with `--ignored --release`): the cost of the allocator.
* name tests in both crates, the converter unit tests.

Swift and Kotlin: `tests/smoke/`, both pass on generated sources, now including the successor genesis
(with a real WebAuthn assertion made by the host language's crypto).

**The web build ran** (after B2's fix round): `colophon-wasm` built for `wasm32-unknown-unknown` in release,
glue generated with wasm-bindgen 0.2.130 (see `tests/smoke/README.md` for the tool and the exact commands),
and `smoke.mjs` passes under **Node 24 and Bun 1.4**. It shows, through the glue: an engine over a JS source;
an action through `begin_*` and `finish`; an `AccountFault` that is a real `Error` with `kind`, `code`,
`detail` and `reason`; a throwing source arriving as `Host`; a `Promise`, `undefined` or `Array` returned by
`read` arriving as a typed `Host` error naming `JsSource.read`; the allocator zeroing a freed secret on the
wasm heap (with the allocator-off build as the positive control). **Numbers on the web:** `u64` and `i64`
(seq, clocks, times in ms, sizes, counters, entropy-independent ids) are `bigint` and cross exactly,
including above 2^53 and `u64::MAX`; `u32` (an HTTP status) is a `number`; a `Number` passed for a
`bigint` is a plain `TypeError`, and a negative `bigint` passed for a `u64` wraps (wasm-bindgen's own
conversion). **In a browser:** the JavaScript session's tests run the exports in headless Chrome, bundled by Bun, with the
`read` and `readBlob` shims over an IndexedDB-backed source ([js-session.md](js-session.md)). **Still not run on the web:**
the `translate` shim, Safari and Firefox, and the `FinalizationRegistry`'s timing.
Also not run: XCFramework builds, Kotlin on a JDK other than 17. (The AAR is built for `arm64-v8a` and `x86_64` and the Kotlin session runs from it on an API 36 arm64 emulator: [android.md](android.md).)

**Known gaps** (named so an SDK does not assume them). Two are for the next round and each needs one
thing:

* **A creation leaves the session locked**, so a passkey user is asked twice at first run (the creation's own
  assertion, then the unlock by a slot) and again for the successor genesis. It needs an engine constructor
  over a created `Account` (`Engine::from_account`, in `v05/engine/`, which another builder owns). Adding it
  later changes no existing signature.
* **The web build is run under Node, Bun and Chrome** (see above); Safari and Firefox are still to do.

And these, shippable: `BlobAvailability` for `Complete` reports `present: 0, total: 0` (the core gives no
counts); `suggest_signers` has no `SignerNeed` for a pending transition's recovery-set consent;
`EntryChange.kind` is still a string; `u64` counters inside `*_json` results lose precision above 2^53
under `JSON.parse`, and on the web a negative `bigint` passed for a `u64` wraps (wasm-bindgen's own conversion); the web secret records' getters copy `output`, `secret` and `shared` back out to JS
(the records are consumed and wiped by the call, a copy the host reads is the host's); an earlier
succession attempt is judged live unless it is vetoed or premature (its window never opened, or its F is
dated before the due time); a handover that does not meet
the rule that may write F, and the control rule, are still checked after the passkey ceremony because
they need the built keyring (every other check runs before it).

**Open sets.** A C-like enum cannot carry data on both platforms, so each enum that mirrors an open
protocol set has an `Unknown` variant and the raw text beside it in the record that holds it:
`AccountMember.kind_raw` and `RequestInfo.kind_raw` (`AccountMemberKind.Unknown`), `Controller.roles_raw`
(`ControllerRole.Unknown` in `roles`), `SlotInfo.kind_raw` and `SwiftSlotInfo.kind_raw`,
`Home.status_raw`, `AccountDenial.reason_raw`. A newer account does not crash an older SDK; an `Unknown`
is never accepted as input. `ListedPath.version`, `RequestSpec.custody` and `RequestSpec.operator` are
optionals. `AccountDenial.reason` and `AccountError.Denied.reason` are `AccountDenialReason`;
`AccountError.BadSignature.check` is the failed WebAuthn check (`SignatureCheck`) beside the code.
`Controller.key` is the key descriptor. `account_map_swift_role(role)` is the core's role-to-kind map
for the migration.
