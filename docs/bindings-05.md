# Colophon 0.5 bindings (package B1)

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
where the protocol or a domain leaves the value open, as in 0.4: controller objects, terms, the policy
document, the `change` of a transition, record payloads, import batches, blob manifests, and `view`,
`query`, `history`, `operation_at`, `ledger`, `proposals` and `tools` results. Those fields and calls are
named `*_json`. Async is the SDK layer's concern (as in 0.4): every call is synchronous.

An action is one method per action (`begin_approve`, `begin_revoke`, ...), each with typed arguments. (The
spec asked for an enum with one variant per action; wasm-bindgen cannot export data-carrying enums, and one
method per action carries exactly the same typed fields on both platforms, as 0.4's `begin_*` did.)

**Naming.** Methods and fields are `snake_case` in Rust and on the web (as 0.4's wasm exports); the Swift and
Kotlin generators camel-case them. Enum variants are UpperCamel (`Cold`; Swift `.cold`, Kotlin `COLD`, web
numeric `OpenMode.Cold`). Four record names carry an `Account` prefix because 0.4's UniFFI namespace already
has them: `AccountSigningStep`, `AccountMember`, `AccountMemberKind`, `AccountGrant` and `AccountDenial`.
On the web, a record is a class with a constructor taking every field in order and a getter and a setter per
field; `u64` and `i64` are `bigint`; `optional<T>` is `undefined`.

## 2. Objects and calls

| Object | What it is |
| --- | --- |
| `AccountEngine` | The session: reads the host's record source; unlock; refresh; reads; every action; live state; blobs; imports; saved state; the exchange. The only object a session needs. |
| `AccountAction` | A prepared action held in Rust. One-shot. |
| `AccountCreation` | Creation before any store exists: PRF, genesis, first `rekey`; the result is the account ID and the stores. |
| `AccountRequest` | A device's membership request before it is a member (public values only). |
| `AccountPairing`, `PairingFailureLimiter`, `PairingTransferKey` | The pairing ceremony (§7.3). |
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
| `begin_approve` | `request: bytes`, `terms_json`, `signers` | 32 |
| `begin_renew` / `begin_renew_shares` | `member`, `expires_ms` (renew only), `signers` | 32 |
| `begin_revoke` | `member`, `keep: RevokeKeep`, `signers` | 32 |
| `begin_end_sessions` / `begin_end_my_sessions` | `member`, `signers` / none | 0 |
| `begin_rekey` | `namespaces`, `signers` | 32 |
| `begin_keyring` | `add_controllers_json: list<string>`, `add_slots_json: list<string>`, `policy_json`, `signers` | 0 |
| `begin_add_controller` | `controller_json`, `mode: AddMode`, `signers`, `rule: RuleKind` | 0 |
| `begin_add_slot` | `signer`, `plan: SlotPlan` | 32 |
| `begin_rotate_vault` | `signer`, `has_plans: bool`, `plans: list<SlotPlan>` | 64 (new seed, entropy) |
| `begin_remove_controller` | `remove`, `keep`, `signers`, `rule`, `rotate: bool` | 64 if `rotate`, else 0 |
| `begin_transition` | `change_json`, `signers`, `rule` | 0 |
| `begin_veto` / `begin_suspend` / `begin_resolve` | as the core | 0 |
| `begin_write` / `begin_propose` | `namespace`, `kind`, `payload_json` | 32 |
| `begin_resolution` | `namespace`, `accept`, `proposals` | 32 |
| `begin_import` | `namespace`, `batch_json` | 32 |

### `AccountEngine`

`open(source, listing: list<ListedPath>, identity, account, namespaces, batch, saved: SavedState, key, now_ms)`
(`identity` is `controller:<32 hex>` or `member:<32 hex>`; `listing` carries each path's content version in
one batch, an empty version meaning none; empty `SavedState` means none). Reads: `id identity status head_seq
head_digest controllers homes policy pending owed_shares notices(shown_seq, shown_transitions, local_keys)
slots is_unlocked begin_unlock_slot(index) begin_unlock_epochs fork_candidates suggest_signers(available, need)
latest_epoch write_denial record_verdict verdict_of live_heads open_info stats access revision revisions me
members`, and JSON: `proposals_json tools_json ledger_json view_json query_json history_json
operation_at_json blob_manifest_json`. Progress: `load refresh(listing) apply_paths(list<ListedPath>) advance
finish_unlock_slot(index, list<UnlockSecret>) finish_unlock_epochs(list<EpochAnswer>) apply_live stale_live
live_verdicts missing_covered budget_scope_unavailable rejudged save(nonce_seed) verify_batch(limit)`. Blobs:
`begin_blob open_blob_chunk blob_chunk read_blob blob_availability required_blob_fetches`. Live: `begin_live_write
finish_live_write`. Exchange: `exchange_homes exchange_set_bearer exchange_next(home) exchange_provide_call
exchange_answer(home, ticket, HttpAnswer) exchange_want_blob receipted_by`. Session: `record_due set_read_scope lock is_locked
transfer_seed accept_seed_transfer accept_predecessor_entry exchange_abort source_faults version_paths
begin_link begin_call` (a link or call's envelope is `Written.artifact`). Move: `swift_succession
swift_predecessor begin_swift_veto begin_swift_freeze begin_swift_copier_shares begin_swift_migration
finish_move swift_copy_destination begin_swift_copy_write finish_swift_copy_write finish_swift_copy`.

The exchange: `exchange_next` returns an `ExchangeStep`: `Request` (with `request: HttpRequest`: ticket, home,
method, url, headers, body), `NeedCall` (with `need: CallNeed`: ticket, home, audience, purpose, method, url;
build the call for exactly that and give it to `exchange_provide_call`), `Waiting` or `Done`. The host performs
the request and answers it; the `Report` has `store` (persist), `changes` and `faults: list<ExchangeFault>`.

Standalone: `account_verify_history`, `account_webauthn_check(KeyDescriptorView, body, der_signature,
authenticator_data, client_data, WebauthnMode)`, `account_verify_swift_predecessor`, `account_key_id`,
`account_webauthn_prf_input`, `account_vault_public`, `account_format_date`, `account_request_info`,
`account_default_policy`.

### Key descriptors

One encoding on the whole surface: `KeyDescriptorView` is the protocol descriptor of §3.1 (`form`, `signing`,
and `agreement` for raw, or `rp`, `credential`, `origins`, `authority_origins` for webauthn). A step carries
it as `descriptor`; `account_webauthn_check` takes it. The core's internal serde form never crosses.

## 3. Errors

Every call returns `AccountError` or succeeds. A host branches on the variant or on `code`; `detail` is for
logs and never carries key material. `Refused` carries the §19 reason; `Denied` the access reason.

| Variant | `code` | Meaning |
| --- | --- | --- |
| `Malformed` | `malformed` | A rule is broken; also an argument that is not valid JSON. Pairing aborts: `pairing:commitmentMismatch`, `pairing:invalidPoint`, `pairing:wrongAccount`. |
| `BadSignature` | `badSignature`; from `account_webauthn_check` `badSignature:<check>` | A signature, assertion, possession proof or key binding failed. Checks: `point rawLength scalar der verify clientData clientDataBound unknownForm type challenge origin crossOrigin relyingParty userPresence userVerification form callOrigin`. |
| `NewerFormat` | `newerFormat` | Authenticated content of a newer format. |
| `Unavailable` | `unavailable` | Something needed could not be obtained. |
| `Refused` | `refused:<reason>`, `reason` | `audience window replay conflict fork revoked expired ended notNarrower outOfScope origin rollback notGranted wrongEpoch clockJump budgetSpent wrongFormat invalidPayload caveatedLive vaultLocked`; also `pairing:limit` (reason `pairingLimit`). |
| `Denied` | `denied:<reason>`, `reason` | `notGranted revoked expired budgetSpent notReadable unavailable`. |
| `Host` | `host` | A host callback failed; `detail` is the host's own message (a foreign exception arrives here too). |
| `Reentered` | `reentered` | A callback called back into the object that was calling it, on the same thread. |
| `Consumed` | `consumed` | A one-shot object was used up, or a pairing step is in the wrong stage (nothing consumed then). |
| `WrongObject` | `wrongObject` | An action was finished on another session. |
| `Bound` | `bound` | An argument exceeded a bound or has the wrong length. |
| `Integrity` | `integrity` | The engine found its source or home inconsistent and is unusable; discard it. Not a mistake in the call. |
| `Internal` | `internal` | A panic was caught; discard the object. |

Concurrency: a call from another thread waits for the engine's lock (as 0.4 does). Only a call from the thread
that already holds it, from inside a callback, is `Reentered`.

## 4. What crosses, and what never does

**Never returned, logged, or serialized:** vault seed bytes; epoch key bytes; a PRF output or ECDH result read
back; the sealed-state key; a prepared action's retained state; a transfer key's private scalar. No type here
has a `Debug`, `Clone` or serial form that includes one: the three records that carry a host secret
(`PrfAnswer`, `UnlockSecret`, `EpochAnswer`) have no `Clone` even on the web build.

**Crosses in, consumed and wiped:** PRF outputs, ECDH results and epoch shares (fields of the three secret
records), entropy (`Vec<u8>`), the nonce seed of `save`, and the device-held sealed-state key. Every copy the
binding makes is overwritten before the call returns, including on error paths, and the argument vectors are
wiped. `v05_secrets.rs` runs a counting allocator that scans every freed block for the secret in raw, base64,
base64url and hex form: **through the binding, no freed block holds a share or an ECDH result that the core
alone does not already leave** (before this round, on the JSON-string surface: 2 freed blocks with the raw
secret and 3 with its base64 for one `finish_unlock_slot`). The residue is the core's own: `hpke::extract`
builds a 51-byte temporary containing a share that it does not erase (`finish_unlock_epochs`: 1 block, with or
without the binding; `finish_unlock_slot`: 0). The core's engine keeps its own copy of the device key for its
life (its `EngineOptions` has no wipe; the branch `engine-0.5-e9` adds one); the binding wipes its argument.
The host is trusted with these secrets exactly as the core's header says.

**Never accepted from the host:** verified state, a `PendingAction` or `SigningStep`, a keyring, terms, a
fold, a seed. Saved state is accepted only sealed under the device key; one that fails its seal is ignored
and the history replays (`open_info` says so).

## 5. Bounds

Every bound is checked on the raw length before any parse or allocation that scales with it. JSON document
argument (`*_json`, `policy_json`, controller, terms, payload): 4 MiB. Binary argument: 40 MiB (a `ListedPath`
list, `ByteString` list and `Store` list: 262,144 items). Name lists (signers, namespaces, controllers, slot
controllers, shown transitions, local keys): 256. Entropy: exactly the 32, 64 or 96 bytes the call says; the
sealed-state key 32. Signatures list 256; signature or assertion field 64 KiB. Bearer token 8 KiB; call 16 KiB;
HTTP response body 128 MiB; headers 256; blob chunk 64 KiB (writer) and 1 MiB (open); QR payload 4 KiB;
limiter state 64 KiB; a request or entry blob 40 MiB. The core adds its own bounds. Measured
(`v05_secrets.rs`): a 64 MiB payload argument is refused with **381 bytes** of extra allocation (on the
JSON-string surface the same size reached **1.07 GiB** peak before its bound applied).

A callback that returns garbage is judged by the core. A callback that fails is `Host` with its message. A
callback that re-enters is `Reentered` and nothing deadlocks. A finish that fails changes nothing.

## 6. Types

Enums are C-like. A record's `optional` field is set only as its doc says.

| Enum | Variants | Meaning |
| --- | --- | --- |
| `StepRole` | `Primary`, `Cosignature`, `Possession`, `Handover` | What a signature is for in a batch. |
| `SignForm` | `Raw`, `Webauthn` | The signature form a signer uses. |
| `AccountMemberKind` | `Device`, `App`, `Agent`, `Server` | A member's kind. |
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
| `ListedPath` | `path: String`, `version: String` | A listed path with the provider's content-version token (empty for none). |
| `ByteString` | `bytes: bytes` | One byte string (a list of them cannot be a field on every platform). |
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
| `SlotInfo` | `index: u64`, `kind: String`, `label: String`, `controllers: list<SlotController>` | One slot of the current vault, as a chooser shows it. |
| `SlotPlan` | `controllers: list<String>`, `label: String` | What a slot is built for: its controllers and label. |
| `Status` | `seq: u64`, `code: String`, `stop_seq: optional<u64>`, `detail: optional<String>`, `rollback: bool` | The verdict on the verified history. |
| `EntryChange` | `seq: u64`, `kind: String` | An entry that joined the verified branch. |
| `NamespaceRevision` | `namespace: String`, `revision: u64` | A namespace whose fold changed, with its new revision. |
| `RefusedHead` | `home: String`, `code: String` | A head a home sent that was refused. |
| `Changes` | `authority_from_seq: u64`, `authority_to_seq: u64`, `entries: list<EntryChange>`, `members_added: list<String>`, `members_revoked: list<String>`, `controllers_added: list<String>`, `controllers_removed: list<String>`, `vault_changed: bool`, `policy_changed: bool`, `reorganized: bool`, `namespaces: list<NamespaceRevision>`, `pending_added: list<String>`, `pending_gone: list<String>`, `pending_now: list<String>`, `heads_accepted: list<String>`, `heads_refused: list<RefusedHead>`, `foreign: u64`, `status: optional<Status>` | What a call changed in the account. |
| `Written` | `stores: list<Store>`, `changes: Changes`, `artifact: optional<bytes>` | What a finished action produced: store these bytes at these paths, in order. `artifact` is the envelope of a link or a call (§12), which is not stored: for the host to use. |
| `Controller` | `id: String`, `label: String`, `roles: list<String>`, `form: SignForm`, `verification: bool`, `holder: optional<String>`, `has_slot: bool`, `provisional: bool`, `suspended: bool` | A controller of the verified keyring. |
| `AccountGrant` | `namespaces: list<String>`, `access: list<AccessKind>`, `expires: optional<String>`, `write_budget: optional<u64>`, `import: bool` | What a grant allows (the 0.4 shape). |
| `AccountMember` | `id: String`, `label: String`, `kind: AccountMemberKind`, `grant: optional<AccountGrant>`, `since: u64`, `revoked_at: optional<u64>`, `writes: u64`, `expires_ms: optional<i64>`, `provisional: bool`, `home: bool`, `session: u64` | A member with its standing. |
| `Standing` | `kind: StandingKind`, `controller: optional<Controller>`, `member: optional<AccountMember>`, `unknown_id: optional<String>` | What this session is. Exactly one of `controller`, `member`, `unknown_id` is set, by `kind`. |
| `Home` | `id: String`, `label: String`, `status: String`, `endpoints: list<String>`, `primary: bool` | A home the account names. |
| `Policy` | `threshold: u64`, `recover_threshold: u64`, `add_threshold: u64`, `count_by_holders: bool`, `call_window: u64`, `head_max_age: u64`, `head_quorum: u64`, `link_max_age: u64`, `member_rule: String`, `recovery_delay: u64`, `primary_home: optional<String>` | The effective policy (§6.3). |
| `Signer` | `id: String`, `label: String` | A signer with its label. |
| `Pending` | `digest: String`, `by: String`, `signers: list<Signer>`, `issued_ms: i64`, `anchor_seq: u64`, `first_seen_seq: optional<u64>`, `due_ms: optional<i64>`, `veto_deadline_ms: optional<i64>`, `full_set: optional<bool>`, `components: list<String>`, `removes: list<String>`, `adds: list<String>`, `vetoes: list<String>`, `vetoable: bool` | A pending transition, as §17.5 says it must be shown. |
| `Receipted` | `home: String`, `received_ms: i64` | When a home receipted an object. |
| `SeenActivation` | `seq: u64`, `transition: String`, `signers: list<String>`, `components: list<String>`, `receipted: list<Receipted>` | An activation the person has not seen. |
| `Owed` | `member: String`, `namespace: String`, `epoch: u64`, `provisional: bool` | A share a member is owed (§9.4). |
| `Notices` | `pending: list<Pending>`, `activations: list<SeenActivation>`, `owed: list<Owed>`, `controllers_without_slot: list<String>`, `vault_retiring: bool`, `no_home: bool` | What the person must be shown (§17.5). |
| `AccountDenial` | `reason: String`, `detail: String` | A write refused for access reasons: `reason` is one of notGranted, revoked, expired, budgetSpent, notReadable, unavailable. |
| `HeadRef` | `namespace: String`, `digest: String` | Facts about a prepared action a host may show or follow up on. |
| `ActionInfo` | `name: String`, `rekey_owed: bool`, `owed_namespaces: list<String>`, `walk_incomplete: bool`, `kept: list<String>`, `heads: list<HeadRef>` | Facts about a prepared action. |
| `EngineStats` | `records_read: u64`, `signatures_verified: u64`, `payloads_decrypted: u64`, `walked_last: u64`, `folds_applied_last: u64`, `ignored_paths: u64`, `held_paths: u64`, `unread_paths: u64` | Work the engine did. |
| `OpenInfo` | `mode: OpenMode`, `reason: optional<String>` | How the open treated saved state: `mode`, and why when it was invalidated. |
| `SavedPart` | `namespace: String`, `bytes: bytes` | One sealed part of saved state. |
| `SavedState` | `verifier: bytes`, `checkpoint: bytes`, `parts: list<SavedPart>` | The sealed state a host stores between sessions (caches sealed under the device key). An empty `verifier` and `checkpoint` mean "no saved state". |
| `ForkCandidate` | `seq: u64`, `first: String`, `second: String` | Two candidates at a seq a `resolve` may choose between. |
| `Header` | `name: String`, `value: String` | A header of an HTTP message. |
| `HttpRequest` | `ticket: u64`, `home: String`, `method: HttpMethod`, `url: String`, `headers: list<Header>`, `body: bytes` | A request for the host to send. |
| `CallNeed` | `ticket: u64`, `home: String`, `audience: String`, `purpose: String`, `method: HttpMethod`, `url: String` | A request that needs a fresh `Authorization: Colophon` call built for exactly it. |
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
| `CreateParams` | `label: String`, `namespaces: list<String>`, `controllers_json: list<String>`, `slots: list<SlotPlan>`, `threshold: optional<u64>`, `recover_threshold: optional<u64>`, `add_threshold: optional<u64>`, `count_by_holders: bool`, `policy_json: String`, `signers: list<String>`, `rekey_signers: list<String>` | What to create. `controllers_json` holds one protocol controller object (§6.1) per item; `policy_json` the §6.3 policy document (empty: the §18 person default). |
| `Created` | `account: String`, `stores: list<Store>` | A created account: its ID and everything to store. |
| `RequestSpec` | `account: String`, `signing: bytes`, `agreement: bytes`, `label: String`, `kind: AccountMemberKind`, `terms_json: String`, `created: String`, `custody: String`, `operator: String`, `endpoints: list<String>` | A member's request (§9.1). `custody` and `operator` are empty for none. |
| `RequestInfo` | `raw: bytes`, `member: String`, `label: String`, `kind: AccountMemberKind`, `terms_json: String` | A verified request as an approver sees it. |
| `AuthorityObjects` | `entries: list<ByteString>`, `pending: list<ByteString>`, `heads: list<ByteString>`, `predecessor: list<ByteString>` | The authority objects of an account, for the history verifier. |
| `Conflict` | `seq: u64`, `standing: String`, `losing: list<String>` | A conflict the verifier decided (§8.6). |
| `HistoryReport` | `code: String`, `seq: u64`, `detail: optional<String>`, `rollback: bool`, `account: optional<String>`, `branch: list<String>`, `conflicts: list<Conflict>`, `held_until_ms: optional<i64>` | The history verifier's verdict, with no host identity. |
| `WebauthnMode` | `kind: CheckKind`, `rule: AuthorityRuleKind`, `verification: bool`, `sign_controller: bool`, `origins: list<String>`, `uv_required: bool` | How `account_webauthn_check` judges a signature. `kind` selects the fields used: `rule`, `verification`, `sign_controller` for Authority; `origins`, `uv_required` for Call; `uv_required` for SwiftPredecessor. |
| `WebauthnOk` | `uv: bool`, `origin: String`, `counter: u32` | A verified WebAuthn assertion. |
| `SwiftEntry` | `seq: optional<u64>`, `digest: String`, `issued_ms: i64`, `layout: optional<u64>` | An entry of a verified Swift predecessor. |
| `SwiftPredecessor` | `account: String`, `entries: list<SwiftEntry>` | A verified Swift predecessor history. |
| `UpgradeParams` | `policy_json: String`, `add_threshold: u64`, `count_by: String`, `issued_ms: i64`, `signers: list<String>` | The 0.5 settings an in-place upgrade adds (§16.1). `count_by` is `keys` or `holders`. |
| `LegacyHistory` | `records: list<Store>` | The 0.4 account's authority records, by path. |
| `PairingReveal` | `e: bytes`, `nb: bytes` | The pairing reveal a joiner sends: its ephemeral point and nonce. |
| `SuccessionTiming` | `window_start_ms: i64`, `window_end_ms: i64`, `recovery_delay_s: u64`, `veto_deadline_ms: i64`, `due_ms: i64`, `quorum: u64`, `homes: list<String>`, `vetoers: list<String>`, `keys_needed: u64` | The succession window and the times derived from it. |
| `SwiftSuccession` | `stage: MoveStage`, `format: String`, `predecessor: String`, `head_seq: u64`, `head_digest: String`, `genesis_digest: String`, `handover_count: u64`, `authorized: bool`, `vetoed: bool`, `verified_seq: optional<u64>`, `verified_digest: optional<String>`, `timing: optional<SuccessionTiming>` | The Swift succession an account claims (§15.1). |
| `MoveResult` | `stores: list<Store>`, `veto: optional<bytes>`, `frozen_entry: optional<bytes>`, `frozen_seq: optional<u64>`, `succession_verified: bool`, `changes: optional<Changes>` | What a finished step of a move produced: bytes to store, and for F the exact Swift entry (`frozen_entry`) the host appends to the predecessor. |
| `SealedSeed` | `enc: bytes`, `ciphertext: bytes` | A sealed seed (an HPKE box): public, only the paired device can open it. |
| `SourceFault` | `path: String`, `what: String` | A fault of the record source the host must show: it changed bytes it must never change. |
| `CallOrigin` | `rp: String`, `origins: list<String>` | The origins a call-ceremony `rp` may use. |
| `CallTarget` | `audiences: list<String>`, `call_origins: list<CallOrigin>`, `controller_purposes: list<String>`, `home_endpoints: list<String>` | What the verifier of a call is configured with (§12.3). |
| `SwiftSlotInfo` | `index: u64`, `kind: String`, `label: String`, `controller: optional<String>`, `problem: optional<String>` | One slot of a Swift keyring. `controller` is the one it names, `problem` why it cannot be read. |
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

## 7. The Swift move through one object

```text
SwiftSource.read(entries) -> slots() -> begin_open_slot / finish_open_slot (host ECDH or PRF)
  -> open_namespace_keys()                         (keys stay inside)
AccountEngine.swift_succession() -> begin_swift_veto (during the wait) | begin_swift_freeze (when due)
  -> AccountMove.steps() -> host signs -> AccountEngine.finish_move() -> MoveResult.frozen_entry
  -> the host appends F to the predecessor; accept_predecessor_entry(entry) when it comes back
AccountEngine.swift_copy_destination(library) -> SwiftCopyPlan.read(source, files, translator, destination)
  loop: plan.next_batch(n) -> begin_swift_copy_write(plan, item, entropy) -> sign -> finish_swift_copy_write
  -> finish_swift_copy(plan) -> SwiftCopyResult
  -> begin_swift_copier_shares / begin_swift_migration(copy, members, drain..., signers) -> finish_move
```

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
| `begin_import_grant`, `begin_import`, `import_output_id`, `import_occurrence_id`, `import_identity_category`, `reconcile_import_prefix` | `begin_approve` with `terms_json` carrying `import`; `begin_import` |
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

## 9. What was run

Native (UniFFI crate): `v05_journeys` (5 tests, only the exports: create with a passkey-like controller and a
device key; the controller's engine appoints a home and records its activation (`record_due`); approves a
member; adds a laptop; the pairing ceremony then `transfer_seed` and `accept_seed_transfer`, the laptop
builds its own slot and unlocks by it; the member writes and reads; two engines synced through an in-memory
home built from the exchange values; read scope, `lock`, `exchange_abort`, `version_paths`, saved-state
resume; the 0.4 in-place upgrade then old records and a new write; a prepared action cannot be altered,
replayed or finished elsewhere; a hostile source: garbage, a throwing callback, a re-entering callback, a
second thread; a record changed under the engine is `Integrity`), `v05_swift` (1: a real Swift keyring library
opened through `SwiftSource`, planned through `SwiftCopyPlan` with a typed translator, omissions with the host's
reason), `v05_secrets` (3), name tests. **Not run:** the steps of the Swift move that need a verified 0.5
successor (the succession window, veto, F, the import writes, the migration): they are exported and compile,
but no successor-account fixture exists in this crate (the core's `v05_swift_journey` builds one). Swift and
Kotlin: `tests/smoke/`, both pass on generated sources, covering `lock`, seed transfer and `record_due`.
Web: the wasm build compiles for `wasm32-unknown-unknown` and its exports were read from the module; nothing
was executed through the wasm-bindgen glue because the installed CLI does not match the crate's wasm-bindgen
(see the PR). The web test that runs natively covers everything that needs no JS host.
