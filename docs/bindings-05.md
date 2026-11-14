# Colophon 0.5 bindings (package B1)

The UniFFI (`colophon-ffi`) and wasm-bindgen (`colophon-wasm`) exports of the 0.5 Rust core. This is
the contract the Swift, Kotlin/Android and JavaScript SDK layers are written against. The 0.4
exports are untouched and keep working (an in-place upgrade reads a 0.4 library first, and the SDKs
move over one at a time).

**One source, two crates.** The surface is written once, in `crates/colophon-ffi/src/v05/api/`.
`colophon-ffi` compiles it with the `native05` feature (UniFFI attributes); `colophon-wasm` includes
the same files by `#[path]` with the `web05` feature (wasm-bindgen attributes). The two differ only
where the platform forces it (below). The list of exported names is
`crates/colophon-ffi/src/v05/surface-names.txt`; each crate has a test that computes its own names
from the sources and fails if they differ from that list.

## 1. Shape of the surface

Everything that crosses is a scalar, a byte string (`Vec<u8>` / `Uint8Array`), a UTF-8 string, or a
**JSON string**. In JSON, binary fields are standard base64 (the protocol's own text form). Composite
results (views, members, steps, changes) are JSON documented below. Objects stay in Rust; a host holds
opaque handles. Async is the SDK layer's concern (as in 0.4): every call is synchronous.

| Object | What it is |
| --- | --- |
| `AccountEngine` | The session an app runs: reads the host's record source, unlock, refresh, reads, writes, live state, blobs, imports, checkpoints, the exchange with a home. Wraps the core's `Engine`. |
| `AccountCore` | An account held in memory without an engine: opened from objects. Used for what the engine does not forward (below), for creation's result, seed transfer, calls and links, moving. Wraps the core's `Account`. |
| `AccountAction` | A prepared action: what to sign, held by the core until finished. One-shot. |
| `AccountCreation` | Creation in progress (genesis, first `rekey`, first slots). |
| `AccountRequest` | A member's request (§9.1), public values only. |
| `AccountPairing`, `PairingFailureLimiter`, `PairingTransferKey` | Pairing (§7.3) and moving the seed (§7.4). |
| `AccountBlobWriter`, `AccountLiveWrite` | A streaming blob upload; a prepared live write. |
| `AccountMove` | A prepared move step: the 0.4 upgrade, a Swift veto, F, shares. |
| free functions `account_*` | The standalone verifiers and small helpers. |
| `HostSource` | The host callback: `read(path)`, `version(path)`, `read_blob(path)`. |
| `AccountError` | The error of every call. |

### Platform differences (and only these)

| | UniFFI (Swift, Kotlin) | wasm-bindgen (JS) |
| --- | --- | --- |
| Constructors | `#[uniffi::constructor]`, return `Arc<T>` | static methods returning the object (`AccountCore.open(...)`) |
| Passing an object | `Arc<T>` | `&T` (a JS object) |
| Host callback | `HostSource` callback interface (`Send + Sync`) | a JS object with `read`, `version`, `readBlob` (`JsSource`); only `AccountEngine.open` takes it |
| Error | `AccountError` enum (variants with fields) | thrown `AccountFault` object with `kind`, `code`, `detail` getters |
| Integers | `u64`, `i64` | `bigint` for `u64` and `i64` |
| Panic | caught, returned as `AccountError.Internal`; the object is poisoned and says so | **not catchable on wasm32** (panic aborts the instance): discard the instance. The code forbids `unsafe`, checks every bound before allocating and returns errors instead of panicking; none is known to panic |

Method names are the Rust `snake_case` names in both crates; the Swift and Kotlin generators camel-case
them (`finishUnlockSlot`), the wasm exports keep `snake_case` (as the 0.4 wasm exports did).

## 2. Errors

Every call returns `AccountError` or succeeds. A host branches on the variant or on `code`, never on
`detail` (a diagnostic for logs that never carries key material).

| Variant | `code` | Meaning |
| --- | --- | --- |
| `Malformed` | `malformed` | The bytes or structure break a rule; also an argument that is not JSON/base64. |
| `BadSignature` | `badSignature` | A signature, assertion, possession proof or key binding failed. |
| `NewerFormat` | `newerFormat` | Authenticated content of a newer format. |
| `Unavailable` | `unavailable` | Something needed could not be obtained (never evidence of anything). |
| `Refused` | `refused:<reason>` and `reason` | A §19 refusal: `audience window replay conflict fork revoked expired ended notNarrower outOfScope origin rollback notGranted wrongEpoch clockJump budgetSpent wrongFormat invalidPayload caveatedLive vaultLocked`. |
| `Denied` | `denied:<reason>` and `reason` | A grant or key does not allow it now: `notGranted revoked expired budgetSpent notReadable unavailable`. |
| `Host` | `host` | A host callback failed. |
| `Reentered` | `reentered` | A callback called back into the object that was calling it. |
| `Consumed` | `consumed` | A one-shot object (action, creation, pairing step, writer) was used up or is in the wrong stage. |
| `WrongObject` | `wrongObject` | An action was finished on a session other than the one that prepared it. |
| `Bound` | `bound` | An argument exceeded a bound or has the wrong length. |
| `Internal` | `internal` | A panic was caught; discard the object. |

Pairing aborts are `Malformed` with `code` `pairing:commitmentMismatch`, `pairing:invalidPoint`,
`pairing:wrongAccount`; the five-per-hour limit is `Refused` with `code` `pairing:limit`.

## 3. What crosses, and what never does

**Never returned, logged, or serialized by any export:** vault seed bytes; epoch key bytes; a PRF
output; a raw ECDH result; the sealed-state key; a prepared action's retained state; the private scalar
of a transfer key. No export has a `Debug`, `Display` or JSON form of any of these; `AccountError`
carries only the core's own diagnostics (which carry none).

**Crosses in (host to core), consumed and not read back:** PRF outputs and ECDH results (inside
`finish_unlock_slot`, `finish_unlock_epochs`, `provide_prf`) as base64 in a JSON argument; fresh
entropy (`Vec<u8>`, overwritten after use); the device-held sealed-state key (see 6); a host-chosen
vault seed inside the 96 bytes given to `AccountCreation.begin`, and the 32 bytes given to
`PairingTransferKey.create`. The host is trusted with these exactly as the core's header says
(`v05/account/mod.rs`): it can recompute what it seals. The JSON text a host builds for a secret is
the host's own string; the parse inside the call is dropped but, like the core's erasure, not
overwritten (best effort).

**Crosses out (core to host), all public or the host's own bytes:** exact signing bodies, signers and
challenges (copies); PRF requests (salt, challenge, rp, credential: public); unlock inputs (the HPKE
`enc` points and PRF salts); records and objects the host stores; a sealed seed (an HPKE ciphertext
only the paired device can open); views, members, ledger, policy.

**Never accepted from the host:** verified state (no export takes a state, keyring, terms, session
number, fold or seed), a `PendingAction` or `SigningStep` (an action is held in Rust; the host passes
signatures only; finishing re-assembles the bytes from the core's own state and verifies them under the
history verifier first), a checkpoint that was not sealed under the device key (an unsealable state is
ignored and the history replays).

Which types are `Clone` or serializable: no core type was made so. This crate adds none; the JSON the
exports return is built field by field from non-secret accessors, never `serde` of a secret-holding type.

## 4. Bounds and hostile hosts

Checked before allocation or parse: any JSON argument 64 MiB; any binary argument 40 MiB; lists
262,144 items; signer, namespace and controller name lists 256; an entropy argument exactly 32, 64 or
96 bytes as the action says; a bearer token 8 KiB; a call 16 KiB; an HTTP response body 128 MiB; a blob
chunk 64 KiB (writer) and 1 MiB (open); the sealed state 1 GiB; a status code and a history page limit
(1 to 200) are range-checked. The core adds its own bounds on top (`MAX_OBJECTS` and the like).

A callback that returns garbage is judged by the core (it is bytes; nothing is trusted on its say). A
callback that errors becomes `Host` (open and refresh fail; the engine stays usable). A callback that
re-enters the object it is called from gets `Reentered`, because every object takes a non-waiting lock;
nothing deadlocks. A host that passes the same action twice gets `Consumed`; an action to another
session `WrongObject`. A finish that fails changes nothing (the core's rule) and consumes the action:
prepare again with fresh entropy.

## 5. The calls

`R` is JSON. `entropy` is fresh random bytes from the host's CSPRNG, never reused.

### Free functions

| Call | Args | Result |
| --- | --- | --- |
| `account_verify_history` | `objects` JSON `{entries,pending,heads,predecessor}` (base64 arrays), `now_ms` | `{code, seq, detail, rollback, account, branch[], conflicts[], heldUntil}`: the history verifier with no identity |
| `account_webauthn_check` | descriptor JSON, body, DER signature, authenticatorData, clientData, mode JSON | `{ok,uv,origin,counter}` or `BadSignature` naming the failed check |
| `account_verify_swift_predecessor` | `entries` JSON (base64 array) | `{account, entries[{seq,digest,issuedMs,layout}]}` |
| `account_key_id`, `account_webauthn_prf_input`, `account_vault_public`, `account_format_date`, `account_default_policy`, `account_request_info` | | helpers, public values only |

### `AccountCreation` (replaces `begin_create`, `begin_create_with`, `advance_create`)

`begin(params, identity, now_ms, entropy[96])` then `stage`, `prf_requests`, `steps`, `provide_prf(results)`,
`provide_signatures(sigs)` (returns `continue` or `done`), `take_account()` returns an `AccountCore`. `params` JSON: `label`,
`namespaces`, `controllers` (protocol JSON), `slots [{controllers,label}]`, optional `threshold`,
`recoverThreshold`, `addThreshold`, `countByHolders`, `policy`, `signers`, `rekeySigners`.
`identity` is `controller:<32 hex>` or `member:<32 hex>`.

### Steps, signatures, PRF (the shape of "begin and finish")

`AccountAction.steps()` is `[{path, body, signer, role, form, descriptor, signingKey, challenge, uv}]`:
`body` is base64 of the exact bytes to sign; `role` is `primary|cosignature|possession|handover`; `form`
is `raw` or `webauthn`; `challenge` is present for a WebAuthn signer. Signatures go back in step order as
`[{signature, authenticatorData?, clientData?}]` (raw `r||s`, or DER with the assertion). PRF:
`prf_requests()` is `[{controller, rp, credential, salt, challenge}]`; the host makes the assertion and
returns `[{authenticatorData, clientData, signature, output}]` (`output` is the 32-byte `results.first`)
through `provide_prf`, after which `steps()` is non-empty.

### `AccountCore` and `AccountEngine` shared reads

`id identity status head controllers homes policy pending owed_shares notices(shown_seq,
shown_transitions, local_keys) proposals tools slots is_unlocked begin_unlock_epochs begin_unlock_slot
fork_candidates suggest_signers latest_epoch write_denial stores`, plus on both (the engine's own
versions on the engine): `me members ledger access view query revision`.

### `begin(spec, entropy)` on `AccountCore` and `AccountEngine`

Returns an `AccountAction` (`kind`, `denial`, `info`, `account`, `steps`, `prf_requests`). `denial()` is
non-empty (`{"reason","detail"}`) when a write is refused for access reasons (it is a value, as in 0.4).
`spec` is JSON with `"action"`:

| `action` | Fields | Entropy | 0.5 call |
| --- | --- | --- | --- |
| `approve` | `request`(b64), `terms`, `signers` | 32 | `begin_approve` (a `grant`; `terms.import` is an import grant) |
| `renew` | `member`, `expiresMs`, `signers` | 32 | `begin_renew` |
| `renew_shares` | `member`, `signers` | 32 | `begin_renew_shares` |
| `revoke` | `member`, `keep` (`everything`/`nothing`/`{kept,heads}`), `signers` | 32 | `begin_revoke` |
| `end_sessions` | `member`, `signers` | 0 | `begin_end_sessions` |
| `end_my_sessions` | none | 0 | `begin_end_my_sessions` |
| `rekey` | `namespaces`, `signers` | 32 | `begin_rekey` |
| `keyring` | `addControllers`, `addSlots`, `policy`, `signers` | 0 | `begin_keyring` |
| `add_controller` | `controller`, `mode` (`immediate`/`transition`), `signers`, `rule` | 0 | `begin_add_controller` |
| `add_slot` | `signer`, `plan{controllers,label}` | 32 | `begin_add_slot` |
| `rotate_vault` | `signer`, `plans`? | 64 (new seed, entropy) | `begin_rotate_vault` |
| `remove_controller` | `remove`, `keep`, `signers`, `rule`, `rotate` | 0 or 64 | `begin_remove_controller` |
| `transition` | `change` (the §8.7 object), `signers`, `rule` | 0 | `begin_transition` |
| `veto`, `suspend`, `resolve` | as the core | 0 | |
| `write`, `propose` | `namespace`, `kind`, `payload` | 32 | `begin_write`, `begin_propose` (the engine's `begin_write` retains live heads) |
| `resolution` | `namespace`, `accept`, `proposals` | 32 | `begin_resolution` |
| `link`, `call` | see the core; `call`'s request ID is the 32 entropy bytes | 0 / 32 | `begin_link`, `begin_call`, **on `AccountCore` only** (the engine does not return a call's artifact) |

Then `provide_prf(action, results)` if `prf_requests()` is non-empty, then `finish(action, signatures)`.
`AccountCore.finish` returns `{entries[{seq,bytes}], pending[], records[{path,bytes}], artifact, stores,
changes, info}`; `AccountEngine.finish` returns `{stores, changes}`. **`stores` is `[{path, bytes}]`:
store exactly those bytes at those paths, in order.** An engine that finished a write already holds
the bytes; the host stores them and need not call `apply_paths`.

### `AccountEngine`

`open(source, listing, identity, account, namespaces, batch, saved, key, now_ms)`: `listing` is a JSON
array of every path the source holds; `namespaces` a JSON array (empty: all); `saved` the JSON `save`
returned (or empty); `key` the 32-byte device-held key. Then `open_mode stats load refresh apply_paths
advance finish_unlock_slot finish_unlock_epochs missing_covered budget_scope_unavailable rejudged
revisions history operation_at begin begin_import provide_prf finish begin_live_write finish_live_write
apply_live stale_live live_verdicts save verify_batch begin_blob blob_manifest open_blob_chunk blob_chunk
read_blob blob_availability required_blob_fetches`, and the exchange: `exchange_homes
exchange_set_bearer exchange_next exchange_provide_call exchange_answer exchange_want_blob receipted_by`.

The exchange as values the host performs: `exchange_next(home)` returns `{"step":"request","request":
{ticket, home, method, url, headers[[k,v]], body}}`, `{"step":"needCall","need":{ticket, home, audience,
purpose, method, url}}`, `{"step":"waiting"}` or `{"step":"done"}`. The host sends the request,
and calls `exchange_answer(home, ticket, status, headers, body)`, which returns `{store[{path,bytes}],
changes, faults[{kind, home, ...}]}`. Fault kinds: `rollback fork badObject foreignAccount noProgress
mismatch refused conflict race unauthorized redirect malformed cursorReset more headAhead status`. A `needCall` is answered by
`exchange_provide_call(home, ticket, call)` with a call built by the host (`begin` `call` on an `AccountCore`).

### Pairing and the seed (replaces `begin_add_passkey`, `begin_recovery_add`, the 0.4 pairing)

Joiner (new device): `PairingTransferKey.create(entropy32)`; `AccountPairing.join(account, key.public(),
nb)`; send `commitment()`; on `na`: `receive_nonce(na)` returns `{e, nb}` to send; `digits()`; `confirm()`.
Existing device: `AccountPairing.existing_receive_commitment(account, commitment, limiter, now_ms)`;
`send_nonce(na)`; `receive_reveal(e, nb, limiter, now_ms)` returns the digits; `confirm()`; then
`AccountCore.transfer_seed(pairing, entropy)` returns a sealed box JSON. New device:
`AccountCore.accept_seed_transfer(key, sealed, pairing)`. The QR path is `join_qr` / `qr_payload` and
`existing_scan_qr` (the host attests the scan). Keep the `PairingFailureLimiter` state (`to_json`).

### Moving

`AccountMove.begin_upgrade(history, params, now_ms)` is the 0.4 in-place upgrade (§16.1): `history` is
`{"authority/00000001.json": b64, ...}`; `finish(sigs)` returns the entry to store at
`authority/<seq>.json`. Swift succession on `AccountCore`: `swift_succession`, `swift_predecessor`,
`begin_swift_veto`, `begin_swift_freeze`, `begin_swift_copier_shares`, `finish_move`,
`accept_predecessor_entry`. **Not exported: the Swift copy** (`CopyPlan`, the host `Translator`
callback, `begin_swift_copy_write`/`finish_swift_copy_write`, `swift_copy_destination`,
`finish_swift_copy`, `begin_swift_migration`). It needs the Swift slot opening (`swift_slots`: a host
opening a Swift library's epoch keys) and a translator callback with a documented JSON shape; it is
the next piece, not a hidden gap.

## 6. Sealed state and keys

`AccountEngine.open` takes the device-held key once and the core's engine keeps it for `save` and the
saved-state check (the core's design; `EngineOptions` has no accessor). Stored state is a cache: a bad
tag, another account or identity, an unknown format or a wrong key is ignored and the history replays
(`open_mode` says `invalidated`). `AccountCore.open` and `export_persisted` take the key per call and
keep nothing. The core never calls a host key provider (§3.4, §17.1): there is no `KeyProvider`
callback in 0.5; the host reads the steps and signs.

## 7. The 0.4 calls and their exports (the account header's table)

| 0.4 | Export, or why none |
| --- | --- |
| `begin_create`, `begin_create_with`, `advance_create` | `AccountCreation` |
| `open`, `open_with_checkpoints` | `AccountCore.open`; `AccountEngine.open` |
| `id`, `identity`, `me` | `id`, `identity`, `me` |
| `records`, `authority` | `AccountCore.stores`, `controllers`, `policy`, `homes` |
| `set_read_scope` | `AccountCore.set_read_scope`; the engine takes `namespaces` at `open` (the core's engine has no forward) |
| `merge`, `merge_with_changes`, `changes`, `finish_with_changes` | `AccountCore.merge`; every `finish` returns `changes` |
| `revision`, `applied_operations` | `revision`, `revisions`, `stats` |
| `checkpoint`, `restore_checkpoint`, `set_checkpoint_policy` | `AccountEngine.save` and `open(saved)`; `AccountCore.export_persisted` and `open(stored, key)` |
| `query`, `view` | `query`, `view` |
| `finish`, `finish_authority` | `finish` |
| `begin_unlock_slot`, `finish_unlock_slot`, `begin_unlock_slots` | `slots`, `begin_unlock_slot`, `finish_unlock_slot` |
| `begin_unlock`, `finish_unlock`, `finish_unlock_many` | `finish_unlock_slot` (vault), `begin_unlock_epochs`, `finish_unlock_epochs` (member) |
| `build_sealed_slot`, `begin_prf_slot`, `finish_prf_slot`, `begin_combined_slot`, `finish_combined_slot`, `finish_prf_part`, `finish_prf_slot_for` | `begin add_slot`, `prf_requests`, `provide_prf` |
| `begin_request`, `finish_request` | `AccountRequest`, `account_request_info` |
| `begin_approve` | `begin approve` |
| `begin_revoke` | `begin revoke` |
| `begin_rekey` | `begin rekey` |
| `begin_keyring`, `begin_thresholds` | `begin keyring`, `begin transition` |
| `begin_add_controller`, `begin_recovery_add`, `begin_add_passkey` | `begin add_controller`, `AccountPairing`, `transfer_seed`, `accept_seed_transfer` |
| `begin_remove_controller` | `begin remove_controller`, `begin rotate_vault` |
| `select_controller`, `eligible_signers`, `prepare_authority` | gone in 0.5 (the caller names signers); `suggest_signers` |
| `begin_import_grant`, `begin_import`, `import_*`, `reconcile_import_prefix` | `begin approve` with `terms.import`; `AccountEngine.begin_import` |
| `begin_write`, `written_operation*`, `live_generation` | `begin write`, `operation_at`, `begin_live_write`, `finish_live_write`, `live_verdicts` |
| `begin_layout` | none: a 0.5 account is at layout 2 from genesis (§11.8) |
| `members`, `me` | `members`, `me`, `controllers` |
| `tools`, `begin_call` | `tools`, `begin call`, `begin link` (`AccountCore`) |
| `ledger` | `ledger` |
| `begin_blob`, `open_blob_chunk`, `read_blob_chunk`, `NativeBlobWriter` | `AccountEngine.begin_blob`, `AccountBlobWriter`, `open_blob_chunk`, `blob_chunk`, `read_blob` |
| `NativeEngine::*`, `RecordSource`, `verify_batch`, `records_at`, `update_versions` | `AccountEngine`, `HostSource` (its `version` replaces `update_versions`), `verify_batch`; `records_at` none (the engine reads by path) |
| `NativeCheckpoint*` | `save`, `open(saved)`: sealed under the device key; no member-signed ticket |
| `vault_public`, `webauthn_prf_input`, `parse_registration` | `account_vault_public`, `account_webauthn_prf_input`; `parse_registration` is the 0.4 export, unchanged and still correct for 0.5 |
| `KeyProvider::sign_with`, `sign_controller_with`, `HostAction::sign_with` | none: the core never calls a key provider; the host signs the steps |
| `PendingBatch::record_paths`, `HostAction::record_paths` | `finish` returns `stores`; before finish, each step's `path` |
| `migration.rs` `import_legacy_batch`, `bind_legacy_import_state` | none: upgrade tooling (plan step 8), not the account |
| the 0.4 to 0.5 `upgrade` entry (§16.1) | `AccountMove.begin_upgrade` |
| the Swift keyring upgrade (§16.2) | the Swift succession steps above; the copy is not exported |
| §15 `/5` succession (`begin_successor`, `begin_succession_*`) | none: not built in the core |
| (new) pending transitions, notices, owed shares, proposals | `pending`, `record_due`, `begin transition/veto/suspend/resolve`, `fork_candidates`, `notices`, `owed_shares`, `begin renew_shares`, `proposals`, `begin propose/resolution` |

## 8. Gaps in the core the exports cannot close

* The core's `Engine` exposes `Account` read-only, so it forwards no `record_due`, `set_read_scope`,
  `accept_seed_transfer` or `accept_predecessor_entry`, and its `finish_write` drops a link or call's
  artifact. These are on `AccountCore`: a host that needs them opens an `AccountCore` over the same
  stores, does the step, stores what comes back, and calls `AccountEngine.apply_paths`. A one-line
  `Engine::account_mut` or those forwards would remove the second object; they were not added because
  `v05/engine/` is being edited by another package.

## 9. What was run, and what was not

See the pull request for the numbers. Run: the name tests in both crates; two journeys through the
UniFFI surface (create with a passkey-like controller, approve, write, read, pair, transfer, sync two
engines through an in-memory home built from the exchange values; upgrade a 0.4 library in place, read
its records, write a new one); the hostile cases; the same create/approve/write/pair path natively
through the wasm build's `AccountCore`. **Not run:** anything that needs a JS host: the wasm
`AccountEngine`, `JsSource`, the exchange and the thrown `AccountFault` were compiled for
`wasm32-unknown-unknown` and compiled natively but never executed in a browser or Node (there is no
harness here). The generated Swift and Kotlin sources were produced and `swiftc -parse` accepted the
Swift; they were not compiled with an Apple SDK or Gradle.
