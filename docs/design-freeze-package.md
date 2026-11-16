# Colophon 0.5: the freeze package (design)

Status: design. Revision 16 of the spec stated the whole package; after the independent check it was
revised once. **Revision 17 cuts it to what shipping 0.5 and a later in-place upgrade need**, on the
owner's word: "modularity can wait till 0.6, I just don't want to get blocked on shipping 0.5. also
don't want to do another full on migration once we start to work on 0.6", and "I'm not that worried
about the unknowns." The 0.5 parts are built, and 0.5 was frozen on 2026-11-16 (spec §21); the
sections marked "Deferred to 0.6" are not built. The spec text is revision 17 of
[`spec/colophon-0.5.md`](../spec/colophon-0.5.md), mapped in
[`spec/colophon-0.5-changes.md`](../spec/colophon-0.5-changes.md) §A.12 (rows 159–197, the
withdrawn ones marked) and §A.13 (rows 198–202). Base: `spec-0.5` at `25027b0`.

**In 0.5:** P (approval consumes a confirmed pairing), F2 (the current-principal check; unknown kinds
stay under the control rule), F3 (the layout door; one opt-in covers a whole later format version),
S (a stopped reader and a stopped home, in the form the door needs), text-only reservations
(`refused:notGranted` among them), the three Low fixes, the home rules the home code follows (spec
§13.1, §13.3, §14; code in PR 28), the stated limits and what is open at the freeze.

**Deferred to 0.6:** F1, F4, F5, F6, F7 behind the door, and F8 (invites), which needs no door. Their sections below are kept so the work is
not lost, each marked **"Deferred to 0.6: not a 0.5 rule"**; §16 summarizes them. In 0.5, revision
15's behaviour stands in each place.

**The two governing rules:** never widen who can stop a device; an older reader may say "update me"
where a newer one decides, but never decides differently.

## 0. Summary

| Item | Existing vectors that change verdict | Size | Risk |
| --- | --- | --- | --- |
| P Member approval consumes a confirmed pairing (a live defect) | none (interface) | M | High until fixed: today a relay can substitute a member key |
| F2 Current principal; unknown kinds stay under the control rule | none (inputs: an expired or provisional member's `endSessions`, `ok`/`newerFormat` → `badSignature`) | S | Low |
| F3 The upgrade door (`layout`) | `upgrade/then-v5-layout` (0.5: `ok` → `malformed`, regenerated as two cases) | S | Low |
| S Stops at the door: a stopped reader, the stopped home | none | S | Medium: the stopped-home table must be built exactly |
| R Text-only reservations | none | S | Low |
| L Two Low findings (L1, L2), the owed home sentence, stated limits; L3 withdrawn (a seq-0 Swift envelope is ignored, as today) | none | S | Low |
| F1, F4, F5, F6, F7, F8 | withdrawn in revision 17 (deferred to 0.6) | — | — |

**Existing vectors that change verdict:** one, `upgrade/then-v5-layout` (F3). The three that revision
16 would have changed (`rules/t-grant-component-extra-field`, `records/revoke-17-heads`,
`succession/authority5-chain-17`) no longer change.

### Order of work: dispatchable streams

W0 is merged (`cases_freeze_{authority,swift,records,calls,home}.rs` exist and are registered; no
stream edits `tests/v5_candidate.rs`). `cases_freeze_records.rs` stays empty in 0.5 (its items are
deferred). No file belongs to two streams of one wave; a stream starts when everything it depends on
is merged into `spec-0.5`.

Common acceptance for every Rust stream (private `CARGO_TARGET_DIR`, Rust 1.99.1, through
`pressroom run`): `cargo test -p colophon-core --test v05_candidate`, `cargo test -p colophon-core
--test v5_candidate -- --ignored v5_generator_check`, `cargo test -p colophon-core`, `cargo clippy -p
colophon-core --all-targets -- -D warnings`.

**Wave 1**

| Stream | Owns exactly | Depends on | Items | Vectors and generator | Extra acceptance |
| --- | --- | --- | --- | --- | --- |
| **W1-P Approval** | `crates/colophon-core/src/v05/pairing.rs`, `v05/account/action.rs`, `v05/write/authority.rs`, `crates/colophon-ffi/src/v05/api/{pairing,engine,action}.rs`, `crates/colophon-ffi/src/v05/surface-names.txt`, generated bindings (`swift/Sources/ColophonKit/Generated/*`, `sdk/kotlin/src/main/kotlin/com/luff/colophon/colophon_ffi.kt`), `swift/Sources/ColophonSession/*`, `swift/Sources/ColophonSessionUI/*`, `swift/Tests/ColophonSessionTests/*`, `sdk/kotlin/src/main/kotlin/com/luff/colophon/session/*`, `js/src/session/*`, `js/src/index.ts`, `js/scripts/smoke.mjs`, `playground/src/*`, `examples/ColophonSample/*`, new `crates/colophon-core/tests/v05_freeze_approval.rs` | — | P, L2 | none in `conformance/`; tests: approve without a token refused; a token for another key refused; a token spent twice refused; the code path and the scan path each issue one | `cargo test -p colophon-core --test v05_freeze_approval`, `cargo test -p colophon-ffi`, `swift test`, `cd sdk/kotlin && ./gradlew test`, `cd js && npm test`, `cd playground && npm test` |
| **W1-A Authority** | `crates/colophon-core/src/v05/history/state.rs`, `history/mod.rs`, `engine/checkpoint.rs`, `tests/v5_candidate/cases_freeze_authority.rs`, the `conformance/0.5/candidate/{rules,upgrade}/` cases it generates (and the regenerated `upgrade/then-v5-layout`) | — | F2 (current principal, first commit), F3 (stored layout, the door), S (the reader's stopped flag, `Verdict::stopped`), L1 | §2 vectors, §3.4 vectors | — |

**Wave 2** (after W1-A: the stopped flag and the current-principal helper)

| Stream | Owns exactly | Depends on | Items | Vectors and generator | Extra acceptance |
| --- | --- | --- | --- | --- | --- |
| **W2-C Calls** | `crates/colophon-core/src/v05/calls.rs`, `tests/v5_candidate/cases_freeze_calls.rs`, `conformance/0.5/candidate/calls/` cases it generates | W1-A | S (a stopped reader's calls `unavailable`) | `calls/s-stopped-reader-call` | — |

**Wave 3**

| Stream | Owns exactly | Depends on | Items | Vectors and generator | Extra acceptance |
| --- | --- | --- | --- | --- | --- |
| **W3-H Home** | `crates/colophon-home-wasm/src/*`, `crates/colophon-core/src/v05/history/home.rs`, `engine/paths.rs`, `engine/exchange.rs`, `relay/*`, `tests/v5_candidate/cases_freeze_home.rs`, new `crates/colophon-core/tests/v05_freeze_home.rs` | W2-C and PR 28 merged | S (the stopped home, §13.6), R (`layouts`, refusal names shown raw) | home tests: each row of §13.6; unknown `refused:` refuses one request | `cargo test -p colophon-home-wasm`, `cargo test -p colophon-core --test v05_freeze_home --test v05_home --test v05_engine_home`, `cd relay && npm test` |
| **W3-G Write side, exports, SDK surfacing** | `crates/colophon-core/src/v05/account/{read,derived,mod}.rs`, `crates/colophon-ffi/src/v05/api/*` other than W1-P's (and those once W1-P is merged), the three session layers, `playground/src/*` | W1-P, W2-C, W3-H | the stopped status; "waiting for approval" wording for a member no grant names | none new | as W1-P |

W1-P and W3-G both touch the FFI and the session layers, in different waves. At most two builders at once
(wave 1).

## 1. F1: Unknown content, one rule

> **Deferred to 0.6 (revision 17): not a 0.5 rule.** Revision 15's behaviour stands in 0.5; this
> section is kept as the design to build after the door. Summary: §16.


### Rule

Inside a known protocol, an unknown field, kind, form, role, value or variant is `newerFormat`,
reported only after every check that authenticates and authorizes the object has passed (the
pipeline of §1). Exactly five kinds of object stay closed, and say so: envelopes and signature
items (they decide which signatures count), unsigned recording entries (nobody authenticates their
extra fields), the pairing QR payload (never authenticated), equivocation evidence containers
(unsigned wrappers of signed objects) and the frozen legacy formats (`/3` headers, the `/4` prefix,
the Swift format), which are read exactly as their own versions wrote them.

### Every place, audited

Every `finish_closed()` in `crates/colophon-core/src/v05/` (27 calls outside the builders) and
every closed match below an authenticated body. "Today" is source-read at `9027b98`. Eight places
(marked **silent**) ignore unknown content today; they are the worst case, because two readers can
reach different verdicts.

| # | Place (function) | Today | Rule | After which checks | What a home does |
| --- | --- | --- | --- | --- | --- |
| 1 | `/5` operation header fields (`OperationHeader::parse`, `records.rs:181`) | **silent** (collected into `unknown`, never read) | `newerFormat` for that record | signature, §11.5 steps 1–8 (it reserves and counts, §6.3) | stores it (stable fields, §1.2) |
| 2 | header `level` (`records.rs:143`) | `malformed` before the signature | `newerFormat` for that record; step 1 reads it as "needs a `records` entry" | as 1 | stores it |
| 3 | `colophon/operation/N`, N > 5 (`records.rs:128`) | `malformed` | `newerFormat` for that record when the stable fields parse | as 1 | stores it |
| 4 | `live` stamp fields (`records.rs:166`) | **silent** | `newerFormat` for that candidate; the slot shows `newerFormat` if it would be the head | as 1 | stores it |
| 5 | plaintext top-level fields (`open_plaintext`, `records.rs:298`) | `invalidPayload` | `newerFormat` for that record (it already reserved) | opening and the ID check | — (encrypted) |
| 6 | receipt fields (`check_receipt`, `state.rs:1327`; `succession::receipts`, `succession.rs:381`; home admission, `home.rs:849`) | `malformed` before the signature | `newerFormat` | signature, object, window | refuses with 422 `newerFormat` (a home verifies authority) |
| 7 | transition `anchor` (`check_transition`, `state.rs:1084`) | `malformed` | `newerFormat` at the recording entry | rule, consent, receipts, anchor on branch | refuses at admission (`newerFormat`) |
| 8 | `head.authority` (`heads::verify_inner`, `heads.rs:85`) | `malformed` | `newerFormat` | signature (as the head's other unknown fields today) | — |
| 9 | heads embedded in `final` (`parse_head`, `state.rs:400`) | **silent** (no field check at all) | `newerFormat` at the `final` | the `final` table row | refuses |
| 10 | keyring `vault` (`Keyring::parse`, `keyring.rs:90`) | `malformed` | `newerFormat` | the entry's rule | refuses |
| 11 | slot kind (`Keyring::check_slot`), slot and part fields (`Slot::from_value`, serde closed) | `malformed` | `newerFormat`; the typed slot checks run only on known slots | the entry's rule | refuses |
| 12 | `rekey` top-level and epoch-object fields (`immediate`, `state.rs:2919`) | **silent** (no prescan for `rekey`) | `newerFormat` | rule | refuses |
| 13 | `keyring` entry top-level fields (`keyring_entry`) | **silent** | `newerFormat` | rule | refuses |
| 14 | `vault` entry top-level fields (`vault_entry`) | **silent** | `newerFormat` | rule | refuses |
| 15 | `suspend` top-level fields (`suspend`) | **silent** | `newerFormat` | rule and the `suspend` row | refuses |
| 16 | `activate`, `vetoed`, `final` top-level fields; `final.activation` | **silent** | `malformed` (deliberately closed: unsigned) | — | refuses |
| 17 | `successionVetoed` fields (`succession.rs:471`) | `malformed` | unchanged (unsigned) | — | refuses |
| 18 | the veto inside `successionVetoed` (`succession.rs:484`, `:565`) | `malformed` | `newerFormat` (as a `/5` veto already is, `check_veto`) | signatures, eligibility | refuses |
| 19 | genesis `predecessor` and `predecessor.head` (`succession::prepare`, `:191–192`) | `malformed` | `newerFormat`; an unknown `format` too | genesis signatures and `handover` | refuses |
| 20 | `migration` subobjects (`succession::migration`, `:773–845`): `predecessor`, `final`, `drain`, namespace, omission, controller, member items; unknown member `kind` or `outcome` | `malformed` | `newerFormat` | the transition's rule and the verified succession | refuses |
| 21 | grant component of a transition and `homes.appoint` items (`parse_transition_grant`, `members.rs:415`) | `malformed` (closed in revision 15) | `newerFormat`, except `shares`, which stays `malformed` (a known field that is forbidden there) | rule, consent, receipts | refuses at admission (`newerFormat`) |
| 22 | call `signer` variant (`Call::parse`, `calls.rs:630`) | `malformed` | `malformed` as today, unless `key` is the signing point of a current principal of the account: then `newerFormat` after steps 1–5 (finding 16); `account`, `organisation` reserved and refused | as stated; reserves nothing | 403 |
| 23 | `layout` value (`apply_delta`, `state.rs:1562`) | never read | F3 | — | F3 |
| 24 | a count above its 0.5 maximum | `malformed` | F4 | — | F4 |
| 25 | unknown `(namespace, kind)` or `v` of a live candidate (`live::judge_one`, `records.rs:1777`) | `invalidPayload` | F5 | — | stores it |
| 26 | a new top-level term field in a grant | the whole history stops | F6 (narrow): that member opaque | — | refuses the member's calls |
| 27 | request `member`, `service`, grant `shares` and epoch objects, `serves` values | `newerFormat` | unchanged (account-wide, F6) | — | refuses |
| 28 | descriptor `form` and fields, controller fields and roles, policy fields and values, keyring fields, `countBy`, terms, links, request fields, veto fields, head fields, call fields | `newerFormat` | unchanged | — | as today |
| 29 | authority, request, call and head envelopes; signature items; `assertion` (`envelope.rs`, `signature.rs:508`, `calls.rs:606,614`) | `malformed` | unchanged: closed | — | — |
| 30 | `/3` header and its `live` stamp (`records.rs:1248,1257`); `/4` prefix (`upgrade.rs`); Swift format | `malformed` / Swift ignores | unchanged: frozen legacy | — | — |
| 31 | QR payload (`pairing.rs`); equivocation evidence objects | `malformed` | unchanged: unauthenticated | — | — |
| 32 | exchange JSON (§14 request and response bodies) | unspecified | a client ignores unknown response members; a home answers a request whose JSON has an unknown member with 422 `{"result":"newerFormat"}` | — | as stated |

### 1.1 Why, and the alternative rejected

Daybreak's audit rule is adopted: collect unknown content wherever the object is authenticated,
close only what is envelope structure or unauthenticated. The alternative, closing every new
object and confining growth to `payload` and `v` (Daybreak's fallback for row 5), is rejected
for row 5: an encrypted plaintext is authenticated by the epoch key and the member's signature,
and a newer writer's extra plaintext field would read as a forged record. It costs one site.

Unsigned recording entries (rows 16 and 17) stay closed, against the general rule, because nobody
signs them: a home builds them deterministically from embedded signed objects, so an extra field
is junk anyone could add. A later version that needs a new field there raises the layout first
(F3).

### 1.2 The stable header

So that homes can store what newer members write (row 1–4), §11.2 now names the **stable fields**
of an operation header, which every later header version keeps with the same meaning:
`protocol` (`colophon/operation/<N>`), `account`, `namespace`, `author`, `epoch`, `id`, `clock`,
`authority`, `created`, `level` (present; its value may be new), `previous`, and for a
live-stamped header `live.slot`; the envelope is `{body, signature}` signed `raw` by the author's
member key; the paths are §11.2's and 0.3 §4's. A later version that must change any of these uses
another marker name, which 0.5 does not store, and raises the layout first.

### 1.3 Frozen rules that make record-level `newerFormat` agree across versions

A record that is `newerFormat` must not make a 0.5 reader admit something a newer reader refuses.
Three rules do that, stated in §11.5 and §11.6:

1. **Steps 1–8 are frozen.** Every header that passes §11.5 steps 1–7 reserves its budget slot and
   counts its clock (step 8), whatever its unknown content; for step 1 an unknown `level` needs only a `records` entry for the namespace. A later version that
   refuses such a header for a level 0.5 does not know refuses it after step 8, as `outOfScope`
   already is. So budgets and clock bounds are the same for every reader.
2. **`duplicateID`.** A header that sorts after a `newerFormat` header with the same author and ID
   (§11.4 order) is itself `newerFormat`: 0.5 cannot tell whether the first one authenticates.
3. **Proposals.** A proposal whose first valid resolution in fold order comes after a
   `newerFormat` record of the same namespace by an author whose `records` entry there has `write` is
   `newerFormat` (unresolved for this reader), never
   resolved by the later resolution.

Domain folds (last-writer-wins and the rest) skip `newerFormat` records as they skip unknown
kinds and payload versions today. A host MUST show, per namespace, how many records it could not
read (§17.1). That is the residual risk of §1.7.

### 1.4 Functions that change

- `encoding.rs`: no change to `Obj::finish_closed`; call sites move to `Obj::finish(&mut unknown)`.
- `records.rs`: `OperationHeader::parse` split into `parse_stable` (the §1.2 fields, signature
  target, path) and the full `/5` parse; `Level::Unknown(String)`; `judge_candidate` (step 1
  reading, `newerFormat` after step 8, the `duplicateID` rule); `open_plaintext` (row 5); the
  proposal pass (`judge_records`, the `resolution_targets` loop) for rule 3.
- `live.rs`: `judge_one` (rows 4, 25), `judge_group` (a `newerFormat` candidate that would be the
  head makes the slot `newerFormat`; it counts for equivocation).
- `history/state.rs`: `check_transition` (row 7), `check_receipt` (row 6), `parse_head` and
  `final_entry` (row 9), `immediate` (row 12), `keyring_entry` (row 13), `vault_entry` (row 14),
  `suspend` (row 15), `activate`, `vetoed`, `final_entry` (row 16: a closed field check),
  `classify` (row 21 via `members::parse_transition_grant`).
- `prescan.rs`: `authority_fields` covers `rekey`, `keyring`, `vault`, `suspend`; a
  `recording_fields` closed check for the four unsigned kinds.
- `history/keyring.rs`: `Keyring::parse` (row 10) and `Keyring::check`, run only after the unknown
  check; `slots.rs`: `Slot::from_value` gains an `Unknown` slot (row 11).
- `history/succession.rs`: `prepare`, `receipts`, `vetoed`, the veto check, `migration`.
- `history/home.rs`: the receipt arm of admission (row 6).
- `heads.rs`: `verify_inner` (row 8). `members.rs`: `parse_transition_grant` (row 21).
- `calls.rs`: `Call::parse`, `CallSigner::Unknown(String)`, and the step order (row 22).

### 1.5 Vectors

Added (all under `conformance/0.5/candidate/`, built by `cases_freeze_a.rs`, `_b.rs`, `_c.rs`):

| Vector | Expected |
| --- | --- |
| `records/f1-header-unknown-field` | the record `newerFormat`; history `ok` |
| `records/f1-header-unknown-field-bad-signature` | the signature failure wins; never `newerFormat` |
| `records/f1-header-unknown-level` | the record `newerFormat` |
| `records/f1-header-unknown-level-no-entry` | `notGranted` |
| `records/f1-operation-6` | the record `newerFormat` |
| `records/f1-operation-6-missing-stable-field` | not a record (`malformed`) |
| `records/f1-live-stamp-unknown-field` | the slot `newerFormat`; no lower value shown |
| `records/f1-plaintext-unknown-field` | the record `newerFormat`, slot reserved |
| `records/f1-newer-reserves-budget` | `writes: 1`: the newer record, then a plain one → the second `budgetSpent` |
| `records/f1-newer-counts-clock` | a later record within 1,024 of the newer one's clock is admitted |
| `records/f1-newer-blocks-duplicate` | a same-ID header sorting after a newer one → `newerFormat` |
| `records/f1-newer-blocks-resolution` | the proposal `newerFormat` |
| `rules/f1-anchor-unknown-field` | `newerFormat` at the `activate` |
| `rules/f1-receipt-unknown-field` | `newerFormat` at the `activate` |
| `rules/f1-receipt-unknown-field-bad-signature` | `badSignature` |
| `heads/f1-authority-unknown-field` | `newerFormat` |
| `rules/f1-final-head-unknown-field` | `newerFormat` at the `final` |
| `rules/f1-vault-unknown-field` | `newerFormat` at seq 1 |
| `rules/f1-slot-unknown-kind`, `-unknown-field`, `-unknown-part-kind` | `newerFormat` at the entry |
| `rules/f1-rekey-unknown-field` | `newerFormat` (today `ok`) |
| `rules/f1-keyring-entry-unknown-field`, `rules/f1-vault-entry-unknown-field`, `rules/f1-suspend-unknown-field` | `newerFormat` (today `ok`) |
| `rules/f1-activate-unknown-field`, `rules/f1-final-unknown-field`, `rules/f1-final-activation-unknown-field` | `malformed` (today `ok`) |
| `rules/f1-migration-unknown-field`, `rules/f1-migration-unknown-member-kind` | `newerFormat` |
| `succession/f1-predecessor-unknown-field`, `succession/f1-predecessor-unknown-format` | genesis `newerFormat` |
| `succession/f1-succession-veto-unknown-field` | `newerFormat` at the `successionVetoed` |
| `calls/f1-signer-unknown-variant-bound` | `newerFormat` (`key` is a current member's point) |
| `calls/f1-signer-unknown-variant-unbound` | `malformed` (an outsider's key) |
| `calls/f1-signer-organisation` | `malformed` (reserved, refused) |
| `calls/f1-signer-unknown-variant-bad-signature` | `badSignature` |

**Existing vector that changes:** `rules/t-grant-component-extra-field`, `malformed` →
`newerFormat` (regenerated; its description changes). `rules/t-grant-component-shares` and
`rules/t-appoint-item-shares` stay `malformed`.

**Inputs whose verdict changes and no vector holds:** rows 12–15 (`ok` → `newerFormat`), row 9
(`ok` → `newerFormat`), row 16 (`ok` → `malformed`), rows 2, 3, 5 (`malformed`/`invalidPayload` →
`newerFormat` for the record), rows 6–8, 10, 11, 18–22 (`malformed` → `newerFormat`). Unit tests
that assert the old closed behaviour (the E12 grant-component tests, `members.rs` tests) change
with them.

### 1.6 Effect elsewhere

- **Home.** `check_record` (`colophon-home-wasm/src/ops.rs`) uses `OperationHeader::parse_stable`:
  account, path, author a member of the home's verified history, signature. It stores headers with
  unknown fields, an unknown level or a later `/operation/N`. For authority objects nothing
  changes: a home verifies and refuses `newerFormat` (422), because it signs heads only over what
  it verified (§13.3). That is the stated limit: an account uses newer **authority** content only
  once its homes read it (F3).
- **Write side.** Builders never write unknown content; nothing changes in `write/`.
- **Exports.** The record judgement JSON already carries `newerFormat`; the view gains a per
  namespace count `newer` (§17.1). No new function.
- **SDKs.** Swift, Kotlin and JS map `newerFormat` to `updateRequired` today; they surface the
  count. No other change.

### 1.7 Residual risk

A domain fold skips a `newerFormat` record, so a 0.5 device may show a value a newer device has
replaced (a note edited by a newer app). This already happens for unknown kinds and payload
versions; it is surfaced, never silent, and no protocol verdict depends on it. Hostile input now
reaches signature checks it used to stop before (row 2); the existing byte bounds contain that.

## P. Member approval consumes a confirmed pairing (first in the order of work)

### Rule

The core refuses to prepare or finish a `grant` (and a transition's `grant` component) unless the
call consumes a **confirmed pairing**: an opaque token the core issues once when §7.3 completes,
bound to the account and to the exact `member.signing` of the request, and spent by that approval.
No interface approves a member from a member ID or a prefix code (§9.1, §17.1).

### The defect

Live on the branch. Swift (`AccessRequest.code(for:)`: `id.prefix(8)`), JS (`pairingCode`:
`id.slice(0, 8)`) and Kotlin (`id.take(8)`) show a code that is the first 32 bits of the member ID,
with no commitment and no nonce, and approval consumes no pairing state. A relay that intercepts the
request grinds about 2^32 signing keys until one has the same prefix, substitutes its request, both
screens show the same code, and the approver grants the attacker's key. The core and bindings already
implement §7.3 (`v05/pairing.rs`, `AccountPairing`), but the session layers use it only to move the
seed, and `begin_approve` is callable on its own.

### Design

- `v05/pairing.rs`: `ConfirmedPairing` gains `account` and `point` (the `E` that paired) and becomes
  single-use (moved into the call that spends it). It is issued by `confirm` on the code path and by
  a new `scanned_request(account, request_bytes)` on the camera path (H scans the request from J's
  screen: `E` is `member.signing`, nothing to compare).
- `account/action.rs`: `begin_approve(request, terms, signers, seed, pairing: ConfirmedPairing)`
  refuses `refused:outOfScope` unless `pairing.account` is this account and `pairing.point` equals
  the request's `member.signing`; the same for `Change::grant`. `write/authority.rs`:
  `prepare_grant` becomes `pub(crate)` and takes the token, so no other path reaches it. L2 (the
  prepare-time check of a composite change) lands here too, in `begin_transition`.
- **Exports.** UniFFI: `AccountEngine.begin_approve` gains a `pairing: Arc<AccountPairing>`
  argument in the `Confirmed` stage and spends it; `AccountPairing.scan_request(account, request)`
  returns a confirmed pairing; the old signature is removed (listed in `surface-names.txt`). Wasm
  (the `web05` build of the same API): the same, the pairing passed as its handle. The legacy 0.3 and
  0.4 surfaces (`colophon-ffi/src/lib.rs`, `storage_engine.rs`, `colophon-wasm/src/lib.rs`) are not
  0.5 and keep their own approval; they are out of scope and say so.
- **Session layers.** Swift `ColophonSession`, Kotlin `ColophonSession`, JS `session`: the request
  list carries no `pairingCode`; approving opens a pairing (`join`/`existing_receive_commitment`, or
  the QR scan) whose confirmation is passed to `approve`. The joining side shows the §7.3 six-digit
  code after the commitment exchange, or shows its request as a QR. `AccessRequest.code(for:)`,
  `pairingCode` and the Kotlin equivalent are deleted.
- **Test apps.** `playground` and `examples/ColophonSample`, and the two test apps outside this
  repository: the approve screen runs the ceremony or scans the request; no code from an ID.

### Residual risk

Appointing a home is outside the rule (its request comes from the home's own base over TLS and names
the member); stated as a limit in §9.1.

## 2. F2: Current principal; unknown kinds stay under the control rule

### Rule

An unknown entry kind or transition component stays under today's control rule and is then
`newerFormat` (withdrawn: the revision that let any current principal sign one). A later kind signed
another way (by a member, a home or recovery keys alone) is reached only through the upgrade door
(F3): the account opts in to a later layout once, with the strongest consent, and from then on 0.5
readers stop anyway. **One opt-in covers a whole format version**, not one per kind. The defect the
check found stays in the package: one normative **current principal** check (§8.5) used for
`endSessions` and wherever a principal's signature is accepted, before unknown content is looked at.

### Why

The check showed the earlier F2 widened who can stop a device: with `memberRule: control` and a
threshold of 2, one approve-, control- or recover-only key cannot meet the control rule today, but
could sign an unknown kind (finding 1); and a 0.5 reader would stop where the version that defines the
kind rejects it as unauthorized (finding 3), an older reader deciding differently. Under the control
rule the signers who can stop a device are exactly those who can already rewrite the keyring.

Finding 2 is a defect of revision 15's code: `immediate`'s member branch checks only
`revoked_seq.is_none()`, so an expired or provisional member can sign `endSessions`, and with an
unknown field get `newerFormat`, a stop by a key that is no longer current.

### Functions

`history/state.rs`: a `current_principal(s, id, rule, at_ms) -> Result<Principal>` helper; the
`endSessions` member branch of `immediate` uses it (expiry at `e.issued`, provisional, revoked);
`check_item` callers for controllers (suspension, provisional, role), `check_receipt` and heads
(current home) route through it. The unknown-kind arm and `classify` are unchanged.

### Vectors

| Vector | Expected |
| --- | --- |
| `rules/f2-end-sessions-expired-member` | `badSignature` (today `ok`) |
| `rules/f2-end-sessions-provisional-member` | `badSignature` |
| `rules/f2-end-sessions-expired-unknown-field` | `badSignature`, never `newerFormat` |
| `rules/f2-end-sessions-current-unknown-field` | `newerFormat` |
| `rules/f2-unknown-kind-single-approve` | `badSignature` (unchanged rule, now a vector) |
| `rules/f2-unknown-kind-control-rule` | `newerFormat` |
| `rules/f2-unknown-component-control-rule` | `newerFormat` at the `activate` |
| `rules/f2-unknown-component-recovery-rule` | `badSignature` |

Existing vectors that change: none.

### Who can stop a 0.5 device

Unchanged from today: the control rule (any entry or transition), any single-rule signer within that
rule's kinds (an unknown field in a `grant`, `renew` or `revoke`), and a current member in
its own `endSessions`; and now only while each is a current principal, which narrows it.

## S. Stops at the door

### Rule

A reader is stopped (spec §1 "A stop") at an entry it judges `newerFormat` under today's rules, or
when an activation raising the layout becomes **final** (revision 17 fix round: a provisional raise
is judged as any transition, and a `vetoed` that displaces it is applied, so a vetoed raise strands
nobody; the companion rule in §20: a later-format implementation writes nothing of the later format
until the raise is final). Once stopped: every call it verifies is `unavailable` whatever S is, it accepts no head, admits no
record it had not admitted before, answers no question of currency, membership or access, and builds
nothing. A home that stops follows the normative table of spec §13.6. Revision 17 removed only the
parts that served deferred items (`ext/` files, location statements, the policy window W).

### Why

Finding 4 of the check: an entry 0.5 cannot judge at N and the attacker's revoke at N+1; a reader
that made only the calls "needing" N unavailable would still accept the attacker under a fresh head
at N−1. A stopped reader cannot see N+1, so it trusts nothing new. The door makes this case ordinary:
every account that opts in stops its 0.5 readers and homes at the raise.

### The stopped home (spec §13.6), and the veto question

Keeps and serves what it holds (what needs no call); forwards every pending object it holds; signs no
head after the stop, not even a fresh one at N−1; stores and vouches for no authority at or after N;
verifies no call (503 `unavailable`), so it serves nothing under `members` and stores nothing new.
It receipts a veto, or a removal-only transition, anchored before the stop, judged at its last
verified state, within 300 s: a receipt only witnesses arrival time and every reader re-judges the
signers, so it cannot make an invalid object count, while refusing could let a hostile stop suppress
a veto or a revocation. It receipts nothing else.

**Limit:** under `members` a stopped home serves only what needs no call (`GET {base}`, and the
history under `public`), because verifying a call is a trust decision; newer devices read through the
account's other homes, and the host offers to update or revoke the stopped home.

### Functions and vectors

`history/mod.rs` (`Verdict::stopped`, W1-A), `calls.rs` (step 4, W2-C), `history/home.rs` and
`colophon-home-wasm` (the table, W3-H). Vectors: `rules/f3-layout-then-entry` (nothing after the
raise applied), `calls/s-stopped-reader-call` (`unavailable`, with fresh heads at N−1); home tests,
one per row of §13.6. A stopped reader's record holding is in W1-A's `Verdict` and needs no change in
`records.rs` (records citing the stop or later are already held `authorityBehind`; records admitted
before stay shown).

## 3. F3: The upgrade door

### Rule

The transition component `layout` is an integer. A `/5` account is at layout 2 from genesis and an
upgraded account at layout 2 from its `upgrade`; the verifier stores it. A `layout` component that
does not raise it (2 or less) voids the transition (`malformed` at its `activate`). One that raises
it above 2 is judged and recorded as any transition (control rule and the recovery set's consent,
§8.4); while its activation is provisional the reader applies nothing of the later layout and goes
on, and a `vetoed` may displace it; once the activation is final the reader is stopped and applies
nothing after the entry at which it became final. Later versions opt an account in through this
component and no other, and write nothing of the later format until the raise is final.

### 3.1 Why, and the alternative rejected

One door, not two. The alternative is a new entry kind under F2. `layout` is chosen because it
already exists in the transition grammar, already needs the strongest consent (control rule plus
recovery set), already means "stop" to 0.3 and Swift readers (Swift's freezing entry is a `layout`
above 2), and the verifier already recognizes it; the fix is to read its value. A new kind would
also work, but a second door means a second rule to get right; an opt-in that retires rules
for every device belongs under the strongest rule.

### 3.2 What a 0.5 home does

A 0.5 home refuses a transition raising the layout at admission (422 `newerFormat`) and refuses
its `activate`. A host MUST NOT propose a raise until every current home lists the target in
`GET {base}`'s `layouts` (R); a 0.5 home answers `"layouts":[2]`. If newer homes reach
`headQuorum` without it, the 0.5 home stores nothing after the entry before the raise, signs no
head beyond it, and keeps serving what it holds; at `headQuorum` it can then stall finality until
it is revoked, which is why the host rule comes first.

### 3.3 Functions that change

`history/state.rs`: `State.layout: u64`; `classify` (the `layout` arm parses an integer; another
type `malformed`); `apply_delta` (`layout ≤ current` → void; `> 2` → `newerFormat` after the delta's
other checks); `genesis` and the upgrade path set 2; `engine/checkpoint.rs` persists it.
`history/succession.rs` is unchanged (the Swift freezing entry is §16.3's own reading).

### 3.4 Vectors

| Vector | Expected |
| --- | --- |
| `rules/f3-layout-3` | the reader stopped once the raise is final (`final` entry, or at once with no home) |
| `rules/f3-layout-3-vetoed` | a `vetoed` displaces the provisional raise; nothing stops; later entries apply |
| `rules/f3-layout-3-provisional` | the reader goes on past the provisional `activate`, applying nothing of layout 3 |
| `rules/f3-layout-2` | `malformed` at the `activate` (void) |
| `rules/f3-layout-3-no-consent` | `badSignature` |
| `rules/f3-layout-not-integer` | `malformed` |
| `rules/f3-layout-then-entry` | `newerFormat` at the layout; the later entry is not applied |
| `upgrade/then-v5-layout-3` | 0.4 `newerFormat`; 0.5 `newerFormat` |

**Existing vector that changes:** `upgrade/then-v5-layout` sets `layout: 2` in an account already
at layout 2. Under F3 that is a void transition: 0.5 `ok` → `malformed`. It is regenerated as
`upgrade/then-v5-layout` (`malformed`, description "a layout component that does not raise the
layout voids the transition") plus `upgrade/then-v5-layout-3` above, which keeps the case's intent
(a `/5` layout transition after the upgrade is judged by the control rule).

### 3.5 Effect elsewhere

Write side: no builder writes a raise in 0.5 (`prepare_transition` refuses a `layout` component;
today it accepts any). Exports, SDKs: none (the stop reason is `newerFormat`).

### 3.6 Residual risk

A controller set with the control rule and consent can strand old devices by raising the layout.
That is true of any authenticated format upgrade (Daybreak), and the same set can already remove
every other key.

## 4. F4: Limits that can be raised

> **Deferred to 0.6 (revision 17): not a 0.5 rule.** Revision 15's behaviour stands in 0.5; this
> section is kept as the design to build after the door. Summary: §16.


### Rule

Every upper bound on a count, or on an integer range, in authenticated content is a **0.5
supported maximum**: above it, and at or below its **parse ceiling**, the value is `newerFormat`
after the object authenticates and its rule holds; above the ceiling it is `malformed` before
authentication. Byte bounds (§2.4), grammars, lower bounds and **rule limits** (limits on what one
signer may do immediately, and relations between fields) stay `malformed`; a later version
changes those only after raising the layout.

### 4.1 Every cap

| Cap | Where | 0.5 value | Becomes | Ceiling |
| --- | --- | --- | --- | --- |
| Declared namespaces, over the account's life | §8.2 | 64 | supported max **256** (raised: the builder already allows 256; a `rekey` of 256 epochs with a few recipients fits the body bound) | 4,096 |
| Controllers in a keyring | §6.2 | 64 | supported max | 4,096 |
| Controllers a `keyring` entry may leave | §6.2 | 56 | rule limit (headroom for transitions) | — |
| Slots | §6.2 | 256 | supported max | 4,096 |
| Slots a `keyring` entry may leave | §6.2 | 224 | rule limit | — |
| Controllers one immediate `keyring` entry adds | §8.4 | 4 | rule limit | — |
| Current homes | §13.1 | 8 | supported max | 64 |
| `headQuorum` | §6.3 | 1–8 | supported max 8; below 1 `malformed` | 64 |
| `records`, `services` entries; `kinds`; `purposes`; `in` values | §10.1, §10.4 | 64 each | supported max | 4,096 |
| `conditions` predicates; nesting | §10.4 | 32; 4 | supported max | 256; 16 (and §2.3's 64) |
| condition path segments | §10.4 | 8 | supported max | 64 |
| `conditions` bytes | §10.4 | 4,096 | byte bound | — |
| `depth` | §10.1 | 0–4 | supported max 4 | 16 |
| Links in a call | §12.2 | 4 | supported max | 16 |
| `origins`, `authorityOrigins`, `audiences` | §3.1, §6.1 | 32 | supported max | 4,096 |
| `service.endpoints` | §9.1 | 8 | supported max | 64 |
| Predecessor chain | §2.4, §15.1 | 16 | supported max | 64 |
| `revoke` heads per namespace | §9.5 | 16 | supported max | 256 |
| `migration.omitted` | §15.4 | 4,096 | supported max | 65,536 |
| `colophon.accept`/`decline` proposals; `basis` items | §11.6, §11.7 | 64; 32 | payload schema of a core kind: unchanged (`invalidPayload`); grows by payload `v` | — |
| Policy `callWindow`, `headMaxAge`, `linkMaxAge`, `recoveryDelay`, `rate` maxima | §6.3 | as §6.3 | supported max; below the minimum `malformed` | 2^53−1 |
| Policy `witnessWindow` (new) | §6.3 | 60–3,600, absent = 300 | supported max 3,600 | 2^53−1 |
| Live candidates per slot path, in all | §11.8 | 8; 16,384 | replica-local storage bound (no verdict): unchanged, a replica MAY keep more | — |
| Pending admission caps | §13.1 | 2, 2, 8 | home-local: unchanged | — |
| Clock jump | §11.4 | 1,024 | verdict constant shared by every replica: unchanged | — |
| Future skew; recording bound | §8.1, §8.7 | 60 s; 7 days | constants: unchanged | — |
| `kept` | §9.5 | the body bound | byte bound: stated limit | — |
| Hints | §5.2 | 8 | unsigned discovery: unchanged | — |

### 4.1a Invariants first (finding 13)

Before any `newerFormat` for a count above its maximum (or any unknown content), the reader checks
every version-independent invariant whose inputs are all values it knows (a count above its maximum is
a known value); a failure is `malformed`. An invariant that needs an unknown value is skipped. The
list (§2.4): `headQuorum` at least 1 and at most the current homes while there is a home;
`primaryHome` a current home; `recoveryDelay` at least 3,600 with a home; `threshold`,
`recoverThreshold` and `addThreshold` against units; at least one `control` controller; holders under
`countBy: holders`; sorted and distinct lists; slots naming current non-`sign` controllers; §3.3;
granted namespaces declared and `shares` complete; a `revoke`'s epochs; the rule limits. Functions:
`Policy::check_homes`, `Keyring::check` and the grant checks run before `Unknown::check` wherever
their inputs are known (W1-A). Vectors: `rules/f4-headquorum-9-eight-homes` (`malformed`),
`rules/f4-headquorum-9-nine-homes` (`newerFormat`), `rules/f4-threshold-above-units-with-cap`
(`malformed`).

### 4.2 `policy.witnessWindow`

The 300-second witness window becomes `policy.witnessWindow`: optional, absent means 300, range
60–3,600 seconds, changed only by a transition with the recovery set's consent (either direction:
a shorter window makes vetoes harder to deliver; a longer one widens backdating at a home). It is
the only cap that becomes a policy field: whether a home must answer within five minutes depends
on the person's homes (a self-hosted box behind a slow link answers differently from a hosted
home), which is the test of principle 3. Absent-means-300 keeps every existing vector's bytes.

Where 300 s is used, it now reads the window **W**, chosen so every verifier computes the same:

| Rule | W is the value in force at |
| --- | --- |
| A transition's receipts, its due time (`issued` + W + delay), a home's admission window and its late-`activate` rule (§8.7, §13.1, §13.5) | the transition's anchor |
| A veto's receipts and a late veto at a home | the vetoed transition's anchor |
| A home's clock rule for immediate entries and full sets (`refused:late`) | the home's current state |
| The Swift succession window, the genesis receipts and the succession veto receipts (§15.1) | the successor's state after the window's entry |
| Hosts' resubmission and "Quorum 2" rules (§17.5) | as for the transition |

The 60 s future-clock tolerance stays a constant: it bounds clock error, not delivery.

Other caps stay constants: the counts are capacity bounds tied to the body bounds and the
portability floor, not choices a person would answer differently; the clock jump and the 7-day
bound are verdict rules every replica shares (a later version can still add a policy field for
one, and an unknown policy field is a safe stop).

### 4.3 Functions that change

`descriptor.rs`: `Policy::parse` (`ranged` splits into upper → unknown, lower → `malformed`;
`witnessWindow`), `Controller::parse` and descriptor list caps; `terms.rs`: `Terms::parse` (each
count cap collects member-local unknown, F6); `history/state.rs`: `genesis` (`:585`), the
namespace counter of F5, `check_transition` and `check_receipt` (W), `delay_at` beside a `window_at`,
`check_checkpoint_shape` (`:194–216`: ranges become ceilings); `history/home.rs` (`WINDOW`);
`history/succession.rs` (the five `300_000`s, `MAX_PREDECESSOR_ACCOUNTS`); `members.rs`
(`Request::parse` endpoints; revoke heads `:602`); `calls.rs` (links); `write/authority.rs`
(`RECEIPT_WINDOW_MS`); `engine/exchange.rs` (`:1007`, `:2133`).

### 4.4 Vectors

| Vector | Expected |
| --- | --- |
| `rules/f4-namespaces-256` | `ok` |
| `rules/f4-namespaces-257` | `newerFormat` at seq 1 |
| `rules/f4-namespaces-4097` | `malformed` |
| `rules/f4-headquorum-9-nine-homes` | `newerFormat` at the `activate` |
| `rules/f4-headquorum-9-eight-homes` | `malformed` |
| `rules/f4-callwindow-above` | `newerFormat`; `upgrade/policy-out-of-range` (below) stays `malformed` |
| `rules/f4-witness-window-absent` | a receipt at 299 s valid, at 301 s `malformed` |
| `rules/f4-witness-window-600` | a receipt at 450 s valid; due = `issued` + 600 + delay |
| `rules/f4-witness-window-change-no-consent` | `badSignature` |
| `rules/f4-witness-window-3601`, `-59` | `newerFormat`, `malformed` |
| `rules/f4-witness-window-at-anchor` | a window change activating after T's anchor does not change T's receipts |
| `records/f4-revoke-257-heads` | `malformed` |
| `succession/f4-chain-65` | genesis `malformed` |
| `rules/i-add-five-approve` | unchanged `malformed` (rule limit) |

**Existing vectors that change:** `records/revoke-17-heads` (history `malformed` at seq 4 →
`newerFormat` at seq 4) and `succession/authority5-chain-17` (genesis `malformed` →
`newerFormat`). Both are regenerated with new descriptions.

### 4.5 Effect elsewhere

Home: the clock rule and admission read W (`history/home.rs`, the relay's late checks). Write side:
`write/authority.rs` and the exchange read W from the state at the anchor; the account creator
writes no `witnessWindow` by default. Exports: the policy JSON gains the optional field. SDKs: a
setting for `witnessWindow` beside `recoveryDelay`, as policy JSON.

### 4.6 Residual risk

`witnessWindow` touches every timing rule; a mismatch between the verifier, the home and the
builders on which state supplies W would split verdicts. The table in §4.2 is the whole rule, and
each row gets a vector. Raising namespaces to 256 lengthens the post-rotation `rekey`; a later
version that allows more than fit one body must split it, which is its own design.

## 5. F5: Namespaces after genesis, and live state beyond one module

> **Deferred to 0.6 (revision 17): not a 0.5 rule.** Revision 15's behaviour stands in 0.5; this
> section is kept as the design to build after the door. Summary: §16.


### Rule

A `rekey` epoch for a valid namespace that is not yet declared **declares it**, when that epoch is
1, under the **control rule** with UV (no recovery-set consent; finding 15), and the account stays within 256 namespaces; epoch 1 is sealed to the
current vault (no member has access yet). From the next entry, grants may name it. Namespaces are
never removed in 0.5. Names beginning `colophon.` are reserved: declaring one is `newerFormat`. A
live candidate whose `(namespace, kind)` has no live rule this reader knows, or whose `v` its rule
does not know, is `newerFormat` for that record, not `invalidPayload`. The **0.5 live-rule registry is normative with exactly one entry**, the podcast `position` rule every
conforming 0.5 reader applies (finding 14); 0.3's kinds table stays a module, not conformance.

### 5.1 Why, and the alternative rejected

The survey's proposal is adopted. The alternative, a new authority kind for namespaces, would stop
every 0.5 device at the first app that brings a namespace. Declaring by `rekey` reuses the rule
that already introduces epochs, which is right because a namespace is nothing but its epochs. The
seq-2 rule stays exact (seq 2 introduces epoch 1 for exactly the genesis namespaces); declaring
starts at seq 3. A `revoke`'s `epochs` cannot declare (only declared namespaces). A declaration
while the vault is retiring is refused, as every `rekey` is.

**Read scopes.** A replica holds only its read scope (0.3 §4, §9.5 "Held means read"); a new
namespace is in no existing scope until a host widens it, so other apps neither fetch nor judge it.

**Names.** A record's `kind` follows the §10.1 kind grammar (writers MUST; a reader refuses nothing
new, so no verdict changes: a kind outside it simply cannot be named by a grant's `kinds`).
App-owned namespaces SHOULD use a reverse-DNS name of a domain the app's maker controls, with `-`
written as `_` (the namespace grammar has no `-`); bare names are kept for the standard library,
and the four existing names are grandfathered. Free-form kinds belong in the app's own namespace.
A record whose kind begins `colophon.` and that this reader does not define is `newerFormat` for
that record (today admitted and skipped): `colophon.` kinds are engine kinds, and a new one can
change what the engine does.

### 5.2 The live-rule registry

Normative, one entry: 0.3 §5.1's `listening.podcasts` `position`, `v` 1, no `seek`, with its slot
derivation. Every conforming 0.5 reader applies it whatever modules it has, so two 0.5 readers never
disagree on a live verdict. Any other `(namespace, kind)` or `v` is `newerFormat` for every 0.5
reader alike; the registry rule refusing a payload (`seek`) is `invalidPayload`. Folds, views and the
kinds table stay modules (no verdict).

### 5.3 Functions that change

`history/state.rs`: `immediate`'s `rekey` arm (declare; the cap), `State.namespaces` becomes the
genesis list plus declarations in seq order (checkpoint); `members::check_granted_terms` reads the
state's list. `protocol.rs`: `live_slot` becomes `live_rule(namespace, kind, v) -> LiveRule
{Slot(String), Refused, Unknown}`; `live.rs::judge_one` and `records.rs` (`:1777`) map `Unknown` to
`newerFormat`. `records.rs`: the `colophon.` kind check after opening. `account/action.rs` and
`write/authority.rs`: `prepare_rekey` accepts a new name at epoch 1 (`Change::declare_namespace`).

### 5.4 Vectors

| Vector | Expected |
| --- | --- |
| `rules/f5-rekey-declares-namespace` | `ok` (control rule); a later grant naming it `ok` |
| `rules/f5-declare-single-approve` | `badSignature` |
| `rules/f5-declare-at-epoch-2` | `malformed` |
| `rules/f5-declare-colophon-namespace` | `newerFormat` |
| `rules/f5-declare-while-retiring` | `malformed` |
| `rules/f5-declare-257th` | `newerFormat` |
| `rules/f5-grant-before-declared` | `malformed` |
| `rules/f5-seq2-declares-extra` | `malformed` (seq 2 is exact) |
| `records/f5-live-unknown-kind` | the candidate `newerFormat` |
| `records/f5-live-unknown-v` | the candidate `newerFormat` |
| `records/f5-live-podcast-position` | current head (the first live vectors) |
| `records/f5-live-podcast-seek` | `invalidPayload` |
| `records/f5-colophon-kind-unknown` | the record `newerFormat` |

**Existing vectors that change:** none (no vector declares a namespace after genesis, and there
are no live vectors yet).

### 5.5 Effect elsewhere

Home: stores live candidates of any kind (it never opened them). Write side: the declaring
`rekey`; the reference engine writes nothing new for live state. Exports: `begin_rekey` gains an
optional list of names to declare (`colophon-ffi/src/v05/api/action.rs`). SDKs: one call to add a
namespace to an account; reading the namespace list from the state, not the genesis.

### 5.6 Residual risk

The control rule can declare up to 256 permanent namespaces; the rate limit bounds the pace. Removal
waits for a later kind (after the door).

## 6. F6: Opaque members, narrow form

> **Deferred to 0.6 (revision 17): not a 0.5 rule.** Revision 15's behaviour stands in 0.5; this
> section is kept as the design to build after the door. Summary: §16.


### Rule

Only a **new top-level term field** (in the requested or granted `terms`) is member-local. A grant
whose only unknown content is such fields applies, and its member is **opaque**: keys, expiry,
shares, session number, revocation and the rate charge apply; its records and live candidates pass
§11.5 steps 1–8 and are `newerFormat`; every call it makes is `newerFormat`, at a home as anywhere.
Everything else unknown in a grant stops the account as today: an unknown `access` value, request
`kind` or `custody`, request field, field of `member`, `service`, a `records` or `services` entry,
`serves` value, `import`, anything in `shares`, and any count above its maximum. Unknown condition
operators stay three-valued per record and call and make no member opaque.

### Why the narrow form

The check (finding 6) showed the wide form bought safety by sealing every epoch to any `records`
member, whatever its unknown access: a future `writeOnly` or `metadataOnly` member would get the keys
from a 0.5 host. In the narrow form every `records` entry and its access are known, so the epochs
sealed to an opaque member are exactly those sealed to a member with the same entries, and **no 0.5
host seals an epoch to a member whose access it does not understand**. The home exception of the
wide form (an opaque member reading and writing at a 0.5 home) is dropped: what a home serves is
among the things a new term field may not change, and the smallest sound form serves an opaque
member nothing through a call.

### The host fence

**Removed as a security rule; stated as interface guidance with no security weight** (finding 7).
The verifier accepts an extension or re-grant of an opaque member by any host, and that is sound: it
gives the member nothing a 0.5 reader acts on, because every act of an opaque member is
`newerFormat` for every 0.5 reader. Making the operation an account-wide `newerFormat` would stop 0.5
devices whenever a newer host renews a newer app's member, the stop F6 exists to avoid.

### The promise later versions keep (§9.8)

1. A new term field decides only what that member itself may do with its own records and calls. It
   never changes what is sealed or to whom, what a home serves, any key, epoch or share, what another
   principal may do or read, which entries are valid, or any entry's rule; such content is a new
   value or a field outside `terms`, which stops 0.5 readers.
2. A later version never makes an entry invalid because of a new term field or its coverage; at most
   it refuses that member's acts.
3. §11.5 steps 1–8 stay frozen.
4. Known grammars inside terms are not relaxed.

### Safety

Accept: an opaque member's records and calls are `newerFormat`, never admitted. Serve: nothing
through a call. Decrypt: sealing depends only on known `records` entries with known access. Two 0.5
readers agree (opacity is a function of the bytes and 0.5's defined term fields). A 0.5 and a later
reader agree on every entry (promise 1–2) and on budgets and clocks (promise 3); they differ only on
the opaque member's own acts, where the 0.5 reader says `newerFormat`.

### Functions

`prescan.rs` (`authority_fields("grant")` splits out top-level unknown term fields), `members.rs`
(`Grant::parse`, `read_granted`, `parse_transition_grant`, `check_granted` on known parts),
`terms.rs` (keep unknown term fields aside), `history/state.rs` (`MemberRecord.opaque`, checkpoint),
`records.rs`, `live.rs`, `calls.rs` (opaque → `newerFormat`), `account/read.rs` (listing).

### Vectors

| Vector | Expected |
| --- | --- |
| `rules/f6-grant-new-term-field` | history `ok`; the member opaque; its record `newerFormat`; another member's record admitted |
| `rules/f6-grant-unknown-access` | history `newerFormat` (account-wide) |
| `rules/f6-grant-unknown-request-kind` | history `newerFormat` |
| `rules/f6-grant-unknown-records-entry-field` | history `newerFormat` |
| `rules/f6-grant-records-65` | history `newerFormat` |
| `rules/f6-grant-unknown-operator` | not opaque; condition true → admitted, unknown → `newerFormat` |
| `rules/f6-new-term-undeclared-namespace` | `malformed` |
| `rules/f6-revoke-opaque` | `ok` |
| `rules/f6-renew-opaque` | `ok` (guidance only) |
| `records/f6-opaque-reserves-budget` | the next record of that member `budgetSpent` |
| `calls/f6-opaque-call` | `newerFormat` |
| `calls/f6-opaque-home-read` | `newerFormat` |

Existing vectors that change: none. Inputs whose verdict changes: a grant whose only unknown content
is a new term field (history `newerFormat` → `ok`, member opaque); one with a new term field and a
malformed known part (`newerFormat` → `malformed`).

### Effect elsewhere and residual risk

Home: none beyond refusing the opaque member's calls. Exports: member JSON `"opaque": true`. SDKs:
show it. Residual: the promise binds code not yet written; domain folds skip `newerFormat` records
(surfaced by count).

## 7. F7: A home's address can change

> **Deferred to 0.6 (revision 17): not a 0.5 rule.** Revision 15's behaviour stands in 0.5; this
> section is kept as the design to build after the door. Summary: §16.


### Rule

A home's appointed `service.endpoints` are its identifiers and the audience of every call to it. A
host sends an authorized request (one with a call) only to an appointed endpoint or to a base named
by a valid **location statement** (`colophon/location/5`, §14): `{protocol, account, by, bases,
issued}`, signed `raw` by the home's member key, verified against that key in the client's verified
state. Monotonic by `issued` (ties: lower body digest); no expiry; replaced by a newer statement,
ended by the home's revocation. Public like a head: every current home stores, forwards and serves
the latest statement of every current home at `records/locations/<home ID>.json`, and a shared folder
holds the same path.

### Why

Finding 8: with only an unsigned `moved` or a redirect, a forged location could relay the client's
valid call (bound to the real home's audience) to the real home and read the response, the whole
history or headers and ciphertext. A statement signed by the home's key proves the new base is the
home's choice before any call is sent there. Finding 9: the path through another home is now defined
(the replicated statement). `homes.update` is still rejected (recovery consent per customer per
hostname change).

### An old device that knows only the dead base

It fetches `records/locations/<home ID>.json` from any other current home or the folder (no call),
verifies it under the home's key from its own verified state, and calls the new base. **With no other
home and no folder, recovery needs another device of the person** (the pairing channel) or the person
typing the base; a 308 at the old base helps only unauthorized fetches.

### Functions and vectors

`v05/location.rs` (parse, verify, monotonic choice; W2-C); `engine/exchange.rs` (send calls only to
verified bases; fetch statements from peers and the folder), `engine/paths.rs` (`Kind::Location`),
`colophon-home-wasm` (store, forward by `PUT {peer}/records/locations/<id>.json`, serve) (W3-H).
Vectors: `heads/f7-location-valid` (`ok`), `heads/f7-location-bad-signature` (`badSignature`),
`heads/f7-location-not-a-home` (`badSignature`), `heads/f7-location-older-ignored` (the later one
kept), `heads/f7-location-unknown-field` (`newerFormat`); exchange tests: no call to an unverified
base; recovery through a peer home and through a folder.

### Residual risk

A home's key still changes only by re-appointment. A compromised home key can point clients anywhere,
as it can already sign any head.

## 7a. F8: A device with nothing gets the authority chain

> **Deferred to 0.6 (revision 17): not a 0.5 rule.** In 0.5 the approving device hands over the
> authority history out of band (spec §13.4), and `refused:notGranted` is only a reserved name.
> Summary: §16.

Found by the test apps: a new device joining an account whose history is `members` can fetch only
the head, so the apps put the whole authority history in the invite (about 10 KB for a new
account, far over one QR code's 2,953 bytes), and joining by camera does not work. Revision 15's
sentence that the history comes "from the approving device over the pairing channel" was written
without knowing this.

### Rule

The approving device makes an **invite link** (§13.4): a link from its member key (a current
principal, not a home) to a session key, whose terms are exactly one or two `services` entries, each a current home's appointed
endpoint with `["colophon.history.read"]`, lasting at most an hour (host default ten minutes). A
home serves the authority chain and its verification pages, and nothing else (not `/pending`), to calls through it, without checking narrowing or
`depth` against the member's own terms. The **invite** (§7.3, `colophon/invite/5`) carries the
account ID, the link, the session key's private scalar and `nA`; J fetches and verifies the history
from seq 1 against the account ID, then answers with its request, which H scans from J's screen.

### Why links as specified cannot do it

0.5 already has the mechanism in shape (a link, a call, `colophon.history.read` at a home), and
the design keeps all of it. Three rules of §12.3 stop it today:

1. **Narrowing** (step 6): a link's `services` entry needs an entry for the same audience in the
   member's own terms. A device member's terms are normally `records` only, so the link is
   `refused:notNarrower`.
2. **Depth** (step 6, §10.1): `depth` is 0 for every non-agent by default (§18), so no link may
   follow at all.
3. **Purpose** (step 7): through links, the home serves `colophon.history.read` only when the
   link's terms grant it, which (1) forbids.

Granting every device a `services` entry for its homes and `depth` 1 would also let it hand out
links for records and writes; the exemption is for exactly one purpose at exactly the homes named.
A controller makes no links, so an approving device that holds only a controller (a passkey, no
member key) cannot invite; every app host holds a member key, so that is a stated limit. The
joining device cannot run the signer's own check (it holds nothing); it sends the call and the
home, which holds the history, decides, as §12.3 already lets a member that does not find itself.

### Who signs, what it grants, how long, what a leak exposes

- **Signs:** the approving device's **member key** (a controller approves; a link is a member's
  instrument, and controllers make no links), which must be a current principal (§8.5) and not a home. A link of the invite shape from a home's member key is not an invite link
  (finding 11). The link's `session` is the member's session number.
- **Grants:** `GET` of the authority chain and what verifying it needs, at the named homes:
  `{base}/authority`, `records/authority/*`, the predecessor chain and its receipts (a successor
  genesis's), and the public heads. **Not** `/pending` or `/pending/<digest>`, transitions, vetoes or
  other receipts (finding 10), no records, live values, blobs or writes.
- **Lifetime:** at most 3,600 s and within `linkMaxAge`; default 10 minutes (§18). Not single use
  (a history is many pages; each call has its own `requestId` in the replay store). Ended early by
  the member's `endSessions` or revocation.
- **Leak:** the bearer reads the authority chain until the link ends: controller labels, key
  IDs and descriptors (relying party, credential IDs, origins), holder labels, members' labels,
  kinds, operators and terms (namespaces, access, audiences, purposes, conditions), namespace names,
  policy, home endpoints and any predecessor chain. Every current member already reads all of it. It
  is not the pending feed (proposed removals and additions, vetoes, their signers), no record, key or
  write. **Configurable:** a *bound invite* (third scan: H shows the account, J shows its
  request, H shows a link bound to the request key with no private scalar) exposes nothing if
  leaked; the default is the one-scan invite.

### Minimum contents and size

`{"account","key","link":{"body","signature"},"nA","protocol":"colophon/invite/5"}`, the link as a
JSON object (not base64 twice). The invite is in §1's list of closed objects (finding 17): an extra
member is `malformed`. One home with a typical endpoint (about 110 bytes): link body about
580 bytes, invite about 1.1 KB. Two homes with the longest allowed endpoints (512 bytes): about
2.4 KB, under the 2,953-byte limit of one QR code at the lowest correction level. The size does not
grow with the number of homes: an account with eight homes names one or two in the invite and J
reads the rest from the verified history. The request back (about 760 characters) already fits.

**An account with no home** (folder only): there is no home to call; the history is in the shared
folder, which the operating system shares and the invite does not name. The invite carries only
`account` and `nA` (about 160 bytes); J reads the folder and verifies against `account`.

### "Not yet a member"

Before approval, a joining device's own check reports `refused:revoked` for its own call, because
§12.3 step 5 calls an absent member revoked. Decided: a member ID that no grant or appointment in the
held history names is `refused:notGranted` (the name §11.5 already uses for records by an unknown
author), and the SDKs word it "waiting for approval". Controllers keep `refused:revoked` for a
pending addition, so `rules/call-by-pending-addition` does not change. No existing vector has an
absent member's call.

### The SDKs and §7.3

Checked in source. The Rust core (`v05/pairing.rs`) and the bindings (`colophon-ffi/src/v05/api/
pairing.rs`, `AccountPairing`) implement §7.3 as written: commitment, `nA` only after it, reveal,
the six-digit code, the QR alternative and the five-failures-an-hour limiter. The session layers use
it only to move the seed (`transferSeed`, `acceptSeedTransfer`). **Member approval does not use it:**
Swift (`AccessRequest.code(for:)`, `SessionTypes.swift:201`), JS (`pairingCode`, `types.ts:136`)
and Kotlin (`SessionTypes.kt:154`) show a code made from the first eight hex characters of the
member ID, with no commitment and no nonce. That is a 32-bit prefix of a key the requester chose: a
relay can grind a substitute key with the same prefix offline, the attack §7.3 exists to stop, so
approval through it does not meet §9.1 ("approval of a request whose key did not pair ... hosts MUST
NOT offer it"). Fix: item P, first in the order of work: the core refuses an approval that does not consume a
confirmed pairing for the request's exact key.

### Functions that change

`calls.rs`: `verify_home_request` and step 6 (`is_invite_link`: exact terms, home audience, one or
two entries, the hour; skip narrowing and depth), step 7 (authority chain paths only), step 5
(`refused:notGranted`). `write/calls.rs`: `prepare_invite_link`. A new `v05/invite.rs`: the invite
object (build, strict parse, size). `engine/exchange.rs`: `join_from_invite` (fetch head and history
through the link, verify from seq 1). Home: none beyond `calls.rs` (the relay already passes calls
to the module). Exports: `AccountEngine.begin_invite` and `join_from_invite`; the session layers'
invite and join flows; the pairing fix above.

### Vectors

| Vector | Expected |
| --- | --- |
| `calls/f8-invite-history-read` | `ok` (a device member with no `services` and `depth` 0) |
| `calls/f8-invite-records-path` | `refused:outOfScope` |
| `calls/f8-invite-write` | `refused:outOfScope` |
| `calls/f8-invite-other-home` | `refused:audience` |
| `calls/f8-invite-three-homes` | `refused:notNarrower` (not an invite link; an ordinary link) |
| `calls/f8-invite-extra-purpose` | `refused:notNarrower` |
| `calls/f8-invite-over-an-hour` | `refused:notNarrower` (not an invite link) |
| `calls/f8-invite-expired` | `refused:expired` |
| `calls/f8-invite-after-end-sessions` | `refused:ended` |
| `calls/f8-invite-by-revoked-member` | `refused:revoked` |
| `calls/f8-not-yet-member` | `refused:notGranted` |
| `calls/f8-invite-pending` | `refused:outOfScope` (`/pending`) |
| `calls/f8-invite-pending-digest` | `refused:outOfScope` |
| `calls/f8-invite-predecessor` | `ok` |
| `calls/f8-invite-by-home` | `refused:notNarrower` (a home's link is not an invite link) |
| `calls/f8-invite-by-expired-member` | `refused:expired` |
| `pairing/invite.json` | canonical bytes of a one-home and a two-home invite, a no-home invite, and strict-parse refusals (extra member, `key` not matching `to`, `link` for another account) |

Existing vectors that change: none.

### Residual risk

A bearer credential travels in a QR code: anyone who photographs it within its lifetime reads what
any member reads. The bound invite removes that at the cost of a third scan. An approving device
with only a controller cannot invite.

## 8. Reservations (text only)

| Reserved | Text | 0.5 behaviour |
| --- | --- | --- |
| `refused:overQuota`, `refused:noEntitlement`, `refused:closed`, `refused:notProvisioned` | spec §14 "Refusals a paid home may give", §19 | A home MAY send them (507, 402, 410, 403). An unknown `refused:` from a home refuses only that request and is shown raw. `refused:closed` is not evidence of deletion. (The retry signal and the closing-home SHOULD of revision 16 are deferred.) |
| purposes `colophon.home.export`, `colophon.home.close` | spec §20 | A 0.5 home refuses them (`refused:outOfScope`, as any other purpose). |
| principals `account`, `organisation` | spec §20 | Refused in 0.5, as any unknown value is today: a call signer `malformed`; a descriptor form or request kind `newerFormat`. |
| kinds and namespaces `colophon.*` | spec §20 | Reserved; 0.5 writers do not use names the spec does not define; met in 0.5, judged as today. |
| `layouts` in `GET {base}` | spec §14 | A 0.5 home answers `"layouts":[2]` (the door's host rule needs it). |
| `refused:notGranted` for a call | spec §20 | Reserved for "not yet a member"; 0.5 answers `refused:revoked` for a member no grant names, and hosts word it as waiting for approval. |

Withdrawn in revision 17 (deferred): the no-home call option, the suite discriminator, `location`,
`colophon/location/5` and `ext/`. Functions: `colophon-home-wasm/src/ops.rs` (`identity`/`limits`
for `layouts`; `peer_answer` treats an unknown `refused:` as refusing that object only). Home test:
an unknown `refused:` is surfaced raw.

## 9. The Low findings, the owed sentence, and stated limits

- **L1, key-ID collision within one transition** (`apply_delta`, `state.rs:1584`):
  `keyring_points` also holds each point's key ID, so a member and a controller with one truncated
  ID in one transition are refused, as §3.3 says. Text: §3.3 adds "including within one entry or
  transition". No vector (it needs a 128-bit collision); a unit test with a substituted key-ID
  function.
- **L2, prepare-time check of a composite change** (`Account::begin_transition`, `action.rs:1075`):
  members are checked against the old state plus the change's own added controllers, so a doomed
  composite asks for no signature. Text: §17.1. Unit test.
- **L3, withdrawn in the revision 17 fix round.** An independent check of the code showed anyone
  can write a readable Swift envelope at seq 0 without a key, so making it fatal would let a hostile
  home or folder fail a valid predecessor, against §2.2. §16.3 states today's behaviour: an envelope
  at seq 0, readable or not, names no place in the chain and is ignored. No code change.
- **The owed sentence** (home package): a successor's home holds the provisioned account's genesis
  and takes predecessor entries only as the hash chain that genesis claims, from its head down, and
  serves none of them before its first upload is verified. Text: §14.
- **Stated limits** (§20 "Limits of 0.5", text only): before an account opts in, a 0.5 device that
  meets something newer may refuse it rather than ask to be updated, and nothing in an account's own
  data requires a move to a new account (§17); the deferred items as today's limits (namespaces fixed
  at genesis, podcast-only live state, fixed caps, the 300 s window, a home's address in its
  request); no compaction (device-local checkpoints, §17.2, and the door, which any pruning must
  follow); `kept`
  bounded by one body (about 15,400 digests) and no continuation; a blob at most 512 MiB (64 KiB
  chunks, 8,192 per manifest; a larger blob is a later manifest kind, which 0.5 folds skip); live
  slot retention is lossy and per replica; the clock jump, the 60 s skew and the 7-day bound are
  constants; a home's key changes only by re-appointment; a namespace is never removed; two
  successors of one predecessor can each verify; an account with no home has no witness of order.

## 10. What a home does, in one place (0.5)

- Authority entries, transitions, vetoes, receipts, heads: verifies, as revision 15; refuses what it
  cannot judge. An account uses newer authority content only after its homes read it; a host checks
  `layouts` before raising the layout (F3).
- At and after a stop: §13.6's table (S).
- The rules of PR 28: predecessor staging and `PUT` by a controller only; the non-primary exemption
  from the 300 s rule; 503 with `Retry-After` when a head is due and cannot be signed; serving
  intervals never under-recorded; bounded, expiring unmatched receipts; settled objects off the cap.
- Reserved refusals: may send them (R).

## 11. Exports and SDKs, in one place (0.5)

`begin_approve` spending a confirmed pairing and `AccountPairing.scan_request` (P); a stopped status
(S); "waiting for approval" wording for a member no grant names.
Swift, Kotlin and JS surface `newerFormat` as `updateRequired`, as today. No other SDK change.

## 12. Where this design differs from a review, and why

(Rows for F1, F4, F5, F6 and F7 record the design of deferred items; see §16.)

| Point | Review | Chosen | Why |
| --- | --- | --- | --- |
| F2 rule | Opus: any current controller or home; Daybreak: today's control rule | Daybreak's, after the independent check | Opus's widens who can stop a device and lets an old reader stop where the new version refuses; one layout opt-in covers a whole later format version |
| F3 door | Opus: a new `/5` entry kind | `layout` | one door under the strongest rule; already parsed, already a stop for 0.3 and Swift readers |
| F6 scope | Opus: every member-local unknown (kind, access, terms) | only new top-level term fields | an unknown access would otherwise get epoch keys from a 0.5 host |
| F6 write fence | Opus: no authority entry while an opaque member exists | interface guidance only, no security weight | an extension of an opaque member gives it nothing a 0.5 reader acts on |
| F6 conditions | Opus: unknown operators make the member opaque | three-valued, not opaque | §10.4 already decides per record and call; opacity would discard decidable records |
| F7 | Daybreak: `homes.update` with consent; Opus: discovery with a fixed audience | identifiers plus a home-signed, monotonic location statement | no recovery consent per hostname change, and no call ever goes to a base the home did not sign for |
| History for a new device | revision 15: over the pairing channel | an invite link to one or two homes | the history does not fit a QR code; links already exist and need only a one-purpose exemption |
| Compaction | Daybreak: fix before freeze, or accept | accept as a stated limit, with room left | a checkpoint trust anchor is a design of its own; `ext/` side objects and the layout door leave room (principle 9) |
| Revocation retention pages | Daybreak: add `retain` pages now | stated limit | a later single-rule kind under F2 adds it without a migration |
| Blob manifest version | Daybreak: version the manifest now if video is planned | stated limit | a later manifest kind is skipped by 0.5 folds; nothing breaks |
| Suite discriminator | Daybreak: add `suite` now, or state the rule | state the rule | a mandatory field changes every vector; F1 makes the objects open, so an added `suite` is a safe stop |
| Refusal names | Opus: `quota`, `lapsed`, `closed`; Daybreak: `overQuota`, `entitlement`, `closed`, `provisioning` | `overQuota`, `noEntitlement`, `closed`, `notProvisioned` | the task's four states, each named as what is wrong |
| Caps | Opus narrower fallback: raise namespaces to 1,024 | general rule; namespaces 256 | 256 is what the builder already allows and what fits one `rekey`; the general rule makes any later raise safe |
| Policy lower bounds | Daybreak lists ranges generally | only upper bounds are `newerFormat` | lower bounds are floors (safety, structure); loosening one is a rule change after the layout door; keeps `upgrade/policy-out-of-range` |
| Per-entry limits (four additions, 56 and 224 headroom) | both list them among caps | rule limits, `malformed` | they bound what one key can do at once; keeps `rules/i-add-five-approve` |
| Witness window | Opus: a constant is fine (an unknown policy field is a safe stop) | `policy.witnessWindow` | principle 3: a person with a slow self-hosted home answers differently |

## 13. Questions that are truly the owner's

None of the items touches keys he holds, data he holds or money, beyond these, each with the
default this design uses so no work waits:

1. **His real library (freeze condition 4).** Nothing in the package changes the Swift path.
   Default: no action.
2. **Names LUFF uses for its own new namespaces.** Default: `works.luff.<app>.<area>`, bare names
   only for the standard library.
3. **A paid home's refusals.** Default: reserve the four codes; no tier names, prices or
   entitlement format are defined.

## 14. Principles this work relied on that are not yet written down

For the owner's principles file (private repository):

- **An extension point is only as safe as the promise it asks of later versions.** F6 works only
  with the promise later versions keep (§6); F1's record-level stop works only with frozen steps 1–8.
  Design the point and the promise together, and write the promise into the format.
- **Never widen who can stop a device.** A new stop is acceptable when the set of principals who
  could already cause one is unchanged; measure each new `newerFormat` against that set.
- **Homes store what they need not understand, and vouch only for what they verify.** Records and
  side objects pass through any home; authority waits for homes that read it.
- **Across versions an older reader may say "update me" where a newer one decides, never decide
  differently.** Every rule here is chosen so the older side errs toward `newerFormat` or held,
  never toward `ok` or a refusal the newer side would not give.

## 15. Changes after the independent check (2026-11-15)

| Finding | Severity | Change |
| --- | --- | --- |
| 1, 3 F2 widens who can stop; old/new split | High | F2 withdrawn as designed: unknown kinds and components stay under the control rule; later kinds signed another way come after the layout door, one opt-in per format version (§2, spec §8.5, §8.7, §20) |
| 2 expired or provisional members' `endSessions` | High | one normative current-principal check (§2, spec §8.5), before unknown content; vectors |
| 4 a stop before a revoke | High | a stopped reader trusts nothing new: every call `unavailable` whatever S (item S, spec §1, §12.3) |
| 5 stopped homes unspecified | High | the normative table of spec §13.6; it receipts vetoes and removal-only transitions anchored before the stop |
| 6 F6 seals keys to unknown access | High | narrow form: only new term fields are member-local (§6, spec §9.8, §10.2) |
| 7 host fence | Medium | removed as a security rule; interface guidance with no security weight, and why (§6) |
| 8 forged location relays calls | High | home-signed, monotonic location statements; calls only to appointed or signed bases (§7, spec §14) |
| 9 no path through another home | Medium | statements replicated by every home and a folder (§7) |
| 10 invite reads `/pending` | High | invite links read the authority chain and its verification pages only (§7a, spec §13.4) |
| 11 who signs an invite | Medium | the approving device's member key, current, not a home, not opaque (§7a) |
| 12 approval by prefix code | High | item P: approval consumes a confirmed pairing token; export and SDK changes; first wave |
| 13 `newerFormat` before invariants | High | invariants with known inputs first (§4.1a, spec §2.4); quorum 9 with 8 homes `malformed` |
| 14 live verdicts differ between 0.5 readers | High | a normative one-entry live registry (§5.2, spec §11.8) |
| 15 namespace exhaustion by one key | Medium | declaring needs the control rule (§5, spec §8.2, §8.4) |
| 16 unknown signer without account authentication | Medium | `malformed` unless `key` is a current principal's point; reserved names refused (spec §12.2) |
| 17 invite closed or open | Medium | in §1's closed list |
| 18 order of work | Low | dispatchable streams with exact files, W0 stubs, waves (§0) |

**What could not be made sound as asked:** a stopped home cannot keep serving under `members`,
because every read there is a call and verifying it is a trust decision (item S); a device that knows
only a dead base, with no other home and no folder, needs another device (§7); appointing a home is
outside the pairing token (§P); an approving device that holds only a controller cannot invite
(§7a).

## 16. Deferred to 0.6

Each item below was designed for revision 16 and withdrawn in revision 17. In 0.5, revision 15's
text and behaviour stand. Each comes in place after an account's layout is raised (F3), under the
rule that a later version changes an account's rules only after the raise (spec §20).

- **F1, one rule for unknown content** (§1). Every place below an authenticated body where unknown
  content is `malformed`, `invalidPayload` or silently ignored becomes `newerFormat`, with the stable
  header fields, frozen admission steps 1–8 and the record-level fold rules. In 0.5 today: unknown
  header fields and a few signed-entry fields are ignored, an unknown `level`, receipt or anchor field,
  slot kind or call signer is `malformed`, an unknown plaintext field is `invalidPayload`. Before the
  door, a later implementation writes none of these into a layout-2 account.
- **F4, limits that can be raised** (§4). Counts and ranges above a 0.5 maximum as `newerFormat`
  under a parse ceiling, invariants first, 256 namespaces, and `policy.witnessWindow`. In 0.5 the
  stated maxima are `malformed` when exceeded and the witness window is a constant 300 s.
- **F5, namespaces after genesis and the live rule** (§5). Declaring a namespace by a control-rule
  `rekey`; a normative live-rule registry with `newerFormat` for other live kinds; `colophon.` kinds
  as `newerFormat`. In 0.5 namespaces are fixed at genesis, and 0.3 §5.1's podcast `position` rule
  and 0.3 §6's kinds table are what 0.5 does (other live candidates `invalidPayload`).
- **F6, opaque members** (§6). A new top-level term field makes only that member opaque, with the
  promise later versions keep (no effect on sealing, serving, other principals or entry validity).
  In 0.5 an unknown term stops the account's history (`newerFormat`).
- **F7, a home's address can change** (§7). Home-signed, monotonic `colophon/location/5` statements,
  replicated by homes and folders; calls only to appointed or signed bases. In 0.5 a home's address is
  the endpoint in its immutable request; changing it means revoking and appointing a new home.
- **F8, invites for a device that holds nothing** (§7a). A member-signed invite link for
  `colophon.history.read` of the authority chain at one or two homes, at most an hour, the closed
  `colophon/invite/5` object fitting one QR code, and `refused:notGranted` for a member no grant
  names. In 0.5 the approving device hands the history over out of band (about 10 KB for a new
  account, more than one QR code), and a member no grant names is `refused:revoked`. This one needs
  no door (§17).
- Also deferred: the no-home call option, the suite discriminator, `ext/` side objects, the refusal
  retry signal (§8).

## 17. Can a later format take over a 0.5 account in place?

The trimmed plan rests on this: with only the door (F3) in 0.5, a later format can take over every
0.5 account in place, by raising that account's layout, and **nothing a 0.5 account writes forces a
succession to a new account.** Checked item by item:

| What a 0.5 account wrote | Why a later format takes it over in place |
| --- | --- |
| The account ID (SHA-256 of genesis) and the 32-character `libraryID` in epoch and blob AADs | Identifiers only; the later version keeps deriving them from the same genesis, as 0.5 already does for upgraded 0.4 accounts. |
| The authority chain (`/5` entries, a `/4` prefix after an upgrade) | Immutable history the later version verifies under 0.5's rules up to the raise and its own after; §8.1's "no other mixture" binds 0.5 readers, which are stopped at the raise. |
| Namespaces fixed at genesis | Declaring more is a new rule after the raise (F5's design); existing namespaces and epochs are untouched. |
| Record paths and `/5` header fields; `/3` headers | Immutable records the later version keeps reading at their paths under 0.5's rules (spec §20 says it must); new header versions or paths come after the raise. |
| Live slot derivation (podcast `position`, slot = SHA-256 of the episode ID) | The later version keeps the rule for existing slots and adds rules after the raise; live values are replaceable, so nothing old is stranded. |
| Blob manifests (64 KiB chunks, at most 512 MiB) | Existing blobs stay readable; larger blobs are a new manifest kind after the raise. |
| A home's address inside its immutable request | The request stays the home's identity and audience; a location rule (F7's design) or a new component after the raise moves it. Until then a hostname change is a revoke and re-appointment, inside the same account. |
| Caps and the 300 s window | Rules, not data: the later version raises them after the raise. |
| Keys, vault, slots, epoch seals (one cryptographic suite) | A new suite adds new slots, seals and controllers by transitions on the same account; old seals stay readable to a reader that keeps the old suite. |
| Revocation `kept` sets, grants, requests | Immutable entries the later version reads as written; a continuation kind comes after the raise. |
| Long histories | Compaction or checkpoints after the raise (when 0.5 readers are already stopped), on the same account. |
| Devices that stay on 0.5 | They stop at the raise and write nothing citing authority after it; the later version admits their `/5` records that cite authority before the raise (spec §20). |
| Homes that stay on 0.5 | They refuse the raise and stop (§13.6); the owner updates or revokes them, inside the same account. |
| Joining by an invite (F8, deferred) | Needs **no** opt-in: it changes only what a home serves to a bearer of a link a current member signed, and what the two devices exchange. Nothing is written into the account (a link is never an authority entry or record), so no 0.5 reader judges anything new. A 0.5 home refuses the link (it fails narrowing today), and the devices fall back to handing the history over out of band; a newer home serves it. The account's data is the same either way. |

**The answer: none.** One dependency, which is why F3 stays: the door works only once the 0.5
verifier reads `layout` and stops above 2. Today's code accepts a `layout` change without reading it,
so without F3 a later format's raise would be silently continued by 0.5 readers, a split between
versions (not a forced move to a new account, but a silent disagreement). With F3 built, no deferred
item needs to come back for this reason. The one honest cost, stated in the limits: before an account
opts in, a 0.5 device that meets something newer may refuse it rather than ask to be updated, which
is why spec §20 also binds later implementations to write only what a 0.5 reader accepts into a
layout-2 account.

## 18. Revision 17 fix round (2026-11-16)

The independent check of revision 17 (3 High, 2 Medium, 3 Low) confirmed the in-place-upgrade claim
(§17). Changes: a layout raise stops a reader or home only once final, with the companion rule for
later implementations (spec §1, §8.2, §8.7, §13.6, §20); §2.3 describes, case by case, what the 0.5
verifier does with unknown content, and §20 states the unfortunate cases as limits; the quorum-2
forwarding rule is written from PR 28's fix: a home forwards its entries after a peer's latest head
by `POST {peer}/authority`, and appends due recording entries before any head (spec §13.1, §13.3,
changes row 211); the
candidate README's "Required for freeze" gains the revision 17 cases; genesis namespaces at most 64
for writers too; the scan path names the canonical request envelope; §20's preservation sentence is
"including, without limitation"; L3 is withdrawn (seq 0 ignored, as today) and W1-C with it. The
vectors that change verdict when the code lands are still only `upgrade/then-v5-layout`.
