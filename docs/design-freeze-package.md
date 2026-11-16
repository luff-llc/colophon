# Colophon 0.5: the freeze package (design)

Status: design for review, 2026-11-15. Nothing here is built. The spec text is revision 16 of
[`spec/colophon-0.5.md`](../spec/colophon-0.5.md), mapped in
[`spec/colophon-0.5-changes.md`](../spec/colophon-0.5-changes.md) §A.12, rows 159 to 190, each
marked "code follows in the freeze package". Base: `spec-0.5` at `9027b98`.

**The one idea.** When a 0.5 implementation meets something it does not understand, the result is
"update me" (`newerFormat`), never "this is broken" (`malformed`, `badSignature`,
`invalidPayload`), and never silent acceptance of something that could change a verdict. Each
item below is that idea applied to one place, in its smallest sound form.

**Sources.** The consolidated list of 2026-11-15, the Opus and Daybreak freeze reviews of
revision 15, the domains survey (`docs/roadmap-domains-as-plugins.md` on `docs-0.6-domains`),
the three Low findings of the E12 check, and the owed sentence from the home package. Every
place this design chooses differently from a review is in §12.

## 0. Summary

| Item | Existing vectors that change verdict | Size | Risk |
| --- | --- | --- | --- |
| F1 Unknown content, one rule | `rules/t-grant-component-extra-field` (`malformed` → `newerFormat`) | M | Medium: 27 closed parses and eight places that ignore unknown content today |
| F2 Unknown kinds and components signed another way | none | S | Medium: who can stop a device (§2.4) |
| F3 The upgrade door (`layout`) | `upgrade/then-v5-layout` (0.5: `ok` → `malformed`, regenerated as two cases) | S | Low |
| F4 Limits that can be raised; `policy.witnessWindow` | `records/revoke-17-heads`, `succession/authority5-chain-17` (`malformed` → `newerFormat`) | M | Medium: the window threads through every timing rule |
| F5 Namespaces after genesis; live state beyond one module | none | S–M | Low |
| F6 One member's unknown term stops only that member | none | L | High: needs the frozen contract of §6.3 |
| F7 A home's address can change | none | S | Low |
| F8 A device with nothing gets the history (invites); "not yet a member" | none | S–M | Medium: a bearer credential in a QR code |
| R Reservations | none | S | Low |
| L Three Low findings, the owed home sentence, stated limits | none (a Swift predecessor with a readable seq-0 envelope goes `ok` → `malformed`; no vector has one) | S | Low |

Four existing vectors change, each listed with its item. Every other change of verdict is on an
input no vector holds today; those are listed per item under "Inputs whose verdict changes".

### Order of work and what runs in parallel

The verifier changes fall into three disjoint file sets. Each stream adds its vectors in its own
generator file (`crates/colophon-core/tests/v5_candidate/cases_freeze_<stream>.rs`) so the
generator never conflicts.

| Wave | Stream | Items | Files | Depends on |
| --- | --- | --- | --- | --- |
| 1 | **A. Authority** | F1 (authority sites), F3, F2, F4, F5 (namespaces), F6 (grant side), L1 | `history/state.rs`, `history/keyring.rs`, `history/succession.rs`, `history/home.rs` (receipt site), `slots.rs`, `members.rs`, `terms.rs`, `prescan.rs`, `descriptor.rs`, `heads.rs` | — |
| 1 | **B. Records and live** | F1 (header, stamp, plaintext), F5 (live, `colophon.` kinds), the fold rules of F1 and F6 | `records.rs`, `live.rs`, `protocol.rs` | the field `MemberRecord.opaque` (name fixed here; A adds it, B reads it, defaulting to `false` until A lands) |
| 1 | **E. Small** | L3 (Swift seq 0), L2 (prepare-time check) | `history/swift.rs`, `account/action.rs` | — |
| 2 | **C. Calls** | F1 (signer), F6 (calls), F8 (invite links, `notGranted`), R (no-home rule, reserved principals) | `calls.rs`, `write/calls.rs` | A (opaque flag, policy) |
| 2 | **D. Home and exchange** | F1 (home storage), F4 (window at the home), F7, R (refusals, `layouts`, `ext/`) | `colophon-home-wasm/src/ops.rs`, `engine/paths.rs`, `engine/exchange.rs`, `history/home.rs` (clock and admission), `relay/home.js` | A (window), B (stable header parse) |
| 3 | **F. Write side, exports, SDKs** | builders, write fence, surfacing, F8 invites and §7.3 pairing in the session layers | `write/*.rs`, `account/*.rs`, `colophon-ffi/src/v05/api/*`, Swift, Kotlin, JS | A, B, C |

Inside stream A the order is fixed because every item touches `history/state.rs`: F1 first (it
changes how unknown content is collected), then F3 (one state field), F2 (the signer rule of
unknown kinds), F4 (caps and the window), F5, F6 last. At most three builders at once: A, B and E
in wave 1; C and D in wave 2; F alone.

The checkpoint format (`engine/checkpoint.rs`, §17.2) gains three fields (the layout, the declared
namespaces in order, and per member `opaque`); it bumps once, in stream A, and B and C read the
fields through `State` accessors.

## 1. F1: Unknown content, one rule

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
| 22 | call `signer` variant (`Call::parse`, `calls.rs:630`) | `malformed` | `newerFormat`; `account` and `organisation` reserved (R) | §12.3 steps 1–3 (possession, audience, window, replay look-up); reserves nothing | answers 403 `newerFormat` |
| 23 | `layout` value (`apply_delta`, `state.rs:1562`) | never read | F3 | — | F3 |
| 24 | a count above its 0.5 maximum | `malformed` | F4 | — | F4 |
| 25 | unknown `(namespace, kind)` or `v` of a live candidate (`live::judge_one`, `records.rs:1777`) | `invalidPayload` | F5 | — | stores it |
| 26 | member-local unknowns in a grant | the whole history stops | F6 | — | stores the member's records |
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
   counts its clock (step 8), whatever its unknown content; for step 1 an unknown `level` or
   `access` value needs only a `records` entry for the namespace. A later version that refuses
   such a header for a level or access 0.5 does not know refuses it after step 8, as `outOfScope`
   already is. So budgets and clock bounds are the same for every reader.
2. **`duplicateID`.** A header that sorts after a `newerFormat` header with the same author and ID
   (§11.4 order) is itself `newerFormat`: 0.5 cannot tell whether the first one authenticates.
3. **Proposals.** A proposal whose first valid resolution in fold order comes after a
   `newerFormat` record of the same namespace by an author whose `records` entry there has `write`
   or an access value 0.5 does not know is `newerFormat` (unresolved for this reader), never
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
| `calls/f1-signer-unknown-variant` | `newerFormat` |
| `calls/f1-signer-unknown-variant-bad-signature` | `badSignature` |
| `calls/f1-signer-unknown-variant-wrong-audience` | `refused:audience` |

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

## 2. F2: Unknown entry kinds and transition components signed another way

### Rule

An authority entry of an unknown kind is `newerFormat` once every attached signature verifies
and `by` and every cosigner are **current principals**: a controller that is not only `sign`, not
suspended and not added by a provisional activation; or a member (a home included) that is not
revoked, not expired and not provisional. Otherwise it is `badSignature`, as today. A transition
with an unknown component is `newerFormat` at the entry that records or embeds it (`activate`,
`vetoed`, `suspend`) once its signatures verify, every signer is a current controller that is not
only `sign`, escalation and receipts hold, and its known components meet a rule they allow; a
transition whose known components meet no rule is `badSignature`. An unsigned entry of an unknown
kind is `badSignature`.

### 2.1 Why, and the alternative rejected

Daybreak holds that today's rule (unknown kinds under the control rule) is enough, because a later
version can raise the layout first. Opus proposes `newerFormat` for any current non-`sign`
controller or home. Settled for Opus's direction, widened to members, for three reasons:

1. **It does not widen who can stop a device.** Today every current non-`sign` controller can
   sign some entry whose unknown fields are `newerFormat` (approve keys a `grant`; control and
   recover keys a `rekey`, whose unknown fields F1 stops ignoring), and every current member,
   homes included, can sign its own `endSessions`, whose unknown fields are `newerFormat` today.
   F2 changes the forms a stop can take, not the set of principals who can cause one (§2.4).
2. **Today's rule turns the foreseeable kinds into forgeries.** Member key rotation, a home
   rotating its key or resigning, an agent-signed delegated grant (Galley's mandate), a revocation
   continuation and recovery-only actions are all signed by someone other than the control rule.
   Under today's rule a 0.5 device calls them `badSignature`: a broken account.
3. **Layout-first is a ceremony per kind.** Raising the layout needs the control rule and the
   recovery set's consent (§8.4), so every new kind would need the owner's recovery keys. That is
   the approval machine the owner rejected; F2 makes the stop happen only where the kind is used.

Members are included, against Opus, because they can already stop a device through `endSessions`,
and because the two kinds Galley most needs (member key rotation, an agent's delegated grant) are
member-signed.

### 2.2 Functions that change

`history/state.rs`: `immediate` (the `other =>` arm moves before the controller lookup: a
`signer_principal` helper resolves `by` and each cosigner among controllers and members, checks
currency, and verifies each item as an authority signature with UV only when the controller has
`verification`); `apply` (an unknown unsigned kind: `badSignature`); `classify` and
`check_transition` (an unknown component sets `rule_unknown`; `recovery_ok` no longer false for
it); `activate`, `vetoed`, `suspend` (report `newerFormat` when the embedded transition has
`rule_unknown`, after the checks that do not need its rule, before the determined `issued`, which
needs the full-set decision).

### 2.3 Vectors

| Vector | Expected |
| --- | --- |
| `rules/f2-unknown-kind-single-approve` | `newerFormat` (today `badSignature`) |
| `rules/f2-unknown-kind-recover-only` | `newerFormat` |
| `rules/f2-unknown-kind-by-home` | `newerFormat` |
| `rules/f2-unknown-kind-by-member` | `newerFormat` |
| `rules/f2-unknown-kind-home-and-controller` | `newerFormat` |
| `rules/f2-unknown-kind-by-sign-controller` | `badSignature` |
| `rules/f2-unknown-kind-by-revoked-member`, `-expired-member`, `-suspended`, `-provisional` | `badSignature` |
| `rules/f2-unknown-kind-unsigned` | `badSignature` |
| `rules/f2-unknown-kind-bad-cosignature` | `badSignature` |
| `rules/f2-unknown-component-recovery-rule` | `newerFormat` at the `activate` |
| `rules/f2-unknown-component-known-part-fails` | `badSignature` |
| `rules/f2-vetoed-unknown-transition` | `newerFormat` at the `vetoed` |
| `rules/f2-stop-applies-nothing-after` | history `newerFormat` at seq n; a record citing n `authorityBehind`; a call `unavailable` |

**Existing vectors that change:** none (no vector holds an unknown kind by a non-control signer).
**Inputs whose verdict changes:** unknown kinds and components by such signers, `badSignature` →
`newerFormat`.

### 2.4 Who can make a 0.5 device stop, and why that is acceptable

After F1 and F2: any current non-`sign` controller, and any current member (homes included), by an
entry carrying content 0.5 does not know; and the control rule by any transition. That is the same
set of principals as today (point 1 of §2.1). For the stop to reach a device the entry must also be
in the history the device fetches, which means one of:

- **a home that stores it.** A 0.5 home refuses every `newerFormat` entry (422), so a 0.5 home
  never lets one in. A newer home stores only what its own rules accept, so junk under every
  version is refused there too. What gets in is real newer content, and "update me" is the right
  answer.
- **a hostile primary home.** A hostile primary can already refuse every immediate entry, a
  denial of service as large; the remedy (revoking it) is unchanged.
- **no home.** Without a home there is no witness of order: any member can already fork the
  history at will (two `endSessions` at one seq give `refused:fork`). No new power.

A stopped device never applies anything after the stop (§1 "A stop", revision 16): its verified
history ends before the entry, records citing it or later are held `authorityBehind`, calls whose
S needs it are `unavailable`, and the host builds nothing for the account until it is updated.

### 2.5 Effect elsewhere

Home: none (it already refuses `newerFormat`). Write side: none. Exports and SDKs: none beyond the
stop reason they already surface.

### 2.6 Residual risk

A junk kind signed by a current principal, admitted by a hostile primary home or written into an
account with no home, stops 0.5 devices, and every later version that does not define that kind
stops too. The same is true today of an unknown term in a grant. The defence is the default of
two homes (§18).

## 3. F3: The upgrade door

### Rule

The transition component `layout` is an integer. A `/5` account is at layout 2 from genesis and an
upgraded account at layout 2 from its `upgrade`; the verifier stores it. A `layout` component that
does not raise it (2 or less) voids the transition (`malformed` at its `activate`). One that raises
it above 2 is `newerFormat` once its transition passes every other check (control rule and the
recovery set's consent, §8.4), and the reader applies nothing at or after that entry. Later
versions opt an account in through this component and no other.

### 3.1 Why, and the alternative rejected

One door, not two. The alternative is a new entry kind under F2. `layout` is chosen because it
already exists in the transition grammar, already needs the strongest consent (control rule plus
recovery set), already means "stop" to 0.3 and Swift readers (Swift's freezing entry is a `layout`
above 2), and the verifier already recognizes it; the fix is to read its value. A new kind would
also work after F2, but it could be signed by any current principal; an opt-in that retires rules
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
| `rules/f3-layout-3` | `newerFormat` at the `activate` |
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
| `rules/f4-headquorum-9` | `newerFormat` at the `activate` |
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

### Rule

A `rekey` epoch for a valid namespace that is not yet declared **declares it**, when that epoch is
1, under the `rekey` rule, and the account stays within 256 namespaces; epoch 1 is sealed to the
current vault (no member has access yet). From the next entry, grants may name it. Namespaces are
never removed in 0.5. Names beginning `colophon.` are reserved: declaring one is `newerFormat`. A
live candidate whose `(namespace, kind)` has no live rule this reader knows, or whose `v` its rule
does not know, is `newerFormat` for that record, not `invalidPayload`. 0.3's kinds table and the
podcast live rule become the reference implementation's built-in modules, not conformance.

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

### 5.2 Built-in modules

§11.8's table keeps 0.3 §6's generic rules (modules, views, tools, unknown kinds skipped) and marks
its namespace table and 0.3 §5.1's podcast specifics as the reference implementation's built-in
modules. A module that defines a live rule names `(namespace, kind, v)` and derives the slot; a
conforming implementation without that module answers `newerFormat` for those live candidates. A
known rule that refuses (a podcast `position` with `seek: true`) is still `invalidPayload`.

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
| `rules/f5-rekey-declares-namespace` | `ok`; a later grant naming it `ok` |
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

A single `approve`, `control` or `recover` key can declare namespaces (as it can introduce
epochs), up to 256 for the account's life with no removal. The rate limit bounds the pace; a
person is told in the ledger. Removal waits for a later kind.

## 6. F6: One member's unknown term stops only that member

### Rule

Unknown content in a grant is **member-local** when it is in the request's `kind`, `custody` or
top-level fields (not `member`, not `service`), or in the requested or granted `terms` (an unknown
term field, `access` value, field in a `records` or `services` entry, or a count above its cap),
except `serves`, `import` and each `records` entry's `namespace`. A grant whose only unknown content
is member-local applies, and its member is **opaque**: keys, expiry, shares, session number,
revocation and the rate charge apply as for any member; its records, live candidates and calls are
`newerFormat` (after the frozen steps of §1.3); unknown kinds it signs follow F2. Unknown condition
operators make no member opaque: they stay three-valued per record and call (§10.4). Everything
else unknown in a grant stops the account, as today.

### 6.1 What stays account-wide, and why

| Part | Why it is account-wide |
| --- | --- |
| `request.member` (keys), `request.account`, `protocol` | §3.3 key uniqueness is decided for the whole account; an unknown key field could be a key 0.5 cannot register |
| `request.service`, `terms.serves` | a home receipts, signs heads and counts toward quorum: everyone's verdicts |
| `terms.import` | an import grant is a transition with its own rule (§9.3) |
| `records[].namespace` | decides sealing (§7.1) and the namespaces a `revoke` must re-key (§9.5) |
| `shares`, epoch objects and seals | what is sealed to whom |
| the grant entry's own fields, and any `renew` field | entry structure |

### 6.2 Opaque members in practice

- **Records and live:** steps 1–8 with the frozen reading of §1.3 (it reserves and counts), then
  `newerFormat`. Never admitted, never folded, never resolves a proposal.
- **Calls:** `newerFormat` after step 5 (the member is found and current). One exception, at a
  0.5 home: `colophon.home.read` with its own key and no links, and `colophon.home.write` of its own
  records in namespaces whose `records` entry has a known access that covers the write, are judged
  by those known parts, exactly as for a member whose grant holds the same known parts. Without
  this, a 0.5 home would block every newer app's member.
- **Sealing:** §10.2 is frozen: every `records` entry, whatever its access, receives its
  namespace's epochs. So a 0.5 host seals new epochs to an opaque member exactly as to any member
  with the same namespaces, and a `revoke` of it re-keys its namespaces.
- **Hosts (write fence):** a 0.5 host shows the member as "access needs an update to show", MAY
  revoke it, end its sessions, renew its shares (shares-only form), and MUST NOT extend its expiry,
  re-grant it or build any entry whose effect it cannot show the person.

### 6.3 The frozen contract (what later versions must keep)

F6 is safe only together with these rules, which §10.1 and §20 now state as binding on every later
version:

1. Terms are member-local: they decide only what the member itself may do (its records, calls and
   links). A later version MUST NOT define a term that changes what any other principal may do or
   read, which entries are valid, the rule of any entry, or what is sealed; such content goes
   outside `terms`, where it stops 0.5 for the account.
2. A later version MUST NOT make an entry invalid because of member-local content, nor because its
   coverage (§9.2) cannot be decided from 0.5's known parts: at most it refuses that member's acts.
3. A member's new powers over authority come as new kinds (F2), never as permission to sign a 0.5
   kind.
4. §11.5 steps 1–8 are frozen as §1.3 says.
5. Known grammars inside terms (kinds, purposes, audiences, paths) are not relaxed; a later version
   adds fields instead.

### 6.4 The safety argument

**No 0.5 device accepts, serves or decrypts more for an opaque member than for one it understands.**
Accept: its records and calls are `newerFormat`, never admitted; its own `endSessions` only ends
its own links; its unknown kinds stop the device (F2), which any member can already do. Serve: a 0.5
home serves it exactly what it serves a member with the same known parts, and nothing through
links. Decrypt: sealing depends only on `records[].namespace` (frozen §10.2), the same for any
member with those namespaces; a 0.5 host never admits an opaque member itself (it cannot build its
terms).

**Two 0.5 devices cannot disagree.** Opacity is a pure function of the grant's bytes and 0.5's
fixed known sets; no domain module, read scope or arrival order enters it.

**A 0.5 device and a later one agree on the history.** By contract rules 1–3, every entry's
validity and rule are decided by 0.5's known parts in every version, so the two hold the same
entries. They differ only on the opaque member's own acts, where the 0.5 device says
`newerFormat`. By rule 4 they agree on budgets and clock bounds. By §1.3 rules 2 and 3 a
`newerFormat` record never lets the 0.5 device admit a duplicate or settle a proposal the later
one would not.

What could not be made safe without the contract: if a later version invalidated a grant entry
for a term (instead of refusing the member), a 0.5 device would accept the entries after it while
the later device stopped at it. The contract forbids that; a later version that breaks it splits
accounts. **The narrower form, if the contract is not wanted:** make only unknown **term fields**
member-local (not access values, request kinds or caps), which keeps every known field's meaning
and still lets each app add terms; everything else stays an account-wide stop.

### 6.5 Why, and the alternatives rejected

Opus proposed this; Daybreak did not address it. Rejected: accepting today's behaviour and telling
Galley that every new term is a forced upgrade of every app on the account (principle 4 and 5:
Taupe and Later would stop for a Galley term). Rejected: Opus's write fence of "no authority entry
at all while an opaque member exists", which would also forbid revoking the opaque member from an
old device, the one action that must always work; §6.2's fence is narrower.

### 6.6 Functions that change

`prescan.rs`: `authority_fields("grant")` returns `(account_wide, member_local)`; `terms` and a new
`request_scan` classify. `members.rs`: `Request::parse` and `read_granted` return both sets;
`check_granted` checks coverage on known parts only (`Terms::covered_by_known`); `Grant::parse`.
`history/state.rs`: `MemberRecord.opaque: bool` (checkpoint), set in the `grant` arm,
`transition_members` and `member_record`. `records.rs`: `judge_candidate` (opaque → `newerFormat`
after step 8), `live.rs::judge_one`. `calls.rs`: `evaluate` and the member arm (opaque →
`newerFormat`; the home exception via `home_record_writes`, `home_purposes`). `account/read.rs`:
member listing shows `opaque`. `account/action.rs`: the fence in `begin_renew` (with expiry) and
grant builders.

### 6.7 Vectors

| Vector | Expected |
| --- | --- |
| `rules/f6-grant-unknown-term` | history `ok`; the member opaque; its record `newerFormat`; another member's record admitted |
| `rules/f6-grant-unknown-access` | as above |
| `rules/f6-grant-unknown-request-kind` | as above |
| `rules/f6-grant-unknown-request-field` | as above |
| `rules/f6-grant-records-65` | as above |
| `rules/f6-grant-unknown-operator` | not opaque; a record whose condition is true admitted, unknown `newerFormat` |
| `rules/f6-grant-unknown-member-field` | history `newerFormat` |
| `rules/f6-grant-unknown-serves` | history `newerFormat` |
| `rules/f6-grant-unknown-share-field` | history `newerFormat` |
| `rules/f6-unknown-term-undeclared-namespace` | `malformed` |
| `rules/f6-known-malformed-and-unknown-term` | `malformed` (was `newerFormat`; no vector) |
| `rules/f6-revoke-opaque` | `ok`; a `revoke` omitting its namespace `malformed` |
| `rules/f6-renew-shares-opaque` | `ok` |
| `rules/f6-opaque-unknown-kind` | `newerFormat` |
| `calls/f6-opaque-call` | `newerFormat` |
| `calls/f6-opaque-home-read` | `ok` |
| `calls/f6-opaque-home-write-unknown-access` | `refused:outOfScope` |
| `records/f6-opaque-reserves-budget` | as `f1-newer-reserves-budget` |

**Existing vectors that change:** none.
**Inputs whose verdict changes:** a grant with only member-local unknown content, history
`newerFormat` → `ok` with an opaque member; with member-local unknown content and a malformed known
part, `newerFormat` → `malformed`.

### 6.8 Effect elsewhere

Home: the call exception of §6.2 in `calls::verify_home_request`. Write side: the fence. Exports:
member JSON gains `"opaque": true`. SDKs: show the member as needing an update; no new call.

### 6.9 Residual risk

High, and the reason this item needs its own check: the safety rests on the contract of §6.3,
which binds code not yet written. Domain folds can show stale values (§1.7). A 0.5 home lets an
opaque member store records under its own author ID that no 0.5 reader admits (bounded by the
home's quota).

## 7. F7: A home's address can change

### Rule

A home's appointed `service.endpoints` are **identifiers**, fixed for that home member: the
audience of a call to the home is one of them, wherever the home is reached. Where a home is reached
is discovery: a host may reach it at any `https://` URL whose `GET {base}` names that home member,
and every object fetched there is verified as usual (heads and receipts under the home's key,
entries under §8). `homes.update` is not added.

### 7.1 Why, and the alternative rejected

Daybreak proposed `homes.update`, a transition replacing endpoints with consent as for appointing a
home. Rejected: a transition needs the control rule and, because it changes homes, the recovery
set's consent (§8.4), so a hosted provider changing its hostname would need every customer's
recovery key, which is the approval machine the owner rejected and puts the operator in the middle
of the person's keys (principle 1). The "receipt from the new endpoint" it asks for is not
checkable: a receipt is signed by the home's key wherever it is sent from. Opus's form is adopted:
the code already takes a home's call audiences from its appointed endpoints
(`calls::CallConfig::home_endpoints`), and §9.1 already calls them discovery data, so this is a
statement, not a change.

### 7.2 The audience after a move, an old device, a hostile change

- **Audience:** unchanged, the appointed string. The home's deployment configuration (§10.1)
  keeps accepting it at its new location.
- **An old device that knows only the dead address** finds the new one from: an HTTP 308 redirect
  at the old base, which an operator SHOULD keep for as long as it expects devices to be offline
  (the reference: a year); `GET {base}`'s optional `moved` member there (R); another current home,
  which it can reach because the default is two homes; another device of the person (pairing); or
  the person typing it. A device with none of these waits; nothing it holds is wrong.
- **A hostile location** (a hijacked DNS name, a forged redirect, a hint): it cannot sign heads or
  receipts as the home, so it can withhold (`unavailable`) and see call metadata, exactly as a DNS
  hijack of the home's hostname can today. It cannot change a verdict. A call sent there is bound
  to its request (§14) and to the home's audience, so relaying it to the real home only does what
  the signer asked.

### 7.3 Functions that change

None in the verifier. `engine/exchange.rs`: a local, verified location per home (learned from a
308, `moved`, a peer or the person) used for requests, the appointed endpoint used as audience.
Home: `relay/home.js` serves `moved` when configured.

### 7.4 Vectors

None (the audience rule is today's). Relay tests: a home reached at a second URL accepts calls
whose audience is its appointed endpoint; a host follows a 308 and verifies the member.

### 7.5 Residual risk

Rotating a home's key is still a re-appointment (revoke and appoint, uploading again); a later
home-signed kind can add it under F2. A device offline for longer than the redirect is kept, with
no other home or device, needs the person.

## 7a. F8: A device with nothing gets the history

Found by the test apps: a new device joining an account whose history is `members` can fetch only
the head, so the apps put the whole authority history in the invite (about 10 KB for a new
account, far over one QR code's 2,953 bytes), and joining by camera does not work. Revision 15's
sentence that the history comes "from the approving device over the pairing channel" was written
without knowing this.

### Rule

The approving device makes an **invite link** (§13.4): a link from a current member to a session
key, whose terms are exactly one or two `services` entries, each a current home's appointed
endpoint with `["colophon.history.read"]`, lasting at most an hour (host default ten minutes). A
home serves the history paths, and nothing else, to calls through it, without checking narrowing or
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

- **Signs:** any current member, with its own key (it can already read the history and forward
  it). The link's `session` is the member's session number.
- **Grants:** `GET` of the history paths at the named homes. No records, live values, blobs,
  pending writes or writes.
- **Lifetime:** at most 3,600 s and within `linkMaxAge`; default 10 minutes (§18). Not single use
  (a history is many pages; each call has its own `requestId` in the replay store). Ended early by
  the member's `endSessions` or revocation.
- **Leak:** the bearer reads the authority history until the link ends: controller labels, key
  IDs and descriptors (relying party, credential IDs, origins), holder labels, members' labels,
  kinds, operators and terms (namespaces, access, audiences, purposes, conditions), namespace names,
  policy and home endpoints. Every current member already reads all of it; no record, key or write
  is exposed. **Configurable:** a *bound invite* (third scan: H shows the account, J shows its
  request, H shows a link bound to the request key with no private scalar) exposes nothing if
  leaked; the default is the one-scan invite.

### Minimum contents and size

`{"account","key","link":{"body","signature"},"nA","protocol":"colophon/invite/5"}`, the link as a
JSON object (not base64 twice). One home with a typical endpoint (about 110 bytes): link body about
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
NOT offer it"). Fix (stream F): approve a request only after the §7.3 code ceremony with
`E = member.signing` through `AccountPairing`, or after scanning the request from the requester's
screen; drop the ID-prefix code.

### Functions that change

`calls.rs`: `verify_home_request` and step 6 (`is_invite_link`: exact terms, home audience, one or
two entries, the hour; skip narrowing and depth), step 7 (history paths only), step 5
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
| `pairing/invite.json` | canonical bytes of a one-home and a two-home invite, a no-home invite, and strict-parse refusals (extra member, `key` not matching `to`, `link` for another account) |

Existing vectors that change: none.

### Residual risk

A bearer credential travels in a QR code: anyone who photographs it within its lifetime reads what
any member reads. The bound invite removes that at the cost of a third scan. An approving device
with only a controller cannot invite.

## 8. Reservations (names and unknown-handling only)

| Reserved | Text | 0.5 behaviour |
| --- | --- | --- |
| `refused:overQuota`, `refused:noEntitlement`, `refused:closed`, `refused:notProvisioned` | §14 "Answers", §19 | A home MAY send them (507, 402, 410, 403). An unknown `refused:` from a home refuses only that request and is shown raw. **Retry signal:** `Retry-After` means retry after it; `"permanent": true` in the answer means do not retry that request; neither means retry with backoff. Forwarding counts an answer with `"permanent": true` as delivered. `refused:closed` is not evidence of deletion. A closing home SHOULD keep signing heads until its revocation is final. |
| purposes `colophon.home.export`, `colophon.home.close` | §12.2 | A 0.5 home refuses them (`refused:outOfScope`, as any other purpose). |
| principals `account`, `organisation` | §12.2 (call `signer`), §3.1 (descriptor `form`), §9.1 (request `kind`) | Confer nothing. Met in a call signer: `newerFormat` (F1 row 22); as a descriptor form: `newerFormat`, reported last (§1); as a request kind: the member is opaque (F6). |
| calls with no fresh head | §12.3 "No home" | A verifier configured for it (default off) MAY, for its own audience only and never at a home, take S from its persisted verified history fetched within `headMaxAge` from a source the account names or the person configured, when the latest held state has no current home. It never changes an authority verdict. Vectors test the default. |
| the suite | §20 "Suites" | One suite in 0.5. A later suite adds a `suite` member to the objects it changes (seals, slots and parts, `previousVault`, the vault); absent means suite 1; descriptors keep `form`. An unknown `suite` is `newerFormat` by F1. |
| `layouts`, `moved` in `GET {base}` | §14 | A 0.5 home answers `"layouts":[2]`; `moved` optional (F7). |
| `ext/<principal ID>/…` store paths | §14 "Store layout" | A home stores immutable files there written by `colophon.home.write` of that principal with its own key (a current member, or a controller with `approve` or `control`), up to 16 MiB each, serves them under `colophon.home.read`; readers ignore them. Room for side objects (checkpoints, manifests) without a home upgrade. |
| kinds and namespaces `colophon.*` | §11.8 | F5. |

Functions: `colophon-home-wasm/src/ops.rs` (`peer_answer`, `access`, `identity`/`limits`),
`engine/paths.rs` (`Kind::Ext`), `engine/exchange.rs` (retry signal), `calls.rs` (`CallConfig`
gains `no_home_leniency: bool`). Vectors: `calls/r-signer-organisation` (`newerFormat`),
`calls/r-no-home-default` (`unavailable`). Home tests for the refusal codes, the retry signal and
`ext/`.

## 9. The Low findings, the owed sentence, and stated limits

- **L1, key-ID collision within one transition** (`apply_delta`, `state.rs:1584`):
  `keyring_points` also holds each point's key ID, so a member and a controller with one truncated
  ID in one transition are refused, as §3.3 says. Text: §3.3 adds "including within one entry or
  transition". No vector (it needs a 128-bit collision); a unit test with a substituted key-ID
  function.
- **L2, prepare-time check of a composite change** (`Account::begin_transition`, `action.rs:1075`):
  members are checked against the old state plus the change's own added controllers, so a doomed
  composite asks for no signature. Text: §17.1. Unit test.
- **L3, a readable Swift envelope at seq 0** (`history/swift.rs::read_envelope`, `:359`): a
  readable `seq` of 0 makes the predecessor `malformed`. Text: §16.3. Vector
  `succession/swift-seq-zero` (`malformed`).
- **The owed sentence** (home package): a successor's home holds the provisioned account's genesis
  and takes predecessor entries only as the hash chain that genesis claims, from its head down, and
  serves none of them before its first upload is verified. Text: §14.
- **Stated limits** (§20 "Limits of 0.5", text only): no compaction, with what leaves room for it
  (signed side objects under `ext/`, never read by 0.5 readers; device-local checkpoints, §17.2; and
  the layout door, which any pruning must follow because 0.5 readers expect every record); `kept`
  bounded by one body (about 15,400 digests) and no continuation; a blob at most 512 MiB (64 KiB
  chunks, 8,192 per manifest; a larger blob is a later manifest kind, which 0.5 folds skip); live
  slot retention is lossy and per replica; the clock jump, the 60 s skew and the 7-day bound are
  constants; a home's key changes only by re-appointment; a namespace is never removed; two
  successors of one predecessor can each verify; an account with no home has no witness of order.

## 10. What a home does, in one place

- Records, live values, history files: stores any header whose stable fields parse, whose path
  matches and whose envelope verifies under a current member's key, whatever else it holds (F1).
- `ext/` files: stores them (R).
- Authority entries, transitions, vetoes, receipts, heads: verifies, and refuses `newerFormat` with
  422. A home vouches with heads, so it must understand authority; an account uses newer authority
  content only after its homes read it, and a host checks `layouts` before raising the layout (F3).
- Calls by opaque members: §6.2's exception.
- The witness window: from the state §4.2 names.
- Unknown request members: 422 `newerFormat`; unknown response members: ignored by clients.

## 11. Exports and SDKs, in one place

No new export beyond: `begin_rekey` with names to declare (F5); policy JSON with `witnessWindow`
(F4); member JSON with `opaque` (F6); view JSON with a per-namespace `newer` count (F1). Swift,
Kotlin and JS: surface `newerFormat` (they already map it to `updateRequired`), the count, opaque
members, and one "add a namespace" call. No SDK type changes shape.

## 12. Where this design differs from a review, and why

| Point | Review | Chosen | Why |
| --- | --- | --- | --- |
| F2 rule | Daybreak: today's control rule is enough | any current principal | today's rule makes foreseeable kinds forgeries; layout-first is a recovery-key ceremony per kind; the set of principals who can stop a device is unchanged (§2.1) |
| F2 signers | Opus: controllers (not `sign`) and homes only | also members | members can already stop a device through `endSessions`; member key rotation and an agent's delegated grant are member-signed |
| F3 door | Opus: a new `/5` entry kind | `layout` | one door under the strongest rule; already parsed, already a stop for 0.3 and Swift readers |
| F6 write fence | Opus: no authority entry while an opaque member exists | a narrow fence | revoking the opaque member from an old device must always work |
| F6 conditions | Opus: unknown operators make the member opaque | three-valued, not opaque | §10.4 already decides per record and call; opacity would discard decidable records |
| F7 | Daybreak: `homes.update` with consent | identifiers plus discovery | consent per customer per hostname change; the endpoint receipt is not checkable; the code already uses appointed endpoints as audiences |
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

1. **His real library (freeze condition 4).** The only change on the Swift path is L3 (a readable
   seq-0 envelope is refused); shipped Swift never writes one. Default: no action; the dry run
   would show it.
2. **Names LUFF uses for its own new namespaces.** Default: `works.luff.<app>.<area>`, bare names
   only for the standard library.
3. **A paid home's refusals.** Default: reserve the four codes; no tier names, prices or
   entitlement format are defined.

## 14. Principles this work relied on that are not yet written down

For the owner's principles file (private repository):

- **An extension point is only as safe as the promise it asks of later versions.** F6 works only
  with the frozen contract of §6.3; F1's record-level stop works only with frozen steps 1–8.
  Design the point and the promise together, and write the promise into the format.
- **Never widen who can stop a device.** A new stop is acceptable when the set of principals who
  could already cause one is unchanged; measure each new `newerFormat` against that set.
- **Homes store what they need not understand, and vouch only for what they verify.** Records and
  side objects pass through any home; authority waits for homes that read it.
- **Across versions an older reader may say "update me" where a newer one decides, never decide
  differently.** Every rule here is chosen so the older side errs toward `newerFormat` or held,
  never toward `ok` or a refusal the newer side would not give.
