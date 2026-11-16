# Colophon 0.5 vectors

**Status: the 0.5 vectors, frozen with [spec/colophon-0.5.md](../../spec/colophon-0.5.md) on
2026-11-16.** They were built at `conformance/0.5/candidate/` and moved here at the freeze with
their bytes unchanged. The Rust history verifier replays them
(`crates/colophon-core/tests/v05_candidate.rs`); no Swift implementation has, and no implementation
in a second language has. Every `expected` outcome is the spec author's reading of the text. The
bytes are real: `/5` bodies are canonical JSON, and every signature verifies under ordinary ES256
(raw, or WebAuthn over `authenticatorData ‖ SHA-256(clientData)` with the challenge checked), except
where a case says a signature is invalid on purpose. Spec §21 says which vectors must exist; the
index under "Required for freeze" says which vector or test covers each item.

**Paths inside the vectors.** Some cases name files by path (`verifier.history`, `verifier.heads`,
`verifier.replay`), and those paths still begin `conformance/0.5/candidate/`, because the bytes are
frozen. Read such a path with that prefix replaced by `conformance/0.5/`. Key names derive under the
label `colophon-0.5-candidate/` (`keys.json`); that label is part of the bytes and stays.

`legacy-draft-1/` is not part of the 0.5 vectors: see its README.

All keys are public test secrets (`keys.json`, `succession/keys.json`, `../0.4/keys/keys.json`).
Never use them for real data.

## Regenerate and check

One Rust generator, `crates/colophon-core/tests/v5_candidate.rs` (helpers in
`crates/colophon-core/tests/v5_candidate/`), builds every generated file here. It is opt-in
(both tests are `#[ignore]`) and uses only the core's own dependencies (`p256`, `aes-gcm`, `hkdf`,
`sha2`, `serde`, `serde_json`, `base64`). It does not call the 0.5 verifier: canonical JSON, signing and
entry building are written out again in the test, so the vectors stay independent of the code they
test.

```sh
# compare the files here with what the generator builds
cargo test -p colophon-core --test v5_candidate -- --ignored v5_generator_check
# rewrite them
COLOPHON_WRITE_V5_VECTORS=1 cargo test -p colophon-core --test v5_candidate -- --ignored v5_generator_write
```

Signatures are deterministic (RFC 6979 over SHA-256), so regeneration is byte-identical. The
generator also re-encodes all 267 published 0.4 authority bodies without duplicate names and
checks that its canonical encoder reproduces them byte for byte, and checks that every envelope's
body is canonical JSON and every honest call and link signature verifies. It replaces the Python
generator (`generate.py`, `rules.py`, `rules_v8.py`, which needed `cryptography`), which produced
the same 1,078 files.

## Contents

| Path | Spec | What |
| --- | --- | --- |
| `identifiers.json`, `upgrade/*` | §5.1, §16.1 | Identifiers; the 0.4 in-place upgrade |
| `account/`, `calls/*`, `heads/*` | §9, §12, §13 | Identity account (its home appointed by a transition and its determined `activate`), calls and heads. `calls/one-link` carries the member's condition (`ok`); `copied-link` then reaches the acting-key check |
| `rules/t-*` | §8.3, §8.6, §8.7 | Due time and deadline; held; the 7-day bound; identical and differing bytes; once only; evaluation before `activate`; vetoes (target, too few, sharing a unit, approve-only, after the deadline, 22 signers); ordering (a primary-covered entry before due keeps its seq; a backdated uncovered one doesn't; a `final` is never displaced); **finality as a recorded fact** (`final` with every witness, missing a witness, a non-witness head, out of order; a provisional addition signs nothing, a final one does; a full set finalizes earlier activations; finality survives a home rotation; a revoked witness and the veto that still stands); escalation; full sets with receipts and due from the receipt; consent and composites; `keep`; a recovery-rule home appointment refused below `threshold`; vault: removal of a slotted key without a vault change (retiring), by one recovery key, rotation by a `vault` entry, a `vault` entry when not retiring or without its own slot, a self-slot, `rekey` by a recover key; suspension |
| `rules/i-*` | §8.4, §13.1 | Immediate entries; the rate limit (verifier), planted keys, revocations outside the account limit, and the dormant-account burst a home refuses |
| `rules/call-*` | §12.3, §13.4 | Pending addition, provisional addition, after `final`, pending removal, suspended, suspended history read, a suspension expired by the clock, recover-only history read. Each carries `verifier.statuses` |
| `rules/veto-webauthn-*` | §4.3, §8.7 | A veto signature with and without UV, and from a call origin |
| `rules/row-*` | changes §H | Event sequences: rows 2, 3, 4, 8, 9, 10, 11, 12 (and a gone home revoked by one recovery key), 13 (the honest home serves the transition; the owner's veto stands), 17 |
| `rules/t-excusal-final-not-displaced-by-vetoed`, `t-cascade-final-not-displaced-by-vetoed`, `t-full-set-final-not-displaced-by-vetoed`, `t-vetoed-displaces-activation-and-later-revocation`, `t-order-guard-keeps-later-addition-provisional` | §8.6, §8.7 | Revision 12 (M1, H1, M-a): an activation that is final by excusal, by the cascade or by a full set is never displaced by a `vetoed`; a `vetoed` that displaces a provisional one takes the later revocations with it; Order keeps a later addition provisional behind an earlier one when a non-removal-only revocation does not excuse its home |
| `rules/t-rekey-slotted-drops-slot`, `i-rekey-slotted-as-immediate` | §8.3, §8.4 | Revision 12 engine correction: re-keying the slotted controller drops its slot and retires the vault; the same change as an immediate entry is `malformed` |
| `rules/t-conflict-no-evidence`, `t-quorum2-veto-beats-removal`, `row-13-quorum1-hidden-transition`, `t-removal-unblocks-addition`, `t-revoke-home-*`, `t-planted-key-dropped`, `t-vault-by-approve-only`, `t-recovery-*` | §8.3, §8.4, §8.6, §8.7 | Revision 8: one per High of the second review of revision 7 |
| `encoding/number-ties.json` | §2.1 | Doubles with two equally near shortest decimals: the even last digit is canonical |
| `calls/link-unknown-operator-*` | §10.4, §12.3 | `any:[true, unknown]` is `ok`; `any:[false, unknown]` is `newerFormat` |
| `rules/origin-*`, `rules/replay-*`, `rules/removal-after-heads`, `rules/rollback`, `rules/malleated-envelope`, `rules/non-canonical-*`, `rules/invalid-expires-date` | §2, §4.3, §12, §13 | Unchanged from revision 3, rebuilt on the new account |
| `rules/equivocation`, `rules/equivocation-displaced` | §8.6, §13.3 | Heads evidence judged against held history: each ships the account's history and the ordinary grant held beside the seq 3 activation (`branch-ordinary/`). An earlier head over the activation that stands and a later one over the grant that lost to it convict; an earlier head over the grant and a later one over the activation that displaced it (§8.6 rule 1) do not. Rebuilt after revision 12 (the first form's second head covered no held entry) |
| `records/*` | §7.1, §9.2, §9.4, §9.5, §10.1, §11, §16.1 | Namespace vectors (36 cases). Each ships its authority history (`records/authority`), the held headers (`ops/`), `holders` (members whose public test agreement scalar opens the seals addressed to them) and `expected` outcomes per header. `shares-and-epochs` (rekey and grant shares, the epoch current at the cited seq, grant start, access levels, a future claim); `header-aad`, `missing-key`; `author-chain`; `revoke-kept-heads`, `revoke-walk-refused-header`, `revoke-missing-intermediate`, `revoke-missing-head`, `revoke-fork-heads`, `revoke-fork-one-head`, `revoke-16-heads`, `revoke-17-heads` (malformed at the entry); `renew-shares`; `renew-shares-only` (a `renew` with no `expires` and shares only: the expiry stays as it is), `renew-shares-only-empty`, `-has-epoch`, `-revoked` and `-expired` (malformed: §9.4); `same-id-two-bodies` (the lowest body digest wins one operation ID, in any order), `one-body-two-envelopes` (a high-S twin is the same object), `revoke-while-retiring` (empty `epochs`, no epoch introduced), `rekey-while-retiring` and `revoke-epochs-while-retiring` (malformed: §8.3); `proposal-*` (accept, decline, resolution clock equal and lower, two resolutions, a resolver that may not write the kind, a missing proposal); `upgraded-fence`, `upgraded-revoked-after`, `upgraded-revoked-before` (the `/3` records of an in-place upgraded account) |
| `pairing/pairing.json` | §7.3 | Commitment and code |
| `rules/t-resolve-fork`, `t-resolve-two`, `t-resolve-below-rule`, `t-resolve-three-candidates`, `t-resolve-no-losing-branch`, `t-resolve-second-fork` | §8.4, §8.6, §8.7 | Revision 13 (`resolve` keeps one entry): a fork resolved by a `resolve` activation on one branch (that branch stands); a `resolve` on each branch keeping its own entry (the fork stands); a `resolve` signed by a recover-only key (no control rule: the fork stands); three candidates settled by one `resolve`; the resolved branch and the owner's next entry with no trace of the loser; a second fork later on the same branch settled the same way |
| `rules/t-resolve-late-fork-witnessed`, `t-resolve-homeless-late-fork` | §8.6, §13.1, §18 | Revision 13 fix round: with homes, a late fork by a former controller and its `resolve` do not discard a branch whose later activation homes witnessed (`refused:fork`); **the stated limit**: with no home the same late fork wins for a new verifier (`ok`), because nothing in the objects tells the histories apart |
| `rules/t-vetoed-choice-right`, `t-vetoed-late-receipt-skipped`, `t-vetoed-other-valid-receipt-accepted` | §8.7 | Revision 13: the lowest home's timely receipt is what a recorder chooses; a lower home's receipt after the veto deadline is skipped and does not block the entry; an entry carrying another valid receipt is accepted (a verifier judges what an entry carries) |
| `rules/t-final-head-choice-right`, `t-final-head-other-valid-head-accepted`, `t-final-head-ahead-ignored` | §8.7, §13.3 | Revision 13: of two heads one home signed over the activation a recorder carries the lower body digest; an entry carrying the other valid head is accepted; a head dated after the `final`'s `issued` is not usable |
| `rules/t-slot-wrong-length-genesis`, `i-slot-add-valid`, `i-slot-add-wrong-length` | §7.2, §8.5 | Revision 13: a sealed slot box of 47 bytes is `malformed` at replay in a genesis and in a `keyring` entry; the same entry with a 48-byte box is `ok` |
| `rules/rollback` | §13.3 | Now run (revision 13): `verifier.history` names the account's records; the head over seq 2 is `refused:rollback` against the home's mark at seq 3, and accepted without it |
| `succession/swift-*` | §13.5, §15.1, §16.3 | Receipt 60 s into the succession window (verified), 400 s (late, unverified); F before the due time; veto recorded as `successionVetoed`; a key removed before the last removal and before the delay can't veto, the last-removed key can, and so can a key removed within the delay before the genesis; a hand-over with an extra key needs two vetoers; root library signed by the root alone, and vetoed by the kit; WebAuthn and recover-set swaps; a premature thief freeze followed by the owner's verified layout-4 freeze; an entry after a verified F |
| `succession/authority5-chain` | §15.1 | A to B to C, each a `/5` successor: C verifies B through B's own predecessor |
| `succession/authority5-successor-*` | §8.4, §8.7, §15.1 | Revision 12 (M2, H2, M-b, M-c): a predecessor with homes. F provisional (not verified; the genesis lacking possession proofs is held); F made final by a `final` (verified, the same genesis `ok`); F displaced by a `vetoed` (not verified, the predecessor continues; without proofs the genesis is `badSignature`, with proofs it is valid); a dead witness home revoked after F, which excuses it (verified); a `final` of an earlier removal-only activation refused after F |
| `succession/swift-migration`, `swift-migration-counts`, `swift-migration-final-digest`, `-drain-before-f`, `-before-drain-ends`, `-premature-f` | §15.4 | The `migration` of a Swift succession: recorded, or its activation is `malformed`: counts that do not add up; `final.digest` that is not F's; a drain window starting before F's `issued`; a transition issued before `drain.until`; F issued before the succession is due (the succession is not verified) |
| `succession/authority5-chain-16`, `authority5-chain-17` | §2.4, §15.1 | Revision 12 (H3): a real chain of 16 predecessor accounts verifies, one of 17 is `malformed` |
| `succession/swift-no-handover-needs-possession`, `swift-handover-below-rule-needs-possession` | §8.4, §15.1 | Revision 12 (M4): a genesis listing the predecessor's kit with no `handover`, or one below the rule that may write F: the kit's possession is required, `badSignature` at seq 1 |
| `probes/swift-der/` | §16.3 | CryptoKit probe |

## What was run

- `v5_generator_check` (the Rust generator), at the freeze (2026-11-16): 2,165 generated files
  match, byte for byte. The directory holds 2,168 files outside `legacy-draft-1/` (64 files, not
  0.5 vectors): those plus three sources (`README.md` and the probe's `Package.swift` and
  `main.swift`). The Python generator it replaced matched 1,078 of an earlier set.
- The fifth reviewer's signature checker (`sigcheck5.py`): 2,203 signatures, including heads in
  `final` entries and objects embedded in recording entries and `suspend`; 7 failures, all
  intended (two invalid call signatures, two origin cases, two veto cases, one `signers` mismatch).
- **`v05_candidate` (the 0.5 history verifier), at the freeze:** 422 in scope, 422 pass, 0 fail, 0 not
  implemented. No other implementation has replayed the vectors (spec §21 condition 2).
- **0.4 engine** on `upgrade/*`: `newerFormat` everywhere except `foreign-signer` (`badSignature`).
- **Swift verifier** (Marginalia `c8280332`, unmodified): every full predecessor stops at its first
  freeze with `unsupportedStorageLayout(3)`.
- **CryptoKit DER probe** (macOS 27.0.1, 200 random keys): minimal DER and high-S accepted, every
  other form tested refused, including `r` or `s` of zero. iOS and visionOS have not been run as of 0.5.0 (spec §21 condition
  3).
- New-vault slots and `previousVault` seals are structurally valid synthetic bytes, not openable.
- No valid transition approaches the 622,592-byte envelope bound, so the quorum-8 size
  composition (§2.4) is checked by arithmetic, not by a vector.

## Required for freeze

Normative for spec §21 condition 1.

- **Keys, encoding and upgrade:**
  - every 0.4 key case as `/5`;
  - authority origins for entries, transitions and vetoes;
  - controller calls from call and authority origins;
  - non-canonical JSON and base64; malleated envelopes; invalid dates;
  - the 0.4 upgrade with every refusal.
- **Immediate entries:**
  - each §8.4 row accepted, and the same change refused as immediate;
  - tightening another key's authentication refused;
  - `layout` and `migration` as immediate refused;
  - two epochs for one namespace in a `rekey` refused;
  - the rate limit at every verifier, keys planted by an addition charged to their adder, revocations
    outside the account limit; at most four controllers per addition; headroom at 56 controllers
    and 224 slots.
- **Transitions:**
  - composite removal with a vault change and `previousVault`, slot rebasing at activation, and
    the `rekey` that follows; composite rules mixing components;
  - `keep`, including keys added after the anchor;
  - evaluation before `activate`: an anchor before the first home, an anchor at a lower past
    delay, a receipt by a revoked home (`malformed`), an anchor off the branch;
  - due time as `issued` + 300 s + delay; the veto deadline; receipt choice;
  - `signers` not matching the envelope;
  - determined recording entries from two homes, and two that differ only in receipts;
  - once only: a duplicate `vetoed`, a re-appended `activate`; the 7-day bound;
  - an `activate` that doesn't displace covered entries;
  - veto validity: count, disjoint units, eligibility, UV, origin, quorum, the deadline;
  - escalation at receipt and before activation, its reset, distinct transitions;
  - the full set (a) and (b), with removed keys counted and no receipts;
  - suspension: carried objects, its end, a void transition, one per unit, history reads,
    calls and immediate entries;
  - delta void cases;
  - mutual removal and the tie;
  - finality: the home set before, full sets, a `vetoed` after finality as evidence; rollback of a
    provisional activation and what it removes;
  - every row of changes §H.
- **Conflicts:** evidence; a fork with and without homes; `resolve`; a transition anchored on a
  losing branch.
- **Members and records:**
  - request coverage; pairing; `serves` and import;
  - renew; revoke with `kept` and up to 16 `heads`; `endSessions`;
  - `/5` headers; proposals.
- **Calls:** every §12.3 refusal; replay states (replay, conflict, abandoned); quorum; S.
- **Heads:** valid, stale, non-home, fork, rollback, equivocation.
- **Succession:**
  - `/5` and Swift (root and keyring, WebAuthn, `rotateRecovery`);
  - the genesis receipt window from the appointing entry;
  - the veto window: in time, too few, by a key no longer current, by a key current within the
    delay before the genesis, recorded as `successionVetoed`;
  - a premature freeze followed by a verified attempt;
  - an entry after the final one; two attempts.
- **Seed transfer:** the HPKE label, wrong nonces.
- **Finality:** `final` entries, revoked witnesses, a full set finalizing earlier activations, rule-1 conflicts with and without a primary head.
- **Vault:** retiring, rotation, self-slots, `rekey` by a recover key.
- **Exchange:** the pending listing (§14) and its cursors, against a simulated home.
- **Revision 17** (the freeze package, cut; generators `cases_freeze_*.rs`, home and interface tests
  where no vector can hold the case):
  - the layout door (§8.2, §20): a raise to layout 3 (`newerFormat`, the reader stopped once final);
    a `layout` component that does not raise (void, `malformed`); a raise without the recovery set's
    consent (`badSignature`); an entry after a final raise (not applied); a provisional raise that a
    `vetoed` displaces (nothing stops; the history goes on); a provisional raise not yet final (the
    reader goes on, applying nothing of the later layout); in an account with no home, a raise final
    at once;
  - a stopped reader (§1): its calls `unavailable` with fresh heads before the stop; no head
    accepted; no new record admitted;
  - the stopped home (§13.6): one home test per row of the table (keeps and serves, forwards,
    receipts a veto and a removal-only transition anchored at or before N, and each "must not"),
    and a 0.5 home witnessing a provisional raise and recording its `vetoed`;
  - the current principal (§8.5): an expired member's `endSessions` and a provisional member's
    `endSessions` are `badSignature`, with or without an unknown field; a current member's with an
    unknown field is `newerFormat`;
  - the confirmed pairing (§9.1, interface tests): an approval without a token, with a token spent
    once already, with a token for another account, and with a token for another key are refused;
    the code path and the scan path (the canonical request envelope) each issue one;
  - the two-home tests pass (`crates/colophon-home-wasm/tests/v05_relay_h2.rs` and
    `v05_relay_home.rs`, every run). Convergence between several homes in general is not a 0.5
    requirement: 0.5 supports one home per account, and exchange between homes is experimental
    (spec §13.1; open issues in `docs/multi-home-open-issues.md`);
  - Swift (§16.3): an envelope at seq 0, readable or not, is ignored and a valid predecessor stays
    valid;
  - dropping a home that is gone (§8.7 validity 2, "Revoking a home"; changes rows 224–226): full
    set (b), and full set (a) by two recovery units, drop a silent sole home with no receipt, final
    at once, leaving no home (`rules/f2-drop-home-full-set-b`, `-full-set-a`), also when a signer of
    full set (a) holds `control` too (`-full-set-a-dual-role`; not without every recovery key,
    `-dual-role-not-full`, nor for a component the recovery rule may not make,
    `rules/f2-dual-role-full-a-component-not-recovery`), then appoint a new
    one (`-then-appoint`); one control and one recovery unit do the same (`-one-control-one-recovery`);
    with two homes only the remaining home's receipt is needed and it alone witnesses
    (`rules/f2-drop-one-of-two-homes`), and the revoked home's receipt alone is `malformed`
    (`-revoked-receipt-only`); the sole home's receipt given anyway is still `ok`
    (`-full-set-with-receipt`); without the receipt the control rule, the recovery rule (not a full
    set) and one unit stay `malformed` (`-control-rule-no-receipt`, `-recovery-rule-no-receipt`,
    `-one-unit`); a full set with no home remaining issued more than 7 days before the entry it
    follows is `malformed`, within that `ok` (`-full-set-backdated`, `-full-set-within-bound`);
    the revoked home stores the activation without its own receipt and a remaining home receipts
    as usual (`crates/colophon-core/tests/v05_home.rs`); a device whose only home never answers
    records the full set, then appoints and uses a new home
    (`crates/colophon-core/tests/v05_engine_home.rs`).

## Index: what covers each required item

Recorded at the freeze, 2026-11-16, in the order of the list above. A path is a vector directory
under `conformance/0.5/` (replayed by `crates/colophon-core/tests/v05_candidate.rs`,
`candidate_conformance`); a test is `file: test name`, with files under `crates/` and core tests in
`crates/colophon-core/tests/` unless a path says otherwise. **None found** marks a required item
for which no vector or test was found at the freeze; it is not covered.

| Item | Covered by |
| --- | --- |
| Every 0.4 key case as `/5` | **None found.** `identifiers.json` covers only the identifiers of the 0.4 geneses, and `upgrade/*` the in-place upgrade; no 0.4 key case is restated as `/5` |
| Authority origins for entries, transitions and vetoes | `rules/origin-*`, `rules/veto-webauthn-*`; `v05_attack_sig.rs: webauthn_origin_matrix` |
| Controller calls from call and authority origins | `rules/veto-webauthn-call-origin`; `v05_engine.rs: controller_calls_origins_roles_and_statuses` |
| Non-canonical JSON and base64; malleated envelopes; invalid dates | `rules/non-canonical-json`, `rules/non-canonical-base64`, `rules/malleated-envelope`, `rules/invalid-expires-date`; `v05_attack_json_diff.rs`, `v05_attack_misc.rs: base64_differential`, `dates_differential` |
| The 0.4 upgrade with every refusal | `upgrade/*`; `v05_write_upgrade.rs: prepare_refuses_what_the_upgrade_vectors_refuse` |
| Each §8.4 row accepted, and the same change refused as immediate | `rules/i-*` (`i-add-approve`, `i-relabel-other`, `i-tighten-policy`, `i-loosen-policy`, `i-raise-rate`, `i-removal-as-immediate`, `i-rekey-slotted-as-immediate`, `i-slot-add-*`); `v05_write_authority.rs: immediate_entries_each_verify`, `entries_the_signers_cannot_make_are_refused_at_prepare` |
| Tightening another key's authentication refused | **None found** |
| `layout` and `migration` as immediate refused | **None found.** `rules/f3-layout-*` and `rules/t-migration-without-predecessor` are transitions; `upgrade/then-v4-entry` is a `/4` entry |
| Two epochs for one namespace in a `rekey` refused | **None found** |
| The rate limit at every verifier; planted keys; revocations outside the account limit; four controllers per addition | `rules/i-rate-limit`, `rules/i-rate-planted-keys`, `rules/i-rate-revoke-outside-account-limit`, `rules/i-rate-dormant-burst`, `rules/i-add-five-approve` |
| Headroom at 56 controllers and 224 slots | **None found** (the limits are checked in `crates/colophon-core/src/v05/history/state.rs`, with no vector or test) |
| Composite removal with a vault change and `previousVault`; the `rekey` that follows; composite rules mixing components | `rules/t-vault-change-previous`, `rules/t-vault-change-previous-short`, `rules/t-composite-mixed-rules`; `v05_account.rs: removing_a_slotted_controller_rotates_the_vault_at_once_and_a_rekey_follows` |
| Slot rebasing at activation | **None found** |
| `keep`, including keys added after the anchor | `rules/t-keep-removes-unknown-key`, `rules/t-keep-needs-recovery-rule`; `v05_account.rs: review_explicit_keep_keeps_only_what_it_names` |
| Evaluation before `activate`: anchor before the first home; receipt by a revoked home; anchor off the branch | `rules/t-anchor-before-first-home`, `rules/t-receipt-by-revoked-home`, `rules/t-anchor-off-branch`, `rules/t-issued-before-anchor` |
| Evaluation before `activate`: an anchor at a lower past delay | **None found** |
| Due time; the veto deadline; receipt choice | `rules/t-remove-after-delay`, `rules/t-activate-early`, `rules/t-late-veto`, `rules/t-vetoed-after-deadline`, `rules/t-vetoed-choice-right`, `rules/t-vetoed-late-receipt-skipped`; `v05_write_authority.rs: receipts_are_chosen_by_lowest_home_then_lowest_digest` |
| `signers` not matching the envelope | `rules/t-signers-mismatch` |
| Determined recording entries from two homes; two that differ only in receipts | `rules/t-activate-identical-bytes`, `rules/t-activate-differing-receipts` |
| Once only; the 7-day bound | `rules/t-vetoed-duplicate`, `rules/t-activate-reappended`, `rules/t-activate-expired` |
| An `activate` that doesn't displace covered entries | `rules/t-activate-after-covered-entry`, `rules/t-activate-after-covered-entry-invalid-final` |
| Veto validity | count `rules/t-veto-too-few`; units `rules/t-veto-shares-a-unit`; eligibility `rules/t-veto-by-approve-only`, `rules/t-vetoed-by-target`; UV `rules/veto-webauthn-no-uv`; origin `rules/veto-webauthn-call-origin`; quorum `rules/t-quorum2-veto-beats-removal`; deadline `rules/t-vetoed-after-deadline`; `rules/t-veto-22-signers` |
| Escalation, its reset, distinct transitions | `rules/t-escalation-alone`, `rules/t-escalation-two`, `rules/row-28-*` |
| The full set (a) and (b) | `rules/t-full-set-b`, `rules/t-full-set-b-missing-recover`, `rules/t-full-set-needs-every-control-key`, `rules/t-full-set-due-from-receipt`, `rules/row-4-thief-has-phone`, `rules/row-9-both-recovery-keys-no-device` |
| Suspension | `rules/t-suspend`, `rules/t-suspend-by-non-signer`, `rules/t-suspend-second-by-unit`, `rules/t-suspend-void-transition`, `rules/t-suspended-immediate-entry`, `rules/t-suspension-ends-*`, `rules/call-by-suspended`, `rules/call-suspended-history-read`, `rules/call-suspension-expired` |
| Delta void cases | `rules/t-noop-void`, `rules/t-add-present-different-roles`, `rules/t-add-home-key-as-controller`, `rules/t-policy-unknown-field`, `rules/f3-raise-with-void-component` |
| Mutual removal and the tie | **None found** |
| Finality: home set, full sets, a `vetoed` after finality, rollback of a provisional activation | `rules/t-full-set-finalizes-earlier`, `rules/t-vetoed-after-final`, `rules/t-vetoed-displaces-activation-and-later-revocation`, `rules/t-final-*`, `rules/t-provisional-addition-signs` |
| Every row of changes §H | rows 2, 3, 4, 8, 9, 10, 11, 12, 13, 17, 28: `rules/row-*`. **None found** for rows 1, 5, 6, 7, 14, 15, 16 and 18 to 27: no vector is named for them, and whether other cases cover them was not mapped |
| Conflicts | evidence `rules/t-conflict-no-evidence`, `rules/equivocation*`; forks `rules/t-resolve-late-fork-witnessed`, `rules/t-resolve-homeless-late-fork`; `resolve` `rules/t-resolve-*`, `rules/t-three-candidate-*`; losing branch `rules/f3-raise-on-discarded-branch`; `v05_write_authority.rs: entries_evidence_*`, `heads_evidence_*` |
| Request coverage; pairing; `serves` and import | `v05_write_calls.rs: the_agent_request_reproduces_and_refusals_return_nothing`; `v05_engine.rs: grants_requests_and_principals`; `pairing/pairing.json`; `rules/t-grant-import-*`, `rules/i-add-home-key-as-controller`, `rules/t-appoint-item-*` |
| Renew; revoke with `kept` and up to 16 `heads`; `endSessions` | `records/renew-shares*`, `records/revoke-*` (`revoke-16-heads`, `revoke-17-heads`), `calls/ended-session`, `rules/f2-end-sessions-*` |
| `/5` headers; proposals | `records/header-aad`, `records/author-chain`, `records/missing-key`, `records/same-id-two-bodies`, `records/one-body-two-envelopes`, `records/proposal-*` |
| Calls: every §12.3 refusal; replay states; quorum; S | `calls/*`, `rules/replay-identical`, `rules/replay-conflict`, `rules/call-*`, `rules/removal-after-heads`; `v05_engine.rs: replay_store_crash_recovery_after_ok` (abandoned), `member_calls_links_and_reservations`; `rules/f2-head-expired-not-quorum`; `calls/s-*` |
| Heads | `heads/valid`, `heads/stale`, `heads/not-a-home`, `heads/fork`, `rules/rollback`, `rules/equivocation`, `rules/equivocation-displaced`; `v05_head_marks.rs` |
| Succession: `/5` and Swift | `succession/authority5-*`, `succession/swift-keyring`, `succession/swift-root-library*`, `succession/swift-webauthn*`; `v05_revision_12.rs` (`rotateRecovery` steward thresholds) |
| The genesis receipt window | `succession/swift-keyring`, `succession/swift-late-genesis-receipt`; `v05_home_h2_succession.rs: a_genesis_receipt_by_a_window_home_counts_after_that_home_is_revoked` |
| The veto window | `succession/swift-veto-by-*`, `succession/swift-handover-extra-key-raises-veto`, `succession/swift-succession-vetoed`, `succession/swift-root-library-kit-vetoes` |
| A premature freeze followed by a verified attempt | `succession/swift-premature-freeze-then-owner` |
| An entry after the final one; two attempts | `succession/swift-entry-after-final`; `v05_write_succession.rs: a_competing_successor_is_refused_when_the_head_follows_a_freezing_entry` |
| Seed transfer: the HPKE label, wrong nonces | `v05_vault.rs: the_seed_moves_to_a_new_device_under_the_transfer_label`, `pairing_aborts_on_a_substituted_key_or_nonce`; `v05_account.rs: a_seed_cannot_be_moved_by_a_pairing_for_another_account_or_a_wrong_key` |
| Finality: `final` entries, revoked witnesses, a full set finalizing earlier, rule-1 conflicts | `rules/t-final-*`, `rules/t-revoke-home-control-rule-needs-its-head`, `rules/t-provisional-home-revocation-keeps-home`, `rules/f2-head-revoked-at-head-seq`, `rules/t-full-set-finalizes-earlier`, `rules/t-backdated-entry-vs-provisional`, `rules/t-activate-after-covered-entry` |
| Vault | `rules/t-removal-slotted-without-vault`, `rules/t-one-recovery-key-removes-slotted`, `rules/t-vault-rotation*`, `rules/t-self-slot`, `rules/t-rekey-by-recover-key`, `rules/t-vault-entry-*`, `rules/t-vault-by-approve-only` |
| Exchange: the pending listing and its cursors | `v05_home.rs: receipt_window_retry_restart_signature_and_pending_pagination`; `v05_engine_home.rs: a_cursor_the_home_no_longer_honours_makes_the_engine_list_again` |
| Revision 17: the layout door | `rules/f3-layout-3`, `rules/f3-layout-2`, `rules/f3-layout-3-no-consent`, `rules/f3-raise-final-then-entry`, `rules/f3-layout-then-entry`, `rules/f3-raise-vetoed`, `rules/f3-raise-provisional`, `rules/f3-raise-with-policy` (no home: final at once), the other `rules/f3-*`, `upgrade/then-v5-layout-3` |
| Revision 17: a stopped reader | calls `unavailable`: `calls/s-stopped-reader-call`, `calls/s-before-stop-call`, `v05_freeze_calls.rs: a_stopped_reader_verifies_no_call_under_a_fresh_head_before_the_stop`; no new record: `v05_freeze_stopped.rs: records_that_arrive_after_the_stop_are_not_admitted`; no head accepted: **none found** (no test names a head refused by a stopped reader) |
| Revision 17: the stopped home | `crates/colophon-core/tests/v05_freeze_home.rs` and `crates/colophon-home-wasm/tests/v05_relay_stopped.rs`, merged with H4: `a_stopped_home_keeps_its_verified_prefix_and_pending_objects_across_restart`, `no_head_or_entry_or_unrelated_pending_object_is_admitted_after_stop`, `stopped_home_receipts_vetoes_and_removals_at_or_before_n_and_only_in_window`, `a_provisional_raise_is_receipted_and_a_vetoed_displaces_it_without_stopping`; `stopped_public_home_keeps_every_store_kind_and_serves_only_call_free_reads_after_restart`, `stopped_members_home_never_challenges_or_verifies_a_call_and_rejects_new_pending_kinds`, `stopped_home_receipts_only_timely_vetoes_and_removals_and_never_records_them`, `a_home_witnesses_a_provisional_raise_and_records_the_vetoed_that_displaces_it`, `existing_forwarding_sends_stopped_homes_new_removals_vetoes_and_receipts`; also `calls/s-stopped-home-read` |
| Revision 17: the current principal | `rules/f2-end-sessions-expired-member`, `rules/f2-end-sessions-expired-unknown-field`, `rules/f2-end-sessions-provisional-member`, `rules/f2-end-sessions-current-unknown-field` |
| Revision 17: the confirmed pairing | `v05_freeze_approval.rs`: without a token `a_grant_component_without_a_pairing_is_refused`; another account `a_pairing_for_another_account_is_refused`; another key `a_pairing_for_another_key_is_refused`; spent once already: `ConfirmedPairing` is not `Clone` (the `compile_fail` example in `crates/colophon-core/src/v05/pairing.rs`) and `a_grant_transition_spends_a_pairing_for_exactly_its_request`; code path `the_code_ceremony_issues_a_pairing_that_approves_the_request`; scan path `the_scanned_request_issues_a_pairing_that_approves_the_request` |
| Revision 17: the two-home tests pass | `crates/colophon-home-wasm/tests/v05_relay_h2.rs` and `crates/colophon-home-wasm/tests/v05_relay_home.rs`, every test in both files |
| Revision 17: Swift seq 0 | **None found.** The generator file for it, `crates/colophon-core/tests/v5_candidate/cases_freeze_swift.rs`, builds nothing |

