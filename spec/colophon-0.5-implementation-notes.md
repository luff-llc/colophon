# Colophon 0.5: implementation notes

**Status:** running list kept while building `colophon_core::v05` against
[colophon-0.5.md](colophon-0.5.md) revision 11 (`63bbeff`). The foundation (encoding, keys,
signatures, terms, records, calls) was merged as colophon#4. This branch brings it to revision 11
(step 1) and adds the authority history verifier of §8 (step 2).

Revisions 7–11 settled every open item of the revision-6 list:
- retention 7,260 s;
- the origin prefix grammar;
- number ties, lone surrogates, nesting at 64;
- UV per rule;
- members reading at a home;
- both controller forms, and the re-added controller;
- the unknown form;
- `newerFormat` in §11.5, and the 60 s head rule;
- statuses on the call vectors.

Those items are gone from this list.

## Step 1: brought to revision 11

- **Conditions.** Only an unknown *result* is `newerFormat` for a call, so
  `any:[true, unknown]` is true.
  - `Terms::unknown()` still lists unknown operators, for authority entries (§8.5 step 4, §11.5).
  - `Terms::unknown_outside_conditions()` leaves them out, for calls (§12.3 step 8).
- **Nesting** is capped at 64 containers by a linear pre-scan in `encoding::strict_parse`, which
  also applies to `clientData`.
- **Bounds.** The §2.4 envelope bounds are in `encoding::bounds`.
  - A compile-time assertion proves the composition (`COMPOSED_VETOED_AT_QUORUM_8 ≤ AUTHORITY_BODY`).
  - `RawEnvelope::parse_bounded` takes an explicit envelope bound.
- **§12.3 step 6.** Every link binding and the acting key are checked first (`badSignature`).
  Session, time, narrowing and principals follow, link by link.
- **No bypass of `AuthorityRule`.** `verify_webauthn`, `OriginRule` and `Strictness` are
  crate-private. The public standalone check is `webauthn_check(…, CheckMode)`; its authority
  mode takes an `AuthorityRule` and derives the origin rule and UV from it.
- **Runner.** It handles `final` entries and suspensions that end by the clock.
  - Finality is a recorded fact: an empty witness set or a `final` entry, never heads seen.
  - Statuses the vectors state (`verifier.statuses`) are checked against the derived ones.

## Still open

| # | Section | Question | What this implementation does |
| --- | --- | --- | --- |
| 1 | §16.3 | A lenient predecessor DER form | None exists in the text; the predecessor check differs only in its origin rule. Whether CryptoKit's `rawRepresentation` accepts r or s = 0 is unknown, so it is refused. |

## Step 2: the authority history verifier (§8)

`v05::history::verify_history(objects, persisted, now)` replays an account from its object set:
entries in any order (including conflicting ones and branches), held transitions, vetoes and
receipts, and heads. `AccountView::from_history_verifier(&verdict, &objects, now)` builds the call
view from the verdict, deriving every §8.7 status:
- added but not final;
- suspended until due + 7 days;
- pending addition or removal, from held valid unrecorded transitions.

Implemented, following the state table:
- genesis, and the immediate entries `grant`, `renew`, `revoke`, `endSessions`, `rekey` and
  `keyring` (including self-slots, headroom and policy lowering);
- `vault`, `suspend`, `activate` (including full sets), `vetoed` and `final`;
- the composite rule, consent, escalation and full sets of two units;
- removal-only activations, homes staying current until their revocation is final, and the
  stronger authority for revoking a home;
- planted keys dropped with the key that planted them, the retiring vault and its rotation rule,
  and recovery installing control;
- the rate limit with charged signers;
- the §8.6 activation order and total order, equivocation by heads, and forks;
- held entries;
- the high-water mark, which only detects rollback.

**Not implemented** (reported as not implemented, never as passing):
- `predecessor`, `successionVetoed`, `successor` and `resolve` (succession and forks' way out);
- the 0.4 `upgrade` prefix;
- homes' admission rules (§13.1 caps and the clock) and the exchange (§14);
- resuming from a persisted folded state: the verifier replays from seq 1 and takes only the
  high-water mark;
- equivocation evidence objects;
- seal recipients in `shares` and `epochs`;
- slot cryptography.

### Disputed vectors

| Vector | Expected | This verifier | Why |
| --- | --- | --- | --- |
| `rules/t-receipt-by-revoked-home` | `malformed` at 4 | `ok` | H2's revocation at seq 3 is under the control rule and has no `final`. Per §8.7 "Revoking a home", it stays current, for receipts too, until the revocation is final. The vector reads §8.7's "a transition whose only receipting homes are revoked before activation is dead" as applying at activation. |
| `rules/t-recovery-rule-appoints-home-low-threshold` | `badSignature` at 3 | `badSignature` at 1 | The genesis has `threshold` 2 and one control signer; Ph signs only `additions`, which never count toward a rule (§4.1). |
| `rules/t-veto-22-signers` | `ok` at 3 | `malformed` at 1 | The genesis keyring keeps the base slot naming A, who isn't a controller there (§7.2: slots name current controllers). |

### Questions, and the reading chosen

| # | Section | Question | Reading implemented | Test |
| --- | --- | --- | --- | --- |
| 1 | §8.7 "Choosing receipts" | A verifier can't know which receipts the entry's builder held, so it can't check "the lowest member IDs whose valid receipts it holds" | Checked: exactly `headQuorum` valid receipts from distinct current homes, sorted by home. Differing choices for one transition are decided by §8.6 (lower body digest). | `rules/t-activate-differing-receipts` |
| 2 | §8.7 "dead" transitions vs "Revoking a home" | Does "revoked before activation" mean activated or final? | Final: a home stays current until its revocation is final. | disputed `t-receipt-by-revoked-home` |
| 3 | §8.7 "Finality", `final` row | Homes excused by a removal-only `final` count for the earlier activations that same `final` finalizes? | No: excusal follows A's finality, so earlier activations need a later `final`. | `rules/t-removal-unblocks-addition` |
| 4 | §8.7 | An activation whose witnesses are all excused later: final at once, or does it need a `final` (which can't be empty)? | Its required witness set shrinks, but it needs a `final` entry, and a `final` with no heads is `malformed`. This can't complete: the text should say it is final once its remaining witness set is empty. | none (no vector) |
| 5 | §8.6 | More than two valid candidates at one seq | Pairwise, in body-digest order. Rule 1's mixed comparisons aren't obviously transitive, so a three-way conflict of recording and signed entries could depend on the pairing order. | none (no vector) |
| 6 | §8.4 Recovery | What may the recovery rule add? | Controllers with roles within `approve` and `control`. An `update` that adds roles counts as control-rule only. | `t-recovery-installs-control-pending`, `t-recovery-adds-recover-refused` |
| 7 | §8.3 planted keys | Keys planted by a planted key? | Followed transitively (charged signer chain). | `t-planted-key-dropped` (one level) |
| 8 | §8.7 suspension end | "The first entry after which T is no longer valid at a hypothetical `activate`" | T is re-checked after every entry (rule, consent, escalation, receipts, anchor), ignoring its due time. | `t-suspension-ends-with-veto`, `t-suspension-ends-at-expiry` |
| 9 | §13.1 rate | Window bounds | Entries with `issued` in (E − 24 h, E], E included. | `i-rate-*` |
| 10 | §8.6 rule 1 | "A head of the primary home covering Y" | A head by the primary home (from the state before seq n) whose digest is Y's or a descendant's among the held entries, verified under that home's key. | `t-activate-after-covered-entry`, `t-backdated-entry-vs-provisional`, `t-final-not-displaced` |
| 11 | §8.7 order | "T not recorded on the branch" before validity | Yes for `activate` and `vetoed`, so a duplicate is `malformed` even when its signer's escalation count has changed. | `t-vetoed-duplicate`, `t-activate-reappended` |
| 12 | §8.4 possession | Possession for an `add` of a key that is already present | Not required: nothing is added (the delta voids it if the roles differ). | `t-add-present-different-roles` |
