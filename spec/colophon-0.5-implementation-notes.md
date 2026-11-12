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

### Step 1 of engine-0.5-rest: corrected vectors

| Vector | Expected | This verifier | Why |
| --- | --- | --- | --- |
| `rules/t-receipt-by-revoked-home` | `ok` at 4 (corrected) | `ok` | H2's revocation at seq 3 is under the control rule and has no `final`. Per §8.7 "Revoking a home", it stays current, for receipts too, until the revocation is final. Corrected the generator expectation and description: "revoked" here means final. |
| `rules/t-recovery-rule-appoints-home-low-threshold` | `badSignature` at 3 | `badSignature` at 3 | The genesis had `threshold` 2 and one control signer; Ph signed only `additions`, which never count toward a rule (§4.1). Added Ph as a genesis cosigner, retaining its possession proof, so the intended refusal at seq 3 is reached. |
| `rules/t-veto-22-signers` | `ok` at 3 | `ok` at 3 | The genesis keyring kept the base slot naming A, who isn't a controller there (§7.2: slots name current controllers). Made A the first of the 23 control keys, retaining its valid slot (§6.2 requires at least one at genesis). The vector now reaches its 22-signer veto. |

### Questions, and the reading chosen

| # | Section | Question | Reading implemented | Test |
| --- | --- | --- | --- | --- |
| 1 | §8.7 "Choosing receipts" | A verifier can't know which receipts the entry's builder held, so it can't check "the lowest member IDs whose valid receipts it holds" | Checked: exactly `headQuorum` valid receipts from distinct current homes, sorted by home. Differing choices for one transition are decided by §8.6 (lower body digest). | `rules/t-activate-differing-receipts` |
| 2 | §8.7 "dead" transitions vs "Revoking a home" | Does "revoked before activation" mean activated or final? | Final: a home stays current until its revocation is final. | `t-receipt-by-revoked-home` |
| 3 | §8.7 "Finality", `final` row | Homes excused by a removal-only `final` count for the earlier activations that same `final` finalizes? | No: excusal follows A's finality, so earlier activations need a later `final`, unless no remaining witnesses need heads (question 4's correction). | `rules/t-removal-unblocks-addition` |
| 4 | §8.7 | An activation whose witnesses are all excused later | Corrected after revision 11: final without an empty `final` once every remaining witness is excused; repeat after each entry to a fixed point. | `all_witnesses_excused_makes_addition_final_without_empty_final`, `t-all-witnesses-excused` |
| 5 | §8.6 | More than two valid candidates at one seq | Corrected after revision 11: stand only a candidate winning every pairwise comparison. Otherwise keep all as an unresolved fork. A deterministic fold is insufficient: it can pick a loser in a cycle or miss a universal winner after an undecided pair. | `three_candidate_comparison_cycle_is_an_unresolved_fork`, `three_candidates_find_winner_despite_undecided_losing_pair`; vectors `t-three-candidate-cycle`, `t-three-candidate-winner` |
| 6 | §8.4 Recovery | What may the recovery rule add? | Controllers with roles within `approve` and `control`. An `update` that adds roles counts as control-rule only. | `t-recovery-installs-control-pending`, `t-recovery-adds-recover-refused` |
| 7 | §8.3 planted keys | Keys planted by a planted key? | Followed transitively (charged signer chain). | `t-planted-key-dropped` (one level) |
| 8 | §8.7 suspension end | "The first entry after which T is no longer valid at a hypothetical `activate`" | T is re-checked after every entry (rule, consent, escalation, receipts, anchor), ignoring its due time. | `t-suspension-ends-with-veto`, `t-suspension-ends-at-expiry` |
| 9 | §13.1 rate | Window bounds | Entries with `issued` in (E − 24 h, E], E included. | `i-rate-*` |
| 10 | §8.6 rule 1 | "A head of the primary home covering Y" | A head by the primary home (from the state before seq n) whose digest is Y's or a descendant's among the held entries, verified under that home's key. | `t-activate-after-covered-entry`, `t-backdated-entry-vs-provisional`, `t-final-not-displaced` |
| 11 | §8.7 order | "T not recorded on the branch" before validity | Yes for `activate` and `vetoed`, so a duplicate is `malformed` even when its signer's escalation count has changed. | `t-vetoed-duplicate`, `t-activate-reappended` |
| 12 | §8.4 possession | Possession for an `add` of a key that is already present | Not required: nothing is added (the delta voids it if the roles differ). | `t-add-present-different-roles` |

All three fixes are in `rules_v8.py` and its deterministic generated files. The runner now fails on every in-scope mismatch; it has no dispute exemptions. No engine or normative text change was needed.

Step-1 verification: 315 workspace tests pass; conformance 237 in scope, 237 pass, 0 fail, 38 not implemented. Offline locked clippy (workspace/all targets), WASM check and FFI build pass. The changed Rust file passes rustfmt; workspace rustfmt reports pre-existing differences in `library.rs`, `authority.rs`, `keys_performance.rs`, `route_binding.rs`, and both binding `lib.rs` files. These released 0.4 files are unchanged.

## Step 2 of engine-0.5-rest: finality and multi-candidate conflicts

Corrections after revision 11 are recorded in changes §G.15. The all-excused vector removes
both original homes by two recovery transitions; the earlier addition becomes final and its
added controller signs a grant. The cycle vector uses two receipt variants of one activation:
the lower digest beats the higher; a `final` covers only the higher, so it beats `vetoed`;
`vetoed` beats the lower. No candidate wins every comparison, so the account stays forked.
The unique-winner vector has three signed entries, with a quorum head covering only the
highest digest; an undecided comparison between the two losers cannot stop its selection.
All three are included automatically in the existing shuffled-object and hostile-input tests.
The named cycle test also verifies each two-candidate subset to prove the non-transitivity.

Step-2 verification: 318 workspace tests pass (4 existing ignored tests); conformance 240 in scope, 240 pass, 0 fail, 38 not implemented. All 1,058 generated files reproduce. Offline locked clippy (workspace/all targets), WASM check and FFI build pass. Changed Rust files pass rustfmt; workspace rustfmt still reports only the unchanged 0.4 files listed above. No dependency or lockfile changes.

## Step 3 of engine-0.5-rest: clock events and persisted resumption

`Persisted::checkpoint` saves a format-versioned folded state, high-water marker and exact
retained object set. `to_bytes`/`from_bytes` are for the caller's trusted local storage, written
atomically, never for accepting a peer's claimed state. Ordinary suffixes start with that
folded state. New earlier candidates, new heads, prior conflicts or a backwards clock cause
replay of retained objects: caching must not turn the high-water marker into branch selection.
The retained entries also preserve historical signer points, rate charges, final entries,
held entries, displaced candidates and the context needed by call-view construction.
There is one folded state, not a quadratic collection of per-entry snapshots.

Clock checks retry both future entries (at the inclusive 60-second boundary) and activations
(at due). `State::active_suspensions(now)` applies clock expiry with the existing inclusive
end instant; expired historical suspension records remain available for historical admission
checks. The caller still supplies every time. There is no clock, storage or network in core.

The brief calls these eleven event-row vectors. The current corpus has **eight** cases with
`expected.events`; all eight now have additional machine-checkable `checks`, `result`, `seq`
and final-state expectations, generated by `rules_v8.py`. No signed event or history bytes
changed. Each event is checked at an explicit prefix; the full row is then replayed and its
controller set checked. The read-history event gets a generated fresh head in check metadata.
Row 4 additionally checks that the thief's proposal becomes invalid after full recovery.
The existing prose remains explanatory and is never used by the runner to decide a pass.
The previously unimplemented special fixtures `equivocation`, `i-rate-dormant-burst`,
`rollback` and `t-activate-identical-bytes` are distinct from those eight event rows; none is
silently counted as passing. Evidence belongs to step 6 and admission to step 4.

Veto signature, unit and eligibility checks are shared between recording-entry verification
and `check_pending_veto`, which checks before the home's own receipt exists. The recording
path still requires its quorum of receipts, deadline and determined `issued`.

Named tests:
- `persisted_folded_state_resumes_suffix_with_replay_equivalent_verdict`: every history fixture,
  three split points, serialized restart, shuffled suffix/pending/heads; compares complete
  serialized folded states as well as branches, stops and conflict decisions.
- `clock_retries_held_activation_and_expires_suspension_after_restart`: activation due and
  suspension expiry, including the exact last suspended millisecond.
- `clock_retries_future_genesis_and_immediate_entry_at_sixty_second_boundary`.
- `checkpoint_rejects_unknown_format_and_malformed_bytes`.

No normative specification change or new dependency was needed. The snapshot is an internal
versioned storage representation, not a signed Colophon wire format. A host must protect it
as it protects other locally verified state; untrusted histories still enter through the
bounded signed-object verifiers.

Step-3 verification: 322 workspace tests pass (4 existing ignored); conformance 248 in scope,
248 pass, 0 fail, 30 not implemented. All 1,058 generated files reproduce. Offline locked
workspace/all-target clippy with `-D warnings`, WASM check and FFI build pass. Changed Rust
files pass rustfmt; workspace rustfmt reports only the same six unchanged 0.4 files. No
`Cargo.lock`, dependency, released engine, FFI or WASM export changes.
