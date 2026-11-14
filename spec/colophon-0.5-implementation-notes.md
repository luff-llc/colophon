# Colophon 0.5: implementation notes

**Status:** running list kept while building `colophon_core::v05` against
[colophon-0.5.md](colophon-0.5.md) revision 13 (`spec-0.5-r12` plus the revision 13 branch). The
foundation (encoding, keys, signatures, terms, records, calls) was merged as colophon#4. Step 1
brought it to revision 11 (`63bbeff`); step 2 added the authority history verifier of §8;
revision 12 and revision 13 are the last two sections. No vector of revision 12 or revision 13
was replayed by the Swift source.

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

All three fixes are in the Rust generator (`crates/colophon-core/tests/v5_candidate/`, which replaced `rules_v8.py`) and its deterministic generated files. The runner now fails on every in-scope mismatch; it has no dispute exemptions. No engine or normative text change was needed.

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
and final-state expectations, generated by the Rust generator (formerly `rules_v8.py`). No signed event or history bytes
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


## Step 4 of engine-0.5-rest: home admission and pending exchange

`v05::history::home` is sans-IO. `admit` takes a persisted `HomeState`, one envelope and a
clock date, returning the proposed next state, acceptance or one named refusal, and receipt
bodies for the host's signer. The host must commit the returned state even on refusal: first
observations and permanent late-activation decisions survive restart. `finish_receipt` checks
the raw signature, exact requested body and actual signing window before accepting it.
The engine never holds a home private key or performs storage, networking or clock reads.

Implemented:
- entry verification, inclusive 60-second/300-second clock boundaries, primary ordering,
  primary endpoint redirects, and overlap/gap conflicts;
- latest-state transition validation including non-void deltas; ordered proposer/account/veto
  caps, with no eviction; veto eligibility and receipt quorum before a veto blocks activation;
- first-seen facts, serving history and permanent late-activation refusals; late transitions
  and their receipts remain available even when the activation is refused;
- one receipt per home/object, persistent signing drafts, verified completion, body-based
  idempotence and preservation of the first stored envelope;
- authenticated receipts arriving before their objects are held separately and answered
  `unavailable`; only after target/window validation can they affect first-seen facts or the
  listing. The local unmatched-receipt buffer is documented at 4,096 objects; beyond that the
  result is `unavailable`. Unknown dependencies are retried by the caller;
- pending POST batches of 1–16 with a result for each object, including malformed objects;
  GET pages of 1–64 with monotonic never-reused cursors, `more`, digest lookup and receipts;
  recorded objects and their receipts stop appearing. Time-based retention may exceed seven
  days (dropping after that is optional), including full sets whose receipt-based due time
  has not been established yet;
- versioned home checkpoints including all these local facts. Reading APIs assume the caller
  has performed §13.4 authorization using the existing call verifier. Transport adapters,
  notices, forwarding, signing and scheduling recording entries remain host responsibilities.

Readings chosen, with tests (no normative text changed):

| Question | Reading | Named test |
| --- | --- | --- |
| “not serving for any part of that window” | No serving interval overlaps the window, including its endpoints. Serving for even one instant removes this exception. | `downtime_exception_requires_no_serving_during_the_receipt_window` |
| Who “proposed” a multi-signer transition for the local quota? | Every signing unit; each unit's quota is checked before the account quota. Vetoes consume every vetoing unit's one-per-transition allowance. | `proposer_cap_never_evicts_and_returns_per_object_batch_results`, `account_cap_follows_proposer_cap_and_retains_receipted_late_evidence`, `veto_cap_is_per_unit_and_valid_veto_blocks_activation_until_recorded` |
| A receipt arrives before its transition | Authentication alone cannot establish its window or first-seen eligibility. Hold it, answer unavailable, and promote only after validating the target bytes. An invalid-window receipt never excuses late activation. | `forwarded_receipt_before_transition_counts_only_after_its_window_is_validated` |
| A permanently refused activation carries a foreign-receipted transition while the home is full | Honor §13.1's explicit requirement to retain and serve that transition and its receipts; admission caps still refuse new receipt requests and never evict. Consequently §14's computed 10,368-object bound is not a guaranteed bound on this retained late evidence. This tension in the text remains recorded for review; no wire or normative text was changed silently. | `account_cap_follows_proposer_cap_and_retains_receipted_late_evidence` |

The test `shuffled_pending_objects_converge_after_unavailable_dependencies_are_retried`
checks all 24 permutations of transition, transition receipt, veto and veto receipt, with
serialized restarts and dependency retries, then verifies the recording entry and listing.
Local caps and cursor order remain arrival-dependent exactly as §13.1 explicitly permits.
The hostile-input test mutates every byte of a real transition; boundary, restart, receipt
signature, pagination, mixed-batch and non-primary-head tests cover the remaining interfaces.

Generator changes (metadata only): `i-rate-dormant-burst` now states the exact admission
object, home and `refused:late` result; the runner executes it instead of reporting it not
implemented. `row-13-backdating-home` additionally checks the honest home's refusal of the
hostile branch's activation, as well as its existing history verdict. The descriptive prose
is retained, not interpreted as an expected code. No signed fixture bytes changed.

Step-4 verification: 334 workspace tests pass (4 existing ignored); conformance 249 in scope,
249 pass, 0 fail, 29 not implemented. All 1,058 generated files reproduce. Offline locked
workspace/all-target clippy with `-D warnings`, WASM check and FFI build pass. Changed Rust
files pass rustfmt; workspace rustfmt reports only the same six unchanged 0.4 files. No new
dependency, lockfile, released engine or existing binding/export changes.


## Step 5: succession and the incorporated upgrade prefix

The `/4` prefix is replayed by the unchanged released `Authority::replay`; the signed
upgrade is checked under that keyring's control rule, with UV, before its new fields.
Only `addThreshold`, `countBy` and `policy` may differ. The folded `/5` state carries
members as terms, epochs, historic points, sequence/digests and an explicit upgrade fence.
Subsequent `/4` entries are malformed. No released engine code is changed.

`Objects.predecessor` supplies exact predecessor envelopes, independently of the successor
history. `history::swift::verify` verifies Swift body bytes without imposing `/5`
canonical encoding. It handles root/recovery/steward and adopted-keyring rules, the
strict predecessor WebAuthn check, keyring recovery's multiset-only-add rule, layout
freezes and later attempts. The successor checks handover, carried-key possession
exemptions, the witnessed window, historically eligible vetoers, determined
`successionVetoed`, fresh heads, and the final binding. It persists verified succession
and reports sequence numbers of evidence after F. A `/5` predecessor is checked by
`verify_history`; successor activation is terminal. Migration is an owner assertion
with a checked manifest shape, not evidence of complete copying.

Readings pinned by tests:

- Swift has no agreement field on a controller. Descriptor equivalence for possession
  means the signing point, form, RP and credential; `/5` adds authority origins and may
  carry the agreement point in its raw descriptor. Existing identities are not new keys.
- Optional extra handover keys may be current predecessor keys absent from the new ring.
  Their predecessor descriptor is used when no genesis descriptor exists; a present
  genesis descriptor supplies authority origins. This follows “further keys current at
  head”; the root-only rule means the required authority is the root, with optional extra
  veto weight. The `swift-handover-extra-key-raises-veto` vector pins this reading.
- A malformed `successionVetoed` candidate does not veto a succession. Its error remains
  reported at sequence 3; valid history through sequence 2 and fresh heads can establish
  the succession. A valid recording permanently vetoes it.
- A Swift freeze strictly after the due instant is needed (“due before F”).

Generator corrections, no normative text changes:

1. Every Swift succession fixture lacked the fresh successor head required by §15.1.
   Added a signed `successor-head.json` covering the unvetoed two-entry prefix, issued
   after due. The verifier checks it; deleting heads or genesis receipts prevents verification.
2. `swift-premature-freeze-then-owner` dated the owner's genesis before its named head,
   and its appointing entry before that head too. Its genesis now uses the head's issued
   time and its appointing transition/window is later. Recomputed affected bindings.
3. `upgrade/then-v5-layout` used a directly signed layout, contrary to §8.4's transition
   classification. It now embeds a signed layout transition in its determined unsigned
   activation. The intended acceptance and all other upgrade expectations stay unchanged.

Named tests in `v05_succession.rs` cover every succession/upgrade fixture in reverse
arrival order and at every serialized restart split, including full folded-state equality;
missing fresh heads/receipts; and malformed predecessor bytes. The runner executes all
25 formerly excluded cases rather than matching descriptions or counting exemptions.

Additional step-5 checks: `authority5-successor` is a new generated positive native
predecessor vector. `forged_swift_candidate_cannot_create_a_fork` authenticates every
candidate before deciding a Swift fork; one invalid competing body cannot block the
verified chain. `malformed_evidence_after_verified_swift_final_does_not_undo_succession`
checks that malformed bytes beyond F remain evidence and cannot undo a verified succession.
The original whole-predecessor preflight remains available to a copy tool through
`history::swift::verify`, while succession verification needs only the prefix through F.

Step-5 verification: 339 workspace tests pass, four existing tests ignored; conformance
275 in scope, 275 pass, zero fail, four not implemented. All 1,078 generated files reproduce.
Offline locked workspace/all-target clippy with `-D warnings`, WASM target check and FFI
build pass. Changed Rust files pass rustfmt; workspace rustfmt still reports only the same
six unchanged 0.4 files. No dependency, lockfile, released engine or binding changes.
The legacy `/3` record parser/admission path remains a limitation beyond this authority
upgrade adapter; the stored upgrade sequence is available to callers for its format fence.

## Fix round after the independent check (2026-11-14)

Fixed, each with a regression test (`tests/v05_fix_round.rs`, `v05_history_props.rs`, `v05_home.rs`)
and, where a vector fits, a generated one:

- H1, H2: only a `final` that is a valid entry on the activate's own branch (a descendant whose
  chain applies in turn) covers an activate in §8.6 rule 1; an unverified or off-branch `final`
  covers nothing. Vectors `t-vetoed-beats-activate-invalid-final`,
  `t-activate-after-covered-entry-invalid-final`.
- H3: the checkpoint records the earliest time a candidate held at an already decided seq comes
  due (`held_until`); a resumed verifier replays once the clock reaches it. **Checkpoint format 2** (3 since revision 12);
  a format 1 checkpoint is refused (`unknown checkpoint version`) and is rebuilt from its objects.
- M3: a `/5` predecessor that is itself a successor is verified with its own predecessor, split
  from the flat set by genesis and descent. The implementation refuses more than 16 distinct
  genesis accounts in the set as `malformed` (written into §2.4 and §15.1 in revision 12). A cycle cannot recur: each level removes its own genesis. Vector
  `succession/authority5-chain`.
- L3: a Swift `layout` needs every signer to hold `control` (§16.3). Vector
  `succession/swift-layout-extra-noncontrol-cosigner`.
- L4: a transition refused `refused:early` leaves no first-seen time (§13.1).
- L6: §15.1 step 3 is exact: for an entry dated exactly W0 minus the delay only the state after
  it counts, so the code now uses `>` at the cutoff. Vector
  `succession/swift-veto-by-key-removed-at-cutoff`.

Left open after this round: L1 (quadratic `/4` prefix replay), for the performance step. M1, M2,
M4, L2, L5 and the chain bound were decided in revision 12 and are built (next section).

## Revision 12 (2026-11-14)

Built on `spec-0.5-r12`, one commit per item, each with a test or a generated vector. The text
decisions are in changes §A.8, §G.16 and §G.17. **No vector or test of revision 12 was replayed by
the Swift source**; the Swift readings (L2, M-d, M-e) are the engine's reading of Marginalia
`origin/main` `c8280332`.

- **One meaning of final (§8.6, §8.7; M1, H1).** §8.7 "Final" defines "a `final` covers" once;
  `final_covers` tests `Activation::final_`, the flag the rest of the engine uses, in the state
  after the activate and after any valid entry that follows it on its branch. A `vetoed` therefore
  never rolls back a cascade-final, full-set-final or excusal-final activation. Vectors
  `t-excusal-`, `t-cascade-` and `t-full-set-final-not-displaced-by-vetoed`, and
  `t-vetoed-displaces-activation-and-later-revocation` for the other direction.
- **Order guard (§8.7; M-a).** `finalize_empty_witnesses` obeys Order, and an activation with no
  witnesses becomes final at the fixed point rather than inside `activate`. The first version of
  these notes said no history makes the guard matter. One does: a revocation of a home that also
  loosens a policy field is not removal-only, so once final it revokes the home without excusing
  it. `t-order-guard-keeps-later-addition-provisional` fails with the guard removed. Open design
  point, not decided here: that home is revoked but never excused, so an earlier activation that
  lists it as a witness can only become final through its head or a full set.
- **Final successions (§15.1, §15.2; M2, M-b, M-c).** The state keeps `successor_seq`. While F is
  provisional the account admits F's `final`, a `final` of an earlier activation that is not
  removal-only, the `activate` of a removal-only home revocation and that revocation's `final`;
  nothing else (a `vetoed` displacing F is a candidate at F's seq). Once F is final nothing is
  admitted. A removal-only revocation excuses a dead witness for F, so F can become final. The
  succession is verified only when F is final. Vectors `succession/authority5-successor-*`.
- **Possession (§8.4; M4, H2).** Swift: the carried-key exemption needs the `handover` to meet the
  rule that may write F. `/5`: it needs the succession verified. While a `/5` predecessor's F is
  absent or provisional the successor genesis is held (`Succession::undecided`); it is `ok` when F
  is final and `badSignature` when the predecessor has another entry at F's seq. A genesis with
  every proof is valid on its own. Vectors `succession/swift-*-needs-possession`,
  `authority5-successor-provisional`, `-final`, `-vetoed-no-proofs`, `-vetoed`.
- **Proposer cap (§13.1; L5).** `TCheck.proposer` is the unit of the primary signer; a pending
  transition's `units` is that unit only; the early check runs before the caps and before a first
  sighting is recorded. Two tests in `v05_home.rs`.
- **Chain bound (§2.4, §15.1; H3).** `chain_length` follows `predecessor` references from the
  claimed account; more than 16 accounts is `malformed`; other objects are ignored. Vectors
  `succession/authority5-chain-16` (verified) and `-17` (`malformed`); the earlier test that
  counted unsigned geneses now asserts they change nothing.
- **Swift numbers and quorum (§16.3; L2, M-d, M-e).** `AuthorityState.swift:105` and `:315`
  (`?? 0`), `:164` (`threshold > 0`), `AuthorityEntry.swift:51` (`Int?`) and `:135` (a
  `DecodingError` is rethrown). `threshold` is checked on every entry kind: absent or `null` is 0,
  any other form than a plain integer is `malformed` (Foundation accepts `2.0`; shipped writers
  never write it). The engine's quorum handover is stricter than Swift's (`:165-167` ignores extra,
  duplicate, mislabelled and non-steward signatures); that is stated in §16.3 and left unchanged.
- **Checkpoint format 3.** `successor_seq` and `undecided` changed the saved state; a format 2
  checkpoint is refused and the account rebuilt.

Revision-12 verification numbers are in PR #7.

## Revision 13 (2026-11-14)

Engine round 2, built on the integrated write side (PR #8), one commit per item. **No vector or
test of revision 13 was replayed by the Swift source.**

- **`resolve` (§8.6 rule 3, §8.7; E1 M3).** The reading implemented, written out in §8.6
  "Resolving a fork":
  - *Which branch.* The transition's anchor is on the branch that will keep the fork's seq; its
    `activate` is an entry on that branch. `discarded` names the other candidate's `{seq, digest}`.
  - *Who signs.* The control rule of the keyring before the fork (state after seq
    `discarded.seq − 1`), counting only the control units that keyring holds, up to its
    threshold. Consent (`recoverThreshold`) and "each signer current" are judged in the state
    before the recording entry, as for every transition. The pre-fork keyring is kept in the
    state (`State.fork`, set only during the verifier's look-ahead) so no history walk is needed.
  - *How the verifier chooses.* At a conflict that §8.6 rules 1 and 2 leave open, each valid
    candidate's own branch is folded forward with the fork in view (no nested look-ahead: a later
    unresolved conflict ends that branch). A candidate stands when its branch holds an activation
    of a `resolve` that discards every other valid candidate and no other candidate's branch holds
    one. The activation, not its finality, resolves it; a `vetoed` displacing it leaves the fork.
  - *The losing branch.* Not on the verified branch; the verdict's `conflicts` lists it as a loser.
  - *Two resolves.* The text gives no order, so neither resolves: the fork stands. This is the
    fail-safe reading of "activates on one branch", reported to the spec owner as undetermined.
  - *Only a held fork.* `apply_delta` voids a `resolve` that names no held, valid candidate at that
    seq other than its own branch's. Home and builder admission judge the shape only (one branch
    is all they see). A home that has stopped at a fork cannot receipt a `resolve` anchored beyond
    its folded state: not built.
  - Tests in `v05_write_authority.rs` (`resolve_finish_returns_the_transition_and_the_verifier_
    applies_its_activation`, `two_resolves_one_on_each_branch_leave_the_fork`,
    `a_resolve_is_judged_by_the_keyring_before_the_fork`, `a_resolve_activation_names_a_fork_the_
    verifier_holds`); vectors `t-resolve-fork`, `t-resolve-two`, `t-resolve-below-rule`.
- **Head rollback (§13.3, §17.2; E1 gap).** The mark is per home, as the decision says, kept in
  `Persisted` (`head_mark`, `accept_head`, `check_head`) and checked by `heads::verify_head_with_mark`
  after the signature, clock and held-history checks. A head behind its home's mark is
  `refused:rollback` only while the marked entry is still on the held history, so a displaced
  activation (§8.7 rollback) does not make an honest home's later, lower head a rollback.
  `verify_head` itself is unchanged (no mark), so `calls.rs` and the write side are untouched.
  Checkpoint format 4 (marks, and the fork a `resolve` names): a format 3 checkpoint is refused and
  rebuilt (test `marks_survive_a_checkpoint_and_a_previous_format_is_refused`). `rules/rollback` is
  now run (`run_rollback`); its `case.json` gained `verifier.history` (the account records), its
  expectation is unchanged. Tests: `tests/v05_head_marks.rs`.
- **`vetoed` choosing rule (§8.7; E1 H4).** The verifier takes the veto's receipts it holds
  (`Pending.receipts`) together with the entry's own, keeps those valid under §13.5 and received at
  or before the deadline, takes each home's lowest body digest and the `headQuorum` lowest home IDs,
  and requires the entry's receipts to equal that. Partial views: adding the entry's own receipts
  to the held set means a verifier that lacks a receipt the recorder held still accepts a correct
  entry (test `a_verifier_missing_a_receipt_the_recorder_held_does_not_refuse`). Activation's
  receipt choice is *not* enforced this way (question 1 above: differing choices are decided by
  §8.6 digest order); the veto rule is stricter because the checker found two bodies for one
  `vetoed`. **Risk for the spec owner:** a hostile low-ID home that signs a second, lower-digest
  receipt in time and shows it only to some verifiers makes those verifiers refuse an otherwise
  correct `vetoed` (an entry the recorder built without that receipt). A home signs one receipt per
  object, so this needs a home that equivocates. Vectors `t-vetoed-choice-right`,
  `t-vetoed-late-receipt-skipped`, `t-vetoed-wrong-choice`; tests in `v05_vetoed_choice.rs`.
  Text item D (admission at the home's current head) is in §8.7 with this item.
- **`final` with several covering heads per witness (§8.7).** Text and enforcement as for the
  veto receipts: per witness the lowest body digest among the covering, usable heads, judged over
  the heads held plus the entry's own. **Reading chosen, with the conflict that forced it:** the write side
  ignores a head dated more than 60 s ahead of *its clock*. Taken literally at the verifier,
  usability would depend on the verifier's clock, so a correct `final` would turn `malformed` once
  the clock passed a lower-digest head's date (first version of `v05_final_choice.rs`); and a
  verifier holding a later `final`'s embedded head (dated after the earlier one) would refuse the
  earlier `final` of `t-removal-unblocks-addition` (the state-aware builder replay in
  `v05_write_authority.rs` showed it with a 60 s slack). Usability is therefore measured against
  the entry's own `issued`: for an entry a builder made the two agree (a usable lower head would
  have been chosen and raised `issued`), and no existing vector changes. `prepare_final` (not
  edited) is unchanged. Vectors `t-final-head-choice-right`,
  `-choice-wrong`, `-ahead-ignored`; tests in `v05_final_choice.rs`.
- **Late veto at a home (§13.1; E3 M2).** `home.rs` stores a veto that arrives after its 300 s
  window (or the veto deadline) when an in-window receipt of it from another current home, received
  at or before the deadline, is already held in `unmatched_receipts`; it then promotes the receipt,
  stores and serves the veto and signs nothing. With none held it is `refused:late` and not stored,
  as before; a receipt forwarded afterwards stays unmatched until the veto is sent again. Test
  `a_late_veto_is_stored_with_an_in_window_receipt_from_another_home_and_signs_none`; no vector
  (the runner's admission case takes one object, and this needs a receipt held first).
- **Two heads for one seq (§13.3; E3).** The home module never drafts heads; the host does, with
  `write::calls::prepare_head`, which knows no history. The guard is `HomeState::guard_head(seq,
  digest, issued, now)`: the host MUST call it before preparing a head and persist the state it
  returns (the draft counts as signed). It refuses a head for an entry not on the home's verified
  branch, non-increasing `issued`, and a second digest at a seq unless following both entries
  back to where their branches first differ lands on a conflict the home's verdict decided for
  this head's side with a recording entry on one side (`displaced_by_rule_1`). `signed_heads` is a
  new `#[serde(default)]` field of `HomeState` (version unchanged). `prepare_head` is not edited:
  nothing in the write module enforces that a host calls the guard. Test
  `a_home_signs_one_head_per_seq_unless_the_first_was_displaced_under_rule_1`.
- **Slot shape at replay (§7.2; coordinator item A).** `Keyring::parse` now also calls
  `slots::validate_slots`, the same structural validation the write side uses, so a slot with a
  wrong-length sealed box, a bad salt, wrong parts and the rest is `malformed` at replay in
  genesis, `keyring` and `vault` entries, activations and checkpoints. No existing vector
  changed (314 in scope all pass). Vectors `t-slot-wrong-length-genesis`, `i-slot-add-valid`,
  `i-slot-add-wrong-length` (the last two differ only in the 47-byte ciphertext). Only the
  wrong-length case is vectored; the other shapes are covered by the slot module's own tests.
- **Text-only items (one commit).**
  - *Equivocation evidence (§13.3; item 7 as decided in coordinator item B).* The three forms are
    judged against held history. Written against `v05/write/authority.rs` as first read; the
    integrator's commits `e74ed50` (heads: walk back to the divergence, equal `issued`, `unavailable`
    without the chain) and `884fe26` (entries: the signer units on both, a recording entry convicts
    nobody) then made the code match this text, and the veto form already carried the activation.
    Not enforced anywhere: that a home's heads have strictly increasing `issued` is checked at signing
    by `HomeState::guard_head`, not by evidence verification.
  - *Notices (§17.5, §13.1), link `created` (§12.1), kit derivation (§7.5; `vault::kit_identity` is
    the one derivation), restricted open (§17.1; bounds `HOST_OPEN_MAX_INFO` 1,024 and
    `HOST_OPEN_MAX_CIPHERTEXT` 65,536, the `{enc, ciphertext}` of §11.1, ciphertext at least 16
    bytes, `refused:outOfScope` for a `colophon/` label), PRF-building assertion (§7.2: the §4.3
    general origin rule, UV iff the controller's `verification`), the seed guarantee (§17.1, §3.4;
    coordinator item C).
  - *QR payload (§7.3).* Canonical JSON of the closed object `{account, e, nB, protocol:
    "colophon/pair-qr/5"}`. `pairing.rs` has `QrPayload {account, e, nb}` and no encoder or decoder
    ("the byte format is not specified"): it needs `to_bytes`/`from_bytes` for this and a doc
    update. **Not changed** (not my file); the `protocol` member is new text, not a payload field.
