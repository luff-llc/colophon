# Colophon 0.6 sessions: findings from the reference machine

**Date:** 2026-11-22, updated 2026-11-23. **Against:** `spec/colophon-0.6-sessions.md`, revisions 1–7 (revision 7: `63375bf`). **Code:** `crates/colophon-core/src/v06/session/`.

The reference machine implements the draft, and also the departures listed here. Each
departure that changes behaviour has a switch in `Fixes`. `Fixes::default()` (= `ALL`) is the
reference reading (revision 7; `Fixes::REV6` down to `REV3` are earlier drafts as written), and `Fixes::LITERAL` is the revision 1 draft, so every counterexample below
can be reproduced. Evidence comes from three sources:

- **Explorer:** `tests/v06_session_explore.rs`, an exhaustive BFS to depth 8 with fair
  completions. `draft_counterexamples` keeps the draft's failures as a test.
- **Simulator ablation:** `tests/v06_session_sim.rs` `fix_ablation` (`--ignored`), run over
  1,000 seeds. For each fix it reports the seeds that fail with that fix off, in the random
  workload and in the §S12 playback script.
- **Vectors:** `conformance/0.6-sessions/`.

Each finding is labelled as one of:

- **Spec bug:** the draft as written breaks a §S11 guarantee.
- **Wording:** a guarantee or rule says something the protocol cannot deliver or contradicts.
- **Ambiguity:** the draft does not say, and the reference reading chose.
- **Implementation choice:** a decision local to this layer.

Claims are written `term.rank.holder`. Member IDs are `a`, `b`, `c` in the explorer and `0a`…`4e`
in the simulator.

| | Finding | Kind | Evidence with the fix off |
| --- | --- | --- | --- |
| F1 | Rank-1 acceptance (§S4 rule 3) strands members | spec bug | explorer (3 members); sim 112/1000 |
| F2 | `hello.seen` cannot say "no snapshot" (§S8) | spec bug | explorer (2 members); sim 343/1000, playback 148/1000 |
| F3 | Whether the passer accepts `next` | ambiguity | — |
| F4 | Pass resend contradicts G2/G3 | wording | checker exemption |
| F5–F7 | A claim whose holder has gone quiet is never corrected | spec bug (as a group) | sim seed 930 with F5–F8 off |
| F8 | Pings and pongs keep a non-holder "alive" | spec bug | sim seed 4 (before F9) |
| F9 | A lost `ask` is never repaired | spec bug | playback 151/1000 |
| F10 | Renewal by a member that has just returned steals the role | spec bug | playback 19/1000 |
| F11 | G6 as worded is false | wording | analysis plus checked operational form |
| F12 | Two passes can name the same `next` | spec bug | revision 1/2 machine; now `two_passes_to_one_asker_explored` and `f12_f21_two_passes_to_one_asker` |
| F21 | Revision 2's F12 renewal misses a lost second pass | spec bug | same tests |
| F13–F20 | Smaller readings | ambiguity or choice | — |

**Ablation rerun against revision 3 (2026-11-23, 1,000 seeds; machine narrowed as below).** Since the first run, the simulator also models the 128-wide `n` window, uses `ratePermille` anchors, supplies state on restart and sends publish bursts, so seed streams differ from those cited in the sections below. With each fix off, the seeds that fail are:

| Fix off | Random workload | Playback script |
| --- | --- | --- |
| Revision 1 draft (all fixes off) | 333/1000 | 345/1000 |
| F1 | 115/1000 | 0/1000 |
| F2 | 264/1000 | 46/1000 |
| F9 | 0/1000 | 90/1000 |
| F10 | 0/1000 | 13/1000 |
| F5–F8 together | 1/1000 (seed 930, G4) | 0/1000 |

With F5, F6, F7 or F8 off alone, no seed fails. F12 and F21 have no switch since revision 3 (`Claim::via`); the explorer's two-holder start and the scripted loss test show them.

The early-hold buffer now does real work: about 330 messages were applied from it per 300 seeds.

Every 300-seed and 1,000-seed simulator run and every explorer profile passes with all fixes
on.

## F1. Rank-1 acceptance strands members (spec bug)

**Status:** adopted in revision 2: §S4 rule 3.

**Spec (§S4 rule 3).** A rank-1 claim is accepted only after "a `pass` frame from the holder
of the member's previous accepted claim". Until then, it "treats a rank-1 claim as rank 0 for
ordering".

**Counterexample (explorer, 3 members, ask/take/pass profile).** Start: all members accept
`1.0.a`.

1. `b` asks, and the ask reaches `a`.
2. `a` passes to `b` with `next 2.1.b`. The copy to `c` is lost.
3. `a` and `b` now hold `2.1.b`. `c` stays at `1.0.a`.
4. From then on, every frame from `b` carries `2.1.b`. `c` did not see the pass, and `b` is
   not the holder of `c`'s previous claim, so `c` never accepts.
5. Result: G4 fails forever. The same rule blocks any member that joins after a pass.

**Variant (simulator, seed 5).** `0a` takes `3.0.0a`, which is concurrent with a pass that
made `1b` holder of `3.1.1b`. `1b`'s `state` reaches `0a`, which orders it as `3.0.1b`, a
lesser claim, so it does not yield. Two holders keep running after exchanging frames, which
breaks G6.

**Fix applied (`rank1_from_holder`).** Accept a rank-1 claim:

- from any frame sent by its own holder;
- from a `pass` sent by `pass.claim.holder`, whatever the receiver accepted before.

Rule 3 gives no protection against a dishonest member, which can take at any term. Among
members that follow the document, a member claims rank 1 only after it received a pass, so
the check only costs liveness.

**Spec text (as proposed, now adopted).** "For rank 1, the frame is from `claim.holder`, or is a `pass` from
`pass.claim.holder` with `next = claim`."

## F2. `hello.seen` cannot say "no snapshot" (spec bug)

**Status:** adopted in revision 2: §S3 (`hello`), §S8.

**Spec (§S8).** A member that "changes claim without a snapshot sends `hello`". The holder
answers "with the missing `msg` frames when `seen` names its current claim … else with
`state`".

**Counterexample (explorer, 2 members).**

1. `b` asks, nothing is heard, and `b` takes `2.0.b`.
2. `b`'s `state` to `a` is lost.
3. `a` accepts `2.0.b` from the `take`. It has no snapshot of `b`'s state, and it sends
   `hello seen = {2.0.b, seq 0}`.
4. That names `b`'s current claim at `b`'s current seq, so `b` sends nothing.
5. `a` stays forever on its old state under `b`'s claim. After a later `msg`, `b` would
   resend from its tail, and `a` would fold it onto the wrong base.

**Fix applied (`seen_unsynced`).** `seen.seq` is `null` when the sender holds no snapshot
for `seen`'s claim. The holder answers `null` with `state`.

**Spec text (as proposed, now adopted).** "`seq` is `null` when the member holds no state for that claim."

## F3. Whether the passer accepts its own `next` (ambiguity)

**Status:** adopted in revision 2: §S5 (the passer accepts `next`).

**Spec.** The spec says the passer "is not holder" from the moment it sends `pass`. It does
not say which claim the passer then holds.

**Reading.** The passer accepts `next`, with `snapshot` as its state. Rule 3, read literally,
lets it do so: it is "the holder of the previous claim".

**Why it matters.** If the passer kept the old claim, a `take` by the asker at the same term
would supersede the pass silently, and the resend rule of §S5 would never fire.

## F4. Pass resend contradicts G2/G3 (wording)

**Status:** adopted in revision 2: §S11 G2, G3.

**Spec.** §S5 says the passer "resends the same `pass` when it next hears the asker speak
under an older claim". A `pass` is a holder frame, and it is sent under the old claim, which
is now less than the passer's accepted claim. That breaks G2 and G3 as worded.

**Checker.** The checker exempts an identical resend of a pass the member already sent.

**Proposal (now adopted).** G2 and G3 should say "other than a resend of the same `pass`".

## F5–F7. A claim whose holder has gone quiet is never corrected (spec bug, as a group)

**Status:** adopted in revision 2: §S4 "Correcting lesser claims", §S5 renewing, §S6 (lapse `hello` to all), §S11 G4.

**Spec.** In the draft, claims travel only in their own holder's frames. Only a holder
answers lesser claims, and renewal reacts only to `hello.seen`. When the holder of the
greatest claim releases, leaves, or loses the frames that carried its claim, nobody tells the
other members.

**Counterexample (simulator, seed 930, F5–F8 off).**

1. `2c` took `4.0.2c` and released. Its `bye` was lost to `0a`.
2. `0a`, still at `3.x`, took `4.0.0a`.
3. `1b` accepted `4.0.2c` and therefore ignores `0a`'s lesser frames. `1b` is not a holder,
   so it sends nothing.
4. `0a` never learns of `4.0.2c` and never renews above it.
5. Result: G4 fails with a live holder.

An earlier explorer run, before F6 and F7 existed, found the same shape in six steps
(G5). In that run, a holder took and then yielded to the `hello` of a member that had
released.

**Fixes applied.**

- **F5 (`bye_resend`).** A member that released answers any frame carrying a claim up to its
  own with `bye` again. A listener whose holder lapses sends `hello` to all.
- **F6 (`answer_lesser`).**
  - A non-holder that meets a holder frame or `take` under a claim less than its own answers
    the sender with `hello`, so the sender can renew.
  - "Not present" in renewing means "has sent no holder frame or `take` within
    `holderTimeoutMs`", not presence. A member that released is present but holds nothing.
- **F7 (`renew_wider`).** Renewing also covers three cases:
  - a `hello.seen` that names a greater claim of this very holder (a pass it never
    received);
  - a greater claim met in a `bye` (a released claim has no holder);
  - a greater claim in a `hello` from its own holder. A `hello` cannot say whether its sender
    still holds, so a holder raises its claim instead of yielding to it. A sender that does
    hold then yields to the resulting `state`.

**Bounds of the evidence.** At the explorer's depth 8 and over 1,000 simulator seeds, none of
F5, F6 or F7 alone is shown necessary: the others cover for it. With F5–F8 off together, sim
seed 930 fails. They are kept as one mechanism.

**Proposal (now adopted).** Extend §S4 "Stale holders" to every member: a member that meets a holder frame
under a lesser claim answers with `hello`. Read "not present" in renewing as "not heard
holding".

**G4 note (wording).** With no live holder, nothing need be sent. Members can then keep
different dead claims, or see "no holder" (a `bye` arrived) against "lapsed holder" (the `bye`
was lost). The checker therefore applies G4's claim agreement only while a holder is live. The
next take or renewal restores agreement. G4 should be stated for a live holder.

## F8. Pings and pongs keep a non-holder "alive" (spec bug)

**Status:** adopted in revision 2: §S5 take, §S6 lapsing.

**Spec.** Lapsing (§S6) and the ask timeout (§S5) count what the member "accepted from" or
"heard from" the holder.

**Counterexample (simulator, playback seed 4, before F9).**

1. `0a` passed to `2c`, and the pass was lost.
2. `0a` is no longer holder, but it answers `2c`'s pings every second.
3. `2c` therefore hears "the holder" constantly. It never reaches the ask timeout and never
   sees a lapse.
4. Pings carry no claim, so `0a`'s pass-resend rule never fires either.
5. Result: no holder forever.

**Fix applied (`liveness_holder_frames`).** Only holder frames under the accepted claim count
for lapsing and the ask timeout. F9 now also repairs this trace, by resending the ask, which
triggers the pass resend. F8 is kept because liveness should not depend on pings.

## F9. A lost `ask` is never repaired (spec bug)

**Status:** adopted in revision 2: §S5 (ask resend).

**Spec.** The asker may take only when it has "heard nothing from the holder for
`askTimeoutMs`". The draft never resends an `ask`.

**Counterexample (playback seed 6; 151 of 1,000 seeds fail with the fix off).**

1. `1b`'s ask is lost.
2. `0a` keeps beating, so `1b` keeps hearing it.
3. `1b` waits forever. G5 does not cover this case, because the holder is reachable.

**Fix applied (`ask_resend`).** An asker that heard the holder but got no `pass` or `decline`
within `askTimeoutMs` sends `ask` again.

## F10. Renewal by a member that has just returned steals the role (spec bug)

**Status:** adopted in revision 2: §S5 renewing (the link-has-worked guard).

**Spec.** §S5 renewing uses "is not present". A member that has just come back has heard
nobody, so to it every other holder is "not present".

**Counterexample (playback seed 30; 19 of 1,000 seeds fail with the fix off).**

1. `1b` returns after 40 s out of contact.
2. Its `hello {lapsed: true}` is lost to the real holder `2c`, which holds `3.0.2c`.
3. After `askTimeoutMs`, `1b` retakes at `3.0.1b`.
4. `0a`'s `hello` names `3.0.2c`. To `1b`, `2c` is "not present", so `1b` renews to
   `4.0.1b`.
5. The returning lapsed holder takes the role from the live one. That is contrary to §S6:
   "If within that time it accepts a claim of another member … it yields".

**Fix applied (`renew_needs_contact`).** A holder judges "not present" only after its own link
has worked for `holderTimeoutMs`. Before that, it treats everyone as present.

## F11. G6 as worded is false (wording)

**Status:** adopted in revision 2: §S11 G6.

**Spec.** G6 says "Two members both acting as holder have, since each one's claim began,
exchanged no frame".

**Why it fails.** When the lesser holder's frame reaches the greater holder, the greater
holder answers with `state`. Until that answer arrives, both act as holder, and they have
exchanged a frame. G6's second clause has two gaps:

- frames with no claim (`ping`, `pong`, `presence`, `submit`, `refuse`) cannot make the other
  stop;
- the `pass` frame names the passer, not the holder.

**What is checked.** The operational form: once a frame that carries claim `c` from
`c.holder` reaches a member, that member does not act as holder under a claim less than `c`.

**Proposal (now adopted).** "Once a frame carrying the greater claim, from that claim's holder, reaches the
other, the other stops."

## F12. Two passes can name the same `next` (spec bug)

**Status:** superseded in revision 3: §S4 (claims carry `via`, rule 3), §S5 (a holder that learns of a greater claim naming itself that it has not acted under renews). Revision 2's one-shot rule (`pass_conflict_renew`) was reproduced by a scripted test and has been removed.

**Scenario.**

1. `A` holds `T.0.A` and `B` holds `T.0.B`, partitioned from each other.
2. `X` asks `A`, then accepts `B`'s claim and re-asks `B`.
3. Both pass, and both passes name `next = (T+1).1.X`, with different snapshots.
4. Members that accept different passes hold the same claim at seq 0 with different states.
   That breaks G3 ("the new holder's initial state equals the pass snapshot") and G4.

**Checker.** The checker flags two passes that name the same `next` with different snapshots.
Neither the explorer at its bounds nor the simulator produced one.

**Proposal (now adopted).** A holder made by a pass renews when it meets a different `pass` naming its
claim. Alternatively, put the passer's claim in rank-1 ordering.

## F21. Revision 2's F12 renewal misses a lost second pass (spec bug)

**Status:** fixed at the root in revision 3 (§S4 `via`); the machine's interim `pass_echo` has been removed.

**Spec (revision 2, §S5).** "A holder made by a pass that later meets a different `pass` naming its own claim … renews."

**Counterexample (`tests/v06_session_explore.rs` `f12_two_passes_to_one_asker`, second half).**

1. `a` holds `1.0.a` and `b` holds `1.0.b`, and they cannot reach each other. `x` asks `a`, then accepts `1.0.b` and re-asks `b`.
2. Both pass `next = 2.1.x`: `b` with state `B`, `a` with state `A`. `a`'s pass to `x` is lost.
3. `x` holds `2.1.x` with `B` and never meets a different pass, so it never renews.
4. `a` accepted its own `next` with `A`. `x`'s beats carry `2.1.x` at seq 0, which `a` already holds, so nothing repairs it. `a` resends its pass only when `x` speaks under an older claim, and `x` never does.
5. Result: G3 and G4 fail forever after the partition heals.

**Revision 3 fix.** The two passes now name different claims, `2.1.x.a` and `2.1.x.b`, ordered by `via`. Whoever holds the lesser one meets frames under the greater one and accepts it. Two cases:

- The new holder `x` is on the lesser one. It meets the greater claim naming itself, in a `pass` or in the `hello` that a member sends to correct its lesser frames, and renews to `3.0.x` with its current state.
- `x` is on the greater one. A member on the lesser one accepts `x`'s beats, has no snapshot for that claim, sends `hello`, and gets `state`.

No single frame is needed.

**Evidence.**

- The explorer starts from the two-holder state (`Start::TwoHolders`) and covers both passes in any order, with loss, a duplicate and a link change: 228,196 states at depth 7, with G1–G6 checked and G4/G5 by completion.
- The scripted test runs three cases, and each ends in one claim (`2.1.x.b` or `3.0.x`) and one state:
  - both passes delivered;
  - `a`'s pass to `x` lost;
  - 300 seeds that lose 30 % of the frames from the passes on, then deliver everything.

**G3 under revision 3.** The checker still holds G3 on every transition, read as: "a member that becomes holder by a pass starts with exactly its snapshot". Two cases need that reading made explicit:

- A pass whose claim loses to another pass names a "new holder" that never holds under it.
- An asker that is already holder (it took after the ask timeout, or holds another pass) renews instead of starting from the snapshot.

Proposed wording: "…and a member that becomes holder by that `pass` starts with exactly its snapshot."

## F13–F20. Smaller readings (ambiguity or implementation choice)

**Status:** adopted in revision 2: F13 §S6; F14 §S5 take, §S6 restart, §S12; F15 §S3 `bye.leaving`, §S5 release; F16 §S3 (`lapsed` is informational); F17 §S3 (`n` window), §S8 (gap hellos once per second); F18 `take.basis` removed from §S3, automatic ordering remains a choice of this layer; F19 §S12 `ratePermille`; F20 §S1 `fold`.

- **F13. Lapse while the link is down.** Lapse time counts only while a link works: from
  `max(last heard, link up)`. Otherwise a member coming back would take before hearing the
  holder's answer to its `hello`. (Ambiguity.)
- **F14. A restarted holder.** A holder that restarts with its own persisted claim and no state
  is treated like an out-of-contact holder: `hello {lapsed: true}`, no holder frames for
  `askTimeoutMs`, then a retake at `term + 1`. It retakes with an empty state, unless the
  application supplies one with `take`. This wipes the cell's state even though listeners
  still hold it (vector `restart-holder`). Proposal: let `Join` carry a snapshot, or let a
  returning holder adopt a listener's `state` during its wait. (Spec gap; implementation
  choice.)
- **F15. `release`.** It is not a frame. Here it is a holder `bye` after which the member
  stays joined. (Ambiguity.)
- **F16. `hello {lapsed: true}` on receipt.** The draft gives it no meaning for the receiver,
  and receivers ignore the flag. (Ambiguity.)
- **F17. The §S3 `n` rule makes early hold mostly useless.** A frame that arrives after a
  later frame from the same key is dropped, so reordering turns into loss, and gaps are
  repaired by resume rather than by early hold. Persistent loss of one `msg` also makes every
  resend trigger another gap `hello`. A real host should rate-limit gap hellos (found while
  generating vectors). (Ambiguity; efficiency.)
- **F18. Submits.** They are ordered automatically. The only refusal is `too-large`, and the
  application cannot veto. `take.basis` is sent but nothing reads it. (Implementation
  choice.)
- **F19. The anchor rate.** The §S12 anchor `rate` is a float in the draft. The simulator uses
  integer per-mille. A canonical encoding of `rate` (for example per-mille) would make
  projections reproducible across bindings. (Ambiguity.)
- **F20. The holder's ordered state.** The holder must produce `state` at any moment, so the
  core folds messages itself. `Reducer::Latest` is the §S12 rule; `Reducer::Append` is for
  logs and tests. A cell's fold should be part of its declaration in §S1. (Spec gap.)

## R. First independent design review and revision 4

The first independent review judged revision 3 unsound. In summary, it found:

- a renewal livelock on a three-member chain whose ends cannot hear each other;
- state silently lost when a take raced a delayed pass, or when a released holder restarted;
- a pass revealed before its claim was persisted;
- no safe way to bootstrap a session key, and a nonce scheme open to reuse;
- submits with neither delivery guarantee;
- unbounded growth and integer overflow;
- passes that answered no ask;
- evidence that exercised only a complete graph with one fair schedule.

The table below maps each item to its resolution.

**Machine:** revision 4 is `Fixes::REV4`. The reference reading is `Fixes::ALL`, which is revision 4 plus five fixes, R1c, R1e, R2d and R2e, that the explorer and the simulator showed revision 4 needs. Each fix has its own switch. **Harness changes (H1–H5):**

- per-directed-edge reachability, including a chain profile a↔b↔c with a↮c;
- completions that keep the topology, under three fair schedules (FIFO, LIFO, rotating);
- a strict G5: the asking writer itself must become holder;
- G10 (no claim changes in the second half of a long quiet completion);
- G11 provenance checks: a ghost ledger of displaced states, and late passes checked on each transition;
- G12 crash-prefix steps: every single-member step is cut after each prefix of its outputs, then the member restarts from what it persisted;
- the review's traces scripted.

| Review item | Resolution | Evidence |
| --- | --- | --- |
| Renew livelock A↔B↔C, A↮C | **R1** (revision 4 §S4 evidence, `heard`). The `hearsay` renewal is behind `Fixes::REV3`. | `chain_two_holders_rev3_livelocks` reproduces the livelock: a G10 failure with 12 claim changes in 11 ticks. `chain_two_holders_settle` passes under revision 4 (132 states). `chain_handoff` passes (14,437 states). |
| Take racing a delayed pass loses SA | **R2a** (`LatePass`). | `h5_take_races_delayed_pass`: revision 3 never tells `b`'s application SA; revision 4 reports it. Sim: with R2 off, 12/500 seeds fail. |
| Released holder restarts and overwrites newer state | **R2c** (tombstone persisted). | `h5_released_restart_does_not_overwrite`: revision 3 overwrites N; revision 4 keeps N. Vector `release`. |
| Pass emitted before its claim is persisted | **R3**: `adopt` (which persists) runs before `Send(pass)`; release and leave persist before `bye`. | `crash_prefixes` (26,709 + 5,835 states): G12/G1, and G3 including "no holder frame under a claim passed away". |
| Session-key bootstrap, nonces | **R4**: codec layer (delegation in the clear, per-key key, nonce = `n`). The `fresh`/`echo` gate is in the machine and used when the codec passes `key` and `n`. | Vector `freshness`. |
| Submit neither at-most- nor at-least-once | **R5**: at-least-once with resends and `SubmitFailed`. | `h5_submit_across_holder_change`: revision 3 orders nothing and tells no one; revision 4 orders X at least once. |
| Unbounded `ordered`, append growth, overflow | **R6**: last `tail` ids; `tail` early messages; `append` keeps the last `tail` payloads; checked arithmetic; `MAX_INT`; oversize frames dropped; ids are 16-byte unpadded base64url. | `offset.json` now uses 2^53−1 instead of `u64::MAX`. |
| Pass need not answer an ask | **R7**: `Pass` is rejected unless the member's ask is pending under the current claim. Asks are cleared on claim change, decline and `bye leaving`. | Explorer passes only to asks the machine recorded. |
| Explorer heals to a mesh, one FIFO suffix; weak G5 | **H1/H2**. | See above. |

### Where revision 4 is wrong or incomplete (the explorer and simulator contradict it)

- **R1b/R1c. Evidence never reaches a silent member** (spec gap; fixed beyond revision 4, switch `evidence_push`). Revision 4 corrects only holder frames and `take`. A member with no claim, or with a lesser claim, that is not a holder sends neither. On the chain, `c` joined before `a` took, and it never learns the holder.
  - Trace: `rev4_text_counterexamples`, first case. It fails G4 with `c has None but the holder a has 1.0.a`.
  - Fix: evidence also answers a `hello` that names a lesser claim or none. Each member remembers the claim named in every peer's last `hello` and forwards new evidence to peers that are behind.
- **R1d. G5's askTimeoutMs bound does not hold** (guarantee contradicted; reported, not fixed).
  - `b` asks while the holder `a` (3.0.a) has just been cut off, and takes 2.0.b on time.
  - `c` heard `a` less than holderTimeoutMs ago and forwards `a`'s state as evidence. `b` yields to a holder that nobody can reach. `b`'s want is gone, so it never takes again.
  - Trace: printed by `COLOPHON_EXPLORE_SHOW_R1D=1`; 11 states in `three_members_handoff`.
  - Keeping the want after such a yield livelocks: two members that each took because they wanted to take from each other every askTimeoutMs, because askTimeoutMs < beatMs. G10 fails at once.
  - Proposal: G5 promises holderTimeoutMs + askTimeoutMs when evidence is involved, and a writer displaced by evidence of a holder that then lapses may take again.
- **R1e. A returning holder wins on a missed-beats testimony** (spec bug; fixed beyond revision 4, switch `renew_guard`). Revision 4 moved the "link has worked for holderTimeoutMs" guard from the renewer to the witness. Under loss, a witness can miss three beats of a live holder and report `heard: lapsed`.
  - Trace: sim playback seed 943. `1b` returns lapsed and retakes 4.0.1b, which is below 2c's live 4.0.2c. `0a` missed 2c's beats, so `0a`'s `hello` says lapsed, and `1b` renews to 5.0.1b, displacing the live holder.
  - Fix: keep the guard on the renewer as well. (No seed among the first 500 fails with the guard off; seed 943 appears in a 2,000-seed run.)
- **R2d. One `yielded` resend does not survive two losses** (spec bug; fixed beyond revision 4, switch `yielded_retry`).
  - Trace: `rev4_text_counterexamples`, second case. Both copies are lost to the cap, which fails G11. Sim: 6/500 playback seeds fail.
  - Fix: resend on hearing the new holder, and on ticks while it was heard within holderTimeoutMs; at most once per askTimeoutMs, 8 times.
- **R2e. A pass's snapshot is lost when the holder renews first on a `hello`** (spec bug; fixed). The passer, which accepted `next`, answers the taker's lesser `take` with a `hello` naming `next`. The taker renews on that `hello` before the delayed pass arrives. The pass then names a lesser claim and is dropped without a report.
  - Fix: a pass naming a holder that has moved past it is still reported once (`LatePass`). Covered by `h5_take_races_delayed_pass`.
- **R2f. G11 cannot be guaranteed without an acknowledgement** (guarantee contradicted; reported). If the taker is itself displaced and never speaks to the displaced member again, or if every resend falls inside a partition, no bounded resend scheme delivers the report.
  - Explorer: 33 completions in the two-holder profile. Sim: 2 of 2,000 random seeds, for example seed 485. These are counted and reported, not failed.
  - Proposal: the new holder acknowledges `yielded`, and the displaced member resends on every frame from it until it is acknowledged.
- **R4a. The freshness answer rule loops** (spec bug; fixed). As written, "answer each `hello` ... whose `fresh` it has not answered" makes two members answer each other's answers forever, because every answer carries a new `fresh`.
  - Fix: do not answer a `hello` that itself echoes one of this member's `fresh` values, unless that `hello` just opened the window. The handshake then ends after four hellos (vector `freshness`).
- **R5a.** A submitter that becomes holder orders its own pending submits.
- **G11 and crashes.** A displaced holder that crashes before its `yielded` goes out cannot report a state it no longer has. G12 does not cover G11. The ghost ledger drops such entries.
- **Forwarded frames and the `n` window.** A forwarded frame keeps its origin's `n`. A receiver whose window for that origin has moved more than 128 past that `n` drops it, so the evidence is lost and the next correction resends it. The simulator does not model the window for forwarded frames.
- **Implementation choices.**
  - Ask liveness uses a "heard since ask" flag rather than comparing timestamps; a beat in the same millisecond as the ask counts.
  - `Pass` is rejected when its snapshot exceeds `maxPayload`.

## R (continued). Revision 5

**Status:** revision 5 (`7c07150`) adopts R1c, R1e, R2e, R4a and R5a as implemented.

It decides R2d, R2f and R1d differently, and the machine now follows those decisions:

- **R2d/R2f:** `ack {yielded}`. The displaced member resends `yielded` to its current holder whenever it hears that holder directly, at most once per askTimeoutMs, until an `ack` arrives.
- **R1d:** forwarded evidence does not count for the ask-timeout take. A writer displaced by evidence keeps wanting and takes once that holder is lapsed to it.
- **§S3 evidence without a window:** only the frame's claim is used, and the holder counts as heard. The carrier reports this with `Input::Frame.forwarded {via, windowed}`. The simulator decides `windowed` from its 128-wide `n` window.

`Fixes::ALL` is revision 5 plus R1f, R1g and R1h below. `Fixes::REV5`, `REV4` and `REV3` are regression presets.

**Evidence.** These checks are now strict; none is "counted, not failed":

- **G11:** a displaced member that keeps running and can talk to its component's holder must have had its state reported. Crashes are excluded.
- **G5:** the bound is askTimeoutMs, or holderTimeoutMs + askTimeoutMs from the last forwarded evidence.

| Test | What it shows |
| --- | --- |
| `rev4_counterexamples` | Revision 4 fails each of these, as expected: G4 without R1c, G11 without the `ack`, G5 without R1d. |
| Vector `want-kept-after-evidence` | `x` yields to evidence, does not take on the ask timeout, and takes 3.0.x once `z` is lapsed. |
| Vectors `stale-evidence` and `evidence-forward` | A windowless or replayed evidence frame only makes a member accept a claim that was once real. The member keeps its own state, then lapses and takes. |

### R1f. Revision 5 livelocks on the chain (spec bug; fixed beyond revision 5, switch `evidence_refresh`)

**Trace.** `chain_two_holders_rev5_livelocks` runs a↔b↔c with a↮c, both `a` and `c` having taken because they wanted the role, and no application command. G10 fails: 11 claim changes in 11 ticks.

1. `a` yields to `c`'s claim, relayed by `b`. Under R1d it keeps wanting.
2. `c` is lapsed to `a` after holderTimeoutMs, because `a` never hears `c` directly. `a` takes.
3. `b` relays `a`'s claim to `c`. `c` yields and keeps wanting.
4. And so on, forever. Revision 5 says this loop cannot happen; it only cannot happen between members that hear each other.

**Fix.** A want kept after evidence takes only askTimeoutMs after its lapse `hello` (which goes to all). A member that still has fresh evidence of that holder answers such a `hello` (heard: lapsed, naming its own claim) with the evidence; a holder answers it with `state`. The lapse then clears and the claims stop changing: `chain_two_holders_settle` covers 1,023 states. G5's bound, holderTimeoutMs + askTimeoutMs from the last evidence, still holds.

**Proposed spec text (§S5, after "keeps wanting the role").** "It takes only `askTimeoutMs` after its lapse `hello`. A member that accepted a holder frame of that claim within `holderTimeoutMs` answers a `hello` that reports that holder `lapsed` with the frame, as evidence."

### Machine bugs the revision 5 harness caught

- **Lesser-claim ordering.** The machine still ordered a reported rank-1 claim of another holder as rank 0, a leftover from revision 1. On the two-holder start, a holder and a listener answered each other forever with `state` and `hello`. That order now applies only under `Fixes::LITERAL`.
- **Report before ack.** The holder emitted `ack` before its `Displaced` event. A crash between the two would lose the report, and `crash_prefixes` caught it. The event now comes first.

### R1g. A kept want hands the role back to a returning holder (reading; fixed)

**Trace.** Sim playback seed 18, out of 2,000.

1. `1b` returns after an outage and yields to `2c`'s claim. Evidence relayed by `0a` arrives before `2c`'s direct `state`, so `1b` yields to evidence and keeps wanting under R1d.
2. `1b` asks `2c` at once.
3. The playback application passes on every ask, so `1b` holds again. That contradicts §S6: the returning holder should yield.

**Cause.** Revision 5 keeps the want of a writer that yields to evidence "of a holder it cannot reach". At the moment of yielding, the member cannot know whether the holder is reachable.

**Reading applied.**

- A want kept only because the member had taken does not ask. It waits for the lapse.
- If the member hears the holder directly, the want is dropped. A want that the application had asked for is kept, but it is no longer limited to the lapse rule.

### R1h. Forwarded evidence must not renew evidence (spec gap; fixed)

**Trace.** With the holder cut off, two non-holders that store each other's forwarded frames as evidence keep the dead holder "fresh" for each other forever. The strict G5 completion on the two-holder start never ended (the G5 deadline kept moving).

**Reading applied.** Only a frame heard directly from its holder becomes evidence, and its age is the age of that direct hearing.

**Proposed spec text (§S4 evidence).** "The most recent holder frame it accepted directly from the greater claim's holder."

**Ablation (500 seeds; seeds failing, random/playback).** Revision 5 as written: 0/23, first failure seed 18 (R1g). Revision 4: 4/6. Revision 3: 10/11. Without the `ack`: 1/6. Without R2: 12/12. With every fix: 0/0.

**Results under revision 5.** Explorer 16/16, with G4, G5 (revision 5 bound), G10, G11 (strict) and G12. Sim: 2,000 random and 2,000 playback seeds pass. Vectors: 21 scenarios plus `offset.json`. The vectors include `ack`, `stale-evidence`, `want-kept-after-evidence`, and windowless `evidence-forward`.

## S. Second independent design review and revision 7

The second independent review judged revision 6 unsound. In summary, it found:

- one-hop evidence cannot carry a claim along a chain of four members, so the two ends renew over each other forever (G4, G10);
- an `append` state can outgrow the frame limit;
- windowless evidence can be replayed to keep a dead holder alive;
- `ack` and `yielded` were not checked against their sender;
- freshness windows grew without bound;
- the clock assumption was unstated;
- the evidence covered only three members, one chain and crash points 0–3.

**Revision 7** splits the design into two layers:

- **Carriers bridge (§S9).** Inside a connected group every frame sent to all reaches every member. This is `crate::v06::bridge`.
- **The session rules assume that group.** Evidence forwarding, `hello.heard`, windowless evidence and the kept-want rules are gone. Correcting lesser claims with `hello`, and renewing on a quiet claim after the holder's own link has worked holderTimeoutMs, are back.

`Fixes::ALL` is revision 7. `Fixes::REV6`, `REV5`, `REV4` and `REV3` are kept as regression presets.

| Review item | Resolution | Evidence |
| --- | --- | --- |
| Four-member chain, holders at both ends, endless renewal | **Bridging (§S9)**, with the session rules written for a fully reachable group. | `v06_session_bridged`: reproduced. Under revision 6 without bridging, every fair schedule fails G10 with 15 claim changes in the last 80 s. Revision 7 with bridging settles on one holder and one state for chains of 3, 4 and 5, a five-member ring and a five-member star, under all three schedules, over 200 s. |
| `append` snapshot can exceed `maxPayload` | `Fold::apply_bounded`: the oldest payloads are dropped until the encoded state fits. | `append_state_fits_a_frame`: revision 6 produces a 68-byte state against a 64-byte limit and the joiner cannot sync; revision 7 does not. Vector `append-bound`. |
| Windowless evidence replay | Removed, together with evidence (revision 7). | — |
| `ack`/`yielded` sender | `yielded` is accepted only from its claim's holder, `ack` only from the accepted holder. | `third_writer_cannot_clear_or_inject_reports`: revision 6 accepted the injected `yielded`. |
| Unbounded freshness windows | At most 4 keys per member, oldest dropped; `Session::forget_member` drops them all. | `freshness_windows_are_bounded`. |
| Clock assumption | §S0: within 500 ppm, and a stall delays only the stalled member's own timeouts. | The simulator draws drift of ±500 ppm. About one random seed in five stalls one member's clock for up to 30 s. 2,000 random and 2,000 playback seeds pass. Take accuracy is not checked for stalled members. |
| Three identities, one chain, crash points 0–3 | Bridge tests on 2–6 members. Session-on-bridge runs with 3–5 members. Explorer: bridged chain, groups that split and merge, and every output prefix for G12. | `v06_bridge`; `v06_session_bridged`; `crash_prefixes`, `groups_split_merge`. |

### Observations on revision 7

- **B1. Resending the same `n` does not cross a bridge.** A bridge that already accepted a frame drops the resend and does not forward it again, so a copy lost beyond the first hop is repaired only by a new frame with a new `n` (`same_n_resend_does_not_cross_a_bridge`). The session layer's beats, answers and resends provide such frames. The spec should say that retransmission means new frames.
- **B2. Bridging and freshness interact** (not modelled). Under §S3 a member accepts non-`hello` frames only from keys with an open window, so a bridge forwards a member's frames only after its own freshness exchange with that member. Until then those frames do not cross the bridge and are not forwarded later; later frames repair this. With the four-key cap, a frame of an evicted key could be accepted and flooded once more. Both effects are bounded, but the test bridge here windows every key without a handshake.
- **B3. Outside the model, the rules give no protection.** On an unbridged four-member chain, revision 7 leaves the two end holders in place indefinitely: G4 fails while G10 holds (`rev7_without_bridging_is_outside_the_model`). Revision 7 states this assumption; a deployment must bridge.
- **B4. `append` and a payload of exactly `maxPayload`.** Such a payload does not fit even alone once its 4-byte frame is added, so the state becomes empty. Proposal: limit `append` payloads to `maxPayload − 4`.

**Ablation under revision 7** (500 seeds; seeds failing, random / playback):

| Preset or fix turned off | Random | Playback |
| --- | --- | --- |
| None (revision 7) | 0 | 0 |
| Revision 6 | 0 | 0 |
| Revision 5 | 0 | 20 |
| Revision 4 | 1 | 4 |
| Revision 3 | 7 | 11 |
| Revision 1 | 154 | 152 |
| Without F1 | 44 | 0 |
| Without F2 | 120 | 31 |
| Without F9 | 0 | 37 |
| Without F10 | 0 | 16 |
| Without R2 | 9 | 19 |
| Without the `ack` | 0 | 7 |

The simulator's network is complete, so the hello-correction and renewal rules of revision 7 are exercised by `v06_session_bridged` and the explorer rather than by the simulator.

**Explorer state counts under revision 7** (18 explorer tests, plus the three new targeted tests):

| Profile | States |
| --- | --- |
| Two members, handoff | 128,648 |
| Two members, membership | 311,415 |
| Three members, handoff | 85,237 |
| Three members, membership | 176,120 |
| Groups split and merge | 80,836 |
| Bridged chain, handoff | 23,098 |
| Bridged chain, two holders | 624 |
| Two holders passing to one asker | 128,486 |
| Crash prefixes, every prefix | 26,247 + 5,694 |

## Where the machine and the spec differed (resolved 2026-11-23)

Revision 2 was narrower than the machine in three places. Each was tested by narrowing the machine to the spec text and rerunning the whole explorer (including the two-holder start) and the simulator (1,000 random seeds and 1,000 playback seeds). Nothing failed in any of the three, so the machine has been narrowed to the spec text and the spec needs no widening:

- **N1.** A holder now corrects a lesser claim with `state` only in holder frames and `take` (§S4). Previously it also did so in `ask`, `decline` and `pass`. (A `hello` is still answered under §S8, as before.)
- **N2.** A member that released now resends `bye` only for a holder frame or `take` under a strictly lesser claim (§S4).
- **N3.** The once-per-second limit now applies only to gap `hello`s (§S8). The repeated "no snapshot yet" `hello` that a beat triggers is no longer limited.
- **Automatic ordering of submits (F18).** This remains a choice of this layer.

Everything else in revisions 2 and 3 is checked against the machine and matches exactly, including revision 3's `via` and rule 3:
- `seen.seq` is `null` (§S3).
- Lapsing counts only holder frames under the accepted claim, from the later of the last such frame and the last link-up, and the listener then sends `hello` to all (§S6).
- Ask resend (§S5).
- The four renewal triggers, with a renewal target of "not less than its own" and the link-has-worked guard (§S5).
- `bye.leaving`; release is `leaving: false` (§S5).
- `take` has no `basis`.
- `Join` and `Take` carry the application's state, and the restarted holder retakes with it (§S6).
- `policy.fold` (§S1).

## Take accuracy (§S12)

Over 3,000 playback seeds and 3,000 random seeds:

- **Clocks:** offsets up to 10^9 ms and drift of ±200 ppm per member.
- **Carriers:** home latency 30–150 ms with up to 200 ms jitter and up to 20 % loss.
- **Passes:** every pass started exactly at the stopped position.
- **Takes:** the worst take error was 107 ms. The bound
  `rate × (ceil(rtt/2) + |drift difference| × sample age + 3 ms)` was never exceeded; the
  largest bound computed was 292 ms.
