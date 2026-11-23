# Colophon 0.6 sessions: findings from the reference machine

**Date:** 2026-11-22. **Against:** `spec/colophon-0.6-sessions.md` (unfrozen draft of the same
day). **Code:** `crates/colophon-core/src/v06/session/`.

The reference machine implements the draft, and also the departures listed here. Each
departure that changes behaviour has a switch in `Fixes`. `Fixes::default()` (= `ALL`) is the
reference reading, and `Fixes::LITERAL` is the draft as written, so every counterexample below
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
| F12 | Two passes can name the same `next` | spec bug (not reproduced) | analysis |
| F13–F20 | Smaller readings | ambiguity or choice | — |

Every 300-seed and 1,000-seed simulator run and every explorer profile passes with all fixes
on.

## F1. Rank-1 acceptance strands members (spec bug)

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

**Proposed spec text.** "For rank 1, the frame is from `claim.holder`, or is a `pass` from
`pass.claim.holder` with `next = claim`."

## F2. `hello.seen` cannot say "no snapshot" (spec bug)

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

**Proposed spec text.** "`seq` is `null` when the member holds no state for that claim."

## F3. Whether the passer accepts its own `next` (ambiguity)

**Spec.** The spec says the passer "is not holder" from the moment it sends `pass`. It does
not say which claim the passer then holds.

**Reading.** The passer accepts `next`, with `snapshot` as its state. Rule 3, read literally,
lets it do so: it is "the holder of the previous claim".

**Why it matters.** If the passer kept the old claim, a `take` by the asker at the same term
would supersede the pass silently, and the resend rule of §S5 would never fire.

## F4. Pass resend contradicts G2/G3 (wording)

**Spec.** §S5 says the passer "resends the same `pass` when it next hears the asker speak
under an older claim". A `pass` is a holder frame, and it is sent under the old claim, which
is now less than the passer's accepted claim. That breaks G2 and G3 as worded.

**Checker.** The checker exempts an identical resend of a pass the member already sent.

**Proposal.** G2 and G3 should say "other than a resend of the same `pass`".

## F5–F7. A claim whose holder has gone quiet is never corrected (spec bug, as a group)

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

**Proposal.** Extend §S4 "Stale holders" to every member: a member that meets a holder frame
under a lesser claim answers with `hello`. Read "not present" in renewing as "not heard
holding".

**G4 note (wording).** With no live holder, nothing need be sent. Members can then keep
different dead claims, or see "no holder" (a `bye` arrived) against "lapsed holder" (the `bye`
was lost). The checker therefore applies G4's claim agreement only while a holder is live. The
next take or renewal restores agreement. G4 should be stated for a live holder.

## F8. Pings and pongs keep a non-holder "alive" (spec bug)

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

**Spec.** The asker may take only when it has "heard nothing from the holder for
`askTimeoutMs`". The draft never resends an `ask`.

**Counterexample (playback seed 6; 151 of 1,000 seeds fail with the fix off).**

1. `1b`'s ask is lost.
2. `0a` keeps beating, so `1b` keeps hearing it.
3. `1b` waits forever. G5 does not cover this case, because the holder is reachable.

**Fix applied (`ask_resend`).** An asker that heard the holder but got no `pass` or `decline`
within `askTimeoutMs` sends `ask` again.

## F10. Renewal by a member that has just returned steals the role (spec bug)

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

**Proposal.** "Once a frame carrying the greater claim, from that claim's holder, reaches the
other, the other stops."

## F12. Two passes can name the same `next` (spec bug, not reproduced)

**Scenario.**

1. `A` holds `T.0.A` and `B` holds `T.0.B`, partitioned from each other.
2. `X` asks `A`, then accepts `B`'s claim and re-asks `B`.
3. Both pass, and both passes name `next = (T+1).1.X`, with different snapshots.
4. Members that accept different passes hold the same claim at seq 0 with different states.
   That breaks G3 ("the new holder's initial state equals the pass snapshot") and G4.

**Checker.** The checker flags two passes that name the same `next` with different snapshots.
Neither the explorer at its bounds nor the simulator produced one.

**Proposal.** A holder made by a pass renews when it meets a different `pass` naming its
claim. Alternatively, put the passer's claim in rank-1 ordering.

## F13–F20. Smaller readings (ambiguity or implementation choice)

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

## Take accuracy (§S12)

Over 3,000 playback seeds and 3,000 random seeds:

- **Clocks:** offsets up to 10^9 ms and drift of ±200 ppm per member.
- **Carriers:** home latency 30–150 ms with up to 200 ms jitter and up to 20 % loss.
- **Passes:** every pass started exactly at the stopped position.
- **Takes:** the worst take error was 107 ms. The bound
  `rate × (ceil(rtt/2) + |drift difference| × sample age + 3 ms)` was never exceeded; the
  largest bound computed was 292 ms.
