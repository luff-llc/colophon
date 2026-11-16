# Several homes per account: what works and what is open

Colophon 0.5 supports one home per account. An account may appoint more, and verifiers judge it
by the same rules. But exchange between homes (forwarding entries, heads and candidates) is
experimental in 0.5 and not part of the freeze (spec §13.1). This list is where the 0.6 work starts.
It comes from the three independent checks of PR 28 (2026-11-15, 2026-11-16, and the third check
on 2026-11-16) and from the builder's own notes.

## What works today

These are the two-home tests in `crates/colophon-home-wasm/tests/v05_relay_h2.rs`. Each runs real
relay processes and passed 30 of 30 runs on the Mac at the end of PR 28.

- **Quorum 2, a late veto.** A veto that reaches a home more than 300 s late is stored there when
  it comes with another home's receipt that was in window (`a_late_veto_is_stored_with_another_homes_in_window_receipt_and_signs_none`).
- **Catching up after being offline.** A home that was down for 20 minutes catches up from a
  device's pass and signs heads again, one digest per seq (`an_offline_home_catches_up_from_a_device_and_signs_heads_again`).
- **A home down for a whole window.** It stores the `activate` it never saw (`a_home_that_was_down_during_a_window_stores_the_activate_it_never_saw`).
- **The entry behind a `final`.** A home that recorded `final` first gives its peer the entry,
  so the peer can sign a head over it (`a_home_that_recorded_final_first_gives_its_peer_the_entry`).
- **No stale heads.** A head that is due is not forwarded until it is signed (`a_head_due_to_be_replaced_is_not_forwarded`).
- **A fork and its resolve.** A fork caused by an equivocating primary is held, served, and settled
  by a `resolve`, and devices then sync to the result (`a_home_holding_a_fork_serves_it_refuses_what_depends_on_it_and_admits_a_resolve`).
- **A one-entry fork between two homes.** It converges by candidate exchange (`homes_on_different_branches_exchange_candidates_and_converge`).
- **A silent peer.** It delays no other peer (`a_silent_peer_does_not_hold_up_forwarding_to_the_others`).

## Open issues

Each item gives where it is, what goes wrong, and the fix proposed.

1. **Forks deeper than 63 entries never converge.**
   - Where: `crates/colophon-home-wasm/src/ops.rs`, `forward_entries` (`from = (shared + 1).max(seq.saturating_sub(63))`).
   - What goes wrong: when the peer's head is more than 64 entries past the last shared entry, the
     sender starts 63 before the head. The receiver lacks that entry's parent and refuses it (409),
     and every pass sends the same suffix.
   - Proposed fix: page forward from the last shared entry, one 64-entry request per pass, keeping
     a per-peer exchange cursor in `forward.json`. The receiver stores each page as candidates (its
     parent is then held). Specify the procedure in §13.1.
2. **One home can recycle its candidate slot.**
   - Where: `crates/colophon-core/src/v05/history/home.rs`, `admit_candidate` (`slot_free`), with
     `kept_heads` keeping only four off-branch heads per home.
   - What goes wrong: slot ownership is rebuilt from the heads the home still keeps. A home that
     posts newer off-branch heads pushes out its old covering head, then covers a new candidate.
     Repeating this fills all four slots, and an honest candidate can no longer be exchanged.
   - Proposed fix: record each kept candidate's covering home with the candidate itself, in the
     checkpoint, not derived from current heads. Never count a home twice at one seq.
3. **Standing candidates are unbounded at one seq.**
   - Where: `admit_candidate`, the `stands || (forks && covered)` branch, which runs before the
     per-seq bound is checked.
   - What goes wrong: a controller who can produce successively better recording candidates (for
     example by grinding digests under §8.6's order) gets each new winner stored. Displaced winners
     are never removed.
   - Proposed fix: when a new candidate stands, drop the displaced non-standing candidates beyond
     the bound, keeping the evidence §13.3 needs (one per covering home).
4. **A head can go out before an entry it covers.**
   - Where: `relay/home.js`, `forwardEntries`. `fwd` is computed under the lock, the request goes
     out without it, and `putHead()` takes the lock again later.
   - What goes wrong: an entry appended in between gets a head that is sent without its entry. The
     peer then holds a head ahead of what it can verify, until the next pass.
   - Proposed fix: take the head and the entries in one module call under one lock (the head over
     exactly the last entry sent), or send no head newer than the entries just sent.
5. **The 15 s pass limit is not enforced around entries and the head.**
   - Where: `relay/home.js`, `forwardTo` and `forwardEntries`.
   - What goes wrong: after the new-object offers use up the deadline, the entries request, the
     head request and a forced retry still run, each with a 5 s limit. A pass can take about 30 s.
     Other peers are not affected.
   - Proposed fix: check the deadline before each request, and give each request the smaller of
     5 s and the time left.
6. **The spec text for deep forks and batch judging is incomplete.**
   - Where: `spec/colophon-0.5.md` §13.1 (candidate exchange) and §14 (`POST {base}/authority`).
   - What goes wrong: "from the seq after the last shared entry, at most 64 entries" gives no
     interoperable procedure past 64. §14 does not say that a home keeps judging the rest of a
     request after storing a candidate it answers with 409 or `refused:fork`; another
     implementation may stop at the first conflict.
   - Proposed fix: write the paging procedure of item 1. In §14, require judging every entry of a
     request after a stored candidate.
7. **Up to three hostile homes can keep an honest non-standing candidate out.**
   - Where: `admit_candidate`, the per-seq bound (`CANDIDATES_PER_SEQ`, 4).
   - What goes wrong: with the home's own entry and three slots taken by candidates that three
     other homes cover, a fourth home's candidate that does not stand is refused. A standing
     candidate is always stored.
   - Proposed fix: one slot per current home (at most 8) instead of a fixed 4, once item 2 makes
     slot ownership durable.
8. **The tests do not reach the failure cases above.**
   - Where: `v05_relay_h2.rs`, `v05_home_h2.rs`, `relay/test/forward.test.js`.
   - What goes wrong: the exchange test has a one-entry fork, and the evidence test never evicts a
     covering head or reaches four candidates. The silent-peer test does not crash mid-pass or
     check the deadline. The fork test waits until both homes agree before devices sync, so it
     does not show what a device sees while the homes exchange.
   - Proposed fix: one test per item above, written first. Add a device test during exchange
     (expect `refused:fork` or 503, never a wrong history).
9. **Another test port picker remains.**
   - Where: `crates/colophon-ffi/tests/v05_relay/mod.rs` (`free_port`).
   - What goes wrong: a port is probed and released before the relay binds it, so a parallel test
     can take it.
   - Proposed fix: start on port 0 and use the resolve file, as `support_relay` now does.

Fixed during PR 28, for the record:

- a candidate `activate` that skipped the late-activation rule;
- homes on different branches that never reconciled (one-entry case);
- a slow peer that blocked the others;
- a resend time that was not durable;
- an old full set kept as evidence (third check, finding 3);
- a forwarding cursor saved without its retries (third check, finding 1).
