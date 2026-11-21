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

6. **The spec text for deep forks and batch judging is incomplete.**
   - Where: `spec/colophon-0.5.md` §13.1 (candidate exchange) and §14 (`POST {base}/authority`).
   - What goes wrong: "from the seq after the last shared entry, at most 64 entries" gives no
     interoperable procedure past 64. §14 does not say that a home keeps judging the rest of a
     request after storing a candidate it answers with 409 or `refused:fork`; another
     implementation may stop at the first conflict.
   - Proposed fix: write the paging procedure of item 1. In §14, require judging every entry of a
     request after a stored candidate.

## Fixed

The safety follow-up on `fix/multi-home-safety` fixes items **#2, #3, #4, #5, #7,
#8 (for these fixes), and #9**:

- **#2 / #7: durable, per-home candidate slots.** `HomeState` persists each evidence slot's
  covering home and candidate digest, independently of retained heads. A home cannot recycle
  its slot when its covering head is evicted. Each current home has one evidence slot (at most
  eight), with the standing entry also retained. The serde-defaulted field keeps version-2
  checkpoints readable. On first use at a seq, legacy evidence is assigned from held heads;
  a legacy candidate whose covering head was already evicted owns no home's slot and does not
  block honest homes from claiming their evidence slots at that seq.
- **#3: bounded displaced winners.** When a candidate stands, the checkpoint retains that
  winner and at most one evidence candidate per covering home at the seq. Displaced winners
  without an evidence slot are removed; repeated recording-candidate grinding cannot grow
  the seq without bound. Rebuilding preserves head marks, the stop floor and high-water mark.
- **#4: a consistent forwarding snapshot.** The relay settles and captures the head and entries
  under one lock, before any network request. An append during forwarding cannot advance the
  captured head past the entries sent. Candidate exchange still sends the covering head first,
  as required to admit non-standing evidence; ordinary catch-up sends entries first.
- **#5: one request deadline for the whole pass.** New-object offers, backlog offers, entries,
  the head and a forced entries retry all check the remaining 15 s budget immediately before
  a request and use the smaller of 5 s and that remainder. Local lock/storage work can still
  delay completion, but cannot start another network timeout past the deadline.
- **#8: focused regressions.** Core tests evict the covering head, serialize and restore the
  home checkpoint, exercise all eight homes, and grind 32 successive recording candidates.
  Host tests append during an entries request and exhaust the deadline across offers, entries,
  head and retry. The real-relay fork test syncs a device while forwarding is running and
  asserts `refused:fork` / 503 until the fork is resolved. Deep-fork paging tests remain with
  #1 / #6 and require the spec revision described above.
- **#9: no probe-and-release port picker.** FFI journeys start every relay on port 0, read its
  bound port from the listening announcement, then atomically publish peer mappings through
  the resolve file, matching `support_relay`.

### Fixed during PR 28

- a candidate `activate` that skipped the late-activation rule;
- homes on different branches that never reconciled (one-entry case);
- a slow peer that blocked the others;
- a resend time that was not durable;
- an old full set kept as evidence (third check, finding 3);
- a forwarding cursor saved without its retries (third check, finding 1).
