//! Shared invariant checks for the 0.6 session explorer, simulator and vectors.
#![allow(dead_code, clippy::unwrap_used)]
use colophon_core::v06::session::*;
use std::collections::{BTreeMap, BTreeSet};

/// Ghost state kept beside the members to check G2/G3 (part of the explored state).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ghost {
    /// Every fresh `pass` ever sent: next → snapshots (more than one is a G3 failure).
    pub pass_snaps: BTreeMap<Claim, BTreeSet<Bytes>>,
    /// Per member, the passes it sent (claim, next, snapshot), so resends are recognised.
    pub sent: BTreeMap<String, BTreeSet<(Claim, Claim, Bytes)>>,
    /// Per member, the greatest claim its own frames revealed as its accepted claim (take,
    /// its holder frames, a fresh pass's `next`): after any crash and restart its accepted
    /// claim must not be less (G1 under G12).
    pub exposed: BTreeMap<String, Claim>,
    /// Per member, claims whose release it revealed with a `bye` (G12: not resurrected).
    pub released: BTreeMap<String, BTreeSet<Claim>>,
    /// G11: state a displaced holder owes the member that took over: (new holder,
    /// displaced holder, the claim it held). Cleared when the new holder reports it.
    pub owed: BTreeSet<(String, String, Claim)>,
}

impl Ghost {
    fn expose(&mut self, me: &str, c: &Claim) {
        let e = self.exposed.entry(me.to_owned()).or_insert_with(|| c.clone());
        if *c > *e {
            *e = c.clone();
        }
    }
    /// G1/G12 after a restart: the member's accepted claim is not below what it revealed,
    /// and it does not act as holder of a claim it revealed as released.
    pub fn check_restart(&self, s: &Session) -> Result<(), String> {
        if let Some(e) = self.exposed.get(s.me()) {
            if s.accepted() < Some(e) {
                return Err(format!(
                    "G12/G1: {} restarted at {:?} below the claim {} it had revealed",
                    s.me(),
                    s.accepted().map(show_claim),
                    show_claim(e)
                ));
            }
        }
        Ok(())
    }
}

/// G1, G2 and G3 for one `handle` call of member `me`.
///
/// - G1: `accepted` after ≥ `accepted` before.
/// - G2: every holder frame other than `pass` and `refuse` carries a claim ≥ the sender's
///   accepted claim after the step, held by the sender; a fresh `pass` carries the claim the
///   sender held before the step. An identical resend of an earlier pass is exempt (finding F4).
/// - G3: a member that sent a pass never later sends a non-pass holder frame under the old
///   claim (implied by G2, since the passer's accepted claim is `next`); two passes never name
///   the same `next` with different snapshots; a holder made by a pass starts with exactly its
///   snapshot.
pub fn check_step(
    ghost: &mut Ghost,
    me: &str,
    before: &Session,
    after: &Session,
    outs: &[Output],
) -> Result<(), String> {
    check_step_input(ghost, me, before, after, outs, None)
}

/// [`check_step`] with the delivered frame, for the G11 late-pass check: a holder that renews
/// because a `pass` naming it arrived must report that pass's snapshot (`LatePass`).
pub fn check_step_input(
    ghost: &mut Ghost,
    me: &str,
    before: &Session,
    after: &Session,
    outs: &[Output],
    delivered: Option<&Frame>,
) -> Result<(), String> {
    if before.accepted() > after.accepted() {
        return Err(format!(
            "G1: {me} accepted claim decreased {:?} -> {:?}",
            before.accepted(),
            after.accepted()
        ));
    }
    if let Some(Frame {
        body: Body::Pass { next, snapshot, .. },
        ..
    }) = delivered
    {
        let renewed = outs.iter().any(|o| {
            matches!(o, Output::Event { event: Event::BecameHolder { via: Via::Renew, .. } })
        });
        if next.holder == me && before.is_holder() && renewed {
            let reported = outs.iter().any(|o| {
                matches!(o, Output::Event { event: Event::LatePass { snapshot: s, .. } } if s == snapshot)
            });
            if !reported {
                return Err(format!(
                    "G11: {me} renewed over a late pass {} without reporting its snapshot",
                    show_claim(next)
                ));
            }
        }
    }
    for o in outs {
        if let Output::Event { event } = o {
            match event {
                Event::Yielded { to } if to.rank == 0 => {
                    if let Some(held) = before.accepted() {
                        ghost
                            .owed
                            .insert((to.holder.clone(), me.to_owned(), held.clone()));
                    }
                }
                Event::Displaced { from, claim, .. } => {
                    ghost.owed.remove(&(me.to_owned(), from.clone(), claim.clone()));
                }
                Event::BecameHolder { .. } => {
                    // A displaced member that holds again kept its own state.
                    ghost.owed.retain(|(_, d, _)| d != me);
                }
                _ => {}
            }
        }
    }
    for o in outs {
        match o {
            Output::Send { frame } => {
                if let Body::Bye { claim: Some(c), .. } = &frame.body {
                    if c.holder == me {
                        ghost.released.entry(me.to_owned()).or_default().insert(c.clone());
                    }
                }
                if matches!(frame.body, Body::Take { .. }) || frame.body.is_holder_frame() {
                    if let (Some(c), false) = (frame.body.claim(), matches!(frame.body, Body::Pass { .. })) {
                        if c.holder == me {
                            let c = c.clone();
                            ghost.expose(me, &c);
                        }
                    }
                }
                let b = &frame.body;
                if let Body::Pass {
                    claim,
                    next,
                    snapshot,
                    ..
                } = b
                {
                    let key = (claim.clone(), next.clone(), snapshot.clone());
                    let resend = ghost.sent.get(me).is_some_and(|s| s.contains(&key));
                    if resend {
                        continue;
                    }
                    if before.accepted() != Some(claim) || !before.sends_as_holder() {
                        return Err(format!(
                            "G2: {me} sent a fresh pass under {claim:?} while accepted {:?}",
                            before.accepted()
                        ));
                    }
                    ghost.sent.entry(me.to_owned()).or_default().insert(key);
                    ghost.expose(me, next);
                    let snaps = ghost.pass_snaps.entry(next.clone()).or_default();
                    snaps.insert(snapshot.clone());
                    if snaps.len() > 1 {
                        return Err(format!(
                            "G3: two passes name {next:?} with different snapshots"
                        ));
                    }
                    continue;
                }
                if b.is_holder_frame() {
                    if let Some(c) = b.claim() {
                        let passed_away = ghost
                            .sent
                            .get(me)
                            .is_some_and(|s| s.iter().any(|(old, _, _)| old == c));
                        if passed_away {
                            return Err(format!(
                                "G3: {me} sent {} under {} after passing that claim away",
                                b.kind(),
                                show_claim(c)
                            ));
                        }
                        let tomb = ghost.released.get(me).is_some_and(|s| s.contains(c));
                        if tomb && !after.released() {
                            return Err(format!(
                                "G12: {me} sent {} under {} after releasing it",
                                b.kind(),
                                show_claim(c)
                            ));
                        }
                        if c.holder != me || after.accepted().is_none_or(|a| c < a) {
                            return Err(format!(
                                "G2: {me} sent {} under {c:?} with accepted {:?}",
                                b.kind(),
                                after.accepted()
                            ));
                        }
                    }
                }
            }
            Output::Event {
                event:
                    Event::BecameHolder {
                        claim,
                        snapshot,
                        via: Via::Pass,
                    },
            } => {
                let ok = ghost
                    .pass_snaps
                    .get(claim)
                    .is_some_and(|s| s.contains(snapshot));
                if !ok || after.state() != snapshot {
                    return Err(format!(
                        "G3: {me} became holder of {claim:?} by pass with a state other than the pass snapshot"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// G6 (operational form): once a frame carrying claim `c` from `c.holder` reaches a member,
/// that member is not acting as holder under a claim less than `c`.
pub fn check_g6(frame: &Frame, after: &Session) -> Result<(), String> {
    let Some(c) = frame.body.claim() else {
        return Ok(());
    };
    if c.holder != frame.from || matches!(frame.body, Body::Pass { .. }) {
        return Ok(());
    }
    if after.is_holder() && after.accepted().is_some_and(|a| a < c) {
        return Err(format!(
            "G6: {} still acts as holder under {:?} after {} from {} under {c:?}",
            after.me(),
            after.accepted(),
            frame.body.kind(),
            frame.from
        ));
    }
    Ok(())
}

/// G4 at quiescence: every joined member holds the same claim; if there is a holder, exactly
/// that member acts as holder (not gated) and everyone has its `(seq, state)`.
pub fn check_converged(members: &[Session]) -> Result<(), String> {
    let n = members.len();
    check_converged_topo(members, &vec![vec![true; n]; n])
}

/// G4 (revision 4) under a topology: `reach[i][j]` says frames from member `i` reach `j`.
/// Members joined by a chain of two-way edges form a component. In a component with a live
/// holder, every joined member holds the holder's claim; members the holder reaches
/// directly also hold its ordered state (the ordered lane is not relayed in 0.6). Exactly
/// one member of the component acts as holder.
pub fn check_converged_topo(members: &[Session], reach: &[Vec<bool>]) -> Result<(), String> {
    let n = members.len();
    let mut comp: Vec<usize> = (0..n).collect();
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            for j in 0..n {
                if i != j && reach[i][j] && reach[j][i] && comp[j] < comp[i] {
                    comp[i] = comp[j];
                    changed = true;
                }
            }
        }
    }
    for c in 0..n {
        let joined: Vec<usize> = (0..n).filter(|i| comp[*i] == c && members[*i].joined()).collect();
        let holders: Vec<usize> = joined.iter().copied().filter(|i| members[*i].is_holder()).collect();
        if holders.is_empty() {
            // No live holder: dead claims may differ (G4).
            continue;
        }
        if holders.len() != 1 || !members[holders[0]].sends_as_holder() {
            return Err(format!(
                "G4: {} members of one component act as holder: {:?}",
                holders.len(),
                holders.iter().map(|i| members[*i].me().to_owned()).collect::<Vec<_>>()
            ));
        }
        let h = holders[0];
        let hm = &members[h];
        for &m in &joined {
            let s = &members[m];
            if s.accepted() != hm.accepted() || s.holder() != hm.holder() {
                return Err(format!(
                    "G4: {} has {:?} (holder {:?}) but the holder {} has {:?}",
                    s.me(),
                    s.accepted().map(show_claim),
                    s.holder(),
                    hm.me(),
                    hm.accepted().map(show_claim)
                ));
            }
            if m != h && reach[h][m] && (!s.synced() || s.seq() != hm.seq() || s.state() != hm.state()) {
                return Err(format!(
                    "G4: {} at seq {} synced {} state {:?} differs from holder {} at seq {} state {:?}",
                    s.me(),
                    s.seq(),
                    s.synced(),
                    s.state(),
                    hm.me(),
                    hm.seq(),
                    hm.state()
                ));
            }
        }
    }
    Ok(())
}

/// A short readable line for an output.
pub fn show_output(o: &Output) -> String {
    match o {
        Output::Send { frame } => format!(
            "send {}->{} {}",
            frame.from,
            frame.to.as_deref().unwrap_or("*"),
            show_body(&frame.body)
        ),
        Output::Persist { claim, released } => {
            format!("persist {}{}", show_claim(claim), if *released { " (released)" } else { "" })
        }
        Output::Forward { to, frame } => format!(
            "forward ->{to} [{}'s {}]",
            frame.from,
            show_body(&frame.body)
        ),
        Output::Event { event } => format!("event {event:?}"),
    }
}
/// `term.rank.holder`.
pub fn show_claim(c: &Claim) -> String {
    match &c.via {
        Some(v) => format!("{}.{}.{}.{v}", c.term, c.rank, c.holder),
        None => format!("{}.{}.{}", c.term, c.rank, c.holder),
    }
}
/// A short readable body.
pub fn show_body(b: &Body) -> String {
    let s = |x: &Bytes| String::from_utf8_lossy(&x.0).into_owned();
    match b {
        Body::Hello { seen, lapsed, heard, .. } => format!(
            "hello seen={} heard={heard:?} lapsed={lapsed}",
            seen.as_ref().map_or("null".into(), |x| format!(
                "{}@{:?}",
                show_claim(&x.claim),
                x.seq
            ))
        ),
        Body::State {
            claim,
            seq,
            snapshot,
        } => format!("state {}@{seq} {:?}", show_claim(claim), s(snapshot)),
        Body::Beat { claim, seq } => format!("beat {}@{seq}", show_claim(claim)),
        Body::Msg {
            claim, seq, payload, ..
        } => format!("msg {}@{seq} {:?}", show_claim(claim), s(payload)),
        Body::Pass {
            claim,
            next,
            snapshot,
            ..
        } => format!(
            "pass {} -> {} {:?}",
            show_claim(claim),
            show_claim(next),
            s(snapshot)
        ),
        Body::Take { claim, .. } => format!("take {}", show_claim(claim)),
        Body::Ask { claim } => format!("ask {}", show_claim(claim)),
        Body::Decline { claim } => format!("decline {}", show_claim(claim)),
        Body::Bye { claim, leaving } => format!("bye {:?} leaving={leaving}", claim.as_ref().map(show_claim)),
        Body::Yielded { claim, snapshot, .. } => {
            format!("yielded {} {:?}", show_claim(claim), s(snapshot))
        }
        other => other.kind().to_owned(),
    }
}
