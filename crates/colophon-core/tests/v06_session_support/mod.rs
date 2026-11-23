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
    if before.accepted() > after.accepted() {
        return Err(format!(
            "G1: {me} accepted claim decreased {:?} -> {:?}",
            before.accepted(),
            after.accepted()
        ));
    }
    for o in outs {
        match o {
            Output::Send { frame } => {
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
    let joined: Vec<&Session> = members.iter().filter(|m| m.joined()).collect();
    let Some(first) = joined.first() else {
        return Ok(());
    };
    let holders: Vec<&&Session> = joined.iter().filter(|m| m.is_holder()).collect();
    // With no live holder, "no holder" (a `bye` arrived) and "lapsed holder" (it was lost
    // with its sender) are the same situation (finding F5): compare claims only.
    let live = !holders.is_empty();
    if !live {
        // With no live holder nothing need be sent, and a claim travels only in its own
        // holder's frames, so members may keep different (dead) claims (finding F5). The next
        // take or renewal restores agreement; G4 is checked for live holders.
        return Ok(());
    }
    for m in &joined {
        if m.accepted() != first.accepted() || m.holder() != first.holder() {
            return Err(format!(
                "G4: {} has {:?} (holder {:?}) but {} has {:?} (holder {:?})",
                m.me(),
                m.accepted(),
                m.holder(),
                first.me(),
                first.accepted(),
                first.holder()
            ));
        }
    }
    if let Some(h) = first.holder() {
        let Some(hm) = joined.iter().find(|m| m.me() == h) else {
            // The holder left without a bye reaching anyone; nothing to compare yet.
            return if holders.is_empty() {
                Ok(())
            } else {
                Err("G4: a holder acts for a claim it does not hold".into())
            };
        };
        if holders.len() != 1 || !hm.sends_as_holder() {
            return Err(format!(
                "G4: {} members act as holder; {h} sends as holder: {}",
                holders.len(),
                hm.sends_as_holder()
            ));
        }
        for m in &joined {
            if !m.synced() || m.seq() != hm.seq() || m.state() != hm.state() {
                return Err(format!(
                    "G4: {} at seq {} synced {} state {:?} differs from holder {h} at seq {} state {:?}",
                    m.me(),
                    m.seq(),
                    m.synced(),
                    m.state(),
                    hm.seq(),
                    hm.state()
                ));
            }
        }
    } else if !holders.is_empty() {
        return Err("G4: a member acts as holder while the cell has no holder".into());
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
        Output::Persist { claim } => format!("persist {}", show_claim(claim)),
        Output::Event { event } => format!("event {event:?}"),
    }
}
/// `term.rank.holder`.
pub fn show_claim(c: &Claim) -> String {
    format!("{}.{}.{}", c.term, c.rank, c.holder)
}
/// A short readable body.
pub fn show_body(b: &Body) -> String {
    let s = |x: &Bytes| String::from_utf8_lossy(&x.0).into_owned();
    match b {
        Body::Hello { seen, lapsed, .. } => format!(
            "hello seen={} lapsed={lapsed}",
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
        Body::Bye { claim } => format!("bye {:?}", claim.as_ref().map(show_claim)),
        other => other.kind().to_owned(),
    }
}
