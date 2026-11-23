//! One member of one cell (§S4–§S8), as a deterministic state machine.
//!
//! [`Session::handle`] takes one [`Input`] and the member's monotonic clock and returns the
//! [`Output`]s in order. Nothing inside reads a clock, draws randomness or does IO; ids come
//! from the caller. The type is `Clone + Eq + Hash` so explorers can deduplicate states, and
//! [`Session::view`] / [`Session::digest`] give the protocol-visible state.
//!
//! The machine follows revision 2 of the draft, which adopted the findings in
//! `docs/colophon-0.6-sessions-findings.md`; [`Fixes::LITERAL`] reproduces revision 1.
//! Choices still local to this layer: submits are ordered automatically (the only refusal
//! is `too-large`), and the fold is the cell's `policy.fold`.

pub mod clock;
pub mod io;
pub mod types;

pub use clock::{sample, Sample, Samples};
pub use io::{Command, Event, Input, Output, Via};
pub use types::{
    Body, Bytes, Claim, Fixes, Fold, Frame, MemberId, Policy, Seen, TakeRule, MAX_TERM,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// An ordered message kept by the holder (tail) or held early by a listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Held {
    origin: MemberId,
    id: Bytes,
    payload: Bytes,
}

/// A writer that wants the role.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Want {
    /// When the `ask` was sent to the current holder, if one was.
    asked_at: Option<u64>,
    /// The holder declined that ask.
    declined: bool,
    /// The application's projection to start from.
    snapshot: Option<Bytes>,
}

/// The `pass` this member sent, kept to resend (§S5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SentPass {
    claim: Claim,
    next: Claim,
    seq: u64,
    snapshot: Bytes,
}

/// The protocol-visible state of a member, for digests and cross-implementation vectors.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct View {
    /// The greatest accepted claim.
    pub accepted: Option<Claim>,
    /// The holder this member sees (`None`: no holder).
    pub holder: Option<MemberId>,
    /// This member acts as holder (gated or not).
    pub holding: bool,
    /// This member is an out-of-contact or restarted holder waiting `askTimeoutMs`.
    pub gated: bool,
    /// Whether it holds a snapshot for `accepted`.
    pub synced: bool,
    /// The last applied (listener) or ordered (holder) `seq` of `accepted`.
    pub seq: u64,
    /// The ordered state.
    pub state: Bytes,
}

/// One member of one cell.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Session {
    me: MemberId,
    can_write: bool,
    policy: Policy,
    fixes: Fixes,
    joined: bool,
    accepted: Option<Claim>,
    released: bool,
    synced: bool,
    seq: u64,
    state: Bytes,
    early: BTreeMap<u64, Held>,
    tail: VecDeque<(u64, Held)>,
    ordered: BTreeSet<Bytes>,
    sent_pass: Option<SentPass>,
    /// When the last gap `hello` was sent (§S8: at most one per second).
    last_gap_hello: Option<u64>,
    want: Option<Want>,
    gate: Option<u64>,
    link_up: bool,
    link_since: u64,
    link_down_since: Option<u64>,
    last_heard_holder: u64,
    lapse_reported: bool,
    last_sent_all: Option<u64>,
    heard: BTreeMap<MemberId, u64>,
    heard_holding: BTreeMap<MemberId, u64>,
    presence: BTreeMap<MemberId, (Bytes, u64)>,
    clocks: BTreeMap<MemberId, Samples>,
}

type Out = Vec<Output>;

/// §S8: gap `hello`s at most once per second.
pub const GAP_HELLO_MS: u64 = 1_000;

impl Session {
    /// A member before `join`. `persisted` is the claim it stored with [`Output::Persist`].
    pub fn new(me: &str, can_write: bool, policy: Policy, persisted: Option<Claim>) -> Self {
        Self::with_fixes(me, can_write, policy, persisted, Fixes::default())
    }

    /// As [`Session::new`], choosing which findings' fixes apply.
    pub fn with_fixes(
        me: &str,
        can_write: bool,
        policy: Policy,
        persisted: Option<Claim>,
        fixes: Fixes,
    ) -> Self {
        Self {
            me: me.to_ascii_lowercase(),
            can_write,
            policy,
            fixes,
            joined: false,
            accepted: persisted.filter(Claim::well_formed),
            released: false,
            synced: false,
            seq: 0,
            state: Bytes::default(),
            early: BTreeMap::new(),
            tail: VecDeque::new(),
            ordered: BTreeSet::new(),
            sent_pass: None,
            last_gap_hello: None,
            want: None,
            gate: None,
            link_up: true,
            link_since: 0,
            link_down_since: None,
            last_heard_holder: 0,
            lapse_reported: false,
            last_sent_all: None,
            heard: BTreeMap::new(),
            heard_holding: BTreeMap::new(),
            presence: BTreeMap::new(),
            clocks: BTreeMap::new(),
        }
    }

    // -----------------------------------------------------------------------------------
    // Queries.

    /// This member's ID.
    pub fn me(&self) -> &str {
        &self.me
    }
    /// Whether it has joined.
    pub fn joined(&self) -> bool {
        self.joined
    }
    /// The greatest accepted claim.
    pub fn accepted(&self) -> Option<&Claim> {
        self.accepted.as_ref()
    }
    /// The holder this member sees, `None` when there is none.
    pub fn holder(&self) -> Option<&str> {
        match (&self.accepted, self.released) {
            (Some(c), false) => Some(&c.holder),
            _ => None,
        }
    }
    /// Whether it acts as holder (including while gated, §S6 "keeps acting locally").
    pub fn is_holder(&self) -> bool {
        self.joined && self.holder() == Some(self.me.as_str())
    }
    /// Whether it may send holder frames now.
    pub fn sends_as_holder(&self) -> bool {
        self.is_holder() && self.gate.is_none()
    }
    /// Whether a timer can still change this member without input: it wants the role, or it
    /// is a gated holder (§S6).
    pub fn pending(&self) -> bool {
        self.joined && (self.want.is_some() || self.gate.is_some())
    }
    /// The ordered state.
    pub fn state(&self) -> &Bytes {
        &self.state
    }
    /// The position in the accepted claim's lane.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Whether it holds a snapshot for the accepted claim.
    pub fn synced(&self) -> bool {
        self.synced
    }
    /// Presence values by member.
    pub fn presence(&self) -> impl Iterator<Item = (&MemberId, &Bytes)> {
        self.presence.iter().map(|(k, (v, _))| (k, v))
    }
    /// The best clock sample to `peer` (§S7).
    pub fn offset_to(&self, peer: &str) -> Option<Sample> {
        self.clocks.get(peer).and_then(Samples::best)
    }
    /// The best clock sample to the holder; zero for the holder itself.
    pub fn holder_offset(&self) -> Option<Sample> {
        match self.holder() {
            Some(h) if h == self.me => Some(Sample {
                rtt: 0,
                offset: 0,
                error: 0,
            }),
            Some(h) => self.offset_to(h),
            None => None,
        }
    }
    /// The protocol-visible state.
    pub fn view(&self) -> View {
        View {
            accepted: self.accepted.clone(),
            holder: self.holder().map(str::to_owned),
            holding: self.is_holder(),
            gated: self.gate.is_some(),
            synced: self.synced,
            seq: self.seq,
            state: self.state.clone(),
        }
    }
    /// SHA-256 hex of the canonical JSON of [`Session::view`].
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(&self.view()).unwrap_or_default();
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Hash the whole state with every time replaced by its age at `now`, ages capped at
    /// `horizon` (and future deadlines by their distance from `now`). With `horizon` above
    /// every policy duration, two states with equal hashes behave identically from `now` on
    /// (up to `Ping`/`Pong` clock values), so a model checker can explore unbounded time.
    pub fn hash_at<H: std::hash::Hasher>(&self, now: u64, horizon: u64, h: &mut H) {
        use std::hash::Hash;
        let age = |t: u64| now.saturating_sub(t).min(horizon);
        let ahead = |t: u64| t.saturating_sub(now);
        self.me.hash(h);
        self.can_write.hash(h);
        self.policy.hash(h);
        self.fixes.hash(h);
        self.joined.hash(h);
        self.accepted.hash(h);
        self.released.hash(h);
        self.synced.hash(h);
        self.seq.hash(h);
        self.state.hash(h);
        self.early.hash(h);
        self.tail.hash(h);
        self.ordered.hash(h);
        self.sent_pass.hash(h);
        self.last_gap_hello
            .map(|t| now.saturating_sub(t).min(GAP_HELLO_MS))
            .hash(h);
        match &self.want {
            None => 0u8.hash(h),
            Some(w) => {
                1u8.hash(h);
                w.asked_at.map(age).hash(h);
                w.asked_at.map(|a| self.last_heard_holder <= a).hash(h);
                w.declined.hash(h);
                w.snapshot.hash(h);
            }
        }
        self.gate.map(ahead).hash(h);
        self.link_up.hash(h);
        age(self.link_since).hash(h);
        self.link_down_since.map(age).hash(h);
        age(self.last_heard_holder).hash(h);
        self.lapse_reported.hash(h);
        self.last_sent_all.map(age).hash(h);
        if !self.fixes.answer_lesser {
            // Only the literal reading of "present" reads it.
            for (k, t) in &self.heard {
                (k, age(*t)).hash(h);
            }
        }
        0xffu8.hash(h);
        for (k, t) in &self.heard_holding {
            (k, age(*t)).hash(h);
        }
        0xffu8.hash(h);
        for (k, (v, t)) in &self.presence {
            (k, v, age(*t)).hash(h);
        }
        self.clocks.hash(h);
    }

    // -----------------------------------------------------------------------------------
    // The machine.

    /// Process one input at `now` (this member's monotonic ms).
    pub fn handle(&mut self, input: Input, now: u64) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Frame { frame, writer } => self.on_frame(frame, writer, now, &mut out),
            Input::Tick => self.on_tick(now, &mut out),
            Input::LinkUp => self.on_link_up(now, &mut out),
            Input::LinkDown => {
                if self.link_up {
                    self.link_up = false;
                    self.link_down_since = Some(now);
                }
            }
            Input::App { command } => self.on_command(command, now, &mut out),
        }
        out
    }

    fn send(&self, out: &mut Out, to: Option<&str>, retain: bool, body: Body) {
        out.push(Output::Send {
            frame: Frame {
                from: self.me.clone(),
                to: to.map(str::to_owned),
                retain,
                body,
            },
        });
    }
    fn event(out: &mut Out, event: Event) {
        out.push(Output::Event { event });
    }
    fn reject(out: &mut Out, command: &str, reason: &str) {
        Self::event(
            out,
            Event::Rejected {
                command: command.into(),
                reason: reason.into(),
            },
        );
    }

    fn seen(&self) -> Option<Seen> {
        self.accepted.as_ref().map(|c| Seen {
            claim: c.clone(),
            seq: if self.synced || !self.fixes.seen_unsynced {
                Some(self.seq)
            } else {
                None
            },
        })
    }
    fn send_hello(&self, out: &mut Out, to: Option<&str>, lapsed: bool) {
        self.send(
            out,
            to,
            false,
            Body::Hello {
                session_key: Bytes::default(),
                seen: self.seen(),
                lapsed,
            },
        );
    }
    /// A gap `hello` (§S8), rate-limited to one per [`GAP_HELLO_MS`].
    fn gap_hello(&mut self, out: &mut Out, to: &str, now: u64) {
        if self
            .last_gap_hello
            .is_some_and(|t| now.saturating_sub(t) < GAP_HELLO_MS)
        {
            return;
        }
        self.last_gap_hello = Some(now);
        self.send_hello(out, Some(to), false);
    }
    fn send_state(&mut self, out: &mut Out, to: Option<&str>, now: u64) {
        let Some(claim) = self.accepted.clone() else {
            return;
        };
        if to.is_none() {
            self.last_sent_all = Some(now);
        }
        self.send(
            out,
            to,
            true,
            Body::State {
                claim,
                seq: self.seq,
                snapshot: self.state.clone(),
            },
        );
    }
    fn present(&self, member: &str, now: u64) -> bool {
        if self.fixes.renew_needs_contact
            && (!self.link_up || now.saturating_sub(self.link_since) < self.policy.holder_timeout_ms)
        {
            return true;
        }
        if self.fixes.answer_lesser {
            return self
                .heard_holding
                .get(member)
                .is_some_and(|t| now.saturating_sub(*t) < self.policy.holder_timeout_ms);
        }
        self.heard
            .get(member)
            .is_some_and(|t| now.saturating_sub(*t) < self.policy.presence_timeout_ms)
    }
    fn no_holder(&self) -> bool {
        self.holder().is_none()
    }
    fn lapsed(&self, now: u64) -> bool {
        match self.holder() {
            Some(h) if h != self.me => {
                self.link_up
                    && now.saturating_sub(self.last_heard_holder.max(self.link_since))
                        >= self.policy.holder_timeout_ms
            }
            _ => false,
        }
    }
    fn may_take(&self) -> bool {
        self.joined && self.can_write && self.policy.take == TakeRule::Free
    }

    /// Whether a rank-1 claim carried by a non-pass frame from `from` is acceptable (§S4 3).
    fn rank1_ok(&self, c: &Claim, from: &str) -> bool {
        self.fixes.rank1_from_holder && c.holder == from
    }
    /// The claim as this member orders it (§S4 3: unverified rank 1 orders as rank 0).
    fn ordering(&self, c: &Claim, from: &str) -> Claim {
        if c.rank == 1 && !self.rank1_ok(c, from) && self.accepted.as_ref() != Some(c) {
            c.as_rank0()
        } else {
            c.clone()
        }
    }
    fn is_lesser(&self, c: &Claim, from: &str) -> bool {
        self.accepted
            .as_ref()
            .is_some_and(|a| self.ordering(c, from) < *a)
    }

    /// §S4 acceptance for a claim met in a frame other than a `pass`.
    fn consider(&mut self, c: &Claim, from: &str, now: u64, out: &mut Out) -> bool {
        if !c.well_formed() || self.accepted.as_ref().is_some_and(|a| c <= a) {
            return false;
        }
        let ok = match c.rank {
            0 => c.holder == from,
            _ => self.rank1_ok(c, from),
        };
        if ok {
            self.adopt(c.clone(), None, now, out);
        }
        ok
    }

    /// Accept `c` (greater than the current claim), optionally with its initial state.
    fn adopt(&mut self, c: Claim, snapshot: Option<Bytes>, now: u64, out: &mut Out) {
        let was_holder = self.is_holder();
        self.accepted = Some(c.clone());
        self.released = false;
        self.gate = None;
        self.early.clear();
        self.tail.clear();
        self.ordered.clear();
        self.seq = 0;
        self.lapse_reported = false;
        self.last_heard_holder = now;
        if self.sent_pass.as_ref().is_some_and(|p| p.next < c) {
            self.sent_pass = None;
        }
        let mine = c.holder == self.me;
        match &snapshot {
            Some(s) => {
                self.state = s.clone();
                self.synced = true;
            }
            None => self.synced = mine,
        }
        out.push(Output::Persist { claim: c.clone() });
        if was_holder && !mine {
            Self::event(out, Event::Yielded { to: c.clone() });
        }
        if !mine {
            Self::event(
                out,
                Event::HolderChanged {
                    claim: Some(c.clone()),
                },
            );
            if let Some(s) = snapshot {
                Self::event(
                    out,
                    Event::Snapshot {
                        claim: c.clone(),
                        seq: 0,
                        snapshot: s,
                    },
                );
            } else {
                // §S8: changed claim without a snapshot.
                self.send_hello(out, Some(&c.holder), false);
            }
            if let Some(w) = &mut self.want {
                // Ask the new holder.
                w.asked_at = Some(now);
                w.declined = false;
                self.send(out, Some(&c.holder), false, Body::Ask { claim: c.clone() });
            }
        }
    }

    /// Become holder at `term + 1`, rank 0 (§S5 take, §S6 retake).
    fn take(&mut self, snapshot: Option<Bytes>, via: Via, now: u64, out: &mut Out) {
        let term = self.accepted.as_ref().map_or(0, |c| c.term);
        let Some(t) = term.checked_add(1).filter(|t| *t <= MAX_TERM) else {
            Self::reject(out, "take", "term-exhausted");
            return;
        };
        let claim = Claim::new(t, 0, &self.me);
        if let Some(s) = snapshot {
            self.state = s;
        }
        self.become_holder(claim.clone(), now, out);
        self.send(out, None, false, Body::Take { claim });
        self.send_state(out, None, now);
        let claim = self.accepted.clone().unwrap_or_else(|| Claim::new(t, 0, &self.me));
        Self::event(
            out,
            Event::BecameHolder {
                claim,
                snapshot: self.state.clone(),
                via,
            },
        );
    }
    fn become_holder(&mut self, claim: Claim, now: u64, out: &mut Out) {
        self.accepted = Some(claim.clone());
        self.released = false;
        self.gate = None;
        self.want = None;
        self.synced = true;
        self.seq = 0;
        self.early.clear();
        self.tail.clear();
        self.ordered.clear();
        self.last_heard_holder = now;
        out.push(Output::Persist { claim });
    }

    /// §S5 renewing: raise the claim above `term`.
    fn renew(&mut self, term: u64, now: u64, out: &mut Out) {
        let Some(t) = term.checked_add(1).filter(|t| *t <= MAX_TERM) else {
            return;
        };
        let claim = Claim::new(t, 0, &self.me);
        self.become_holder(claim.clone(), now, out);
        self.send_state(out, None, now);
        Self::event(
            out,
            Event::BecameHolder {
                claim,
                snapshot: self.state.clone(),
                via: Via::Renew,
            },
        );
    }

    fn apply(&mut self, seq: u64, h: Held, out: &mut Out) {
        self.state = self.policy.fold.apply(&self.state, &h.payload);
        self.seq = seq;
        if let Some(claim) = self.accepted.clone() {
            Self::event(
                out,
                Event::Message {
                    claim,
                    seq,
                    origin: h.origin,
                    id: h.id,
                    payload: h.payload,
                },
            );
        }
    }
    fn drain_early(&mut self, out: &mut Out) {
        while let Some(h) = self.early.remove(&(self.seq + 1)) {
            self.apply(self.seq + 1, h, out);
        }
        let seq = self.seq;
        self.early.retain(|k, _| *k > seq);
    }

    /// Order one message as holder (publish or submit).
    fn order(&mut self, origin: MemberId, id: Bytes, payload: Bytes, now: u64, out: &mut Out) {
        let Some(claim) = self.accepted.clone() else {
            return;
        };
        let seq = self.seq + 1;
        let h = Held {
            origin: origin.clone(),
            id: id.clone(),
            payload: payload.clone(),
        };
        self.ordered.insert(id.clone());
        self.tail.push_back((seq, h.clone()));
        while self.tail.len() as u64 > self.policy.tail {
            self.tail.pop_front();
        }
        self.apply(seq, h, out);
        if self.gate.is_none() {
            self.last_sent_all = Some(now);
            self.send(
                out,
                None,
                false,
                Body::Msg {
                    claim,
                    seq,
                    origin,
                    id,
                    payload,
                },
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // Frames.

    fn on_frame(&mut self, f: Frame, writer: bool, now: u64, out: &mut Out) {
        if !self.joined || f.from == self.me {
            return;
        }
        if f.to.as_ref().is_some_and(|t| *t != self.me) {
            return;
        }
        if f.body.needs_writer() && !writer {
            return;
        }
        let from = f.from;
        self.heard.insert(from.clone(), now);
        let holding_frame = f.body.is_holder_frame() || matches!(f.body, Body::Take { .. });
        if holding_frame && f.body.claim().is_some_and(|c| c.holder == from) {
            self.heard_holding.insert(from.clone(), now);
        }
        let alive = !self.fixes.liveness_holder_frames
            || (f.body.is_holder_frame()
                && f.body.claim().is_none_or(|c| self.accepted.as_ref() == Some(c)));
        if alive && self.holder() == Some(from.as_str()) {
            self.last_heard_holder = now;
            self.lapse_reported = false;
        }
        // §S5: resend the pass when the asker speaks under an older claim.
        if let Some(p) = &self.sent_pass {
            if from == p.next.holder && f.body.claim().is_some_and(|c| *c < p.next) {
                let body = Body::Pass {
                    claim: p.claim.clone(),
                    next: p.next.clone(),
                    seq: p.seq,
                    snapshot: p.snapshot.clone(),
                };
                self.send(out, Some(&from), false, body);
            }
        }
        // F5: a lost `bye` is answered again.
        let released_mine = self.released
            && self.accepted.as_ref().is_some_and(|a| a.holder == self.me);
        if self.fixes.bye_resend
            && self.released
            && self.accepted.as_ref().is_some_and(|a| a.holder == self.me)
            && holding_frame
            && f.body.claim().is_some_and(|c| Some(c) < self.accepted.as_ref())
            && !matches!(f.body, Body::Bye { .. })
        {
            let claim = self.accepted.clone();
            self.send(
                out,
                Some(&from),
                false,
                Body::Bye {
                    claim,
                    leaving: false,
                },
            );
        }
        // F6: tell a sender holding under a lesser claim what this member accepted.
        if self.fixes.answer_lesser
            && holding_frame
            && !self.is_holder()
            && !(self.fixes.bye_resend && released_mine)
            && !matches!(f.body, Body::Pass { .. })
            && f.body
                .claim()
                .is_some_and(|c| c.holder == from && self.is_lesser(c, &from))
        {
            self.send_hello(out, Some(&from), false);
        }
        match f.body {
            Body::Hello { seen, .. } => self.on_hello(&from, seen, now, out),
            Body::State {
                claim,
                seq,
                snapshot,
            } => {
                self.consider(&claim, &from, now, out);
                if self.accepted.as_ref() == Some(&claim) && claim.holder == from {
                    if !self.is_holder() && (!self.synced || seq > self.seq) {
                        self.state = snapshot.clone();
                        self.seq = seq;
                        self.synced = true;
                        Self::event(
                            out,
                            Event::Snapshot {
                                claim,
                                seq,
                                snapshot,
                            },
                        );
                        self.drain_early(out);
                    }
                } else {
                    self.stale(&claim, &from, now, out);
                }
            }
            Body::Beat { claim, seq } => {
                self.consider(&claim, &from, now, out);
                if self.accepted.as_ref() == Some(&claim) && claim.holder == from {
                    if !self.is_holder() && !self.synced {
                        self.send_hello(out, Some(&from), false);
                    } else if !self.is_holder() && seq > self.seq {
                        self.gap_hello(out, &from, now);
                    }
                } else {
                    self.stale(&claim, &from, now, out);
                }
            }
            Body::Msg {
                claim,
                seq,
                origin,
                id,
                payload,
            } => {
                let fresh = self.consider(&claim, &from, now, out);
                if self.accepted.as_ref() == Some(&claim) && claim.holder == from {
                    if self.is_holder() {
                        return;
                    }
                    let h = Held {
                        origin,
                        id,
                        payload,
                    };
                    if self.synced && seq == self.seq + 1 {
                        self.apply(seq, h, out);
                        self.drain_early(out);
                    } else if seq > self.seq + 1 || !self.synced {
                        if seq <= self.seq.saturating_add(self.policy.tail) {
                            self.early.insert(seq, h);
                        }
                        if self.synced && !fresh {
                            // §S8 gap.
                            self.gap_hello(out, &from, now);
                        }
                    }
                } else {
                    self.stale(&claim, &from, now, out);
                }
            }
            Body::Submit { id, payload } => {
                if !self.sends_as_holder() || self.ordered.contains(&id) {
                    return;
                }
                if payload.len() as u64 > self.policy.max_payload {
                    self.send(
                        out,
                        Some(&from),
                        false,
                        Body::Refuse {
                            id,
                            reason: "too-large".into(),
                        },
                    );
                    return;
                }
                self.order(from, id, payload, now, out);
            }
            Body::Refuse { id, reason } => {
                if self.holder() == Some(from.as_str()) {
                    Self::event(out, Event::Refused { id, reason });
                }
            }
            Body::Presence { payload } => {
                self.presence.insert(from.clone(), (payload.clone(), now));
                Self::event(
                    out,
                    Event::PresenceChanged {
                        member: from,
                        payload: Some(payload),
                    },
                );
            }
            Body::Ask { claim } => {
                self.consider(&claim, &from, now, out);
                if self.sends_as_holder() {
                    Self::event(out, Event::AskReceived { from });
                }
            }
            Body::Pass {
                claim,
                next,
                seq: _,
                snapshot,
            } => self.on_pass(&from, claim, next, snapshot, now, out),
            Body::Decline { claim } => {
                self.consider(&claim, &from, now, out);
                if self.accepted.as_ref() == Some(&claim) && claim.holder == from {
                    if let Some(w) = &mut self.want {
                        if w.asked_at.is_some() {
                            w.declined = true;
                            Self::event(out, Event::Declined { from });
                        }
                    }
                }
            }
            Body::Take { claim } => {
                if claim.rank != 0 || claim.holder != from {
                    return;
                }
                if !self.consider(&claim, &from, now, out) {
                    self.stale(&claim, &from, now, out);
                }
            }
            Body::Ping { t } => {
                self.send(
                    out,
                    Some(&from),
                    false,
                    Body::Pong {
                        t: now,
                        echo: t,
                        hold: 0,
                    },
                );
            }
            Body::Pong { t, echo, hold } => {
                let s = sample(now, t, echo, hold);
                if let Some(best) = self.clocks.entry(from.clone()).or_default().push(s) {
                    Self::event(
                        out,
                        Event::OffsetChanged {
                            peer: from,
                            offset: best.offset,
                            error: best.error,
                        },
                    );
                }
            }
            Body::Bye { claim, leaving: _ } => {
                if self.presence.remove(&from).is_some() {
                    Self::event(
                        out,
                        Event::PresenceChanged {
                            member: from.clone(),
                            payload: None,
                        },
                    );
                }
                if let Some(c) = claim {
                    if self.fixes.renew_wider
                        && self.sends_as_holder()
                        && c.holder == from
                        && self.accepted.as_ref().is_some_and(|a| c > *a)
                    {
                        // F7: a released claim has no holder; stay holder above it.
                        self.renew(c.term, now, out);
                        return;
                    }
                    self.consider(&c, &from, now, out);
                    if self.accepted.as_ref() == Some(&c) && c.holder == from && !self.released {
                        self.released = true;
                        Self::event(out, Event::HolderChanged { claim: None });
                    }
                }
            }
        }
    }

    /// §S4 stale holders: a holder answers a lesser claim with `state`.
    fn stale(&mut self, claim: &Claim, from: &str, now: u64, out: &mut Out) {
        if self.sends_as_holder() && self.is_lesser(claim, from) {
            self.send_state(out, Some(from), now);
        }
    }

    fn on_hello(&mut self, from: &str, seen: Option<Seen>, now: u64, out: &mut Out) {
        if let Some(s) = &seen {
            if s.claim.holder == from {
                let greater = self.accepted.as_ref().is_none_or(|a| s.claim > *a);
                if self.fixes.renew_wider && self.sends_as_holder() && greater {
                    // F7: a hello does not say whether its sender still holds (it may have
                    // released); a holder raises its claim instead of yielding to it. A
                    // sender that does hold accepts the resulting state and yields.
                    self.renew(s.claim.term, now, out);
                    return;
                }
                self.consider(&s.claim, from, now, out);
            }
        }
        if !self.sends_as_holder() {
            return;
        }
        let Some(mine) = self.accepted.clone() else {
            return;
        };
        let Some(s) = seen else {
            self.send_state(out, Some(from), now);
            return;
        };
        if s.claim == mine {
            match s.seq {
                Some(q) if q >= self.seq => {}
                Some(q) if self.tail.front().is_some_and(|(first, _)| *first <= q + 1) => {
                    let missing: Vec<_> = self
                        .tail
                        .iter()
                        .filter(|(n, _)| *n > q)
                        .cloned()
                        .collect();
                    for (n, h) in missing {
                        self.send(
                            out,
                            Some(from),
                            false,
                            Body::Msg {
                                claim: mine.clone(),
                                seq: n,
                                origin: h.origin,
                                id: h.id,
                                payload: h.payload,
                            },
                        );
                    }
                }
                _ => self.send_state(out, Some(from), now),
            }
            return;
        }
        // §S5 renewing.
        let other = s.claim.holder != self.me && !self.present(&s.claim.holder, now);
        let own_greater = self.fixes.renew_wider && s.claim.holder == self.me && s.claim > mine;
        if s.claim >= mine && (other || own_greater) {
            self.renew(s.claim.term, now, out);
            return;
        }
        if self.is_lesser(&s.claim, from) {
            self.send_state(out, Some(from), now);
        }
    }

    fn on_pass(
        &mut self,
        from: &str,
        claim: Claim,
        next: Claim,
        snapshot: Bytes,
        now: u64,
        out: &mut Out,
    ) {
        // §S4 rule 3 (revision 3): a `pass` from `next.via`, which held `claim`.
        let shaped = next.well_formed()
            && claim.well_formed()
            && next.rank == 1
            && next.via.as_deref() == Some(from)
            && Some(next.term) == claim.term.checked_add(1)
            && claim.holder == from;
        let verified = shaped
            && if self.fixes.rank1_from_holder {
                true
            } else {
                // §S4 3: from the holder of the member's previous accepted claim.
                self.accepted.as_ref().is_some_and(|a| a.holder == from)
            };
        if verified
            && self.fixes.renew_wider
            && next.holder == self.me
            && self.is_holder()
            && self.accepted.as_ref().is_some_and(|a| next > *a)
        {
            // §S5 (revision 3): a greater claim naming this holder that it has not acted under
            // (a second pass from another holder): renew with the current state.
            self.renew(next.term, now, out);
            return;
        }
        if !verified || self.accepted.as_ref().is_some_and(|a| next <= *a) {
            return;
        }
        if next.holder == self.me {
            if !self.may_take() {
                return;
            }
            let claim = next.clone();
            self.state = snapshot.clone();
            self.become_holder(next, now, out);
            Self::event(
                out,
                Event::BecameHolder {
                    claim,
                    snapshot,
                    via: Via::Pass,
                },
            );
        } else {
            self.adopt(next, Some(snapshot), now, out);
        }
    }

    // -----------------------------------------------------------------------------------
    // Time and links.

    fn on_tick(&mut self, now: u64, out: &mut Out) {
        if !self.joined {
            return;
        }
        let expired: Vec<MemberId> = self
            .presence
            .iter()
            .filter(|(_, (_, t))| now.saturating_sub(*t) >= self.policy.presence_timeout_ms)
            .map(|(k, _)| k.clone())
            .collect();
        for member in expired {
            self.presence.remove(&member);
            Self::event(
                out,
                Event::PresenceChanged {
                    member,
                    payload: None,
                },
            );
        }
        if let Some(until) = self.gate {
            if now >= until && self.is_holder() {
                // §S6: nobody else claimed within askTimeoutMs; retake.
                self.gate = None;
                self.take(None, Via::Take, now, out);
                return;
            }
        }
        if self.sends_as_holder() {
            if self
                .last_sent_all
                .is_none_or(|t| now.saturating_sub(t) >= self.policy.beat_ms)
            {
                if let Some(claim) = self.accepted.clone() {
                    self.last_sent_all = Some(now);
                    self.send(out, None, true, Body::Beat { claim, seq: self.seq });
                }
            }
            return;
        }
        let lapsed = self.lapsed(now);
        if lapsed && !self.lapse_reported {
            self.lapse_reported = true;
            if let Some(h) = self.holder() {
                let holder = h.to_owned();
                if self.fixes.bye_resend {
                    self.send_hello(out, None, false);
                }
                Self::event(out, Event::HolderLapsed { holder });
            }
        }
        if let Some(w) = &self.want {
            if self.is_holder() || !self.may_take() {
                return;
            }
            let ask_expired = w.asked_at.is_some_and(|at| {
                !w.declined
                    && now.saturating_sub(at) >= self.policy.ask_timeout_ms
                    && self.last_heard_holder <= at
            });
            let unanswered = w.asked_at.is_some_and(|at| {
                !w.declined
                    && now.saturating_sub(at) >= self.policy.ask_timeout_ms
                    && self.last_heard_holder > at
            });
            if self.no_holder() || lapsed || ask_expired {
                let snapshot = w.snapshot.clone();
                self.take(snapshot, Via::Take, now, out);
            } else if unanswered && self.fixes.ask_resend {
                if let (Some(c), Some(w)) = (self.accepted.clone(), self.want.as_mut()) {
                    w.asked_at = Some(now);
                    let to = c.holder.clone();
                    self.send(out, Some(&to), false, Body::Ask { claim: c });
                }
            }
        }
    }

    fn on_link_up(&mut self, now: u64, out: &mut Out) {
        let was_down = self.link_down_since.take();
        if self.link_up {
            return;
        }
        self.link_up = true;
        self.link_since = now;
        if !self.joined {
            return;
        }
        let lapsed = self.sends_as_holder()
            && was_down.is_some_and(|d| now.saturating_sub(d) >= self.policy.holder_timeout_ms);
        if lapsed {
            self.gate = Some(now + self.policy.ask_timeout_ms);
        }
        self.send_hello(out, None, lapsed || self.gate.is_some());
    }

    // -----------------------------------------------------------------------------------
    // Commands.

    fn on_command(&mut self, command: Command, now: u64, out: &mut Out) {
        if !self.joined && !matches!(command, Command::Join { .. }) {
            Self::reject(out, "command", "not-joined");
            return;
        }
        match command {
            Command::Join { state } => {
                if self.joined {
                    return;
                }
                if let Some(st) = state {
                    // §S6: the application's state, which a restarted holder retakes with.
                    self.state = st;
                }
                self.joined = true;
                self.link_since = now;
                self.last_heard_holder = now;
                // A holder that lost its state (restart, or rejoin after leaving as holder
                // keeps `released`) retakes like an out-of-contact holder (§S6).
                let restarted = self.is_holder() && !self.synced;
                if restarted {
                    self.gate = Some(now + self.policy.ask_timeout_ms);
                }
                self.send_hello(out, None, restarted);
            }
            Command::Leave => {
                let claim = self.is_holder().then(|| self.accepted.clone()).flatten();
                if claim.is_some() {
                    self.released = true;
                }
                self.send(out, None, false, Body::Bye { claim, leaving: true });
                self.joined = false;
                self.want = None;
                self.gate = None;
            }
            Command::Release => {
                if !self.is_holder() {
                    Self::reject(out, "release", "not-holder");
                    return;
                }
                let claim = self.accepted.clone();
                self.released = true;
                self.gate = None;
                self.send(out, None, false, Body::Bye { claim, leaving: false });
            }
            Command::Ask => {
                if !self.may_take() {
                    Self::reject(out, "ask", "not-allowed");
                    return;
                }
                if self.is_holder() {
                    return;
                }
                let mut w = Want {
                    asked_at: None,
                    declined: false,
                    snapshot: None,
                };
                if let (Some(c), false) = (self.accepted.clone(), self.no_holder()) {
                    w.asked_at = Some(now);
                    let to = c.holder.clone();
                    self.send(out, Some(&to), false, Body::Ask { claim: c });
                }
                self.want = Some(w);
                self.on_tick(now, out);
            }
            Command::Take { state: snapshot } => {
                if !self.may_take() {
                    Self::reject(out, "take", "not-allowed");
                    return;
                }
                if self.is_holder() {
                    return;
                }
                let asked_at = self.want.as_ref().and_then(|w| w.asked_at);
                let declined = self.want.as_ref().is_some_and(|w| w.declined);
                self.want = Some(Want {
                    asked_at,
                    declined,
                    snapshot,
                });
                self.on_tick(now, out);
            }
            Command::Pass { to, snapshot } => {
                if !self.sends_as_holder() || to == self.me {
                    Self::reject(out, "pass", "not-holder");
                    return;
                }
                let Some(claim) = self.accepted.clone() else {
                    return;
                };
                let Some(t) = claim.term.checked_add(1).filter(|t| *t <= MAX_TERM) else {
                    Self::reject(out, "pass", "term-exhausted");
                    return;
                };
                let next = Claim::passed(t, &to, &self.me);
                let p = SentPass {
                    claim: claim.clone(),
                    next: next.clone(),
                    seq: self.seq,
                    snapshot: snapshot.clone(),
                };
                self.send(
                    out,
                    None,
                    false,
                    Body::Pass {
                        claim,
                        next: next.clone(),
                        seq: p.seq,
                        snapshot: snapshot.clone(),
                    },
                );
                self.adopt(next, Some(snapshot), now, out);
                self.sent_pass = Some(p);
            }
            Command::Decline { to } => {
                if !self.sends_as_holder() {
                    Self::reject(out, "decline", "not-holder");
                    return;
                }
                if let Some(claim) = self.accepted.clone() {
                    self.send(out, Some(&to), false, Body::Decline { claim });
                }
            }
            Command::Publish { id, payload } => {
                if !self.is_holder() {
                    Self::reject(out, "publish", "not-holder");
                    return;
                }
                if payload.len() as u64 > self.policy.max_payload {
                    Self::reject(out, "publish", "too-large");
                    return;
                }
                let me = self.me.clone();
                self.order(me, id, payload, now, out);
            }
            Command::Submit { id, payload } => {
                if !self.can_write {
                    Self::reject(out, "submit", "not-allowed");
                    return;
                }
                if payload.len() as u64 > self.policy.max_payload {
                    Self::reject(out, "submit", "too-large");
                    return;
                }
                if self.is_holder() {
                    let me = self.me.clone();
                    self.order(me, id, payload, now, out);
                } else if let Some(h) = self.holder().map(str::to_owned) {
                    self.send(out, Some(&h), false, Body::Submit { id, payload });
                } else {
                    Self::reject(out, "submit", "no-holder");
                }
            }
            Command::Presence { payload } => {
                self.send(out, None, false, Body::Presence { payload });
            }
            Command::Ping { to } => {
                self.send(out, Some(&to), false, Body::Ping { t: now });
            }
        }
    }
}
