//! One member of one cell (§S3–§S8), as a deterministic state machine.
//!
//! [`Session::handle`] takes one [`Input`] and the member's monotonic clock and returns the
//! [`Output`]s in order. Nothing inside reads a clock, draws randomness or does IO; ids and
//! the `fresh` seed come from the caller. The type is `Clone + Eq + Hash` so explorers can
//! deduplicate states, and [`Session::view`] / [`Session::digest`] give the protocol-visible
//! state.
//!
//! The machine follows revision 15 of the draft (`Fixes::ALL`). [`Fixes::LITERAL`] reproduces
//! revision 1 and [`Fixes::REV3`] revision 3, so every finding stays reproducible
//! (`docs/colophon-0.6-sessions-findings.md`). Outputs are ordered so that a crash between
//! any two of them breaks no guarantee (G12): every `Persist` precedes the frames that
//! reveal it.
//!
//! The §S3 freshness gate is in the machine, and is used when the codec passes the sender's
//! key and `n` with each frame and the host seeds `fresh` ([`Session::with_fresh_seed`]).
//! The machine also owns which session keys of other members are open or candidates
//! (revision 17); signatures, sealing and the 128-wide `n` window of each cached key are in
//! [`codec`], which caches only keys the machine knows ([`Session::knows_key`]).
//! [`endpoint`] wires the two for the bindings.
//!
//! **This module is a protocol engine, not a trust boundary.** Its types let a Rust caller
//! supply the account view and the epoch keys directly ([`keys::SessionAccount::with_member`],
//! [`codec::EpochTable::with`]), which tests, tools and the conformance vectors need. A
//! production embedder takes both from the verified 0.5 history instead
//! ([`crate::v05::account::Account::session_account`] and
//! [`crate::v05::account::Account::session_epochs`]); the shipping bindings enforce that, and
//! also the ordering duties [`endpoint::Endpoint`] leaves to its caller (a view of the current
//! authority head before each call, `Persist` stored before the frames that reveal it).

pub mod clock;
pub mod codec;
pub mod endpoint;
pub mod io;
pub mod keys;
mod hooks;
pub mod types;
pub mod wire;

pub use clock::{sample, Sample, Samples};
pub use io::{Command, Event, Input, Output, Via};
pub use types::{
    Body, Bytes, Claim, Fixes, Fold, Frame, Heard, Id, MemberId, Persisted, Policy, Seen,
    TakeRule, MAX_ECHO, MAX_INT, MAX_TERM,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// An ordered message kept by the holder (tail) or held early by a listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Held {
    origin: MemberId,
    id: Id,
    payload: Bytes,
}

/// A writer that wants the role.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Want {
    /// When the `ask` was sent to the current holder, if one was.
    asked_at: Option<u64>,
    /// The holder declined that ask.
    declined: bool,
    /// A holder frame from the holder arrived since the ask (a flag, not a time comparison:
    /// a beat accepted in the same millisecond as the ask must count).
    heard_since: bool,
    /// The holder is known only from forwarded evidence (R1d): no take on the ask timeout,
    /// only once the holder is lapsed.
    evidence_only: bool,
    /// The want exists only because this member had taken (no application ask).
    kept: bool,
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
    /// When it was last sent (revision 15: resent at most once per `askTimeoutMs`).
    last: u64,
    /// The wait before the next resend: `askTimeoutMs`, doubled after each resend up to
    /// `holderTimeoutMs` while unacknowledged.
    interval: u64,
}

/// A `yielded` not yet acknowledged (§S5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PendingYield {
    /// The member it was first sent to (the taker).
    first: MemberId,
    body: Body,
    held: Claim,
    /// Resends left (revision 4: one; revision 5: until acknowledged).
    left: u8,
    last: u64,
}

/// An unanswered submit (§S8, revision 4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PendingSubmit {
    payload: Bytes,
    tries: u8,
    last: u64,
}

/// Resends of an unanswered submit before it is reported failed.
pub const SUBMIT_TRIES: u8 = 8;
/// §S8: gap `hello`s at most once per second.
pub const GAP_HELLO_MS: u64 = 1_000;
/// Passes awaiting an `ack` that a member keeps resending (revision 15).
pub const MAX_SENT_PASSES: usize = 4;
/// A claim more than this many terms above the accepted term is ignored (revision 15).
pub const MAX_TERM_STEP: u64 = 1 << 20;
/// Unknown-key hellos at most this many per second in all (revision 15 §S3 step 4).
pub const PROBES_PER_SECOND: usize = 4;
/// Freshness windows kept per member (§S3, revision 7).
pub const MAX_KEYS_PER_MEMBER: usize = 4;
/// Own `fresh` values remembered (§S3 freshness).
const OWN_FRESH: usize = 32;
/// An echo is honoured only of a `fresh` sent within this long (§S3, revision 10).
pub const FRESH_MEMORY_MS: u64 = 60_000;

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
    /// The last `tail` ids ordered in this term (§S8 dedupe).
    ordered: VecDeque<Id>,
    /// Passes sent and not yet acknowledged (revision 15; at most [`MAX_SENT_PASSES`],
    /// newest last). Before revision 15, only the latest, until a greater claim.
    sent_passes: VecDeque<SentPass>,
    /// Members whose `ask` was accepted under the current claim and is unanswered (§S5).
    asks: BTreeSet<MemberId>,
    /// The last broadcast holder frame accepted under the accepted claim from its holder,
    /// and when: the evidence a member forwards (§S4, revision 4).
    evidence: Option<(Frame, u64)>,
    /// A `yielded` frame to resend to the new holder (§S5), with resends left and when last
    /// sent.
    pending_yielded: Option<PendingYield>,
    /// It holds because it wanted the role and took (R1d).
    took_wanting: bool,
    /// Transient during `handle`: the input is forwarded evidence.
    in_evidence: bool,
    /// Transient during `handle`: the input's time, for `fresh` bookkeeping.
    fresh_now: u64,
    /// The claim each member's last `hello` named (finding R1c): a member that names a lesser
    /// claim or none is sent evidence as soon as this member has it.
    peers_seen: BTreeMap<MemberId, Option<Claim>>,
    /// Displaced reports already given, by sender and claim (at most 8).
    reported: VecDeque<(MemberId, Claim)>,
    submits: BTreeMap<Id, PendingSubmit>,
    /// When the last gap `hello` was sent (§S8: at most one per second).
    last_gap_hello: Option<u64>,
    want: Option<Want>,
    gate: Option<u64>,
    link_up: bool,
    link_since: u64,
    link_down_since: Option<u64>,
    last_heard_holder: u64,
    lapse_reported: bool,
    /// When the current lapse was reported (R1f).
    lapse_since: Option<u64>,
    last_sent_all: Option<u64>,
    heard: BTreeMap<MemberId, u64>,
    heard_holding: BTreeMap<MemberId, u64>,
    presence: BTreeMap<MemberId, (Bytes, u64)>,
    clocks: BTreeMap<MemberId, Samples>,
    /// Freshness (§S3): the seed `fresh` values derive from, how many were made, the last
    /// ones sent, open windows per (member, key) with their lowest accepted `n`, and the
    /// last `fresh` answered per member.
    fresh_seed: Option<[u8; 16]>,
    fresh_count: u64,
    /// Own `fresh` values: the value, when it was issued, and its issue number.
    own_fresh: VecDeque<(Id, u64, u64)>,
    /// The writers entitled at the accepted authority head, once the host said (§S1). Until
    /// then nobody is entitled (revision 12: fail closed).
    entitled: Option<BTreeSet<MemberId>>,
    /// A `join` given before the host supplied the entitled set; it takes effect then.
    pending_join: Option<Option<Bytes>>,
    windows: BTreeMap<(MemberId, String), u64>,
    /// When a freshness probe was last sent to each member (finding B5), only entries younger
    /// than `askTimeoutMs` (revision 15: bounded).
    probed: BTreeMap<MemberId, u64>,
    /// When the last unknown-key hellos were sent, at most [`PROBES_PER_SECOND`] (revision 15).
    probe_times: VecDeque<u64>,
    /// Keys with windows per member, oldest first (revision 7 cap).
    window_order: BTreeMap<MemberId, VecDeque<String>>,
    /// Revision 17: keys per member that passed the codec's checks but have no open window
    /// yet (only their `hello`s are used), at most [`MAX_KEYS_PER_MEMBER`], oldest first.
    candidates: BTreeMap<MemberId, VecDeque<String>>,
    /// Revision 17: per member, the issue number of this member's last `fresh` when one of
    /// that member's windows was last closed or its keys stopped being accepted. An echo from
    /// that member opens a window only for a `fresh` issued after it.
    closed_after: BTreeMap<MemberId, u64>,
    /// Revision 17 hardening: per member, the `fresh` values of candidate `hello`s whose
    /// answer the probe limit suppressed (at most [`MAX_ECHO`], newest last). One `hello`
    /// echoing them all is sent when the member's budget reopens, so a genuine new key is not
    /// left unanswered by replays of old ones.
    deferred: BTreeMap<MemberId, VecDeque<Id>>,
    answered: BTreeMap<MemberId, Id>,
    to_echo: VecDeque<Id>,
}

type Out = Vec<Output>;

/// The next wait between resends of an unacknowledged pass (revision 17: doubled up to
/// `holderTimeoutMs`; before, always `askTimeoutMs`).
fn backoff(interval: u64, policy: &Policy, fixes: Fixes) -> u64 {
    if fixes.reopen_challenge {
        interval.saturating_mul(2).min(policy.holder_timeout_ms.max(policy.ask_timeout_ms))
    } else {
        policy.ask_timeout_ms
    }
}

impl Session {
    /// A member before `join`. `persisted` is what it stored with [`Output::Persist`].
    pub fn new(me: &str, can_write: bool, policy: Policy, persisted: Option<Persisted>) -> Self {
        Self::with_fixes(me, can_write, policy, persisted, Fixes::default())
    }

    /// As [`Session::new`], choosing which findings' fixes apply.
    pub fn with_fixes(
        me: &str,
        can_write: bool,
        policy: Policy,
        persisted: Option<Persisted>,
        fixes: Fixes,
    ) -> Self {
        let persisted = persisted.filter(|p| p.claim.well_formed());
        let released = persisted
            .as_ref()
            .is_some_and(|p| p.released && fixes.persist_release);
        Self {
            me: me.to_ascii_lowercase(),
            can_write,
            policy,
            fixes,
            joined: false,
            accepted: persisted.map(|p| p.claim),
            released,
            synced: false,
            seq: 0,
            state: Bytes::default(),
            early: BTreeMap::new(),
            tail: VecDeque::new(),
            ordered: VecDeque::new(),
            sent_passes: VecDeque::new(),
            asks: BTreeSet::new(),
            evidence: None,
            pending_yielded: None,
            took_wanting: false,
            in_evidence: false,
            fresh_now: 0,
            peers_seen: BTreeMap::new(),
            reported: VecDeque::new(),
            submits: BTreeMap::new(),
            last_gap_hello: None,
            want: None,
            gate: None,
            link_up: true,
            link_since: 0,
            link_down_since: None,
            last_heard_holder: 0,
            lapse_reported: false,
            lapse_since: None,
            last_sent_all: None,
            heard: BTreeMap::new(),
            heard_holding: BTreeMap::new(),
            presence: BTreeMap::new(),
            clocks: BTreeMap::new(),
            fresh_seed: None,
            fresh_count: 0,
            own_fresh: VecDeque::new(),
            entitled: None,
            pending_join: None,
            windows: BTreeMap::new(),
            window_order: BTreeMap::new(),
            candidates: BTreeMap::new(),
            closed_after: BTreeMap::new(),
            deferred: BTreeMap::new(),
            probed: BTreeMap::new(),
            probe_times: VecDeque::new(),
            answered: BTreeMap::new(),
            to_echo: VecDeque::new(),
        }
    }

    /// The host no longer accepts `member` (§S2: revoked, suspended, expired or a newer
    /// session): drop every freshness window for its keys, so none of its frames is accepted.
    pub fn forget_member(&mut self, member: &str) {
        self.windows.retain(|(m, _), _| m != member);
        self.window_order.remove(member);
        self.candidates.remove(member);
        self.deferred.remove(member);
        self.answered.remove(member);
        // Revision 17: no echo of an earlier `fresh` reopens any of its keys.
        self.closed_after.insert(member.to_owned(), self.fresh_count);
    }
    /// Every `(member, key)` with an open window or a candidate (revision 17).
    pub fn known_keys(&self) -> BTreeSet<(MemberId, String)> {
        let mut out: BTreeSet<(MemberId, String)> = self.windows.keys().cloned().collect();
        for (m, c) in &self.candidates {
            out.extend(c.iter().map(|k| (m.clone(), k.clone())));
        }
        out
    }
    /// Whether this member holds anything for `member`'s session key `key`: an open window
    /// or a candidate (revision 17). The codec keeps keys only while this holds.
    pub fn knows_key(&self, member: &str, key: &str) -> bool {
        self.windows.contains_key(&(member.to_owned(), key.to_owned()))
            || self
                .candidates
                .get(member)
                .is_some_and(|c| c.iter().any(|k| k == key))
    }
    /// The number of candidate keys held for `member` (revision 17).
    pub fn candidates_for(&self, member: &str) -> usize {
        self.candidates.get(member).map_or(0, VecDeque::len)
    }
    /// The number of members with a `closed after` mark (revision 17).
    pub fn closed_marks(&self) -> usize {
        self.closed_after.len()
    }
    /// The number of freshness windows held for `member`.
    pub fn windows_for(&self, member: &str) -> usize {
        self.windows.keys().filter(|(m, _)| m == member).count()
    }
    /// Whether the host's entitled set names `member` (false until the host supplies it).
    fn is_entitled(&self, member: &str) -> bool {
        self.entitled.as_ref().is_some_and(|e| e.contains(member))
    }

    /// The earliest time (this member's clock, ms) at which a [`Input::Tick`] may do
    /// something, or `None` when no timer is pending. A host schedules one tick for it
    /// (§S11 G5: within 250 ms of the due time) instead of polling; a time already past
    /// means "now". Every other input may change it, so the host asks again after each one.
    pub fn next_deadline(&self) -> Option<u64> {
        if !self.joined {
            return None;
        }
        let p = &self.policy;
        let mut d: Option<u64> = None;
        let mut at = |t: u64| d = Some(d.map_or(t, |x| x.min(t)));
        for (_, t) in self.presence.values() {
            at(t.saturating_add(p.presence_timeout_ms));
        }
        if self.fixes.submit_retry && self.holder().is_some_and(|h| h != self.me) {
            for s in self.submits.values() {
                at(s.last.saturating_add(p.ask_timeout_ms));
            }
        }
        if let Some(until) = self.gate {
            if self.is_holder() {
                at(until);
            }
        }
        if self.fixes.pass_ack {
            for sp in &self.sent_passes {
                at(sp.last.saturating_add(sp.interval));
            }
        }
        for m in self.deferred.keys() {
            let due = self.probed.get(m).map_or(0, |t| t.saturating_add(p.ask_timeout_ms));
            // The global cap may push it a little later; ask again then.
            let oldest = self.probe_times.front().map_or(0, |t| t.saturating_add(1_000));
            at(due.max(if self.probe_times.len() >= PROBES_PER_SECOND { oldest } else { 0 }));
        }
        if self.sends_as_holder() {
            at(self.last_sent_all.map_or(0, |t| t.saturating_add(p.beat_ms)));
            return d;
        }
        if self.link_up && self.holder().is_some_and(|h| h != self.me) && !self.lapse_reported {
            at(self.last_heard_holder.max(self.link_since).saturating_add(p.holder_timeout_ms));
        }
        if let Some(w) = &self.want {
            if !self.is_holder() && self.may_take() && self.term_left() {
                if self.no_holder() || (self.lapse_reported && self.lapsed_since_ok()) {
                    at(0);
                }
                if let Some(a) = w.asked_at {
                    if !w.declined {
                        at(a.saturating_add(p.ask_timeout_ms));
                    }
                }
                if w.evidence_only && self.fixes.evidence_refresh {
                    if let Some(t) = self.lapse_since {
                        at(t.saturating_add(p.ask_timeout_ms));
                    }
                }
            }
        }
        d
    }
    /// Revisions 4–6 hold a kept want back for askTimeoutMs after the lapse hello.
    fn lapsed_since_ok(&self) -> bool {
        !self.want.as_ref().is_some_and(|w| w.evidence_only && self.fixes.evidence_refresh)
    }

    /// Whether a frame from `member` under carrier `key` and number `n` would pass the §S3
    /// window check now (an open window at or below `n`). For harnesses.
    pub fn window_admits(&self, member: &str, key: &str, n: u64) -> bool {
        self.windows.get(&(member.to_string(), key.to_string())).is_some_and(|floor| n >= *floor)
    }

    /// As an [`Input::Entitled`] given before anything else: the host's entitled set at
    /// start-up. For harnesses and hosts that know the set when they build the machine.
    pub fn with_entitled<I: IntoIterator<Item = S>, S: Into<MemberId>>(mut self, writers: I) -> Self {
        self.entitled = Some(writers.into_iter().map(Into::into).collect());
        self
    }

    /// Seed the `fresh` values of this process's hellos (16 random bytes from the host, new
    /// for every process start). Without a seed every `fresh` is zero, which is only for
    /// tests and model checking without the freshness gate.
    pub fn with_fresh_seed(mut self, seed: [u8; 16]) -> Self {
        self.fresh_seed = Some(seed);
        self
    }

    // -----------------------------------------------------------------------------------
    // Queries.

    /// This member's ID.
    pub fn me(&self) -> &str {
        &self.me
    }
    /// Whether this member's carriers work, as the last `LinkUp` or `LinkDown` said.
    pub fn link_is_up(&self) -> bool {
        self.link_up
    }
    /// When the current outage began (monotonic ms), while the link is down.
    pub fn link_down_since(&self) -> Option<u64> {
        self.link_down_since
    }
    /// Whether it has joined.
    pub fn joined(&self) -> bool {
        self.joined
    }
    /// The greatest accepted claim.
    pub fn accepted(&self) -> Option<&Claim> {
        self.accepted.as_ref()
    }
    /// Whether the accepted claim has been released (no holder).
    pub fn released(&self) -> bool {
        self.released
    }
    /// What this member has persisted (claim and tombstone).
    pub fn persisted(&self) -> Option<Persisted> {
        self.accepted.clone().map(|claim| Persisted {
            released: self.released && claim.holder == self.me,
            claim,
        })
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
    /// Whether a timer can still change this member without input: it wants the role, it is
    /// a gated holder (§S6), or it has unanswered submits.
    pub fn pending(&self) -> bool {
        self.joined
            && (self.want.is_some()
                || self.gate.is_some()
                || !self.submits.is_empty()
                || (self.fixes.pass_ack && !self.sent_passes.is_empty()))
    }
    /// Members whose ask is pending (§S5).
    pub fn asks(&self) -> impl Iterator<Item = &MemberId> {
        self.asks.iter()
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
        for p in &self.sent_passes {
            (&p.claim, &p.next, p.seq, &p.snapshot, age(p.last), p.interval).hash(h);
        }
        self.asks.hash(h);
        self.evidence.as_ref().map(|(f, t)| (f, age(*t))).hash(h);
        self.pending_yielded
            .as_ref()
            .map(|p| (&p.first, &p.body, &p.held, p.left, age(p.last)))
            .hash(h);
        self.took_wanting.hash(h);
        self.peers_seen.hash(h);
        self.reported.hash(h);
        for (k, p) in &self.submits {
            (k, &p.payload, p.tries, age(p.last)).hash(h);
        }
        self.last_gap_hello
            .map(|t| now.saturating_sub(t).min(GAP_HELLO_MS))
            .hash(h);
        match &self.want {
            None => 0u8.hash(h),
            Some(w) => {
                1u8.hash(h);
                w.asked_at.map(age).hash(h);
                w.heard_since.hash(h);
                w.evidence_only.hash(h);
                w.kept.hash(h);
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
        self.lapse_since.map(age).hash(h);
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
        self.fresh_seed.hash(h);
        self.fresh_count.hash(h);
        for (id, t, c) in &self.own_fresh {
            (id, now.saturating_sub(*t).min(FRESH_MEMORY_MS + 1), c).hash(h);
        }
        self.candidates.hash(h);
        self.closed_after.hash(h);
        self.deferred.hash(h);
        self.entitled.hash(h);
        self.pending_join.hash(h);
        self.windows.hash(h);
        self.window_order.hash(h);
        for (k, t) in &self.probed {
            (k, age(*t)).hash(h);
        }
        for t in &self.probe_times {
            age(*t).hash(h);
        }
        self.answered.hash(h);
        self.to_echo.hash(h);
    }

    // -----------------------------------------------------------------------------------
    // The machine.

    /// Process one input at `now` (this member's monotonic ms).
    pub fn handle(&mut self, input: Input, now: u64) -> Vec<Output> {
        let mut out = Vec::new();
        self.fresh_now = now;
        match input {
            Input::Frame {
                frame,
                writer,
                key,
                n,
            } => self.on_frame(frame, writer, key, n, now, &mut out),
            Input::Entitled { writers } => {
                let set: BTreeSet<MemberId> = writers.into_iter().collect();
                self.asks.retain(|a| set.contains(a));
                // A pass to a member that is no longer a writer is no longer owed.
                self.sent_passes.retain(|p| set.contains(&p.next.holder));
                self.entitled = Some(set);
                // §S1 (revision 12): a join waits for the entitled set.
                if let Some(state) = self.pending_join.take() {
                    self.on_command(Command::Join { state }, now, &mut out);
                }
            }
            Input::LegacyEvidence {
                frame,
                writer,
                via: _,
                windowed,
            } => {
                // Revisions 4–6 only: unreachable with any current preset.
                if self.fixes.evidence {
                    self.in_evidence = true;
                    if windowed {
                        self.on_frame(frame, writer, None, None, now, &mut out);
                    } else {
                        self.claim_only(frame, writer, now, &mut out);
                    }
                    self.in_evidence = false;
                }
            }
            Input::Tick => self.on_tick(now, &mut out),
            Input::LinkUp => self.on_link_up(now, &mut out),
            Input::LinkDown => {
                if self.link_up {
                    self.link_up = false;
                    self.link_down_since = Some(now);
                }
            }
            Input::Outage { down_ms, ended } => {
                // What `LinkDown` at `now - down_ms` does (only when the link was up: an outage
                // already under way keeps its own start), then `LinkUp` at `now`.
                if self.link_up {
                    self.link_up = false;
                    self.link_down_since = Some(now.saturating_sub(down_ms));
                }
                if ended {
                    self.on_link_up(now, &mut out);
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
    fn persist(&self, out: &mut Out) {
        if let Some(p) = self.persisted() {
            out.push(Output::Persist {
                claim: p.claim,
                released: p.released && self.fixes.persist_release,
            });
        }
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
    /// `hello.heard` about the accepted claim's holder (§S4, revision 4).
    fn heard_of_holder(&self, now: u64) -> Heard {
        let Some(h) = self.accepted.as_ref().map(|c| c.holder.clone()) else {
            return Heard::Unknown;
        };
        if h == self.me {
            return Heard::Live;
        }
        let timeout = self.policy.holder_timeout_ms;
        if self
            .heard_holding
            .get(&h)
            .is_some_and(|t| now.saturating_sub(*t) < timeout)
        {
            Heard::Live
        } else if self.link_up && now.saturating_sub(self.link_since) >= timeout {
            Heard::Lapsed
        } else {
            Heard::Unknown
        }
    }
    fn next_fresh(&mut self) -> Id {
        let Some(seed) = self.fresh_seed else {
            return Id::default();
        };
        self.fresh_count = self.fresh_count.saturating_add(1);
        let mut d = Sha256::new();
        d.update(seed);
        d.update(self.fresh_count.to_be_bytes());
        let mut b = [0u8; 16];
        b.copy_from_slice(&d.finalize()[..16]);
        let id = Id(b);
        self.own_fresh.push_back((id, self.fresh_now, self.fresh_count));
        while self.own_fresh.len() > OWN_FRESH {
            self.own_fresh.pop_front();
        }
        id
    }
    /// Whether `e`, echoed by `from`, is one of this member's `fresh` values sent within the
    /// last 60 s and (revision 17) after `from`'s windows were last closed.
    fn honours(&self, e: &Id, now: u64, from: &str) -> bool {
        let after = if self.fixes.reopen_challenge {
            self.closed_after.get(from).copied().unwrap_or(0)
        } else {
            0
        };
        self.own_fresh
            .iter()
            .any(|(id, t, c)| id == e && now.saturating_sub(*t) <= FRESH_MEMORY_MS && *c > after)
    }
    /// Revision 17: `from`'s windows were closed now; only a later challenge reopens one.
    fn mark_closed(&mut self, from: &str) {
        if self.fixes.reopen_challenge {
            self.closed_after.insert(from.to_owned(), self.fresh_count);
        }
    }
    fn send_hello_echo(
        &mut self,
        out: &mut Out,
        to: Option<&str>,
        lapsed: bool,
        echo: Vec<Id>,
        now: u64,
    ) {
        let fresh = self.next_fresh();
        let heard = self.fixes.evidence.then(|| self.heard_of_holder(now));
        let seen = self.seen();
        self.send(
            out,
            to,
            false,
            Body::Hello {
                fresh,
                echo,
                seen,
                heard,
                lapsed,
            },
        );
    }
    fn send_hello(&mut self, out: &mut Out, to: Option<&str>, lapsed: bool, now: u64) {
        let echo: Vec<Id> = self.to_echo.drain(..).collect();
        self.send_hello_echo(out, to, lapsed, echo, now);
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
        self.send_hello(out, Some(to), false, now);
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
    /// Revision 3's hearsay test for renewing (kept for `Fixes::REV3` and earlier).
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
    /// §S1 (revision 8): with `append`, a payload is at most `maxPayload` − 4 bytes, so it
    /// fits a snapshot with its framing; otherwise at most `maxPayload`.
    fn payload_fits(&self, payload: &Bytes) -> bool {
        let max = if self.fixes.append_bound && self.policy.fold == Fold::Append {
            self.policy.max_payload.saturating_sub(4)
        } else {
            self.policy.max_payload
        };
        payload.len() as u64 <= max
    }
    fn may_take(&self) -> bool {
        self.joined && self.can_write && self.policy.take == TakeRule::Free
    }
    fn term_left(&self) -> bool {
        self.accepted.as_ref().is_none_or(|c| c.term < MAX_TERM)
    }

    /// Whether a rank-1 claim carried by a non-pass frame from `from` is acceptable (§S4 3).
    fn rank1_ok(&self, c: &Claim, from: &str) -> bool {
        self.fixes.rank1_from_holder && c.holder == from
    }
    /// The claim as this member orders it (revision 1: unverified rank 1 orders as rank 0).
    fn ordering(&self, c: &Claim, from: &str) -> Claim {
        // Since revision 2 (F1) claims order as they are; only revision 1 ordered an
        // unverified rank-1 claim as rank 0.
        if !self.fixes.rank1_from_holder
            && c.rank == 1
            && !self.rank1_ok(c, from)
            && self.accepted.as_ref() != Some(c)
        {
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

    fn reset_lane(&mut self) {
        self.early.clear();
        self.tail.clear();
        self.ordered.clear();
        self.asks.clear();
        self.evidence = None;
        self.seq = 0;
    }

    /// Accept `c` (greater than the current claim), optionally with its initial state.
    fn adopt(&mut self, c: Claim, snapshot: Option<Bytes>, now: u64, out: &mut Out) {
        let was_holder = self.is_holder();
        let was_wanting = self.want.is_some() || (was_holder && self.took_wanting);
        let old = (self.accepted.clone(), self.seq, self.state.clone());
        self.accepted = Some(c.clone());
        self.released = false;
        self.gate = None;
        self.reset_lane();
        self.lapse_reported = false;
        self.last_heard_holder = now;
        if !self.fixes.pass_ack {
            self.sent_passes.retain(|p| p.next >= c);
        }
        let mine = c.holder == self.me;
        match &snapshot {
            Some(s) => {
                self.state = s.clone();
                self.synced = true;
            }
            None => self.synced = mine,
        }
        self.persist(out);
        if was_holder && !mine {
            Self::event(out, Event::Yielded { to: c.clone() });
            // §S5 yielding state (revision 4): tell the taker what this member held.
            if let (true, 0, Some(held)) = (self.fixes.state_reports, c.rank, old.0) {
                let body = Body::Yielded {
                    claim: held.clone(),
                    seq: old.1,
                    snapshot: old.2,
                };
                self.send(out, Some(&c.holder), false, body.clone());
                self.pending_yielded = Some(PendingYield {
                    first: c.holder.clone(),
                    body,
                    held,
                    left: 1,
                    last: now,
                });
            }
        }
        // R1d (revision 5): yielding to forwarded evidence keeps the wish for the role; take
        // again only once that holder is lapsed (not on the ask timeout).
        if !mine && was_wanting && self.in_evidence && self.fixes.evidence_keeps_want {
            let snapshot = self.want.as_ref().and_then(|w| w.snapshot.clone());
            let kept = self.want.is_none();
            self.want = Some(Want {
                asked_at: None,
                declined: false,
                heard_since: false,
                evidence_only: true,
                kept,
                snapshot,
            });
        }
        self.took_wanting = false;
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
                self.send_hello(out, Some(&c.holder), false, now);
            }
            if let Some(w) = &mut self.want {
                // Ask the new holder. A want kept only because this member had taken does not
                // ask (finding R1g): if the holder is in fact reachable, an immediate ask hands
                // the role back to a returning holder; it waits for the lapse instead.
                let silent = w.evidence_only && w.kept && self.fixes.evidence_refresh;
                w.asked_at = Some(now);
                w.declined = false;
                w.heard_since = false;
                if !silent {
                    self.send(out, Some(&c.holder), false, Body::Ask { claim: c.clone() });
                }
            }
            self.resend_submits(now, out);
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
        self.send(out, None, false, Body::Take { claim: claim.clone() });
        self.send_state(out, None, now);
        Self::event(
            out,
            Event::BecameHolder {
                claim,
                snapshot: self.state.clone(),
                via,
            },
        );
        self.order_own_submits(now, out);
    }
    fn become_holder(&mut self, claim: Claim, now: u64, out: &mut Out) {
        // A displaced member that holds again keeps its own state.
        self.pending_yielded = None;
        self.accepted = Some(claim);
        self.released = false;
        self.gate = None;
        self.want = None;
        self.synced = true;
        self.reset_lane();
        self.last_heard_holder = now;
        self.persist(out);
    }

    /// §S5 renewing: raise the claim above `term` (never past 2^53 − 1).
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
        let max = self.fixes.append_bound.then_some(self.policy.max_payload);
        self.state = self
            .policy
            .fold
            .apply_bounded(&self.state, &h.payload, self.policy.tail, max);
        self.seq = seq;
        if h.origin == self.me {
            self.submits.remove(&h.id);
        }
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
        while let Some(next) = self.seq.checked_add(1) {
            let Some(h) = self.early.remove(&next) else {
                break;
            };
            self.apply(next, h, out);
        }
        let seq = self.seq;
        self.early.retain(|k, _| *k > seq);
    }

    /// Order one message as holder (publish or submit). Returns false at seq exhaustion.
    fn order(&mut self, origin: MemberId, id: Id, payload: Bytes, now: u64, out: &mut Out) -> bool {
        let Some(claim) = self.accepted.clone() else {
            return false;
        };
        let Some(seq) = self.seq.checked_add(1).filter(|s| *s <= MAX_INT) else {
            return false;
        };
        let h = Held {
            origin: origin.clone(),
            id,
            payload: payload.clone(),
        };
        self.ordered.push_back(id);
        while self.ordered.len() as u64 > self.policy.tail {
            self.ordered.pop_front();
        }
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
        true
    }

    /// A member that became holder orders its own unanswered submits.
    fn order_own_submits(&mut self, now: u64, out: &mut Out) {
        let pending: Vec<(Id, Bytes)> = self
            .submits
            .iter()
            .map(|(k, p)| (*k, p.payload.clone()))
            .collect();
        for (id, payload) in pending {
            let me = self.me.clone();
            if !self.ordered.contains(&id) {
                self.order(me, id, payload, now, out);
            }
            self.submits.remove(&id);
        }
    }
    /// §S8 (revision 4): resend unanswered submits to the (new) holder.
    fn resend_submits(&mut self, now: u64, out: &mut Out) {
        if !self.fixes.submit_retry {
            return;
        }
        let Some(h) = self.holder().map(str::to_owned).filter(|h| *h != self.me) else {
            return;
        };
        let ids: Vec<Id> = self.submits.keys().copied().collect();
        for id in ids {
            self.retry_submit(id, &h, now, out);
        }
    }
    fn retry_submit(&mut self, id: Id, holder: &str, now: u64, out: &mut Out) {
        let Some(p) = self.submits.get_mut(&id) else {
            return;
        };
        if p.tries >= SUBMIT_TRIES {
            self.submits.remove(&id);
            Self::event(out, Event::SubmitFailed { id });
            return;
        }
        p.tries += 1;
        p.last = now;
        let payload = p.payload.clone();
        self.send(out, Some(holder), false, Body::Submit { id, payload });
    }

    // -----------------------------------------------------------------------------------
    // Frames.

    /// §S3 freshness. Returns whether to process the frame in full; a `hello` from a key
    /// without an open window is answered and otherwise only its `fresh`/`echo` are used.
    fn freshness(
        &mut self,
        f: &Frame,
        key: Option<String>,
        n: Option<u64>,
        now: u64,
        out: &mut Out,
    ) -> bool {
        if self.in_evidence {
            // The carrier reported an open window for the origin's key (§S3).
            return true;
        }
        let Body::Hello { fresh, echo, .. } = &f.body else {
            // Non-hello: only through an open window, at or above its floor.
            let Some((k, n)) = key.zip(n) else {
                return true;
            };
            let window = self.windows.get(&(f.from.clone(), k)).copied();
            if window.is_none() && self.fixes.freshness_probe {
                // Finding B5: without an open window this member drops the sender's frames
                // and, if its own hello was lost, would never speak to it again. Probe with a
                // hello, at most once per askTimeoutMs per sender.
                let due = self
                    .probed
                    .get(&f.from)
                    .is_none_or(|t| now.saturating_sub(*t) >= self.policy.ask_timeout_ms);
                if due {
                    let ask = self.policy.ask_timeout_ms;
                    self.probed.retain(|_, t| now.saturating_sub(*t) < ask);
                    self.probed.insert(f.from.clone(), now);
                    let to = f.from.clone();
                    self.send_hello_echo(out, Some(&to), false, Vec::new(), now);
                }
            }
            return window.is_some_and(|floor| n >= floor);
        };
        let (Some(k), Some(n)) = (key, n) else {
            return true;
        };
        let wk = (f.from.clone(), k);
        let mut opened = false;
        match self.windows.get(&wk) {
            Some(floor) if n < *floor => return false,
            Some(_) => {}
            None => {
                if echo.iter().any(|e| self.honours(e, now, &f.from)) {
                    if let Some(c) = self.candidates.get_mut(&wk.0) {
                        c.retain(|k| *k != wk.1);
                    }
                    self.windows.insert(wk.clone(), n);
                    if self.fixes.window_cap {
                        // Revision 7: at most 4 keys per member, the first opened closed.
                        let order = self.window_order.entry(wk.0.clone()).or_default();
                        order.push_back(wk.1.clone());
                        let mut closed = false;
                        while order.len() > MAX_KEYS_PER_MEMBER {
                            if let Some(old) = order.pop_front() {
                                self.windows.remove(&(wk.0.clone(), old));
                                closed = true;
                            }
                        }
                        if closed {
                            self.mark_closed(&wk.0);
                        }
                    }
                    opened = true;
                } else if self.fixes.reopen_challenge {
                    // Revision 17: a candidate, at most 4 per member, the oldest dropped.
                    let c = self.candidates.entry(wk.0.clone()).or_default();
                    if !c.contains(&wk.1) {
                        c.push_back(wk.1.clone());
                        while c.len() > MAX_KEYS_PER_MEMBER {
                            c.pop_front();
                        }
                    }
                }
            }
        }
        let open = self.windows.contains_key(&wk);
        // Answer a fresh we have not answered, unless the hello is itself an answer to us
        // through a window that was already open (finding R4a: otherwise the two members
        // answer each other's answers forever).
        let answers_us = echo.iter().any(|e| self.honours(e, now, &f.from));
        // Revision 17: a hello from a key without an open window (a candidate,
        // possibly an old key replayed) is answered under the probe limit, per member once per
        // askTimeoutMs and four a second in all.
        let wants = self.answered.get(&f.from) != Some(fresh) && (!answers_us || opened);
        let budget =
            !wants || open || !self.fixes.reopen_challenge || self.probe_budget(&f.from, now);
        if wants && !budget {
            // Defer the answer to when this member's budget reopens (on a tick).
            let d = self.deferred.entry(f.from.clone()).or_default();
            if !d.contains(fresh) {
                d.push_back(*fresh);
                while d.len() > MAX_ECHO {
                    d.pop_front();
                }
            }
        }
        if wants && budget {
            self.answered.insert(f.from.clone(), *fresh);
            let to = f.from.clone();
            self.send_hello_echo(out, Some(&to), false, vec![*fresh], now);
        }
        open
    }

    fn on_frame(
        &mut self,
        f: Frame,
        writer: bool,
        key: Option<String>,
        n: Option<u64>,
        now: u64,
        out: &mut Out,
    ) {
        if !self.joined || f.from == self.me {
            return;
        }
        if f.to.as_ref().is_some_and(|t| *t != self.me) {
            return;
        }
        // §S1 (revision 12): a frame comes from a writer only if the host says so and the
        // sender is in the entitled set; with no set yet, from nobody.
        let from_writer = writer && self.is_entitled(&f.from);
        if f.body.needs_writer() && !from_writer {
            return;
        }
        let mut f = f;
        if self.fixes.writer_claims && !self.admit_claims(&mut f, from_writer) {
            return;
        }
        if !f.body.in_range(self.policy.max_payload) {
            return;
        }
        if let Body::Msg { payload, .. } | Body::Submit { payload, .. } = &f.body {
            if !self.payload_fits(payload) {
                return;
            }
        }
        if !self.freshness(&f, key, n, now, out) {
            return;
        }
        if let Body::Hello { fresh, seen, .. } = &f.body {
            if self.fixes.evidence {
                self.peers_seen
                    .insert(f.from.clone(), seen.as_ref().map(|s| s.claim.clone()));
            }
            if self.fresh_seed.is_some() && !self.to_echo.contains(fresh) {
                self.to_echo.push_back(*fresh);
                while self.to_echo.len() > MAX_ECHO {
                    self.to_echo.pop_front();
                }
            }
        }
        let from = f.from.clone();
        self.heard.insert(from.clone(), now);
        // §S5 yielding state. Revision 5: resend to whichever member is now the holder, when
        // it is heard directly, at most once per askTimeoutMs, until an `ack`. Revision 4:
        // once, when the taker is heard.
        let ask = self.policy.ask_timeout_ms;
        let holder_now = self.holder().map(str::to_owned);
        let direct = !self.in_evidence;
        if let Some(p) = self.pending_yielded.as_mut() {
            let target = if self.fixes.yielded_ack {
                holder_now.filter(|h| *h == from && direct)
            } else {
                (p.first == from && p.left > 0).then(|| from.clone())
            };
            if let Some(to) = target {
                if now.saturating_sub(p.last) >= ask {
                    p.last = now;
                    p.left = p.left.saturating_sub(1);
                    let body = p.body.clone();
                    if !self.fixes.yielded_ack && p.left == 0 {
                        self.pending_yielded = None;
                    }
                    self.send(out, Some(&to), false, body);
                }
            }
        }
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
            let direct = !(self.in_evidence && self.fixes.evidence_keeps_want);
            // R1g (reading): a want kept only because the holder seemed unreachable ends when
            // the holder is heard directly.
            if direct && self.want.as_ref().is_some_and(|w| w.evidence_only) {
                if self.want.as_ref().is_some_and(|w| w.kept) {
                    self.want = None;
                } else if let Some(w) = &mut self.want {
                    w.evidence_only = false;
                }
            }
            if let Some(w) = &mut self.want {
                if w.asked_at.is_some() && direct {
                    w.heard_since = true;
                }
            }
        }
        // §S5: resend the pass. Revision 15: on any frame from the asker, at most once per
        // askTimeoutMs, until it acknowledges; before, when it speaks under an older claim.
        let acked = match &f.body {
            Body::Ack { passed: Some(c), .. } => Some(c.clone()),
            _ => None,
        };
        let pass_ack = self.fixes.pass_ack;
        let mut resend = Vec::new();
        for p in self.sent_passes.iter_mut() {
            if from != p.next.holder || acked.as_ref() == Some(&p.next) {
                continue;
            }
            let due = if pass_ack {
                now.saturating_sub(p.last) >= p.interval
            } else {
                f.body.claim().is_some_and(|c| *c < p.next)
            };
            if due {
                p.last = now;
                p.interval = backoff(p.interval, &self.policy, self.fixes);
                resend.push(Body::Pass {
                    claim: p.claim.clone(),
                    next: p.next.clone(),
                    seq: p.seq,
                    snapshot: p.snapshot.clone(),
                });
            }
        }
        for body in resend {
            self.send(out, Some(&from), false, body);
        }

        self.correct_lesser(&f, holding_frame, now, out);
        let frame_for_evidence = f.clone();
        match f.body {
            Body::Hello { seen, heard, .. } => self.on_hello(&from, seen, heard, now, out),
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
                        self.send_hello(out, Some(&from), false, now);
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
                    if self.synced && Some(seq) == self.seq.checked_add(1) {
                        self.apply(seq, h, out);
                        self.drain_early(out);
                    } else if seq > self.seq.saturating_add(1) || !self.synced {
                        if seq <= self.seq.saturating_add(self.policy.tail) {
                            self.early.insert(seq, h);
                            // §S8: at most `tail` early messages.
                            while self.early.len() as u64 > self.policy.tail {
                                self.early.pop_last();
                            }
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
                // §S8: dedupe over the last `tail` ids of the term.
                if !self.sends_as_holder() || self.ordered.contains(&id) {
                    return;
                }
                self.order(from, id, payload, now, out);
            }
            Body::Refuse { id, reason } => {
                if self.holder() == Some(from.as_str()) {
                    self.submits.remove(&id);
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
                    self.asks.insert(from.clone());
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
            Body::Yielded {
                claim,
                seq,
                snapshot,
            } => {
                // Revision 7: only from the member named as holder in the claim it carries.
                if self.fixes.sender_checks && claim.holder != from {
                    return;
                }
                let key = (from.clone(), claim.clone());
                if self.fixes.yielded_ack && !self.sends_as_holder() {
                    // Revision 5: only the holder reports and acknowledges; the displaced
                    // member resends to the holder it accepts.
                    return;
                }
                if self.fixes.state_reports && !self.reported.contains(&key) {
                    self.reported.push_back(key);
                    while self.reported.len() > 8 {
                        self.reported.pop_front();
                    }
                    Self::event(
                        out,
                        Event::Displaced {
                            from: from.clone(),
                            claim: claim.clone(),
                            seq,
                            snapshot,
                        },
                    );
                }
                if self.fixes.yielded_ack {
                    // Report first, then acknowledge (a crash between them loses no report).
                    self.send(
                        out,
                        Some(&from),
                        false,
                        Body::Ack {
                            yielded: Some(claim),
                            passed: None,
                        },
                    );
                }
            }
            Body::Ack { yielded, passed } => {
                if let Some(yielded) = yielded {
                    // Revision 7: only from the member this member accepts as holder.
                    if self.fixes.sender_checks && self.holder() != Some(from.as_str()) {
                        return;
                    }
                    if self.pending_yielded.as_ref().is_some_and(|p| p.held == yielded) {
                        self.pending_yielded = None;
                    }
                }
                if let Some(passed) = passed {
                    // Revision 15: only from the member the pass named.
                    self.sent_passes
                        .retain(|p| !(p.next == passed && p.next.holder == from));
                }
            }
            Body::Ping { t } => {
                self.send(
                    out,
                    Some(&from),
                    false,
                    Body::Pong {
                        t: now.min(MAX_INT),
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
            Body::Bye { claim, leaving } => {
                if self.presence.remove(&from).is_some() {
                    Self::event(
                        out,
                        Event::PresenceChanged {
                            member: from.clone(),
                            payload: None,
                        },
                    );
                }
                if leaving {
                    self.asks.remove(&from);
                }
                if let Some(c) = claim {
                    if self.fixes.renew_wider
                        && self.sends_as_holder()
                        && c.holder == from
                        && self.accepted.as_ref().is_some_and(|a| c > *a)
                    {
                        // A released claim has no holder; stay holder above it.
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
        // Keep the latest broadcast holder frame of the accepted claim as evidence.
        let fe = frame_for_evidence;
        // Only a frame heard directly from its holder is evidence: a forwarded copy must not
        // renew its freshness, or two members would keep a dead holder alive by forwarding it
        // to each other (finding R1h).
        if !self.in_evidence
            && fe.to.is_none()
            && matches!(fe.body, Body::State { .. } | Body::Beat { .. } | Body::Msg { .. })
            && fe.body.claim() == self.accepted.as_ref()
            && fe.body.claim().is_some_and(|c| c.holder == fe.from)
        {
            // Members whose last hello named a lesser claim or none get this evidence now.
            if self.fixes.evidence && self.fixes.evidence_push && !self.is_holder() {
                let accepted = self.accepted.clone();
                for (to, seen) in self.peers_seen.iter_mut() {
                    if *to != fe.from && seen.as_ref() < accepted.as_ref() {
                        out.push(Output::Forward {
                            to: to.clone(),
                            frame: fe.clone(),
                        });
                        *seen = accepted.clone();
                    }
                }
            }
            self.evidence = Some((fe, now));
        }
    }

    /// Revision 15 §S4 rule 1 and the term step: a claim in a frame from a member that may
    /// only read is ignored in every field, and so is a claim more than [`MAX_TERM_STEP`]
    /// terms above the accepted term, or (outside `hello.seen`, which is only ever renewed
    /// over) one naming a non-writer as holder. A `hello` or `bye` keeps its other fields (a
    /// reader's `hello.seen` survives only when it names this member's own accepted claim, as
    /// a resume position); any other frame whose claim is ignored is dropped. Returns whether
    /// to go on.
    fn admit_claims(&self, f: &mut Frame, from_writer: bool) -> bool {
        let base = self.accepted.as_ref().map_or(0, |a| a.term);
        let step = |c: &Claim| c.term <= base.saturating_add(MAX_TERM_STEP);
        let ok = |c: &Claim| self.is_entitled(&c.holder) && step(c);
        let accepted = self.accepted.as_ref();
        match &mut f.body {
            Body::Hello { seen, .. } => {
                // A writer's `seen` is never adopted unless it names the writer itself (§S4
                // rule 2), but a holder renews over it when nobody holds it; one naming a
                // former writer therefore stays, so a claim accepted before a revocation was
                // known still reaches the holder and is renewed over.
                let keep = seen
                    .as_ref()
                    .is_none_or(|s| step(&s.claim) && (from_writer || Some(&s.claim) == accepted));
                if !keep {
                    *seen = None;
                }
                true
            }
            Body::Bye { claim, .. } => {
                // Revision 17: a reader's `bye` counts only when it releases exactly the
                // accepted claim and that claim is the reader's own (a demoted holder
                // stopping); no other claim in it is considered.
                let demoted = |c: &Claim| {
                    self.fixes.reopen_challenge && Some(c) == accepted && c.holder == f.from
                };
                if claim
                    .as_ref()
                    .is_some_and(|c| if from_writer { !ok(c) } else { !demoted(c) })
                {
                    *claim = None;
                }
                true
            }
            Body::Pass { claim, next, .. } => ok(claim) && ok(next),
            Body::Ack { yielded, passed } => yielded.iter().chain(passed.iter()).all(ok),
            Body::Yielded { claim, .. } => ok(claim),
            other => other.claim().is_none_or(ok),
        }
    }

    /// §S3 evidence without a window: only the claim, under §S4 rules 1–4, and the holder
    /// counts as heard at receipt; `seq`, `snapshot` and `payload` are ignored.
    fn claim_only(&mut self, f: Frame, writer: bool, now: u64, out: &mut Out) {
        if !self.joined || f.from == self.me || !writer || !f.body.in_range(self.policy.max_payload) {
            return;
        }
        let holding = matches!(f.body, Body::State { .. } | Body::Beat { .. } | Body::Msg { .. });
        let Some(c) = f.body.claim().cloned().filter(|c| holding && c.holder == f.from) else {
            return;
        };
        self.consider(&c, &f.from, now, out);
        if self.accepted.as_ref() == Some(&c) && !self.released {
            self.last_heard_holder = now;
            self.lapse_reported = false;
            self.heard_holding.insert(f.from.clone(), now);
        }
    }

    /// §S4 correcting lesser claims, for a member that is not the holder.
    fn correct_lesser(&mut self, f: &Frame, holding_frame: bool, now: u64, out: &mut Out) {
        let from = f.from.clone();
        // Finding R1b: a member with no claim or a lesser one that is not a holder sends no
        // holder frame, so the evidence rule must also answer its `hello`.
        let lesser_hello = ((self.fixes.evidence && self.fixes.evidence_push)
            || self.fixes.hello_correction)
            && match &f.body {
                Body::Hello { seen, .. } => seen
                    .as_ref()
                    .is_none_or(|s| self.accepted.as_ref().is_some_and(|a| s.claim < *a)),
                _ => false,
            };
        let lesser = holding_frame
            && !matches!(f.body, Body::Pass { .. })
            && f.body
                .claim()
                .is_some_and(|c| c.holder == from && self.is_lesser(c, &from));
        if !(lesser || lesser_hello) || self.is_holder() || self.accepted.is_none() {
            return;
        }
        let released_mine =
            self.released && self.accepted.as_ref().is_some_and(|a| a.holder == self.me);
        if released_mine {
            if self.fixes.bye_resend && (lesser || (lesser_hello && self.fixes.hello_correction)) {
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
            return;
        }
        if !self.fixes.answer_lesser {
            return;
        }
        if self.fixes.evidence {
            let timeout = self.policy.holder_timeout_ms;
            let ev = self.evidence.as_ref().filter(|(e, t)| {
                now.saturating_sub(*t) < timeout && e.body.claim() == self.accepted.as_ref()
            });
            if let Some((frame, _)) = ev {
                out.push(Output::Forward {
                    to: from,
                    frame: frame.clone(),
                });
                return;
            }
        }
        if lesser || (lesser_hello && self.fixes.hello_correction) {
            self.send_hello(out, Some(&from), false, now);
        }
    }

    /// §S4: a holder answers a lesser claim in a holder frame or `take` with `state`.
    fn stale(&mut self, claim: &Claim, from: &str, now: u64, out: &mut Out) {
        if self.sends_as_holder() && self.is_lesser(claim, from) {
            self.send_state(out, Some(from), now);
        }
    }

    fn on_hello(
        &mut self,
        from: &str,
        seen: Option<Seen>,
        heard: Option<Heard>,
        now: u64,
        out: &mut Out,
    ) {
        if let Some(s) = &seen {
            if s.claim.holder == from {
                let greater = self.accepted.as_ref().is_none_or(|a| s.claim > *a);
                if self.fixes.renew_wider && self.sends_as_holder() && greater {
                    // A hello does not say whether its sender still holds (it may have
                    // released); a holder raises its claim instead of yielding to it. A
                    // sender that does hold accepts the resulting state and yields.
                    self.renew(s.claim.term, now, out);
                    return;
                }
                self.consider(&s.claim, from, now, out);
            }
        }
        // R1f: a member with fresh evidence answers a report that the holder lapsed.
        if self.fixes.evidence_refresh
            && heard == Some(Heard::Lapsed)
            && seen.as_ref().map(|s| &s.claim) == self.accepted.as_ref()
        {
            if self.sends_as_holder() {
                self.send_state(out, Some(from), now);
                return;
            }
            let timeout = self.policy.holder_timeout_ms;
            if let Some((frame, _)) = self.evidence.as_ref().filter(|(e, t)| {
                now.saturating_sub(*t) < timeout && e.body.claim() == self.accepted.as_ref()
            }) {
                out.push(Output::Forward {
                    to: from.to_owned(),
                    frame: frame.clone(),
                });
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
                Some(q) if self.tail.front().is_some_and(|(first, _)| *first <= q.saturating_add(1)) => {
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
        let other = s.claim.holder != self.me
            && if self.fixes.evidence {
                // Revision 4: only the testimony of a member that listened for that holder
                // (and, R1e, only once this holder has itself been listening that long).
                heard == Some(Heard::Lapsed)
                    && (!self.fixes.renew_guard
                        || (self.link_up
                            && now.saturating_sub(self.link_since) >= self.policy.holder_timeout_ms))
            } else {
                !self.present(&s.claim.holder, now)
            };
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
        // §S4 rule 3: a `pass` from `next.via`, which held `claim`.
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
                // Revision 1: from the holder of the member's previous accepted claim.
                self.accepted.as_ref().is_some_and(|a| a.holder == from)
            };
        if verified && self.fixes.pass_ack && next.holder == self.me {
            self.on_pass_to_me(from, next, snapshot, now, out);
            return;
        }
        if verified
            && self.fixes.renew_wider
            && next.holder == self.me
            && self.is_holder()
            && self.accepted.as_ref().is_some_and(|a| next > *a)
        {
            // §S5: a greater claim naming this holder that it has not acted under (a pass
            // after it took, or a second pass): report the pass's state, renew with its own.
            if self.fixes.state_reports {
                self.reported.push_back((from.to_owned(), next.clone()));
                while self.reported.len() > 8 {
                    self.reported.pop_front();
                }
                Self::event(
                    out,
                    Event::LatePass {
                        from: from.to_owned(),
                        claim: next.clone(),
                        snapshot,
                    },
                );
            }
            self.renew(next.term, now, out);
            return;
        }
        if !verified || self.accepted.as_ref().is_some_and(|a| next <= *a) {
            // R2e: a pass naming this holder that arrives after it already moved past that
            // claim (it renewed on a `hello` naming the pass's claim) is still reported once.
            let key = (from.to_owned(), next.clone());
            if verified
                && self.fixes.state_reports
                && self.fixes.yielded_ack
                && next.holder == self.me
                && self.is_holder()
                && self.accepted.as_ref() != Some(&next)
                && !self.reported.contains(&key)
            {
                self.reported.push_back(key);
                while self.reported.len() > 8 {
                    self.reported.pop_front();
                }
                Self::event(
                    out,
                    Event::LatePass {
                        from: from.to_owned(),
                        claim: next,
                        snapshot,
                    },
                );
            }
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
            self.order_own_submits(now, out);
        } else {
            self.adopt(next, Some(snapshot), now, out);
        }
    }

    /// Revision 15 §S5: a verified `pass` naming this member. Its snapshot reaches the
    /// application (as the starting state, or once as a late pass when this member is
    /// already past it or took meanwhile), and the pass is acknowledged every time.
    fn on_pass_to_me(&mut self, from: &str, next: Claim, snapshot: Bytes, now: u64, out: &mut Out) {
        let greater = self.accepted.as_ref().is_none_or(|a| next > *a);
        let key = (from.to_owned(), next.clone());
        let late = |s: &mut Self, out: &mut Out| {
            if !s.reported.contains(&key) {
                s.reported.push_back(key.clone());
                while s.reported.len() > 8 {
                    s.reported.pop_front();
                }
                Self::event(
                    out,
                    Event::LatePass {
                        from: from.to_owned(),
                        claim: next.clone(),
                        snapshot: snapshot.clone(),
                    },
                );
            }
        };
        if greater && self.is_holder() {
            // A pass after this member took: report it and renew over it with its own state.
            late(self, out);
            self.renew(next.term, now, out);
        } else if greater && self.may_take() {
            let claim = next.clone();
            self.state = snapshot.clone();
            self.become_holder(next.clone(), now, out);
            Self::event(
                out,
                Event::BecameHolder {
                    claim,
                    snapshot: snapshot.clone(),
                    via: Via::Pass,
                },
            );
            self.order_own_submits(now, out);
        } else if self.accepted.as_ref() != Some(&next) {
            late(self, out);
        }
        // Report first, then acknowledge (a crash between them loses no report).
        self.send(
            out,
            Some(from),
            false,
            Body::Ack {
                yielded: None,
                passed: Some(next),
            },
        );
    }

    // -----------------------------------------------------------------------------------
    // Time and links.

    fn on_tick(&mut self, now: u64, out: &mut Out) {
        if !self.joined {
            return;
        }
        // Deferred answers to candidate hellos, once each member's probe budget reopens.
        let members: Vec<MemberId> = self.deferred.keys().cloned().collect();
        for m in members {
            if self.probe_budget(&m, now) {
                let echo: Vec<Id> = self.deferred.remove(&m).map(Vec::from).unwrap_or_default();
                if let Some(last) = echo.last() {
                    self.answered.insert(m.clone(), *last);
                }
                self.send_hello_echo(out, Some(&m), false, echo, now);
            }
        }
        // Beyond revision 15's text: an unacknowledged pass is also resent on a timer, at
        // most once per askTimeoutMs, since an asker that moved on and listens quietly may
        // never send a frame the passer hears.
        if self.fixes.pass_ack {
            let (policy, fixes) = (self.policy.clone(), self.fixes);
            let mut resend = Vec::new();
            for p in self.sent_passes.iter_mut() {
                if now.saturating_sub(p.last) >= p.interval {
                    p.last = now;
                    p.interval = backoff(p.interval, &policy, fixes);
                    resend.push((
                        p.next.holder.clone(),
                        Body::Pass {
                            claim: p.claim.clone(),
                            next: p.next.clone(),
                            seq: p.seq,
                            snapshot: p.snapshot.clone(),
                        },
                    ));
                }
            }
            for (to, body) in resend {
                self.send(out, Some(&to), false, body);
            }
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
        // §S8 (revision 4): resend unanswered submits every askTimeoutMs.
        if self.fixes.submit_retry {
            if let Some(h) = self.holder().map(str::to_owned).filter(|h| *h != self.me) {
                let due: Vec<Id> = self
                    .submits
                    .iter()
                    .filter(|(_, p)| now.saturating_sub(p.last) >= self.policy.ask_timeout_ms)
                    .map(|(k, _)| *k)
                    .collect();
                for id in due {
                    self.retry_submit(id, &h, now, out);
                }
            }
        }
        if let Some(until) = self.gate {
            if now >= until && self.is_holder() {
                // §S6: nobody else claimed within askTimeoutMs; retake.
                self.gate = None;
                if self.term_left() {
                    self.take(None, Via::Take, now, out);
                }
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
        if !lapsed {
            self.lapse_since = None;
        }
        if lapsed && !self.lapse_reported {
            self.lapse_reported = true;
            self.lapse_since = Some(now);
            if let Some(h) = self.holder() {
                let holder = h.to_owned();
                if self.fixes.bye_resend {
                    self.send_hello(out, None, false, now);
                }
                Self::event(out, Event::HolderLapsed { holder });
            }
        }
        if let Some(w) = &self.want {
            if self.is_holder() || !self.may_take() || !self.term_left() {
                return;
            }
            let ask_expired = w.asked_at.is_some_and(|at| {
                !w.declined
                    && !w.evidence_only
                    && now.saturating_sub(at) >= self.policy.ask_timeout_ms
                    && !w.heard_since
            });
            let unanswered = w.asked_at.is_some_and(|at| {
                !w.declined && now.saturating_sub(at) >= self.policy.ask_timeout_ms && w.heard_since
            });
            // R1f: a want kept after evidence takes only askTimeoutMs after the lapse hello, so
            // a member with fresh evidence can answer it.
            let lapse_ok = lapsed
                && !(w.evidence_only
                    && self.fixes.evidence_refresh
                    && self
                        .lapse_since
                        .is_none_or(|t| now.saturating_sub(t) < self.policy.ask_timeout_ms));
            if self.no_holder() || lapse_ok || ask_expired {
                let snapshot = w.snapshot.clone();
                self.take(snapshot, Via::Take, now, out);
                self.took_wanting = self.is_holder();
            } else if unanswered && self.fixes.ask_resend {
                if let (Some(c), Some(w)) = (self.accepted.clone(), self.want.as_mut()) {
                    w.asked_at = Some(now);
                    w.heard_since = false;
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
            self.gate = Some(now.saturating_add(self.policy.ask_timeout_ms));
        }
        let gated = lapsed || self.gate.is_some();
        self.send_hello(out, None, gated, now);
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
                if self.entitled.is_none() {
                    self.pending_join = Some(state);
                    return;
                }
                if let Some(st) = state {
                    // §S6: the application's state, which a restarted holder retakes with.
                    self.state = st;
                }
                self.joined = true;
                self.link_since = now;
                self.last_heard_holder = now;
                // A holder that lost its state (restart) retakes like an out-of-contact
                // holder (§S6). A released claim (tombstone) is not resurrected.
                let restarted = self.is_holder() && !self.synced;
                if restarted {
                    self.gate = Some(now.saturating_add(self.policy.ask_timeout_ms));
                }
                self.send_hello(out, None, restarted, now);
            }
            Command::Leave => {
                let claim = self.is_holder().then(|| self.accepted.clone()).flatten();
                if claim.is_some() {
                    self.released = true;
                    // R3: persist the tombstone before the `bye` reveals it.
                    self.persist(out);
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
                self.took_wanting = false;
                self.persist(out);
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
                        heard_since: false,
                    evidence_only: false,
                    kept: false,
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
                let heard_since = self.want.as_ref().is_some_and(|w| w.heard_since);
                let evidence_only = self.want.as_ref().is_some_and(|w| w.evidence_only);
                self.want = Some(Want {
                    asked_at,
                    declined,
                    heard_since,
                    evidence_only,
                    kept: false,
                    snapshot,
                });
                self.on_tick(now, out);
            }
            Command::Pass { to, snapshot } => {
                if !self.sends_as_holder() || to == self.me {
                    Self::reject(out, "pass", "not-holder");
                    return;
                }
                // §S5 (revision 10): still entitled at the accepted authority head (checked
                // first: losing the entitlement also drops the member's pending ask).
                if !self.is_entitled(&to) {
                    Self::reject(out, "pass", "not-entitled");
                    return;
                }
                // R7: only to a member whose ask is pending under this claim.
                if !self.asks.contains(&to) {
                    Self::reject(out, "pass", "no-ask");
                    return;
                }
                if snapshot.len() as u64 > self.policy.max_payload {
                    Self::reject(out, "pass", "too-large");
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
                    last: now,
                    interval: self.policy.ask_timeout_ms,
                };
                self.took_wanting = false;
                // R3: accept and persist `next` before the pass reveals it.
                self.adopt(next.clone(), Some(snapshot.clone()), now, out);
                self.send(
                    out,
                    None,
                    false,
                    Body::Pass {
                        claim,
                        next,
                        seq: p.seq,
                        snapshot,
                    },
                );
                if !self.fixes.pass_ack {
                    self.sent_passes.clear();
                }
                self.sent_passes.push_back(p);
                while self.sent_passes.len() > MAX_SENT_PASSES {
                    self.sent_passes.pop_front();
                }
            }
            Command::Decline { to } => {
                if !self.sends_as_holder() {
                    Self::reject(out, "decline", "not-holder");
                    return;
                }
                self.asks.remove(&to);
                if let Some(claim) = self.accepted.clone() {
                    self.send(out, Some(&to), false, Body::Decline { claim });
                }
            }
            Command::Publish { id, payload } => {
                if !self.is_holder() {
                    Self::reject(out, "publish", "not-holder");
                    return;
                }
                if !self.payload_fits(&payload) {
                    Self::reject(out, "publish", "too-large");
                    return;
                }
                let me = self.me.clone();
                if !self.order(me, id, payload, now, out) {
                    Self::reject(out, "publish", "seq-exhausted");
                }
            }
            Command::Submit { id, payload } => {
                if !self.can_write {
                    Self::reject(out, "submit", "not-allowed");
                    return;
                }
                if !self.payload_fits(&payload) {
                    Self::reject(out, "submit", "too-large");
                    return;
                }
                if self.is_holder() {
                    let me = self.me.clone();
                    if !self.order(me, id, payload, now, out) {
                        Self::reject(out, "submit", "seq-exhausted");
                    }
                    return;
                }
                if self.fixes.submit_retry {
                    if self.submits.len() as u64 >= self.policy.tail {
                        Self::reject(out, "submit", "too-many-pending");
                        return;
                    }
                    self.submits.insert(
                        id,
                        PendingSubmit {
                            payload: payload.clone(),
                            tries: 0,
                            last: now,
                        },
                    );
                }
                if let Some(h) = self.holder().map(str::to_owned) {
                    self.send(out, Some(&h), false, Body::Submit { id, payload });
                } else if !self.fixes.submit_retry {
                    Self::reject(out, "submit", "no-holder");
                }
            }
            Command::Presence { payload } => {
                self.send(out, None, false, Body::Presence { payload });
            }
            Command::Ping { to } => {
                self.send(out, Some(&to), false, Body::Ping { t: now.min(MAX_INT) });
            }
        }
    }
}
