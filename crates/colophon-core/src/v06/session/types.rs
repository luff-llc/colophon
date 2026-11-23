//! Claims, frames and the cell policy (§S1, §S3, §S4).
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A member ID: lowercase hex, compared as a string (§S4).
pub type MemberId = String;

/// The greatest term a claim may carry (§S4): 2^53 − 1.
pub const MAX_TERM: u64 = (1 << 53) - 1;
/// Every integer in a frame is at most this (§S3, revision 4).
pub const MAX_INT: u64 = MAX_TERM;
/// At most this many `echo` values in a `hello` (§S3).
pub const MAX_ECHO: usize = 8;

/// The longest `refuse.reason` (§S3, revision 15).
pub const MAX_REASON: usize = 64;
/// `refuse.reason` (§S3, revision 15): at most 64 bytes of `a–z 0–9 -`.
pub fn valid_reason(s: &str) -> bool {
    s.len() <= MAX_REASON
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A 16-byte id or `fresh` value, unpadded base64url in JSON (§S3, revision 4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(pub [u8; 16]);
impl Id {
    /// An id derived from a label (tests, tools and deterministic hosts).
    pub fn from_label(label: &str) -> Self {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(label.as_bytes());
        let mut b = [0u8; 16];
        b.copy_from_slice(&d[..16]);
        Id(b)
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let v = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let b: [u8; 16] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("an id is 16 bytes"))?;
        Ok(Id(b))
    }
}

/// `hello.heard` (§S4, revision 4): has the sender itself received holder frames from
/// `seen.holder`?
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Heard {
    /// A holder frame from it within `holderTimeoutMs`.
    Live,
    /// Its own link worked for `holderTimeoutMs` and no holder frame from it arrived.
    Lapsed,
    /// It has not listened long enough to say.
    Unknown,
}

/// What a member persists (§S4, §S5 release, revision 4): its greatest accepted claim and
/// whether it released that claim.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Persisted {
    /// The greatest accepted claim.
    pub claim: Claim,
    /// It released that claim (a tombstone: after a restart it does not act as its holder).
    pub released: bool,
}

/// Opaque application bytes (payloads, snapshots, ids), base64 in JSON (§S3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bytes(pub Vec<u8>);
impl Bytes {
    /// Bytes from a slice.
    pub fn from_slice(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
    /// The length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map(Bytes)
            .map_err(serde::de::Error::custom)
    }
}

/// `{term, rank, holder, via}` (§S4, revision 3). The derived order is the protocol order:
/// term, then rank, then holder, then via (member IDs as lowercase hex strings; `via` is
/// present exactly when rank is 1).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Claim {
    /// A positive integer at most [`MAX_TERM`].
    pub term: u64,
    /// 0 (taken) or 1 (passed).
    pub rank: u8,
    /// The holder's member ID.
    pub holder: MemberId,
    /// The passer's member ID, present exactly when `rank` is 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<MemberId>,
}
impl Claim {
    /// A claim without `via` (rank 0; or a revision 1 rank-1 claim).
    pub fn new(term: u64, rank: u8, holder: &str) -> Self {
        Self {
            term,
            rank,
            holder: holder.to_owned(),
            via: None,
        }
    }
    /// A passed claim `{term, rank: 1, holder, via}`.
    pub fn passed(term: u64, holder: &str, via: &str) -> Self {
        Self {
            term,
            rank: 1,
            holder: holder.to_owned(),
            via: Some(via.to_owned()),
        }
    }
    /// Whether the fields are in range and `via` is present exactly when rank is 1.
    pub fn well_formed(&self) -> bool {
        (1..=MAX_TERM).contains(&self.term)
            && self.rank <= 1
            && !self.holder.is_empty()
            && (self.rank == 1) == self.via.as_ref().is_some_and(|v| !v.is_empty())
    }
    /// The same claim at rank 0: how revision 1 ordered a rank-1 claim before its pass was
    /// seen.
    pub fn as_rank0(&self) -> Self {
        Self {
            rank: 0,
            via: None,
            ..self.clone()
        }
    }
}

/// `hello.seen`: the sender's accepted claim and its position in that claim's lane.
///
/// `seq` is `null` when the sender holds no state for `claim` (finding F2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Seen {
    /// The sender's accepted claim.
    #[serde(flatten)]
    pub claim: Claim,
    /// The last applied `seq` of that claim, or `None` without a snapshot for it.
    pub seq: Option<u64>,
}

/// A plaintext frame body (§S3 table). Field names are the protocol's.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Body {
    /// Join or rejoin; sent on every link-up.
    Hello {
        /// 16 random bytes, new for this `hello` (freshness, §S3).
        fresh: Id,
        /// The `fresh` values of the hellos this one answers (at most 8).
        echo: Vec<Id>,
        /// The sender's accepted claim and position.
        seen: Option<Seen>,
        /// Whether the sender itself hears `seen.holder` (revisions 4–6; absent in 7).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        heard: Option<Heard>,
        /// An out-of-contact holder returning (§S6); informational.
        lapsed: bool,
    },
    /// Full state, from the holder.
    State {
        /// The holder's claim.
        claim: Claim,
        /// The last ordered `seq` folded into `snapshot`.
        seq: u64,
        /// The state.
        snapshot: Bytes,
    },
    /// Holder liveness.
    Beat {
        /// The holder's claim.
        claim: Claim,
        /// The holder's latest `seq`.
        seq: u64,
    },
    /// One ordered message.
    Msg {
        /// The holder's claim.
        claim: Claim,
        /// Position in the claim's lane, from 1.
        seq: u64,
        /// Who asked for it (the holder for its own `publish`).
        origin: MemberId,
        /// The submit or publish id.
        id: Id,
        /// Application bytes.
        payload: Bytes,
    },
    /// Ask the holder to order a message.
    Submit {
        /// Caller-chosen id (16 random bytes).
        id: Id,
        /// Application bytes.
        payload: Bytes,
    },
    /// The holder declined a submit.
    Refuse {
        /// The submit's id.
        id: Id,
        /// Why.
        reason: String,
    },
    /// Latest presence value of the sender.
    Presence {
        /// Application bytes.
        payload: Bytes,
    },
    /// Ask the holder for the role.
    Ask {
        /// The claim the asker believes current.
        claim: Claim,
    },
    /// Hand the role over.
    Pass {
        /// The passer's current claim.
        claim: Claim,
        /// `{term: claim.term + 1, rank: 1, holder: asker, via: passer}`.
        next: Claim,
        /// The final `seq` of `claim`.
        seq: u64,
        /// The final state.
        snapshot: Bytes,
    },
    /// The holder will not pass now.
    Decline {
        /// The holder's claim.
        claim: Claim,
    },
    /// Assume the role.
    Take {
        /// `{term, rank: 0, holder: sender}`.
        claim: Claim,
    },
    /// A member that yielded to a take tells the new holder what it held (§S5, revision 4).
    Yielded {
        /// The claim it held.
        claim: Claim,
        /// Its last `seq` under that claim.
        seq: u64,
        /// Its state.
        snapshot: Bytes,
    },
    /// The sender's application has been given a `yielded` or a passed state (§S5,
    /// revisions 5 and 15). Exactly one of the two fields is present.
    Ack {
        /// The claim named by the `yielded` it answers (sent by the holder).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        yielded: Option<Claim>,
        /// The `next` of the `pass` it answers (sent by the member the pass named).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passed: Option<Claim>,
    },
    /// Round trip and offset (§S7).
    Ping {
        /// Sender clock, ms.
        t: u64,
    },
    /// Answer to `ping`.
    Pong {
        /// Responder clock when sending, ms.
        t: u64,
        /// The ping's `t`.
        echo: u64,
        /// How long the responder held the ping, ms.
        hold: u64,
    },
    /// A holder's `bye` releases the role; `leaving` also ends the sender's membership.
    Bye {
        /// The sender's claim if it is or was the holder of it.
        claim: Option<Claim>,
        /// The sender leaves the session (`false`: a release, it stays).
        leaving: bool,
    },
}
impl Body {
    /// The claim this body carries as its sender's, if any (`hello.seen` included).
    pub fn claim(&self) -> Option<&Claim> {
        match self {
            Body::Hello { seen, .. } => seen.as_ref().map(|s| &s.claim),
            Body::State { claim, .. }
            | Body::Beat { claim, .. }
            | Body::Msg { claim, .. }
            | Body::Ask { claim }
            | Body::Pass { claim, .. }
            | Body::Decline { claim }
            | Body::Take { claim, .. } => Some(claim),
            Body::Bye { claim, .. } => claim.as_ref(),
            _ => None,
        }
    }
    /// §S3 bounds: integers at most 2^53 − 1, payloads and snapshots at most `max_payload`,
    /// claims well formed, at most 8 `echo` values. A frame that fails is dropped.
    pub fn in_range(&self, max_payload: u64) -> bool {
        let int = |x: u64| x <= MAX_INT;
        let size = |b: &Bytes| b.len() as u64 <= max_payload;
        let claim_ok = self.claim().is_none_or(Claim::well_formed);
        claim_ok
            && match self {
                Body::Hello { echo, seen, .. } => {
                    echo.len() <= MAX_ECHO && seen.as_ref().is_none_or(|s| s.seq.is_none_or(int))
                }
                Body::State { seq, snapshot, .. } => int(*seq) && size(snapshot),
                Body::Beat { seq, .. } => int(*seq),
                Body::Msg { seq, payload, .. } => int(*seq) && size(payload),
                Body::Submit { payload, .. } | Body::Presence { payload } => size(payload),
                Body::Pass {
                    next, seq, snapshot, ..
                } => next.well_formed() && int(*seq) && size(snapshot),
                Body::Yielded {
                    claim, seq, snapshot,
                } => claim.well_formed() && int(*seq) && size(snapshot),
                Body::Ack { yielded, passed } => match (yielded, passed) {
                    (Some(c), None) | (None, Some(c)) => c.well_formed(),
                    _ => false,
                },
                Body::Refuse { reason, .. } => valid_reason(reason),
                Body::Ping { t } => int(*t),
                Body::Pong { t, echo, hold } => int(*t) && int(*echo) && int(*hold),
                _ => true,
            }
    }
    /// Whether only the holder sends this kind (§S4 yielding list).
    pub fn is_holder_frame(&self) -> bool {
        matches!(
            self,
            Body::State { .. }
                | Body::Beat { .. }
                | Body::Msg { .. }
                | Body::Refuse { .. }
                | Body::Pass { .. }
                | Body::Decline { .. }
        )
    }
    /// Whether only a writer may send this kind (§S1, §S3 table: holder frames, `submit`,
    /// `ask`, `take`, `yielded` and `ack`).
    pub fn needs_writer(&self) -> bool {
        self.is_holder_frame()
            || matches!(
                self,
                Body::Submit { .. }
                    | Body::Ask { .. }
                    | Body::Take { .. }
                    | Body::Yielded { .. }
                    | Body::Ack { .. }
            )
    }
    /// The protocol `kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            Body::Hello { .. } => "hello",
            Body::State { .. } => "state",
            Body::Beat { .. } => "beat",
            Body::Msg { .. } => "msg",
            Body::Submit { .. } => "submit",
            Body::Refuse { .. } => "refuse",
            Body::Presence { .. } => "presence",
            Body::Ask { .. } => "ask",
            Body::Pass { .. } => "pass",
            Body::Decline { .. } => "decline",
            Body::Take { .. } => "take",
            Body::Ping { .. } => "ping",
            Body::Pong { .. } => "pong",
            Body::Bye { .. } => "bye",
            Body::Yielded { .. } => "yielded",
            Body::Ack { .. } => "ack",
        }
    }
}

/// A frame after §S3 checks: the outer fields this layer needs, and the opened body.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Frame {
    /// Sender.
    pub from: MemberId,
    /// Recipient; `None` means every member in the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<MemberId>,
    /// Ask carriers to keep it (§S9).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retain: bool,
    /// The plaintext.
    pub body: Body,
}

/// `policy.take` (§S1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TakeRule {
    /// Any eligible member may take.
    Free,
    /// A reserved value: this host never takes in the cell.
    Reserved,
}

/// `policy.fold` (§S1): how ordered messages become state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fold {
    /// The state is the last payload (§S12 anchors).
    Latest,
    /// The state is the list of payloads; here their concatenation after the snapshot.
    Append,
}
impl Fold {
    /// Fold one message payload into a state. `append` keeps the last `tail` payloads
    /// (§S1, revision 4), each framed as a 4-byte big-endian length and the bytes.
    pub fn apply(self, state: &Bytes, payload: &Bytes, tail: u64) -> Bytes {
        self.apply_bounded(state, payload, tail, None)
    }
    /// As [`Fold::apply`], with `append` also keeping the encoded state at most `max_bytes`
    /// (revision 7: oldest payloads dropped first; a payload that cannot fit with its
    /// 4-byte frame even alone leaves the state empty).
    pub fn apply_bounded(
        self,
        state: &Bytes,
        payload: &Bytes,
        tail: u64,
        max_bytes: Option<u64>,
    ) -> Bytes {
        match self {
            Fold::Latest => payload.clone(),
            Fold::Append => {
                let mut entries = Self::entries(state);
                entries.push(payload.clone());
                let keep = usize::try_from(tail.max(1)).unwrap_or(usize::MAX);
                let mut drop = entries.len().saturating_sub(keep);
                if let Some(max) = max_bytes {
                    let size = |e: &[Bytes]| e.iter().map(|x| 4 + x.len() as u64).sum::<u64>();
                    while drop < entries.len() && size(&entries[drop..]) > max {
                        drop += 1;
                    }
                }
                Self::framed(&entries[drop..])
            }
        }
    }
    /// The payloads of an `append` state (a state that is not framed is one entry).
    pub fn entries(state: &Bytes) -> Vec<Bytes> {
        let mut out = Vec::new();
        let b = &state.0;
        let mut i = 0usize;
        while i < b.len() {
            let Some(len) = b.get(i..i + 4).map(|h| u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize) else {
                return vec![state.clone()];
            };
            let Some(body) = b.get(i + 4..i + 4 + len) else {
                return vec![state.clone()];
            };
            out.push(Bytes(body.to_vec()));
            i += 4 + len;
        }
        out
    }
    /// An `append` state from payloads.
    pub fn framed(entries: &[Bytes]) -> Bytes {
        let mut v = Vec::new();
        for e in entries {
            v.extend_from_slice(&u32::try_from(e.len()).unwrap_or(u32::MAX).to_be_bytes());
            v.extend_from_slice(&e.0);
        }
        Bytes(v)
    }
}

/// A cell policy (§S1). Times in the member's monotonic ms.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    /// The holder sends some frame at least this often.
    pub beat_ms: u64,
    /// A holder not heard from for this long is lapsed to the listener.
    pub holder_timeout_ms: u64,
    /// How long an asker waits for a pass before it may take.
    pub ask_timeout_ms: u64,
    /// Presence is dropped after this silence.
    pub presence_timeout_ms: u64,
    /// Longest carrier retention (carriers only).
    pub retain_ms: u64,
    /// Ordered messages the holder keeps for resume.
    pub tail: u64,
    /// Largest payload, bytes.
    pub max_payload: u64,
    /// How ordered messages become state.
    pub fold: Fold,
    /// Who may take.
    pub take: TakeRule,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            beat_ms: 5_000,
            holder_timeout_ms: 15_000,
            ask_timeout_ms: 1_500,
            presence_timeout_ms: 15_000,
            retain_ms: 60_000,
            tail: 256,
            max_payload: 8_192,
            fold: Fold::Latest,
            take: TakeRule::Free,
        }
    }
}

/// Departures from the draft text that the explorer showed necessary
/// (`docs/colophon-0.6-sessions-findings.md`). [`Fixes::default`] is the reference reading;
/// [`Fixes::LITERAL`] reproduces the revision 1 draft so the counterexamples stay
/// reproducible, [`Fixes::REV3`] to [`Fixes::REV7`] those drafts. [`Fixes::ALL`] is the
/// current revision (15). The revision 4–6 evidence rules (`evidence*` switches) are reached
/// only through the hidden `Input::LegacyEvidence`, for those regression presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixes {
    /// F1: accept a rank-1 claim from its own holder, and a `pass` from `pass.claim.holder`,
    /// without having accepted the passer's claim first.
    pub rank1_from_holder: bool,
    /// F2: `hello.seen.seq` is `null` when the sender holds no snapshot for its claim.
    pub seen_unsynced: bool,
    /// F5: a holder that released answers a frame carrying its released claim with `bye`
    /// again, and a listener whose holder lapsed sends it `hello`, so a lost `bye` heals.
    pub bye_resend: bool,
    /// F6: a member that meets a holder frame or `take` under a claim less than its own
    /// answers the sender with `hello`; and §S5 renewing reads "not present" as "has sent no
    /// holder frame or `take` within `holderTimeoutMs`" rather than presence.
    pub answer_lesser: bool,
    /// F7: renewing also covers (i) a `hello.seen` naming a claim of this holder greater than
    /// its own (a pass it never received) and (ii) a holder meeting a greater claim in a
    /// `bye` (a released claim) or in a `hello` from its holder (which may have released):
    /// it raises its claim instead of yielding to nobody.
    pub renew_wider: bool,
    /// F8: only holder frames under the accepted claim count as hearing from the holder for
    /// lapsing and the ask timeout (§S5, §S6); a `pong` or `presence` from a member that has
    /// passed or yielded does not keep it alive.
    pub liveness_holder_frames: bool,
    /// F9: an asker that heard the holder but got neither `pass` nor `decline` within
    /// `askTimeoutMs` sends `ask` again (a lost `ask` is otherwise never repaired).
    pub ask_resend: bool,
    /// F10: a holder judges another holder "not present" for §S5 renewing only after its own
    /// link has worked for `holderTimeoutMs` (a returning member has heard nobody yet).
    pub renew_needs_contact: bool,
    /// R1 (revision 4): a non-holder corrects a lesser holder frame with the greater claim's
    /// holder frame as evidence, or with `hello.heard`; a holder renews over another member's
    /// claim only on `heard: lapsed`. Off: revision 3's hearsay renewing ("not present").
    pub evidence: bool,
    /// R2a/b (revision 4): a late pass naming the holder and a yielded holder's state are
    /// reported to the application (`LatePass`, `yielded` / `Displaced`).
    pub state_reports: bool,
    /// R2c (revision 4): a release is persisted, so a restart does not resurrect the claim.
    pub persist_release: bool,
    /// R5 (revision 4): unanswered submits are resent on holder change and every
    /// `askTimeoutMs`, at most 8 times, then reported failed.
    pub submit_retry: bool,
    /// R1b/R1c (revision 5): evidence also answers a `hello` naming a lesser
    /// claim or none, and is pushed to members whose last `hello` did, as soon as this member
    /// has it. Off: revision 4 as written (only holder frames and `take` are corrected).
    pub evidence_push: bool,
    /// R2d/R2f (revision 5): `yielded` is acknowledged (`ack`) and resent to the current
    /// holder, on hearing it, at most once per `askTimeoutMs`, until acknowledged; a late
    /// pass to a member that has moved on is reported once (R2e). Off: revision 4 (one
    /// resend, no `ack`).
    pub yielded_ack: bool,
    /// R1d (revision 5): forwarded evidence does not count for the ask-timeout take, and a
    /// writer that took or wanted to take and yields to forwarded evidence keeps wanting,
    /// taking only once that holder is lapsed to it. Off: revision 4.
    pub evidence_keeps_want: bool,
    /// R1f (beyond revision 5's text): a writer that keeps wanting after evidence takes only
    /// askTimeoutMs after its lapse `hello`, and a member with fresh evidence answers a
    /// `hello` reporting that holder lapsed with the evidence (the holder itself with
    /// `state`). Without it, two wanting members that cannot reach each other on a chain
    /// take from each other forever. Off: revision 5 as written.
    pub evidence_refresh: bool,
    /// R1e (revision 5): a holder renews on `heard: lapsed` only once its own
    /// link has worked for `holderTimeoutMs` (a returning holder must not win on the word of
    /// a member that merely missed the live holder's beats). Off: revision 4 as written.
    pub renew_guard: bool,
    /// Revision 7: a non-holder answers a `hello` naming a lesser claim or none with `hello`
    /// (with evidence off, this is how a quiet claim reaches the group).
    pub hello_correction: bool,
    /// Revision 7: `yielded` only from its claim's holder, `ack` only from the accepted
    /// holder.
    pub sender_checks: bool,
    /// Revision 7: freshness windows for at most 4 keys per member.
    pub window_cap: bool,
    /// Revision 7: an `append` state is at most `maxPayload` bytes once encoded.
    pub append_bound: bool,
    /// Finding B5 (beyond revision 8): a member that drops a frame for want of a freshness
    /// window sends that sender a `hello`, at most once per `askTimeoutMs`, so a lost
    /// handshake is retried.
    pub freshness_probe: bool,
    /// Revision 15 §S4 rule 1: a claim in any field of a frame from a member that may only
    /// read, or one naming a non-writer as holder, or more than 2^20 terms above the
    /// accepted term, is ignored.
    #[serde(default)]
    pub writer_claims: bool,
    /// Revision 15 §S5: the passer resends its `pass` on hearing any frame from the asker,
    /// at most once per `askTimeoutMs`, until an `ack {passed}`; the member a pass names
    /// gives its snapshot to the application and acknowledges it every time.
    #[serde(default)]
    pub pass_ack: bool,
}
impl Fixes {
    /// The revision 1 draft as written.
    pub const LITERAL: Fixes = Fixes {
        rank1_from_holder: false,
        seen_unsynced: false,
        bye_resend: false,
        answer_lesser: false,
        renew_wider: false,
        liveness_holder_frames: false,
        ask_resend: false,
        renew_needs_contact: false,
        evidence: false,
        state_reports: false,
        persist_release: false,
        submit_retry: false,
        evidence_push: false,
        yielded_ack: false,
        evidence_keeps_want: false,
        evidence_refresh: false,
        renew_guard: false,
        hello_correction: false,
        sender_checks: false,
        window_cap: false,
        append_bound: false,
        freshness_probe: false,
        writer_claims: false,
        pass_ack: false,
    };
    /// The revision 3 draft: revisions 2 and 3 fixes, none of revision 4.
    pub const REV3: Fixes = Fixes {
        rank1_from_holder: true,
        seen_unsynced: true,
        bye_resend: true,
        answer_lesser: true,
        renew_wider: true,
        liveness_holder_frames: true,
        ask_resend: true,
        renew_needs_contact: true,
        evidence: false,
        state_reports: false,
        persist_release: false,
        submit_retry: false,
        evidence_push: false,
        yielded_ack: false,
        evidence_keeps_want: false,
        evidence_refresh: false,
        renew_guard: false,
        hello_correction: false,
        sender_checks: false,
        window_cap: false,
        append_bound: false,
        freshness_probe: false,
        writer_claims: false,
        pass_ack: false,
    };
    /// Revision 4 as written.
    pub const REV4: Fixes = Fixes {
        evidence_push: false,
        yielded_ack: false,
        evidence_keeps_want: false,
        evidence_refresh: false,
        renew_guard: false,
        ..Fixes::REV6
    };
    /// Revision 5 as written (revision 6 without R1f).
    pub const REV5: Fixes = Fixes {
        evidence_refresh: false,
        ..Fixes::REV6
    };
    /// Revision 6: evidence forwarding over one hop, with every fix up to R1h.
    pub const REV6: Fixes = Fixes {
        rank1_from_holder: true,
        seen_unsynced: true,
        bye_resend: true,
        answer_lesser: true,
        renew_wider: true,
        liveness_holder_frames: true,
        ask_resend: true,
        renew_needs_contact: true,
        evidence: true,
        state_reports: true,
        persist_release: true,
        submit_retry: true,
        evidence_push: true,
        yielded_ack: true,
        evidence_keeps_want: true,
        evidence_refresh: true,
        renew_guard: true,
        hello_correction: false,
        sender_checks: false,
        window_cap: false,
        append_bound: false,
        freshness_probe: false,
        writer_claims: false,
        pass_ack: false,
    };
    /// Revision 8, plus finding B5: carriers bridge (`crate::v06::bridge`), so the session
    /// rules assume a fully reachable group; no evidence forwarding, no `hello.heard`.
    pub const ALL: Fixes = Fixes {
        evidence: false,
        evidence_push: false,
        evidence_keeps_want: false,
        evidence_refresh: false,
        hello_correction: true,
        sender_checks: true,
        window_cap: true,
        append_bound: true,
        freshness_probe: true,
        writer_claims: true,
        pass_ack: true,
        ..Fixes::REV6
    };
    /// Revision 7 (and 8, whose changes are in the bridge and the `append` payload bound).
    pub const REV7: Fixes = Fixes {
        freshness_probe: false,
        writer_claims: false,
        pass_ack: false,
        ..Fixes::ALL
    };
    /// Revision 14: everything before revision 15's writer-only claims and pass `ack`.
    pub const REV14: Fixes = Fixes {
        writer_claims: false,
        pass_ack: false,
        ..Fixes::ALL
    };
}
impl Default for Fixes {
    fn default() -> Self {
        Self::ALL
    }
}
