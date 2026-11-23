//! Claims, frames and the cell policy (§S1, §S3, §S4).
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A member ID: lowercase hex, compared as a string (§S4).
pub type MemberId = String;

/// The greatest term a claim may carry (§S4): 2^53 − 1.
pub const MAX_TERM: u64 = (1 << 53) - 1;

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

/// `{term, rank, holder}` (§S4). The derived order is the protocol order: term, then rank,
/// then holder as a (lowercase hex) string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Claim {
    /// A positive integer at most [`MAX_TERM`].
    pub term: u64,
    /// 0 (taken) or 1 (passed).
    pub rank: u8,
    /// The holder's member ID.
    pub holder: MemberId,
}
impl Claim {
    /// A claim.
    pub fn new(term: u64, rank: u8, holder: &str) -> Self {
        Self {
            term,
            rank,
            holder: holder.to_owned(),
        }
    }
    /// Whether the fields are in range.
    pub fn well_formed(&self) -> bool {
        (1..=MAX_TERM).contains(&self.term) && self.rank <= 1 && !self.holder.is_empty()
    }
    /// The same claim at rank 0: how a rank-1 claim orders before its pass is seen (§S4 3).
    pub fn as_rank0(&self) -> Self {
        Self {
            rank: 0,
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
        /// The §S2 envelope; opaque in this layer.
        #[serde(rename = "sessionKey")]
        session_key: Bytes,
        /// The sender's accepted claim and position.
        seen: Option<Seen>,
        /// An out-of-contact holder returning (§S6).
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
        id: Bytes,
        /// Application bytes.
        payload: Bytes,
    },
    /// Ask the holder to order a message.
    Submit {
        /// Caller-chosen id (16 random bytes in the protocol).
        id: Bytes,
        /// Application bytes.
        payload: Bytes,
    },
    /// The holder declined a submit.
    Refuse {
        /// The submit's id.
        id: Bytes,
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
        /// `{term: claim.term + 1, rank: 1, holder: asker}`.
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
    /// Whether only a writer may send this kind (§S1).
    pub fn needs_writer(&self) -> bool {
        self.is_holder_frame()
            || matches!(self, Body::Submit { .. } | Body::Ask { .. } | Body::Take { .. })
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
    /// Fold one message payload into a state.
    pub fn apply(self, state: &Bytes, payload: &Bytes) -> Bytes {
        match self {
            Fold::Latest => payload.clone(),
            Fold::Append => {
                let mut v = state.0.clone();
                v.extend_from_slice(&payload.0);
                Bytes(v)
            }
        }
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
/// reproducible. Revision 2 of the draft adopts every fix except F21 (proposed).
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
    /// F12: a holder made by a pass that meets a different `pass` naming its own claim (two
    /// partitioned holders both passed to it) renews, so one state prevails.
    pub pass_conflict_renew: bool,
    /// F21: a passer also resends its `pass`, once, on the first holder frame it gets from
    /// the new holder under `next`, so a new holder made by another pass meets this one (F12).
    pub pass_echo: bool,
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
        pass_conflict_renew: false,
        pass_echo: false,
    };
    /// Every fix.
    pub const ALL: Fixes = Fixes {
        rank1_from_holder: true,
        seen_unsynced: true,
        bye_resend: true,
        answer_lesser: true,
        renew_wider: true,
        liveness_holder_frames: true,
        ask_resend: true,
        renew_needs_contact: true,
        pass_conflict_renew: true,
        pass_echo: true,
    };
}
impl Default for Fixes {
    fn default() -> Self {
        Self::ALL
    }
}
