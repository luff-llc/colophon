//! What goes into and comes out of [`super::Session::handle`].
use super::types::{Bytes, Claim, Frame, Id, MemberId};
use serde::{Deserialize, Serialize};

/// One input. Time is passed beside it, in the member's own monotonic ms.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "input", rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum Input {
    /// A frame that passed §S3 (parsed, signed by an accepted session key, opened).
    Frame {
        /// The frame.
        frame: Frame,
        /// Whether the sender's entry for the namespace has access `write` (§S1).
        writer: bool,
        /// The sender's session key ID and the frame's `n` (§S3), for the freshness gate.
        /// Without them (tests, or a codec that gates freshness itself) the gate is open.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        /// The frame's `n`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        n: Option<u64>,
    },
    /// The members entitled to write in the namespace at the accepted authority head (§S1,
    /// §S5: a pass goes only to an entitled asker). Until the host gives it, no pass is
    /// refused for entitlement.
    Entitled {
        /// Their member IDs.
        writers: Vec<MemberId>,
    },
    /// Revisions 4–6 only (evidence forwarded by another member). Ignored unless the
    /// machine runs one of those regression presets; not part of any current revision.
    #[doc(hidden)]
    LegacyEvidence {
        /// The origin's frame.
        frame: Frame,
        /// Whether the origin may write.
        writer: bool,
        /// The member that forwarded it.
        via: MemberId,
        /// Whether the receiver had a window for the origin's key.
        windowed: bool,
    },
    /// Time passed; the host calls this at least every few hundred ms.
    Tick,
    /// Some carrier works again.
    LinkUp,
    /// No carrier works.
    LinkDown,
    /// An application command.
    App {
        /// The command.
        command: Command,
    },
}

/// Application commands (§S10).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum Command {
    /// Join the session (also after a restart).
    Join {
        /// The application's state for the cell (a restarted holder retakes with it, §S6).
        state: Option<Bytes>,
    },
    /// Leave; a holder releases the role.
    Leave,
    /// Ask the holder for the role; takes by itself when §S5 allows.
    Ask,
    /// Pass the role to an asker with the final snapshot (the application stopped first).
    Pass {
        /// The asker.
        to: MemberId,
        /// The final state.
        snapshot: Bytes,
    },
    /// Decline an asker.
    Decline {
        /// The asker.
        to: MemberId,
    },
    /// Take as soon as §S5 allows (at once if it does now).
    Take {
        /// The state to start from (the application's projection), else the core's state.
        state: Option<Bytes>,
    },
    /// Give up the role without passing (sends `bye` and stays joined).
    Release,
    /// Order a message (holder).
    Publish {
        /// Caller-chosen id (16 random bytes).
        id: Id,
        /// Application bytes.
        payload: Bytes,
    },
    /// Ask the holder to order a message (writer).
    Submit {
        /// Caller-chosen id (16 random bytes).
        id: Id,
        /// Application bytes.
        payload: Bytes,
    },
    /// Publish this member's presence.
    Presence {
        /// Application bytes.
        payload: Bytes,
    },
    /// Measure round trip and offset to a member.
    Ping {
        /// The member.
        to: MemberId,
    },
}

/// How a member became holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    /// A `pass` named it.
    Pass,
    /// It took (§S5) or a returning holder retook (§S6).
    Take,
    /// It raised its own claim (§S5 renewing).
    Renew,
}

/// Something the application should know.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "camelCase")]
pub enum Event {
    /// This member is now holder.
    BecameHolder {
        /// Its claim.
        claim: Claim,
        /// Its state.
        snapshot: Bytes,
        /// How.
        via: Via,
    },
    /// This member stopped being holder (yield or pass): the application stops what the
    /// role controls.
    Yielded {
        /// The claim it yielded to.
        to: Claim,
    },
    /// The holder as this member sees it changed (`None`: no holder).
    HolderChanged {
        /// The accepted claim, or `None` after a holder's `bye`.
        claim: Option<Claim>,
    },
    /// A writer asked for the role.
    AskReceived {
        /// The asker.
        from: MemberId,
    },
    /// The holder declined this member's ask.
    Declined {
        /// The holder.
        from: MemberId,
    },
    /// One ordered message, applied.
    Message {
        /// Its claim.
        claim: Claim,
        /// Its position.
        seq: u64,
        /// Who asked for it.
        origin: MemberId,
        /// Its id.
        id: Id,
        /// Application bytes.
        payload: Bytes,
    },
    /// The state was replaced by a snapshot.
    Snapshot {
        /// Its claim.
        claim: Claim,
        /// Its position.
        seq: u64,
        /// The state.
        snapshot: Bytes,
    },
    /// The holder refused this member's submit.
    Refused {
        /// The submit's id.
        id: Id,
        /// Why.
        reason: String,
    },
    /// A member's presence changed (`None`: dropped).
    PresenceChanged {
        /// The member.
        member: MemberId,
        /// Its value.
        payload: Option<Bytes>,
    },
    /// The holder is lapsed to this member (§S6).
    HolderLapsed {
        /// The holder.
        holder: MemberId,
    },
    /// A new best clock sample to a member (§S7).
    OffsetChanged {
        /// The member.
        peer: MemberId,
        /// `peerClock ≈ myClock + offset`.
        offset: i64,
        /// `ceil(rtt / 2)`.
        error: u64,
    },
    /// A pass naming this member arrived after it already held under a lesser claim (it
    /// took, or another holder passed to it): the pass's snapshot, which the member did not
    /// install. It renewed with its own state; the application may publish a correction
    /// (§S5, revision 4, G11).
    LatePass {
        /// The passer.
        from: MemberId,
        /// The pass's `next`.
        claim: Claim,
        /// The pass's snapshot.
        snapshot: Bytes,
    },
    /// A member that yielded to this member's take reported what it held (§S5, G11).
    Displaced {
        /// The displaced holder.
        from: MemberId,
        /// The claim it held.
        claim: Claim,
        /// Its last `seq`.
        seq: u64,
        /// Its state.
        snapshot: Bytes,
    },
    /// A submit was resent 8 times without an answer (§S8, revision 4).
    SubmitFailed {
        /// Its id.
        id: Id,
    },
    /// A command could not be carried out now.
    Rejected {
        /// The command's name.
        command: String,
        /// Why.
        reason: String,
    },
}

/// One effect for the host.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "output", rename_all = "camelCase")]
pub enum Output {
    /// Seal, sign and send this frame on the best carrier.
    Send {
        /// The frame.
        frame: Frame,
    },
    /// Store this before any later output (it survives restarts).
    Persist {
        /// The accepted claim.
        claim: Claim,
        /// The member released that claim (tombstone).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        released: bool,
    },
    /// Send another member's frame unchanged to `to` (evidence, §S4, revision 4).
    Forward {
        /// The recipient.
        to: MemberId,
        /// The origin's frame, as it was received.
        frame: Frame,
    },
    /// Tell the application.
    Event {
        /// The event.
        event: Event,
    },
}
