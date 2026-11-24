//! The façade the bindings call: one member of one cell, from wire bytes to application
//! events and back.
//!
//! An [`Endpoint`] owns the state machine ([`Session`]), the sending side ([`Sender`]: the
//! session key, `n` and the delegation) and the receiving side ([`Receiver`]: cached
//! delegations and replay windows of the keys the machine has open or as candidates). It is sans-IO and deterministic given its inputs: the
//! host passes the clock with every call ([`Clock`]), randomness at construction (the session
//! key and the `fresh` seed), epoch keys through [`EpochKeys`], and the account view through
//! [`Endpoint::set_account`]. The member key signs only the delegation, in the host, between
//! [`Endpoint::begin_delegation`] and [`Endpoint::finish_delegation`].
//!
//! Every call returns a [`Step`]: the effects in the order the host must carry them out
//! (`Persist` before the frames that reveal it, 0.5 G12) and, for a received frame that was
//! dropped, why.
use super::codec::{CellId, Dropped, EpochKeys, Receiver, SealError, Sender};
use super::io::{Command, Event, Input, Output};
use super::keys::{KeyError, SessionAccount, SessionKey};
use super::types::{Claim, MemberId, Persisted, Policy};
use super::Session;
use crate::v05::terms::Access;

/// The host's clocks at a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    /// Monotonic milliseconds (§S7): every session timer.
    pub mono_ms: u64,
    /// Wall-clock milliseconds since the Unix epoch: delegation windows and member expiry.
    pub wall_ms: i64,
}

/// One effect for the host, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Send these bytes to every member of the cell on the best carrier; `to` is advice.
    Send {
        /// The sealed frame.
        bytes: Vec<u8>,
        /// The member the frame is for, if any.
        to: Option<MemberId>,
        /// The plaintext kind (for logs; carriers cannot see it).
        kind: &'static str,
    },
    /// Store this before any later effect (it survives restarts).
    Persist {
        /// The accepted claim.
        claim: Claim,
        /// The member released that claim.
        released: bool,
    },
    /// Tell the application.
    Event(Event),
    /// A frame the machine sent could not be sealed. To the protocol this is loss.
    Unsent {
        /// The plaintext kind.
        kind: &'static str,
        /// Why.
        error: SealError,
    },
}

/// What one call produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// Effects, in order.
    pub effects: Vec<Effect>,
    /// For [`Endpoint::receive`]: the frame was dropped, and why (silent on the wire).
    pub dropped: Option<Dropped>,
}
impl Step {
    /// The sealed frames, in order.
    pub fn frames(&self) -> impl Iterator<Item = &[u8]> {
        self.effects.iter().filter_map(|e| match e {
            Effect::Send { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        })
    }
    /// The application events, in order.
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.effects.iter().filter_map(|e| match e {
            Effect::Event(ev) => Some(ev),
            _ => None,
        })
    }
}

/// Why an endpoint could not be made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// The session key could not be made.
    Key(KeyError),
    /// This member is not current in the account view, or has no `records` entry for the
    /// namespace.
    NotEntitled,
    /// The account view is of another account than the cell's.
    WrongAccount,
    /// The cell policy is out of bounds, or its largest frame would not fit (§S1, §S3).
    Policy(String),
}
impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EndpointError {}

/// The largest `maxPayload` a cell may declare (§S1: the largest snapshot must fit a frame
/// with its delegation).
pub const MAX_PAYLOAD_LIMIT: u64 = 8_192;

/// Check a cell policy: every duration positive, `holderTimeoutMs` above `beatMs`, `tail`
/// at least 1, `maxPayload` from 1 (5 under `append`) to 8,192, and the largest frame of every
/// kind, with every integer at 2^53 − 1, `to`, `retain` and the largest delegation attached,
/// at most 16,384 bytes. Returns the largest frame size.
pub fn validate_policy(policy: &Policy, cell: &CellId) -> Result<usize, String> {
    use super::types::{Body, Bytes, Fold, Id, Seen, MAX_ECHO, MAX_INT, MAX_REASON, MAX_TERM};
    use super::wire::{encode_body, Outer, WireFrame, MAX_FRAME_BYTES, TAG_BYTES};
    let p = policy;
    if p.beat_ms == 0 || p.ask_timeout_ms == 0 || p.presence_timeout_ms == 0 {
        return Err("a timeout is zero".into());
    }
    if p.holder_timeout_ms <= p.beat_ms {
        return Err("holderTimeoutMs must exceed beatMs".into());
    }
    if p.tail == 0 {
        return Err("tail must be at least 1".into());
    }
    let min = if p.fold == Fold::Append { 5 } else { 1 };
    if !(min..=MAX_PAYLOAD_LIMIT).contains(&p.max_payload) {
        return Err(format!("maxPayload must be {min} to {MAX_PAYLOAD_LIMIT}"));
    }
    if !super::wire::valid_cell(&cell.cell)
        || !super::wire::valid_account(&cell.account)
        || !crate::v05::terms::valid_namespace(&cell.namespace)
    {
        return Err("invalid cell".into());
    }
    let id = "f".repeat(32);
    let big = Claim::passed(MAX_TERM, &id, &id);
    let blob = Bytes(vec![0xff; usize::try_from(p.max_payload).unwrap_or(usize::MAX)]);
    let fid = Id([0xff; 16]);
    let bodies = vec![
        Body::Hello {
            fresh: fid,
            echo: vec![fid; MAX_ECHO],
            seen: Some(Seen { claim: big.clone(), seq: Some(MAX_INT) }),
            heard: None,
            lapsed: false,
        },
        Body::State { claim: big.clone(), seq: MAX_INT, snapshot: blob.clone() },
        Body::Beat { claim: big.clone(), seq: MAX_INT },
        Body::Msg { claim: big.clone(), seq: MAX_INT, origin: id.clone(), id: fid, payload: blob.clone() },
        Body::Submit { id: fid, payload: blob.clone() },
        Body::Refuse { id: fid, reason: "z".repeat(MAX_REASON) },
        Body::Presence { payload: blob.clone() },
        Body::Ask { claim: big.clone() },
        Body::Pass { claim: big.clone(), next: big.clone(), seq: MAX_INT, snapshot: blob.clone() },
        Body::Decline { claim: big.clone() },
        Body::Take { claim: big.clone() },
        Body::Ping { t: MAX_INT },
        Body::Pong { t: MAX_INT, echo: MAX_INT, hold: MAX_INT },
        Body::Yielded { claim: big.clone(), seq: MAX_INT, snapshot: blob },
        Body::Ack { yielded: None, passed: Some(big.clone()) },
        Body::Bye { claim: Some(big), leaving: false },
    ];
    // The largest delegation: every field at its longest.
    let body = format!(
        r#"{{"account":"{}","expires":"9999-12-31T23:59:59.999Z","key":"{}","member":"{id}","namespace":"{}","notBefore":"9999-12-31T23:59:59.999Z","protocol":"colophon/session-key/6","session":{MAX_INT}}}"#,
        cell.account,
        crate::v05::encoding::encode_base64(&[4u8; 65]),
        cell.namespace
    );
    let envelope = format!(
        r#"{{"body":"{}","signature":"{}"}}"#,
        crate::v05::encoding::encode_base64(body.as_bytes()),
        crate::v05::encoding::encode_base64(&[0u8; 64])
    );
    let outer = Outer {
        account: cell.account.clone(),
        namespace: cell.namespace.clone(),
        cell: cell.cell.clone(),
        from: id.clone(),
        key: id.clone(),
        to: Some(id),
        n: MAX_INT,
        epoch: MAX_INT,
        retain: true,
    };
    let mut largest = 0;
    for b in &bodies {
        let plaintext = encode_body(b)?;
        let w = WireFrame {
            outer: outer.clone(),
            ciphertext: vec![0; plaintext.len() + TAG_BYTES],
            signature: [0; 64],
            delegation: Some(envelope.clone().into_bytes()),
        };
        let size = w.encode().len();
        if size > MAX_FRAME_BYTES {
            return Err(format!("the largest {} frame is {size} bytes", b.kind()));
        }
        largest = largest.max(size);
    }
    Ok(largest)
}

/// One member of one cell, with sealing.
#[derive(Debug)]
pub struct Endpoint {
    cell: CellId,
    me: MemberId,
    policy: Policy,
    machine: Session,
    sender: Sender,
    receiver: Receiver,
    account: SessionAccount,
    /// This member holds a `records` entry for the namespace at the accepted head. Without
    /// one nothing is sealed.
    entitled: bool,
}

impl Endpoint {
    /// Start a session: a fresh session key from `key_random` (wiped), the machine seeded with
    /// `fresh_seed` (16 random bytes, new for every process start), and the account view.
    /// `persisted` is what the host stored from earlier `Persist` effects. The policy is
    /// checked with [`validate_policy`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cell: CellId,
        me: &str,
        policy: Policy,
        persisted: Option<Persisted>,
        account: SessionAccount,
        key_random: &mut [u8; 32],
        fresh_seed: [u8; 16],
        clock: Clock,
    ) -> Result<Self, EndpointError> {
        let key = SessionKey::generate(key_random).map_err(EndpointError::Key)?;
        validate_policy(&policy, &cell).map_err(EndpointError::Policy)?;
        if account.account() != cell.account {
            return Err(EndpointError::WrongAccount);
        }
        let access = account
            .access(me, &cell.namespace, clock.wall_ms)
            .ok_or(EndpointError::NotEntitled)?;
        let machine = Session::new(me, access == Access::Write, policy.clone(), persisted)
            .with_fresh_seed(fresh_seed);
        let mut e = Self {
            sender: Sender::new(cell.clone(), me, key),
            receiver: Receiver::new(cell.clone(), me),
            cell,
            me: me.to_owned(),
            policy,
            machine,
            account: SessionAccount::default(),
            entitled: true,
        };
        // The entitled set at construction produces no output (nothing is joined yet).
        let _ = e.apply_account(account, clock);
        Ok(e)
    }

    /// This member.
    pub fn me(&self) -> &str {
        &self.me
    }
    /// The cell.
    pub fn cell(&self) -> &CellId {
        &self.cell
    }
    /// The state machine (read only).
    pub fn machine(&self) -> &Session {
        &self.machine
    }
    /// The receiving side (read only).
    pub fn receiver(&self) -> &Receiver {
        &self.receiver
    }
    /// The session key's ID.
    pub fn key_id(&self) -> &str {
        self.sender.key().id()
    }
    /// The highest `n` sealed so far.
    pub fn last_n(&self) -> u64 {
        self.sender.key().last_n()
    }
    /// The invariant between the layers (revision 17): the codec caches exactly the keys the
    /// machine has open or as candidates.
    pub fn keys_consistent(&self) -> bool {
        self.receiver.key_set() == self.machine.known_keys()
    }
    /// Whether this member holds a `records` entry for the namespace (it may send).
    pub fn entitled(&self) -> bool {
        self.entitled
    }
    /// When the host should next call [`Endpoint::tick`] (monotonic ms), if ever.
    pub fn next_deadline(&self) -> Option<u64> {
        self.machine.next_deadline()
    }

    /// The exact `colophon/session-key/6` body for the host to sign `raw` with this member's
    /// key (0.5 §3.4), for the window `[not_before_ms, expires_ms]` (at most 86,400 s). A key
    /// whose member's session number changed is retired: a new session needs a new endpoint.
    pub fn begin_delegation(&self, not_before_ms: i64, expires_ms: i64) -> Result<Vec<u8>, KeyError> {
        let session = self
            .account
            .member(&self.me)
            .map(|m| m.session)
            .ok_or(KeyError::Window)?;
        self.sender.delegation_body(session, not_before_ms, expires_ms)
    }
    /// Install the host's signature over a body from [`Endpoint::begin_delegation`], after
    /// verifying it under this member's key in the account view.
    pub fn finish_delegation(&mut self, body: &[u8], signature: &[u8], clock: Clock) -> Result<(), String> {
        self.sender.install(body, signature, &self.account, clock.wall_ms)
    }

    /// A newly accepted authority head (§S1, §S2). The host calls this before delivering any
    /// frame received after it accepted that head. Other members' keys whose delegations no
    /// longer hold are dropped and the machine closes or forgets them; the machine is given the
    /// new entitled writers; and this member's own access is applied: promoted, it may take;
    /// reduced to read, it releases and seals only what a reader may send; without the
    /// namespace, it leaves and seals nothing. A new session number retires its key.
    /// A view of another account than the cell's changes nothing.
    pub fn set_account(&mut self, account: SessionAccount, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        if account.account() != self.cell.account {
            return Step::default();
        }
        let outs = self.apply_account(account, clock);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }
    fn apply_account(&mut self, account: SessionAccount, clock: Clock) -> Vec<Output> {
        let gone = self.receiver.set_account(&account, clock.wall_ms);
        for m in &gone.members {
            self.machine.forget_member(m);
        }
        for (m, k) in &gone.keys {
            self.machine.close_window(m, k);
        }
        let machine = &self.machine;
        self.receiver.retain(|m, k| machine.knows_key(m, k));
        let writers = account.writers(&self.cell.namespace, clock.wall_ms);
        let access = account.access(&self.me, &self.cell.namespace, clock.wall_ms);
        let session = account.member(&self.me).map(|m| m.session);
        self.sender.observe_session(session);
        self.account = account;
        let mut outs = self
            .machine
            .handle(Input::Entitled { writers }, clock.mono_ms);
        outs.extend(
            self.machine
                .set_can_write(access == Some(Access::Write), clock.mono_ms),
        );
        match access {
            None if self.entitled => {
                // Without the namespace nothing this member sends would be accepted: leave.
                if self.machine.joined() {
                    outs.extend(
                        self.machine
                            .handle(Input::App { command: Command::Leave }, clock.mono_ms),
                    );
                }
                self.entitled = false;
            }
            Some(_) => self.entitled = true,
            None => {}
        }
        outs
    }

    /// An application command (§S10).
    pub fn command(&mut self, command: Command, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        let outs = self.machine.handle(Input::App { command }, clock.mono_ms);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }
    /// A timer expiry (at or after [`Endpoint::next_deadline`]).
    pub fn tick(&mut self, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        let outs = self.machine.handle(Input::Tick, clock.mono_ms);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }
    /// Some carrier works again.
    pub fn link_up(&mut self, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        let outs = self.machine.handle(Input::LinkUp, clock.mono_ms);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }
    /// No carrier works.
    pub fn link_down(&mut self, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        let outs = self.machine.handle(Input::LinkDown, clock.mono_ms);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }

    /// A link outage reported after the fact ([`Input::Outage`]): no carrier worked for the
    /// last `down_ms`, and, when `ended`, one works again now.
    pub fn outage(&mut self, down_ms: u64, ended: bool, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        let outs = self.machine.handle(Input::Outage { down_ms, ended }, clock.mono_ms);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }

    /// Bytes received from a carrier. A frame that fails any §S3 check is dropped silently
    /// and changes no state; a frame from a key this member has not accepted, sent by a
    /// member entitled to the namespace, makes the machine send that member a `hello` (rate
    /// limited per member and in all).
    pub fn receive(&mut self, bytes: &[u8], clock: Clock, epochs: &dyn EpochKeys) -> Step {
        match self.receiver.open(
            bytes,
            &self.account,
            clock.wall_ms,
            epochs,
            self.policy.max_payload,
        ) {
            Ok(o) => {
                let outs = self.machine.handle(
                    Input::Frame {
                        frame: o.frame,
                        writer: o.writer,
                        key: Some(o.key),
                        n: Some(o.n),
                    },
                    clock.mono_ms,
                );
                // Revision 17: the machine owns which keys are open or candidates; the
                // receiver caches nothing for any other.
                let machine = &self.machine;
                self.receiver.retain(|m, k| machine.knows_key(m, k));
                debug_assert!(self.keys_consistent(), "codec and machine key sets differ");
                Step {
                    effects: self.run(outs, clock, epochs),
                    dropped: None,
                }
            }
            Err(d) => {
                let outs = match &d.hello_to {
                    Some(m) => self.machine.hello_for_unknown_key(m, clock.mono_ms),
                    None => Vec::new(),
                };
                Step {
                    effects: self.run(outs, clock, epochs),
                    dropped: Some(d),
                }
            }
        }
    }

    fn run(&mut self, outs: Vec<Output>, clock: Clock, epochs: &dyn EpochKeys) -> Vec<Effect> {
        let mut effects = Vec::with_capacity(outs.len());
        for o in outs {
            match o {
                Output::Send { frame } => {
                    let kind = frame.body.kind();
                    let sealed = if !self.entitled {
                        Err(SealError::NotEntitled)
                    } else if frame.body.needs_writer() && !self.machine.can_write() {
                        Err(SealError::NotWriter)
                    } else {
                        self.sender.seal(&frame, epochs, clock.wall_ms)
                    };
                    match sealed {
                        Ok(bytes) => effects.push(Effect::Send {
                            bytes,
                            to: frame.to,
                            kind,
                        }),
                        Err(error) => effects.push(Effect::Unsent { kind, error }),
                    }
                }
                Output::Persist { claim, released } => {
                    effects.push(Effect::Persist { claim, released });
                }
                Output::Event { event } => effects.push(Effect::Event(event)),
                // Evidence forwarding exists only in the revision 4–6 presets.
                Output::Forward { .. } => {}
            }
        }
        effects
    }
}
