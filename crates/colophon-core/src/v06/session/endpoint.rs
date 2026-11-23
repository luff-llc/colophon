//! The façade the bindings call: one member of one cell, from wire bytes to application
//! events and back.
//!
//! An [`Endpoint`] owns the state machine ([`Session`]), the sending side ([`Sender`]: the
//! session key, `n` and the delegation) and the receiving side ([`Receiver`]: other members'
//! accepted keys and replay windows). It is sans-IO and deterministic given its inputs: the
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
}
impl std::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EndpointError {}

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
}

impl Endpoint {
    /// Start a session: a fresh session key from `key_random` (wiped), the machine seeded with
    /// `fresh_seed` (16 random bytes, new for every process start), and the account view.
    /// `persisted` is what the host stored from earlier `Persist` effects.
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
    /// When the host should next call [`Endpoint::tick`] (monotonic ms), if ever.
    pub fn next_deadline(&self) -> Option<u64> {
        self.machine.next_deadline()
    }

    /// The exact `colophon/session-key/6` body for the host to sign `raw` with this member's
    /// key (0.5 §3.4), for the window `[not_before_ms, expires_ms]` (at most 86,400 s).
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
    /// frame received after it accepted that head. Keys of members that are no longer current,
    /// lost the namespace or have a higher session number are dropped with their windows, and
    /// the machine is given the new entitled writers.
    pub fn set_account(&mut self, account: SessionAccount, clock: Clock, epochs: &dyn EpochKeys) -> Step {
        let outs = self.apply_account(account, clock);
        Step {
            effects: self.run(outs, clock, epochs),
            dropped: None,
        }
    }
    fn apply_account(&mut self, account: SessionAccount, clock: Clock) -> Vec<Output> {
        for m in self.receiver.set_account(&account, clock.wall_ms) {
            self.machine.forget_member(&m);
        }
        let writers = account.writers(&self.cell.namespace, clock.wall_ms);
        self.account = account;
        self.machine
            .handle(Input::Entitled { writers }, clock.mono_ms)
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

    /// Bytes received from a carrier. A frame that fails any §S3 check is dropped silently
    /// and changes no state; a frame from a key this member has not accepted makes the machine
    /// send that member a `hello` (rate limited).
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
                    match self.sender.seal(&frame, epochs, clock.wall_ms) {
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
