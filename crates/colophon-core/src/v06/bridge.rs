//! §S9 bridging (revision 8), as a small sans-IO component of the carrier layer.
//!
//! Every member bridges. A frame that passes the §S3 outer checks up to and including the
//! frame signature under an accepted session key (the caller says so with `verified`) is
//! forwarded the first time this member sees its `(key, n)`, unchanged, on each of its other
//! links; never back where it came from and never twice. The forwarding memory is a 128-wide
//! window per key, kept apart from the delivery window, and a frame older than it is not
//! forwarded. Forwarding does not wait for this member's own freshness exchange with the
//! origin: freshness (in `super::session`) governs only what this member acts on.
//!
//! A frame lost beyond the first hop is not sent again under the same `n`; the session layer
//! repairs loss with new frames. A frame addressed with `to` is bridged the same way; the
//! session layer ignores it unless it names this member.
use super::session::{Frame, MemberId};
use std::collections::{BTreeMap, BTreeSet};

/// A link of this member: one carrier, or one direct peer on a carrier.
pub type LinkId = u32;

/// Width of the §S3 window.
pub const WINDOW: u64 = 128;

/// A frame as carriers move it: the origin's session key and `n`, and the frame.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Wire {
    /// The session key ID of the origin.
    pub key: String,
    /// The frame's `n` under that key.
    pub n: u64,
    /// The frame (its `from` is the origin).
    pub frame: Frame,
}

/// The §S3 window for one sender key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Window {
    high: u64,
    seen: BTreeSet<u64>,
}

/// What the window says about an `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// First time: accept, deliver and bridge.
    New,
    /// Already accepted.
    Duplicate,
    /// More than 128 below the highest accepted.
    TooOld,
}

impl Window {
    /// Record `n`; say whether it was new.
    pub fn admit(&mut self, n: u64) -> Seen {
        if self.seen.contains(&n) {
            return Seen::Duplicate;
        }
        if n.saturating_add(WINDOW) < self.high {
            return Seen::TooOld;
        }
        self.seen.insert(n);
        if n > self.high {
            self.high = n;
        }
        let floor = self.high.saturating_sub(WINDOW);
        self.seen.retain(|x| *x >= floor);
        Seen::New
    }
}

/// What a received frame leads to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Hand this to the session layer (the codec verifies and opens it first).
    pub deliver: Option<Wire>,
    /// Transmit these on these links.
    pub forward: Vec<(LinkId, Wire)>,
}

/// One member's bridge.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Bridge {
    me: MemberId,
    links: BTreeSet<LinkId>,
    /// Delivery window per key: what was handed to the session layer.
    windows: BTreeMap<String, Window>,
    /// Forwarding window per key (§S9, revision 8), separate from the delivery window.
    forwarded: BTreeMap<String, Window>,
    /// Whether to bridge at all (off: deliver only; for revision 6 comparisons).
    bridging: bool,
}

impl Bridge {
    /// A bridge for `me` with no links.
    pub fn new(me: &str) -> Self {
        Self {
            me: me.to_owned(),
            links: BTreeSet::new(),
            windows: BTreeMap::new(),
            forwarded: BTreeMap::new(),
            bridging: true,
        }
    }
    /// The same, delivering without forwarding (a member that does not bridge).
    pub fn without_bridging(me: &str) -> Self {
        Self {
            bridging: false,
            ..Self::new(me)
        }
    }
    /// A link came up.
    pub fn add_link(&mut self, link: LinkId) {
        self.links.insert(link);
    }
    /// A link went away.
    pub fn remove_link(&mut self, link: LinkId) {
        self.links.remove(&link);
    }
    /// The process restarted: every window is lost (a new session key also starts).
    pub fn restart(&mut self) {
        self.windows.clear();
        self.forwarded.clear();
    }
    /// Forget a key whose delegation expired or whose member is no longer accepted.
    pub fn forget_key(&mut self, key: &str) {
        self.windows.remove(key);
        self.forwarded.remove(key);
    }
    /// The number of keys with a forwarding window.
    pub fn forwarding_keys(&self) -> usize {
        self.forwarded.len()
    }
    /// This member sends a frame of its own: transmit on every link. Its own window records
    /// it, so a copy that comes back is dropped.
    pub fn send(&mut self, wire: Wire) -> Vec<(LinkId, Wire)> {
        self.windows.entry(wire.key.clone()).or_default().admit(wire.n);
        self.forwarded.entry(wire.key.clone()).or_default().admit(wire.n);
        self.links.iter().map(|l| (*l, wire.clone())).collect()
    }
    /// A frame arrived on `link`. `verified`: it passed the §S3 outer checks through the
    /// frame signature under an accepted session key; otherwise it is dropped.
    pub fn receive(&mut self, link: LinkId, wire: Wire) -> Received {
        self.receive_checked(link, wire, true)
    }
    /// As [`Bridge::receive`], saying whether the frame verified.
    pub fn receive_checked(&mut self, link: LinkId, wire: Wire, verified: bool) -> Received {
        if wire.frame.from == self.me || !verified {
            return Received::default();
        }
        let forward = match self.forwarded.entry(wire.key.clone()).or_default().admit(wire.n) {
            Seen::New if self.bridging => self
                .links
                .iter()
                .filter(|l| **l != link)
                .map(|l| (*l, wire.clone()))
                .collect(),
            _ => Vec::new(),
        };
        let deliver = match self.windows.entry(wire.key.clone()).or_default().admit(wire.n) {
            Seen::New => Some(wire),
            Seen::Duplicate | Seen::TooOld => None,
        };
        Received { deliver, forward }
    }
}
