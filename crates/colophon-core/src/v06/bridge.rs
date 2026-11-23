//! §S9 bridging (revision 7), as a small sans-IO component of the carrier layer.
//!
//! A member with more than one carrier or peer forwards every frame it accepts for the first
//! time, unchanged, on each of its other links; never back where it came from and never a
//! frame it has already accepted. The memory of "already accepted" is the §S3 window per
//! sender key: the highest `n` seen and which of the 128 values below it were seen. A frame
//! addressed with `to` is bridged the same way; the session layer ignores it unless it names
//! this member. Frames are signed by their origin, so this layer never changes them.
//!
//! The bridge decides only delivery and forwarding. Signature checks, the freshness
//! handshake and sealing are the codec's; the session machine (`super::session`) sees each
//! frame at most once per bridge incarnation.
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
    windows: BTreeMap<String, Window>,
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
    }
    /// This member sends a frame of its own: transmit on every link. Its own window records
    /// it, so a copy that comes back is dropped.
    pub fn send(&mut self, wire: Wire) -> Vec<(LinkId, Wire)> {
        self.windows.entry(wire.key.clone()).or_default().admit(wire.n);
        self.links.iter().map(|l| (*l, wire.clone())).collect()
    }
    /// A frame arrived on `link`.
    pub fn receive(&mut self, link: LinkId, wire: Wire) -> Received {
        if wire.frame.from == self.me {
            return Received::default();
        }
        match self.windows.entry(wire.key.clone()).or_default().admit(wire.n) {
            Seen::New => {
                let forward = if self.bridging {
                    self.links
                        .iter()
                        .filter(|l| **l != link)
                        .map(|l| (*l, wire.clone()))
                        .collect()
                } else {
                    Vec::new()
                };
                Received {
                    deliver: Some(wire),
                    forward,
                }
            }
            Seen::Duplicate | Seen::TooOld => Received::default(),
        }
    }
}
