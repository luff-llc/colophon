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
//! 0.6 conformance covers only the home carrier; bridging is specified for later carriers
//! (revision 10). A bridge keeps windows for at most 4 keys per origin member and limits
//! what it forwards per origin member (by default 50 frames and 262,144 bytes per second).
//!
//! A frame lost beyond the first hop is not sent again under the same `n`; the session layer
//! repairs loss with new frames. A frame addressed with `to` is bridged the same way; the
//! session layer ignores it unless it names this member.
use super::session::{Frame, MemberId};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Keys with windows kept per origin member (§S9, revision 10); the oldest is dropped.
pub const KEYS_PER_MEMBER: usize = 4;
/// Default forwarding limit per origin member, frames per second (§S9).
pub const FRAMES_PER_SECOND: u64 = 50;
/// Default forwarding limit per origin member, bytes per second (§S9).
pub const BYTES_PER_SECOND: u64 = 262_144;

/// A token bucket per origin member (milli-tokens, refilled from the caller's clock).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct Bucket {
    frames: u64,
    bytes: u64,
    at: u64,
}

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
    /// Keys with windows per origin member, oldest first (at most [`KEYS_PER_MEMBER`]).
    keys: BTreeMap<MemberId, VecDeque<String>>,
    /// Forwarding budget per origin member.
    buckets: BTreeMap<MemberId, Bucket>,
    /// The forwarding limits: frames and bytes per second per origin member.
    limits: (u64, u64),
    /// Frames not forwarded because their origin exceeded the limit.
    rate_dropped: u64,
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
            keys: BTreeMap::new(),
            buckets: BTreeMap::new(),
            limits: (FRAMES_PER_SECOND, BYTES_PER_SECOND),
            rate_dropped: 0,
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
        for ks in self.keys.values_mut() {
            ks.retain(|k| k != key);
        }
    }
    /// Forget a member no longer accepted: its keys, windows and budget.
    pub fn forget_member(&mut self, member: &str) {
        if let Some(ks) = self.keys.remove(member) {
            for k in ks {
                self.windows.remove(&k);
                self.forwarded.remove(&k);
            }
        }
        self.buckets.remove(member);
    }
    /// Set the per-origin forwarding limits (frames and bytes per second).
    pub fn set_limits(&mut self, frames_per_second: u64, bytes_per_second: u64) {
        self.limits = (frames_per_second, bytes_per_second);
    }
    /// Frames not forwarded because of the rate limit.
    pub fn rate_dropped(&self) -> u64 {
        self.rate_dropped
    }
    /// Note a key of `origin`; keep at most [`KEYS_PER_MEMBER`] per member.
    fn note_key(&mut self, origin: &str, key: &str) {
        let ks = self.keys.entry(origin.to_owned()).or_default();
        if ks.iter().any(|k| k == key) {
            return;
        }
        ks.push_back(key.to_owned());
        while ks.len() > KEYS_PER_MEMBER {
            if let Some(old) = ks.pop_front() {
                self.windows.remove(&old);
                self.forwarded.remove(&old);
            }
        }
    }
    /// Take one frame of `size` bytes from `origin`'s budget at `now` (ms).
    fn within_limit(&mut self, origin: &str, size: u64, now: u64) -> bool {
        let (fps, bps) = self.limits;
        let b = self.buckets.entry(origin.to_owned()).or_insert(Bucket {
            frames: fps * 1000,
            bytes: bps * 1000,
            at: now,
        });
        let dt = now.saturating_sub(b.at);
        b.at = now;
        // A full bucket holds one second's worth.
        b.frames = (b.frames + dt * fps).min(fps * 1000);
        b.bytes = (b.bytes + dt * bps).min(bps * 1000);
        if b.frames >= 1000 && b.bytes >= size * 1000 {
            b.frames -= 1000;
            b.bytes -= size * 1000;
            true
        } else {
            false
        }
    }
    /// The number of keys with a forwarding window.
    pub fn forwarding_keys(&self) -> usize {
        self.forwarded.len()
    }
    /// This member sends a frame of its own: transmit on every link. Its own window records
    /// it, so a copy that comes back is dropped.
    pub fn send(&mut self, wire: Wire) -> Vec<(LinkId, Wire)> {
        let origin = wire.frame.from.clone();
        self.note_key(&origin, &wire.key);
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
        self.receive_at(link, wire, verified, None)
    }
    /// As [`Bridge::receive_checked`], applying the per-origin forwarding limit at `now`
    /// (ms; `None`: no limit).
    pub fn receive_at(&mut self, link: LinkId, wire: Wire, verified: bool, now: Option<u64>) -> Received {
        if wire.frame.from == self.me || !verified {
            return Received::default();
        }
        let origin = wire.frame.from.clone();
        self.note_key(&origin, &wire.key);
        let first = self.forwarded.entry(wire.key.clone()).or_default().admit(wire.n) == Seen::New;
        let allowed = first
            && self.bridging
            && match now {
                Some(t) => {
                    let size = serde_json::to_vec(&wire.frame).map_or(0, |v| v.len() as u64);
                    let ok = self.within_limit(&origin, size, t);
                    if !ok {
                        self.rate_dropped += 1;
                    }
                    ok
                }
                None => true,
            };
        let forward = match allowed {
            true => self
                .links
                .iter()
                .filter(|l| **l != link)
                .map(|l| (*l, wire.clone()))
                .collect(),
            false => Vec::new(),
        };
        let deliver = match self.windows.entry(wire.key.clone()).or_default().admit(wire.n) {
            Seen::New => Some(wire),
            Seen::Duplicate | Seen::TooOld => None,
        };
        Received { deliver, forward }
    }
}
