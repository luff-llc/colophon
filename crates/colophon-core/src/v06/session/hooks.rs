//! What the codec layer tells the machine beyond frames: a `hello` for an unknown key, a
//! session key whose window was closed, and a change of this member's own write access.
//!
//! The machine owns the lifecycle of other members' session keys (revision 17): at most 4
//! open windows and 4 candidates per member, and per member the mark after which an echo
//! may open a window. The codec caches a key's delegation and replay window only while the
//! machine knows the key ([`Session::knows_key`]).
use super::io::{Event, Output};
use super::types::Body;
use super::{Session, PROBES_PER_SECOND};

impl Session {
    /// Send `from` a `hello` because one of its frames was dropped for want of an accepted
    /// session key (§S3 step 4). The codec calls this only for a member entitled to the
    /// namespace. At most once per `askTimeoutMs` per member (shared with the freshness
    /// probe) and [`PROBES_PER_SECOND`] in all. Nothing happens before `join`, or for this
    /// member itself.
    pub fn hello_for_unknown_key(&mut self, from: &str, now: u64) -> Vec<Output> {
        let mut out = Vec::new();
        if !self.joined || from == self.me {
            return out;
        }
        let ask = self.policy.ask_timeout_ms;
        let due = self
            .probed
            .get(from)
            .is_none_or(|t| now.saturating_sub(*t) >= ask);
        while self
            .probe_times
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= 1_000)
        {
            self.probe_times.pop_front();
        }
        if due && self.probe_times.len() < PROBES_PER_SECOND {
            self.fresh_now = now;
            self.probed.retain(|_, t| now.saturating_sub(*t) < ask);
            self.probed.insert(from.to_owned(), now);
            self.probe_times.push_back(now);
            self.send_hello_echo(&mut out, Some(from), false, Vec::new(), now);
        }
        out
    }

    /// `member`'s session key `key` stopped being accepted (§S2: its delegation no longer
    /// holds, or it expired). Its window or candidacy ends; a window closing marks the member,
    /// so the key reopens only through a new challenge (§S3, revision 17).
    pub fn close_window(&mut self, member: &str, key: &str) {
        let had = self.windows.remove(&(member.to_owned(), key.to_owned())).is_some();
        if let Some(order) = self.window_order.get_mut(member) {
            order.retain(|k| k != key);
        }
        if let Some(c) = self.candidates.get_mut(member) {
            c.retain(|k| k != key);
        }
        if had {
            self.mark_closed(member);
        }
    }

    /// Whether this member may write, as of the host's accepted authority head (§S1). A
    /// member that loses write access stops acting as holder at once (it releases with
    /// `bye`), gives up wanting the role, its pending passes and its `yielded`, and reports
    /// its unanswered submits failed. A member that gains it may ask, take and submit.
    pub fn set_can_write(&mut self, can_write: bool, now: u64) -> Vec<Output> {
        let mut out = Vec::new();
        if self.can_write == can_write {
            return out;
        }
        self.can_write = can_write;
        if can_write {
            return out;
        }
        self.fresh_now = now;
        self.want = None;
        self.asks.clear();
        self.sent_passes.clear();
        self.pending_yielded = None;
        let ids: Vec<_> = self.submits.keys().copied().collect();
        self.submits.clear();
        if self.is_holder() {
            let claim = self.accepted.clone();
            self.released = true;
            self.gate = None;
            self.took_wanting = false;
            self.persist(&mut out);
            self.send(&mut out, None, false, Body::Bye { claim, leaving: false });
            Self::event(&mut out, Event::HolderChanged { claim: None });
        }
        for id in ids {
            Self::event(&mut out, Event::SubmitFailed { id });
        }
        out
    }

    /// Whether this member may write (§S1), as last set.
    pub fn can_write(&self) -> bool {
        self.can_write
    }
}
