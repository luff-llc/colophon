//! The `hello` a receiver sends when it drops a frame for want of an accepted session key
//! (§S3 "find an accepted session key for `(from, key)`, else drop the frame and send `hello`
//! to `from`").
//!
//! The codec decides that the key is missing, but only the machine can make a `hello` (its
//! `fresh` must be one the machine remembers, so that an echo of it opens a window). The
//! hello shares the machine's freshness-probe rate limit: at most one per `askTimeoutMs` per
//! member, whether the frame was dropped for a missing key or for a window not yet open.
use super::io::Output;
use super::Session;

impl Session {
    /// Send `from` a `hello` because one of its frames was dropped for want of an accepted
    /// session key, at most once per `askTimeoutMs` per member. Nothing happens before
    /// `join`, or for this member itself.
    pub fn hello_for_unknown_key(&mut self, from: &str, now: u64) -> Vec<Output> {
        let mut out = Vec::new();
        if !self.joined || from == self.me {
            return out;
        }
        let due = self
            .probed
            .get(from)
            .is_none_or(|t| now.saturating_sub(*t) >= self.policy.ask_timeout_ms);
        if due {
            self.fresh_now = now;
            self.probed.insert(from.to_owned(), now);
            self.send_hello_echo(&mut out, Some(from), false, Vec::new(), now);
        }
        out
    }
}
