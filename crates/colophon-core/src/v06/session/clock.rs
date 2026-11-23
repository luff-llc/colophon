//! Round trip and clock offset (§S7).
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Samples kept per peer.
pub const SAMPLES: usize = 8;

/// One `pong` evaluated by the asker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sample {
    /// `max(0, (now − echo) − hold)`.
    pub rtt: u64,
    /// `pong.t − now + floor(rtt / 2)`: `responderClock ≈ askerClock + offset`.
    pub offset: i64,
    /// `ceil(rtt / 2)`.
    pub error: u64,
}

/// The §S7 integer formula. `now` is the asker's clock on receipt; all values are ms.
/// Saturates instead of overflowing.
pub fn sample(now: u64, pong_t: u64, echo: u64, hold: u64) -> Sample {
    let elapsed = i128::from(now) - i128::from(echo) - i128::from(hold);
    let rtt = u64::try_from(elapsed.max(0)).unwrap_or(u64::MAX);
    let offset = i128::from(pong_t) - i128::from(now) + i128::from(rtt / 2);
    let offset = i64::try_from(offset).unwrap_or(if offset < 0 { i64::MIN } else { i64::MAX });
    Sample {
        rtt,
        offset,
        error: rtt / 2 + rtt % 2,
    }
}

/// The last [`SAMPLES`] samples to one peer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Samples(VecDeque<Sample>);
impl Samples {
    /// Add a sample; returns the best one if it changed.
    pub fn push(&mut self, s: Sample) -> Option<Sample> {
        let before = self.best();
        self.0.push_back(s);
        while self.0.len() > SAMPLES {
            self.0.pop_front();
        }
        let after = self.best();
        (after != before).then_some(after).flatten()
    }
    /// The sample with the smallest `rtt`; the most recent one among equals.
    pub fn best(&self) -> Option<Sample> {
        let mut best: Option<Sample> = None;
        for s in &self.0 {
            if best.is_none_or(|b| s.rtt <= b.rtt) {
                best = Some(*s);
            }
        }
        best
    }
}
