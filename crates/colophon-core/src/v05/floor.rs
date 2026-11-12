//! The portability floor (§2.4, revision 5) as counters a verifier or service enforces.
//!
//! The core does no I/O and keeps no clock budget, so it can't impose the floor itself. A
//! caller that verifies an account counts what it verifies with a [`FloorCounter`]: every
//! authority entry, every pending object (transitions, vetoes and receipts held outside the history; copies embedded in entries count only as those entries), every envelope byte and
//! every signature verification (authority entries, transitions, vetoes, receipts, heads,
//! `handover`, `additions`, embedded requests). Exceeding a limit is `unavailable` (history
//! incomplete), never partial validity.
use super::{Failure, Result};

/// Limits on what one account may cost a verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloorLimits {
    /// Authority entries.
    pub entries: u64,
    /// Transitions, vetoes and receipts together.
    pub pending_objects: u64,
    /// Envelope bytes.
    pub bytes: u64,
    /// Signature verifications.
    pub signatures: u64,
}
/// The floor every service and verifier MUST support (§2.4).
pub const FLOOR: FloorLimits = FloorLimits {
    entries: 65_536,
    pending_objects: 4_096,
    bytes: 256 * 1024 * 1024,
    signatures: 262_144,
};
impl FloorLimits {
    /// True when every limit is at least the floor (a service MAY set higher limits only).
    pub fn meets_floor(&self) -> bool {
        self.entries >= FLOOR.entries
            && self.pending_objects >= FLOOR.pending_objects
            && self.bytes >= FLOOR.bytes
            && self.signatures >= FLOOR.signatures
    }
}

/// Running counts against a set of limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorCounter {
    limits: FloorLimits,
    entries: u64,
    pending_objects: u64,
    bytes: u64,
    signatures: u64,
}
impl FloorCounter {
    /// A counter enforcing `limits`. Limits below the floor are raised to it.
    pub fn new(limits: FloorLimits) -> Self {
        let limits = FloorLimits {
            entries: limits.entries.max(FLOOR.entries),
            pending_objects: limits.pending_objects.max(FLOOR.pending_objects),
            bytes: limits.bytes.max(FLOOR.bytes),
            signatures: limits.signatures.max(FLOOR.signatures),
        };
        Self {
            limits,
            entries: 0,
            pending_objects: 0,
            bytes: 0,
            signatures: 0,
        }
    }
    /// Counts so far: `(entries, pending objects, bytes, signatures)`, each saturating.
    pub fn counts(&self) -> (u64, u64, u64, u64) {
        (
            self.entries,
            self.pending_objects,
            self.bytes,
            self.signatures,
        )
    }
    /// The limits in force.
    pub fn limits(&self) -> FloorLimits {
        self.limits
    }
    fn check(&self) -> Result<()> {
        let l = self.limits;
        if self.entries > l.entries
            || self.pending_objects > l.pending_objects
            || self.bytes > l.bytes
            || self.signatures > l.signatures
        {
            return Err(Failure::Unavailable(
                "account exceeds this verifier's documented limits".into(),
            ));
        }
        Ok(())
    }
    /// Count one authority entry of `envelope_bytes` bytes carrying `signatures` signatures
    /// (primary, cosignatures, `additions`, `handover`, embedded requests).
    pub fn entry(&mut self, envelope_bytes: u64, signatures: u64) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        self.bytes = self.bytes.saturating_add(envelope_bytes);
        self.signatures = self.signatures.saturating_add(signatures);
        self.check()
    }
    /// Count one transition, veto or receipt.
    pub fn pending_object(&mut self, envelope_bytes: u64, signatures: u64) -> Result<()> {
        self.pending_objects = self.pending_objects.saturating_add(1);
        self.bytes = self.bytes.saturating_add(envelope_bytes);
        self.signatures = self.signatures.saturating_add(signatures);
        self.check()
    }
    /// Count signature verifications outside entries and pending objects (heads).
    pub fn signatures(&mut self, n: u64) -> Result<()> {
        self.signatures = self.signatures.saturating_add(n);
        self.check()
    }
    /// True once any count passes half the floor: hosts MUST then warn the owner (§2.4).
    pub fn past_half_floor(&self) -> bool {
        self.entries.saturating_mul(2) > FLOOR.entries
            || self.pending_objects.saturating_mul(2) > FLOOR.pending_objects
            || self.bytes.saturating_mul(2) > FLOOR.bytes
            || self.signatures.saturating_mul(2) > FLOOR.signatures
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn floor_is_enforced_and_never_lowered() {
        let mut c = FloorCounter::new(FloorLimits {
            entries: 1,
            pending_objects: 1,
            bytes: 1,
            signatures: 1,
        });
        assert_eq!(c.limits(), FLOOR);
        for _ in 0..FLOOR.pending_objects {
            c.pending_object(10, 1).unwrap();
        }
        assert!(c.past_half_floor());
        assert_eq!(c.pending_object(10, 1).unwrap_err().code(), "unavailable");
        assert!(FLOOR.meets_floor());
    }
}
