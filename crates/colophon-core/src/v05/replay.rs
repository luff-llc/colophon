//! The call replay store (§12.4, revision 5) as an interface, with an in-memory reference
//! implementation for tests and single-process services.
//!
//! State machine: a key is **reserved** (`Pending`) by an atomic compare-and-swap after
//! §12.3 step 7 (this crate reserves after step 8, see the implementation notes) and before
//! any effect. A pending reservation ends as exactly one of `Completed(result, effect)`,
//! `Completed(result, none)` or `Abandoned`. Terminal states never change. A crash leaves
//! `Pending`; recovery resolves it from the durable effect record, never by re-running the
//! effect. Refusals before the reservation leave no trace.
use std::collections::BTreeMap;

/// Reservations are kept this long, whatever the account's policy (§12.4).
pub const RETENTION_MS: i64 = 7_200_000;

/// The reservation key `(account, audience, acting key ID, purpose, requestId)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayKey {
    /// 64-hex account ID.
    pub account: String,
    /// The call's audience.
    pub audience: String,
    /// Key ID of the acting key (never the signature bytes).
    pub acting_key: String,
    /// The call's purpose.
    pub purpose: String,
    /// The call's `requestId`, as sent.
    pub request_id: String,
}

/// The durable record an effect writes in its own transaction when it can't commit together
/// with the completion: call digest, effect identity and a replayable result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRecord {
    /// Body digest of the call the effect served.
    pub call_digest: String,
    /// The service's identity for the effect (for example a transaction ID).
    pub effect: String,
    /// A result the audience may return to a later identical call of a non-read purpose.
    pub result: String,
}

/// The state of one reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayState {
    /// Reserved; no terminal state yet.
    Pending {
        /// Body digest of the reserving call.
        digest: String,
    },
    /// The call finished; `effect` is `None` when no protected effect committed.
    Completed {
        /// Body digest of the reserving call.
        digest: String,
        /// The result code returned.
        result: String,
        /// The committed effect, if any.
        effect: Option<EffectRecord>,
    },
    /// Resolved after a crash with no committed effect, or given up by the service.
    Abandoned {
        /// Body digest of the reserving call.
        digest: String,
    },
}
impl ReplayState {
    /// The reserving call's body digest.
    pub fn digest(&self) -> &str {
        match self {
            Self::Pending { digest }
            | Self::Completed { digest, .. }
            | Self::Abandoned { digest } => digest,
        }
    }
}

/// The outcome of a compare-and-swap reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The key was free and is now `Pending` with this digest.
    Reserved,
    /// A reservation with the same digest exists: `refused:replay`.
    Replay,
    /// A reservation with a different digest exists: `refused:conflict`.
    Conflict,
}

/// A store transition that the state machine forbids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// No reservation under this key.
    Missing,
    /// The reservation is already terminal.
    NotPending,
    /// A durable record names a different call digest than the reservation.
    DigestMismatch,
}

/// The replay store a call verifier and its service share (§12.4). Every method is one atomic
/// operation; a shared implementation (a database row with a unique key) MUST make `reserve`
/// a compare-and-swap across every instance serving the audience.
pub trait ReplayStore {
    /// Read-only look-up, for the consultation at §12.3 step 3. Expired entries are absent.
    fn lookup(&self, key: &ReplayKey, now_ms: i64) -> Option<ReplayState>;
    /// Atomically reserve `key` as `Pending` with `digest` unless a live reservation exists.
    fn reserve(&mut self, key: &ReplayKey, digest: &str, now_ms: i64) -> Reservation;
    /// `Pending` → `Completed(result, effect)`.
    fn complete(
        &mut self,
        key: &ReplayKey,
        result: &str,
        effect: Option<EffectRecord>,
    ) -> Result<(), ReplayError>;
    /// `Pending` → `Abandoned`.
    fn abandon(&mut self, key: &ReplayKey) -> Result<(), ReplayError>;
    /// Crash recovery: resolve a `Pending` reservation from the durable record. With a record
    /// for this call it becomes `Completed(record.result, record)`; without one, `Abandoned`.
    fn recover(
        &mut self,
        key: &ReplayKey,
        record: Option<EffectRecord>,
    ) -> Result<ReplayState, ReplayError>;
}

/// An in-memory [`ReplayStore`]. Not shared across processes; for tests and single instances.
#[derive(Clone, Debug, Default)]
pub struct MemoryReplayStore {
    entries: BTreeMap<ReplayKey, (i64, ReplayState)>,
}
impl MemoryReplayStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
    /// Drop reservations older than [`RETENTION_MS`].
    pub fn purge(&mut self, now_ms: i64) {
        self.entries
            .retain(|_, (at, _)| now_ms - *at < RETENTION_MS);
    }
    /// Number of live entries (including expired ones not yet purged).
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn pending_mut(&mut self, key: &ReplayKey) -> Result<&mut (i64, ReplayState), ReplayError> {
        let entry = self.entries.get_mut(key).ok_or(ReplayError::Missing)?;
        match entry.1 {
            ReplayState::Pending { .. } => Ok(entry),
            _ => Err(ReplayError::NotPending),
        }
    }
}
impl ReplayStore for MemoryReplayStore {
    fn lookup(&self, key: &ReplayKey, now_ms: i64) -> Option<ReplayState> {
        self.entries
            .get(key)
            .filter(|(at, _)| now_ms - *at < RETENTION_MS)
            .map(|(_, s)| s.clone())
    }
    fn reserve(&mut self, key: &ReplayKey, digest: &str, now_ms: i64) -> Reservation {
        if let Some(existing) = self.lookup(key, now_ms) {
            return if existing.digest() == digest {
                Reservation::Replay
            } else {
                Reservation::Conflict
            };
        }
        self.entries.insert(
            key.clone(),
            (
                now_ms,
                ReplayState::Pending {
                    digest: digest.into(),
                },
            ),
        );
        Reservation::Reserved
    }
    fn complete(
        &mut self,
        key: &ReplayKey,
        result: &str,
        effect: Option<EffectRecord>,
    ) -> Result<(), ReplayError> {
        let entry = self.pending_mut(key)?;
        let digest = entry.1.digest().to_string();
        if effect.as_ref().is_some_and(|e| e.call_digest != digest) {
            return Err(ReplayError::DigestMismatch);
        }
        entry.1 = ReplayState::Completed {
            digest,
            result: result.into(),
            effect,
        };
        Ok(())
    }
    fn abandon(&mut self, key: &ReplayKey) -> Result<(), ReplayError> {
        let entry = self.pending_mut(key)?;
        entry.1 = ReplayState::Abandoned {
            digest: entry.1.digest().to_string(),
        };
        Ok(())
    }
    fn recover(
        &mut self,
        key: &ReplayKey,
        record: Option<EffectRecord>,
    ) -> Result<ReplayState, ReplayError> {
        let entry = self.pending_mut(key)?;
        let digest = entry.1.digest().to_string();
        entry.1 = match record {
            Some(r) if r.call_digest == digest => ReplayState::Completed {
                digest,
                result: r.result.clone(),
                effect: Some(r),
            },
            Some(_) => return Err(ReplayError::DigestMismatch),
            None => ReplayState::Abandoned { digest },
        };
        Ok(entry.1.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn key(r: &str) -> ReplayKey {
        ReplayKey {
            account: "a".repeat(64),
            audience: "https://s.example".into(),
            acting_key: "k".repeat(32),
            purpose: "p".into(),
            request_id: r.into(),
        }
    }
    #[test]
    fn state_machine() {
        let mut s = MemoryReplayStore::new();
        let k = key("1");
        assert_eq!(s.reserve(&k, "d1", 0), Reservation::Reserved);
        assert_eq!(s.reserve(&k, "d1", 1), Reservation::Replay);
        assert_eq!(s.reserve(&k, "d2", 1), Reservation::Conflict);
        let rec = EffectRecord {
            call_digest: "d1".into(),
            effect: "tx1".into(),
            result: "ok".into(),
        };
        assert_eq!(
            s.complete(
                &k,
                "ok",
                Some(EffectRecord {
                    call_digest: "dX".into(),
                    ..rec.clone()
                })
            ),
            Err(ReplayError::DigestMismatch)
        );
        s.complete(&k, "ok", Some(rec)).unwrap();
        assert_eq!(s.complete(&k, "ok", None), Err(ReplayError::NotPending));
        assert_eq!(s.abandon(&k), Err(ReplayError::NotPending));
        assert_eq!(
            s.reserve(&k, "d1", 2),
            Reservation::Replay,
            "later identical calls stay refused"
        );
        // Crash recovery.
        let k2 = key("2");
        s.reserve(&k2, "d", 0);
        assert!(matches!(
            s.recover(&k2, None).unwrap(),
            ReplayState::Abandoned { .. }
        ));
        assert_eq!(s.recover(&k2, None), Err(ReplayError::NotPending));
        let k3 = key("3");
        s.reserve(&k3, "d", 0);
        let r = EffectRecord {
            call_digest: "d".into(),
            effect: "e".into(),
            result: "ok".into(),
        };
        assert!(matches!(
            s.recover(&k3, Some(r)).unwrap(),
            ReplayState::Completed {
                effect: Some(_),
                ..
            }
        ));
        assert_eq!(s.complete(&key("4"), "ok", None), Err(ReplayError::Missing));
        // Retention.
        assert_eq!(s.reserve(&k, "d9", RETENTION_MS), Reservation::Reserved);
        s.purge(RETENTION_MS * 3);
        assert!(s.is_empty());
    }
}
