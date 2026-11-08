//! Device-local incremental projections and bounded replay checkpoints.
pub use crate::library::storage::{
    Engine, EngineOptions, EngineStats, HistoryPage, OpenMode, RecordSource, VerificationProgress,
};
use crate::{domain::State, model::OperationView, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Changed namespace revisions from one merge, unlock, or completed write.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSummary {
    /// Namespace name to its new local revision. Empty for an identical merge.
    pub namespaces: BTreeMap<String, u64>,
}
/// Automatic checkpoint policy; zero cadence disables automatic snapshots.
#[derive(Clone, Debug)]
pub struct CheckpointPolicy {
    /// Snapshot after this many admitted operations.
    pub every: usize,
    /// Maximum in-memory snapshots retained per namespace.
    pub retain: usize,
}
impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            every: 10_000,
            retain: 4,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub position: usize,
    pub digest: [u8; 32],
    pub state: State,
}
#[derive(Clone)]
pub(crate) struct Namespace {
    pub revision: u64,
    pub state: State,
    pub order: Vec<String>,
    pub hashes: Vec<[u8; 32]>,
    pub clock: u64,
    pub checkpoints: Vec<Snapshot>,
    pub applied: u64,
}
impl Namespace {
    pub fn new(ns: &str) -> Self {
        Self {
            revision: 0,
            state: State::new(ns),
            order: Vec::new(),
            hashes: vec![[0; 32]],
            clock: 0,
            checkpoints: Vec::new(),
            applied: 0,
        }
    }
    pub fn append(
        &mut self,
        digest: &str,
        op: &OperationView,
        kind: Option<crate::domain::AuthorContext>,
        policy: &CheckpointPolicy,
    ) {
        self.state.apply_with_context(op, kind.as_ref());
        self.applied += 1;
        self.clock = self.clock.max(op.clock);
        self.order.push(digest.into());
        self.hashes
            .push(roll(self.hashes.last().copied().unwrap_or([0; 32]), digest));
        self.state
            .bind_admitted_prefix(*self.hashes.last().expect("prefix"));
        if policy.every > 0 && policy.retain > 0 && self.order.len() % policy.every == 0 {
            self.checkpoints.push(self.snapshot());
            if self.checkpoints.len() > policy.retain {
                self.checkpoints.remove(0);
            }
        }
    }
    /// Insert an already verified live predecessor after unrelated durable work. The
    /// caller proves episode ordering is unchanged; keep canonical prefix hashes for caches.
    pub fn insert_retained(
        &mut self,
        digest: &str,
        op: &OperationView,
        kind: Option<crate::domain::AuthorContext>,
        position: usize,
    ) {
        self.state.apply_with_context(op, kind.as_ref());
        self.applied += 1;
        self.clock = self.clock.max(op.clock);
        self.order.insert(position, digest.into());
        self.hashes = prefix_hashes(&self.order);
        self.state
            .bind_admitted_prefix(*self.hashes.last().expect("prefix"));
        self.checkpoints
            .retain(|snapshot| snapshot.position <= position);
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            position: self.order.len(),
            digest: self.hashes.last().copied().unwrap_or([0; 32]),
            state: self.state.clone(),
        }
    }
    pub fn reconcile(
        &mut self,
        ns: &str,
        ops: &[(&str, &OperationView)],
        policy: &CheckpointPolicy,
        restored: Option<Snapshot>,
        member_kind: impl Fn(&OperationView) -> Option<crate::domain::AuthorContext>,
    ) -> bool {
        let common = self
            .order
            .iter()
            .zip(ops)
            .take_while(|(old, (new, _))| old.as_str() == *new)
            .count();
        let changed = common != self.order.len() || common != ops.len();
        let mut start = common;
        if common < self.order.len() {
            self.checkpoints
                .retain(|s| s.position <= common && self.hashes.get(s.position) == Some(&s.digest));
            let checkpoint = self.checkpoints.last();
            start = checkpoint.map_or(0, |s| s.position);
            self.state = checkpoint.map_or_else(|| State::new(ns), |s| s.state.clone());
        }
        if let Some(s) = restored {
            start = s.position;
            self.state = s.state;
            self.order = ops[..start].iter().map(|(d, _)| (*d).to_owned()).collect();
            self.hashes = prefix_hashes(&self.order);
            self.checkpoints.clear();
            if policy.retain > 0 {
                self.checkpoints.push(self.snapshot());
            }
        }
        self.order.truncate(start);
        self.hashes.truncate(start + 1);
        self.clock = if start == 0 {
            0
        } else {
            ops[start - 1].1.clock
        };
        for (digest, op) in &ops[start..] {
            self.append(digest, op, member_kind(op), policy);
        }
        changed
    }
    pub fn query(&self, name: &str, args: &serde_json::Value) -> Result<serde_json::Value> {
        self.state.query(name, args)
    }
}
pub(crate) fn prefix_hashes(digests: &[String]) -> Vec<[u8; 32]> {
    let mut hashes = vec![[0; 32]];
    for digest in digests {
        hashes.push(roll(hashes.last().copied().unwrap_or([0; 32]), digest));
    }
    hashes
}
pub(crate) fn roll(previous: [u8; 32], digest: &str) -> [u8; 32] {
    // Operation digests are verified SHA-256 lowercase hex; hash their raw 32 bytes.
    let mut raw = [0u8; 32];
    for (i, pair) in digest.as_bytes().chunks_exact(2).take(32).enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        raw[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    let mut h = Sha256::new();
    h.update(previous);
    h.update(raw);
    h.finalize().into()
}
