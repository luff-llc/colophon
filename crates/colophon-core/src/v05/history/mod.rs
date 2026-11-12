//! The authority history verifier (§8), following §8.7's state table.
//!
//! Sans-IO: [`verify_history`] takes the object set (entries, pending transitions, vetoes and
//! receipts, heads), the versioned folded state and retained objects of §17.2, and the
//! verifier's clock. The high-water mark detects rollback and never selects a branch. The verdict is a function of
//! those inputs only: it doesn't depend on the order of the objects (a property test checks
//! that), and nothing in this module reads a clock or storage.
//!
//! Succession inputs include the predecessor history through its final entry. The caller
//! supplies all receipts, fresh heads and clocks. No peer checkpoint is trusted.
pub mod envelope;
pub mod home;
pub mod keyring;
mod state;
mod succession;
pub mod swift;
mod upgrade;

pub use state::{
    check_pending_transition, check_pending_veto, Activation, HomeStatus, MemberRecord, State,
    Suspension,
};

use crate::v05::{Failure, Unknown};
use envelope::AuthEnvelope;
use std::collections::BTreeMap;

/// What the verifier holds.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Objects {
    /// Authority entry envelopes, any order, possibly conflicting.
    pub entries: Vec<Vec<u8>>,
    /// Transitions, vetoes and receipts held outside the history.
    pub pending: Vec<Vec<u8>>,
    /// Head envelopes.
    pub heads: Vec<Vec<u8>>,
    /// Predecessor authority envelopes through F, supplied by the caller.
    #[serde(default)]
    pub predecessor: Vec<Vec<u8>>,
}

/// Locally trusted verifier state (§17.2). Persist atomically; never accept a checkpoint
/// supplied by a peer. The retained objects allow earlier conflicts to be reconsidered.
#[derive(Clone, Debug, Default)]
pub struct Persisted {
    /// The highest accepted `(seq, digest)`.
    pub high_water: Option<(u64, String)>,
    checkpoint: Option<Checkpoint>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Checkpoint {
    version: u32,
    now_ms: i64,
    state: Option<State>,
    objects: Objects,
    conflicts: bool,
    high_water: Option<(u64, String)>,
}

impl Persisted {
    /// A rollback marker without a folded state.
    pub fn high_water(seq: u64, digest: String) -> Self {
        Self {
            high_water: Some((seq, digest)),
            checkpoint: None,
        }
    }

    /// Save a verdict and the exact objects used to obtain it. Verification is repeated here
    /// so callers cannot accidentally pair a folded state with a different object set.
    pub fn checkpoint(objects: &Objects, previous: &Self, now_ms: i64) -> Self {
        let all = merged_objects(objects, previous);
        let verdict = verify_history(objects, previous, now_ms);
        let high_water = previous
            .high_water
            .clone()
            .filter(|(seq, _)| *seq >= verdict.branch.len() as u64)
            .or_else(|| {
                verdict
                    .branch
                    .last()
                    .map(|d| (verdict.branch.len() as u64, d.clone()))
            });
        Self {
            high_water: high_water.clone(),
            checkpoint: Some(Checkpoint {
                version: 1,
                now_ms,
                state: verdict.state,
                objects: all,
                conflicts: !verdict.conflicts.is_empty()
                    || matches!(verdict.stop, Some(Stop::Fork { .. })),
                high_water,
            }),
        }
    }

    /// Serialize a locally trusted checkpoint, including its format version.
    pub fn to_bytes(&self) -> crate::v05::Result<Vec<u8>> {
        let cp = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| crate::v05::malformed("no folded checkpoint"))?;
        let mut cp = cp.clone();
        cp.high_water = self.high_water.clone();
        serde_json::to_vec(&cp).map_err(|e| crate::v05::malformed(e.to_string()))
    }

    /// Restore bytes from the caller's trusted storage, never from the network.
    pub fn from_bytes(bytes: &[u8]) -> crate::v05::Result<Self> {
        let cp: Checkpoint =
            serde_json::from_slice(bytes).map_err(|e| crate::v05::malformed(e.to_string()))?;
        crate::v05::require(cp.version == 1, "unknown checkpoint version")?;
        if let Some(state) = &cp.state {
            state.check_checkpoint_shape()?;
        }
        Ok(Self {
            high_water: cp.high_water.clone(),
            checkpoint: Some(cp),
        })
    }

    /// Objects retained for rollback, conflict reconsideration and call-view construction.
    pub fn objects(&self) -> Option<&Objects> {
        self.checkpoint.as_ref().map(|cp| &cp.objects)
    }
}

fn merged_objects(objects: &Objects, persisted: &Persisted) -> Objects {
    let mut all = persisted.objects().cloned().unwrap_or_default();
    for (dst, src) in [
        (&mut all.entries, &objects.entries),
        (&mut all.pending, &objects.pending),
        (&mut all.heads, &objects.heads),
        (&mut all.predecessor, &objects.predecessor),
    ] {
        let mut seen: std::collections::BTreeSet<Vec<u8>> = dst.iter().cloned().collect();
        for bytes in src {
            if seen.insert(bytes.clone()) {
                dst.push(bytes.clone());
            }
        }
    }
    all
}

/// Why verification stopped before the end of the branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The entry at `seq` failed with `failure`.
    Failed {
        /// Seq of the failing entry.
        seq: u64,
        /// The §8.5 result.
        failure: Failure,
    },
    /// The entry at `seq` is held.
    Held {
        /// Seq of the held entry.
        seq: u64,
        /// Why.
        why: String,
    },
    /// An unresolved fork at `seq` (§8.6 rule 3).
    Fork {
        /// Seq of the conflict.
        seq: u64,
    },
}

/// The verdict over an object set.
#[derive(Clone, Debug)]
pub struct Verdict {
    /// The verified branch: body digests from seq 1.
    pub branch: Vec<String>,
    /// The folded state at the last verified entry (absent when the genesis failed).
    pub state: Option<State>,
    /// Why verification stopped, if it did before the branch ended.
    pub stop: Option<Stop>,
    /// The persisted high-water mark is not on this branch, or beyond it (§13.3).
    pub rollback: bool,
    /// Conflicts decided by §8.6, as `(seq, standing digest, losing digests)`.
    pub conflicts: Vec<(u64, String, Vec<String>)>,
}
impl Verdict {
    /// The §1 result code of the verification: `ok`, `held`, `refused:fork` or a failure's.
    pub fn code(&self) -> String {
        match &self.stop {
            None => "ok".into(),
            Some(Stop::Failed { failure, .. }) => failure.code(),
            Some(Stop::Held { .. }) => "held".into(),
            Some(Stop::Fork { .. }) => "refused:fork".into(),
        }
    }
    /// The seq the code refers to: the stopping entry, or the last verified seq.
    pub fn seq(&self) -> u64 {
        match &self.stop {
            Some(Stop::Failed { seq, .. })
            | Some(Stop::Held { seq, .. })
            | Some(Stop::Fork { seq }) => *seq,
            None => self.branch.len() as u64,
        }
    }
}

/// A parsed entry with its header.
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub env: AuthEnvelope,
    pub seq: u64,
    pub previous: Option<String>,
    pub issued: i64,
    pub by: String,
    pub kind: String,
    pub size: usize,
}

fn parse_entry(bytes: &[u8]) -> Result<Entry, Failure> {
    use crate::v05::encoding::bounds::AUTHORITY_BODY;
    let env = AuthEnvelope::parse(
        bytes,
        AUTHORITY_BODY,
        AUTHORITY_BODY.saturating_mul(2),
        false,
    )?;
    let (h, _) = crate::v05::members::AuthorityHeader::split(env.value.clone())?;
    if h.protocol != "colophon/authority/5" {
        return Err(if h.protocol == "colophon/authority/4" {
            crate::v05::malformed("a /4 entry outside the upgrade prefix")
        } else {
            crate::v05::malformed("not a colophon/authority/5 entry")
        });
    }
    Ok(Entry {
        size: env.body.len(),
        env,
        seq: h.seq,
        previous: h.previous,
        issued: h.issued.1,
        by: h.by,
        kind: h.kind,
    })
}

/// Verify an account's history from its object set, the persisted state and the clock.
pub fn verify_history(objects: &Objects, persisted: &Persisted, now_ms: i64) -> Verdict {
    let incoming = objects;
    let all_objects = merged_objects(objects, persisted);
    let objects = &all_objects;
    // Parse every entry; group candidates by (seq, previous). Unparseable entries are kept as
    // failures at their seq when nothing valid stands there.
    let mut by_seq: BTreeMap<u64, Vec<Result<Entry, Failure>>> = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut parse_failures: BTreeMap<u64, (String, Failure)> = BTreeMap::new();
    for bytes in &objects.entries {
        match parse_entry(bytes) {
            Ok(e) => {
                if seen.insert(e.env.digest.clone()) {
                    by_seq.entry(e.seq).or_default().push(Ok(e));
                }
            }
            Err(f) => {
                // Position from the raw body when the header doesn't parse. Several failures at
                // one seq: the one with the lowest envelope digest, so input order never matters.
                let seq = state::raw_seq(bytes).unwrap_or(0);
                let d = crate::v05::encoding::digest(bytes);
                match parse_failures.get(&seq) {
                    Some((old, _)) if old <= &d => {}
                    _ => {
                        parse_failures.insert(seq, (d, f));
                    }
                }
            }
        }
    }
    // Sort candidates at each seq by body digest so iteration never depends on input order.
    for list in by_seq.values_mut() {
        list.sort_by(|a, b| match (a, b) {
            (Ok(x), Ok(y)) => x.env.digest.cmp(&y.env.digest),
            _ => std::cmp::Ordering::Equal,
        });
    }
    let pending = state::Pending::parse(&objects.pending);
    let heads = state::HeadSet::parse(&objects.heads);
    let mut verdict = Verdict {
        branch: Vec::new(),
        state: None,
        stop: None,
        rollback: false,
        conflicts: Vec::new(),
    };
    let mut st: Option<State> = None;
    let mut seq = 1u64;
    if let Some(result) = upgrade::bootstrap(objects, now_ms) {
        match result {
            Ok(saved) => {
                verdict.branch = saved.history().to_vec();
                seq = verdict.branch.len() as u64 + 1;
                st = Some(saved);
            }
            Err(stop) => {
                verdict.stop = Some(stop);
                return verdict;
            }
        }
    }
    // Fast path: append to the verified folded state. An earlier candidate, new head,
    // prior conflict, or backwards clock requires replay of the retained objects. In
    // particular a high-water marker never freezes a provisional branch.
    if let Some(cp) = &persisted.checkpoint {
        if let Some(saved) = &cp.state {
            let retained: std::collections::BTreeSet<&Vec<u8>> =
                cp.objects.entries.iter().collect();
            let safe = !cp.conflicts
                && now_ms >= cp.now_ms
                && incoming
                    .predecessor
                    .iter()
                    .all(|h| cp.objects.predecessor.contains(h))
                && incoming.heads.iter().all(|h| cp.objects.heads.contains(h))
                && incoming.entries.iter().all(|b| {
                    retained.contains(b)
                        || parse_entry(b).is_ok_and(|e| e.seq > saved.history().len() as u64)
                });
            if safe {
                verdict.branch = saved.history().to_vec();
                st = Some(saved.clone());
                seq = verdict.branch.len() as u64 + 1;
            }
        }
    }
    loop {
        let prev = verdict.branch.last().cloned();
        let candidates: Vec<&Entry> = by_seq
            .get(&seq)
            .map(|l| {
                l.iter()
                    .filter_map(|r| r.as_ref().ok())
                    .filter(|e| e.previous == prev)
                    .collect()
            })
            .unwrap_or_default();
        if candidates.is_empty() {
            if let Some((_, f)) = parse_failures.get(&seq) {
                verdict.stop = Some(Stop::Failed {
                    seq,
                    failure: f.clone(),
                });
            }
            break;
        }
        // Judge every candidate against the state before it.
        let mut valid: Vec<(&Entry, State)> = Vec::new();
        let mut first_failure: Option<(Stop, &Entry)> = None;
        for e in &candidates {
            let r = match &st {
                None => state::genesis(e, now_ms, &objects.predecessor),
                Some(s) => state::apply(s, e, &pending, &heads, by_seq_all(&by_seq), now_ms),
            };
            match r {
                Ok(next) => valid.push((e, next)),
                Err(state::Outcome::Fail(f)) => {
                    if first_failure.is_none() {
                        first_failure = Some((Stop::Failed { seq, failure: f }, e));
                    }
                }
                Err(state::Outcome::Held(why)) => {
                    if first_failure.is_none()
                        || matches!(first_failure, Some((Stop::Failed { .. }, _)))
                    {
                        first_failure = Some((Stop::Held { seq, why }, e));
                    }
                }
            }
        }
        let chosen = match valid.len() {
            0 => {
                verdict.stop = first_failure.map(|(s, _)| s);
                break;
            }
            1 => valid.pop(),
            _ => match &st {
                Some(s) => match state::resolve_conflict(s, &valid, &heads, by_seq_all(&by_seq)) {
                    Some(i) => {
                        let losers = valid
                            .iter()
                            .enumerate()
                            .filter(|(j, _)| *j != i)
                            .map(|(_, (e, _))| e.env.digest.clone())
                            .collect();
                        verdict
                            .conflicts
                            .push((seq, valid[i].0.env.digest.clone(), losers));
                        Some(valid.swap_remove(i))
                    }
                    None => {
                        verdict.stop = Some(Stop::Fork { seq });
                        break;
                    }
                },
                None => {
                    verdict.stop = Some(Stop::Fork { seq });
                    break;
                }
            },
        };
        let Some((e, next)) = chosen else { break };
        verdict.branch.push(e.env.digest.clone());
        st = Some(next);
        seq += 1;
    }
    if let Some((hw_seq, hw_digest)) = &persisted.high_water {
        let on_branch = usize::try_from(hw_seq.saturating_sub(1))
            .ok()
            .and_then(|i| verdict.branch.get(i));
        verdict.rollback = on_branch != Some(hw_digest);
    }
    if !matches!(verdict.stop, Some(Stop::Fork { .. })) {
        if let Some(s) = &mut st {
            succession::finish(s, objects, now_ms);
        }
    }
    verdict.state = st;
    verdict
}

fn by_seq_all(by_seq: &BTreeMap<u64, Vec<Result<Entry, Failure>>>) -> Vec<&Entry> {
    by_seq
        .values()
        .flatten()
        .filter_map(|r| r.as_ref().ok())
        .collect()
}

/// Unknown content found in an authority entry's kind fields by the pre-scan (§8.5 step 4).
pub(crate) fn prescan(kind: &str, body: &serde_json::Value) -> Unknown {
    crate::v05::prescan::authority_fields(kind, body).unwrap_or_default()
}
