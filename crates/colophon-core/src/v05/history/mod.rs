//! The authority history verifier (§8), following §8.7's state table.
//!
//! Sans-IO: [`verify_history`] takes the object set (entries, pending transitions, vetoes and
//! receipts, heads), the persisted state of §17.2 (here only the high-water mark, which detects
//! rollback and never selects a branch) and the verifier's clock. The verdict is a function of
//! those inputs only: it doesn't depend on the order of the objects (a property test checks
//! that), and nothing in this module reads a clock or storage.
//!
//! Not here (reported as not implemented by callers): succession (`predecessor`,
//! `successionVetoed`, `successor`), `resolve`, the 0.4 `upgrade` prefix, homes' admission
//! rules (§13.1 caps and clock) and the pending exchange (§14).
pub mod envelope;
pub mod keyring;
mod state;

pub use state::{
    check_pending_transition, Activation, HomeStatus, MemberRecord, State, Suspension,
};

use crate::v05::{Failure, Unknown};
use envelope::AuthEnvelope;
use std::collections::BTreeMap;

/// What the verifier holds.
#[derive(Clone, Debug, Default)]
pub struct Objects {
    /// Authority entry envelopes, any order, possibly conflicting.
    pub entries: Vec<Vec<u8>>,
    /// Transitions, vetoes and receipts held outside the history.
    pub pending: Vec<Vec<u8>>,
    /// Head envelopes.
    pub heads: Vec<Vec<u8>>,
}

/// The persisted state a resuming verifier passes in (§17.2). Only the high-water mark is
/// used, and only to detect rollback (§13.3).
#[derive(Clone, Debug, Default)]
pub struct Persisted {
    /// The highest accepted `(seq, digest)`.
    pub high_water: Option<(u64, String)>,
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
            Failure::NewerFormat("0.4 upgrade prefixes are not implemented".into())
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
                None => state::genesis(e, now_ms),
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
