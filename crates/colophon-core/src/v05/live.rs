//! Live state (0.3 §5.1 as 0.5 §11.8 incorporates it): replaceable per-author slots at
//! `state/<author>/<namespace>/<slot>.json`, each a signed `/5` operation header with a `live`
//! stamp. This module judges a held set of such candidates against the verified history. It is a
//! pure function of its inputs, like [`judge_records`](super::records::judge_records), and the
//! verdict is a function of the set of candidates, never of the order they arrived in.
//!
//! What it decides, from the text of 0.3 §5.1 with 0.5's substitutions:
//!
//! * The header parses as `/5`, carries a stamp whose `account` is this account's 64-hex ID,
//!   whose `slot` is the path's slot, whose `generation` is the signed `clock` and whose
//!   `operationID` is the header's ID; its path is `state/<author>/<namespace>/<slot>.json`;
//!   its signature verifies under the author's member key.
//! * The author is a current member: granted at the cited authority, not revoked, and
//!   **uncaveated** (no `expires`, `writes`, `kinds` or `conditions`): a caveated writer's
//!   live-stamped header is refused (`caveatedLive`: the §19 results have no code for it; this
//!   is the local spelling). A revoked writer's slot supplies no current state.
//! * Authority newer than the replica is quarantined (`authorityBehind`), as is a header whose
//!   epoch key is not held (`unavailable`); neither replaces anything.
//! * The epoch is current at the cited seq (`wrongEpoch`); the decrypted operation matches the
//!   stamp: its kind and payload give this slot (`invalidPayload`).
//! * The 1,024 bound of §11.4 against the highest earlier admitted durable header clock in the
//!   namespace (`clockJump`).
//! * Per `(author, namespace, slot)` the current head is the valid candidate of the highest
//!   generation. Two different bodies at one generation are equivocation: that generation
//!   supplies nothing, the highest lower valid one stays.
//! * A head whose body is also an admitted immutable record (an exact retained copy) is folded
//!   once, as that record.
use super::ids::AccountId;
use super::records::{EpochKeys, HeldRecord, Judgement, Level, OperationHeader, Outcome};
use super::signature::RawEnvelope;
use super::terms::Access;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The most distinct candidate byte strings kept per live path.
pub const MAX_CANDIDATES_PER_PATH: usize = 8;

/// A verified current live head.
#[derive(Clone, Debug)]
pub struct LiveHead {
    /// Its path.
    pub path: String,
    /// Its header body digest.
    pub digest: String,
    /// The author.
    pub author: String,
    /// The namespace.
    pub namespace: String,
    /// The slot name.
    pub slot: String,
    /// The generation (the signed clock).
    pub generation: u64,
    /// The operation ID.
    pub id: String,
    /// The operation kind.
    pub kind: String,
    /// The opened plaintext.
    pub plaintext: Value,
    /// The exact envelope.
    pub bytes: Vec<u8>,
}

/// What became of one candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveVerdict {
    /// The current head of its slot.
    Current,
    /// Valid, but a higher generation is the head.
    Superseded,
    /// Valid, and exactly an admitted immutable record: it folds as that record.
    Retained,
    /// Two different bodies at its generation.
    Equivocation,
    /// Held until authority or a key arrives: `authorityBehind` or `unavailable`.
    Quarantined(&'static str),
    /// Refused, by §19 reason or `caveatedLive`.
    Refused(&'static str),
    /// Not a live record: it did not parse, or its path or binding is wrong.
    Invalid(String),
}

/// The result of [`judge_live`].
#[derive(Clone, Debug, Default)]
pub struct LiveJudgement {
    /// The current heads, by `(namespace, author, slot)`.
    pub heads: Vec<LiveHead>,
    /// One verdict per candidate, in the order given.
    pub verdicts: Vec<(String, LiveVerdict)>,
}

/// `state/<author>/<namespace>/<slot>.json`.
pub fn live_path(author: &str, namespace: &str, slot: &str) -> String {
    format!("state/{author}/{namespace}/{slot}.json")
}

/// The highest admitted durable clock in a namespace before a fold position.
type Earlier<'a> = &'a dyn Fn(&str, (u64, &str, &str)) -> u64;

struct Valid {
    idx: usize,
    head: LiveHead,
}

fn bad(why: &str) -> LiveVerdict {
    LiveVerdict::Invalid(why.to_string())
}

/// Judge one candidate down to a valid head, or a verdict.
fn judge_one(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    account: &AccountId,
    earlier: Earlier<'_>,
    h: &HeldRecord,
    skip_signature: bool,
) -> Result<LiveHead, LiveVerdict> {
    let Ok((hd, env)) = OperationHeader::parse(&h.bytes) else {
        return Err(bad("not a /5 header"));
    };
    let Some(stamp) = hd.live.clone() else {
        return Err(bad("no live stamp"));
    };
    if &hd.account != account || stamp.account != account.as_str() {
        return Err(bad("another account"));
    }
    if h.path != live_path(&hd.author, &hd.namespace, &stamp.slot)
        || stamp.generation != hd.clock
        || stamp.operation_id != hd.id
        || hd.level != Level::Write
        || hd.previous.is_some()
    {
        return Err(bad("stamp, path or header disagree"));
    }
    let Some(member) = auth.member(&hd.author) else {
        return Err(LiveVerdict::Refused("notGranted"));
    };
    if !skip_signature
        && RawEnvelope::parse(
            &h.bytes,
            super::encoding::bounds::OPERATION_HEADER_BODY,
            false,
        )
        .and_then(|e| OperationHeader::verify(&e, &member.request.signing))
        .is_err()
    {
        return Err(bad("bad signature"));
    }
    let _ = env;
    let entry = member
        .terms
        .records()
        .and_then(|r| r.iter().find(|e| e.namespace == hd.namespace));
    let Some(_) = entry.filter(|e| e.access >= Access::Write) else {
        return Err(LiveVerdict::Refused("notGranted"));
    };
    if hd.authority < member.granted_seq {
        return Err(LiveVerdict::Refused("notGranted"));
    }
    if member.revoked_seq.is_some() {
        return Err(LiveVerdict::Refused("revoked"));
    }
    if super::records::live_caveated(member, &hd.namespace) {
        return Err(LiveVerdict::Refused(super::Reason::CaveatedLive.as_str()));
    }
    if hd.authority > auth.authority_seq() || auth.fork_seq().is_some_and(|f| hd.authority >= f) {
        return Err(LiveVerdict::Quarantined("authorityBehind"));
    }
    if auth.epoch_at(&hd.namespace, hd.authority) != Some(hd.epoch) {
        return Err(LiveVerdict::Refused("wrongEpoch"));
    }
    let Some(key) = keys.get(account, &hd.namespace, hd.epoch) else {
        return Err(LiveVerdict::Quarantined("unavailable"));
    };
    let Ok(pt) = key.open(&hd) else {
        return Err(LiveVerdict::Refused("invalidPayload"));
    };
    let kind = pt.get("kind").and_then(Value::as_str).unwrap_or_default();
    let payload = pt.get("payload").cloned().unwrap_or(Value::Null);
    if pt.get("v").and_then(Value::as_u64) != Some(1)
        || crate::protocol::live_slot(&hd.namespace, kind, &payload).as_deref()
            != Some(stamp.slot.as_str())
    {
        return Err(LiveVerdict::Refused("invalidPayload"));
    }
    let before = earlier(&hd.namespace, (hd.clock, &hd.author, &hd.id));
    if hd.clock > before.saturating_add(1_024) {
        return Err(LiveVerdict::Refused("clockJump"));
    }
    Ok(LiveHead {
        path: h.path.clone(),
        digest: hd.digest(),
        author: hd.author.clone(),
        namespace: hd.namespace.clone(),
        slot: stamp.slot,
        generation: hd.clock,
        id: hd.id.clone(),
        kind: kind.to_string(),
        plaintext: pt,
        bytes: h.bytes.clone(),
    })
}

/// Judge `held` live candidates against the verified history `auth`, the epoch `keys` and the
/// judgement of the immutable records (for the clock bound and the retained copies).
pub fn judge_live(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    judgement: &Judgement,
    held: &[HeldRecord],
) -> LiveJudgement {
    judge_live_with(auth, keys, judgement, held, None)
}

/// [`judge_live`], optionally skipping the signature check of the one candidate at `unsigned`
/// (the write side judges its header before the host has signed it).
pub(crate) fn judge_live_with(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    judgement: &Judgement,
    held: &[HeldRecord],
    unsigned: Option<usize>,
) -> LiveJudgement {
    let account = auth.account().clone();
    // The admitted durable headers, by namespace, in fold order.
    let mut admitted: BTreeMap<String, Vec<(u64, String, String)>> = BTreeMap::new();
    let mut retained: BTreeSet<String> = BTreeSet::new();
    for j in &judgement.records {
        if j.outcome == Outcome::Admitted {
            if let (Some(ns), Some(a), Some(id), Some(d)) = (
                j.namespace.clone(),
                j.author.clone(),
                j.id.clone(),
                j.digest.clone(),
            ) {
                admitted.entry(ns).or_default().push((j.clock, a, id));
                retained.insert(d);
            }
        }
    }
    for v in admitted.values_mut() {
        v.sort();
    }
    let earlier = |ns: &str, key: (u64, &str, &str)| -> u64 {
        admitted.get(ns).map_or(0, |v| {
            let at = v.partition_point(|(c, a, i)| (*c, a.as_str(), i.as_str()) < key);
            at.checked_sub(1).map_or(0, |i| v[i].0)
        })
    };
    let mut verdicts: Vec<Option<LiveVerdict>> = vec![None; held.len()];
    let mut valid: Vec<Valid> = Vec::new();
    for (idx, h) in held.iter().enumerate() {
        match judge_one(auth, keys, &account, &earlier, h, unsigned == Some(idx)) {
            Ok(head) => valid.push(Valid { idx, head }),
            Err(v) => verdicts[idx] = Some(v),
        }
    }
    // One body under several envelopes is one object (§2.2): the first of its envelopes in
    // (path, bytes) order is the one used, whatever order the candidates arrived in.
    valid.sort_by(|a, b| {
        (&held[a.idx].path, &held[a.idx].bytes).cmp(&(&held[b.idx].path, &held[b.idx].bytes))
    });
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut kept: Vec<Valid> = Vec::new();
    for v in valid {
        if seen.insert(v.head.digest.clone()) {
            kept.push(v);
        } else {
            verdicts[v.idx] = Some(LiveVerdict::Superseded);
        }
    }
    let valid = kept;
    // Per slot: the highest valid generation that no two bodies share.
    let mut slots: BTreeMap<(String, String, String), Vec<&Valid>> = BTreeMap::new();
    for v in &valid {
        slots
            .entry((
                v.head.namespace.clone(),
                v.head.author.clone(),
                v.head.slot.clone(),
            ))
            .or_default()
            .push(v);
    }
    let mut heads = Vec::new();
    for list in slots.values() {
        let mut gens: BTreeMap<u64, Vec<&Valid>> = BTreeMap::new();
        for v in list {
            gens.entry(v.head.generation).or_default().push(v);
        }
        let mut current: Option<u64> = None;
        for (g, group) in gens.iter().rev() {
            if group.len() > 1 {
                for v in group {
                    verdicts[v.idx] = Some(LiveVerdict::Equivocation);
                }
                continue;
            }
            if current.is_none() {
                current = Some(*g);
                let v = group[0];
                if retained.contains(&v.head.digest) {
                    verdicts[v.idx] = Some(LiveVerdict::Retained);
                } else {
                    verdicts[v.idx] = Some(LiveVerdict::Current);
                    heads.push(v.head.clone());
                }
            } else {
                verdicts[group[0].idx] = Some(LiveVerdict::Superseded);
            }
        }
    }
    heads.sort_by(|a, b| {
        (&a.namespace, &a.author, &a.slot).cmp(&(&b.namespace, &b.author, &b.slot))
    });
    LiveJudgement {
        heads,
        verdicts: held
            .iter()
            .zip(verdicts)
            .map(|(h, v)| (h.path.clone(), v.unwrap_or_else(|| bad("not judged"))))
            .collect(),
    }
}
