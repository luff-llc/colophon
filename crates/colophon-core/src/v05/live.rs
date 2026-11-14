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
    mut cache: Option<&mut super::records::JudgeCache>,
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
    let vk = super::records::verified_key(&h.bytes, &member.request.signing);
    let known = cache.as_ref().is_some_and(|c| c.sig_known(&vk));
    if !skip_signature && !known {
        if RawEnvelope::parse(
            &h.bytes,
            super::encoding::bounds::OPERATION_HEADER_BODY,
            false,
        )
        .and_then(|e| OperationHeader::verify(&e, &member.request.signing))
        .is_err()
        {
            return Err(bad("bad signature"));
        }
        if let Some(c) = cache.as_mut() {
            c.mark_sig(vk);
        }
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
    let body = hd.digest();
    let opened = match cache.as_ref().and_then(|c| c.opened_get(&body)) {
        Some(o) => o,
        None => {
            let o = key.open(&hd).ok();
            if let Some(c) = cache.as_mut() {
                c.opened_put(&body, o.clone());
            }
            o
        }
    };
    let Some(pt) = opened else {
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

/// What the live judgement reads of the judged durable records: the admitted headers of each
/// namespace in fold order (for the 1,024 bound), the digests admitted (an exact retained copy)
/// and the `(author, id)` pairs admitted (`duplicateID`). It is a function of the judgement,
/// built whole by [`DurableIndex::of`] and grown by [`DurableIndex::add`] (the same code), so a
/// derivation that grew record by record holds the index a rebuild gives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DurableIndex {
    admitted: BTreeMap<String, BTreeSet<(u64, String, String)>>,
    retained: BTreeSet<String>,
    ids: BTreeSet<(String, String)>,
}
impl DurableIndex {
    /// The index of a whole judgement.
    pub(crate) fn of(judgement: &Judgement) -> Self {
        let mut x = Self::default();
        for j in &judgement.records {
            x.add(j);
        }
        x
    }
    /// Add one judged record (a record that is not admitted adds nothing).
    pub(crate) fn add(&mut self, j: &super::records::Judged) {
        if j.outcome != Outcome::Admitted {
            return;
        }
        if let (Some(ns), Some(a), Some(id), Some(d)) = (
            j.namespace.as_deref(),
            j.author.as_deref(),
            j.id.as_deref(),
            j.digest.as_deref(),
        ) {
            self.ids.insert((a.to_string(), id.to_string()));
            self.admitted.entry(ns.to_string()).or_default().insert((
                j.clock,
                a.to_string(),
                id.to_string(),
            ));
            self.retained.insert(d.to_string());
        }
    }
    /// The highest admitted durable clock in `ns` at a fold position before `key`.
    fn earlier(&self, ns: &str, key: (u64, &str, &str)) -> u64 {
        self.admitted.get(ns).map_or(0, |v| {
            v.range(..(key.0, key.1.to_string(), key.2.to_string()))
                .next_back()
                .map_or(0, |k| k.0)
        })
    }
    /// The highest admitted durable clock in `ns` (0 if none).
    pub(crate) fn highest(&self, ns: &str) -> u64 {
        self.admitted
            .get(ns)
            .and_then(|v| v.iter().next_back())
            .map_or(0, |k| k.0)
    }
    /// Whether `digest` is an admitted durable header.
    pub(crate) fn retains(&self, digest: &str) -> bool {
        self.retained.contains(digest)
    }
    /// Whether `(author, id)` is an admitted durable operation.
    pub(crate) fn has_id(&self, author: &str, id: &str) -> bool {
        self.ids.contains(&(author.to_string(), id.to_string()))
    }
}

/// What the live index keeps of one held candidate that parsed as a header: enough to find the
/// slots a new durable record can change, without parsing the candidates again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandMeta {
    pub digest: String,
    pub author: String,
    pub id: String,
    pub clock: u64,
    pub epoch: u64,
    pub nonce: Vec<u8>,
}

/// The result of judging the candidates held at one path.
pub(crate) struct GroupJudgement {
    /// One verdict per candidate, in the order given.
    pub verdicts: Vec<LiveVerdict>,
    /// The current head of the slot, when there is one.
    pub head: Option<LiveHead>,
    /// What each candidate that parsed names.
    pub metas: Vec<Option<CandMeta>>,
}

/// Judge the candidates held at one path (they are one slot's, or none): the verdict of a
/// candidate reads only its own slot's candidates, the verified history, the keys and the
/// durable index, so [`judge_live_with`] is this over every path, and a change to one slot
/// judges that slot alone.
pub(crate) fn judge_group(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    durable: &DurableIndex,
    held: &[HeldRecord],
    unsigned: Option<usize>,
    mut cache: Option<&mut super::records::JudgeCache>,
) -> GroupJudgement {
    let account = auth.account().clone();
    let earlier = |ns: &str, key: (u64, &str, &str)| durable.earlier(ns, key);
    let mut verdicts: Vec<Option<LiveVerdict>> = vec![None; held.len()];
    let mut metas: Vec<Option<CandMeta>> = vec![None; held.len()];
    let mut valid: Vec<Valid> = Vec::new();
    for (idx, h) in held.iter().enumerate() {
        if let Ok((hd, _)) = OperationHeader::parse(&h.bytes) {
            metas[idx] = Some(CandMeta {
                digest: hd.digest(),
                author: hd.author.clone(),
                id: hd.id.clone(),
                clock: hd.clock,
                epoch: hd.epoch,
                nonce: hd.nonce.clone(),
            });
        }
        match judge_one(
            auth,
            keys,
            &account,
            &earlier,
            h,
            unsigned == Some(idx),
            cache.as_deref_mut(),
        ) {
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
    // Per slot: the highest valid generation that no two bodies share.
    let mut slots: BTreeMap<(String, String, String), Vec<&Valid>> = BTreeMap::new();
    for v in &kept {
        slots
            .entry((
                v.head.namespace.clone(),
                v.head.author.clone(),
                v.head.slot.clone(),
            ))
            .or_default()
            .push(v);
    }
    let mut head_out: Option<LiveHead> = None;
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
                if durable.retains(v.head.digest.as_str()) {
                    verdicts[v.idx] = Some(LiveVerdict::Retained);
                } else if durable.has_id(v.head.author.as_str(), v.head.id.as_str()) {
                    // One author, one operation ID: a live head and an immutable record that
                    // share it do not both fold (0.3 §5: `duplicateID`).
                    verdicts[v.idx] = Some(LiveVerdict::Refused("duplicateID"));
                } else {
                    verdicts[v.idx] = Some(LiveVerdict::Current);
                    // Held at one path means one slot; a second slot at a path cannot be
                    // valid (the path names the slot), so there is at most one head.
                    head_out = Some(v.head.clone());
                }
            } else {
                verdicts[group[0].idx] = Some(LiveVerdict::Superseded);
            }
        }
    }
    GroupJudgement {
        verdicts: verdicts
            .into_iter()
            .map(|v| v.unwrap_or_else(|| bad("not judged")))
            .collect(),
        head: head_out,
        metas,
    }
}

/// Judge `held` live candidates against the verified history `auth`, the epoch `keys` and the
/// judgement of the immutable records (for the clock bound and the retained copies).
pub fn judge_live(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    judgement: &Judgement,
    held: &[HeldRecord],
) -> LiveJudgement {
    judge_live_with(auth, keys, judgement, held, None, None)
}

/// [`judge_live`], optionally skipping the signature check of the one candidate at `unsigned`
/// (the write side judges its header before the host has signed it).
pub(crate) fn judge_live_with(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    judgement: &Judgement,
    held: &[HeldRecord],
    unsigned: Option<usize>,
    cache: Option<&mut super::records::JudgeCache>,
) -> LiveJudgement {
    judge_live_indexed(
        auth,
        keys,
        &DurableIndex::of(judgement),
        held,
        unsigned,
        cache,
    )
    .0
}

/// The judgement of every held live candidate over a durable index, and what each candidate
/// that parsed names (aligned with `held`).
pub(crate) fn judge_live_indexed(
    auth: &super::records::RecordAuthority,
    keys: &EpochKeys,
    durable: &DurableIndex,
    held: &[HeldRecord],
    unsigned: Option<usize>,
    mut cache: Option<&mut super::records::JudgeCache>,
) -> (LiveJudgement, Vec<Option<CandMeta>>) {
    // No candidate: no verdict and no head.
    if held.is_empty() {
        return (LiveJudgement::default(), Vec::new());
    }
    // Group by held path (each group is a run in path order, whatever the order given).
    let mut by_path: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, h) in held.iter().enumerate() {
        by_path.entry(h.path.as_str()).or_default().push(i);
    }
    let mut verdicts: Vec<Option<LiveVerdict>> = vec![None; held.len()];
    let mut metas: Vec<Option<CandMeta>> = vec![None; held.len()];
    let mut heads = Vec::new();
    for idxs in by_path.values() {
        let group: Vec<HeldRecord> = idxs.iter().map(|i| held[*i].clone()).collect();
        let at = unsigned.and_then(|u| idxs.iter().position(|i| *i == u));
        let g = judge_group(auth, keys, durable, &group, at, cache.as_deref_mut());
        for ((i, v), m) in idxs.iter().zip(g.verdicts).zip(g.metas) {
            verdicts[*i] = Some(v);
            metas[*i] = m;
        }
        heads.extend(g.head);
    }
    sort_heads(&mut heads);
    (
        LiveJudgement {
            heads,
            verdicts: held
                .iter()
                .zip(verdicts)
                .map(|(h, v)| (h.path.clone(), v.unwrap_or_else(|| bad("not judged"))))
                .collect(),
        },
        metas,
    )
}

/// The order the heads are kept in: `(namespace, author, slot)`.
pub(crate) fn sort_heads(heads: &mut [LiveHead]) {
    heads.sort_by(|a, b| {
        (&a.namespace, &a.author, &a.slot).cmp(&(&b.namespace, &b.author, &b.slot))
    });
}

/// What the live judgement keeps of the candidates held, by path, to find which slots a new
/// durable record can change: a record that is exactly a candidate's body (a retained copy), one
/// that shares a candidate's `(author, id)` (`duplicateID`), or, for any record, a slot whose
/// candidate was refused as `clockJump` (the bound reads the highest earlier admitted clock,
/// which only a new record can raise). A function of the candidates and their verdicts, built
/// whole by [`LiveIndex::of`] and kept in step by [`LiveIndex::set_group`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LiveIndex {
    groups: BTreeMap<String, (Vec<CandMeta>, bool)>,
    by_digest: BTreeMap<String, BTreeSet<String>>,
    by_id: BTreeMap<(String, String), BTreeSet<String>>,
    by_nonce: BTreeMap<(u64, Vec<u8>), BTreeSet<String>>,
    jumped: BTreeSet<String>,
}
impl LiveIndex {
    /// The index of a whole judgement (`held` and `metas` are aligned with its verdicts).
    pub(crate) fn of(held: &[HeldRecord], metas: &[Option<CandMeta>], j: &LiveJudgement) -> Self {
        let mut by_path: BTreeMap<&str, (Vec<CandMeta>, bool)> = BTreeMap::new();
        for ((h, m), (_, v)) in held.iter().zip(metas).zip(&j.verdicts) {
            let e = by_path.entry(h.path.as_str()).or_default();
            if let Some(m) = m {
                e.0.push(m.clone());
            }
            e.1 |= matches!(v, LiveVerdict::Refused("clockJump"));
        }
        let mut x = Self::default();
        for (p, (metas, jumped)) in by_path {
            x.set_group(p, metas, jumped);
        }
        x
    }
    /// Replace what is known of the candidates at `path` (none: the group is forgotten).
    pub(crate) fn set_group(&mut self, path: &str, metas: Vec<CandMeta>, jumped: bool) {
        if let Some((old, _)) = self.groups.remove(path) {
            for m in old {
                if let Some(s) = self.by_digest.get_mut(&m.digest) {
                    s.remove(path);
                    if s.is_empty() {
                        self.by_digest.remove(&m.digest);
                    }
                }
                let k = (m.author, m.id);
                if let Some(s) = self.by_id.get_mut(&k) {
                    s.remove(path);
                    if s.is_empty() {
                        self.by_id.remove(&k);
                    }
                }
                let n = (m.epoch, m.nonce);
                if let Some(s) = self.by_nonce.get_mut(&n) {
                    s.remove(path);
                    if s.is_empty() {
                        self.by_nonce.remove(&n);
                    }
                }
            }
        }
        self.jumped.remove(path);
        if metas.is_empty() && !jumped {
            return;
        }
        for m in &metas {
            self.by_digest
                .entry(m.digest.clone())
                .or_default()
                .insert(path.to_string());
            self.by_id
                .entry((m.author.clone(), m.id.clone()))
                .or_default()
                .insert(path.to_string());
            self.by_nonce
                .entry((m.epoch, m.nonce.clone()))
                .or_default()
                .insert(path.to_string());
        }
        if jumped {
            self.jumped.insert(path.to_string());
        }
        self.groups.insert(path.to_string(), (metas, jumped));
    }
    /// The highest generation among the candidates held at `path` that parse as headers (0 if
    /// none).
    pub(crate) fn floor(&self, path: &str) -> u64 {
        self.groups
            .get(path)
            .map_or(0, |(m, _)| m.iter().map(|c| c.clock).max().unwrap_or(0))
    }
    /// Whether a candidate held names this epoch and nonce.
    pub(crate) fn has_nonce(&self, epoch: u64, nonce: &[u8]) -> bool {
        self.by_nonce.contains_key(&(epoch, nonce.to_vec()))
    }
    /// The paths whose verdicts a newly admitted durable record can change.
    pub(crate) fn affected_by(&self, j: &super::records::Judged, out: &mut BTreeSet<String>) {
        if j.outcome != Outcome::Admitted {
            return;
        }
        if let Some(d) = j.digest.as_deref() {
            if let Some(s) = self.by_digest.get(d) {
                out.extend(s.iter().cloned());
            }
        }
        if let (Some(a), Some(id)) = (j.author.as_deref(), j.id.as_deref()) {
            if let Some(s) = self.by_id.get(&(a.to_string(), id.to_string())) {
                out.extend(s.iter().cloned());
            }
        }
        out.extend(self.jumped.iter().cloned());
    }
}

/// What a path's candidates keep after the merge rule: no candidate that is no live record at
/// all, every candidate that is the head, in equivocation, retained, refused or quarantined, and
/// of the superseded ones the two highest generations. `group` is in `(path, bytes)` order and
/// `g` is its judgement. A function of the group, so a set pruned all at once and pruned by
/// path is the same.
pub(crate) fn prune_group(group: &[HeldRecord], g: &GroupJudgement) -> Vec<HeldRecord> {
    let mut keep: Vec<usize> = Vec::new();
    let mut superseded: Vec<(u64, usize)> = Vec::new();
    for (i, (c, v)) in group.iter().zip(&g.verdicts).enumerate() {
        match v {
            LiveVerdict::Invalid(_) => {}
            LiveVerdict::Superseded => {
                let gen = OperationHeader::parse(&c.bytes).map_or(0, |(h, _)| h.clock);
                superseded.push((gen, i));
            }
            _ => keep.push(i),
        }
    }
    superseded.sort_by(|a, b| b.cmp(a));
    keep.extend(superseded.iter().take(2).map(|(_, i)| *i));
    keep.sort_unstable();
    keep.into_iter().map(|i| group[i].clone()).collect()
}
