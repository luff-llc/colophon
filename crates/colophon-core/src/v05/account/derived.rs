//! Everything an account derives from its held objects: the verdict, the record-layer view,
//! the epoch keys it can open, the judgement of every held record and the namespace folds.
//!
//! A [`Derived`] is a pure function of its inputs ([`Inputs`]) and of the epoch keys already
//! opened (a key that came from a host's ECDH cannot be recomputed, so it is carried over; a
//! key is a fact about one account, namespace and epoch and never changes). The account builds
//! a candidate `Derived` from candidate inputs and replaces its own only when the build
//! succeeds, so a failed merge or finish leaves no partial change.
use super::unlock::SeedRing;
use super::Identity;
use crate::domain::AuthorContext;
use crate::engine::{CheckpointPolicy, Namespace};
use crate::model::{Grant, MemberKind as ModelKind, OperationView};
use crate::v05::encoding::digest;
use crate::v05::history::envelope::AuthEnvelope;
use crate::v05::history::{verify_history, MemberRecord, Objects, Persisted, Verdict};
use crate::v05::members::MemberKind;
use crate::v05::records::{
    judge_cached, EpochKeys, HeldRecord, JudgeCache, Judgement, Level, Outcome, ProposalState,
    RecordAuthority,
};
use crate::v05::terms::Access;
use crate::v05::{malformed, Failure, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// Operations between the fold snapshots kept along each namespace (see [`SNAPSHOTS_KEPT`]).
/// A record that lands at position `p` takes the namespace back to the snapshot at or before
/// `p`, so the work is the distance to it (under this many operations) plus what follows `p`.
pub(super) const SNAPSHOT_EVERY_DEFAULT: usize = 256;
static SNAPSHOT_EVERY_NOW: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(SNAPSHOT_EVERY_DEFAULT);
/// The interval in force.
pub(super) fn snapshot_every() -> usize {
    SNAPSHOT_EVERY_NOW.load(std::sync::atomic::Ordering::Relaxed)
}
/// Change the interval, process-wide (tests set a small one so a short journey rewinds to a
/// snapshot; 0 puts it back to the default). It changes no verdict: snapshots are a cache.
#[doc(hidden)]
pub fn set_fold_snapshot_interval(n: usize) {
    SNAPSHOT_EVERY_NOW.store(
        if n == 0 { SNAPSHOT_EVERY_DEFAULT } else { n },
        std::sync::atomic::Ordering::Relaxed,
    );
}
/// The snapshots kept per namespace: the last ones, covering the most recent
/// `SNAPSHOT_EVERY * SNAPSHOTS_KEPT` operations. A record that lands before the oldest takes
/// the fold back to nothing, which is the cost of a cold fold.
pub(super) const SNAPSHOTS_KEPT: usize = 2;

/// What a [`Derived`] is built from.
pub(super) struct Inputs<'a> {
    pub objects: &'a Objects,
    pub records: &'a [HeldRecord],
    pub live: &'a [HeldRecord],
    pub persisted: &'a Persisted,
    pub now_ms: i64,
    pub seeds: &'a SeedRing,
    pub me: &'a Identity,
    pub scope: &'a Option<BTreeSet<String>>,
    /// Namespace folds a sealed checkpoint carried: `(print in hex, fold)`. Used only when the
    /// print and the operations folded match.
    pub fold_seed: &'a BTreeMap<String, (String, Folded)>,
}

/// One admitted record on its way into a fold: its position `(clock, author, id, digest)`, its
/// view, its author's kind and its header digest.
type FoldItem = (
    (u64, String, String, String),
    OperationView,
    MemberKind,
    String,
);

/// One namespace's fold, of the durable records only: live heads are an overlay answered at
/// read time (see [`Derived::overlaid`]), so a live write never touches this.
#[derive(Clone)]
pub(super) struct Folded {
    pub revision: u64,
    pub fold: Namespace,
    pub admitted: Vec<OperationView>,
    /// The fold position `(clock, author, id, digest)` of each operation folded, parallel to
    /// `fold.order`. A fold taken from a checkpoint is given its positions when the derivation
    /// matches it to the judgement.
    pub keys: Vec<(u64, String, String, String)>,
}

/// The heads of one namespace: their fold positions in order, and an additive hash of their
/// digests (a set hash: a head added or taken away changes it by one term, whatever the order
/// the heads arrived in).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct HeadSet {
    pub keys: BTreeSet<(u64, String, String, String)>,
    acc: [u64; 4],
}
impl HeadSet {
    fn term(digest: &str) -> [u64; 4] {
        use sha2::{Digest, Sha256};
        let h: [u8; 32] = Sha256::digest(digest.as_bytes()).into();
        let mut t = [0u64; 4];
        for (i, c) in h.chunks_exact(8).enumerate() {
            let mut e = [0u8; 8];
            e.copy_from_slice(c);
            t[i] = u64::from_le_bytes(e);
        }
        t
    }
    fn insert(&mut self, k: (u64, String, String, String)) {
        let t = Self::term(&k.3);
        if self.keys.insert(k) {
            for i in 0..4 {
                self.acc[i] = self.acc[i].wrapping_add(t[i]);
            }
        }
    }
    fn remove(&mut self, k: &(u64, String, String, String)) {
        let t = Self::term(&k.3);
        if self.keys.remove(k) {
            for i in 0..4 {
                self.acc[i] = self.acc[i].wrapping_sub(t[i]);
            }
        }
    }
}

/// The overlaid namespaces answered so far, by namespace, with the merged-chain key each was made for.
pub(super) type OverlayCache = BTreeMap<String, ([u8; 32], Arc<Overlaid>)>;

/// A namespace as readers see it when live heads are held: the durable fold with the heads
/// applied at their positions (what folding durable records and heads together gives).
pub(super) struct Overlaid {
    pub fold: Namespace,
    /// The operations from position `split` on, in merged order: durable ones after the first
    /// head and the heads. The operations before `split` are the durable fold's.
    pub admitted: Vec<OperationView>,
    pub split: usize,
    pub revision: u64,
}

pub(super) struct Derived {
    /// The pending transitions and vetoes among `effective` that verify against the state.
    pub verified_pending: BTreeSet<Vec<u8>>,
    /// The held objects with one envelope per pending transition and veto body: several
    /// envelopes over one body are one object (§2.2), and the one used is the first in byte
    /// order that verifies, so a keyless envelope over a real body changes nothing.
    pub effective: Objects,
    pub verdict: Verdict,
    pub auth: RecordAuthority,
    pub keys: EpochKeys,
    pub judgement: Judgement,
    pub windex: WriteIndex,
    /// What the live judgement reads of the judged durable records.
    pub durable: crate::v05::live::DurableIndex,
    /// The judgement of the live-state candidates held (0.3 §5.1).
    pub live: crate::v05::live::LiveJudgement,
    /// The positions `(generation, author, id, digest)` of the heads, by namespace, in fold
    /// order: what the change token and the overlay merge the durable fold with.
    pub head_order: BTreeMap<String, HeadSet>,
    /// The live paths the latest extension judged again.
    pub touched_live: BTreeSet<String>,
    /// Which slots a new durable record can change.
    pub live_idx: crate::v05::live::LiveIndex,
    /// The overlaid namespaces answered so far, by namespace: the merged-chain key they were
    /// made for and the result. Only ever an answer that is a function of the key.
    pub overlays: Mutex<OverlayCache>,
    pub folded: BTreeMap<String, Folded>,
    /// What the judgement read from the verified state that its branch does not fix.
    pub print: [u8; 32],
    /// Memory of the judgement of the held records, shared by the successive derivations of
    /// one account. It only ever remembers answers that are functions of their inputs, and a
    /// derivation uses it only for the inputs it was made under, so sharing it is safe.
    pub cache: Arc<Mutex<JudgeCache>>,
    /// Operations applied to a namespace fold by the latest build (the rest were reused).
    pub fold_applied: u64,
}

/// What a write needs of the judged records, found once per derivation so that preparing and
/// finishing one operation does not pass over the held records (§11.2, §11.4, §11.5).
#[derive(Default, Debug)]
pub(super) struct WriteIndex {
    /// Highest clock among records that reserved a slot, by namespace.
    pub highest: BTreeMap<String, u64>,
    /// Distinct `(author, id)` pairs that reserved a budget slot, by author.
    pub reserved: BTreeMap<String, u64>,
    /// Maximal heads of each author's `/5` chain in a namespace (live-stamped copies and
    /// headers that were never records are outside it).
    pub tips: BTreeMap<(String, String), Vec<String>>,
    /// `(namespace, epoch, nonce)` of every held header: a nonce is never used twice under a key.
    pub nonces: BTreeSet<(String, u64, Vec<u8>)>,
    /// `(author, namespace, previous)` named by a verified header of that author: what makes a
    /// header no tip. Kept so that a merge adds to the index without passing over the records.
    named: BTreeSet<(String, String, String)>,
    /// The `(author, id)` pairs counted in `reserved`.
    reserved_ids: BTreeSet<(String, String)>,
}
impl WriteIndex {
    /// The index of `j`. An author's chain tip is computed from that author's own headers
    /// only, and only from headers whose signature a member of the verified history made
    /// (the rule of [`crate::v05::records::chain_heads`], which the slow path uses): a keyless
    /// header, and a header by an author the history does not know, name no tip (§11.2).
    fn of(j: &Judgement, auth: &RecordAuthority) -> Self {
        let mut w = Self::default();
        w.add(j.records.iter(), auth);
        w
    }

    /// Add judged records to the index: the same code builds the whole index and extends it, so
    /// an extended index is the one a rebuild gives.
    fn add<'a>(
        &mut self,
        records: impl Iterator<Item = &'a crate::v05::records::Judged>,
        auth: &RecordAuthority,
    ) {
        use crate::v05::records::HeaderFormat;
        for r in records {
            let (Some(ns), Some(a)) = (r.namespace.as_deref(), r.author.as_deref()) else {
                continue;
            };
            self.nonces
                .insert((ns.to_string(), r.epoch, r.nonce.clone()));
            if r.reserved {
                let h = self.highest.entry(ns.to_string()).or_default();
                *h = (*h).max(r.clock);
                if let Some(id) = r.id.as_deref() {
                    if self.reserved_ids.insert((a.to_string(), id.to_string())) {
                        *self.reserved.entry(a.to_string()).or_default() += 1;
                    }
                }
            }
            let signed = !matches!(r.outcome, Outcome::Invalid(_)) && auth.member(a).is_some();
            if !(signed && r.format == Some(HeaderFormat::V5) && !r.live) {
                continue;
            }
            let Some(d) = r.digest.as_ref() else {
                continue;
            };
            if let Some(p) = r.previous.as_deref() {
                self.named
                    .insert((a.to_string(), ns.to_string(), p.to_string()));
                // What this header names is no tip, whichever arrived first.
                if let Some(tips) = self.tips.get_mut(&(a.to_string(), ns.to_string())) {
                    tips.retain(|t| t != p);
                }
            }
            if !self
                .named
                .contains(&(a.to_string(), ns.to_string(), d.clone()))
            {
                let tips = self
                    .tips
                    .entry((a.to_string(), ns.to_string()))
                    .or_default();
                if !tips.contains(d) {
                    tips.push(d.clone());
                    tips.sort();
                }
            }
        }
    }
}

/// A hash of everything the judgement of records reads from the verified state besides the
/// branch's own entries: the fork and upgrade seqs and every member with its terms, expiry,
/// revocation and provisional standing.
fn auth_print(verdict: &crate::v05::history::Verdict, auth: &RecordAuthority) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for d in &verdict.branch {
        h.update(d.as_bytes());
        h.update(b"\n");
    }
    h.update(
        format!(
            "fork:{:?};upgrade:{:?};",
            auth.fork_seq(),
            auth.upgrade_seq()
        )
        .as_bytes(),
    );
    let members = auth.state().members();
    match serde_json::to_vec(members) {
        Ok(b) => h.update(b),
        Err(_) => h.update(format!("{members:?}").as_bytes()),
    }
    h.finalize().into()
}

/// The body digest of a held authority entry, `/5` or the 0.4 prefix of an upgraded account.
pub(super) fn entry_digest(bytes: &[u8]) -> Option<String> {
    use crate::v05::encoding::bounds;
    if let Ok(e) = AuthEnvelope::parse(
        bytes,
        bounds::AUTHORITY_BODY,
        bounds::AUTHORITY_BODY.saturating_mul(2),
        false,
    ) {
        return Some(e.digest);
    }
    let env = crate::keys::AuthorityEnvelope::from_json(bytes).ok()?;
    Some(digest(&env.body))
}

pub(super) fn model_kind(k: &MemberKind) -> ModelKind {
    match k {
        MemberKind::Device => ModelKind::Device,
        MemberKind::App => ModelKind::App,
        MemberKind::Agent => ModelKind::Agent,
        MemberKind::Server | MemberKind::Unknown(_) => ModelKind::Server,
    }
}

/// The 0.4-shaped grant a domain module sees: the member's `records` entries as namespaces
/// and read and write access (§11.8: "a grant's namespaces and access read its `records`
/// entries"), and whether the terms contain `import`.
pub(super) fn grant_of(m: &MemberRecord) -> Grant {
    let entries = m.terms.records().unwrap_or_default();
    let mut namespaces: Vec<String> = entries.iter().map(|e| e.namespace.clone()).collect();
    namespaces.sort();
    namespaces.dedup();
    let mut access = vec![crate::model::Access::Read];
    if entries.iter().any(|e| e.access >= Access::Write) {
        access.push(crate::model::Access::Write);
    }
    Grant {
        namespaces,
        access,
        expires: m.expires_ms.map(crate::v05::write::format_date),
        write_budget: m.terms.writes(),
        import: m.terms.import().then_some(true),
    }
}

/// The parts of a derivation that read the clock: the verified history and what is made of it.
pub(super) struct Retimed {
    pub verdict: Verdict,
    pub auth: RecordAuthority,
    pub effective: Objects,
    pub verified_pending: BTreeSet<Vec<u8>>,
}
impl Derived {
    /// The history verified at `inputs.now_ms`, when it leaves everything the record layer was
    /// derived from as `prior` has it: the same branch and the same `print` (members and their
    /// terms, expiries, revocations, standing, fork and upgrade seqs). The epoch keys follow
    /// from the branch and the seeds, so they are the same too. `None` otherwise.
    pub(super) fn retimed(inputs: &Inputs<'_>, prior: &Derived) -> Option<Retimed> {
        let verdict = verify_history(inputs.objects, inputs.persisted, inputs.now_ms);
        let state = verdict.state.as_ref()?;
        if verdict.branch != prior.verdict.branch || state.history().len() != verdict.branch.len() {
            return None;
        }
        let auth = RecordAuthority::from_verdict(inputs.objects, verdict.clone()).ok()?;
        if auth_print(&verdict, &auth) != prior.print {
            return None;
        }
        let (effective, verified_pending) = effective_objects(inputs.objects, auth.state());
        Some(Retimed {
            verdict,
            auth,
            effective,
            verified_pending,
        })
    }
}

impl Derived {
    pub(super) fn build(
        inputs: &Inputs<'_>,
        prior: Option<&Derived>,
        extra: Option<&EpochKeys>,
    ) -> Result<Self> {
        let verdict = verify_history(inputs.objects, inputs.persisted, inputs.now_ms);
        let Some(state) = verdict.state.as_ref() else {
            return Err(match &verdict.stop {
                Some(crate::v05::history::Stop::Failed { failure, .. }) => failure.clone(),
                _ => Failure::Unavailable("the held objects hold no verified genesis".into()),
            });
        };
        // A folded state taken from stored bytes names only entries this account holds.
        let held: BTreeSet<String> = inputs
            .objects
            .entries
            .iter()
            .filter_map(|b| entry_digest(b))
            .collect();
        if !verdict.branch.iter().all(|d| held.contains(d)) {
            return Err(malformed(
                "the stored verifier state names entries the account does not hold",
            ));
        }
        if state.history().len() != verdict.branch.len() {
            return Err(malformed("the folded state and its branch disagree"));
        }
        let auth = RecordAuthority::from_verdict(inputs.objects, verdict.clone())?;
        let account = auth.account().clone();
        // Epoch keys: carried over, then every missing one a seed opens.
        let mut keys = EpochKeys::new();
        for ns in auth.namespaces() {
            for epoch in 1..=auth.latest_epoch(ns) {
                let have = extra
                    .and_then(|x| x.get(&account, ns, epoch))
                    .or_else(|| prior.and_then(|p| p.keys.get(&account, ns, epoch)))
                    .cloned();
                if let Some(k) = have {
                    keys.insert(k)?;
                    continue;
                }
                if !readable(&auth, inputs.me, ns) {
                    continue;
                }
                for seed in inputs.seeds.iter() {
                    if let Ok(k) = auth.open_epoch_with_seed(seed, ns, epoch) {
                        keys.insert(k)?;
                        break;
                    }
                }
            }
        }
        let cache = prior.map_or_else(Default::default, |p| p.cache.clone());
        let print = auth_print(&verdict, &auth);
        let judgement = {
            let mut c = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            judge_cached(&auth, &keys, inputs.records, &mut c, print)
        };
        let durable = crate::v05::live::DurableIndex::of(&judgement);
        let (live, live_idx) = {
            let mut c = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (j, metas) = crate::v05::live::judge_live_indexed(
                &auth,
                &keys,
                &durable,
                inputs.live,
                None,
                Some(&mut c),
            );
            let idx = crate::v05::live::LiveIndex::of(inputs.live, &metas, &j);
            (j, idx)
        };
        let (effective, verified_pending) = effective_objects(inputs.objects, auth.state());
        let windex = WriteIndex::of(&judgement, &auth);
        let head_order = Self::head_order_of(&live);
        let mut derived = Self {
            effective,
            verified_pending,
            verdict,
            auth,
            keys,
            windex,
            judgement,
            durable,
            head_order,
            touched_live: BTreeSet::new(),
            live,
            live_idx,
            overlays: Mutex::new(BTreeMap::new()),
            folded: BTreeMap::new(),
            print,
            cache,
            fold_applied: 0,
        };
        derived.fold(inputs, prior.map(|p| (&p.folded, p.print)));
        Ok(derived)
    }

    /// The fold item of one judged record: its position, its view, its author's kind and its
    /// header digest; `None` for a record that does not fold (not admitted, not authenticated,
    /// an unknown payload version, a resolution, or a proposal not accepted). The same code
    /// serves the whole fold and the extension of one.
    fn fold_item(
        &self,
        j: &crate::v05::records::Judged,
        accepted: &BTreeMap<(String, String), (u64, String, String)>,
    ) -> Option<FoldItem> {
        if j.outcome != Outcome::Admitted {
            return None;
        }
        let (Some(plain), Some(author), Some(id), Some(dg), Some(ns)) = (
            j.plaintext.as_ref(),
            j.author.as_ref(),
            j.id.as_ref(),
            j.digest.as_ref(),
            j.namespace.as_ref(),
        ) else {
            return None;
        };
        if !j.folded {
            return None;
        }
        let kind = plain
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind == "colophon.accept" || kind == "colophon.decline" {
            return None;
        }
        // A proposal folds once, at its accept's position (§11.6), and never before.
        let position = match j.level {
            Some(Level::Propose) => match accepted.get(&(ns.clone(), id.clone())) {
                Some((c, a, i)) => (*c, a.clone(), i.clone(), dg.clone()),
                None => return None,
            },
            _ => (j.clock, author.clone(), id.clone(), dg.clone()),
        };
        let member = self.auth.member(author);
        let (mk, label) = member.map_or((MemberKind::Device, String::new()), |m| {
            (m.request.kind.clone(), m.request.label.clone())
        });
        Some((
            position,
            OperationView {
                id: id.clone(),
                kind: kind.to_string(),
                author: author.clone(),
                author_label: label,
                origin: if mk == MemberKind::Agent {
                    "ai"
                } else {
                    "person"
                }
                .into(),
                clock: plain
                    .get("clock")
                    .and_then(Value::as_u64)
                    .unwrap_or(j.clock),
                created: plain
                    .get("created")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                payload: plain.get("payload").cloned().unwrap_or(Value::Null),
            },
            mk,
            dg.clone(),
        ))
    }

    fn accepted_proposals(&self) -> BTreeMap<(String, String), (u64, String, String)> {
        self.judgement
            .proposals
            .iter()
            .filter_map(|p| match &p.state {
                ProposalState::Accepted { at, .. } => {
                    Some(((p.namespace.clone(), p.id.clone()), at.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// The change token of a fold: a function of the folded operations and their order.
    fn revision_of(fold: &Namespace) -> u64 {
        if fold.order.is_empty() {
            return 0;
        }
        let h = fold.hashes.last().copied().unwrap_or([0; 32]);
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&h[..8]);
        u64::from_be_bytes(eight) & crate::v05::encoding::bounds::MAX_INTEGER
    }

    /// Extend this derivation, in place, by the records now held at `new_at` of `inputs.records`
    /// (ascending positions in the grown set), the authority objects, the clock, the keys and
    /// the scope being what they were. Work is proportional to the new records. It returns
    /// `false`, with nothing changed, when it cannot promise the result a rebuild gives; the
    /// caller then rebuilds. A derivation made this way equals the rebuilt one (`tests/
    /// v05_account_engine.rs` compares them after every step of random journeys).
    pub(super) fn extend(
        &mut self,
        inputs: &Inputs<'_>,
        fresh: &[(usize, &HeldRecord)],
        total: usize,
    ) -> bool {
        let new_at: Vec<usize> = fresh.iter().map(|(at, _)| *at).collect();
        let cache_handle = self.cache.clone();
        let mut cache = cache_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(ext) = crate::v05::records::judge_extend(
            &self.auth,
            &self.keys,
            &mut cache,
            self.print,
            &mut self.judgement,
            fresh,
            total,
        ) else {
            return false;
        };
        // The fold needs the new records' items before anything else is touched.
        let accepted = self.accepted_proposals();
        let mut by_ns: BTreeMap<String, Vec<FoldItem>> = BTreeMap::new();
        let mut full_fold = ext.proposals_refolded;
        for &at in &new_at {
            let Some(j) = self.judgement.records.get(at) else {
                continue;
            };
            if let (Some(item), Some(ns)) = (self.fold_item(j, &accepted), j.namespace.as_ref()) {
                by_ns.entry(ns.clone()).or_default().push(item);
            }
        }
        // The write index, from the new judgements.
        let news: Vec<&crate::v05::records::Judged> = new_at
            .iter()
            .filter_map(|at| self.judgement.records.get(*at))
            .collect();
        // What the live judgement reads of the durable records, and the live slots a new one
        // can change: each of those is judged again, no other.
        let mut affected: BTreeSet<String> = BTreeSet::new();
        for j in &news {
            self.durable.add(j);
            self.live_idx.affected_by(j, &mut affected);
        }
        self.windex.add(news.into_iter(), &self.auth);
        if !affected.is_empty() {
            self.rejudge_live(inputs.live, &affected, &mut cache);
        }
        self.touched_live = affected;
        drop(cache);
        self.fold_applied = 0;
        // Each namespace's fold takes the new operations after its last; operations that land
        // before it take the namespace back to a snapshot and fold from there.
        let mut late: BTreeSet<String> = BTreeSet::new();
        if !full_fold {
            for (ns, items) in &mut by_ns {
                items.sort_by(|a, b| a.0.cmp(&b.0));
                let Some(f) = self.folded.get_mut(ns) else {
                    // Not folded here (unreadable, out of scope, no key): nothing to extend.
                    continue;
                };
                match f.keys.last() {
                    Some(last) => {
                        if items.first().is_some_and(|i| i.0 <= *last) {
                            late.insert(ns.clone());
                        }
                    }
                    // An empty fold with a checkpoint's snapshot to reuse: the full path takes it.
                    None => {
                        if !(f.fold.order.is_empty() && !inputs.fold_seed.contains_key(ns)) {
                            full_fold = true;
                            break;
                        }
                    }
                }
            }
        }
        if full_fold {
            let old = std::mem::take(&mut self.folded);
            self.fold(inputs, Some((&old, self.print)));
            return true;
        }
        let account = self.auth.account().clone();
        let library = account.as_str().chars().take(32).collect::<String>();
        let policy_normal = CheckpointPolicy {
            every: snapshot_every(),
            retain: SNAPSHOTS_KEPT,
        };
        for (ns, items) in by_ns {
            let mut policy = policy_normal.clone();
            let is_late = late.contains(&ns);
            let Some(f) = self.folded.get_mut(&ns) else {
                continue;
            };
            let mut applied = 0u64;
            let mut items = items;
            if is_late {
                // Back to the snapshot at or before the first of them, then every operation
                // from there on, the new ones among them, in fold order. (Operations after the
                // insertion keep their verdicts: `judge_extend` decided that.)
                let first = items[0].0.clone();
                let p = f.keys.partition_point(|k| *k < first);
                f.fold.checkpoints.retain(|s| {
                    s.position <= p && f.fold.hashes.get(s.position) == Some(&s.digest)
                });
                // The snapshot is taken, not copied: it is the state the replay goes on from,
                // and the snapshots after it are gone with the operations they covered.
                let (state, from) = match f.fold.checkpoints.pop() {
                    Some(s) => (s.state, s.position),
                    None => (crate::domain::State::new(&ns), 0),
                };
                let mut tail: Vec<FoldItem> = Vec::new();
                for i in from..f.keys.len() {
                    let (Some(view), Some(dg)) = (f.admitted.get(i), f.fold.order.get(i)) else {
                        continue;
                    };
                    let mk = self
                        .auth
                        .member(&view.author)
                        .map_or(MemberKind::Device, |m| m.request.kind.clone());
                    tail.push((f.keys[i].clone(), view.clone(), mk, dg.clone()));
                }
                tail.append(&mut items);
                tail.sort_by(|a, b| a.0.cmp(&b.0));
                f.fold.state = state;
                f.fold.order.truncate(from);
                f.fold.hashes.truncate(from + 1);
                f.keys.truncate(from);
                f.admitted.truncate(from);
                items = tail;
                // A short replay makes no snapshot (each one is a copy of the state); a long
                // one lays them down again as a fold from nothing does.
                if items.len() <= policy.every {
                    policy = CheckpointPolicy {
                        every: 0,
                        retain: 0,
                    };
                }
            }
            // Over a long replay, only the snapshots that will be kept are made.
            let total = f.keys.len() + items.len();
            let keep_from = total.saturating_sub(policy.every.saturating_mul(SNAPSHOTS_KEPT));
            for (pos, view, mk, dg) in &items {
                let ctx = self.auth.member(&view.author).map(|m| AuthorContext {
                    kind: model_kind(mk),
                    library: library.clone(),
                    grant: Some(grant_of(m)),
                });
                // `append` makes a snapshot at each multiple; for a long replay it is the
                // last few that matter, so the earlier multiples make none.
                let will = policy.every > 0 && (f.fold.order.len() + 1) % policy.every == 0;
                let skip = will && f.fold.order.len() + 1 < keep_from;
                let step = if skip {
                    CheckpointPolicy {
                        every: 0,
                        retain: 0,
                    }
                } else {
                    policy.clone()
                };
                f.fold.append(dg, view, ctx, &step);
                f.admitted.push(view.clone());
                f.keys.push(pos.clone());
                applied += 1;
            }
            self.fold_applied += applied;
            if is_late {
                f.fold.applied = f.keys.len() as u64;
                // Recomputed, not carried: the largest clock among the operations folded.
                f.fold.clock = f.admitted.iter().map(|v| v.clock).max().unwrap_or(0);
            }
            f.revision = Self::revision_of(&f.fold);
        }
        true
    }

    /// Set the head of the slot at `path` (none: the slot has no head), keeping the heads in
    /// `(namespace, author, slot)` order.
    pub(super) fn set_head_of(&mut self, path: &str, head: Option<crate::v05::live::LiveHead>) {
        self.set_head(path, head);
    }
    fn head_key(h: &crate::v05::live::LiveHead) -> (u64, String, String, String) {
        (
            h.generation,
            h.author.clone(),
            h.id.clone(),
            h.digest.clone(),
        )
    }
    fn head_order_of(live: &crate::v05::live::LiveJudgement) -> BTreeMap<String, HeadSet> {
        let mut m: BTreeMap<String, HeadSet> = BTreeMap::new();
        for h in &live.heads {
            m.entry(h.namespace.clone())
                .or_default()
                .insert(Self::head_key(h));
        }
        m
    }
    fn set_head(&mut self, path: &str, head: Option<crate::v05::live::LiveHead>) {
        if let Some(old) = self.live.heads.iter().find(|h| h.path == path) {
            let k = Self::head_key(old);
            if let Some(set) = self.head_order.get_mut(&old.namespace) {
                set.remove(&k);
                if set.keys.is_empty() {
                    self.head_order.remove(&old.namespace);
                }
            }
        }
        if let Some(h) = &head {
            self.head_order
                .entry(h.namespace.clone())
                .or_default()
                .insert(Self::head_key(h));
        }
        self.live.heads.retain(|h| h.path != path);
        if let Some(h) = head {
            let at = self.live.heads.partition_point(|x| {
                (&x.namespace, &x.author, &x.slot) < (&h.namespace, &h.author, &h.slot)
            });
            self.live.heads.insert(at, h);
        }
    }

    /// Judge the candidates held at each of `paths` again, in place: their verdicts, their head
    /// and the live index. `live` is the candidate set the verdicts are aligned with.
    pub(super) fn rejudge_live(
        &mut self,
        live: &[HeldRecord],
        paths: &BTreeSet<String>,
        cache: &mut JudgeCache,
    ) {
        for path in paths {
            let from = live.partition_point(|h| h.path.as_str() < path.as_str());
            let to = from + live[from..].iter().take_while(|h| h.path == *path).count();
            if from == to {
                continue;
            }
            let g = crate::v05::live::judge_group(
                &self.auth,
                &self.keys,
                &self.durable,
                &live[from..to],
                None,
                Some(cache),
            );
            let jumped = g
                .verdicts
                .iter()
                .any(|v| matches!(v, crate::v05::live::LiveVerdict::Refused("clockJump")));
            for (k, v) in g.verdicts.into_iter().enumerate() {
                if let Some(slot) = self.live.verdicts.get_mut(from + k) {
                    slot.1 = v;
                }
            }
            self.set_head(path, g.head);
            self.live_idx
                .set_group(path, g.metas.into_iter().flatten().collect(), jumped);
        }
    }

    /// The heads of `ns`'s live slots as fold items, in fold order.
    fn head_items(&self, ns: &str) -> Vec<FoldItem> {
        let mut out: Vec<FoldItem> = Vec::new();
        for head in self.live.heads.iter().filter(|h| h.namespace == ns) {
            let plain = &head.plaintext;
            let member = self.auth.member(&head.author);
            let (mk, label) = member.map_or((MemberKind::Device, String::new()), |m| {
                (m.request.kind.clone(), m.request.label.clone())
            });
            out.push((
                (
                    head.generation,
                    head.author.clone(),
                    head.id.clone(),
                    head.digest.clone(),
                ),
                OperationView {
                    id: head.id.clone(),
                    kind: head.kind.clone(),
                    author: head.author.clone(),
                    author_label: label,
                    origin: if mk == MemberKind::Agent {
                        "ai"
                    } else {
                        "person"
                    }
                    .into(),
                    clock: head.generation,
                    created: plain
                        .get("created")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    payload: plain.get("payload").cloned().unwrap_or(Value::Null),
                },
                mk,
                head.digest.clone(),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn ctx_of(&self, author: &str) -> Option<AuthorContext> {
        let library = self
            .auth
            .account()
            .as_str()
            .chars()
            .take(32)
            .collect::<String>();
        self.auth.member(author).map(|m| AuthorContext {
            kind: model_kind(&m.request.kind),
            library,
            grant: Some(grant_of(m)),
        })
    }

    /// Where the live heads of `ns` meet the durable fold: the heads in fold order, the number
    /// of durable operations before the first of them and the rolled hash of the merged order
    /// (the namespace's change token comes from it). `None` when the namespace holds no head or
    /// is not folded here.
    fn merge_plan(&self, ns: &str) -> Option<(usize, [u8; 32])> {
        use sha2::{Digest, Sha256};
        let base = self.folded.get(ns)?;
        let heads = self.head_order.get(ns)?;
        let first = heads.keys.iter().next()?;
        let p = base.keys.partition_point(|k| k < first);
        // What the readers' view of the namespace is made of: the durable fold (its rolled
        // hash covers every durable operation and their order) and the set of heads. The
        // position `p` is a function of both.
        let mut h = Sha256::new();
        h.update(base.fold.hashes.last().copied().unwrap_or([0; 32]));
        for w in heads.acc {
            h.update(w.to_le_bytes());
        }
        h.update((heads.keys.len() as u64).to_le_bytes());
        Some((p, h.finalize().into()))
    }

    /// The change token of `ns` as readers see it, the live heads included: a function of the
    /// durable operations and the set of heads, found without a pass over either.
    pub(super) fn revision_of_ns(&self, ns: &str) -> u64 {
        match self.merge_plan(ns) {
            Some((_, h)) => Self::token_of(&h),
            None => self.folded.get(ns).map_or(0, |f| f.revision),
        }
    }
    fn token_of(h: &[u8; 32]) -> u64 {
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&h[..8]);
        u64::from_be_bytes(eight) & crate::v05::encoding::bounds::MAX_INTEGER
    }

    /// The namespace as readers see it when it holds live heads: the durable fold with each
    /// head applied at its position in fold order. A head after every durable operation (the
    /// listening app's passive positions) is applied to a copy of the durable state; one before
    /// the last durable operation takes the durable fold back to its nearest snapshot at or
    /// before it and folds the merged operations from there. `None` when there is no head.
    /// Answers are remembered by the merged order they were made for.
    pub(super) fn overlaid(&self, ns: &str) -> Option<Arc<Overlaid>> {
        let (p, chain) = self.merge_plan(ns)?;
        {
            let c = self
                .overlays
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((k, o)) = c.get(ns) {
                // The merged order and the position where the heads begin: a head that
                // becomes a durable record moves the position and not the order.
                if *k == chain && o.split == p {
                    return Some(o.clone());
                }
            }
        }
        let o = Arc::new(self.build_overlay(ns, self.head_items(ns), p, Self::token_of(&chain))?);
        self.overlays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ns.to_string(), (chain, o.clone()));
        Some(o)
    }

    fn build_overlay(
        &self,
        ns: &str,
        heads: Vec<FoldItem>,
        p: usize,
        revision: u64,
    ) -> Option<Overlaid> {
        let base = self.folded.get(ns)?;
        // Where the replay starts: the snapshot at or before `p` the durable fold still holds.
        let snap = base
            .fold
            .checkpoints
            .iter()
            .rev()
            .find(|s| s.position <= p && base.fold.hashes.get(s.position) == Some(&s.digest));
        let (mut state, from) = match snap {
            Some(s) => (s.state.clone(), s.position),
            None if p == base.keys.len() => (base.fold.state.clone(), p),
            None => (crate::domain::State::new(ns), 0),
        };
        let mut h = base.fold.hashes.get(from).copied()?;
        let mut tail: Vec<OperationView> = Vec::new();
        let (mut i, mut j) = (from, 0usize);
        while i < base.keys.len() || j < heads.len() {
            let (digest, view, ctx, in_tail): (&str, &OperationView, _, bool) =
                if j >= heads.len() || (i < base.keys.len() && base.keys[i] < heads[j].0) {
                    let v = base.admitted.get(i)?;
                    let d = base.fold.order.get(i)?;
                    i += 1;
                    // Durable operations before `p` are replayed from the snapshot only.
                    (d.as_str(), v, self.ctx_of(&v.author), i > p)
                } else {
                    let it = &heads[j];
                    j += 1;
                    (it.3.as_str(), &it.1, self.ctx_of(&it.1.author), true)
                };
            state.apply_with_context(view, ctx.as_ref());
            h = crate::engine::roll(h, digest);
            state.bind_admitted_prefix(h);
            if in_tail {
                tail.push(view.clone());
            }
        }
        let _ = h;
        Some(Overlaid {
            fold: {
                let mut n = crate::engine::Namespace::new(ns);
                n.state = state;
                n
            },
            admitted: tail,
            split: p,
            revision,
        })
    }

    fn fold(&mut self, inputs: &Inputs<'_>, prior: Option<(&BTreeMap<String, Folded>, [u8; 32])>) {
        let account = self.auth.account().clone();
        let library = account.as_str().chars().take(32).collect::<String>();
        let namespaces: Vec<String> = self.auth.namespaces().to_vec();
        for ns in namespaces {
            if !readable(&self.auth, inputs.me, &ns)
                || inputs.scope.as_ref().is_some_and(|s| !s.contains(&ns))
            {
                continue;
            }
            // The latest epoch's key must be held (0.4: "notReadable" otherwise).
            let latest = self.auth.latest_epoch(&ns);
            if latest == 0 || self.keys.get(&account, &ns, latest).is_none() {
                continue;
            }
            let mut ops: Vec<FoldItem> = Vec::new();
            let accepted = self.accepted_proposals();
            for j in &self.judgement.records {
                if j.namespace.as_deref() != Some(ns.as_str()) {
                    continue;
                }
                if let Some(item) = self.fold_item(j, &accepted) {
                    ops.push(item);
                }
            }
            ops.sort_by(|a, b| a.0.cmp(&b.0));
            // A fold is a left fold over the operations in fold order, so when the previous
            // build folded exactly the first operations of this one, under the same verified
            // standing of every member, it is extended instead of redone.
            let reuse = prior
                .filter(|(_, print)| *print == self.print)
                .and_then(|(folded, _)| folded.get(&ns))
                .filter(|f| {
                    f.fold.order.len() <= ops.len()
                        && f.fold.order.iter().zip(&ops).all(|(a, b)| *a == b.3)
                });
            let seeded = inputs
                .fold_seed
                .get(&ns)
                .filter(|(p, _)| *p == crate::v05::engine::hex(&self.print))
                .map(|(_, f)| f)
                .filter(|f| {
                    f.fold.order.len() <= ops.len()
                        && f.fold.order.iter().zip(&ops).all(|(a, b)| *a == b.3)
                });
            // Whichever covers more of the operations.
            let chosen = match (reuse, seeded) {
                (Some(a), Some(b)) => Some(if b.fold.order.len() > a.fold.order.len() {
                    b
                } else {
                    a
                }),
                (a, b) => a.or(b),
            };
            let (mut fold, mut admitted, start) = match chosen {
                Some(f) => (f.fold.clone(), f.admitted.clone(), f.fold.order.len()),
                None => (Namespace::new(&ns), Vec::new(), 0),
            };
            // Snapshots are copies of the state, so a fold from far back lays down only those
            // it will keep: at the multiples of the interval in the last `SNAPSHOTS_KEPT`.
            let every = snapshot_every();
            let policy = CheckpointPolicy {
                every: 0,
                retain: 0,
            };
            let keep_from = ops
                .len()
                .saturating_sub(every.saturating_mul(SNAPSHOTS_KEPT));
            // A fold taken from before (a checkpoint's or the last derivation's) is a place to
            // rewind to as well.
            if start > 0 && fold.checkpoints.last().is_none_or(|s| s.position != start) {
                fold.checkpoints.push(fold.snapshot());
                if fold.checkpoints.len() > SNAPSHOTS_KEPT {
                    fold.checkpoints.remove(0);
                }
            }
            for (i, (_, view, mk, dg)) in ops.iter().enumerate().skip(start) {
                let ctx = self.auth.member(&view.author).map(|m| AuthorContext {
                    kind: model_kind(mk),
                    library: library.clone(),
                    grant: Some(grant_of(m)),
                });
                fold.append(dg, view, ctx, &policy);
                admitted.push(view.clone());
                self.fold_applied += 1;
                let n = i + 1;
                if n % every == 0 && n >= keep_from && n < ops.len() + 1 {
                    fold.checkpoints.push(fold.snapshot());
                    if fold.checkpoints.len() > SNAPSHOTS_KEPT {
                        fold.checkpoints.remove(0);
                    }
                }
            }
            // A change token, not a counter: a function of the folded operations and their
            // order, so it is the same however the objects arrived. Zero for no operations.
            let revision = Self::revision_of(&fold);
            let keys: Vec<(u64, String, String, String)> =
                ops.iter().map(|o| o.0.clone()).collect();
            self.folded.insert(
                ns,
                Folded {
                    revision,
                    fold,
                    admitted,
                    keys,
                },
            );
        }
    }
}

/// Whether `me` may hold keys for `namespace` at all: a controller reads through the vault, a
/// member through the shares of its `records` terms.
pub(super) fn readable(auth: &RecordAuthority, me: &Identity, namespace: &str) -> bool {
    match me {
        Identity::Controller(_) => true,
        Identity::Member(id) => auth.member(id).is_some_and(|m| {
            m.revoked_seq.is_none()
                && m.terms
                    .records()
                    .is_some_and(|r| r.iter().any(|e| e.namespace == namespace))
        }),
    }
}

/// The objects as the write side and the readers should see them: for each pending transition
/// and veto body, the first envelope in byte order that verifies against `state` (or, when none
/// does, the first). Receipts are passed through: choosing among them already skips those that
/// do not verify.
pub(super) fn effective_objects(
    objects: &Objects,
    state: &crate::v05::history::State,
) -> (Objects, BTreeSet<Vec<u8>>) {
    use crate::v05::encoding::bounds;
    use crate::v05::history::{check_pending_transition, check_pending_veto};
    use crate::v05::write::authority::choose_receipts;
    let mut groups: BTreeMap<(String, String), Vec<&Vec<u8>>> = BTreeMap::new();
    let mut rest: Vec<&Vec<u8>> = Vec::new();
    for b in &objects.pending {
        let parsed = AuthEnvelope::parse(
            b,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            true,
        );
        match parsed {
            Ok(e) => match e.value.get("protocol").and_then(Value::as_str) {
                Some(p @ ("colophon/transition/5" | "colophon/veto/5")) => {
                    groups.entry((p.to_string(), e.digest)).or_default().push(b)
                }
                _ => rest.push(b),
            },
            Err(_) => rest.push(b),
        }
    }
    let mut chosen: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
    let mut verified: BTreeSet<Vec<u8>> = BTreeSet::new();
    let transition_of = |digest: &str, chosen: &BTreeMap<(String, String), Vec<u8>>| {
        chosen
            .get(&("colophon/transition/5".to_string(), digest.to_string()))
            .cloned()
    };
    for protocol in ["colophon/transition/5", "colophon/veto/5"] {
        for ((p, digest), list) in &groups {
            if p != protocol {
                continue;
            }
            let mut list = list.clone();
            list.sort();
            let found = list
                .iter()
                .find(|b| {
                    if protocol == "colophon/transition/5" {
                        return check_pending_transition(state, b).is_ok();
                    }
                    let Ok(v) =
                        AuthEnvelope::parse(b, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)
                    else {
                        return false;
                    };
                    let Some(t) = v
                        .value
                        .get("transition")
                        .and_then(Value::as_str)
                        .and_then(|d| transition_of(d, &chosen))
                    else {
                        return false;
                    };
                    let Ok(te) = AuthEnvelope::parse(
                        &t,
                        bounds::TRANSITION_ENVELOPE,
                        bounds::TRANSITION_ENVELOPE,
                        true,
                    ) else {
                        return false;
                    };
                    let issued = te
                        .value
                        .get("issued")
                        .and_then(Value::as_str)
                        .and_then(crate::v05::encoding::parse_date)
                        .unwrap_or(0);
                    choose_receipts(state, &objects.pending, &te.digest, issued, None)
                        .is_ok_and(|r| check_pending_veto(state, &t, &r, b).is_ok())
                })
                .map(|b| (**b).clone());
            if let Some(b) = &found {
                verified.insert(b.clone());
            }
            let pick = found.or_else(|| list.first().map(|b| (**b).clone()));
            if let Some(b) = pick {
                chosen.insert((p.clone(), digest.clone()), b);
            }
        }
    }
    let mut out = objects.clone();
    out.pending = rest
        .into_iter()
        .cloned()
        .chain(chosen.into_values())
        .collect();
    out.pending.sort();
    (out, verified)
}

/// Everything a derivation holds that a rebuild over the same inputs must reproduce, as one
/// string: the judgement of every record, the proposals, the write index, the live judgement
/// and each namespace fold. [`super::Account::verify_derivation`] compares it with a rebuild.
pub(super) fn fingerprint(d: &Derived) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = vec![
        ("judgement".into(), format!("{:?}", d.judgement)),
        ("windex".into(), format!("{:?}", d.windex)),
        (
            "live heads".into(),
            format!(
                "{:?}",
                d.live
                    .heads
                    .iter()
                    .map(|h| (
                        &h.path[h.path.len().saturating_sub(12)..],
                        &h.digest[..8],
                        h.generation
                    ))
                    .collect::<Vec<_>>()
            ),
        ),
        (
            "live verdicts".into(),
            format!(
                "{:?}",
                d.live
                    .verdicts
                    .iter()
                    .map(|(p, v)| (
                        format!(
                            "{}..{}",
                            &p[6..10.min(p.len())],
                            &p[p.len().saturating_sub(8)..]
                        ),
                        v
                    ))
                    .collect::<Vec<_>>()
            ),
        ),
        ("durable".into(), format!("{:?}", d.durable)),
        ("live index".into(), format!("{:?}", d.live_idx)),
        ("head order".into(), format!("{:?}", d.head_order)),
    ];
    for (ns, f) in &d.folded {
        v.push((
            format!("fold {ns}"),
            format!(
                "{}:{:?}:{:?}:{}:{}",
                f.revision,
                f.fold.order,
                f.keys,
                serde_json::to_string(&f.fold.state).unwrap_or_default(),
                serde_json::to_string(&f.admitted).unwrap_or_default(),
            ),
        ));
        v.push((format!("revision {ns}"), d.revision_of_ns(ns).to_string()));
        if let Some(o) = d.overlaid(ns) {
            v.push((
                format!("overlay {ns}"),
                format!(
                    "{}:{}:{}:{}",
                    o.revision,
                    o.split,
                    serde_json::to_string(&o.fold.state).unwrap_or_default(),
                    serde_json::to_string(&o.admitted).unwrap_or_default(),
                ),
            ));
        }
    }
    v
}

/// What readers see of `ns` when the live heads are folded together with the durable records
/// by one plain fold of the merged order from nothing: the reference the overlay must equal.
/// Costs a full fold of the namespace.
pub(super) fn reference_merged(d: &Derived, ns: &str) -> Option<(u64, String, String)> {
    let base = d.folded.get(ns)?;
    let heads = d.head_items(ns);
    type Op = (
        (u64, String, String, String),
        OperationView,
        Option<AuthorContext>,
    );
    let mut ops: Vec<Op> = base
        .keys
        .iter()
        .cloned()
        .zip(base.admitted.iter().cloned())
        .map(|(k, v)| {
            let c = d.ctx_of(&v.author);
            (k, v, c)
        })
        .collect();
    for h in heads {
        let c = d.ctx_of(&h.1.author);
        ops.push((h.0, h.1, c));
    }
    ops.sort_by(|a, b| a.0.cmp(&b.0));
    let policy = CheckpointPolicy {
        every: 0,
        retain: 0,
    };
    let mut fold = Namespace::new(ns);
    let mut admitted = Vec::new();
    for (k, v, c) in &ops {
        fold.append(&k.3, v, c.clone(), &policy);
        admitted.push(v.clone());
    }
    Some((
        Derived::revision_of(&fold),
        serde_json::to_string(&fold.state).unwrap_or_default(),
        serde_json::to_string(&admitted).unwrap_or_default(),
    ))
}

/// What a derivation holds in memory per kind, in bytes (see [`super::Account::held_bytes`]).
pub(super) fn held_bytes(d: &Derived) -> (usize, usize) {
    let plaintext = d
        .judgement
        .records
        .iter()
        .filter_map(|j| j.plaintext.as_ref())
        .map(|p| serde_json::to_vec(p).map_or(0, |b| b.len()))
        .sum();
    let folds = d
        .folded
        .values()
        .flat_map(|f| f.admitted.iter())
        .map(|v| serde_json::to_vec(v).map_or(0, |b| b.len()))
        .sum();
    (plaintext, folds)
}

/// Overwrite every string and number of `v` with zeros and drop its structure.
pub(crate) fn wipe_value(v: &mut Value) {
    match v {
        Value::String(s) => {
            let mut b = std::mem::take(s).into_bytes();
            crate::v05::hpke_wiped::wipe(&mut b);
        }
        Value::Array(a) => {
            for x in a.iter_mut() {
                wipe_value(x);
            }
            a.clear();
        }
        Value::Object(m) => {
            for (_, x) in m.iter_mut() {
                wipe_value(x);
            }
            m.clear();
        }
        other => *other = Value::Null,
    }
}

impl Derived {
    /// Overwrite the opened plaintext this derivation (and its cache) holds, before it is freed.
    pub(super) fn wipe_plaintext(&mut self) {
        for j in &mut self.judgement.records {
            if let Some(p) = j.plaintext.as_mut() {
                wipe_value(p);
            }
        }
        for f in self.folded.values_mut() {
            for v in &mut f.admitted {
                wipe_value(&mut v.payload);
            }
        }
        self.overlays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        for h in &mut self.live.heads {
            wipe_value(&mut h.plaintext);
        }
        let mut c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.wipe_plaintext();
    }
}
