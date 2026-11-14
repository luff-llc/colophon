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
}

/// One admitted record on its way into a fold: its position `(clock, author, id, digest)`, its
/// view, its author's kind and its header digest.
type FoldItem = (
    (u64, String, String, String),
    OperationView,
    MemberKind,
    String,
);

/// One namespace's fold.
pub(super) struct Folded {
    pub revision: u64,
    pub fold: Namespace,
    pub admitted: Vec<OperationView>,
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
    /// The judgement of the live-state candidates held (0.3 §5.1).
    pub live: crate::v05::live::LiveJudgement,
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
    h.update(format!("fork:{:?};upgrade:{:?};", auth.fork_seq(), auth.upgrade_seq()).as_bytes());
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
        let live = crate::v05::live::judge_live(&auth, &keys, &judgement, inputs.live);
        let (effective, verified_pending) = effective_objects(inputs.objects, auth.state());
        let mut derived = Self {
            effective,
            verified_pending,
            verdict,
            auth,
            keys,
            judgement,
            live,
            folded: BTreeMap::new(),
            print,
            cache,
            fold_applied: 0,
        };
        derived.fold(inputs, prior);
        Ok(derived)
    }

    fn fold(&mut self, inputs: &Inputs<'_>, prior: Option<&Derived>) {
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
            let accepted: BTreeMap<(String, String), (u64, String, String)> = self
                .judgement
                .proposals
                .iter()
                .filter_map(|p| match &p.state {
                    ProposalState::Accepted { at, .. } => {
                        Some(((p.namespace.clone(), p.id.clone()), at.clone()))
                    }
                    _ => None,
                })
                .collect();
            for j in &self.judgement.records {
                if j.namespace.as_deref() != Some(ns.as_str()) || j.outcome != Outcome::Admitted {
                    continue;
                }
                let (Some(plain), Some(author), Some(id), Some(dg)) = (
                    j.plaintext.as_ref(),
                    j.author.as_ref(),
                    j.id.as_ref(),
                    j.digest.as_ref(),
                ) else {
                    continue;
                };
                if !j.folded {
                    continue;
                }
                let kind = plain
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if kind == "colophon.accept" || kind == "colophon.decline" {
                    continue;
                }
                // A proposal folds once, at its accept's position (§11.6), and never before.
                let position = match j.level {
                    Some(Level::Propose) => match accepted.get(&(ns.clone(), id.clone())) {
                        Some((c, a, i)) => (*c, a.clone(), i.clone(), dg.clone()),
                        None => continue,
                    },
                    _ => (j.clock, author.clone(), id.clone(), dg.clone()),
                };
                let member = self.auth.member(author);
                let (mk, label) = member.map_or((MemberKind::Device, String::new()), |m| {
                    (m.request.kind.clone(), m.request.label.clone())
                });
                ops.push((
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
                ));
            }
            // Current live heads fold at their `(generation, author, id)` position, as any
            // operation does; the caller of `judge_live` already left out the ones that are an
            // admitted immutable record too.
            for head in self.live.heads.iter().filter(|h| h.namespace == ns) {
                let plain = &head.plaintext;
                let member = self.auth.member(&head.author);
                let (mk, label) = member.map_or((MemberKind::Device, String::new()), |m| {
                    (m.request.kind.clone(), m.request.label.clone())
                });
                ops.push((
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
            ops.sort_by(|a, b| a.0.cmp(&b.0));
            // A fold is a left fold over the operations in fold order, so when the previous
            // build folded exactly the first operations of this one, under the same verified
            // standing of every member, it is extended instead of redone.
            let reuse = prior
                .filter(|p| p.print == self.print)
                .and_then(|p| p.folded.get(&ns))
                .filter(|f| {
                    f.fold.order.len() <= ops.len()
                        && f.fold.order.iter().zip(&ops).all(|(a, b)| *a == b.3)
                });
            let (mut fold, mut admitted, start) = match reuse {
                Some(f) => (f.fold.clone(), f.admitted.clone(), f.fold.order.len()),
                None => (Namespace::new(&ns), Vec::new(), 0),
            };
            let policy = CheckpointPolicy {
                every: 0,
                retain: 0,
            };
            for (_, view, mk, dg) in &ops[start..] {
                let ctx = self.auth.member(&view.author).map(|m| AuthorContext {
                    kind: model_kind(mk),
                    library: library.clone(),
                    grant: Some(grant_of(m)),
                });
                fold.append(dg, view, ctx, &policy);
                admitted.push(view.clone());
                self.fold_applied += 1;
            }
            // A change token, not a counter: a function of the folded operations and their
            // order, so it is the same however the objects arrived. Zero for no operations.
            let revision = if fold.order.is_empty() {
                0
            } else {
                let h = fold.hashes.last().copied().unwrap_or([0; 32]);
                let mut eight = [0u8; 8];
                eight.copy_from_slice(&h[..8]);
                u64::from_be_bytes(eight) & crate::v05::encoding::bounds::MAX_INTEGER
            };
            self.folded.insert(
                ns,
                Folded {
                    revision,
                    fold,
                    admitted,
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
