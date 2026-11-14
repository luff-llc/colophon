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
    judge_records, EpochKeys, HeldRecord, Judgement, Level, Outcome, ProposalState,
    RecordAuthority,
};
use crate::v05::terms::Access;
use crate::v05::{malformed, Failure, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// What a [`Derived`] is built from.
pub(super) struct Inputs<'a> {
    pub objects: &'a Objects,
    pub records: &'a [HeldRecord],
    pub persisted: &'a Persisted,
    pub now_ms: i64,
    pub seeds: &'a SeedRing,
    pub me: &'a Identity,
    pub scope: &'a Option<BTreeSet<String>>,
}

/// One namespace's fold.
pub(super) struct Folded {
    pub revision: u64,
    pub fold: Namespace,
    pub admitted: Vec<OperationView>,
}

pub(super) struct Derived {
    pub verdict: Verdict,
    pub auth: RecordAuthority,
    pub keys: EpochKeys,
    pub judgement: Judgement,
    pub folded: BTreeMap<String, Folded>,
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
        let judgement = judge_records(&auth, &keys, inputs.records);
        let mut derived = Self {
            verdict,
            auth,
            keys,
            judgement,
            folded: BTreeMap::new(),
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
            let mut ops: Vec<((u64, String, String, String), OperationView, MemberKind, String)> =
                Vec::new();
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
                let kind = plain.get("kind").and_then(Value::as_str).unwrap_or_default();
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
                        origin: if mk == MemberKind::Agent { "ai" } else { "person" }.into(),
                        clock: plain.get("clock").and_then(Value::as_u64).unwrap_or(j.clock),
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
            ops.sort_by(|a, b| a.0.cmp(&b.0));
            let mut fold = Namespace::new(&ns);
            let policy = CheckpointPolicy { every: 0, retain: 0 };
            let mut admitted = Vec::new();
            for (_, view, mk, dg) in &ops {
                let ctx = self.auth.member(&view.author).map(|m| AuthorContext {
                    kind: model_kind(mk),
                    library: library.clone(),
                    grant: Some(grant_of(m)),
                });
                fold.append(dg, view, ctx, &policy);
                admitted.push(view.clone());
            }
            let before = prior.and_then(|p| p.folded.get(&ns));
            let revision = match before {
                None => u64::from(!ops.is_empty()),
                Some(b) if b.fold.order == fold.order => b.revision,
                Some(b) => b.revision + 1,
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
