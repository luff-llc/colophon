//! Pure record replica and two-phase host actions. No storage, clocks or platform callbacks.
#[path = "blob_api.rs"]
mod blob_api;
use crate::{
    authority::{self, Action, Authority, AuthorityEntry},
    crypto::{self, Entropy, PublicIdentity},
    domain::{self, Spec},
    engine::{self, ChangeSummary, CheckpointPolicy, Namespace, Snapshot},
    ensure,
    hpke::SealedKey,
    model::*,
    records::{self, bytes, canonical, SignedRecord},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[path = "storage.rs"]
pub(crate) mod storage;

/// One exact body to sign. Finish verifies the supplied signature against `signing`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningStep {
    /// Immutable storage path.
    pub path: String,
    /// Exact body bytes for the host.
    #[serde(with = "bytes")]
    pub body: Vec<u8>,
    /// Expected public signing key.
    #[serde(with = "bytes")]
    pub signing: Vec<u8>,
}
/// An action's complete prepared record batch. Persist/merge atomically after all signatures verify.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PendingBatch {
    /// Host signing steps in authority order.
    pub steps: Vec<SigningStep>,
    /// Extra paths that receive a copy of the signed envelope at the first matching `steps` path.
    #[serde(default)]
    pub aliases: Vec<(String, String)>,
    /// Already-signed records to store (retained live predecessors).
    #[serde(default)]
    pub copies: Records,
}
impl PendingBatch {
    /// Finish all signatures without changing a library. A wrong signature rejects the whole batch.
    pub fn finish(self, signatures: Vec<Vec<u8>>) -> Result<Records> {
        ensure(
            self.steps.len() == signatures.len(),
            "Signature count mismatch",
        )?;
        let mut records = self.copies;
        for (step, signature) in self.steps.into_iter().zip(signatures) {
            let record = SignedRecord::finish_sign(step.body, signature, &step.signing)?;
            records.insert(step.path, record.encode()?);
        }
        for (from, to) in self.aliases {
            let bytes = records
                .get(&from)
                .cloned()
                .ok_or_else(|| Error("Missing signed alias source".into()))?;
            records.insert(to, bytes);
        }
        Ok(records)
    }
}
/// An ECDH task for the host's non-extractable agreement key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgreementStep {
    /// Namespace to unlock.
    pub namespace: String,
    /// Epoch to unlock.
    pub epoch: u64,
    /// Ephemeral public point passed to host `agree`.
    #[serde(with = "bytes")]
    pub peer: Vec<u8>,
}
/// Inputs for creating a library. The recovery secret remains with the host.
pub struct CreateOptions {
    /// Owner's public identity.
    pub owner: PublicIdentity,
    /// Independently derived recovery identity.
    pub recovery: PublicIdentity,
    /// Library label.
    pub label: String,
    /// Owner label.
    pub owner_label: String,
    /// Declared namespace names.
    pub namespaces: Vec<String>,
}
/// In-memory replica: signed records and explicitly unlocked symmetric keys only.
#[derive(Clone)]
pub struct Library {
    records: Records,
    read_scope: Vec<String>,
    authority: Authority,
    me: PublicIdentity,
    keys: BTreeMap<(String, u64), Vec<u8>>,
    checkpoint_keys: BTreeMap<(String, u64), Vec<u8>>,
    judged: Vec<Judged>,
    invalid: BTreeMap<String, (String, Rejection)>,
    admission: Admission,
    namespaces: BTreeMap<String, Namespace>,
    checkpoint_policy: CheckpointPolicy,
    changes: ChangeSummary,
    pending_checkpoints: BTreeMap<String, Vec<u8>>,
    verifiers: std::sync::Arc<crate::verification::Verifiers>,
    /// Current live slots keyed by (author, namespace, slot).
    live: BTreeMap<(String, String, String), Judged>,
    /// Signed candidates awaiting epoch keys; never replace the verified envelope early.
    pending_live: BTreeMap<String, Vec<Vec<u8>>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Admitted,
    Held(String),
    Refused(String),
}
#[derive(Clone, Default)]
struct Admission {
    authenticated_ids: BTreeSet<(String, String)>,
    spent: BTreeMap<String, BTreeSet<String>>,
    clocks: BTreeMap<String, u64>,
    namespace_tails: BTreeMap<String, (u64, String, String)>,
    author_tails: BTreeMap<String, (u64, String, String)>,
}
#[derive(Clone)]
struct Judged {
    digest: String,
    header: OperationHeader,
    operation: Option<OperationView>,
    opened: bool,
    status: Status,
    from_live_slot: bool,
}
impl Library {
    /// Prepare genesis and initial epochs. Every new epoch is sealed to owner and recovery.
    pub fn begin_create(opts: CreateOptions, now: &str, seed: [u8; 32]) -> Result<PendingBatch> {
        opts.owner.validate()?;
        opts.recovery.validate()?;
        time_key(now)?;
        let genesis = AuthorityEntry {
            protocol: crate::protocol::AUTHORITY.into(),
            seq: 1,
            previous: None,
            issued: now.into(),
            by: "root".into(),
            action: Action::Genesis {
                label: opts.label,
                owner_label: opts.owner_label,
                root: opts.owner.clone(),
                recovery: opts.recovery.clone(),
                namespaces: opts.namespaces.clone(),
            },
        };
        let body = canonical(&genesis)?;
        let id = records::id(&body);
        let mut entropy = Entropy::new(seed);
        let epochs = opts
            .namespaces
            .iter()
            .map(|ns| {
                make_epoch(
                    &id,
                    ns,
                    1,
                    &[opts.owner.clone(), opts.recovery.clone()],
                    &mut entropy,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let rekey = AuthorityEntry {
            protocol: crate::protocol::AUTHORITY.into(),
            seq: 2,
            previous: Some(records::digest(&body)),
            issued: now.into(),
            by: "root".into(),
            action: Action::Rekey { epochs },
        };
        let rekey_body = canonical(&rekey)?;
        let layout = AuthorityEntry {
            protocol: crate::protocol::AUTHORITY.into(),
            seq: 3,
            previous: Some(records::digest(&rekey_body)),
            issued: now.into(),
            by: "root".into(),
            action: Action::Layout {
                layout: crate::protocol::LAYOUT,
            },
        };
        Ok(PendingBatch {
            steps: vec![
                SigningStep {
                    path: "authority/00000001.json".into(),
                    body,
                    signing: opts.owner.signing.clone(),
                },
                SigningStep {
                    path: "authority/00000002.json".into(),
                    body: rekey_body,
                    signing: opts.owner.signing.clone(),
                },
                SigningStep {
                    path: "authority/00000003.json".into(),
                    body: canonical(&layout)?,
                    signing: opts.owner.signing,
                },
            ],
            ..PendingBatch::default()
        })
    }
    /// Verify and open records without private keys. Call begin/finish unlock for readable epochs.
    pub fn open(records: Records, me: PublicIdentity) -> Result<Self> {
        me.validate()?;
        let authority = Authority::replay(&records)?;
        if let Some(member) = authority.members.get(&me.id()) {
            ensure(member.public == me, "Member agreement key mismatch")?;
        }
        if me.id() == authority.recovery.id() {
            ensure(me == authority.recovery, "Recovery agreement key mismatch")?;
        }
        let verifiers = std::sync::Arc::new(crate::verification::Verifiers::new(&authority));
        let mut library = Self {
            verifiers,
            records,
            read_scope: Vec::new(),
            authority,
            me,
            keys: BTreeMap::new(),
            checkpoint_keys: BTreeMap::new(),
            judged: Vec::new(),
            invalid: BTreeMap::new(),
            admission: Admission::default(),
            namespaces: BTreeMap::new(),
            checkpoint_policy: CheckpointPolicy::default(),
            changes: ChangeSummary::default(),
            pending_checkpoints: BTreeMap::new(),
            live: BTreeMap::new(),
            pending_live: BTreeMap::new(),
        };
        let paths = library
            .records
            .keys()
            .filter(|p| crate::protocol::is_operation_record(p))
            .cloned()
            .collect::<Vec<_>>();
        library.ingest(&paths, true, &[]);
        Ok(library)
    }
    /// Library identifier derived from genesis bytes.
    pub fn id(&self) -> &str {
        &self.authority.id
    }
    /// Exact records for the host to persist and sync.
    pub fn records(&self) -> &Records {
        &self.records
    }
    /// Verified authority history for protocol inspection.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
    /// This replica's public identity.
    pub fn identity(&self) -> &PublicIdentity {
        &self.me
    }
    /// Declare the coherent namespace listing supplied by this host (empty means all).
    /// Capped cross-namespace grants need their complete scope to enforce the shared budget.
    pub fn set_read_scope(&mut self, namespaces: Vec<String>) {
        if self.read_scope != namespaces {
            self.read_scope = namespaces;
            self.ingest(&[], true, &[]);
        }
    }
    fn budget_scope_complete(authority: &Authority, scope: &[String], author: &str) -> bool {
        scope.is_empty()
            || authority
                .members
                .get(author)
                .and_then(|member| member.member.grant.as_ref())
                .is_none_or(|grant| {
                    grant.write_budget.is_none()
                        || grant.namespaces.iter().all(|ns| scope.contains(ns))
                })
    }
    /// Authenticate a live candidate against current authority and epoch keys. Used by hosts
    /// before conditional storage/sync promotion. Never trusts an unsigned generation.
    pub fn live_generation(&self, path: &str, raw: &[u8], now: &str) -> Result<u64> {
        ensure(crate::protocol::is_replaceable(path), "Not a live slot")?;
        let input = [(path, raw)];
        let (header, digest) = self
            .verifiers
            .operations(&self.authority, &input, None)?
            .remove(0)?;
        let member = self
            .authority
            .members
            .get(&header.meta.author)
            .ok_or_else(|| missing("author"))?;
        ensure(member.member.revoked_at.is_none(), "Revoked live writer")?;
        ensure(
            member.member.grant.as_ref().is_none_or(|g| {
                !expired(&g.expires, now).unwrap_or(true)
                    && g.expires.is_none()
                    && g.write_budget.is_none()
            }),
            "Expired or capped live writer",
        )?;
        let status = Self::judge(
            &self.authority,
            &header.meta,
            &digest,
            &mut BTreeMap::new(),
            // Standalone relay verifiers have authority and keys, but no durable prefix.
            // Relative bounds belong to admission/merge, never this authentication API.
            header.meta.clock,
            true,
        );
        ensure(
            status == Status::Admitted,
            "Live writer is not currently admitted",
        )?;
        let generation = header.meta.clock;
        let mut j = Judged {
            header,
            digest,
            operation: None,
            opened: false,
            status,
            from_live_slot: true,
        };
        Self::open_operation(&self.authority, &self.keys, &mut j);
        ensure(j.operation.is_some(), "Live payload unavailable or invalid")?;
        Ok(generation)
    }
    /// Header-only admission is sufficient to quarantine bytes, never to promote them.
    fn live_header(&self, path: &str, raw: &[u8]) -> Result<(OperationHeader, String)> {
        let (header, digest) = self
            .verifiers
            .operations(&self.authority, &[(path, raw)], None)?
            .remove(0)?;
        ensure(
            self.authority
                .members
                .get(&header.meta.author)
                .is_some_and(|m| m.member.revoked_at.is_none()),
            "Revoked live writer",
        )?;
        ensure(
            Self::judge(
                &self.authority,
                &header.meta,
                &digest,
                &mut BTreeMap::new(),
                self.admission
                    .clocks
                    .get(&header.meta.namespace)
                    .copied()
                    .unwrap_or(0),
                true,
            ) == Status::Admitted,
            "Live writer is not currently admitted",
        )?;
        Ok((header, digest))
    }
    fn retry_live(&mut self) -> Result<()> {
        let pending = std::mem::take(&mut self.pending_live);
        let mut changes = self.changes.clone();
        for (path, mut candidates) in pending {
            candidates.sort_by_key(|raw| decode_header(raw).map(|h| h.meta.clock));
            for raw in candidates {
                self.merge([(path.clone(), raw)].into())?;
                changes.namespaces.extend(self.changes.namespaces.clone());
            }
        }
        self.changes = changes;
        Ok(())
    }
    /// Only the exact previously authenticated current head can bypass earlier-arrival replay.
    fn retains_live(&self, header: &OperationHeader, raw: &[u8]) -> bool {
        let Some(stamp) = &header.live else {
            return false;
        };
        let key = (
            header.meta.author.clone(),
            header.meta.namespace.clone(),
            stamp.slot.clone(),
        );
        self.live.get(&key).is_some_and(|j| {
            j.operation.as_ref().is_some_and(|op| {
                self.namespaces
                    .get(&key.1)
                    .is_some_and(|n| n.state.can_insert_retained(op))
            }) && order(&j.header.meta) == order(&header.meta)
        }) && self
            .records
            .get(&crate::protocol::live_state_path(&key.0, &key.1, &key.2))
            .is_some_and(|old| old == raw)
    }
    /// Merge immutable records transactionally. Conflicting paths fail; identical replay is harmless.
    pub fn merge(&mut self, incoming: Records) -> Result<()> {
        self.merge_with_changes(incoming).map(|_| ())
    }
    /// Merge records and return changed namespace revisions; the original `merge` is a wrapper.
    pub fn merge_with_changes(&mut self, incoming: Records) -> Result<ChangeSummary> {
        for (path, raw) in &incoming {
            ensure(
                path.starts_with("authority/")
                    || path.starts_with("requests/")
                    || path.starts_with("ops/")
                    || path.starts_with("state/")
                    || path.starts_with("history/"),
                "Unknown storage path",
            )?;
            if let Some(old) = self.records.get(path) {
                if crate::protocol::is_replaceable(path) {
                    continue;
                }
                ensure(old == raw, "Immutable record conflict")?;
            }
        }
        let mut incoming: Records = incoming
            .into_iter()
            .filter(|(p, raw)| {
                self.records.get(p) != Some(raw)
                    && (crate::protocol::is_replaceable(p) || !self.records.contains_key(p))
            })
            .collect();
        let authority_changed = incoming.keys().any(|p| p.starts_with("authority/"));
        if authority_changed {
            // Replay only authority records; operations do not participate in authority validation.
            let mut authority_records: Records = self
                .records
                .iter()
                .filter(|(p, _)| p.starts_with("authority/"))
                .map(|(p, r)| (p.clone(), r.clone()))
                .collect();
            authority_records.extend(
                incoming
                    .iter()
                    .filter(|(p, _)| p.starts_with("authority/"))
                    .map(|(p, r)| (p.clone(), r.clone())),
            );
            let authority = Authority::replay(&authority_records)?;
            ensure(authority.id == self.authority.id, "Different library")?;
            self.verifiers = std::sync::Arc::new(crate::verification::Verifiers::new(&authority));
            self.authority = authority;
        }
        // Authenticate candidates against the complete incoming immutable prefix. Locked
        // candidates remain separate until payload validation can succeed after unlock.
        let mut staged = None;
        if incoming.keys().any(|p| crate::protocol::is_replaceable(p))
            && (authority_changed || incoming.keys().any(|p| p.starts_with("ops/")))
        {
            let mut candidate = self.clone();
            candidate.merge(
                incoming
                    .iter()
                    .filter(|(p, _)| !crate::protocol::is_replaceable(p))
                    .map(|(p, b)| (p.clone(), b.clone()))
                    .collect(),
            )?;
            staged = Some(candidate);
        }
        let validator = staged.as_ref().unwrap_or(self);
        let mut ignored = Vec::new();
        let mut deferred = Vec::new();
        for (path, raw) in &incoming {
            if !crate::protocol::is_replaceable(path) {
                continue;
            }
            let Some(old) = self.records.get(path) else {
                continue;
            };
            let Ok((header, _)) = validator.live_header(path, raw) else {
                ignored.push(path.clone());
                continue;
            };
            let old_generation = validator.live_header(path, old).ok().and_then(|(h, _)| {
                // If keys are available, even a signed old envelope must pass payload binding.
                (!validator
                    .keys
                    .contains_key(&(h.meta.namespace.clone(), h.meta.epoch))
                    || validator
                        .live_generation(path, old, &h.meta.created)
                        .is_ok())
                .then_some(h.meta.clock)
            });
            if let Some(old_generation) = old_generation {
                ensure(
                    header.meta.clock != old_generation,
                    "Equivocation at live generation",
                )?;
                if header.meta.clock < old_generation {
                    ignored.push(path.clone());
                    continue;
                }
            }
            if !validator
                .keys
                .contains_key(&(header.meta.namespace.clone(), header.meta.epoch))
            {
                deferred.push((path.clone(), raw.clone()));
                ignored.push(path.clone());
            } else if validator
                .live_generation(path, raw, &header.meta.created)
                .is_err()
            {
                ignored.push(path.clone());
            }
        }
        for (path, raw) in deferred {
            let candidates = self.pending_live.entry(path).or_default();
            if !candidates.contains(&raw) {
                candidates.push(raw);
            }
        }
        for path in ignored {
            incoming.remove(&path);
        }
        let mut paths: Vec<_> = incoming
            .keys()
            .filter(|p| crate::protocol::is_operation_record(p))
            .cloned()
            .collect();
        for path in &paths {
            if crate::protocol::is_replaceable(path) {
                self.judged.retain(|j| {
                    !j.from_live_slot
                        || j.header.live.as_ref().is_none_or(|stamp| {
                            crate::protocol::live_state_path(
                                &j.header.meta.author,
                                &j.header.meta.namespace,
                                &stamp.slot,
                            ) != *path
                        })
                });
            }
        }
        self.records.extend(incoming);
        if authority_changed {
            paths.extend(self.invalid.keys().cloned());
        }
        let invalidated = if authority_changed {
            self.authority.namespaces.clone()
        } else {
            Vec::new()
        };
        self.ingest(&paths, authority_changed, &invalidated);
        Ok(self.changes.clone())
    }
    /// Complete a two-phase write/action and return its namespace changes.
    pub fn finish_with_changes(
        &mut self,
        pending: PendingBatch,
        signatures: Vec<Vec<u8>>,
    ) -> Result<ChangeSummary> {
        self.merge_with_changes(pending.finish(signatures)?)
    }
    /// Changes from the most recent successful merge or key unlock.
    pub fn changes(&self) -> &ChangeSummary {
        &self.changes
    }
    /// Local namespace revision; not a portable content digest or authority sequence.
    pub fn revision(&self, namespace: &str) -> u64 {
        self.namespaces.get(namespace).map_or(0, |n| n.revision)
    }
    /// Configure bounded automatic projection snapshots. Zero cadence disables them.
    pub fn set_checkpoint_policy(&mut self, policy: CheckpointPolicy) {
        for ns in self.namespaces.values_mut() {
            if ns.checkpoints.len() > policy.retain {
                ns.checkpoints.drain(..ns.checkpoints.len() - policy.retain);
            }
        }
        self.checkpoint_policy = policy;
    }
    /// Number of reducer applications in this replica, for diagnostics and performance tests.
    pub fn applied_operations(&self, namespace: &str) -> u64 {
        self.namespaces.get(namespace).map_or(0, |n| n.applied)
    }
    /// Open records with optional device-local checkpoint bytes, applied as keys unlock.
    /// Records still undergo signature, authority and admission validation. Invalid caches are ignored.
    pub fn open_with_checkpoints(
        records: Records,
        me: PublicIdentity,
        checkpoints: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        let mut library = Self::open(records, me)?;
        library.pending_checkpoints = checkpoints;
        Ok(library)
    }
    /// Serialize an authenticated device-local projection cache. Never sync these bytes as records.
    /// The format binds identity, library, namespace, epoch, reducer version and admitted prefix.
    pub fn checkpoint(&self, namespace: &str) -> Result<Vec<u8>> {
        let state = self
            .namespaces
            .get(namespace)
            .ok_or_else(|| missing("namespace"))?;
        let epoch = self
            .authority
            .epoch_at(namespace, self.authority.latest)
            .ok_or_else(|| missing("epoch"))?;
        let key = self
            .checkpoint_keys
            .get(&(namespace.into(), epoch))
            .ok_or_else(|| missing("unlocked checkpoint key"))?;
        let body = serde_json::to_vec(&CheckpointBody {
            version: 1,
            reducer_schema: domain::REDUCER_SCHEMA,
            library: self.id().into(),
            identity: self.me.id(),
            namespace: namespace.into(),
            epoch,
            snapshot: state.snapshot(),
        })?;
        let tag = checkpoint_tag(key, &body)?;
        Ok(serde_json::to_vec(&CheckpointEnvelope { body, tag })?)
    }
    /// Restore a local checkpoint against currently admitted content. Returns false on any mismatch;
    /// the already replayed state remains authoritative. Operations after its position are replayed.
    pub fn restore_checkpoint(&mut self, namespace: &str, bytes: &[u8]) -> Result<bool> {
        let mut ops: Vec<_> = self
            .judged
            .iter()
            .filter(|j| j.status == Status::Admitted && j.header.meta.namespace == namespace)
            .filter_map(|j| j.operation.as_ref().map(|op| (j.digest.as_str(), op)))
            .collect();
        ops.sort_by(|a, b| {
            (a.1.clock, &a.1.author, &a.1.id).cmp(&(b.1.clock, &b.1.author, &b.1.id))
        });
        let Ok(snapshot) = self.decode_checkpoint(namespace, bytes, &ops) else {
            return Ok(false);
        };
        let state = self
            .namespaces
            .entry(namespace.into())
            .or_insert_with(|| Namespace::new(namespace));
        state.reconcile(
            namespace,
            &ops,
            &self.checkpoint_policy,
            Some(snapshot),
            |op| {
                self.authority.members.get(&op.author).map(|member| {
                    domain::AuthorContext::from_member(&member.member, &self.authority.id)
                })
            },
        );
        Ok(true)
    }
    fn decode_checkpoint(
        &self,
        namespace: &str,
        bytes: &[u8],
        ops: &[(&str, &OperationView)],
    ) -> Result<Snapshot> {
        let envelope: CheckpointEnvelope = serde_json::from_slice(bytes)?;
        let body: CheckpointBody = serde_json::from_slice(&envelope.body)?;
        ensure(
            body.version == 1
                && body.reducer_schema == domain::REDUCER_SCHEMA
                && body.library == self.id()
                && body.identity == self.me.id()
                && body.namespace == namespace,
            "Checkpoint format or identity mismatch",
        )?;
        let key = self
            .checkpoint_keys
            .get(&(namespace.into(), body.epoch))
            .ok_or_else(|| missing("checkpoint key"))?;
        let expected = checkpoint_tag(key, &envelope.body)?;
        let difference = expected
            .iter()
            .zip(&envelope.tag)
            .fold(0u8, |d, (a, b)| d | (a ^ b));
        ensure(
            expected.len() == envelope.tag.len() && difference == 0,
            "Checkpoint authentication failed",
        )?;
        ensure(
            std::mem::discriminant(&body.snapshot.state.projection)
                == std::mem::discriminant(&domain::State::new(namespace).projection),
            "Checkpoint domain mismatch",
        )?;
        ensure(
            body.snapshot.position <= ops.len(),
            "Checkpoint prefix unavailable",
        )?;
        let digest = ops[..body.snapshot.position]
            .iter()
            .fold([0; 32], |h, (d, _)| engine::roll(h, d));
        ensure(digest == body.snapshot.digest, "Checkpoint prefix mismatch")?;
        Ok(body.snapshot)
    }
    /// Read a bounded projection without constructing the history-bearing compatibility view.
    /// Queries are documented in docs/engine.md. `read` remains a compatibility full projection.
    pub fn query(
        &self,
        namespace: &str,
        name: &str,
        args: Value,
        now: &str,
    ) -> Result<Outcome<Value>> {
        ensure(args.is_object(), "Query arguments must be an object")?;
        if let Some(denial) = self.authorize(namespace, Access::Read, now)? {
            return Ok(Outcome::failure(denial));
        }
        let epoch = self
            .authority
            .epoch_at(namespace, self.authority.latest)
            .ok_or_else(|| missing("epoch"))?;
        if !self.keys.contains_key(&(namespace.into(), epoch)) {
            return Ok(Outcome::failure(Denial::new(
                "notReadable",
                "The namespace key has not been unlocked",
            )));
        }
        let state = self
            .namespaces
            .get(namespace)
            .ok_or_else(|| missing("namespace"))?;
        if self
            .live
            .values()
            .any(|j| j.header.meta.namespace == namespace)
        {
            Ok(Outcome::success(
                if namespace == "listening.podcasts" && name == "getEpisode" {
                    self.projected_episode(namespace, args["id"].as_str().unwrap_or(""), now)?
                        .query(name, &args)?
                } else {
                    self.projected(namespace, now)?.query(name, &args)?
                },
            ))
        } else {
            Ok(Outcome::success(state.query(name, &args)?))
        }
    }
    /// Verify host signatures, then merge the complete action atomically.
    pub fn finish(&mut self, pending: PendingBatch, signatures: Vec<Vec<u8>>) -> Result<()> {
        self.merge(pending.finish(signatures)?)
    }
    /// Return ECDH steps for all sealed epochs this identity has not unlocked.
    pub fn begin_unlock(&self) -> Vec<AgreementStep> {
        let id = self.me.id();
        self.authority
            .epochs
            .iter()
            .flat_map(|(ns, epochs)| {
                epochs.iter().filter_map(|(epoch, (_, key))| {
                    if self.keys.contains_key(&(ns.clone(), *epoch)) {
                        return None;
                    }
                    key.seals.get(&id).map(|s| AgreementStep {
                        namespace: ns.clone(),
                        epoch: *epoch,
                        peer: s.begin_open().to_vec(),
                    })
                })
            })
            .collect()
    }
    /// Complete one host ECDH step, caching the authenticated epoch key and a local cache key.
    pub fn finish_unlock(&mut self, namespace: &str, epoch: u64, shared: &[u8]) -> Result<()> {
        let (key, checkpoint_key) = self.unseal_key(namespace, epoch, shared)?;
        self.keys.insert((namespace.into(), epoch), key);
        self.checkpoint_keys
            .insert((namespace.into(), epoch), checkpoint_key);
        self.ingest(&[], true, &[namespace.into()]);
        self.retry_live()?;
        Ok(())
    }
    /// Complete all host ECDH results atomically, then refresh admission/projections once.
    /// Each tuple is (namespace, epoch, raw shared secret). Prefer this on cold open.
    pub fn finish_unlock_many(&mut self, results: Vec<(String, u64, Vec<u8>)>) -> Result<()> {
        let keys = results
            .iter()
            .map(|(ns, epoch, shared)| {
                self.unseal_key(ns, *epoch, shared)
                    .map(|key| ((ns.clone(), *epoch), key))
            })
            .collect::<Result<Vec<_>>>()?;
        if !keys.is_empty() {
            let invalidated: Vec<_> = keys
                .iter()
                .map(|(location, _)| location.0.clone())
                .collect();
            for (location, (key, checkpoint_key)) in keys {
                self.keys.insert(location.clone(), key);
                self.checkpoint_keys.insert(location, checkpoint_key);
            }
            self.ingest(&[], true, &invalidated);
            self.retry_live()?;
        }
        Ok(())
    }
    fn unseal_key(&self, namespace: &str, epoch: u64, shared: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let id = self.me.id();
        let sealed = self
            .authority
            .epochs
            .get(namespace)
            .and_then(|e| e.get(&epoch))
            .and_then(|(_, e)| e.seals.get(&id))
            .ok_or_else(|| missing("epoch seal"))?;
        let key = sealed.finish_open(
            &self.me.agreement,
            shared,
            &self.authority.key_info(namespace, epoch, &id),
        )?;
        ensure(key.len() == 32, "Invalid epoch key length")?;
        // A recipient-specific ECDH result, unlike the shared namespace AES key, cannot
        // be reproduced by another granted member. This authenticates local caches only.
        let mut checkpoint_key = vec![0; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"colophon/checkpoint-key/1"), shared)
            .expand(
                &self.authority.key_info(namespace, epoch, &id),
                &mut checkpoint_key,
            )
            .map_err(|_| Error("Checkpoint key derivation failed".into()))?;
        Ok((key, checkpoint_key))
    }
    /// Prepare a self-signed request, before the prospective member has access.
    pub fn begin_request(request: Request) -> Result<PendingBatch> {
        request.member.validate()?;
        time_key(&request.created)?;
        ensure(
            request.protocol == crate::protocol::REQUEST,
            "Request protocol",
        )?;
        Grant {
            namespaces: request.namespaces.clone(),
            access: request.access.clone(),
            expires: None,
            write_budget: None,
        }
        .validate()?;
        Ok(PendingBatch {
            steps: vec![SigningStep {
                path: format!("requests/{}.json", request.member.id()),
                body: canonical(&request)?,
                signing: request.member.signing,
            }],
            ..PendingBatch::default()
        })
    }
    /// Verify a completed request and derive its six-digit display code.
    pub fn finish_request(raw: Vec<u8>, library: &str) -> Result<AccessRequest> {
        let request = authority::verify_request(&raw, library)?;
        Ok(AccessRequest {
            id: request.member.id(),
            label: request.label,
            kind: request.kind,
            namespaces: request.namespaces,
            access: request.access,
            pairing_code: authority::pairing_code(library, &request.member.signing),
            record: raw,
        })
    }
    /// Prepare approval and historical key shares. Only the current root may approve.
    pub fn begin_approve(
        &self,
        request: Vec<u8>,
        grant: Option<Grant>,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        if let Some(d) = self.root_denial() {
            return Ok(Outcome::failure(d));
        }
        let parsed = authority::verify_request(&request, self.id())?;
        let grant = grant.unwrap_or(Grant {
            namespaces: parsed.namespaces.clone(),
            access: parsed.access.clone(),
            expires: None,
            write_budget: None,
        });
        grant.validate()?;
        ensure(
            grant
                .namespaces
                .iter()
                .all(|n| parsed.namespaces.contains(n) && self.authority.namespaces.contains(n))
                && grant.access.iter().all(|a| parsed.access.contains(a)),
            "Grant exceeds requested scope",
        )?;
        let shares = self.shares(&parsed.member, &grant.namespaces, &mut Entropy::new(seed))?;
        self.action(
            Action::Grant {
                request,
                grant,
                shares,
            },
            now,
            "root",
        )
        .map(Outcome::success)
    }
    /// Prepare revocation with all admitted authenticated record digests kept and every readable namespace rotated.
    pub fn begin_revoke(
        &self,
        member_id: &str,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        if let Some(d) = self.root_denial() {
            return Ok(Outcome::failure(d));
        }
        let target = self
            .authority
            .members
            .get(member_id)
            .ok_or_else(|| missing("member"))?;
        ensure(
            member_id != self.authority.root.id() && target.member.revoked_at.is_none(),
            "Cannot revoke this member",
        )?;
        let kept = self.kept_for(member_id);
        let mut entropy = Entropy::new(seed);
        let mut epochs = Vec::new();
        if let Some(grant) = &target.member.grant {
            if grant.access.contains(&Access::Read) {
                for ns in &grant.namespaces {
                    let recipients = self
                        .authority
                        .recipients(ns, now)?
                        .into_iter()
                        .filter(|p| p.id() != member_id)
                        .collect::<Vec<_>>();
                    let epoch = self
                        .authority
                        .epoch_at(ns, self.authority.latest)
                        .unwrap_or(0)
                        + 1;
                    epochs.push(make_epoch(self.id(), ns, epoch, &recipients, &mut entropy)?);
                }
            }
        }
        self.action(
            Action::Revoke {
                member_id: member_id.into(),
                kept,
                epochs,
            },
            now,
            "root",
        )
        .map(Outcome::success)
    }
    /// Prepare an explicit rekey of the specified namespaces for all currently eligible members.
    pub fn begin_rekey(
        &self,
        namespaces: &[String],
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        if let Some(d) = self.root_denial() {
            return Ok(Outcome::failure(d));
        }
        let mut entropy = Entropy::new(seed);
        let epochs = namespaces
            .iter()
            .map(|ns| {
                make_epoch(
                    self.id(),
                    ns,
                    self.authority
                        .epoch_at(ns, self.authority.latest)
                        .unwrap_or(0)
                        + 1,
                    &self.authority.recipients(ns, now)?,
                    &mut entropy,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        self.action(Action::Rekey { epochs }, now, "root")
            .map(Outcome::success)
    }
    /// Prepare planned handover: all historical key reshares precede the handover record.
    pub fn begin_handover(
        &self,
        root: PublicIdentity,
        label: String,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        if let Some(d) = self.root_denial() {
            return Ok(Outcome::failure(d));
        }
        let mut entropy = Entropy::new(seed);
        let shares = self.shares(&root, &self.authority.namespaces, &mut entropy)?;
        let epochs = self.replacement_epochs(&root, now, &mut entropy)?;
        let mut batch = self.action(
            Action::Reshare {
                recipient: root.clone(),
                label,
                shares,
            },
            now,
            "root",
        )?;
        let first = batch.steps.first().ok_or_else(|| missing("reshare"))?;
        let entry = AuthorityEntry {
            protocol: crate::protocol::AUTHORITY.into(),
            seq: self.authority.latest + 2,
            previous: Some(records::digest(&first.body)),
            issued: now.into(),
            by: "root".into(),
            action: Action::Handover {
                root,
                kept: self.kept_for(&self.me.id()),
                epochs,
            },
        };
        batch.steps.push(SigningStep {
            path: format!("authority/{:08}.json", entry.seq),
            body: canonical(&entry)?,
            signing: self.me.signing.clone(),
        });
        Ok(Outcome::success(batch))
    }
    /// Recovery identity opens every epoch, then atomically transfers authority and data access.
    pub fn begin_recover(
        &self,
        root: PublicIdentity,
        label: String,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        if self.me != self.authority.recovery {
            return Ok(Outcome::failure(Denial::new(
                "notGranted",
                "The recovery identity is required",
            )));
        }
        let mut entropy = Entropy::new(seed);
        let shares = self.shares(&root, &self.authority.namespaces, &mut entropy)?;
        let epochs = self.replacement_epochs(&root, now, &mut entropy)?;
        self.action(
            Action::Recover {
                root,
                label,
                kept: self.kept_for(&self.authority.root.id()),
                shares,
                epochs,
            },
            now,
            "recovery",
        )
        .map(Outcome::success)
    }
    fn replacement_epochs(
        &self,
        root: &PublicIdentity,
        now: &str,
        entropy: &mut Entropy,
    ) -> Result<Vec<Epoch>> {
        self.authority
            .namespaces
            .iter()
            .map(|ns| {
                let mut recipients: Vec<_> = self
                    .authority
                    .recipients(ns, now)?
                    .into_iter()
                    .filter(|p| p.id() != self.authority.root.id())
                    .collect();
                recipients.push(root.clone());
                make_epoch(
                    self.id(),
                    ns,
                    self.authority
                        .epoch_at(ns, self.authority.latest)
                        .unwrap_or(0)
                        + 1,
                    &recipients,
                    entropy,
                )
            })
            .collect()
    }
    fn shares(
        &self,
        recipient: &PublicIdentity,
        namespaces: &[String],
        entropy: &mut Entropy,
    ) -> Result<Vec<Epoch>> {
        recipient.validate()?;
        let mut shares = Vec::new();
        for ns in namespaces {
            if let Some(epochs) = self.authority.epochs.get(ns) {
                for epoch in epochs.keys() {
                    let key = self.keys.get(&(ns.clone(), *epoch)).ok_or_else(|| {
                        missing("unlocked historical epoch; recovery must recover data keys")
                    })?;
                    let seal = SealedKey::seal(
                        &recipient.agreement,
                        key,
                        &self.authority.key_info(ns, *epoch, &recipient.id()),
                        entropy,
                    )?;
                    shares.push(Epoch {
                        namespace: ns.clone(),
                        epoch: *epoch,
                        seals: BTreeMap::from([(recipient.id(), seal)]),
                    });
                }
            }
        }
        Ok(shares)
    }
    fn action(&self, action: Action, now: &str, by: &str) -> Result<PendingBatch> {
        time_key(now)?;
        let entry = AuthorityEntry {
            protocol: crate::protocol::AUTHORITY.into(),
            seq: self.authority.latest + 1,
            previous: Some(self.authority.last_digest.clone()),
            issued: now.into(),
            by: by.into(),
            action,
        };
        Ok(PendingBatch {
            steps: vec![SigningStep {
                path: format!("authority/{:08}.json", entry.seq),
                body: canonical(&entry)?,
                signing: self.me.signing.clone(),
            }],
            ..PendingBatch::default()
        })
    }
    fn root_denial(&self) -> Option<Denial> {
        (self.me != self.authority.root)
            .then(|| Denial::new("notGranted", "Only the current root may change access"))
    }
    fn kept_for(&self, author: &str) -> BTreeSet<String> {
        self.evaluate()
            .0
            .into_iter()
            .filter(|j| {
                j.header.meta.author == author
                    && j.status == Status::Admitted
                    && j.operation.is_some()
            })
            .map(|j| j.digest.clone())
            .collect()
    }
    fn authorize(&self, namespace: &str, access: Access, now: &str) -> Result<Option<Denial>> {
        time_key(now)?;
        if !self.read_scope.is_empty() && !self.read_scope.iter().any(|ns| ns == namespace) {
            return Ok(Some(Denial::new(
                "unavailable",
                "Namespace is outside this replica's selected scope",
            )));
        }
        if access == Access::Write
            && !Self::budget_scope_complete(&self.authority, &self.read_scope, &self.me.id())
        {
            return Ok(Some(Denial::new(
                "unavailable",
                "A grant-wide write budget requires the complete grant scope",
            )));
        }
        if !self.authority.namespaces.iter().any(|n| n == namespace) {
            return Ok(Some(Denial::new(
                "notGranted",
                "Namespace is not in this library",
            )));
        }
        if self.me == self.authority.root {
            return Ok(None);
        }
        let Some(member) = self.authority.members.get(&self.me.id()) else {
            return Ok(Some(Denial::new(
                "notGranted",
                "This identity has no grant",
            )));
        };
        if member
            .member
            .grant
            .as_ref()
            .is_some_and(|g| !g.allows(namespace, access))
        {
            return Ok(Some(Denial::new(
                "notGranted",
                "The grant does not include this namespace and access",
            )));
        }
        if member.member.revoked_at.is_some() {
            return Ok(Some(Denial::new(
                "revoked",
                "Access has ended; previously decrypted data cannot be unread",
            )));
        }
        let Some(grant) = &member.member.grant else {
            return Ok(Some(Denial::new(
                "notGranted",
                "This identity is no longer the root",
            )));
        };
        if !grant.allows(namespace, access) {
            return Ok(Some(Denial::new(
                "notGranted",
                "The grant does not include this namespace and access",
            )));
        }
        if expired(&grant.expires, now)? {
            return Ok(Some(Denial::new("expired", "The grant has expired")));
        }
        if access == Access::Write {
            if let Some(budget) = grant.write_budget {
                let writes = self
                    .admission
                    .spent
                    .get(&self.me.id())
                    .map_or(0, |s| s.len()) as u64;
                if writes >= budget {
                    return Ok(Some(Denial::new(
                        "budgetSpent",
                        "The member's write budget is spent",
                    )));
                }
            }
        }
        Ok(None)
    }
    /// Seal an operation and return its signed header task, enforcing current grants and budget.
    pub fn begin_write(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        self.prepare_write(namespace, kind, payload, now, seed, |path| {
            self.records
                .get(path)
                .cloned()
                .ok_or_else(|| missing("live predecessor"))
        })
    }
    fn prepare_write(
        &self,
        namespace: &str,
        kind: &str,
        mut payload: Value,
        now: &str,
        seed: [u8; 32],
        read_live: impl Fn(&str) -> Result<Vec<u8>>,
    ) -> Result<Outcome<PendingBatch>> {
        if let Some(denial) = self.authorize(namespace, Access::Write, now)? {
            return Ok(Outcome::failure(denial));
        }
        ensure(payload.is_object(), "Operation payload must be an object")?;
        let member = self
            .authority
            .members
            .get(&self.me.id())
            .ok_or_else(|| missing("member"))?;
        if kind == crate::imports::BATCH_KIND {
            if let Some(denial) = self.root_denial() {
                return Ok(Outcome::failure(denial));
            }
            if let Some(state) = self.namespaces.get(namespace) {
                state.state.validate_import(&payload)?;
            }
        } else if kind == "colophon.blobPublish" {
            let manifest: crate::blobs::BlobManifest =
                serde_json::from_value(payload["manifest"].clone())?;
            manifest.validate()?;
            ensure(
                payload["reference"].as_str().is_some_and(|r| !r.is_empty()),
                "Missing blob reference",
            )?;
            ensure(
                payload.get("required").is_none_or(Value::is_boolean),
                "Blob required flag must be a boolean",
            )?;
        } else {
            ensure(
                domain::role_allows(namespace, kind, member.member.kind),
                "Authenticated app or device required",
            )?;
        }

        if let Some(module) = domain::module(namespace) {
            if let Some(spec) = module.operations().iter().find(|s| s.name == kind) {
                ensure(
                    domain::validate_input(&spec.input_schema, &payload),
                    "Payload does not match operation schema",
                )?;
            }
        }
        let epoch = self
            .authority
            .epoch_at(namespace, self.authority.latest)
            .ok_or_else(|| missing("epoch"))?;
        let Some(key) = self.keys.get(&(namespace.into(), epoch)) else {
            return Ok(Outcome::failure(Denial::new(
                "unavailable",
                "Unlock the namespace epoch before writing",
            )));
        };
        let mut clock = self.namespaces.get(namespace).map_or(0, |n| n.clock);
        for ((_, ns, _), slot) in &self.live {
            if ns == namespace
                && (slot.operation.as_ref().is_some_and(|op| {
                    targets_episode(kind, &payload, op.payload["id"].as_str().unwrap_or(""))
                }) || contains_revision(&payload, &slot.header.meta.id))
            {
                clock = clock.max(slot.header.meta.clock);
            }
        }
        let clock = clock
            .checked_add(1)
            .ok_or_else(|| Error("Logical clock exhausted".into()))?;
        ensure(
            clock <= 9_007_199_254_740_991,
            "Logical clock exceeds interoperable integer range",
        )?;
        let mut live_slot = crate::protocol::live_slot(namespace, kind, &payload)
            .filter(|_| self.authority.layout >= crate::protocol::LAYOUT)
            .filter(|_| {
                member
                    .member
                    .grant
                    .as_ref()
                    .is_none_or(|g| g.write_budget.is_none() && g.expires.is_none())
            });
        // Periodically anchor playback in durable history. Overwritten ticks never advance
        // admission's durable clock; every cold reader can validate the same bounded gap.
        if clock
            >= self
                .namespaces
                .get(namespace)
                .map_or(0, |n| n.clock)
                .saturating_add(1024)
        {
            live_slot = None;
        }
        let mut copies = Records::new();
        if live_slot.is_some() {
            let current = self
                .projected_episode(namespace, payload["id"].as_str().unwrap_or(""), now)?
                .query("getEpisode", &json!({"id": payload["id"]}))?;
            let informed = payload
                .get("expect")
                .is_some_and(|v| *v == current["positionRevision"]);
            let forward = payload["seconds"].as_f64().unwrap_or(0.0)
                >= current["seconds"].as_f64().unwrap_or(0.0);
            if current["positionBaseline"] == true
                || (!informed && (!forward || payload.get("expect").is_some()))
            {
                live_slot = None;
            } else {
                if payload.get("duration").is_none_or(Value::is_null)
                    && current["duration"].is_number()
                {
                    payload["duration"] = current["duration"].clone();
                }
                // Collapse an own causal chain to the exact durable predecessor. Cross-author
                // references remain exact and are retained below.
                if informed {
                    if let Some(previous) = self.live.values().find(|j| {
                        j.header.meta.author == self.me.id()
                            && current["positionRevision"] == j.header.meta.id
                    }) {
                        if let Some(op) = &previous.operation {
                            if let Some(expect) = op.payload.get("expect") {
                                payload["expect"] = expect.clone();
                            } else {
                                payload["expect"] = self
                                    .namespaces
                                    .get(namespace)
                                    .expect("namespace")
                                    .state
                                    .query("getEpisode", &json!({"id":payload["id"]}))?
                                    ["positionRevision"]
                                    .clone();
                            }
                        }
                    }
                }
            }
        }
        // Retain only targeted episode heads and explicit revision dependencies, including
        // nested completion events and another author's replaceable revision.
        for j in self
            .live
            .values()
            .filter(|j| j.header.meta.namespace == namespace)
        {
            let cited = contains_revision(&payload, &j.header.meta.id);
            if cited
                || (live_slot.is_none()
                    && j.operation.as_ref().is_some_and(|op| {
                        op.payload["id"]
                            .as_str()
                            .is_some_and(|id| targets_episode(kind, &payload, id))
                    }))
            {
                let stamp = j.header.live.as_ref().expect("live stamp");
                let path =
                    crate::protocol::live_state_path(&j.header.meta.author, namespace, &stamp.slot);
                copies.insert(
                    crate::protocol::operation_path(&j.header.meta),
                    read_live(&path)?,
                );
            }
        }
        let mut entropy = Entropy::new(seed);
        let nonce = entropy.take::<12>()?.to_vec();
        let mut operation = Operation {
            id: String::new(),
            kind: kind.into(),
            v: 1,
            clock,
            authority: self.authority.latest,
            created: now.into(),
            payload,
        };
        operation.id = operation_id(namespace, &self.me.id(), epoch, &nonce, &operation)?;
        let id = operation.id.clone();
        let meta = OperationMeta {
            protocol: crate::protocol::OPERATION.into(),
            library: self.id().into(),
            namespace: namespace.into(),
            author: self.me.id(),
            epoch,
            id: id.clone(),
            clock,
            authority: self.authority.latest,
            created: now.into(),
        };
        let live = live_slot.map(|slot| crate::model::LiveStamp {
            library_id: self.id().into(),
            slot,
            generation: clock,
            operation_id: id,
        });
        let ciphertext =
            crypto::seal(key, &nonce, &canonical(&operation)?, &operation_aad(&meta)?)?;
        let history = live.as_ref().map(|_| {
            crate::protocol::history_path(&meta.author, &meta.namespace, meta.clock, &meta.id)
        });
        let state = live.as_ref().map(|stamp| {
            crate::protocol::live_state_path(&meta.author, &meta.namespace, &stamp.slot)
        });
        let path = history
            .clone()
            .unwrap_or_else(|| crate::protocol::operation_path(&meta));
        let body = canonical(&OperationHeader {
            meta,
            nonce,
            ciphertext,
            live,
        })?;
        let aliases = match (history, state) {
            (Some(h), Some(s)) => vec![(h, s)],
            _ => Vec::new(),
        };
        Ok(Outcome::success(PendingBatch {
            steps: vec![SigningStep {
                path,
                body,
                signing: self.me.signing.clone(),
            }],
            aliases,
            copies,
        }))
    }
    /// Root-signed layout raise. New libraries already write layout 2 at creation.
    pub fn begin_layout(&self, layout: u32, now: &str) -> Result<Outcome<PendingBatch>> {
        if let Some(d) = self.root_denial() {
            return Ok(Outcome::failure(d));
        }
        ensure(layout >= self.authority.layout, "Layout cannot be lowered")?;
        ensure(layout >= 1, "Invalid layout")?;
        self.action(Action::Layout { layout }, now, "root")
            .map(Outcome::success)
    }
    /// Read a namespace after grant and expiry checks. Cached keys never override ended access.
    pub fn view(&self, namespace: &str, now: &str) -> Result<Outcome<NamespaceView>> {
        if let Some(denial) = self.authorize(namespace, Access::Read, now)? {
            return Ok(Outcome::failure(denial));
        }
        let epoch = self
            .authority
            .epoch_at(namespace, self.authority.latest)
            .ok_or_else(|| missing("epoch"))?;
        if !self.keys.contains_key(&(namespace.into(), epoch)) {
            return Ok(Outcome::failure(Denial::new(
                "notReadable",
                "The namespace key has not been unlocked",
            )));
        }
        let (judged, invalid) = self.evaluate();
        let mut view = NamespaceView {
            namespace: namespace.into(),
            admitted: Vec::new(),
            held: Vec::new(),
            refused: Vec::new(),
            state: json!({}),
        };
        for j in judged
            .iter()
            .filter(|j| j.header.meta.namespace == namespace)
        {
            let rejection = |reason: &str| Rejection {
                id: j.header.meta.id.clone(),
                author: j.header.meta.author.clone(),
                reason: reason.into(),
            };
            match &j.status {
                Status::Admitted => {
                    if let Some(operation) = &j.operation {
                        if !view
                            .admitted
                            .iter()
                            .any(|old| old.id == operation.id && old.author == operation.author)
                        {
                            view.admitted.push(operation.clone());
                        }
                    } else if self
                        .keys
                        .contains_key(&(namespace.into(), j.header.meta.epoch))
                    {
                        view.refused.push(rejection("invalidPayload"));
                    } else {
                        view.held.push(rejection("unavailable"));
                    }
                }
                Status::Held(reason) => view.held.push(rejection(reason)),
                Status::Refused(reason) => view.refused.push(rejection(reason)),
            }
        }
        view.refused.extend(
            invalid
                .into_iter()
                .filter(|(ns, _)| ns == namespace)
                .map(|(_, r)| r),
        );
        if let Some(state) = self.namespaces.get(namespace) {
            view.state = if self
                .live
                .values()
                .any(|j| j.header.meta.namespace == namespace)
            {
                self.projected(namespace, now)?.query("read", &json!({}))?
            } else {
                state.query("read", &json!({}))?
            };
        }
        Ok(Outcome::success(view))
    }
    fn operation_view(
        authority: &Authority,
        meta: &OperationMeta,
        operation: Operation,
    ) -> OperationView {
        let member = authority.members.get(&meta.author);
        OperationView {
            id: operation.id,
            kind: operation.kind,
            author: meta.author.clone(),
            author_label: member.map(|m| m.member.label.clone()).unwrap_or_default(),
            origin: if member.is_some_and(|m| m.member.kind == MemberKind::Agent) {
                "ai"
            } else {
                "person"
            }
            .into(),
            clock: operation.clock,
            created: operation.created,
            payload: operation.payload,
        }
    }
    /// Known members, with counts derived from signed admission, not mutable counters.
    pub fn members(&self) -> Vec<Member> {
        let (judged, _) = self.evaluate();
        self.authority
            .members
            .values()
            .map(|state| {
                let mut m = state.member.clone();
                m.writes = judged
                    .iter()
                    .filter(|j| j.header.meta.author == m.id && j.status == Status::Admitted)
                    .map(|j| &j.header.meta.id)
                    .collect::<BTreeSet<_>>()
                    .len() as u64;
                m
            })
            .collect()
    }
    /// This member, or an ungranted placeholder for a prospective identity.
    pub fn me(&self) -> Member {
        self.members()
            .into_iter()
            .find(|m| m.id == self.me.id())
            .unwrap_or(Member {
                id: self.me.id(),
                label: "Unapproved member".into(),
                kind: MemberKind::Device,
                grant: Some(Grant {
                    namespaces: vec![],
                    access: vec![],
                    expires: None,
                    write_budget: None,
                }),
                since: 0,
                revoked_at: None,
                writes: 0,
            })
    }
    /// Generate tools from module specs, filtering by this member's present grant.
    pub fn tools(&self, now: &str) -> Result<Vec<Spec>> {
        let mut tools = Vec::new();
        for ns in domain::NAMESPACES {
            if let Some(module) = domain::module(ns) {
                if self.authorize(ns, Access::Read, now)?.is_none() {
                    for mut spec in module
                        .queries()
                        .into_iter()
                        .chain(crate::imports::query_specs())
                    {
                        spec.name = format!("{ns}__{}", spec.name);
                        tools.push(spec);
                    }
                }
                if self.authorize(ns, Access::Write, now)?.is_none() {
                    for mut spec in module.operations() {
                        if !domain::role_allows(ns, &spec.name, self.me().kind) {
                            continue;
                        }
                        spec.name = format!("{ns}__{}", spec.name);
                        tools.push(spec);
                    }
                }
            }
        }
        Ok(tools)
    }
    /// Route a generated tool. Read results are immediate; writes return a host signing batch.
    pub fn begin_call(
        &self,
        tool: &str,
        input: Value,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<Call>> {
        let Some((ns, kind)) = tool.split_once("__") else {
            return Ok(Outcome::failure(Denial::new("unavailable", "Unknown tool")));
        };
        let Some(module) = domain::module(ns) else {
            return Ok(Outcome::failure(Denial::new(
                "unavailable",
                "Unknown module",
            )));
        };
        let spec = module
            .queries()
            .into_iter()
            .chain(module.operations())
            .find(|s| s.name == kind);
        let Some(spec) = spec else {
            return Ok(Outcome::failure(Denial::new("unavailable", "Unknown tool")));
        };
        ensure(
            domain::validate_input(&spec.input_schema, &input),
            "Tool input does not match schema",
        )?;
        if kind == "read" {
            Ok(map_outcome(self.view(ns, now)?, |v| Call::Read {
                value: json!(v),
            }))
        } else if module.queries().iter().any(|s| s.name == kind)
            || crate::imports::query_names().contains(&kind)
        {
            Ok(map_outcome(self.query(ns, kind, input, now)?, |value| {
                Call::Read { value }
            }))
        } else {
            Ok(map_outcome(
                self.begin_write(ns, kind, input, now, seed)?,
                |pending| Call::Write { pending },
            ))
        }
    }
    fn evaluate(&self) -> (Vec<&Judged>, Vec<(String, Rejection)>) {
        let mut judged: Vec<_> = self.judged.iter().collect();
        judged.sort_by(|a, b| order(&a.header.meta).cmp(&order(&b.header.meta)));
        (judged, self.invalid.values().cloned().collect())
    }
    fn ingest(&mut self, paths: &[String], mut replay: bool, invalidated: &[String]) {
        self.changes = ChangeSummary::default();
        let mut touched = BTreeSet::new();
        let mut candidates = Vec::new();
        let input: Vec<_> = paths
            .iter()
            .filter(|p| p.starts_with("ops/") || p.starts_with("state/"))
            .filter_map(|p| self.records.get(p).map(|r| (p.as_str(), r.as_slice())))
            .collect();
        let results = self
            .verifiers
            .operations(&self.authority, &input, None)
            .expect("portable verifier has no host failure");
        for ((path, raw), parsed) in input.into_iter().zip(results) {
            match parsed {
                Ok((header, digest)) => {
                    self.invalid.remove(path);
                    touched.insert(header.meta.namespace.clone());
                    candidates.push(Judged {
                        header,
                        digest,
                        operation: None,
                        opened: false,
                        status: Status::Admitted,
                        from_live_slot: path.starts_with("state/"),
                    });
                }
                Err(error) => {
                    // Best-effort location for UI only; these untrusted fields grant no capability.
                    let header = serde_json::from_slice::<SignedRecord>(raw)
                        .ok()
                        .and_then(|r| serde_json::from_slice::<OperationHeader>(&r.body).ok());
                    if let Some(header) = &header {
                        touched.insert(header.meta.namespace.clone());
                    }
                    self.invalid.insert(
                        path.to_owned(),
                        (
                            header
                                .as_ref()
                                .map(|h| h.meta.namespace.clone())
                                .unwrap_or_default(),
                            Rejection {
                                id: header
                                    .as_ref()
                                    .map(|h| h.meta.id.clone())
                                    .unwrap_or_else(|| path.to_owned()),
                                author: header.map(|h| h.meta.author).unwrap_or_default(),
                                reason: format!("invalidRecord: {error}"),
                            },
                        ),
                    );
                }
            }
        }
        candidates.sort_by(|a, b| order(&a.header.meta).cmp(&order(&b.header.meta)));
        let retained: BTreeSet<_> = candidates
            .iter()
            .filter(|c| {
                !c.from_live_slot
                    && self
                        .records
                        .get(&crate::protocol::operation_path(&c.header.meta))
                        .is_some_and(|raw| self.retains_live(&c.header, raw))
                    && !self.judged.iter().any(|j| {
                        j.header.meta.namespace == c.header.meta.namespace
                            && j.status != Status::Admitted
                    })
            })
            .map(|c| c.digest.clone())
            .collect();
        replay |= candidates.iter().any(|c| c.from_live_slot);
        // Namespace clock checks are independent. Only a capped author's grant-wide budget
        // adds an ordering dependency across namespaces. This permits cheap local appends to
        // a quieter namespace even when another namespace has a much higher clock.
        for candidate in &candidates {
            if retained.contains(&candidate.digest) {
                continue;
            }
            let meta = &candidate.header.meta;
            let before = |tail: &(u64, String, String)| {
                order(meta) <= (tail.0, tail.1.as_str(), tail.2.as_str())
            };
            replay |= self
                .admission
                .namespace_tails
                .get(&meta.namespace)
                .is_some_and(before);
            let capped = self
                .authority
                .members
                .get(&meta.author)
                .and_then(|m| m.member.grant.as_ref())
                .and_then(|g| g.write_budget)
                .is_some();
            replay |= capped
                && self
                    .admission
                    .author_tails
                    .get(&meta.author)
                    .is_some_and(before);
            // Duplicate candidates require agreed global order, including invalid copies.
            replay |= self
                .admission
                .authenticated_ids
                .contains(&(meta.author.clone(), meta.id.clone()));
        }
        let old_len = self.judged.len();
        self.judged.extend(candidates);
        if replay {
            self.judged
                .sort_by(|a, b| order(&a.header.meta).cmp(&order(&b.header.meta)));
            self.admission = Admission::default();
        }
        let start = if replay { 0 } else { old_len };
        let mut live_heads: Vec<(String, String, String, String)> = Vec::new();
        for j in &mut self.judged[start..] {
            let meta = &j.header.meta;
            if !j.opened
                && self
                    .keys
                    .contains_key(&(meta.namespace.clone(), meta.epoch))
            {
                Self::open_operation(&self.authority, &self.keys, j);
            }
            let meta = &j.header.meta;
            let is_live = j.header.live.is_some();
            let mut status =
                if !Self::budget_scope_complete(&self.authority, &self.read_scope, &meta.author) {
                    Status::Refused("budgetScopeUnavailable".into())
                } else {
                    Self::judge(
                        &self.authority,
                        meta,
                        &j.digest,
                        &mut self.admission.spent,
                        self.admission
                            .clocks
                            .get(&meta.namespace)
                            .copied()
                            .unwrap_or(0),
                        is_live,
                    )
                };
            if j.from_live_slot
                && status == Status::Admitted
                && self
                    .authority
                    .members
                    .get(&meta.author)
                    .is_some_and(|m| m.member.revoked_at.is_some())
            {
                status = Status::Refused("revoked".into());
            }
            if status == Status::Admitted && !j.from_live_slot {
                self.admission
                    .clocks
                    .entry(meta.namespace.clone())
                    .and_modify(|clock| *clock = (*clock).max(meta.clock))
                    .or_insert(meta.clock);
            }
            if status == Status::Admitted
                && j.operation.is_some()
                && !j.from_live_slot
                && !self
                    .admission
                    .authenticated_ids
                    .insert((meta.author.clone(), meta.id.clone()))
            {
                status = Status::Refused("duplicateID".into());
            }
            if status != j.status {
                touched.insert(meta.namespace.clone());
            }
            j.status = status;
            if j.from_live_slot && j.status == Status::Admitted {
                if let Some(stamp) = j.header.live.as_ref() {
                    live_heads.push((
                        j.header.meta.author.clone(),
                        j.header.meta.namespace.clone(),
                        stamp.slot.clone(),
                        j.header.meta.id.clone(),
                    ));
                }
            }
            if !j.from_live_slot {
                let tail = (meta.clock, meta.author.clone(), meta.id.clone());
                self.admission
                    .namespace_tails
                    .entry(meta.namespace.clone())
                    .and_modify(|old| {
                        if *old < tail {
                            *old = tail.clone();
                        }
                    })
                    .or_insert_with(|| tail.clone());
                self.admission
                    .author_tails
                    .entry(meta.author.clone())
                    .and_modify(|old| {
                        if *old < tail {
                            *old = tail.clone();
                        }
                    })
                    .or_insert(tail);
            }
        }
        for (author, namespace, slot, id) in live_heads {
            self.judged.retain(|old| {
                !(old.from_live_slot
                    && old.header.meta.author == author
                    && old.header.meta.namespace == namespace
                    && old.header.meta.id != id
                    && old.header.live.as_ref().map(|s| s.slot.as_str()) == Some(slot.as_str()))
            });
        }
        if replay {
            let mut grouped: BTreeMap<String, Vec<(&str, &OperationView)>> = BTreeMap::new();
            for j in &self.judged {
                if j.status == Status::Admitted && !j.from_live_slot {
                    if let Some(op) = &j.operation {
                        grouped
                            .entry(j.header.meta.namespace.clone())
                            .or_default()
                            .push((&j.digest, op));
                    }
                }
            }
            for ns in &self.authority.namespaces {
                let ops = grouped.get(ns).map(Vec::as_slice).unwrap_or(&[]);
                // During sequential unlock, do not replay a staged cache's namespace before
                // its current epoch key is available. Queries cannot read that namespace yet.
                let readable = self
                    .authority
                    .epoch_at(ns, self.authority.latest)
                    .is_some_and(|epoch| self.keys.contains_key(&(ns.clone(), epoch)));
                if self.pending_checkpoints.contains_key(ns) && !readable {
                    continue;
                }
                let restored = self
                    .pending_checkpoints
                    .get(ns)
                    .and_then(|bytes| self.decode_checkpoint(ns, bytes, ops).ok());
                // A failed cache is discarded, not retried indefinitely after a mismatch.
                self.pending_checkpoints.remove(ns);
                let state = self
                    .namespaces
                    .entry(ns.clone())
                    .or_insert_with(|| Namespace::new(ns));
                let changed = state.reconcile(ns, ops, &self.checkpoint_policy, restored, |op| {
                    self.authority.members.get(&op.author).map(|member| {
                        domain::AuthorContext::from_member(&member.member, &self.authority.id)
                    })
                });
                if changed || invalidated.contains(ns) || touched.contains(ns) {
                    state.revision += 1;
                    self.changes.namespaces.insert(ns.clone(), state.revision);
                }
            }
        } else {
            for j in &self.judged[start..] {
                let ns = &j.header.meta.namespace;
                if j.status == Status::Admitted && !j.from_live_slot {
                    if let Some(op) = &j.operation {
                        let view = op;
                        let state = self
                            .namespaces
                            .entry(ns.clone())
                            .or_insert_with(|| Namespace::new(ns));
                        let context = self.authority.members.get(&view.author).map(|member| {
                            domain::AuthorContext::from_member(&member.member, &self.authority.id)
                        });
                        if retained.contains(&j.digest) {
                            let position = self
                                .judged
                                .iter()
                                .filter(|other| {
                                    !other.from_live_slot
                                        && other.status == Status::Admitted
                                        && other.operation.is_some()
                                        && other.header.meta.namespace == *ns
                                        && order(&other.header.meta) < order(&j.header.meta)
                                })
                                .count();
                            state.insert_retained(&j.digest, view, context, position);
                        } else {
                            state.append(&j.digest, view, context, &self.checkpoint_policy);
                        }
                    }
                }
                let state = self
                    .namespaces
                    .entry(ns.clone())
                    .or_insert_with(|| Namespace::new(ns));
                self.changes
                    .namespaces
                    .entry(ns.clone())
                    .or_insert_with(|| {
                        state.revision += 1;
                        state.revision
                    });
            }
        }
        self.live.clear();
        for j in &self.judged {
            if j.from_live_slot && j.status == Status::Admitted && j.operation.is_some() {
                let stamp = j.header.live.as_ref().expect("verified live stamp");
                self.live.insert(
                    (
                        j.header.meta.author.clone(),
                        j.header.meta.namespace.clone(),
                        stamp.slot.clone(),
                    ),
                    j.clone(),
                );
            }
        }
        // Invalid records affect rejection queries even when they never enter admitted order.
        for ns in touched {
            if self.authority.namespaces.contains(&ns) && !self.changes.namespaces.contains_key(&ns)
            {
                let state = self
                    .namespaces
                    .entry(ns.clone())
                    .or_insert_with(|| Namespace::new(&ns));
                state.revision += 1;
                self.changes.namespaces.insert(ns, state.revision);
            }
        }
    }
    /// Build a current projection from immutable intent plus verified live heads. Never mutate
    /// the immutable reducer checkpoint with replaceable data; expiry is checked at query time.
    fn projected_episode(&self, namespace: &str, id: &str, now: &str) -> Result<domain::State> {
        let state = self
            .namespaces
            .get(namespace)
            .ok_or_else(|| missing("namespace"))?
            .state
            .playback_slice(id);
        self.overlay_live(namespace, now, Some(id), state)
    }
    fn projected(&self, namespace: &str, now: &str) -> Result<domain::State> {
        let state = self
            .namespaces
            .get(namespace)
            .ok_or_else(|| missing("namespace"))?
            .state
            .clone();
        self.overlay_live(namespace, now, None, state)
    }
    fn overlay_live(
        &self,
        namespace: &str,
        now: &str,
        episode: Option<&str>,
        mut state: domain::State,
    ) -> Result<domain::State> {
        let mut heads: Vec<_> = self
            .live
            .values()
            .filter(|j| {
                j.header.meta.namespace == namespace
                    && episode.is_none_or(|id| {
                        j.operation
                            .as_ref()
                            .is_some_and(|op| op.payload["id"].as_str() == Some(id))
                    })
            })
            .collect();
        heads.sort_by(|a, b| order(&a.header.meta).cmp(&order(&b.header.meta)));
        for j in heads {
            let Some(member) = self.authority.members.get(&j.header.meta.author) else {
                continue;
            };
            if member.member.revoked_at.is_some()
                || member
                    .member
                    .grant
                    .as_ref()
                    .is_some_and(|g| expired(&g.expires, now).unwrap_or(true))
            {
                continue;
            }
            let Some(op) = &j.operation else { continue };
            if !state.live_is_after(op) {
                continue;
            }
            state.apply_with_context(
                op,
                Some(&domain::AuthorContext::from_member(
                    &member.member,
                    &self.authority.id,
                )),
            );
        }
        Ok(state)
    }
    fn open_operation(
        authority: &Authority,
        keys: &BTreeMap<(String, u64), Vec<u8>>,
        j: &mut Judged,
    ) {
        let header = &j.header;
        let meta = &header.meta;
        j.opened = true;
        j.operation = keys
            .get(&(meta.namespace.clone(), meta.epoch))
            .and_then(|key| {
                let plain = crypto::open(
                    key,
                    &header.nonce,
                    &header.ciphertext,
                    &operation_aad(meta).ok()?,
                )
                .ok()?;
                let op: Operation = serde_json::from_slice(&plain).ok()?;
                if op.id != meta.id
                    || op.clock != meta.clock
                    || op.authority != meta.authority
                    || op.created != meta.created
                    || !op.payload.is_object()
                    || op.v != 1
                {
                    return None;
                }
                if operation_id(
                    &meta.namespace,
                    &meta.author,
                    meta.epoch,
                    &header.nonce,
                    &op,
                )
                .ok()?
                    != op.id
                {
                    return None;
                }
                if let Some(stamp) = &header.live {
                    if crate::protocol::live_slot(&meta.namespace, &op.kind, &op.payload).as_deref()
                        != Some(stamp.slot.as_str())
                    {
                        return None;
                    }
                }
                Some(Self::operation_view(authority, meta, op))
            });
        // Exact encrypted records remain in `records`; do not retain a second ciphertext copy.
        j.header.ciphertext = Vec::new();
    }
    fn judge(
        authority: &Authority,
        meta: &OperationMeta,
        digest: &str,
        spent: &mut BTreeMap<String, BTreeSet<String>>,
        clock: u64,
        is_live: bool,
    ) -> Status {
        let refuse = |s: &str| Status::Refused(s.into());
        let Some(member) = authority.members.get(&meta.author) else {
            return refuse("notGranted");
        };
        if meta.authority < member.member.since {
            return refuse("notGranted");
        }
        let is_root = authority.root_at(meta.authority.min(authority.latest)) == Some(&meta.author);
        if !authority.namespaces.contains(&meta.namespace) {
            return refuse("notGranted");
        }
        if !is_root
            && !member
                .member
                .grant
                .as_ref()
                .is_some_and(|g| g.allows(&meta.namespace, Access::Write))
        {
            return refuse("notGranted");
        }
        if is_live
            && member
                .member
                .grant
                .as_ref()
                .is_some_and(|g| g.write_budget.is_some() || g.expires.is_some())
        {
            return refuse("caveatedLiveWriter");
        }
        if let Some(grant) = &member.member.grant {
            if expired(&grant.expires, &meta.created).unwrap_or(true) {
                return refuse("expired");
            }
        }
        if let Some(revoked) = member.member.revoked_at {
            if !member.kept.contains(digest) {
                return if meta.authority >= revoked {
                    refuse("revoked")
                } else {
                    Status::Held("revokedBackdated".into())
                };
            }
        }
        if meta.authority > authority.latest {
            return Status::Held("authorityBehind".into());
        }
        if authority.epoch_at(&meta.namespace, meta.authority) != Some(meta.epoch) {
            return refuse("wrongEpoch");
        }
        // Bound each admitted header's forward jump, including a namespace's first header.
        // Replaceable ticks must be backed by a nearby durable anchor too.
        if meta.clock > 9_007_199_254_740_991 || meta.clock > clock.saturating_add(1024) {
            return refuse("clockJump");
        }
        let count = spent.entry(meta.author.clone()).or_default();
        if !is_root
            && member
                .member
                .grant
                .as_ref()
                .and_then(|g| g.write_budget)
                .is_some_and(|budget| !count.contains(&meta.id) && count.len() as u64 >= budget)
        {
            return refuse("budgetSpent");
        }
        count.insert(meta.id.clone());
        Status::Admitted
    }
    fn preserved_description(&self, author: &str, kept: &BTreeSet<String>) -> String {
        let mut contributions = BTreeMap::<(&str, &str), BTreeSet<(String, String)>>::new();
        for judged in self.evaluate().0 {
            if judged.header.meta.author != author || !kept.contains(&judged.digest) {
                continue;
            }
            let Some(op) = &judged.operation else {
                continue;
            };
            let namespace = judged.header.meta.namespace.clone();
            let names = domain::module(&namespace)
                .filter(|module| module.write_phrase(&op.kind).is_some())
                .map(|module| module.contribution_names(&op.kind))
                .unwrap_or(("update", "updates"));
            let id = op.payload["id"].as_str().unwrap_or(&op.id).to_owned();
            contributions
                .entry(names)
                .or_default()
                .insert((namespace, id));
        }
        let count: usize = contributions.values().map(BTreeSet::len).sum();
        if count == 0 {
            return "What it already read can't be unread.".into();
        }
        let parts: Vec<_> = contributions
            .into_iter()
            .map(|((one, many), ids)| {
                format!("{} {}", ids.len(), if ids.len() == 1 { one } else { many })
            })
            .collect();
        format!(
            "Its {} {}; what it already read can't be unread.",
            english_list(&parts),
            if count == 1 { "stays" } else { "stay" }
        )
    }
    /// Plain-language story in authority order, with writes ordered by date, author and ID per sequence.
    pub fn ledger(&self) -> Vec<LedgerEntry> {
        let mut ledger = Vec::new();
        let mut order = Vec::new();
        let mut previous_root = self.authority.root_at(1).unwrap_or("").to_owned();
        for entry in &self.authority.entries {
            let actor = if entry.by == "recovery" {
                self.authority.recovery.id()
            } else {
                previous_root.clone()
            };
            let label = self
                .authority
                .members
                .get(&actor)
                .map(|m| m.member.label.clone())
                .unwrap_or_else(|| "Recovery identity".into());
            let mut add = |event: &str, subject: Option<String>, text: String| {
                order.push((
                    entry.seq,
                    1u8,
                    [0; 7],
                    String::new(),
                    String::new(),
                    ledger.len(),
                ));
                ledger.push(LedgerEntry {
                    namespace: None,
                    kind: None,
                    origin: None,
                    sequence: ledger.len() as u64 + 1,
                    at: entry.issued.clone(),
                    actor: actor.clone(),
                    actor_label: label.clone(),
                    event: event.into(),
                    subject,
                    text,
                });
            };
            match &entry.action {
                Action::Genesis { namespaces, .. } => {
                    add("created", None, format!("{label} created this library. {} {} sealed with keys only its members hold.", capitalized(&namespace_names(namespaces)), if namespaces.len() == 1 { "is" } else { "are" }));
                }
                Action::Grant { request, grant, .. } => {
                    if let Ok(r) = authority::verify_request(request, self.id()) {
                        add(
                            "granted",
                            Some(r.member.id()),
                            format!(
                                "{label} let {} {}{}{}.",
                                r.label,
                                access_description(&grant.namespaces, &grant.access),
                                grant
                                    .write_budget
                                    .map(|b| format!(" with a budget of {b} writes"))
                                    .unwrap_or_default(),
                                grant
                                    .expires
                                    .as_ref()
                                    .map(|e| format!(" until {e}"))
                                    .unwrap_or_default(),
                            ),
                        );
                    }
                }
                Action::Revoke {
                    member_id,
                    kept,
                    epochs,
                } => {
                    let subject = self
                        .authority
                        .members
                        .get(member_id)
                        .map(|m| m.member.label.as_str())
                        .unwrap_or(member_id);
                    add(
                        "revoked",
                        Some(member_id.clone()),
                        format!(
                            "{label} ended {subject}'s access. {}",
                            self.preserved_description(member_id, kept)
                        ),
                    );
                    add(
                        "rekeyed",
                        Some(member_id.clone()),
                        rekey_description(epochs, Some(subject)),
                    );
                }
                Action::Rekey { epochs } => {
                    // Creation already explains the initial sealing of every namespace.
                    if epochs.iter().any(|epoch| epoch.epoch > 1) {
                        add("rekeyed", None, rekey_description(epochs, None));
                    }
                }
                Action::Reshare { recipient, .. } => add(
                    "rekeyed",
                    Some(recipient.id()),
                    format!("{label} shared the library’s past with its next owner."),
                ),
                Action::Handover { root, epochs, .. } => {
                    add(
                        "granted",
                        Some(root.id()),
                        format!("{label} handed over this library."),
                    );
                    add(
                        "rekeyed",
                        None,
                        rekey_description(epochs, Some("the former owner")),
                    );
                    previous_root = root.id();
                }
                Action::Recover { root, epochs, .. } => {
                    add(
                        "granted",
                        Some(root.id()),
                        "Recovery restored control of this library and access to its past.".into(),
                    );
                    add(
                        "rekeyed",
                        None,
                        rekey_description(epochs, Some("the former owner")),
                    );
                    previous_root = root.id();
                }
                Action::Layout { layout } => {
                    add(
                        "rekeyed",
                        None,
                        format!("{label} required storage layout {layout}."),
                    );
                }
            }
        }
        let mut requests = BTreeMap::new();
        let mut grant_sequences = BTreeMap::new();
        for (path, raw) in self
            .records
            .iter()
            .filter(|(p, _)| p.starts_with("requests/"))
        {
            if let Ok(request) = authority::verify_request(raw, self.id()) {
                if path == &format!("requests/{}.json", request.member.id()) {
                    requests.insert(request.member.id(), request);
                }
            }
        }
        // Approval retains the exact request, even if its standalone path was never synced.
        for entry in &self.authority.entries {
            if let Action::Grant { request, .. } = &entry.action {
                if let Ok(request) = authority::verify_request(request, self.id()) {
                    grant_sequences.insert(request.member.id(), entry.seq);
                    requests.insert(request.member.id(), request);
                }
            }
        }
        for request in requests.into_values() {
            let grant_sequence = grant_sequences
                .get(&request.member.id())
                .copied()
                .unwrap_or(self.authority.latest + 1);
            order.push((
                grant_sequence,
                0,
                time_key(&request.created).unwrap_or_default(),
                request.member.id(),
                String::new(),
                ledger.len(),
            ));
            ledger.push(LedgerEntry {
                namespace: None,
                kind: None,
                origin: None,
                sequence: ledger.len() as u64 + 1,
                at: request.created,
                actor: request.member.id(),
                actor_label: request.label.clone(),
                event: "requested".into(),
                subject: Some(request.member.id()),
                text: format!(
                    "{} asked to {}.",
                    request.label,
                    access_description(&request.namespaces, &request.access)
                ),
            });
        }
        let (judged, invalid) = self.evaluate();
        for j in judged {
            let meta = &j.header.meta;
            let label = self
                .authority
                .members
                .get(&meta.author)
                .map(|m| m.member.label.clone())
                .unwrap_or_default();
            let (event, text) = match &j.status {
                Status::Admitted => {
                    if self
                        .keys
                        .contains_key(&(meta.namespace.clone(), meta.epoch))
                        && j.operation.is_none()
                    {
                        (
                            "refused",
                            format!("{label} sent an update that could not be verified."),
                        )
                    } else {
                        (
                            "wrote",
                            format!(
                                "{label} {}.",
                                j.operation
                                    .as_ref()
                                    .and_then(|op| domain::module(&meta.namespace)?
                                        .write_phrase(&op.kind))
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| format!(
                                        "added an update to {}",
                                        namespace_name(&meta.namespace)
                                    ))
                            ),
                        )
                    }
                }
                Status::Held(reason) => (
                    "held",
                    format!(
                        "{label} has an update waiting: {}.",
                        admission_description(reason)
                    ),
                ),
                Status::Refused(reason) => (
                    "refused",
                    format!(
                        "{label}'s update is refused: {}.",
                        admission_description(reason)
                    ),
                ),
            };
            order.push((
                meta.authority,
                2,
                time_key(&meta.created).unwrap_or_default(),
                meta.author.clone(),
                meta.id.clone(),
                ledger.len(),
            ));
            ledger.push(LedgerEntry {
                namespace: (event == "wrote").then(|| meta.namespace.clone()),
                kind: (event == "wrote")
                    .then(|| j.operation.as_ref().map(|op| op.kind.clone()))
                    .flatten(),
                origin: (event == "wrote").then(|| {
                    if self
                        .authority
                        .members
                        .get(&meta.author)
                        .is_some_and(|member| member.member.kind == MemberKind::Agent)
                    {
                        "ai"
                    } else {
                        "person"
                    }
                    .into()
                }),
                sequence: ledger.len() as u64 + 1,
                at: meta.created.clone(),
                actor: meta.author.clone(),
                actor_label: label,
                event: event.into(),
                subject: Some(meta.id.clone()),
                text,
            });
        }
        for (_, r) in invalid {
            order.push((
                u64::MAX,
                3,
                [0; 7],
                r.author.clone(),
                r.id.clone(),
                ledger.len(),
            ));
            ledger.push(LedgerEntry {
                namespace: None,
                kind: None,
                origin: None,
                sequence: ledger.len() as u64 + 1,
                at: String::new(),
                actor: r.author,
                actor_label: "Unknown or invalid signer".into(),
                event: "refused".into(),
                subject: Some(r.id),
                text: "A record could not be verified.".into(),
            });
        }
        let mut ordered: Vec<_> = order.into_iter().zip(ledger).collect();
        ordered.sort_by(|a, b| a.0.cmp(&b.0));
        ordered
            .into_iter()
            .enumerate()
            .map(|(index, (_, mut entry))| {
                entry.sequence = index as u64 + 1;
                entry
            })
            .collect()
    }
}
fn namespace_name(namespace: &str) -> String {
    domain::module(namespace)
        .map(|module| module.display_name().to_owned())
        .unwrap_or_else(|| namespace.into())
}
fn namespace_names(namespaces: &[String]) -> String {
    let mut names: Vec<_> = namespaces
        .iter()
        .map(|namespace| namespace_name(namespace))
        .collect();
    names.sort();
    names.dedup();
    english_list(&names)
}
fn english_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [item] => item.clone(),
        [first, rest @ ..] => {
            let mut prefix = vec![first.clone()];
            prefix.extend_from_slice(&rest[..rest.len() - 1]);
            format!("{} and {}", prefix.join(", "), rest[rest.len() - 1])
        }
    }
}
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}
fn access_description(namespaces: &[String], access: &[Access]) -> String {
    format!(
        "{} {}",
        if access.contains(&Access::Write) {
            "read and write"
        } else {
            "read"
        },
        namespace_names(namespaces)
    )
}
fn rekey_description(epochs: &[Epoch], excluded: Option<&str>) -> String {
    let namespaces: Vec<_> = epochs.iter().map(|epoch| epoch.namespace.clone()).collect();
    format!(
        "{} {} rekeyed{}.",
        capitalized(&namespace_names(&namespaces)),
        if namespaces.len() == 1 { "was" } else { "were" },
        excluded
            .map(|subject| format!(" without {subject}"))
            .unwrap_or_default()
    )
}
fn admission_description(reason: &str) -> &str {
    match reason {
        "authorityBehind" => "more access history is needed",
        "revokedBackdated" => "it arrived after access ended and was not preserved",
        "notGranted" => "its author does not have permission here",
        "revoked" => "its author's access has ended",
        "expired" => "its author's permission has expired",
        "wrongEpoch" => "it uses a key that was not current",
        "budgetSpent" => "its author's write budget is spent",
        "clockJump" => "its logical clock jumps too far ahead",
        "duplicateID" => "another verified update already uses that identity",
        _ => "it could not be verified",
    }
}
/// Tool dispatch result; the host drives signing only for `Write`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Call {
    /// Immediate query result.
    Read {
        /// Query value.
        value: Value,
    },
    /// Prepared write action.
    Write {
        /// Signing steps.
        pending: PendingBatch,
    },
}
fn map_outcome<A, B>(outcome: Outcome<A>, f: impl FnOnce(A) -> B) -> Outcome<B> {
    match outcome {
        Outcome::Success { value, .. } => Outcome::success(f(value)),
        Outcome::Failure { reason, detail, .. } => Outcome::failure(Denial { reason, detail }),
    }
}
fn make_epoch(
    library: &str,
    ns: &str,
    epoch: u64,
    recipients: &[PublicIdentity],
    entropy: &mut Entropy,
) -> Result<Epoch> {
    validate_namespace(ns)?;
    let key = entropy.take::<32>()?;
    let mut seals = BTreeMap::new();
    for recipient in recipients {
        seals.insert(
            recipient.id(),
            SealedKey::seal(
                &recipient.agreement,
                &key,
                &authority::key_info(library, ns, epoch, &recipient.id()),
                entropy,
            )?,
        );
    }
    Ok(Epoch {
        namespace: ns.into(),
        epoch,
        seals,
    })
}
/// Immutable storage path of an operation.
pub use crate::protocol::operation_path;

fn decode_header(raw: &[u8]) -> Option<OperationHeader> {
    let record: SignedRecord = serde_json::from_slice(raw).ok()?;
    serde_json::from_slice(&record.body).ok()
}
fn operation_id(
    namespace: &str,
    author: &str,
    epoch: u64,
    nonce: &[u8],
    operation: &Operation,
) -> Result<String> {
    // Struct fields are in canonical key order; payload maps already use serde_json's
    // sorted map representation. Borrowing avoids a payload clone and an intermediate Value tree.
    #[derive(Serialize)]
    struct Plain<'a> {
        authority: u64,
        clock: u64,
        created: &'a str,
        id: &'a str,
        kind: &'a str,
        payload: &'a Value,
        v: u32,
    }
    #[derive(Serialize)]
    struct Preimage<'a> {
        author: &'a str,
        epoch: u64,
        namespace: &'a str,
        nonce: &'a [u8],
        operation: Plain<'a>,
        purpose: &'a str,
    }
    let preimage = Preimage {
        author,
        epoch,
        namespace,
        nonce,
        operation: Plain {
            authority: operation.authority,
            clock: operation.clock,
            created: &operation.created,
            id: "",
            kind: &operation.kind,
            payload: &operation.payload,
            v: operation.v,
        },
        purpose: crate::protocol::OPERATION_ID,
    };
    Ok(records::id(&serde_json::to_vec(&preimage)?))
}

fn order(meta: &OperationMeta) -> (u64, &str, &str) {
    (meta.clock, &meta.author, &meta.id)
}

#[derive(Serialize, Deserialize)]
struct CheckpointEnvelope {
    #[serde(with = "bytes")]
    body: Vec<u8>,
    #[serde(with = "bytes")]
    tag: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct CheckpointBody {
    version: u32,
    reducer_schema: u32,
    library: String,
    identity: String,
    namespace: String,
    epoch: u64,
    snapshot: Snapshot,
}
fn checkpoint_tag(key: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    // HKDF-Extract is HMAC-SHA256(salt=recipient-local checkpoint key, IKM=exact cache body).
    // A separate expansion label keeps this authentication purpose separate from wire crypto.
    let mut tag = vec![0; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(key), body)
        .expand(crate::protocol::CHECKPOINT, &mut tag)
        .map_err(|_| Error("Checkpoint authentication failed".into()))?;
    Ok(tag)
}

fn operation_aad(meta: &OperationMeta) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Aad<'a> {
        author: &'a str,
        authority: u64,
        clock: u64,
        created: &'a str,
        epoch: u64,
        id: &'a str,
        library: &'a str,
        namespace: &'a str,
        protocol: &'a str,
    }
    Ok(serde_json::to_vec(&Aad {
        author: &meta.author,
        authority: meta.authority,
        clock: meta.clock,
        created: &meta.created,
        epoch: meta.epoch,
        id: &meta.id,
        library: &meta.library,
        namespace: &meta.namespace,
        protocol: &meta.protocol,
    })?)
}

fn targets_episode(kind: &str, payload: &Value, id: &str) -> bool {
    match kind {
        "position" | "setState" | "episode" => payload["id"] == id,
        "completePlayback" => payload["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["episode"] == id)),
        _ => payload["episode"] == id,
    }
}

fn contains_revision(value: &Value, id: &str) -> bool {
    match value {
        Value::String(s) => s == id,
        Value::Array(values) => values.iter().any(|v| contains_revision(v, id)),
        Value::Object(values) => values.values().any(|v| contains_revision(v, id)),
        _ => false,
    }
}
