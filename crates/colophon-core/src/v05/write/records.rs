//! Record-side builders (§9.2, §9.4, §9.5, §11): epochs and their seals, the `/5` operation
//! (prepare, then finish), the record fields of `rekey`, `grant`, `renew` and `revoke`
//! entries, and proposals' resolutions.
//!
//! **What the host is trusted with, exactly.** Every secret here is an [`EpochKey`]: an opaque
//! handle bound to an account, a namespace and an epoch (see `v05::records` for its
//! guarantees). A new epoch key is made from the 32-byte seed the host passes in, so a host
//! that remembers the seed can recompute the key. The core never returns, logs or serializes a
//! key, never seals one to a key the caller names (the recipients come from the verified
//! authority state: the current vault and the members §7.1 names, plus, for a `grant`, the
//! member of the verified request the entry admits), and encrypts only the one operation a
//! [`PreparedOperation`] describes, under the key bound to that operation's account,
//! namespace and epoch. Hosts MUST pass a fresh seed per action; a repeated seed repeats the
//! key and the nonce, and prepare refuses a nonce already used under the same key by a header
//! it can see.
//!
//! **Prepare, then finish.** Prepared state has private fields and read-only accessors. The
//! only thing a host can change between the two calls is the signature, and `finish` judges
//! the exact envelope it is about to return (parse, signature, binding, path, admission steps
//! 1–8 and opening) through the verifier's own code in `v05::records`. It returns nothing
//! unless the header is admitted and authenticates under the key. `prepare` runs the same
//! judgement on the unsigned header so a host is not asked to sign what `finish` will refuse.
//!
//! No RNG and no clock: seeds and the time are arguments.
use super::authority::{prepare_signed, PendingBatch};
use super::{format_date, Kind, KeptHead, SignatureResult, SigningStep};
use crate::crypto::Entropy;
use crate::v05::encoding::{bounds, canonical, encode_base64};
use crate::v05::history::Objects;
use crate::v05::ids::AccountId;
use crate::v05::members::Request;
use crate::v05::records::{
    chain_heads, epoch_info, judge_core, operation_id, revocation_reach, verified_headers,
    EpochKey, EpochKeys, HeldRecord, HeaderFormat, Judgement, Level, RecordAuthority,
};
use crate::v05::terms::{Access, Terms, TermsKind};
use crate::v05::vault::SealedBox;
use crate::v05::{malformed, require, Failure, Reason, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn seal_json(
    account: &AccountId,
    key: &EpochKey,
    recipient_id: &str,
    agreement: &[u8],
    entropy: &mut Entropy,
) -> Result<Value> {
    let info = epoch_info(account, key.namespace(), key.epoch(), recipient_id);
    let sealed = SealedBox::seal_public(agreement, key.expose(), &info, entropy)?;
    serde_json::to_value(&sealed).map_err(|e| malformed(e.to_string()))
}

fn entropy_error(e: crate::Error) -> Failure {
    malformed(format!("entropy: {e}"))
}

fn sorted_distinct(namespaces: &[String]) -> Result<Vec<String>> {
    let mut v = namespaces.to_vec();
    v.sort();
    v.dedup();
    require(v.len() == namespaces.len(), "namespaces must be distinct")?;
    Ok(v)
}

/// Build one new epoch for each of `namespaces` (§11.1), introduced by an entry issued at
/// `issued_ms`: epoch `latest + 1`, sealed to exactly the recipients the verified state names
/// (§7.1), `exclude` left out. Returns the epoch objects (sorted by namespace) for the entry
/// and the new keys.
pub fn build_epochs(
    auth: &RecordAuthority,
    namespaces: &[String],
    issued_ms: i64,
    exclude: Option<&str>,
    seed: [u8; 32],
) -> Result<(Vec<Value>, EpochKeys)> {
    let namespaces = sorted_distinct(namespaces)?;
    let mut entropy = Entropy::new(seed);
    let mut epochs = Vec::new();
    let mut keys = EpochKeys::new();
    for ns in namespaces {
        require(
            auth.namespaces().contains(&ns),
            "a namespace the account does not declare",
        )?;
        let epoch = auth
            .latest_epoch(&ns)
            .checked_add(1)
            .ok_or_else(|| malformed("epoch overflow"))?;
        require(epoch <= bounds::MAX_INTEGER, "epoch too large")?;
        let mut bytes = entropy.take::<32>().map_err(entropy_error)?;
        let key = EpochKey::from_secret(auth.account(), &ns, epoch, bytes);
        bytes = [0; 32];
        std::hint::black_box(&bytes);
        let mut seals = serde_json::Map::new();
        for r in auth.recipients(&ns, issued_ms, exclude) {
            seals.insert(
                r.id.clone(),
                seal_json(auth.account(), &key, &r.id, &r.agreement, &mut entropy)?,
            );
        }
        epochs.push(json!({"namespace": ns, "epoch": epoch, "seals": seals}));
        keys.insert(key);
    }
    Ok((epochs, keys))
}

/// Seal the held keys for `(namespace, epoch)` pairs to one member (§9.2 `shares`, §9.4).
fn shares_for(
    auth: &RecordAuthority,
    keys: &EpochKeys,
    member_id: &str,
    agreement: &[u8],
    wanted: &BTreeSet<(String, u64)>,
    seed: [u8; 32],
) -> Result<Vec<Value>> {
    let mut entropy = Entropy::new(seed);
    let mut by_ns: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (ns, e) in wanted {
        by_ns.entry(ns.clone()).or_default().push(*e);
    }
    let mut out = Vec::new();
    for (ns, epochs) in by_ns {
        for epoch in epochs {
            let key = keys.get(auth.account(), &ns, epoch).ok_or_else(|| {
                Failure::Unavailable(format!("the epoch key for {ns} epoch {epoch} is not held"))
            })?;
            let seal = seal_json(auth.account(), key, member_id, agreement, &mut entropy)?;
            out.push(json!({"namespace": ns, "epoch": epoch, "seals": {member_id: seal}}));
        }
    }
    Ok(out)
}

/// `rekey` (§8.2, §11.1): new epochs for `namespaces`, sealed to the vault and the active
/// members with access. Returns the batch to sign and the new epoch keys. The first `rekey`
/// (seq 2) must introduce epoch 1 in every declared namespace; prepare refuses anything else.
pub fn prepare_rekey(
    objects: &Objects,
    now_ms: i64,
    signers: &[String],
    issued_ms: i64,
    namespaces: &[String],
    seed: [u8; 32],
) -> Result<(PendingBatch, EpochKeys)> {
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    auth.require_clean()?;
    if auth.authority_seq() == 1 {
        let all: BTreeSet<&String> = auth.namespaces().iter().collect();
        let asked: BTreeSet<&String> = namespaces.iter().collect();
        require(
            all == asked,
            "the first rekey must introduce epoch 1 in every declared namespace",
        )?;
    }
    let (epochs, keys) = build_epochs(&auth, namespaces, issued_ms, None, seed)?;
    let batch = prepare_signed(objects, now_ms, Kind::Rekey { epochs }, issued_ms, signers)?;
    Ok((batch, keys))
}

/// `grant` (§9.2): `shares` seal every historical epoch of every granted namespace to the
/// member's agreement key, taken from the verified request. `keys` must hold each of those
/// epoch keys (opened with [`RecordAuthority::open_epoch`] or made by this account's builders).
pub fn prepare_grant(
    objects: &Objects,
    now_ms: i64,
    signers: &[String],
    issued_ms: i64,
    request: &[u8],
    terms: Value,
    keys: &EpochKeys,
    seed: [u8; 32],
) -> Result<PendingBatch> {
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    auth.require_clean()?;
    let req = Request::parse(request, true)?;
    require(
        &req.account == auth.account(),
        "the request names another account",
    )?;
    let parsed = Terms::parse(terms.clone(), TermsKind::Member)?;
    let mut wanted = BTreeSet::new();
    for entry in parsed.records().unwrap_or_default() {
        for e in 1..=auth.latest_epoch(&entry.namespace) {
            wanted.insert((entry.namespace.clone(), e));
        }
    }
    let shares = shares_for(
        &auth,
        keys,
        &req.member_id(),
        &req.agreement,
        &wanted,
        seed,
    )?;
    prepare_signed(
        objects,
        now_ms,
        Kind::Grant {
            request: request.to_vec(),
            terms,
            shares,
        },
        issued_ms,
        signers,
    )
}

/// `renew` (§9.4): `shares` seal every epoch in the member's `records` scope that no earlier
/// epoch object sealed to it, including epochs introduced while it was expired.
#[allow(clippy::too_many_arguments)]
pub fn prepare_renew(
    objects: &Objects,
    now_ms: i64,
    signers: &[String],
    issued_ms: i64,
    member: &str,
    expires: &str,
    keys: &EpochKeys,
    seed: [u8; 32],
) -> Result<PendingBatch> {
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    auth.require_clean()?;
    let m = auth
        .member(member)
        .ok_or_else(|| malformed("the member does not exist"))?;
    let mut wanted = BTreeSet::new();
    for entry in m.terms.records().unwrap_or_default() {
        for e in 1..=auth.latest_epoch(&entry.namespace) {
            if !auth.sealed_to(&entry.namespace, e).contains(member) {
                wanted.insert((entry.namespace.clone(), e));
            }
        }
    }
    let agreement = m.request.agreement.clone();
    let shares = shares_for(&auth, keys, member, &agreement, &wanted, seed)?;
    prepare_signed(
        objects,
        now_ms,
        Kind::Renew {
            member: member.to_string(),
            expires: expires.to_string(),
            shares,
        },
        issued_ms,
        signers,
    )
}

/// Which of a revoked member's records the revocation keeps (§9.5).
#[derive(Clone, Debug)]
pub enum Keep {
    /// Every header the host holds: each namespace's maximal `/5` heads (every fork head, at
    /// most 16 per namespace) go in `heads`, and every legacy `/3` header's digest in `kept`.
    /// More than 16 maximal heads in a namespace is refused: say what to keep with
    /// [`Keep::Explicit`].
    Everything,
    /// Exactly these `kept` digests and `heads`. Each head must name a held header of the
    /// member in that namespace.
    Explicit {
        /// Digests kept by name.
        kept: Vec<String>,
        /// Walk starting points.
        heads: Vec<KeptHead>,
    },
    /// Nothing is kept.
    Nothing,
}

/// A prepared `revoke` with the record-side fields it computed.
#[derive(Debug)]
pub struct PreparedRevoke {
    batch: PendingBatch,
    keys: EpochKeys,
    kept: Vec<String>,
    heads: Vec<KeptHead>,
    walk_incomplete: bool,
}
impl PreparedRevoke {
    /// The batch to sign.
    pub fn batch(&self) -> &PendingBatch {
        &self.batch
    }
    /// Take the batch (to `finish` it) and the new epoch keys.
    pub fn into_parts(self) -> (PendingBatch, EpochKeys) {
        (self.batch, self.keys)
    }
    /// The `kept` digests in the entry.
    pub fn kept(&self) -> &[String] {
        &self.kept
    }
    /// The `heads` in the entry.
    pub fn heads(&self) -> &[KeptHead] {
        &self.heads
    }
    /// True when a walk from a head meets a header this host does not hold: readers will hold
    /// the member's other records as `unavailable` until it is found (§9.5).
    pub fn walk_incomplete(&self) -> bool {
        self.walk_incomplete
    }
}

/// `revoke` (§9.5): the member's readable namespaces get a new epoch sealed without it, and
/// `kept` and `heads` are computed from `held` under `keep`.
#[allow(clippy::too_many_arguments)]
pub fn prepare_revoke(
    objects: &Objects,
    held: &[HeldRecord],
    now_ms: i64,
    signers: &[String],
    issued_ms: i64,
    member: &str,
    keep: &Keep,
    seed: [u8; 32],
) -> Result<PreparedRevoke> {
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    auth.require_clean()?;
    let m = auth
        .member(member)
        .ok_or_else(|| malformed("the member does not exist"))?;
    let headers: Vec<_> = verified_headers(&auth, held)
        .into_iter()
        .filter(|h| h.author == member)
        .collect();
    let (kept, heads) = match keep {
        Keep::Nothing => (Vec::new(), Vec::new()),
        Keep::Everything => {
            let mut namespaces: BTreeSet<&str> = BTreeSet::new();
            for h in &headers {
                namespaces.insert(&h.namespace);
            }
            let mut heads = Vec::new();
            for ns in namespaces {
                let tips = chain_heads(&headers, member, ns);
                require(
                    tips.len() <= 16,
                    "more than 16 maximal heads in a namespace: choose what to keep explicitly",
                )?;
                heads.extend(tips.into_iter().map(|digest| KeptHead {
                    namespace: ns.to_string(),
                    digest,
                }));
            }
            let mut kept: Vec<String> = headers
                .iter()
                .filter(|h| h.format == HeaderFormat::V3)
                .map(|h| h.digest.clone())
                .collect();
            kept.sort();
            kept.dedup();
            (kept, heads)
        }
        Keep::Explicit { kept, heads } => {
            let mut kept = kept.clone();
            kept.sort();
            kept.dedup();
            require(
                kept.iter().all(|d| crate::v05::encoding::is_digest(d)),
                "kept entries must be digests",
            )?;
            let mut heads = heads.clone();
            heads.sort_by(|a, b| (&a.namespace, &a.digest).cmp(&(&b.namespace, &b.digest)));
            heads.dedup();
            let mut per: BTreeMap<&str, usize> = BTreeMap::new();
            for h in &heads {
                *per.entry(&h.namespace).or_default() += 1;
                require(
                    headers
                        .iter()
                        .any(|x| x.digest == h.digest && x.namespace == h.namespace),
                    "a head must name a held header of the member in its namespace",
                )?;
            }
            require(
                per.values().all(|n| *n <= 16),
                "more than 16 heads in a namespace",
            )?;
            (kept, heads)
        }
    };
    let pairs: Vec<(String, String)> = heads
        .iter()
        .map(|h| (h.namespace.clone(), h.digest.clone()))
        .collect();
    let (_, walk_incomplete) = revocation_reach(&headers, member, &kept, &pairs);
    let readable: Vec<String> = m
        .terms
        .records()
        .unwrap_or_default()
        .iter()
        .map(|e| e.namespace.clone())
        .collect();
    let (epochs, keys) = build_epochs(&auth, &readable, issued_ms, Some(member), seed)?;
    let batch = prepare_signed(
        objects,
        now_ms,
        Kind::Revoke {
            member: member.to_string(),
            kept: kept.clone(),
            heads: heads.clone(),
            epochs,
        },
        issued_ms,
        signers,
    )?;
    Ok(PreparedRevoke {
        batch,
        keys,
        kept,
        heads,
        walk_incomplete,
    })
}

// ---------------------------------------------------------------------------------------------
// The `/5` operation.

/// What to write (§11.2, §11.3).
#[derive(Clone, Debug)]
pub struct OperationSpec<'a> {
    /// The namespace.
    pub namespace: &'a str,
    /// The author's member ID: the signer.
    pub author: &'a str,
    /// `write` or `propose`.
    pub level: Level,
    /// The operation kind.
    pub kind: &'a str,
    /// The payload.
    pub payload: Value,
    /// An explicit clock: it must exceed the highest admitted clock in the namespace and be at
    /// most 1,024 above it. `None`: one past the highest admitted clock (§11.4).
    pub clock: Option<u64>,
}

/// A prepared `/5` header, to sign `raw` by the author's member key. Fields are private;
/// `finish` judges the exact bytes it returns.
#[derive(Debug)]
pub struct PreparedOperation {
    step: SigningStep,
    auth: RecordAuthority,
    held: Vec<HeldRecord>,
    key: EpochKey,
    body: Vec<u8>,
    path: String,
}
/// A finished operation: admitted, and authenticated under its epoch key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishedOperation {
    /// Where it is stored.
    pub path: String,
    /// The envelope bytes.
    pub envelope: Vec<u8>,
    /// The header body digest (the next header's `previous`).
    pub digest: String,
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Write => "write",
        Level::Propose => "propose",
    }
}

fn unsigned_envelope(body: &[u8]) -> Result<Vec<u8>> {
    canonical(&json!({"body": encode_base64(body), "signature": encode_base64(&[0u8; 64])}))
}

fn judged_ok(judgement: &Judgement, path: &str) -> Result<()> {
    let j = judgement
        .records
        .iter()
        .find(|j| j.path == path)
        .ok_or_else(|| malformed("the header was not judged"))?;
    match j.outcome.failure() {
        Some(f) => Err(f),
        None if j.plaintext.is_some() => Ok(()),
        None => Err(malformed("the header did not authenticate")),
    }
}

/// Prepare a `/5` operation (§11.2): the header with its AAD, the nonce from `seed`, the
/// ciphertext, and the exact bytes the author's member key signs. `held` is every header the
/// host holds (the author chain, the highest admitted clock, the budget and the nonces are
/// read from it). Refused here, not at finish: a forked author chain (more than one maximal
/// head: the writer MUST stop, §11.2), a missing epoch key, a header the verifier would refuse.
pub fn prepare_operation(
    objects: &Objects,
    held: &[HeldRecord],
    keys: &EpochKeys,
    now_ms: i64,
    spec: &OperationSpec<'_>,
    seed: [u8; 32],
) -> Result<PreparedOperation> {
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    auth.require_clean()?;
    let account = auth.account().clone();
    let member = auth
        .member(spec.author)
        .ok_or_else(|| Failure::Refused(Reason::NotGranted))?;
    let signing = member.request.signing.clone();
    require(
        crate::v05::terms::valid_namespace(spec.namespace),
        "invalid namespace",
    )?;
    let authority = auth.authority_seq();
    let epoch = auth
        .epoch_at(spec.namespace, authority)
        .ok_or_else(|| malformed("the namespace has no epoch yet"))?;
    let key = keys
        .get(&account, spec.namespace, epoch)
        .ok_or_else(|| Failure::Unavailable("the epoch key is not held".into()))?
        .clone();
    // What the host holds: the clock, the chain, the nonces.
    let before = judge_core(&auth, keys, held, None);
    let highest = before
        .records
        .iter()
        .filter(|j| j.reserved && j.namespace.as_deref() == Some(spec.namespace))
        .map(|j| j.clock)
        .max()
        .unwrap_or(0);
    let clock = match spec.clock {
        None => highest
            .checked_add(1)
            .ok_or_else(|| malformed("clock overflow"))?,
        Some(c) => {
            require(c > highest, "an explicit clock must exceed the highest admitted")?;
            require(
                c - highest <= 1_024,
                "an explicit clock more than 1,024 above the highest admitted is refused (clockJump)",
            )?;
            c
        }
    };
    require(
        (1..=bounds::MAX_INTEGER).contains(&clock),
        "clock out of range",
    )?;
    let headers = verified_headers(&auth, held);
    let tips = chain_heads(&headers, spec.author, spec.namespace);
    if tips.len() > 1 {
        return Err(Failure::Refused(Reason::Fork));
    }
    let previous = tips.into_iter().next();
    let nonce = Entropy::new(seed).take::<12>().map_err(entropy_error)?;
    require(
        !headers
            .iter()
            .any(|h| h.namespace == spec.namespace && h.epoch == epoch && h.nonce == nonce),
        "that nonce is already used under this epoch key: pass a fresh seed",
    )?;
    let created = format_date(now_ms);
    let mut plain = json!({
        "id": "", "kind": spec.kind, "v": 1, "clock": clock,
        "authority": authority, "created": created, "payload": spec.payload,
    });
    let id = operation_id(spec.namespace, spec.author, epoch, &nonce, &plain)?;
    plain["id"] = json!(id);
    let plain_bytes = canonical(&plain)?;
    // The AAD is the verifier's own: build the header without its ciphertext.
    let level = spec.level;
    let sketch = crate::v05::records::OperationHeader {
        body: Vec::new(),
        account: account.clone(),
        namespace: spec.namespace.to_string(),
        author: spec.author.to_string(),
        epoch,
        id: id.clone(),
        clock,
        authority,
        created: (created.clone(), now_ms),
        level,
        previous: previous.clone(),
        nonce: nonce.to_vec(),
        ciphertext: Vec::new(),
        live: None,
        unknown: Default::default(),
    };
    let aad = sketch.aad()?;
    let ciphertext = seal_operation(&key, &nonce, &plain_bytes, &aad)?;
    let body = canonical(&json!({
        "protocol": "colophon/operation/5",
        "account": account.as_str(),
        "namespace": spec.namespace,
        "author": spec.author,
        "epoch": epoch,
        "id": id,
        "clock": clock,
        "authority": authority,
        "created": created,
        "level": level_name(level),
        "previous": previous,
        "nonce": encode_base64(&nonce),
        "ciphertext": encode_base64(&ciphertext),
    }))?;
    require(
        body.len() <= bounds::OPERATION_HEADER_BODY,
        "operation header exceeds its bound",
    )?;
    let path = crate::v05::records::operation_path(spec.author, spec.namespace, clock, &id);
    // Judge the unsigned header exactly as finish will judge the signed one.
    let mut with = held.to_vec();
    with.push(HeldRecord {
        path: path.clone(),
        bytes: unsigned_envelope(&body)?,
    });
    let mut only = EpochKeys::new();
    only.insert(key.clone());
    judged_ok(&judge_core(&auth, &only, &with, Some(&path)), &path)?;
    let step = SigningStep::for_call(
        path.clone(),
        body.clone(),
        spec.author.to_string(),
        signing,
        None,
    );
    Ok(PreparedOperation {
        step,
        auth,
        held: held.to_vec(),
        key,
        body,
        path,
    })
}

fn seal_operation(key: &EpochKey, nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    aes_gcm::Aes256Gcm::new_from_slice(key.expose())
        .map_err(|_| malformed("epoch key"))?
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce),
            Payload { msg: plain, aad },
        )
        .map_err(|_| malformed("encryption failed"))
}

impl PreparedOperation {
    /// The signing step: the header body, the author as signer.
    pub fn step(&self) -> &SigningStep {
        &self.step
    }
    /// Where the finished header is stored.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Assemble the envelope from the host's signature, judge it as a reader would (parse,
    /// signature under the author's key, binding, path, admission, opening) and return it
    /// only when it is admitted and authenticates under the epoch key.
    pub fn finish(self, signature: SignatureResult) -> Result<FinishedOperation> {
        if signature.assertion.is_some() {
            return Err(malformed("an operation header is signed raw"));
        }
        require(signature.signature.len() == 64, "a raw signature is 64 bytes")?;
        let envelope = canonical(
            &json!({"body": encode_base64(&self.body), "signature": encode_base64(&signature.signature)}),
        )?;
        let mut with = self.held.clone();
        with.push(HeldRecord {
            path: self.path.clone(),
            bytes: envelope.clone(),
        });
        let mut only = EpochKeys::new();
        only.insert(self.key.clone());
        let judgement = judge_core(&self.auth, &only, &with, None);
        judged_ok(&judgement, &self.path)?;
        let digest = crate::v05::encoding::digest(&self.body);
        Ok(FinishedOperation {
            path: self.path,
            envelope,
            digest,
        })
    }
}

/// `colophon.accept` / `colophon.decline` (§11.6): a `write` record in the proposals'
/// namespace naming 1–64 proposals. Prepare refuses what the fold would not count: a proposal
/// the host does not hold (admitted and authenticated), a kind the author may not `write`,
/// and a clock that does not exceed every named proposal's.
#[allow(clippy::too_many_arguments)]
pub fn prepare_resolution(
    objects: &Objects,
    held: &[HeldRecord],
    keys: &EpochKeys,
    now_ms: i64,
    author: &str,
    namespace: &str,
    accept: bool,
    proposals: &[String],
    clock: Option<u64>,
    seed: [u8; 32],
) -> Result<PreparedOperation> {
    require(
        (1..=64).contains(&proposals.len()),
        "a resolution names 1 to 64 proposals",
    )?;
    let ids: BTreeSet<&String> = proposals.iter().collect();
    require(ids.len() == proposals.len(), "proposals must be distinct")?;
    let auth = RecordAuthority::from_objects(objects, now_ms)?;
    auth.require_clean()?;
    let judgement = judge_core(&auth, keys, held, None);
    let member = auth
        .member(author)
        .ok_or_else(|| Failure::Refused(Reason::NotGranted))?;
    let mut highest_named = 0;
    for id in proposals {
        let p = judgement
            .proposals
            .iter()
            .find(|p| p.namespace == namespace && &p.id == id)
            .ok_or_else(|| Failure::Unavailable("a named proposal is not held".into()))?;
        let may = member.terms.records().is_some_and(|rs| {
            rs.iter().any(|e| {
                e.namespace == namespace
                    && e.access >= Access::Write
                    && e.kinds
                        .as_ref()
                        .is_none_or(|k| k.iter().any(|x| x == &p.kind))
            })
        });
        require_ok(may, Failure::Refused(Reason::NotGranted))?;
        highest_named = highest_named.max(p.clock);
    }
    if let Some(c) = clock {
        require(
            c > highest_named,
            "the resolution's clock must exceed every named proposal's",
        )?;
    }
    prepare_operation(
        objects,
        held,
        keys,
        now_ms,
        &OperationSpec {
            namespace,
            author,
            level: Level::Write,
            kind: if accept {
                "colophon.accept"
            } else {
                "colophon.decline"
            },
            payload: json!({"proposals": proposals}),
            clock,
        },
        seed,
    )
}

fn require_ok(ok: bool, failure: Failure) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(failure)
    }
}
