//! Sans-IO home admission and pending exchange (§§13–14).
//!
//! The host atomically persists the returned state even for a refusal (first-seen facts and
//! permanent late decisions matter). Receipt bodies are signing requests; `finish_receipt`
//! verifies the host's signature before publishing it. No private keys or IO live here.
use super::envelope::{embedded_bytes, AuthEnvelope};
use super::state::{self, HeadSet};
use super::{parse_entry, verify_history, Objects, Persisted, State, Stop};
use crate::v05::descriptor::Role;
use crate::v05::encoding::{bounds, canonical, date, Obj};
use crate::v05::signature::RawEnvelope;
use crate::v05::{bad_signature, malformed, require, Failure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const WINDOW: i64 = 300_000;
const WEEK: i64 = 7 * 86_400_000;

/// A named local admission refusal. Verification failures retain their §1 code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A parse, authentication or authority failure.
    Verification(Failure),
    /// `refused:early`.
    Early,
    /// `refused:late` (including a persisted permanent late-activation decision).
    Late,
    /// `refused:proposerFull`.
    ProposerFull,
    /// `refused:pendingFull`.
    PendingFull,
    /// `refused:vetoFull`.
    VetoFull,
    /// §14 409: an overlapping different body or a sequence gap.
    Conflict,
    /// §14 421: no primary head covers this immediate entry.
    PrimaryRequired(Vec<String>),
}
impl Refusal {
    /// Stable result spelling; transport adapters map the last two to 409 and 421.
    pub fn code(&self) -> String {
        match self {
            Self::Verification(f) => f.code(),
            Self::Early => "refused:early".into(),
            Self::Late => "refused:late".into(),
            Self::ProposerFull => "refused:proposerFull".into(),
            Self::PendingFull => "refused:pendingFull".into(),
            Self::VetoFull => "refused:vetoFull".into(),
            Self::Conflict => "conflict".into(),
            Self::PrimaryRequired(_) => "primaryRequired".into(),
        }
    }
}
impl From<Failure> for Refusal {
    fn from(f: Failure) -> Self {
        Self::Verification(f)
    }
}
type AdmitResult<T> = std::result::Result<T, Refusal>;

/// A closed interval in milliseconds during which the home served this account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServingInterval {
    /// First serving instant.
    pub from_ms: i64,
    /// Last serving instant; `None` means still serving.
    pub through_ms: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Fact {
    first_seen_ms: i64,
    serving: Vec<ServingInterval>,
    refuse_activation: bool,
}
/// One immutable pending listing item. Cursors belong to this home, never to the account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingObject {
    /// Monotonic, never reused.
    pub seq: u64,
    /// Body digest.
    pub digest: String,
    /// `transition`, `veto`, or `receipt`.
    pub kind: String,
    /// Exact first stored envelope bytes.
    pub envelope: Vec<u8>,
    target: String,
    /// For a transition, its proposer's unit (§13.1 step 1); for a veto, its signers' units.
    units: BTreeSet<String>,
    expires_ms: Option<i64>,
}
/// A complete pending page at the instant the caller supplied its state.
#[derive(Clone, Debug)]
pub struct PendingPage {
    /// Up to the requested limit.
    pub objects: Vec<PendingObject>,
    /// Further visible objects follow this page.
    pub more: bool,
}
/// A pending transition or veto, with every stored receipt for that object.
#[derive(Clone, Debug)]
pub struct PendingDetail {
    /// First stored envelope.
    pub envelope: Vec<u8>,
    /// Signed receipt envelopes.
    pub receipts: Vec<Vec<u8>>,
}
/// An unsigned receipt body to give the host's raw signer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptToSign {
    /// Receipted body's digest.
    pub object: String,
    /// Exact canonical body, including the original receipt time.
    pub body: Vec<u8>,
}
/// Atomic, versioned, locally trusted home state; never accept this from peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HomeState {
    version: u32,
    home: String,
    checkpoint: Vec<u8>,
    pending: Vec<PendingObject>,
    next_cursor: u64,
    facts: BTreeMap<String, Fact>,
    drafts: BTreeMap<String, ReceiptToSign>,
    serving: Vec<ServingInterval>,
    unmatched_receipts: Vec<ObservedReceipt>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ObservedReceipt {
    envelope: Vec<u8>,
    first_seen_ms: i64,
    serving: Vec<ServingInterval>,
}
/// Admission is pure: commit `state` and sign `receipts` in the host, even when `result` refuses.
#[derive(Clone, Debug)]
pub struct Admission {
    /// Proposed next persisted state.
    pub state: HomeState,
    /// Accepted or one refusal.
    pub result: AdmitResult<()>,
    /// Stable signing requests (retries reuse the original body).
    pub receipts: Vec<ReceiptToSign>,
}
impl HomeState {
    /// Start from verified account objects, with the home's historical serving intervals.
    pub fn new(
        home: String,
        objects: &Objects,
        serving: Vec<ServingInterval>,
        now_ms: i64,
    ) -> Result<Self> {
        check_intervals(&serving)?;
        let v = verify_history(objects, &Persisted::default(), now_ms);
        require(
            v.stop.is_none() && v.state.is_some(),
            "home needs a complete verified history",
        )?;
        let st = v.state.as_ref().ok_or_else(|| malformed("no account"))?;
        require(
            st.current_homes().iter().any(|m| {
                m.request.member_id() == home && m.expires_ms.is_none_or(|end| now_ms <= end)
            }),
            "not a current unexpired home",
        )?;
        for head in &objects.heads {
            validate_head(st, head, now_ms)?;
        }
        Ok(Self {
            version: 1,
            home,
            checkpoint: Persisted::checkpoint(objects, &Persisted::default(), now_ms).to_bytes()?,
            pending: Vec::new(),
            next_cursor: 1,
            facts: BTreeMap::new(),
            drafts: BTreeMap::new(),
            serving,
            unmatched_receipts: Vec::new(),
        })
    }
    /// Update serving history supplied by the host, without rewriting past per-object facts.
    pub fn with_serving(&self, serving: Vec<ServingInterval>) -> Result<Self> {
        check_intervals(&serving)?;
        let mut next = self.clone();
        next.serving = serving;
        Ok(next)
    }
    /// Persist atomically alongside the caller's committed history.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| malformed(e.to_string()))
    }
    /// Restore trusted local state, including admission decisions and cursor allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let state: Self = serde_json::from_slice(bytes).map_err(|e| malformed(e.to_string()))?;
        require(state.version == 1, "unknown home checkpoint version")?;
        Persisted::from_bytes(&state.checkpoint)?;
        check_intervals(&state.serving)?;
        require(
            state.next_cursor > 0
                && state.pending.windows(2).all(|p| p[0].seq < p[1].seq)
                && state
                    .pending
                    .last()
                    .is_none_or(|p| p.seq < state.next_cursor),
            "invalid pending cursors",
        )?;
        Ok(state)
    }
    fn context(&self, now_ms: i64) -> Result<(Persisted, State)> {
        let p = Persisted::from_bytes(&self.checkpoint)?;
        let v = verify_history(&Objects::default(), &p, now_ms);
        if let Some(stop) = v.stop {
            return Err(stop_failure(stop));
        }
        Ok((p, v.state.ok_or_else(|| malformed("no home history"))?))
    }
    fn add(
        &mut self,
        env: &AuthEnvelope,
        bytes: &[u8],
        kind: &str,
        target: String,
        units: BTreeSet<String>,
        expires_ms: Option<i64>,
    ) -> Result<()> {
        let seq = self.next_cursor;
        self.next_cursor = seq
            .checked_add(1)
            .filter(|n| *n <= bounds::MAX_INTEGER)
            .ok_or_else(|| Failure::Unavailable("home cursor exhausted".into()))?;
        self.pending.push(PendingObject {
            seq,
            digest: env.digest.clone(),
            kind: kind.into(),
            envelope: bytes.to_vec(),
            target,
            units,
            expires_ms,
        });
        Ok(())
    }
    fn visible(&self, object: &PendingObject, state: &State, now_ms: i64) -> bool {
        !state.recorded.contains(if object.kind == "receipt" {
            self.pending
                .iter()
                .find(|p| p.kind != "receipt" && p.digest == object.target)
                .map(|p| &p.target)
                .unwrap_or(&object.target)
        } else {
            &object.target
        }) && object.expires_ms.is_none_or(|end| now_ms <= end)
    }
    /// GET pending, after a local cursor. Access authorization is the caller's §13.4 call check.
    pub fn pending_page(&self, after: u64, limit: usize, now_ms: i64) -> Result<PendingPage> {
        require((1..=64).contains(&limit), "pending page limit must be 1–64")?;
        let (_, state) = self.context(now_ms)?;
        let mut iter = self
            .pending
            .iter()
            .filter(|p| p.seq > after && self.visible(p, &state, now_ms));
        let objects = iter.by_ref().take(limit).cloned().collect();
        Ok(PendingPage {
            objects,
            more: iter.next().is_some(),
        })
    }
    /// GET pending/digest, with every held receipt, or absent. The caller authorizes the read.
    pub fn pending_object(&self, digest: &str, now_ms: i64) -> Result<Option<PendingDetail>> {
        let (_, state) = self.context(now_ms)?;
        let Some(object) = self
            .pending
            .iter()
            .find(|p| p.digest == digest && p.kind != "receipt" && self.visible(p, &state, now_ms))
        else {
            return Ok(None);
        };
        let receipts = self
            .pending
            .iter()
            .filter(|p| p.kind == "receipt" && p.target == digest)
            .map(|p| p.envelope.clone())
            .collect();
        Ok(Some(PendingDetail {
            envelope: object.envelope.clone(),
            receipts,
        }))
    }
}
fn check_intervals(intervals: &[ServingInterval]) -> Result<()> {
    require(
        intervals
            .iter()
            .all(|i| i.through_ms.is_none_or(|end| end >= i.from_ms))
            && intervals
                .windows(2)
                .all(|p| p[0].through_ms.is_some_and(|end| end < p[1].from_ms)),
        "invalid serving intervals",
    )
}
fn validate_head(st: &State, bytes: &[u8], now_ms: i64) -> Result<()> {
    let homes: Vec<_> = st
        .current_homes()
        .iter()
        .filter(|m| m.expires_ms.is_none_or(|end| now_ms <= end))
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    let ctx = crate::v05::heads::HeadContext {
        account: st.account(),
        history: st.history(),
        homes: &homes,
        now_ms,
    };
    match crate::v05::heads::verify_head(bytes, ctx) {
        Ok(_) => Ok(()),
        Err(Failure::Unavailable(why)) if why == "history not held up to the head" => Ok(()),
        Err(f) => Err(f),
    }
}
fn stop_failure(stop: Stop) -> Failure {
    match stop {
        Stop::Failed { failure, .. } => failure,
        Stop::Held { why, .. } => Failure::Unavailable(why),
        Stop::Fork { .. } => Failure::Refused(crate::v05::Reason::Fork),
    }
}
fn check_receipt(st: &State, bytes: &[u8], target: &str, issued: i64) -> Result<(String, i64)> {
    // Outer whitespace is allowed on transport, while embedded envelopes are canonical.
    let canonical_envelope = canonical(&crate::v05::encoding::strict_parse(bytes)?)?;
    state::check_receipt(st, &canonical_envelope, target, issued)
}
fn promote_receipts(
    home: &mut HomeState,
    st: &State,
    env: &AuthEnvelope,
    issued: i64,
    expiry: Option<i64>,
) -> Result<()> {
    let mut promoted = Vec::new();
    for observed in &home.unmatched_receipts {
        if check_receipt(st, &observed.envelope, &env.digest, issued).is_ok() {
            let receipt = AuthEnvelope::parse(
                &observed.envelope,
                bounds::RECEIPT_BODY,
                bounds::RECEIPT_ENVELOPE,
                false,
            )?;
            promoted.push((receipt, observed.clone()));
        }
    }
    for (receipt, observed) in promoted {
        if let Some(fact) = home.facts.get_mut(&env.digest) {
            if observed.first_seen_ms < fact.first_seen_ms {
                fact.first_seen_ms = observed.first_seen_ms;
                fact.serving = observed.serving;
            }
        }
        if !home.pending.iter().any(|p| p.digest == receipt.digest) {
            home.add(
                &receipt,
                &observed.envelope,
                "receipt",
                env.digest.clone(),
                BTreeSet::new(),
                expiry,
            )?;
        }
        home.unmatched_receipts
            .retain(|r| r.envelope != observed.envelope);
    }
    Ok(())
}
fn receipts_for(home: &HomeState, digest: &str) -> Vec<Vec<u8>> {
    home.pending
        .iter()
        .filter(|p| p.kind == "receipt" && p.target == digest)
        .map(|p| p.envelope.clone())
        .collect()
}
fn chosen_receipts(home: &HomeState, st: &State, env: &AuthEnvelope) -> Result<Vec<Vec<u8>>> {
    let issued = date(
        env.value
            .get("issued")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("issued"))?,
        "issued",
    )?;
    let mut best: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    for bytes in receipts_for(home, &env.digest) {
        if let Ok((by, _)) = check_receipt(st, &bytes, &env.digest, issued) {
            let r = AuthEnvelope::parse(
                &bytes,
                bounds::RECEIPT_BODY,
                bounds::RECEIPT_ENVELOPE,
                false,
            )?;
            if best.get(&by).is_none_or(|(digest, _)| r.digest < *digest) {
                best.insert(
                    by,
                    (
                        r.digest,
                        canonical(&crate::v05::encoding::strict_parse(&bytes)?)?,
                    ),
                );
            }
        }
    }
    Ok(best
        .into_values()
        .take(st.keyring.policy.head_quorum() as usize)
        .map(|(_, bytes)| bytes)
        .collect())
}

/// Admit one incoming object at an explicit §2.2 clock date. No IO or signature creation.
pub fn admit(home: &HomeState, incoming: &[u8], now: &str) -> Admission {
    let mut next = home.clone();
    let mut receipts = Vec::new();
    let result = (|| -> AdmitResult<()> {
        let now_ms = date(now, "home clock")?;
        let (persisted, st) = home.context(now_ms)?;
        let env = AuthEnvelope::parse(
            incoming,
            bounds::AUTHORITY_BODY,
            bounds::AUTHORITY_BODY * 2,
            false,
        )?;
        // Equality is by body. Re-uploading a stored object never replaces its envelope.
        if next.pending.iter().any(|p| p.digest == env.digest) {
            if let Some(draft) = next.drafts.get(&env.digest) {
                let issued = env
                    .value
                    .get("issued")
                    .and_then(Value::as_str)
                    .and_then(crate::v05::encoding::parse_date);
                if issued.is_some_and(|at| now_ms >= at && now_ms <= at.saturating_add(WINDOW)) {
                    receipts.push(draft.clone());
                }
            }
            return Ok(());
        }
        let protocol = env
            .value
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default();
        require(
            st.current_homes().iter().any(|m| {
                m.request.member_id() == home.home && m.expires_ms.is_none_or(|end| now_ms <= end)
            }),
            "home is no longer current and unexpired",
        )?;
        let issued = env
            .value
            .get("issued")
            .and_then(Value::as_str)
            .map(|s| date(s, "issued"))
            .transpose()?;
        match protocol {
            "colophon/transition/5" => {
                let env = AuthEnvelope::parse(
                    incoming,
                    bounds::TRANSITION_ENVELOPE,
                    bounds::TRANSITION_ENVELOPE,
                    false,
                )?;
                let t = state::admission_transition(&st, incoming)?;
                let at = issued.ok_or_else(|| malformed("issued"))?;
                // `refused:early` comes first (§13.1 "Clock"), before the caps and before any
                // sighting is recorded: a later in-window receipt must not be judged against a
                // sighting before the transition's own `issued`.
                if now_ms < at {
                    return Err(Refusal::Early);
                }
                next.facts.entry(t.digest.clone()).or_insert(Fact {
                    first_seen_ms: now_ms,
                    serving: home.serving.clone(),
                    refuse_activation: false,
                });
                let active: Vec<_> = next
                    .pending
                    .iter()
                    .filter(|p| p.kind == "transition" && next.visible(p, &st, now_ms))
                    .collect();
                // The proposer is the primary signer's unit; cosigners are not charged (§13.1).
                if active
                    .iter()
                    .filter(|p| p.units.contains(&t.proposer))
                    .count()
                    >= 2
                {
                    return Err(Refusal::ProposerFull);
                }
                let units: BTreeSet<_> = st
                    .keyring
                    .controllers
                    .values()
                    .filter(|c| {
                        (c.has(&Role::Control) || c.has(&Role::Recover))
                            && st.controller_provisional(&c.id()).is_none()
                    })
                    .map(|c| st.keyring.unit_of(c))
                    .collect();
                if active.len() >= 2 * units.len() {
                    return Err(Refusal::PendingFull);
                }
                // Late valid transitions are retained and served, but do not get a receipt.
                next.add(
                    &env,
                    incoming,
                    "transition",
                    t.digest.clone(),
                    BTreeSet::from([t.proposer.clone()]),
                    if t.full_set {
                        None
                    } else {
                        Some(t.due_ms.saturating_add(WEEK))
                    },
                )?;
                promote_receipts(
                    &mut next,
                    &st,
                    &env,
                    at,
                    if t.full_set {
                        None
                    } else {
                        Some(t.due_ms.saturating_add(WEEK))
                    },
                )?;
                if now_ms > at.saturating_add(WINDOW) {
                    return Err(Refusal::Late);
                }
                let draft = ReceiptToSign {
                    object: env.digest.clone(),
                    body: canonical(
                        &json!({"protocol":"colophon/receipt/5", "account":st.account.as_str(), "object":env.digest, "received":now, "by":home.home}),
                    )?,
                };
                next.drafts.insert(env.digest, draft.clone());
                receipts.push(draft);
            }
            "colophon/veto/5" => {
                let env =
                    AuthEnvelope::parse(incoming, bounds::VETO_BODY, bounds::VETO_ENVELOPE, false)?;
                let target = env
                    .value
                    .get("transition")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("transition"))?;
                let stored = next
                    .pending
                    .iter()
                    .find(|p| p.kind == "transition" && p.digest == target)
                    .ok_or_else(|| Failure::Unavailable("veto's transition is not held".into()))?;
                let transition = AuthEnvelope::parse(
                    &stored.envelope,
                    bounds::TRANSITION_ENVELOPE,
                    bounds::TRANSITION_ENVELOPE,
                    false,
                )?;
                let rs = chosen_receipts(&next, &st, &transition)?;
                if rs.len()
                    < (st.keyring.policy.head_quorum() as usize).min(st.current_homes().len())
                {
                    return Err(Failure::Unavailable(
                        "transition receipt quorum is not held".into(),
                    )
                    .into());
                }
                state::check_pending_veto(&st, &stored.envelope, &rs, incoming)?;
                let t = state::check_transition(&st, &stored.envelope, &rs, true, false)?;
                let units: BTreeSet<_> = env
                    .signer_ids()
                    .iter()
                    .filter_map(|id| st.keyring.controllers.get(id))
                    .map(|c| st.keyring.unit_of(c))
                    .collect();
                let vetoes: Vec<_> = next
                    .pending
                    .iter()
                    .filter(|p| {
                        p.kind == "veto" && p.target == target && next.visible(p, &st, now_ms)
                    })
                    .collect();
                if vetoes.len() >= 8 || vetoes.iter().any(|p| !p.units.is_disjoint(&units)) {
                    return Err(Refusal::VetoFull);
                }
                let at = issued.ok_or_else(|| malformed("issued"))?;
                if now_ms < at {
                    return Err(Refusal::Early);
                }
                // A veto that reaches the home after its own window is stored only when it comes
                // with at least one in-window receipt from another current home, held already
                // as for a forwarded transition (§13.1); the home signs no receipt of its own.
                let late = now_ms > at.saturating_add(WINDOW) || now_ms > t.deadline_ms;
                if late
                    && !next.unmatched_receipts.iter().any(|r| {
                        check_receipt(&st, &r.envelope, &env.digest, at).is_ok_and(
                            |(by, received)| by != home.home && received <= t.deadline_ms,
                        )
                    })
                {
                    return Err(Refusal::Late);
                }
                next.add(
                    &env,
                    incoming,
                    "veto",
                    target.to_string(),
                    units,
                    Some(t.due_ms.saturating_add(WEEK)),
                )?;
                promote_receipts(
                    &mut next,
                    &st,
                    &env,
                    at,
                    Some(t.due_ms.saturating_add(WEEK)),
                )?;
                if late {
                    return Ok(());
                }
                let draft = ReceiptToSign {
                    object: env.digest.clone(),
                    body: canonical(
                        &json!({"protocol":"colophon/receipt/5", "account":st.account.as_str(), "object":env.digest, "received":now, "by":home.home}),
                    )?,
                };
                next.drafts.insert(env.digest, draft.clone());
                receipts.push(draft);
            }
            "colophon/receipt/5" => {
                let raw = RawEnvelope::parse_bounded(
                    incoming,
                    bounds::RECEIPT_BODY,
                    bounds::RECEIPT_ENVELOPE,
                    false,
                )?;
                let mut o = Obj::new(raw.value.clone(), "receipt")?;
                require(
                    o.string("protocol")? == protocol
                        && o.string("account")? == st.account.as_str(),
                    "receipt account or protocol",
                )?;
                let target = o.digest("object")?;
                let (_, received) = o.date("received")?;
                let by = o.key_id("by")?;
                o.finish_closed()?;
                let key = st
                    .home_key(&by)
                    .ok_or_else(|| bad_signature("receipt home is not current"))?;
                raw.verify(&key).map_err(|e| bad_signature(e.to_string()))?;
                // Keep authenticated forwarded receipts even if their object has not arrived.
                // Its time window is checked against the object before it can count.
                let stored = next
                    .pending
                    .iter()
                    .find(|p| p.digest == target && p.kind != "receipt");
                let expiry = stored.and_then(|p| p.expires_ms);
                if stored.is_none() {
                    if !next
                        .unmatched_receipts
                        .iter()
                        .any(|r| r.envelope == incoming)
                    {
                        if next.unmatched_receipts.len() >= 4_096 {
                            return Err(
                                Failure::Unavailable("unmatched receipt capacity".into()).into()
                            );
                        }
                        next.unmatched_receipts.push(ObservedReceipt {
                            envelope: incoming.to_vec(),
                            first_seen_ms: now_ms,
                            serving: next.serving.clone(),
                        });
                    }
                    return Err(Failure::Unavailable("receipt's object is not held".into()).into());
                }
                if let Some(object) = stored {
                    let object = AuthEnvelope::parse(
                        &object.envelope,
                        bounds::TRANSITION_ENVELOPE,
                        bounds::TRANSITION_ENVELOPE,
                        false,
                    )?;
                    let at = date(
                        object
                            .value
                            .get("issued")
                            .and_then(Value::as_str)
                            .ok_or_else(|| malformed("issued"))?,
                        "issued",
                    )?;
                    check_receipt(&st, incoming, &target, at)?;
                }
                // One signed receipt per home/object, using the first envelope.
                for prior in next
                    .pending
                    .iter()
                    .filter(|p| p.kind == "receipt" && p.target == target)
                {
                    let prior = RawEnvelope::parse_bounded(
                        &prior.envelope,
                        bounds::RECEIPT_BODY,
                        bounds::RECEIPT_ENVELOPE,
                        false,
                    )?;
                    if prior.value.get("by").and_then(Value::as_str) == Some(&by) {
                        return Ok(());
                    }
                }
                if next.pending.len() >= 10_368 {
                    return Err(Failure::Unavailable("home pending storage full".into()).into());
                }
                next.facts.entry(target.clone()).or_insert(Fact {
                    first_seen_ms: now_ms,
                    serving: home.serving.clone(),
                    refuse_activation: false,
                });
                let _ = received;
                next.add(&env, incoming, "receipt", target, BTreeSet::new(), expiry)?;
            }
            "colophon/head/5" => {
                validate_head(&st, incoming, now_ms)?;
                let mut objects = Objects::default();
                objects.heads.push(incoming.to_vec());
                next.checkpoint = Persisted::checkpoint(&objects, &persisted, now_ms).to_bytes()?;
            }
            "colophon/authority/5" => {
                admit_entry(&mut next, &persisted, &st, &env, incoming, now_ms)?
            }
            _ => return Err(malformed("unknown home object protocol").into()),
        }
        Ok(())
    })();
    Admission {
        state: next,
        result,
        receipts,
    }
}

fn admit_entry(
    next: &mut HomeState,
    persisted: &Persisted,
    st: &State,
    env: &AuthEnvelope,
    incoming: &[u8],
    now_ms: i64,
) -> AdmitResult<()> {
    let entry = parse_entry(incoming)?;
    if entry.seq <= st.seq() {
        if st.history().get(entry.seq.saturating_sub(1) as usize) == Some(&env.digest) {
            return Ok(());
        }
        return Err(Refusal::Conflict);
    }
    if entry.seq != st.seq() + 1 {
        return Err(Refusal::Conflict);
    }
    let recording = matches!(
        entry.kind.as_str(),
        "activate" | "vetoed" | "final" | "successionVetoed"
    );
    let mut objects = Objects {
        entries: vec![incoming.to_vec()],
        ..Default::default()
    };
    // Verify authority and schema before home-side refusals; no invalid bytes enter storage.
    let verdict = verify_history(&objects, persisted, now_ms.max(entry.issued));
    if let Some(stop) = verdict.stop {
        return Err(stop_failure(stop).into());
    }
    if entry.issued > now_ms.saturating_add(60_000) {
        return Err(Refusal::Early);
    }
    let mut full = false;
    if entry.kind == "activate" {
        let t_bytes = embedded_bytes(
            env.value.get("transition").unwrap_or(&Value::Null),
            "transition",
            bounds::TRANSITION_ENVELOPE,
        )?;
        let t_env = AuthEnvelope::parse(
            &t_bytes,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            true,
        )?;
        let rs: Vec<_> = env
            .value
            .get("receipts")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("receipts"))?
            .iter()
            .map(|r| embedded_bytes(r, "receipt", bounds::RECEIPT_ENVELOPE))
            .collect::<Result<_>>()?;
        let t = state::check_transition(st, &t_bytes, &rs, true, true)?;
        full = t.full_set;
        if t.due_ms > now_ms {
            return Err(Refusal::Early);
        }
        // A held valid veto forbids storing the activation, even before its recording exists.
        for v in next
            .pending
            .iter()
            .filter(|p| p.kind == "veto" && p.target == t.digest)
        {
            let veto_env =
                AuthEnvelope::parse(&v.envelope, bounds::VETO_BODY, bounds::VETO_ENVELOPE, false)?;
            let veto_receipts = chosen_receipts(next, st, &veto_env)?;
            if state::receipted_veto(st, &t_bytes, &rs, &v.envelope, &veto_receipts).is_ok() {
                return Err(malformed("home holds a valid veto").into());
            }
        }
        let own_receipt = receipts_for(next, &t.digest).iter().any(|r| {
            RawEnvelope::parse_bounded(r, bounds::RECEIPT_BODY, bounds::RECEIPT_ENVELOPE, false)
                .is_ok_and(|r| r.value.get("by").and_then(Value::as_str) == Some(&next.home))
        });
        let at = date(
            t_env
                .value
                .get("issued")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed("issued"))?,
            "issued",
        )?;
        let fact = next.facts.entry(t.digest.clone()).or_insert(Fact {
            first_seen_ms: now_ms,
            serving: next.serving.clone(),
            refuse_activation: false,
        });
        let timely = fact.first_seen_ms >= at && fact.first_seen_ms <= at.saturating_add(WINDOW);
        let served = next.serving.iter().any(|i| {
            i.from_ms <= at.saturating_add(WINDOW) && i.through_ms.is_none_or(|end| end >= at)
        });
        if fact.refuse_activation || (!own_receipt && !timely && served) {
            fact.refuse_activation = true;
            fact.serving = next.serving.clone();
            // Even a permanently refused activation must leave the transition available to veto.
            if !next.pending.iter().any(|p| p.digest == t.digest) {
                next.add(
                    &t_env,
                    &t_bytes,
                    "transition",
                    t.digest.clone(),
                    BTreeSet::from([t.proposer.clone()]),
                    Some(t.due_ms.saturating_add(WEEK)),
                )?;
            }
            for bytes in &rs {
                let receipt = AuthEnvelope::parse(
                    bytes,
                    bounds::RECEIPT_BODY,
                    bounds::RECEIPT_ENVELOPE,
                    true,
                )?;
                if !next.pending.iter().any(|p| p.digest == receipt.digest) {
                    next.add(
                        &receipt,
                        bytes,
                        "receipt",
                        t.digest.clone(),
                        BTreeSet::new(),
                        Some(t.due_ms.saturating_add(WEEK)),
                    )?;
                }
            }
            return Err(Refusal::Late);
        }
    }
    if (!recording || full) && entry.issued < now_ms.saturating_sub(WINDOW) {
        return Err(Refusal::Late);
    }
    if !recording && st.primary_home().is_some_and(|p| p != next.home) {
        let all: Vec<_> = persisted
            .objects()
            .into_iter()
            .flat_map(|o| &o.entries)
            .chain(std::iter::once(&incoming.to_vec()))
            .filter_map(|b| parse_entry(b).ok())
            .collect();
        let refs: Vec<_> = all.iter().collect();
        let heads = HeadSet::parse(
            &persisted
                .objects()
                .map(|o| o.heads.clone())
                .unwrap_or_default(),
        );
        let primary = st.primary_home().ok_or_else(|| malformed("no primary"))?;
        if !state::covered_by_home_head(st, &heads, &refs, &entry, &primary) {
            let endpoints = st
                .current_homes()
                .into_iter()
                .find(|m| m.request.member_id() == primary)
                .and_then(|m| m.request.endpoints.clone())
                .unwrap_or_default();
            return Err(Refusal::PrimaryRequired(endpoints));
        }
    }
    objects.pending = next.pending.iter().map(|p| p.envelope.clone()).collect();
    next.checkpoint = Persisted::checkpoint(&objects, persisted, now_ms).to_bytes()?;
    Ok(())
}

/// Verify and store the host's raw signature over a previously returned receipt body.
pub fn finish_receipt(
    home: &HomeState,
    object: &str,
    envelope: &[u8],
    now: &str,
) -> Result<HomeState> {
    let now_ms = date(now, "home clock")?;
    let draft = home
        .drafts
        .get(object)
        .ok_or_else(|| malformed("no receipt signing request"))?;
    let raw = RawEnvelope::parse_bounded(
        envelope,
        bounds::RECEIPT_BODY,
        bounds::RECEIPT_ENVELOPE,
        false,
    )?;
    require(
        raw.body == draft.body,
        "receipt differs from signing request",
    )?;
    let (_, state) = home.context(now_ms)?;
    let key = state
        .home_key(&home.home)
        .ok_or_else(|| bad_signature("not a current home"))?;
    raw.verify(&key).map_err(|e| bad_signature(e.to_string()))?;
    let stored = home
        .pending
        .iter()
        .find(|p| p.digest == object && p.kind != "receipt")
        .ok_or_else(|| malformed("receipt's object missing"))?;
    let object_env = AuthEnvelope::parse(
        &stored.envelope,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        false,
    )?;
    let issued = date(
        object_env
            .value
            .get("issued")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("issued"))?,
        "issued",
    )?;
    require(
        now_ms >= issued && now_ms <= issued.saturating_add(WINDOW),
        "receipt signing window has ended",
    )?;
    let result = admit(home, envelope, now);
    result.result.map_err(|r| match r {
        Refusal::Verification(f) => f,
        _ => malformed(r.code()),
    })?;
    let mut next = result.state;
    next.drafts.remove(object);
    Ok(next)
}

/// POST pending batch, 1–16 objects, checked in request order. Refusals are per object.
pub fn admit_pending_batch(
    home: &HomeState,
    objects: &[Vec<u8>],
    now: &str,
) -> Result<(HomeState, Vec<AdmitResult<()>>, Vec<ReceiptToSign>)> {
    require(
        (1..=16).contains(&objects.len()),
        "pending batch must contain 1–16 objects",
    )?;
    let mut next = home.clone();
    let mut results = Vec::new();
    let mut receipts = Vec::new();
    for object in objects {
        let parsed = AuthEnvelope::parse(
            object,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            false,
        )
        .and_then(|env| {
            require(
                matches!(
                    env.value.get("protocol").and_then(Value::as_str),
                    Some("colophon/transition/5" | "colophon/veto/5" | "colophon/receipt/5")
                ),
                "not a pending object",
            )?;
            Ok(env)
        });
        let result = match parsed {
            Ok(_) => admit(&next, object, now),
            Err(f) => Admission {
                state: next.clone(),
                result: Err(f.into()),
                receipts: Vec::new(),
            },
        };
        next = result.state;
        results.push(result.result);
        receipts.extend(result.receipts);
    }
    Ok((next, results, receipts))
}
