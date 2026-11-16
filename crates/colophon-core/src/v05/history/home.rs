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
/// The persisted format of [`HomeState`]: 2 stores bytes as base64 and keeps the checkpoint's
/// pending objects and heads replaced, not merged.
const STATE_VERSION: u32 = 2;
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
/// Bytes in the persisted home state as base64 text, not a JSON array of numbers (a byte as
/// "123," costs four characters; base64 costs 1.33).
mod b64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
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
    #[serde(with = "b64_bytes")]
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
    #[serde(with = "b64_bytes")]
    pub body: Vec<u8>,
}
/// Atomic, versioned, locally trusted home state; never accept this from peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HomeState {
    version: u32,
    home: String,
    /// The verifier checkpoint. Its pending objects are exactly `pending` and its heads are
    /// pruned to what the guard and the verifier need ([`refresh_checkpoint`]), so it is never
    /// stale and does not grow with every head.
    #[serde(with = "b64_bytes")]
    checkpoint: Vec<u8>,
    pending: Vec<PendingObject>,
    next_cursor: u64,
    facts: BTreeMap<String, Fact>,
    drafts: BTreeMap<String, ReceiptToSign>,
    serving: Vec<ServingInterval>,
    unmatched_receipts: Vec<ObservedReceipt>,
    /// Heads this home has had drafted for signing: `(seq, digest, issued ms)`, oldest first.
    #[serde(default)]
    signed_heads: Vec<(u64, String, i64)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ObservedReceipt {
    #[serde(with = "b64_bytes")]
    envelope: Vec<u8>,
    first_seen_ms: i64,
    serving: Vec<ServingInterval>,
    /// The home that signed it: each signing home has its own share of the buffer.
    #[serde(default)]
    by: String,
    /// Its `received`, from which it expires ([`unmatched_expiry`]).
    #[serde(default)]
    received_ms: i64,
}
/// Receipts of objects the home does not hold yet, kept per signing home (§13.1: forwarded
/// receipts may arrive before their object). 8 homes at most share 4,096.
const UNMATCHED_PER_HOME: usize = 512;
/// When a receipt of an object the home never received stops being kept: the object's `issued` is
/// at most its `received`, so its due time is at most `received` + 300 s + the recovery delay,
/// and 7 days after that nothing can be recorded of it (§8.7: an `activate` or `vetoed` is
/// `issued` at most 7 days after its due time or latest receipt) and a home may drop it (§14).
fn unmatched_expiry(received_ms: i64, st: &State) -> i64 {
    received_ms
        .saturating_add(WINDOW)
        .saturating_add((st.keyring.policy.recovery_delay() as i64).saturating_mul(1000))
        .saturating_add(WEEK)
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
        let mut state = Self {
            version: STATE_VERSION,
            home,
            checkpoint: Persisted::checkpoint(objects, &Persisted::default(), now_ms).to_bytes()?,
            pending: Vec::new(),
            next_cursor: 1,
            facts: BTreeMap::new(),
            drafts: BTreeMap::new(),
            serving,
            unmatched_receipts: Vec::new(),
            signed_heads: Vec::new(),
        };
        refresh_checkpoint(&mut state, None, now_ms)?;
        Ok(state)
    }
    /// Update serving history supplied by the host, without rewriting past per-object facts.
    pub fn with_serving(&self, serving: Vec<ServingInterval>) -> Result<Self> {
        check_intervals(&serving)?;
        let mut next = self.clone();
        next.serving = serving;
        Ok(next)
    }
    /// The home's serving intervals (§13.1: a home persists its own serving intervals).
    pub fn serving(&self) -> &[ServingInterval] {
        &self.serving
    }
    /// The home's member ID.
    pub fn home_id(&self) -> &str {
        &self.home
    }
    /// The verifier state this home holds: its verified history, exactly the pending objects it
    /// stores and the heads it keeps (`Persisted::objects`), for a host that serves them, builds
    /// recording entries from them or verifies calls over them. Never stale: every admission that
    /// changes the pending objects or the heads replaces the checkpoint's copy of them.
    /// Read-only: nothing here admits anything.
    pub fn persisted(&self) -> Result<Persisted> {
        Persisted::from_bytes(&self.checkpoint)
    }
    /// Persist atomically alongside the caller's committed history.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| malformed(e.to_string()))
    }
    /// Restore trusted local state, including admission decisions and cursor allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let state: Self = serde_json::from_slice(bytes).map_err(|e| malformed(e.to_string()))?;
        require(
            state.version == STATE_VERSION,
            "unknown home checkpoint version",
        )?;
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
    /// The guard of §13.3 for signing a head, run by the host **before** it prepares or signs one
    /// (`write::calls::prepare_head` knows nothing of a home's history, so the check lives here,
    /// where the history is). The home must not sign a head for an entry it has not verified on
    /// its own branch, must give its heads strictly increasing `issued`, and must not sign a
    /// head for a second digest at a seq unless its own verdict shows the first displaced under
    /// §8.6 rule 1: following both entries back to where their branches first differ, the
    /// divergence is decided by rule 1 (a recording entry against another entry) in favour of
    /// this head's side. Returns the state to persist, which records the head as drafted (a
    /// draft counts as signed, so a retry of the same head is allowed and a different one is not).
    pub fn guard_head(
        &self,
        seq: u64,
        digest: &str,
        issued: &str,
        now: &str,
    ) -> Result<(HomeState, HeadGuard)> {
        let now_ms = date(now, "home clock")?;
        let issued_ms = date(issued, "issued")?;
        let (persisted, st) = self.context(now_ms)?;
        require(
            st.on_branch_digest(seq, digest),
            "a head for an entry this home has not verified on its branch",
        )?;
        let token = || HeadGuard {
            home: self.home.clone(),
            seq,
            digest: digest.to_string(),
            issued: issued.to_string(),
        };
        let mut next = self.clone();
        if next
            .signed_heads
            .iter()
            .any(|(s, d, i)| *s == seq && d == digest && *i == issued_ms)
        {
            return Ok((next, token()));
        }
        require(
            next.signed_heads.iter().all(|(_, _, i)| issued_ms > *i),
            "heads must have strictly increasing issued",
        )?;
        let prior: Vec<String> = next
            .signed_heads
            .iter()
            .filter(|(s, d, _)| *s == seq && d != digest)
            .map(|(_, d, _)| d.clone())
            .collect();
        if !prior.is_empty() {
            let verdict = verify_history(&Objects::default(), &persisted, now_ms);
            let entries: BTreeMap<String, super::Entry> = persisted
                .objects()
                .map(|o| {
                    o.entries
                        .iter()
                        .filter_map(|b| parse_entry(b).ok())
                        .map(|e| (e.env.digest.clone(), e))
                        .collect()
                })
                .unwrap_or_default();
            for first in prior {
                require(
                    displaced_by_rule_1(&entries, &verdict.conflicts, &first, digest),
                    "a second head at this seq, and the first is not displaced under §8.6 rule 1",
                )?;
            }
        }
        next.signed_heads.push((seq, digest.to_string(), issued_ms));
        // Prune what the guard no longer needs: nothing at or before the highest final
        // activation can be displaced (§8.6 rule 1), so only the latest `issued` (for the
        // strictly increasing rule) and the digests at seqs not yet settled stay.
        let settled = st
            .activations()
            .iter()
            .filter(|a| a.final_)
            .map(|a| a.seq)
            .max()
            .unwrap_or(0);
        let latest = next.signed_heads.iter().map(|(_, _, i)| *i).max();
        // At one `(seq, digest)` only the newest signing matters to the guard (a second digest
        // at a seq is judged against the digest, and `issued` against the latest), so heads
        // re-signed over an unchanged history do not accumulate.
        let mut newest: BTreeMap<(u64, String), i64> = BTreeMap::new();
        for (q, d, i) in &next.signed_heads {
            let at = newest.entry((*q, d.clone())).or_insert(*i);
            *at = (*at).max(*i);
        }
        next.signed_heads.retain(|(q, d, i)| {
            Some(*i) == latest || (*q > settled && newest.get(&(*q, d.clone())) == Some(i))
        });
        Ok((next, token()))
    }
    fn context(&self, now_ms: i64) -> Result<(Persisted, State)> {
        let p = Persisted::from_bytes(&self.checkpoint)?;
        let v = verify_history(&Objects::default(), &p, now_ms);
        if let Some(stop) = v.stop {
            return Err(stop_failure(stop));
        }
        Ok((p, v.state.ok_or_else(|| malformed("no home history"))?))
    }
    /// The verified state the home holds and, when its history stops at an unresolved fork
    /// (§8.6 rule 3), the seq of the fork: the state is then the verified prefix before it. Any
    /// other stop is an error, as in [`HomeState::context`].
    fn context_any(&self, now_ms: i64) -> Result<(Persisted, State, Option<u64>)> {
        let p = Persisted::from_bytes(&self.checkpoint)?;
        let v = verify_history(&Objects::default(), &p, now_ms);
        let fork = match v.stop {
            None => None,
            Some(Stop::Fork { seq }) => Some(seq),
            Some(stop) => return Err(stop_failure(stop)),
        };
        Ok((p, v.state.ok_or_else(|| malformed("no home history"))?, fork))
    }
    /// The seq of the unresolved fork the home's history stops at, if it does.
    pub fn fork_seq(&self, now_ms: i64) -> Result<Option<u64>> {
        Ok(self.context_any(now_ms)?.2)
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
        let (_, state, _) = self.context_any(now_ms)?;
        let mut iter = self
            .pending
            .iter()
            .filter(|p| p.seq > after && p.kind != "succession" && self.visible(p, &state, now_ms));
        let objects = iter.by_ref().take(limit).cloned().collect();
        Ok(PendingPage {
            objects,
            more: iter.next().is_some(),
        })
    }
    /// GET pending/digest, with every held receipt, or absent. The caller authorizes the read.
    pub fn pending_object(&self, digest: &str, now_ms: i64) -> Result<Option<PendingDetail>> {
        let (_, state, _) = self.context_any(now_ms)?;
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
/// What [`HomeState::guard_head`] returns when a head may be drafted: `write::calls::prepare_head`
/// takes it, so a host cannot prepare a head for signing without having passed the guard. Only
/// `guard_head` makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadGuard {
    home: String,
    seq: u64,
    digest: String,
    issued: String,
}
impl HeadGuard {
    /// The home member ID the guard was issued to.
    pub fn home(&self) -> &str {
        &self.home
    }
    /// The seq it permits.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// The digest it permits.
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// The `issued` it permits.
    pub fn issued(&self) -> &str {
        &self.issued
    }
}

/// Whether the entry `first` is displaced by `second` under §8.6 rule 1: walk both back to the
/// seq where their branches first differ; the verdict decided that conflict for `second`'s side,
/// and at least one of the two entries there is a recording entry.
fn displaced_by_rule_1(
    entries: &BTreeMap<String, super::Entry>,
    conflicts: &[(u64, String, Vec<String>)],
    first: &str,
    second: &str,
) -> bool {
    let (mut a, mut b) = (first.to_string(), second.to_string());
    loop {
        let (Some(x), Some(y)) = (entries.get(&a), entries.get(&b)) else {
            return false;
        };
        if x.seq != y.seq {
            return false;
        }
        if x.previous == y.previous {
            let recording = |e: &super::Entry| {
                ["activate", "vetoed", "final", "successionVetoed"].contains(&e.kind.as_str())
            };
            return a != b
                && (recording(x) || recording(y))
                && conflicts.iter().any(|(s, standing, losers)| {
                    *s == x.seq && *standing == b && losers.contains(&a)
                });
        }
        let (Some(pa), Some(pb)) = (x.previous.clone(), y.previous.clone()) else {
            return false;
        };
        a = pa;
        b = pb;
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
        // A current home's head over another digest at a held seq is the evidence of a fork
        // (§8.6 rules 2 and 3 weigh the heads covering each candidate): kept, bounded per home
        // ([`kept_heads`]), and never a reason to sign or serve anything else.
        Err(Failure::Refused(crate::v05::Reason::Fork)) => Ok(()),
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
    admit_with(home, incoming, &[], now)
}

/// [`admit`] for one entry of an upload, with the entries that follow it in the same request
/// (`later`). They are used for one thing only: whether a primary head covers this entry
/// (§13.1 "Other homes store them once a primary head covers them"), since the primary's head may
/// name a later entry of the same upload. Nothing in `later` is admitted here.
pub fn admit_with(home: &HomeState, incoming: &[u8], later: &[Vec<u8>], now: &str) -> Admission {
    admit_full(home, incoming, later, &[], now)
}

/// [`admit_with`], with the receipts of the same `POST {base}/pending` batch (`batch`): a veto
/// that is late at this home is judged with an in-window receipt in its own batch.
fn admit_full(
    home: &HomeState,
    incoming: &[u8],
    later: &[Vec<u8>],
    batch: &[Vec<u8>],
    now: &str,
) -> Admission {
    let mut next = home.clone();
    let mut receipts = Vec::new();
    let mut admitted_head: Option<Vec<u8>> = None;
    let result = (|| -> AdmitResult<()> {
        let now_ms = date(now, "home clock")?;
        let (persisted, prefix, fork) = home.context_any(now_ms)?;
        // Receipts of objects that never came expire (`unmatched_expiry`).
        next.unmatched_receipts
            .retain(|r| r.received_ms == 0 || now_ms <= unmatched_expiry(r.received_ms, &prefix));
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
            prefix.current_homes().iter().any(|m| {
                m.request.member_id() == home.home && m.expires_ms.is_none_or(|end| now_ms <= end)
            }),
            "home is no longer current and unexpired",
        )?;
        // At an unresolved fork (§8.6 rule 3) the home answers `refused:fork` for everything that
        // depends on either branch until a `resolve` activates: a `resolve` transition, its
        // vetoes and their receipts are judged on the branch the transition is anchored on (the
        // branch it keeps); entries and heads against what the home holds.
        let st = match fork {
            None => prefix,
            Some(_) => match protocol {
                "colophon/transition/5" | "colophon/veto/5" | "colophon/receipt/5" => {
                    match resolve_anchor(&next, &env, protocol) {
                        Some(anchor) => branch_state(&persisted, &anchor, now_ms)?,
                        None if protocol == "colophon/receipt/5" => prefix,
                        None => return Err(Failure::Refused(crate::v05::Reason::Fork).into()),
                    }
                }
                _ => prefix,
            },
        };
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
                // A veto of a Swift succession names the successor's genesis (§15.1 step 4).
                if let Some(status) = super::succession_status(&st)
                    .filter(|s| s.genesis_digest == target && s.timing.is_some())
                {
                    return admit_succession_veto(&mut next, &st, &env, incoming, &status, now_ms, &mut receipts, batch);
                }
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
                // The receipt may be held already (forwarded before the veto), or come in the
                // same batch as the veto: it is judged here either way, never through the
                // buffer's capacity.
                if late
                    && !next
                        .unmatched_receipts
                        .iter()
                        .map(|r| &r.envelope)
                        .chain(batch.iter())
                        .any(|r| {
                            check_receipt(&st, r, &env.digest, at).is_ok_and(
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
                // The signing home: a current home, or a home current at a succession window's
                // entry (§15.1 fixes the homes that receipt the genesis and a veto of the
                // succession at that entry; a later revocation does not unmake their receipts).
                let key = st
                    .home_key(&by)
                    .or_else(|| window_home_key(&st, &by))
                    .ok_or_else(|| bad_signature("receipt home is not current"))?;
                raw.verify(&key).map_err(|e| bad_signature(e.to_string()))?;
                let window_only = st.home_key(&by).is_none();
                // A receipt of a successor genesis (§13.5, §15.1 step 2): judged by the
                // succession verifier's own check (a window home, its key, `received` in the
                // succession window) and kept with the history, served in `GET {base}/authority`
                // `receipts`, never in the pending feed.
                if let Some(status) =
                    super::succession_status(&st).filter(|s| s.genesis_digest == target)
                {
                    let w0 = status
                        .timing
                        .as_ref()
                        .map(|t| t.window_start_ms)
                        .ok_or_else(|| Failure::Unavailable("the succession window has not opened".into()))?;
                    let canon = canonical(&crate::v05::encoding::strict_parse(incoming)?)?;
                    require(
                        super::succession::receipt_is_valid(&st, &canon, &target, w0, i64::MAX),
                        "not a valid receipt of the successor genesis",
                    )?;
                    let one_per_home = next.pending.iter().any(|p| {
                        p.kind == "succession"
                            && RawEnvelope::parse(&p.envelope, bounds::RECEIPT_BODY, false)
                                .is_ok_and(|r| r.value.get("by").and_then(Value::as_str) == Some(&by))
                    });
                    if !one_per_home {
                        next.add(&env, incoming, "succession", target, BTreeSet::new(), None)?;
                    }
                    let _ = received;
                    return Ok(());
                }
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
                        // Each signing home has its own share: one home filling its share
                        // never refuses another's receipts. A receipt sent with its object in
                        // one batch never needs this buffer (`admit_pending_batch`).
                        let share = next.unmatched_receipts.iter().filter(|r| r.by == by).count();
                        if share >= UNMATCHED_PER_HOME {
                            return Err(
                                Failure::Unavailable("unmatched receipt capacity of this home".into()).into()
                            );
                        }
                        next.unmatched_receipts.push(ObservedReceipt {
                            envelope: incoming.to_vec(),
                            first_seen_ms: now_ms,
                            serving: next.serving.clone(),
                            by: by.clone(),
                            received_ms: received,
                        });
                    }
                    return Err(Failure::Unavailable("receipt's object is not held".into()).into());
                }
                let succession_veto = stored.is_some_and(|p| {
                    p.kind == "veto"
                        && super::succession_status(&st).is_some_and(|s| s.genesis_digest == p.target)
                });
                if succession_veto {
                    // A receipt of a veto of the succession: by a home current at the window's
                    // entry, within 300 s of the veto's `issued` and before the veto deadline
                    // (§15.1 step 4), judged by the succession verifier's own check.
                    let object = stored.ok_or_else(|| malformed("veto"))?;
                    let v = AuthEnvelope::parse(&object.envelope, bounds::VETO_BODY, bounds::VETO_ENVELOPE, false)?;
                    let at = date(v.value.get("issued").and_then(Value::as_str).ok_or_else(|| malformed("issued"))?, "issued")?;
                    let deadline = super::succession_status(&st)
                        .and_then(|s| s.timing)
                        .map(|t| t.veto_deadline_ms)
                        .ok_or_else(|| malformed("no succession window"))?;
                    let canon = canonical(&crate::v05::encoding::strict_parse(incoming)?)?;
                    require(
                        super::succession::receipt_is_valid(&st, &canon, &target, at, deadline),
                        "not a valid receipt of the succession veto",
                    )?;
                } else if window_only {
                    return Err(bad_signature("receipt home is not current").into());
                } else if let Some(object) = stored {
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
                // Kept or pruned with the other heads below ([`refresh_checkpoint`]).
                admitted_head = Some(incoming.to_vec());
            }
            "colophon/authority/5" => {
                admit_entry(&mut next, &persisted, &st, &env, incoming, now_ms, fork, later)?
            }
            _ => return Err(malformed("unknown home object protocol").into()),
        }
        Ok(())
    })();
    // The checkpoint's pending objects and heads are replaced whenever they change (a refusal
    // can store a late transition too), so `persisted()` is never stale.
    let changed = admitted_head.is_some() || next.pending.len() != home.pending.len();
    if changed || result.is_ok() {
        let refreshed = date(now, "home clock")
            .and_then(|now_ms| refresh_checkpoint(&mut next, admitted_head.as_deref(), now_ms));
        if let Err(f) = refreshed {
            return Admission {
                state: home.clone(),
                result: Err(f.into()),
                receipts: Vec::new(),
            };
        }
    }
    Admission {
        state: next,
        result,
        receipts,
    }
}

/// The heads a home keeps (§13.3: "a home keeps only what the guard needs"; the verifier's
/// share is the same): per home and `(seq, digest)` only the newest `issued`, and of those each
/// home's latest plus every head at a seq after the highest final activation (`settled`), where
/// §8.6 can still ask which homes covered an entry or `final` can still need a witness. A head
/// over an unchanged history therefore replaces the previous one instead of adding to it.
fn kept_heads(heads: &[Vec<u8>], settled: u64, branch: &[String]) -> Vec<Vec<u8>> {
    struct Held<'a> {
        by: String,
        seq: u64,
        digest: String,
        issued: i64,
        bytes: &'a Vec<u8>,
    }
    let parsed: Vec<Held> = heads
        .iter()
        .filter_map(|b| {
            let raw = RawEnvelope::parse(b, bounds::HEAD_BODY, false).ok()?;
            let v = &raw.value;
            let a = v.get("authority")?;
            Some(Held {
                by: v.get("by")?.as_str()?.to_string(),
                seq: a.get("seq")?.as_u64()?,
                digest: a.get("digest")?.as_str()?.to_string(),
                issued: crate::v05::encoding::parse_date(v.get("issued")?.as_str()?)?,
                bytes: b,
            })
        })
        .collect();
    let newer = |a: &Held, b: &Held| (a.issued, a.bytes) > (b.issued, b.bytes);
    let mut best: BTreeMap<(&str, u64, &str), &Held> = BTreeMap::new();
    let mut latest: BTreeMap<&str, &Held> = BTreeMap::new();
    for h in &parsed {
        let slot = best.entry((&h.by, h.seq, &h.digest)).or_insert(h);
        if newer(h, slot) {
            *slot = h;
        }
        let l = latest.entry(&h.by).or_insert(h);
        if newer(h, l) {
            *l = h;
        }
    }
    let kept: Vec<&Held> = best
        .into_values()
        .filter(|h| h.seq > settled || latest.get(h.by.as_str()).is_some_and(|l| std::ptr::eq(*l, *h)))
        .collect();
    // Fork evidence (a head over another digest than the home's history holds at that seq) is
    // kept too, but at most `OFF_BRANCH` per home, the newest: a hostile home cannot grow the
    // state by signing heads over digests nobody holds.
    let off = |h: &Held| {
        usize::try_from(h.seq.saturating_sub(1))
            .ok()
            .and_then(|i| branch.get(i))
            .is_some_and(|d| *d != h.digest)
    };
    let mut off_count: BTreeMap<&str, usize> = BTreeMap::new();
    let mut newest_first: Vec<&&Held> = kept.iter().filter(|h| off(h)).collect();
    newest_first.sort_by(|a, b| (b.issued, b.bytes).cmp(&(a.issued, a.bytes)));
    let mut dropped: BTreeSet<*const Held> = BTreeSet::new();
    for h in newest_first {
        let n = off_count.entry(h.by.as_str()).or_insert(0);
        *n += 1;
        if *n > OFF_BRANCH {
            dropped.insert(std::ptr::from_ref::<Held>(h));
        }
    }
    kept.into_iter()
        .filter(|h| !dropped.contains(&std::ptr::from_ref::<Held>(h)))
        .map(|h| h.bytes.clone())
        .collect()
}
/// Fork-evidence heads kept per home ([`kept_heads`]).
const OFF_BRANCH: usize = 4;

/// Replace the checkpoint's pending objects with exactly what the home stores and its heads with
/// [`kept_heads`] (plus `new_head`, when one was just admitted). The checkpoint is rebuilt from
/// those objects, not merged with the old ones, so nothing dropped comes back; the head marks,
/// the succession flag and the higher high-water mark are kept.
fn refresh_checkpoint(next: &mut HomeState, new_head: Option<&[u8]>, now_ms: i64) -> Result<()> {
    let p = Persisted::from_bytes(&next.checkpoint)?;
    let before = p.objects().cloned().unwrap_or_default();
    let mut heads = before.heads.clone();
    if let Some(h) = new_head {
        if !heads.iter().any(|x| x == h) {
            heads.push(h.to_vec());
        }
    }
    let st = verify_history(&Objects::default(), &p, now_ms).state;
    let settled = st
        .as_ref()
        .and_then(|st| st.activations().iter().filter(|a| a.final_).map(|a| a.seq).max())
        .unwrap_or(0);
    let branch = st.as_ref().map(|s| s.history().to_vec()).unwrap_or_default();
    let heads = kept_heads(&heads, settled, &branch);
    let pending: Vec<Vec<u8>> = next.pending.iter().map(|o| o.envelope.clone()).collect();
    if heads == before.heads && pending == before.pending {
        return Ok(());
    }
    let objects = Objects {
        entries: before.entries,
        pending,
        heads,
        predecessor: before.predecessor,
    };
    let mut rebuilt = Persisted::rebuild(&objects, &next.checkpoint, now_ms);
    let lower = match (&p.high_water, &rebuilt.high_water) {
        (Some((old, _)), Some((new, _))) => old > new,
        (Some(_), None) => true,
        _ => false,
    };
    if lower {
        rebuilt.high_water = p.high_water.clone();
    }
    next.checkpoint = rebuilt.to_bytes()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn admit_entry(
    next: &mut HomeState,
    persisted: &Persisted,
    st: &State,
    env: &AuthEnvelope,
    incoming: &[u8],
    now_ms: i64,
    fork: Option<u64>,
    later: &[Vec<u8>],
) -> AdmitResult<()> {
    let entry = parse_entry(incoming)?;
    let held: Vec<Vec<u8>> = persisted
        .objects()
        .map(|o| o.entries.clone())
        .unwrap_or_default();
    let held_entries: Vec<super::Entry> = held.iter().filter_map(|b| parse_entry(b).ok()).collect();
    // Equality is by body: an entry held already, on the branch or as a candidate, is stored.
    if held_entries.iter().any(|e| e.env.digest == env.digest) {
        return Ok(());
    }
    let recording = matches!(
        entry.kind.as_str(),
        "activate" | "vetoed" | "final" | "successionVetoed"
    );
    // §13.1 Ordering: a non-primary home stores an immediate entry once a primary head covers
    // it. The head may name a later entry of the same upload (`later`), so those count as the
    // entry's descendants here; nothing else is taken from them.
    let primary = st.primary_home().filter(|p| *p != next.home);
    let covered = !recording
        && primary.as_ref().is_some_and(|p| {
            let extra: Vec<super::Entry> = std::iter::once(incoming)
                .chain(later.iter().map(Vec::as_slice))
                .filter_map(|b| parse_entry(b).ok())
                .collect();
            let refs: Vec<&super::Entry> = held_entries.iter().chain(extra.iter()).collect();
            let heads = HeadSet::parse(
                &persisted
                    .objects()
                    .map(|o| o.heads.clone())
                    .unwrap_or_default(),
            );
            state::covered_by_home_head(st, &heads, &refs, &entry, p)
        });
    let extends = fork.is_none()
        && entry.seq == st.seq() + 1
        && entry.previous.as_ref() == st.history().last();
    if !extends {
        if fork.is_none() && entry.seq > st.seq() + 1 {
            return Err(Refusal::Conflict); // a gap
        }
        return admit_candidate(
            next,
            persisted,
            st,
            &entry,
            incoming,
            now_ms,
            fork,
            &held_entries,
            covered,
        );
    }
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
    // §13.1 Clock: an immediate entry or a full set more than 300 s behind the clock is
    // `refused:late`, except at a non-primary home for an immediate entry a primary head
    // covers: the primary admitted it in time (its clock is the one the rule is about), and a
    // home that was offline must be able to take what the primary admitted meanwhile.
    if (!recording || full) && !covered && entry.issued < now_ms.saturating_sub(WINDOW) {
        return Err(Refusal::Late);
    }
    if !recording && !covered {
        if let Some(p) = &primary {
            return Err(Refusal::PrimaryRequired(endpoints_of(st, p)));
        }
    }
    objects.pending = next.pending.iter().map(|p| p.envelope.clone()).collect();
    next.checkpoint = Persisted::checkpoint(&objects, persisted, now_ms).to_bytes()?;
    Ok(())
}

fn endpoints_of(st: &State, home: &str) -> Vec<String> {
    st.current_homes()
        .into_iter()
        .find(|m| m.request.member_id() == home)
        .and_then(|m| m.request.endpoints.clone())
        .unwrap_or_default()
}

/// An entry that does not extend the home's branch: one at a seq the home holds with other
/// bytes (a candidate, §8.6), one continuing another candidate's branch, or any entry while the
/// home's history stops at an unresolved fork. It is stored only when it is valid in its place
/// (its own branch verifies through it) and either it stands (the verdict with it puts it on the
/// branch: a displacement under §8.6 rule 1 or 2, or the `resolve` that settles a fork), or it is
/// an immediate entry a primary head covers and the home now holds a fork (§13.1: a non-primary
/// home stores what a primary head covers; §8.6 rule 3). Otherwise: `refused:fork` at a fork,
/// 421 at a non-primary home for an entry no primary head covers, 409 (§14) at the primary.
#[allow(clippy::too_many_arguments)]
fn admit_candidate(
    next: &mut HomeState,
    persisted: &Persisted,
    st: &State,
    entry: &super::Entry,
    incoming: &[u8],
    now_ms: i64,
    fork: Option<u64>,
    held: &[super::Entry],
    covered: bool,
) -> AdmitResult<()> {
    let recording = matches!(
        entry.kind.as_str(),
        "activate" | "vetoed" | "final" | "successionVetoed"
    );
    let Some(parent) = entry.previous.as_ref().filter(|p| held.iter().any(|e| &e.env.digest == *p)) else {
        return Err(Refusal::Conflict);
    };
    if entry.issued > now_ms.saturating_add(60_000) {
        return Err(Refusal::Early);
    }
    let pending: Vec<Vec<u8>> = next.pending.iter().map(|p| p.envelope.clone()).collect();
    let heads = persisted.objects().map(|o| o.heads.clone()).unwrap_or_default();
    // Valid in its place: the entry's own branch, from the genesis, verifies through it.
    let mut chain = ancestry(held, parent);
    chain.push(incoming.to_vec());
    let own = verify_history(
        &Objects {
            entries: chain,
            pending: pending.clone(),
            heads: heads.clone(),
            predecessor: persisted.objects().map(|o| o.predecessor.clone()).unwrap_or_default(),
        },
        &Persisted::default(),
        now_ms.max(entry.issued),
    );
    if let Some(stop) = own.stop {
        return Err(stop_failure(stop).into());
    }
    // A held veto of the transition forbids storing its `activate` (§13.1), here as on the
    // branch.
    if entry.kind == "activate" {
        let t = entry
            .env
            .value
            .get("transition")
            .and_then(|t| embedded_bytes(t, "transition", bounds::TRANSITION_ENVELOPE).ok())
            .and_then(|b| AuthEnvelope::parse(&b, bounds::TRANSITION_ENVELOPE, bounds::TRANSITION_ENVELOPE, true).ok())
            .map(|e| e.digest);
        if next.pending.iter().any(|p| p.kind == "veto" && Some(&p.target) == t.as_ref()) {
            return Err(malformed("home holds a veto of the transition").into());
        }
    }
    let objects = Objects {
        entries: vec![incoming.to_vec()],
        pending,
        ..Default::default()
    };
    let verdict = verify_history(&objects, persisted, now_ms.max(entry.issued));
    let stands = verdict.stop.is_none()
        && usize::try_from(entry.seq - 1)
            .ok()
            .and_then(|i| verdict.branch.get(i))
            == Some(&entry.env.digest);
    let forks = matches!(verdict.stop, Some(Stop::Fork { .. }));
    if stands || (forks && covered) {
        if !recording && !covered && entry.issued < now_ms.saturating_sub(WINDOW) {
            return Err(Refusal::Late);
        }
        next.checkpoint = Persisted::checkpoint(&objects, persisted, now_ms).to_bytes()?;
        return Ok(());
    }
    if fork.is_some() {
        return Err(Failure::Refused(crate::v05::Reason::Fork).into());
    }
    if let Some(p) = st.primary_home().filter(|p| *p != next.home) {
        if !recording && !covered {
            return Err(Refusal::PrimaryRequired(endpoints_of(st, &p)));
        }
    }
    Err(Refusal::Conflict)
}

/// A veto of a Swift succession (§15.1 step 4): stored when the succession verifier finds it
/// valid (eligible predecessor keys, as many as `handover` has, inside the window and before
/// the veto deadline) and receipted by a window home within 300 s of its `issued` and before the
/// deadline. A successor home that holds a valid veto records `successionVetoed` (`record_due`).
#[allow(clippy::too_many_arguments)]
fn admit_succession_veto(
    next: &mut HomeState,
    st: &State,
    env: &AuthEnvelope,
    incoming: &[u8],
    status: &super::SuccessionStatus,
    now_ms: i64,
    receipts: &mut Vec<ReceiptToSign>,
    batch: &[Vec<u8>],
) -> AdmitResult<()> {
    let t = status.timing.as_ref().ok_or_else(|| malformed("no window"))?;
    if !super::succession::veto_is_valid(st, incoming) {
        return Err(malformed("not a valid veto of the succession").into());
    }
    let at = date(
        env.value.get("issued").and_then(Value::as_str).ok_or_else(|| malformed("issued"))?,
        "issued",
    )?;
    if now_ms < at {
        return Err(Refusal::Early);
    }
    let in_window = now_ms <= at.saturating_add(WINDOW) && now_ms <= t.veto_deadline_ms;
    // Receipts of it by the homes of the window's entry (§15.1 step 4), held already or in the
    // same batch, judged by the succession verifier against that fixed set.
    let home = next.home.clone();
    let valid = |r: &Vec<u8>| {
        super::succession::receipt_is_valid(st, r, &env.digest, at, t.veto_deadline_ms)
            && RawEnvelope::parse(r, bounds::RECEIPT_BODY, false)
                .is_ok_and(|e| e.value.get("by").and_then(Value::as_str) != Some(home.as_str()))
    };
    let held: Vec<Vec<u8>> = next
        .unmatched_receipts
        .iter()
        .map(|r| r.envelope.clone())
        .chain(batch.iter().cloned())
        .filter_map(|r| crate::v05::encoding::strict_parse(&r).and_then(|v| canonical(&v)).ok())
        .filter(|r| valid(r))
        .collect();
    if !in_window && held.is_empty() {
        return Err(Refusal::Late);
    }
    next.add(env, incoming, "veto", status.genesis_digest.clone(), BTreeSet::new(), None)?;
    for r in held {
        let renv = AuthEnvelope::parse(&r, bounds::RECEIPT_BODY, bounds::RECEIPT_ENVELOPE, false)?;
        if !next.pending.iter().any(|p| p.digest == renv.digest) {
            next.add(&renv, &r, "receipt", env.digest.clone(), BTreeSet::new(), None)?;
        }
        next.unmatched_receipts.retain(|u| canonical(&crate::v05::encoding::strict_parse(&u.envelope).unwrap_or(Value::Null)).ok().as_ref() != Some(&r));
    }
    if in_window && t.homes.contains(&next.home) {
        let draft = ReceiptToSign {
            object: env.digest.clone(),
            body: canonical(&json!({"protocol":"colophon/receipt/5", "account": st.account.as_str(),
                "object": env.digest, "received": crate::v05::write::format_date(now_ms), "by": next.home}))?,
        };
        next.drafts.insert(env.digest.clone(), draft.clone());
        receipts.push(draft);
    }
    Ok(())
}

/// A predecessor entry published to this home (§14 `PUT {base}/predecessor/authority/<8
/// digits>.json`, §15.1 "Published ... at the successor's homes under `{base}/predecessor/`"):
/// the account must claim a Swift predecessor, the entry's `seq` must be the path's and at most
/// F's (`head.seq + 1`), the home must hold no other entry at that seq, and the history verifier
/// with it added must not stop (a forged or foreign entry stops it, or is not part of the chain
/// the genesis claims). Returns the state to persist; an entry held already changes nothing.
pub fn admit_predecessor(
    home: &HomeState,
    seq: u64,
    incoming: &[u8],
    now: &str,
) -> AdmitResult<HomeState> {
    let now_ms = date(now, "home clock")?;
    let (persisted, st, fork) = home.context_any(now_ms)?;
    if fork.is_some() {
        return Err(Failure::Refused(crate::v05::Reason::Fork).into());
    }
    let status = super::succession_status(&st)
        .filter(|s| s.format == "colophon/swift-keyring/2")
        .ok_or(Failure::Refused(crate::v05::Reason::OutOfScope))?;
    let canon = canonical(&crate::v05::encoding::strict_parse(incoming)?)?;
    require(canon.len() <= bounds::AUTHORITY_BODY * 2, "predecessor entry too large")?;
    let raw: Value = serde_json::from_slice(&canon).map_err(|e| malformed(e.to_string()))?;
    let body = crate::v05::encoding::decode_base64(
        raw.get("body").and_then(Value::as_str).ok_or_else(|| malformed("body"))?,
        bounds::AUTHORITY_BODY * 2,
    )?;
    let b: Value = serde_json::from_slice(&body).map_err(|e| malformed(e.to_string()))?;
    require(
        b.get("seq").and_then(Value::as_u64) == Some(seq),
        "the entry's seq is not its path's",
    )?;
    require(
        seq >= 1 && seq <= status.head_seq.saturating_add(1),
        "a predecessor entry after F",
    )?;
    let held = persisted.objects().map(|o| o.predecessor.clone()).unwrap_or_default();
    let digest = crate::v05::encoding::digest(&body);
    for h in &held {
        let Ok(v) = serde_json::from_slice::<Value>(h) else { continue };
        let Some(hb) = v
            .get("body")
            .and_then(Value::as_str)
            .and_then(|t| crate::v05::encoding::decode_base64(t, bounds::AUTHORITY_BODY * 2).ok())
        else {
            continue;
        };
        if crate::v05::encoding::digest(&hb) == digest {
            return Ok(home.clone());
        }
        let hv: Value = serde_json::from_slice(&hb).unwrap_or(Value::Null);
        if hv.get("seq").and_then(Value::as_u64) == Some(seq) {
            return Err(Refusal::Conflict);
        }
    }
    let objects = Objects {
        predecessor: vec![canon],
        ..Default::default()
    };
    let verdict = verify_history(&objects, &persisted, now_ms);
    if let Some(stop) = verdict.stop {
        return Err(stop_failure(stop).into());
    }
    let mut next = home.clone();
    next.checkpoint = Persisted::checkpoint(&objects, &persisted, now_ms).to_bytes()?;
    Ok(next)
}

impl HomeState {
    /// The receipts of a successor genesis this home holds (its own and other window homes'),
    /// served in `GET {base}/authority` `receipts` (§14).
    pub fn succession_receipts(&self) -> Vec<Vec<u8>> {
        self.pending
            .iter()
            .filter(|p| p.kind == "succession")
            .map(|p| p.envelope.clone())
            .collect()
    }
    /// The vetoes of a succession this home holds: the digests of held vetoes naming the
    /// successor's genesis, for the recorder (`write::succession::prepare_succession_vetoed`).
    pub fn succession_vetoes(&self, genesis: &str) -> Vec<String> {
        self.pending
            .iter()
            .filter(|p| p.kind == "veto" && p.target == genesis)
            .map(|p| p.digest.clone())
            .collect()
    }
}

/// The signing key of a home that was current at the succession window's entry (§15.1).
fn window_home_key(st: &State, by: &str) -> Option<Vec<u8>> {
    st.succession.as_ref()?.window.as_ref()?.homes.get(by).cloned()
}

/// The held entries from the genesis to `tip`, following `previous` (seq order).
fn ancestry(held: &[super::Entry], tip: &str) -> Vec<Vec<u8>> {
    let by: BTreeMap<&str, &super::Entry> = held.iter().map(|e| (e.env.digest.as_str(), e)).collect();
    let mut out = Vec::new();
    let mut at = Some(tip.to_string());
    while let Some(d) = at {
        let Some(e) = by.get(d.as_str()) else { break };
        out.push(e.raw.clone());
        at = e.previous.clone();
    }
    out.reverse();
    out
}

/// The anchor digest of the `resolve` transition an object belongs to: the transition itself, a
/// veto of a held one, or a receipt of either. `None` when it is not a `resolve`'s.
fn resolve_anchor(home: &HomeState, env: &AuthEnvelope, protocol: &str) -> Option<String> {
    let parse = |b: &[u8]| {
        AuthEnvelope::parse(b, bounds::TRANSITION_ENVELOPE, bounds::TRANSITION_ENVELOPE, false).ok()
    };
    let held = |d: &str| home.pending.iter().find(|p| p.kind != "receipt" && p.digest == d);
    let transition: Value = match protocol {
        "colophon/transition/5" => env.value.clone(),
        "colophon/veto/5" => parse(&held(env.value.get("transition")?.as_str()?)?.envelope)?.value,
        _ => {
            let object = held(env.value.get("object")?.as_str()?)?;
            let v = parse(&object.envelope)?.value;
            if object.kind == "veto" {
                parse(&held(v.get("transition")?.as_str()?)?.envelope)?.value
            } else {
                v
            }
        }
    };
    transition.get("change")?.get("resolve")?;
    transition.get("anchor")?.get("digest")?.as_str().map(str::to_string)
}

/// The verified state of the branch ending at `anchor` (the entries that follow `previous`
/// back from it), with every held pending object and head: where a `resolve` is judged while
/// the home's history stops at the fork it settles (as `write::authority` builds its
/// `activate`).
fn branch_state(persisted: &Persisted, anchor: &str, now_ms: i64) -> Result<State> {
    let o = persisted.objects().cloned().unwrap_or_default();
    let held: Vec<super::Entry> = o.entries.iter().filter_map(|b| parse_entry(b).ok()).collect();
    let chain = ancestry(&held, anchor);
    require(
        chain.last().and_then(|b| parse_entry(b).ok()).is_some_and(|e| e.env.digest == anchor),
        "the resolve's anchor is not held",
    )?;
    let v = verify_history(
        &Objects {
            entries: chain,
            pending: o.pending,
            heads: o.heads,
            predecessor: o.predecessor,
        },
        &Persisted::default(),
        now_ms,
    );
    if let Some(stop) = v.stop {
        return Err(stop_failure(stop));
    }
    v.state.ok_or_else(|| malformed("no branch state"))
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
    let (_, state, _) = home.context_any(now_ms)?;
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

/// What a first upload leaves a home with (§13.1 "First upload").
#[derive(Clone, Debug)]
pub enum FirstUpload {
    /// The entries so far verify, but this home is not yet appointed in them. They are the
    /// whole of what the home holds; the host keeps them and the next entry continues them.
    Held(Vec<Vec<u8>>),
    /// The entry appointed this home: from here on the home admits with [`admit`].
    Home(Box<HomeState>),
}

/// Admit one entry of an account's first upload to a home that is not yet in its history
/// (§13.1 "First upload"). `account` is the account this home slot was provisioned for: the
/// first entry must be that account's genesis (its body digest is the account ID), and nothing
/// else is held, so nobody else's history can occupy the slot. `held` is every entry the home
/// holds so far, seq 1 upward.
///
/// The entry must verify under §8 with what is held, continue `held` or equal what is held at
/// its seq (`Refusal::Conflict` otherwise), and is `refused:early` more than 60 s ahead of the
/// clock. The rest of the clock rule (`refused:late`, 300 s behind) and the receipt windows apply
/// **from this home's appointment on**: every entry handled here is at or before the entry that
/// appoints the home, written while the home did not serve the account, so its clock witnessed
/// none of them (an account created last week can appoint a new home today and upload its
/// history). Once the history shows this home as a current home, the result is its
/// [`HomeState`], whose serving history starts now, and later entries go through [`admit`].
pub fn admit_first(
    home: &str,
    account: &str,
    held: &[Vec<u8>],
    incoming: &[u8],
    now: &str,
) -> AdmitResult<FirstUpload> {
    admit_first_with(home, account, held, &[], incoming, now)
}

/// [`admit_first`] for a successor of a Swift library (§15.1): `predecessor` is the predecessor
/// history published to this home before its first upload (§14 `PUT
/// {base}/predecessor/authority/<8 digits>.json`), without which the genesis cannot be verified
/// (`unavailable`: "predecessor history required"). Entries in it that are not the chain the
/// genesis claims are ignored by the verifier (§15.1 "Envelopes", "Chain bound").
pub fn admit_first_with(
    home: &str,
    account: &str,
    held: &[Vec<u8>],
    predecessor: &[Vec<u8>],
    incoming: &[u8],
    now: &str,
) -> AdmitResult<FirstUpload> {
    let now_ms = date(now, "home clock")?;
    let entry = parse_entry(incoming)?;
    let have = held.len() as u64;
    if entry.seq <= have {
        let prior = parse_entry(&held[(entry.seq - 1) as usize])?;
        if prior.env.digest == entry.env.digest {
            return Ok(FirstUpload::Held(held.to_vec()));
        }
        return Err(Refusal::Conflict);
    }
    if entry.seq != have + 1 {
        return Err(Refusal::Conflict);
    }
    if have == 0 && crate::v05::ids::AccountId::of_genesis(&entry.env.body).as_str() != account {
        // Not this slot's account: refused, and nothing is held.
        return Err(Failure::Refused(crate::v05::Reason::OutOfScope).into());
    }
    let mut entries = held.to_vec();
    entries.push(incoming.to_vec());
    let objects = Objects {
        entries,
        predecessor: predecessor.to_vec(),
        ..Default::default()
    };
    let verdict = verify_history(&objects, &Persisted::default(), now_ms.max(entry.issued));
    if let Some(stop) = verdict.stop {
        return Err(stop_failure(stop).into());
    }
    if entry.issued > now_ms.saturating_add(60_000) {
        return Err(Refusal::Early);
    }
    let appointed = verdict.state.as_ref().is_some_and(|st| {
        st.current_homes().iter().any(|m| {
            m.request.member_id() == home && m.expires_ms.is_none_or(|end| now_ms <= end)
        })
    });
    if !appointed {
        return Ok(FirstUpload::Held(objects.entries));
    }
    let serving = vec![ServingInterval {
        from_ms: now_ms,
        through_ms: None,
    }];
    Ok(FirstUpload::Home(Box::new(HomeState::new(
        home.to_string(),
        &objects,
        serving,
        now_ms,
    )?)))
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
    // Transitions and vetoes first, in request order, each judged with the receipts of the
    // batch (a veto more than 300 s after its `issued` is stored with an in-window receipt of
    // it from another current home, §13.1, and that receipt may come in this very request);
    // then the receipts, which find their objects stored. A receipt sent with its object never
    // depends on the buffer of receipts whose object is not held. Results stay in request order.
    let is_receipt = |o: &Vec<u8>| {
        RawEnvelope::parse(o, bounds::RECEIPT_BODY, false)
            .is_ok_and(|e| e.value.get("protocol").and_then(Value::as_str) == Some("colophon/receipt/5"))
    };
    let batch: Vec<Vec<u8>> = objects
        .iter()
        .filter(|o| is_receipt(o))
        .filter_map(|o| crate::v05::encoding::strict_parse(o).and_then(|v| canonical(&v)).ok())
        .collect();
    let mut by_index: Vec<Option<AdmitResult<()>>> = vec![None; objects.len()];
    let order: Vec<usize> = (0..objects.len())
        .filter(|i| !is_receipt(&objects[*i]))
        .chain((0..objects.len()).filter(|i| is_receipt(&objects[*i])))
        .collect();
    for i in order {
        let object = &objects[i];
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
            Ok(_) => admit_full(&next, object, &[], &batch, now),
            Err(f) => Admission {
                state: next.clone(),
                result: Err(f.into()),
                receipts: Vec::new(),
            },
        };
        next = result.state;
        by_index[i] = Some(result.result);
        receipts.extend(result.receipts);
    }
    results.extend(by_index.into_iter().map(|r| r.unwrap_or(Err(Refusal::Conflict))));
    Ok((next, results, receipts))
}
