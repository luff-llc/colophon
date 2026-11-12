//! Links and calls (§12.1–§12.3) as a pure function over a **given** verified view.
//!
//! The view is the caller's: the held verified history, verified heads, controllers and members
//! with the seqs at which they changed, policies, and the statuses that come from pending
//! transitions (pending addition or removal, suspension, addition not yet final), which this
//! module takes as inputs and never computes (§8.7 is outside this step).
//!
//! The pipeline is §12.3's, in order. The replay store (§12.4, revision 5) is consulted
//! read-only at step 3 and reserved by compare-and-swap only once every step has passed, so no
//! refusal reserves; the reservation is left `Pending` for the service to complete.
use super::descriptor::{Controller, Policy, Role};
use super::encoding::{
    bounds, canonical, canonical_body, decode_base64, decode_request_id, digest, Obj,
};
use super::heads::Head;
use super::ids::{key_id, AccountId};
use super::members::MemberKind;
use super::replay::{ReplayKey, ReplayStore, Reservation};
use super::signature::{
    verify_assertion_possession, verify_raw, verify_webauthn, AssertionBytes, OriginRule,
    RawEnvelope, Strictness,
};
use super::terms::{valid_audience, valid_purpose, Terms, TermsKind};
use super::{bad_signature, malformed, require, Failure, Reason, Result, Unknown};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The purpose a `recover`-only controller may call (§12.3 step 5, §13.4).
pub const HISTORY_READ: &str = "colophon.history.read";

/// A controller's status from pending transitions (§8.7), supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerStatus {
    /// No pending change affects it.
    Active,
    /// A pending transition would add it: not a controller yet.
    PendingAddition,
    /// A pending transition would remove it: it works until activation.
    PendingRemoval,
    /// Suspended by a `suspend` entry: it signs no call.
    Suspended,
    /// Added by an activation that is not yet final at this verifier: not counted for calls.
    AddedNotFinal,
}

/// A controller in the view: its state after each held entry that changed it.
#[derive(Clone, Debug)]
pub struct ViewController {
    /// Controller ID.
    pub id: String,
    /// `(seq, state)` in seq order; `None` means removed at that seq.
    pub versions: Vec<(u64, Option<Controller>)>,
    /// Status from pending transitions.
    pub status: ControllerStatus,
}
impl ViewController {
    fn at(&self, seq: u64) -> Option<&Controller> {
        self.versions
            .iter()
            .rev()
            .find(|(s, _)| *s <= seq)
            .and_then(|(_, c)| c.as_ref())
    }
    fn latest(&self) -> Option<&Controller> {
        self.versions.last().and_then(|(_, c)| c.as_ref())
    }
}

/// A member in the view.
#[derive(Clone, Debug)]
pub struct ViewMember {
    /// Member ID.
    pub id: String,
    /// Signing point.
    pub signing: Vec<u8>,
    /// Kind.
    pub kind: MemberKind,
    /// Granted terms.
    pub terms: Terms,
    /// Seq of the grant.
    pub granted_seq: u64,
    /// `(seq, new expiry ms)` of each `renew`.
    pub renewals: Vec<(u64, i64)>,
    /// Seqs of each `endSessions`.
    pub end_sessions: Vec<u64>,
    /// Seq of the revocation.
    pub revoked_seq: Option<u64>,
}
impl ViewMember {
    fn expiry_at(&self, seq: u64) -> Option<i64> {
        self.renewals
            .iter()
            .rev()
            .find(|(s, _)| *s <= seq)
            .map(|(_, e)| *e)
            .or(self.terms.expires.as_ref().map(|(_, e)| *e))
    }
    /// True when this member is a current home at `now_ms` (for head acceptance).
    pub fn is_current_home(&self, now_ms: i64) -> bool {
        self.terms.serves_home
            && self.revoked_seq.is_none()
            && self.expiry_at(u64::MAX).is_none_or(|e| now_ms <= e)
    }
}

/// The verified view a call is evaluated over.
#[derive(Clone, Debug)]
pub struct AccountView {
    /// The account.
    pub account: AccountId,
    /// Body digests of the held verified history; `history[0]` is seq 1.
    pub history: Vec<String>,
    /// `(seq, policy in force from seq)`, in seq order, starting at 1.
    pub policies: Vec<(u64, Policy)>,
    /// Every controller ever present.
    pub controllers: Vec<ViewController>,
    /// Every member ever granted.
    pub members: Vec<ViewMember>,
    /// Verified heads (see [`super::heads::verify_head`]).
    pub heads: Vec<Head>,
    /// An unresolved vouched fork (§8.6), as classified by the caller.
    pub vouched_fork: bool,
    /// Every principal's point in the held history (§3.3 rule 4).
    pub principal_points: BTreeSet<Vec<u8>>,
}
impl AccountView {
    fn policy_at(&self, seq: u64) -> Option<&Policy> {
        self.policies
            .iter()
            .rev()
            .find(|(s, _)| *s <= seq)
            .map(|(_, p)| p)
    }
    /// Current homes at `now_ms`: `(member ID, signing point)`.
    pub fn current_homes(&self, now_ms: i64) -> Vec<(String, Vec<u8>)> {
        self.members
            .iter()
            .filter(|m| m.is_current_home(now_ms))
            .map(|m| (m.id.clone(), m.signing.clone()))
            .collect()
    }
}

/// The verifier's own configuration.
#[derive(Clone, Copy, Debug)]
pub struct CallConfig<'a> {
    /// The verifier's clock, ms.
    pub now_ms: i64,
    /// The verifier's own audiences.
    pub audiences: &'a [String],
    /// Call-ceremony origins per `rp`.
    pub call_origins: &'a BTreeMap<String, Vec<String>>,
    /// Purposes allowed for controller calls. A home lists `colophon.history.read`.
    pub controller_purposes: &'a [String],
}

/// Who signed the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallSigner {
    /// A member, by ID.
    Member(String),
    /// A controller, by ID.
    Controller(String),
}

/// A parsed link (§12.1).
#[derive(Clone, Debug)]
pub struct Link {
    env: RawEnvelope,
    account: String,
    from: String,
    to: Vec<u8>,
    session: Option<u64>,
    terms: Terms,
    not_before_ms: i64,
    expires_ms: i64,
}

/// A parsed call.
#[derive(Clone, Debug)]
pub struct Call {
    /// Exact body bytes.
    pub body: Vec<u8>,
    /// Body digest.
    pub digest: String,
    signature: Vec<u8>,
    assertion: Option<(Vec<u8>, Vec<u8>)>,
    /// The account named.
    pub account: String,
    /// `asOf`.
    pub as_of: (u64, String),
    /// The signer.
    pub signer: CallSigner,
    /// The acting key.
    pub key: Vec<u8>,
    links: Vec<Link>,
    /// Audience.
    pub audience: String,
    /// Purpose.
    pub purpose: String,
    /// Arguments.
    pub args: Value,
    /// `requestId` as sent.
    pub request_id: String,
    created_ms: i64,
    unknown: Unknown,
}

/// A call that passed every step, with its reservation left `Pending`.
#[derive(Clone, Debug)]
pub struct VerifiedCall {
    /// The call.
    pub call: Call,
    /// S, the seq the signer was evaluated at.
    pub evaluated_at: u64,
    /// The reservation key; the service completes or abandons it.
    pub replay_key: ReplayKey,
}

fn parse_link(text: &Value, first: bool, unknown: &mut Unknown) -> Result<Link> {
    let Value::String(text) = text else {
        return Err(malformed("links entries must be strings"));
    };
    let bytes = decode_base64(text, bounds::LINK_BODY * 2 + 4_096)?;
    let env = RawEnvelope::parse(&bytes, bounds::LINK_BODY, true)?;
    let mut o = Obj::new(env.value.clone(), "link")?;
    require(
        o.string("protocol")? == "colophon/link/5",
        "embedded link is not colophon/link/5",
    )?;
    let account = o.string("account")?;
    AccountId::parse(&account)?;
    let from = o.key_id("from")?;
    let mut to = o.obj("to")?;
    let to_point = to.bytes("signing", 65)?;
    require(
        super::descriptor::valid_point(&to_point),
        "link to.signing is not a valid point",
    )?;
    to.finish(unknown);
    let session = o.opt_uint("session")?;
    require(
        session.is_some() == first,
        "session is present exactly on the first link",
    )?;
    let terms = Terms::parse(o.value("terms")?, TermsKind::Link, unknown)?;
    let (_, not_before_ms) = o.date("notBefore")?;
    let (_, expires_ms) = o.date("expires")?;
    let _created = o.date("created")?;
    require(
        not_before_ms <= expires_ms,
        "link notBefore is after expires",
    )?;
    o.finish(unknown);
    Ok(Link {
        env,
        account,
        from,
        to: to_point,
        session,
        terms,
        not_before_ms,
        expires_ms,
    })
}

impl Call {
    /// §12.3 step 1: bounds, protocol, embedded links and well-formed fields. Unknown content
    /// is collected for step 8.
    pub fn parse(envelope: &[u8]) -> Result<Self> {
        require(
            envelope.len() <= bounds::CALL_BODY * 2 + 4 * bounds::CLIENT_DATA,
            "call envelope exceeds its bound",
        )?;
        let outer = super::encoding::strict_parse(envelope)?;
        let mut e = Obj::new(outer, "envelope")?;
        let body = decode_base64(&e.string("body")?, bounds::CALL_BODY)?;
        let assertion = match e.opt_obj("assertion")? {
            None => None,
            Some(mut a) => {
                let data = a.bytes("authenticatorData", bounds::CLIENT_DATA)?;
                let client = a.bytes("clientData", bounds::CLIENT_DATA)?;
                a.finish_closed()?;
                Some((data, client))
            }
        };
        let signature = decode_base64(
            &e.string("signature")?,
            if assertion.is_some() { 72 } else { 64 },
        )?;
        e.finish_closed()?;
        let value = canonical_body(&body, bounds::CALL_BODY)?;
        let mut unknown = Unknown::default();
        let mut o = Obj::new(value, "call")?;
        require(
            o.string("protocol")? == "colophon/call/5",
            "not a colophon/call/5 call",
        )?;
        let account = o.string("account")?;
        AccountId::parse(&account)?;
        let mut as_of = o.obj("asOf")?;
        let as_of_seq = as_of.uint("seq")?;
        require(as_of_seq >= 1, "asOf.seq must be at least 1")?;
        let as_of_digest = as_of.digest("digest")?;
        as_of.finish(&mut unknown);
        let signer_value = o.value("signer")?;
        let signer = match &signer_value {
            Value::Object(m) if m.len() == 1 => match m.iter().next() {
                Some((k, Value::String(id))) if k == "member" && super::ids::is_key_id(id) => {
                    CallSigner::Member(id.clone())
                }
                Some((k, Value::String(id))) if k == "controller" && super::ids::is_key_id(id) => {
                    CallSigner::Controller(id.clone())
                }
                _ => return Err(malformed("signer must be {member} or {controller}")),
            },
            _ => return Err(malformed("signer must be {member} or {controller}")),
        };
        let key = o.bytes("key", 65)?;
        require(
            super::descriptor::valid_point(&key),
            "key is not a valid point",
        )?;
        let links = match o.opt_nonempty_array("links")? {
            None => Vec::new(),
            Some(items) => {
                require(
                    matches!(signer, CallSigner::Member(_)),
                    "a controller call carries no links",
                )?;
                require(items.len() <= 4, "at most 4 links")?;
                items
                    .iter()
                    .enumerate()
                    .map(|(i, l)| parse_link(l, i == 0, &mut unknown))
                    .collect::<Result<Vec<_>>>()?
            }
        };
        let mut seen = BTreeSet::new();
        for l in &links {
            require(
                seen.insert(l.to.clone()),
                "a link to.signing repeats within the call (§3.3 rule 4)",
            )?;
        }
        let audience = o.string("audience")?;
        require(valid_audience(&audience), "invalid audience")?;
        let purpose = o.string("purpose")?;
        require(valid_purpose(&purpose), "invalid purpose")?;
        let args = o.value("args")?;
        require(args.is_object(), "args must be an object")?;
        require(
            canonical(&args)?.len() <= bounds::CALL_ARGS,
            "args exceed 16,384 bytes",
        )?;
        let request_id = o.string("requestId")?;
        decode_request_id(&request_id)?;
        let (_, created_ms) = o.date("created")?;
        o.finish(&mut unknown);
        if assertion.is_some() {
            require(
                matches!(signer, CallSigner::Controller(_)),
                "only a WebAuthn controller's call carries an assertion",
            )?;
        }
        Ok(Self {
            digest: digest(&body),
            body,
            signature,
            assertion,
            account,
            as_of: (as_of_seq, as_of_digest),
            signer,
            key,
            links,
            audience,
            purpose,
            args,
            request_id,
            created_ms,
            unknown,
        })
    }
    fn assertion_bytes(&self) -> Option<AssertionBytes<'_>> {
        self.assertion.as_ref().map(|(d, c)| AssertionBytes {
            authenticator_data: d,
            client_data: c,
        })
    }
    /// The reservation key.
    pub fn replay_key(&self) -> ReplayKey {
        ReplayKey {
            account: self.account.clone(),
            audience: self.audience.clone(),
            acting_key: key_id(&self.key),
            purpose: self.purpose.clone(),
            request_id: self.request_id.clone(),
        }
    }
}

fn window_ok(created_ms: i64, now_ms: i64, seconds: u64) -> bool {
    (created_ms - now_ms).unsigned_abs() <= seconds.saturating_mul(1_000)
}
fn revoked() -> Failure {
    Failure::Refused(Reason::Revoked)
}
fn refused(r: Reason) -> Failure {
    Failure::Refused(r)
}

/// Verify a call envelope (§12.3) over `view`. On success the reservation is `Pending` in
/// `store`; the service MUST complete or abandon it (§12.4).
pub fn verify_call(
    envelope: &[u8],
    view: &AccountView,
    cfg: &CallConfig<'_>,
    store: &mut dyn ReplayStore,
) -> Result<VerifiedCall> {
    // 1. Parse.
    let call = Call::parse(envelope)?;
    // 2. Possession, under `key`, before anything is looked up.
    match call.assertion_bytes() {
        None => verify_raw(&call.key, &call.body, &call.signature)
            .map_err(|e| bad_signature(format!("possession: {e}")))?,
        Some(a) => {
            verify_assertion_possession(&call.key, &call.body, &call.signature, a)
                .map_err(|e| bad_signature(format!("possession: {e}")))?;
        }
    }
    // 3. Audience, window, replay (read-only consultation).
    require_refused(
        cfg.audiences.iter().any(|a| a == &call.audience),
        Reason::Audience,
    )?;
    require_refused(
        window_ok(call.created_ms, cfg.now_ms, 3_600),
        Reason::Window,
    )?;
    let replay_key = call.replay_key();
    if let Some(existing) = store.lookup(&replay_key, cfg.now_ms) {
        return Err(refused(if existing.digest() == call.digest {
            Reason::Replay
        } else {
            Reason::Conflict
        }));
    }
    // 4. History and heads.
    if call.account != view.account.as_str() {
        return Err(Failure::Unavailable(
            "no verified history for this account".into(),
        ));
    }
    let held = view.history.len() as u64;
    let (as_of_seq, as_of_digest) = &call.as_of;
    if *as_of_seq > held {
        return Err(Failure::Unavailable(
            "asOf is beyond the held history".into(),
        ));
    }
    if &view.history[usize::try_from(*as_of_seq - 1).map_err(|_| malformed("asOf"))?]
        != as_of_digest
    {
        return Err(refused(Reason::Fork));
    }
    let latest_policy = view
        .policy_at(held)
        .ok_or_else(|| Failure::Unavailable("no policy".into()))?;
    let homes: BTreeSet<String> = view
        .current_homes(cfg.now_ms)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let mut best: BTreeMap<&str, u64> = BTreeMap::new();
    for h in &view.heads {
        if !homes.contains(&h.by) || !h.fresh(cfg.now_ms, latest_policy.head_max_age) {
            continue;
        }
        if h.seq > held {
            return Err(Failure::Unavailable(
                "not fetched up to the highest fresh head".into(),
            ));
        }
        if view.history[usize::try_from(h.seq - 1).map_err(|_| malformed("head"))?] != h.digest {
            return Err(refused(Reason::Fork));
        }
        let e = best.entry(&h.by).or_insert(0);
        *e = (*e).max(h.seq);
    }
    let quorum = usize::try_from(latest_policy.head_quorum).unwrap_or(usize::MAX);
    if homes.is_empty() || best.len() < quorum {
        return Err(Failure::Unavailable(
            "too few fresh heads from current homes".into(),
        ));
    }
    let mut seqs: Vec<u64> = best.values().copied().collect();
    seqs.sort_unstable_by(|a, b| b.cmp(a));
    let s = seqs[quorum - 1];
    let mut policy = view
        .policy_at(s)
        .cloned()
        .ok_or_else(|| Failure::Unavailable("no policy at S".into()))?;
    for (_, later) in view.policies.iter().filter(|(seq, _)| *seq > s) {
        policy = policy.restrict(later);
    }
    require_refused(
        window_ok(call.created_ms, cfg.now_ms, policy.call_window),
        Reason::Window,
    )?;
    if view.vouched_fork {
        return Err(refused(Reason::Fork));
    }
    // 5. Signer at S, with removals beyond S applied.
    let mut member: Option<&ViewMember> = None;
    match &call.signer {
        CallSigner::Controller(id) => {
            let vc = view
                .controllers
                .iter()
                .find(|c| &c.id == id)
                .ok_or_else(revoked)?;
            let (at_s, latest) = match (vc.at(s), vc.latest()) {
                (Some(a), Some(l)) => (a, l),
                _ => return Err(revoked()),
            };
            if matches!(
                vc.status,
                ControllerStatus::PendingAddition
                    | ControllerStatus::Suspended
                    | ControllerStatus::AddedNotFinal
            ) {
                return Err(revoked());
            }
            let both = |r: &Role| at_s.has(r) && latest.has(r);
            let sign_ok = both(&Role::Sign)
                && [at_s, latest].iter().all(|c| {
                    c.audiences
                        .as_ref()
                        .is_some_and(|a| a.contains(&call.audience))
                });
            let role_ok = both(&Role::Approve)
                || both(&Role::Control)
                || sign_ok
                || (both(&Role::Recover) && call.purpose == HISTORY_READ);
            require_refused(role_ok, Reason::OutOfScope)?;
            require_sig(
                latest.key.signing == call.key && at_s.key.signing == call.key,
                "controller key differs from the call key",
            )?;
            match (latest.key.webauthn(), call.assertion_bytes()) {
                (None, None) => {}
                (Some(_), Some(a)) => {
                    let mut origin = String::new();
                    for c in [at_s, latest] {
                        let w = c
                            .key
                            .webauthn()
                            .ok_or_else(|| bad_signature("controller form changed"))?;
                        let ok = verify_webauthn(
                            &c.key.signing,
                            w,
                            &call.body,
                            &call.signature,
                            a,
                            at_s.verification || latest.verification,
                            OriginRule::General,
                            Strictness::Current,
                        )
                        .map_err(|e| bad_signature(e.to_string()))?;
                        origin = ok.origin;
                    }
                    let rp = &latest
                        .key
                        .webauthn()
                        .map(|w| w.rp.clone())
                        .unwrap_or_default();
                    let allowed = cfg
                        .call_origins
                        .get(rp)
                        .is_some_and(|list| list.iter().any(|o| o == &origin));
                    require_refused(allowed, Reason::Origin)?;
                }
                _ => {
                    return Err(bad_signature(
                        "assertion present if and only if the controller is webauthn",
                    ))
                }
            }
        }
        CallSigner::Member(id) => {
            let m = view
                .members
                .iter()
                .find(|m| &m.id == id)
                .ok_or_else(revoked)?;
            if m.granted_seq > s || m.revoked_seq.is_some() {
                return Err(revoked());
            }
            if m.expiry_at(s).is_some_and(|e| cfg.now_ms > e) {
                return Err(refused(Reason::Expired));
            }
            member = Some(m);
        }
    }
    // 6. Chain.
    if let Some(m) = member {
        let mut prev_key: &[u8] = &m.signing;
        let mut prev_terms: &Terms = &m.terms;
        let mut prev_expiry: Option<i64> = m.expiry_at(s);
        for (i, l) in call.links.iter().enumerate() {
            require_sig(
                l.env.verify(prev_key).is_ok()
                    && l.account == call.account
                    && l.from == key_id(prev_key),
                "link does not verify under the previous key, or names another account or from",
            )?;
            if i == 0 {
                require_refused(
                    l.session == Some(m.end_sessions.len() as u64),
                    Reason::Ended,
                )?;
            }
            let in_time = l.not_before_ms <= cfg.now_ms
                && cfg.now_ms <= l.expires_ms
                && prev_expiry.is_none_or(|e| l.expires_ms <= e)
                && (l.expires_ms - l.not_before_ms)
                    <= i64::try_from(policy.link_max_age)
                        .unwrap_or(i64::MAX)
                        .saturating_mul(1_000);
            require_refused(in_time, Reason::Expired)?;
            require_refused(l.terms.narrows(prev_terms), Reason::NotNarrower)?;
            if view.principal_points.contains(&l.to) {
                return Err(malformed(
                    "a link's to.signing is a principal's key (§3.3 rule 4)",
                ));
            }
            prev_key = &l.to;
            prev_terms = &l.terms;
            prev_expiry = Some(l.expires_ms);
        }
        require_sig(
            call.key == prev_key,
            "the acting key is not the last link's to.signing",
        )?;
    }
    // 7. Purpose.
    match member {
        Some(m) => {
            let ok = m.terms.allows(&call.audience, &call.purpose)
                && m.terms.conditions_hold(&call.args)
                && call.links.iter().all(|l| {
                    l.terms.allows(&call.audience, &call.purpose)
                        && l.terms.conditions_hold(&call.args)
                });
            require_refused(ok, Reason::OutOfScope)?;
        }
        None => require_refused(
            cfg.controller_purposes.iter().any(|p| p == &call.purpose),
            Reason::OutOfScope,
        )?,
    }
    // 8. Extensions.
    call.unknown.check()?;
    // Reservation, after every step and before any effect.
    match store.reserve(&replay_key, &call.digest, cfg.now_ms) {
        Reservation::Reserved => {}
        Reservation::Replay => return Err(refused(Reason::Replay)),
        Reservation::Conflict => return Err(refused(Reason::Conflict)),
    }
    Ok(VerifiedCall {
        call,
        evaluated_at: s,
        replay_key,
    })
}
fn require_refused(ok: bool, reason: Reason) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Failure::Refused(reason))
    }
}
fn require_sig(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(bad_signature(why))
    }
}
