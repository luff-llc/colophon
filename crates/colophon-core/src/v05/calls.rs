//! Links and calls (§12.1–§12.3) as a pure function over a **given** verified view.
//!
//! The view ([`AccountView`]) is built from the history verifier's verdict by
//! [`AccountView::from_history_verifier`]; [`AccountView::from_parts_unverified`] assembles one
//! from parts the caller vouches for (tests and tools only). Both check every invariant and
//! validates every structural invariant and returns an error instead of panicking. Its only
//! production caller is the history verifier of plan Step 3 (§17.2); this crate does not
//! verify authority histories yet, so the controllers, members and policies it is given are
//! the caller's claim. Heads are never taken on trust: the view holds head *envelopes*, and
//! [`verify_call`] verifies each with [`super::heads::verify_head`] at the call's clock.
//!
//! Statuses that come from pending transitions (pending addition or removal, suspension,
//! additions not yet final) are inputs; §8.7 is outside this step.
//!
//! The replay store (§12.4) is read at step 3 and reserved by compare-and-swap only after step
//! 8, so no refusal reserves; the reservation is left `Pending` for the service.
use super::descriptor::{Controller, KeyForm, Policy, Role};
use super::encoding::{
    bounds, canonical, canonical_body, decode_base64, decode_request_id, digest, is_digest, Obj,
};
use super::heads::{verify_head, HeadContext};
use super::ids::{key_id, AccountId};
use super::members::MemberKind;
use super::replay::{ReplayKey, ReplayStore, Reservation, MAX_WINDOW_MS};
use super::signature::{
    verify_assertion_possession, verify_raw, verify_webauthn, AssertionBytes, OriginRule,
    RawEnvelope, SigFailure, Strictness,
};
use super::terms::{valid_audience, valid_purpose, Terms, TermsKind, Truth};
use super::{bad_signature, malformed, require, Failure, Reason, Result, Unknown};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The purpose a `recover`-only (or suspended) controller may call (§12.3 step 5, §13.4).
pub const HISTORY_READ: &str = "colophon.history.read";
/// The purposes a home accepts at its own endpoints without configuration (§12.3 step 7).
pub const HOME_PURPOSES: [&str; 3] = [HISTORY_READ, "colophon.home.read", "colophon.home.write"];

/// A controller's status from pending transitions (§8.7), supplied by the history verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerStatus {
    /// No pending change affects it.
    Active,
    /// A pending transition would add it: not a controller yet (`refused:revoked`).
    PendingAddition,
    /// A pending transition would remove it: it works until activation.
    PendingRemoval,
    /// Suspended by a `suspend` entry: it may call only `colophon.history.read`.
    Suspended,
    /// Added by an activation that is not yet final at this verifier (`refused:revoked`).
    AddedNotFinal,
}
/// A member's status from activations (§8.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// Granted by an immediate entry, or by a final activation.
    Active,
    /// Added (for example appointed as a home) by an activation that isn't final yet: its
    /// calls are `refused:revoked` and, as a home, its heads don't count.
    AddedNotFinal,
}

/// A controller in the view: its state after each held entry that changed it.
#[derive(Clone, Debug)]
pub struct ViewController {
    id: String,
    versions: Vec<(u64, Option<Controller>)>,
    status: ControllerStatus,
}
impl ViewController {
    /// `versions` is `(seq, state)` in strictly increasing seq order from 1, `None` meaning
    /// removed at that seq; every state names the same key. A controller whose addition is
    /// pending may have no versions (`id` names it).
    pub fn new(
        id: String,
        versions: Vec<(u64, Option<Controller>)>,
        status: ControllerStatus,
    ) -> Result<Self> {
        require(super::ids::is_key_id(&id), "controller ID is not a key ID")?;
        require(
            !versions.is_empty() || status == ControllerStatus::PendingAddition,
            "controller has no versions",
        )?;
        require(
            versions.first().is_none_or(|(_, c)| c.is_some()),
            "a controller's first version is its addition",
        )?;
        require(
            versions.first().is_none_or(|(s, _)| *s >= 1),
            "seqs start at 1",
        )?;
        require(
            versions.windows(2).all(|w| w[0].0 < w[1].0),
            "versions must be in strictly increasing seq order",
        )?;
        require(
            versions
                .iter()
                .all(|(_, c)| c.as_ref().is_none_or(|c| c.id() == id)),
            "a version names another key",
        )?;
        Ok(Self {
            id,
            versions,
            status,
        })
    }
    /// The controller ID.
    pub fn id(&self) -> &str {
        &self.id
    }
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
    fn removed_after(&self, seq: u64) -> bool {
        self.versions.iter().any(|(s, c)| *s > seq && c.is_none())
    }
}

/// A member in the view.
#[derive(Clone, Debug)]
pub struct ViewMember {
    id: String,
    signing: Vec<u8>,
    kind: MemberKind,
    terms: Terms,
    granted_seq: u64,
    renewals: Vec<(u64, i64)>,
    end_sessions: Vec<u64>,
    revoked_seq: Option<u64>,
    status: MemberStatus,
}
impl ViewMember {
    /// A member granted at `granted_seq`, with each `renew` as `(seq, new expiry ms)`, each
    /// `endSessions` seq and the revocation seq, all after the grant and in increasing order.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signing: Vec<u8>,
        kind: MemberKind,
        terms: Terms,
        granted_seq: u64,
        renewals: Vec<(u64, i64)>,
        end_sessions: Vec<u64>,
        revoked_seq: Option<u64>,
        status: MemberStatus,
    ) -> Result<Self> {
        require(
            super::descriptor::valid_point(&signing),
            "member signing point is invalid",
        )?;
        require(granted_seq >= 1, "granted_seq must be at least 1")?;
        require(
            renewals.iter().all(|(s, _)| *s > granted_seq)
                && renewals.windows(2).all(|w| w[0].0 < w[1].0),
            "renewals must follow the grant in increasing seq order",
        )?;
        require(
            end_sessions.iter().all(|s| *s > granted_seq)
                && end_sessions.windows(2).all(|w| w[0] < w[1]),
            "endSessions must follow the grant in increasing seq order",
        )?;
        require(
            revoked_seq.is_none_or(|r| r > granted_seq),
            "revocation must follow the grant",
        )?;
        Ok(Self {
            id: key_id(&signing),
            signing,
            kind,
            terms,
            granted_seq,
            renewals,
            end_sessions,
            revoked_seq,
            status,
        })
    }
    /// The member ID.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// The member's kind.
    pub fn kind(&self) -> &MemberKind {
        &self.kind
    }
    fn expiry_at(&self, seq: u64) -> Option<i64> {
        self.renewals
            .iter()
            .rev()
            .find(|(s, _)| *s <= seq)
            .map(|(_, e)| *e)
            .or(self.terms.expires_ms())
    }
    fn max_seq(&self) -> u64 {
        [
            Some(self.granted_seq),
            self.renewals.last().map(|r| r.0),
            self.end_sessions.last().copied(),
            self.revoked_seq,
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0)
    }
    /// True when this member counts as a home at `now_ms`: `serves` home, final, not revoked,
    /// not expired (§13.1, §13.3).
    pub fn is_current_home(&self, now_ms: i64) -> bool {
        self.terms.serves_home()
            && self.status == MemberStatus::Active
            && self.revoked_seq.is_none()
            && self.expiry_at(u64::MAX).is_none_or(|e| now_ms <= e)
    }
}

/// What the history verifier hands the call pipeline.
#[derive(Clone, Debug)]
pub struct HistoryVerifierOutput {
    /// The account.
    pub account: AccountId,
    /// Body digests of the held verified history; `history[0]` is seq 1.
    pub history: Vec<String>,
    /// `(seq, policy in force from seq)`, strictly increasing, the first at seq 1.
    pub policies: Vec<(u64, Policy)>,
    /// Every controller ever present (and any whose addition is pending).
    pub controllers: Vec<ViewController>,
    /// Every member ever granted.
    pub members: Vec<ViewMember>,
    /// Head envelopes as received; verified at each call.
    pub heads: Vec<Vec<u8>>,
    /// An unresolved vouched fork (§8.6), as classified by the history verifier.
    pub vouched_fork: bool,
    /// Every principal's point in the held history (§3.3 rule 4).
    pub principal_points: BTreeSet<Vec<u8>>,
}

/// The verified view a call is evaluated over. Sealed: see the module documentation.
#[derive(Clone, Debug)]
pub struct AccountView {
    v: HistoryVerifierOutput,
}
/// Most head envelopes a view holds (more homes than §13.1's 8 can't be current).
pub const MAX_VIEW_HEADS: usize = 64;

impl AccountView {
    /// Build a view from the history verifier's verdict over `objects` (§8, §17.2), at the
    /// verifier's clock. Statuses come from the verdict: controllers added by an activation with
    /// no finality are `AddedNotFinal`; outstanding suspensions (until their transition's due
    /// time + 7 days) are `Suspended`; held transitions that are valid against the state and not
    /// recorded make the keys they add `PendingAddition` and the keys they remove
    /// `PendingRemoval`. An unresolved fork makes every call `refused:fork`.
    pub fn from_history_verifier(
        verdict: &crate::v05::history::Verdict,
        objects: &crate::v05::history::Objects,
        now_ms: i64,
    ) -> Result<Self> {
        use crate::v05::history::{check_pending_transition, HomeStatus, Stop};
        let st = verdict
            .state
            .as_ref()
            .ok_or_else(|| Failure::Unavailable("no verified history".into()))?;
        let mut statuses: BTreeMap<String, ControllerStatus> = BTreeMap::new();
        for id in st.keyring().controllers.keys() {
            if st.controller_provisional(id).is_some() {
                statuses.insert(id.clone(), ControllerStatus::AddedNotFinal);
            }
        }
        for sp in &st.suspensions {
            if now_ms <= sp.ends_ms() {
                statuses.insert(sp.key.clone(), ControllerStatus::Suspended);
            }
        }
        let mut pending_add: Vec<String> = Vec::new();
        for o in &objects.pending {
            let Ok(env) = crate::v05::history::envelope::AuthEnvelope::parse(
                o,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                false,
            ) else {
                continue;
            };
            if env.value.get("protocol").and_then(Value::as_str) != Some("colophon/transition/5")
                || st.recorded.contains(&env.digest)
                || check_pending_transition(st, o).is_err()
            {
                continue;
            }
            let kc = env.value.get("change").and_then(|c| c.get("keyring"));
            for id in kc
                .and_then(|k| k.get("remove"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(id) = id.as_str() {
                    statuses
                        .entry(id.to_string())
                        .or_insert(ControllerStatus::PendingRemoval);
                }
            }
            for c in kc
                .and_then(|k| k.get("add"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Ok(c) = Controller::parse(c.clone(), "add") {
                    if !st.keyring().controllers.contains_key(&c.id()) {
                        pending_add.push(c.id());
                    }
                }
            }
        }
        let mut controllers = Vec::new();
        for (id, versions) in &st.ever {
            let status = statuses
                .get(id)
                .copied()
                .unwrap_or(ControllerStatus::Active);
            controllers.push(ViewController::new(id.clone(), versions.clone(), status)?);
        }
        for id in pending_add {
            if !st.ever.contains_key(&id) {
                controllers.push(ViewController::new(
                    id,
                    Vec::new(),
                    ControllerStatus::PendingAddition,
                )?);
            }
        }
        let mut members = Vec::new();
        for m in st.members() {
            let status = if m.provisional.is_some() {
                MemberStatus::AddedNotFinal
            } else {
                MemberStatus::Active
            };
            let _ = HomeStatus::Home;
            members.push(ViewMember::new(
                m.request.signing.clone(),
                m.request.kind.clone(),
                m.terms.clone(),
                m.granted_seq,
                m.renewals.clone(),
                m.end_sessions.clone(),
                m.revoked_seq,
                status,
            )?);
        }
        Self::from_parts_unverified(HistoryVerifierOutput {
            account: st.account().clone(),
            history: st.history().to_vec(),
            policies: st.policies.clone(),
            controllers,
            members,
            heads: objects.heads.clone(),
            vouched_fork: matches!(verdict.stop, Some(Stop::Fork { .. })),
            principal_points: st
                .points
                .iter()
                .filter(|p| p.len() == 65)
                .cloned()
                .collect(),
        })
    }
    /// Assemble a view from parts the caller vouches for, checking every structural invariant.
    /// Production code builds views with [`AccountView::from_history_verifier`]; this is for
    /// tests and tools, and anything it is given is outside this crate's guarantees.
    pub fn from_parts_unverified(v: HistoryVerifierOutput) -> Result<Self> {
        let held = v.history.len() as u64;
        require(held >= 1, "a view needs at least the genesis")?;
        require(
            v.history.iter().all(|d| is_digest(d)),
            "history digests must be 64 lowercase hex",
        )?;
        require(
            v.policies.first().is_some_and(|(s, _)| *s == 1),
            "the first policy is at seq 1",
        )?;
        require(
            v.policies.windows(2).all(|w| w[0].0 < w[1].0),
            "policies must be in increasing seq order",
        )?;
        require(
            v.policies.iter().all(|(s, _)| *s <= held),
            "a policy is beyond the held history",
        )?;
        let mut ids = BTreeSet::new();
        for c in &v.controllers {
            require(ids.insert(c.id.clone()), "duplicate controller in the view")?;
            require(
                c.versions.iter().all(|(s, _)| *s <= held),
                "a controller version is beyond the held history",
            )?;
        }
        let mut mids = BTreeSet::new();
        for m in &v.members {
            require(mids.insert(m.id.clone()), "duplicate member in the view")?;
            require(
                m.max_seq() <= held,
                "a member change is beyond the held history",
            )?;
        }
        require(v.heads.len() <= MAX_VIEW_HEADS, "too many head envelopes")?;
        require(
            v.heads
                .iter()
                .all(|h| h.len() <= bounds::HEAD_BODY * 2 + 4_096),
            "head envelope exceeds its bound",
        )?;
        Ok(Self { v })
    }
    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.v.account
    }
    /// The status of controller `id` in this view.
    pub fn controller_status(&self, id: &str) -> Option<ControllerStatus> {
        self.v
            .controllers
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.status)
    }
    /// Held history digests.
    pub fn history(&self) -> &[String] {
        &self.v.history
    }
    fn policy_at(&self, seq: u64) -> Option<&Policy> {
        self.v
            .policies
            .iter()
            .rev()
            .find(|(s, _)| *s <= seq)
            .map(|(_, p)| p)
    }
    /// Current homes at `now_ms`: `(member ID, signing point)`.
    pub fn current_homes(&self, now_ms: i64) -> Vec<(String, Vec<u8>)> {
        self.v
            .members
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
    /// Purposes allowed for controller calls.
    pub controller_purposes: &'a [String],
    /// This verifier's own home endpoints, when it is a home of the account: there it accepts
    /// `colophon.history.read`, `colophon.home.read` and `colophon.home.write` without
    /// configuration, as §13.4 and §14 allow them.
    pub home_endpoints: &'a [String],
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
    let terms = Terms::parse(o.value("terms")?, TermsKind::Link)?;
    unknown
        .0
        .extend(terms.unknown_outside_conditions().0.iter().cloned());
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

/// `|a − b| ≤ window`, in checked arithmetic over any `i64` inputs.
fn within(a_ms: i64, b_ms: i64, window_ms: i128) -> bool {
    (i128::from(a_ms) - i128::from(b_ms)).abs() <= window_ms
}
fn secs(s: u64) -> i128 {
    i128::from(s) * 1_000
}
fn revoked() -> Failure {
    Failure::Refused(Reason::Revoked)
}
fn refused(r: Reason) -> Failure {
    Failure::Refused(r)
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
fn index(seq: u64) -> Result<usize> {
    usize::try_from(seq.checked_sub(1).ok_or_else(|| malformed("seq 0"))?)
        .map_err(|_| malformed("seq"))
}

/// Verify a call envelope (§12.3) over `view`. On success the reservation is `Pending` in
/// `store`; the service MUST complete or abandon it (§12.4).
pub fn verify_call(
    envelope: &[u8],
    view: &AccountView,
    cfg: &CallConfig<'_>,
    store: &mut dyn ReplayStore,
) -> Result<VerifiedCall> {
    let v = &view.v;
    // 1. Parse.
    let call = Call::parse(envelope)?;
    // 2. Possession, under `key`, before anything is looked up.
    match call.assertion_bytes() {
        None => verify_raw(&call.key, &call.body, &call.signature)
            .map_err(|e| bad_signature(format!("possession: {e}")))?,
        Some(a) => {
            verify_assertion_possession(&call.key, &call.body, &call.signature, a).map_err(
                |e| match e {
                    SigFailure::ClientDataBound => malformed("clientData exceeds 8,192 bytes"),
                    e => bad_signature(format!("possession: {e}")),
                },
            )?;
        }
    }
    // 3. Audience, window, read-only replay look-up.
    require_refused(
        cfg.audiences.iter().any(|a| a == &call.audience),
        Reason::Audience,
    )?;
    require_refused(
        within(call.created_ms, cfg.now_ms, i128::from(MAX_WINDOW_MS)),
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
    if call.account != v.account.as_str() {
        return Err(Failure::Unavailable(
            "no verified history for this account".into(),
        ));
    }
    let held = v.history.len() as u64;
    let (as_of_seq, as_of_digest) = &call.as_of;
    if *as_of_seq > held {
        return Err(Failure::Unavailable(
            "asOf is beyond the held history".into(),
        ));
    }
    if &v.history[index(*as_of_seq)?] != as_of_digest {
        return Err(refused(Reason::Fork));
    }
    let latest_policy = view
        .policy_at(held)
        .ok_or_else(|| Failure::Unavailable("no policy".into()))?;
    let homes = view.current_homes(cfg.now_ms);
    let mut best: BTreeMap<String, u64> = BTreeMap::new();
    for envelope in &v.heads {
        let ctx = HeadContext {
            account: &v.account,
            history: &v.history,
            homes: &homes,
            now_ms: cfg.now_ms,
        };
        match verify_head(envelope, ctx) {
            Ok(h) if h.fresh(cfg.now_ms, latest_policy.head_max_age()) => {
                let e = best.entry(h.by().to_string()).or_insert(0);
                *e = (*e).max(h.seq());
            }
            Ok(_) => {}
            Err(Failure::Refused(Reason::Fork)) => return Err(refused(Reason::Fork)),
            Err(Failure::Unavailable(m)) if m.contains("not held") => {
                return Err(Failure::Unavailable(
                    "not fetched up to the highest head".into(),
                ))
            }
            // A head that doesn't verify is evidence of nothing and doesn't count.
            Err(_) => {}
        }
    }
    let quorum = usize::try_from(latest_policy.head_quorum()).unwrap_or(usize::MAX);
    if homes.is_empty() || quorum == 0 || best.len() < quorum {
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
    for (_, later) in v.policies.iter().filter(|(seq, _)| *seq > s) {
        policy = policy.restrict_for_calls(later);
    }
    require_refused(
        within(call.created_ms, cfg.now_ms, secs(policy.call_window())),
        Reason::Window,
    )?;
    if v.vouched_fork {
        return Err(refused(Reason::Fork));
    }
    // 5. Signer at S, with removals beyond S applied.
    let mut undecidable = false;
    let mut member: Option<&ViewMember> = None;
    match &call.signer {
        CallSigner::Controller(id) => {
            let vc = v
                .controllers
                .iter()
                .find(|c| &c.id == id)
                .ok_or_else(revoked)?;
            let (at_s, latest) = match (vc.at(s), vc.latest()) {
                (Some(a), Some(l)) if !vc.removed_after(s) => (a, l),
                _ => return Err(revoked()),
            };
            match vc.status {
                ControllerStatus::PendingAddition | ControllerStatus::AddedNotFinal => {
                    return Err(revoked())
                }
                ControllerStatus::Suspended if call.purpose != HISTORY_READ => {
                    return Err(revoked())
                }
                _ => {}
            }
            let both = |r: &Role| at_s.has(r) && latest.has(r);
            let sign_ok = both(&Role::Sign)
                && [at_s, latest]
                    .iter()
                    .all(|c| c.audiences().is_some_and(|a| a.contains(&call.audience)));
            let role_ok = both(&Role::Approve)
                || both(&Role::Control)
                || sign_ok
                || (both(&Role::Recover) && call.purpose == HISTORY_READ);
            require_refused(role_ok, Reason::OutOfScope)?;
            require_sig(
                latest.key().signing() == call.key.as_slice()
                    && at_s.key().signing() == call.key.as_slice(),
                "controller key differs from the call key",
            )?;
            // The call must meet both states' form and UV requirements.
            let uv = at_s.verification() || latest.verification();
            let mut origin: Option<String> = None;
            for c in [at_s, latest] {
                match (c.key().form(), call.assertion_bytes()) {
                    (KeyForm::Unknown(_), _) => undecidable = true,
                    (KeyForm::Raw { .. }, None) => {}
                    (KeyForm::WebAuthn(w), Some(a)) => {
                        let ok = verify_webauthn(
                            c.key().signing(),
                            w,
                            &call.body,
                            &call.signature,
                            a,
                            uv,
                            OriginRule::General,
                            Strictness::Current,
                        )
                        .map_err(|e| match e {
                            SigFailure::ClientDataBound => {
                                malformed("clientData exceeds 8,192 bytes")
                            }
                            e => bad_signature(e.to_string()),
                        })?;
                        origin = Some(ok.origin);
                    }
                    _ => {
                        return Err(bad_signature(
                            "the call's form disagrees with the controller's descriptor",
                        ))
                    }
                }
            }
            if let (Some(origin), Some(w)) = (origin, latest.key().webauthn()) {
                let allowed = cfg
                    .call_origins
                    .get(w.rp())
                    .is_some_and(|list| list.iter().any(|o| o == &origin));
                require_refused(allowed, Reason::Origin)?;
            }
        }
        CallSigner::Member(id) => {
            let m = v.members.iter().find(|m| &m.id == id).ok_or_else(revoked)?;
            if m.granted_seq > s
                || m.revoked_seq.is_some()
                || m.status == MemberStatus::AddedNotFinal
            {
                return Err(revoked());
            }
            if m.expiry_at(s).is_some_and(|e| cfg.now_ms > e) {
                return Err(refused(Reason::Expired));
            }
            member = Some(m);
        }
    }
    // 6. Chain: first every binding and the acting key (badSignature), then link by link.
    if let Some(m) = member {
        let mut prev_key: &[u8] = &m.signing;
        for l in &call.links {
            require_sig(
                l.env.verify(prev_key).is_ok()
                    && l.account == call.account
                    && l.from == key_id(prev_key),
                "link does not verify under the previous key, or names another account or from",
            )?;
            prev_key = &l.to;
        }
        require_sig(
            call.key == prev_key,
            "the acting key is not the last link's to.signing",
        )?;
        let mut prev_terms: &Terms = &m.terms;
        let mut prev_expiry: Option<i64> = m.expiry_at(s);
        for (i, l) in call.links.iter().enumerate() {
            if i == 0 {
                require_refused(
                    l.session == Some(m.end_sessions.len() as u64),
                    Reason::Ended,
                )?;
            }
            let in_time = l.not_before_ms <= cfg.now_ms
                && cfg.now_ms <= l.expires_ms
                && prev_expiry.is_none_or(|e| l.expires_ms <= e)
                && i128::from(l.expires_ms) - i128::from(l.not_before_ms)
                    <= secs(policy.link_max_age());
            require_refused(in_time, Reason::Expired)?;
            require_refused(l.terms.narrows(prev_terms), Reason::NotNarrower)?;
            if v.principal_points.contains(&l.to) {
                return Err(malformed(
                    "a link's to.signing is a principal's key (§3.3 rule 4)",
                ));
            }
            prev_terms = &l.terms;
            prev_expiry = Some(l.expires_ms);
        }
    }
    // 7. Purpose. Conditions are three-valued: false refuses, unknown waits for step 8.
    let at_home = cfg.home_endpoints.iter().any(|e| e == &call.audience)
        && HOME_PURPOSES.contains(&call.purpose.as_str());
    let mut condition_unknown = false;
    match member {
        Some(m) => {
            let home_read =
                at_home && call.links.is_empty() && call.purpose != "colophon.home.write";
            let allowed = home_read
                || (m.terms.allows(&call.audience, &call.purpose)
                    && call
                        .links
                        .iter()
                        .all(|l| l.terms.allows(&call.audience, &call.purpose)));
            require_refused(allowed, Reason::OutOfScope)?;
            let truth = Truth::all(
                std::iter::once(m.terms.conditions_on(&call.args))
                    .chain(call.links.iter().map(|l| l.terms.conditions_on(&call.args))),
            );
            require_refused(truth != Truth::False, Reason::OutOfScope)?;
            condition_unknown = truth == Truth::Unknown;
        }
        None => require_refused(
            at_home || cfg.controller_purposes.iter().any(|p| p == &call.purpose),
            Reason::OutOfScope,
        )?,
    }
    // 8. Extensions: unknown content in the call, links and every terms object used, including
    // terms supplied by the view; an undecided condition; a key of unknown form.
    call.unknown.check()?;
    if let Some(m) = member {
        m.terms.unknown_outside_conditions().check()?;
    }
    if condition_unknown {
        return Err(Failure::NewerFormat(
            "an unknown condition operator decided the call".into(),
        ));
    }
    if undecidable {
        return Err(Failure::NewerFormat(
            "the controller's key has an unknown form".into(),
        ));
    }
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
