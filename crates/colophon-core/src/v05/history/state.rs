//! The folded state (§17.2) and the rows of §8.7's state table.
use super::envelope::{embedded_bytes, AuthEnvelope, SigItem};
use super::keyring::Keyring;
use super::Entry;
use crate::v05::descriptor::{Controller, Policy, Role};
use crate::v05::encoding::{bounds, Obj};
use crate::v05::ids::{key_id, AccountId};
use crate::v05::members::{
    AuthorityHeader, Grant, GrantContext, MemberKind, Renew, Request, Revoke,
};
use crate::v05::signature::{
    verify_authority_signature, verify_raw, AuthorityRule, Checked, RawEnvelope,
};
use crate::v05::terms::{Terms, TermsKind};
use crate::v05::{bad_signature, malformed, Failure, Result};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const SEC: i64 = 1_000;
const DAY: i64 = 86_400 * SEC;
const RECEIPT_WINDOW: i64 = 300 * SEC;

/// Why an entry wasn't applied.
#[derive(Clone, Debug)]
pub(crate) enum Outcome {
    Fail(Failure),
    Held(String),
}
impl From<Failure> for Outcome {
    fn from(f: Failure) -> Self {
        Self::Fail(f)
    }
}
type Step<T> = std::result::Result<T, Outcome>;

/// A member (§9) and, for a home, its status.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MemberRecord {
    /// The request it was admitted with.
    pub request: Request,
    /// Granted terms.
    pub terms: Terms,
    /// Seq of its grant or appointing activation.
    pub granted_seq: u64,
    /// Current expiry.
    pub expires_ms: Option<i64>,
    /// `(seq, expiry)` of each renewal.
    pub renewals: Vec<(u64, i64)>,
    /// Seqs of `endSessions`.
    pub end_sessions: Vec<u64>,
    /// Revocation seq.
    pub revoked_seq: Option<u64>,
    /// Seq of the activation that added it, when that activation isn't final yet.
    pub provisional: Option<u64>,
    /// Home status.
    pub home: HomeStatus,
}
/// A home's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HomeStatus {
    /// Not a home.
    NotHome,
    /// A current home.
    Home,
    /// Revoked by the activation at this seq, which isn't final yet: still current (§8.7).
    RevocationPending(u64),
}
/// An activation and its finality (§8.7).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Activation {
    /// Its seq.
    pub seq: u64,
    /// The `activate` body digest.
    pub digest: String,
    /// The transition body digest.
    pub transition: String,
    /// Its `by`.
    pub by: String,
    /// Its witnesses.
    pub witnesses: BTreeSet<String>,
    /// Removal-only.
    pub removal_only: bool,
    /// Final.
    pub final_: bool,
    /// Final through a `final` entry's heads, not by excusal, an empty witness set or a later
    /// full set: witnessed by homes (§8.6 rule 3, `resolve`).
    #[serde(default)]
    pub witnessed: bool,
    /// The transition's due time.
    pub due_ms: i64,
    /// Homes it revokes.
    pub revokes: Vec<String>,
}
/// An outstanding suspension.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Suspension {
    /// The suspended key.
    pub key: String,
    /// The suspending unit.
    pub unit: String,
    /// The transition's body digest.
    pub transition: String,
    /// The transition and its receipts, to re-check validity.
    pub(crate) t_bytes: Vec<u8>,
    pub(crate) receipts: Vec<Vec<u8>>,
    /// The transition's due time.
    pub due_ms: i64,
}
impl Suspension {
    /// The instant the suspension ends by the clock: due + 7 days.
    pub fn ends_ms(&self) -> i64 {
        self.due_ms.saturating_add(7 * DAY)
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CtrlMeta {
    added_seq: u64,
    /// The charged signer of the immediate `keyring` entry that added it.
    planter: Option<String>,
    /// The activation that added it, while not final.
    provisional: Option<u64>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct RateItem {
    issued: i64,
    charged: String,
    size: usize,
    account: bool,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Retiring {
    current_at_anchor: BTreeSet<String>,
}

/// The folded state of §17.2 at one entry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct State {
    pub(crate) account: AccountId,
    pub(crate) digests: Vec<String>,
    pub(crate) issued: Vec<i64>,
    pub(crate) keyring: Keyring,
    keyring_at: Vec<BTreeSet<String>>,
    delay_at: Vec<u64>,
    pub(crate) policies: Vec<(u64, Policy)>,
    meta: BTreeMap<String, CtrlMeta>,
    /// Every controller ever present, with the seqs it was present at.
    pub(crate) ever: BTreeMap<String, Vec<(u64, Option<Controller>)>>,
    namespaces: Vec<String>,
    epochs: BTreeMap<String, u64>,
    pub(crate) members: Vec<MemberRecord>,
    pub(crate) recorded: BTreeSet<String>,
    pub(crate) activations: Vec<Activation>,
    v: BTreeMap<String, u64>,
    pub(crate) suspensions: Vec<Suspension>,
    rate: Vec<RateItem>,
    retiring: Option<Retiring>,
    excused: BTreeSet<String>,
    pub(crate) points: BTreeSet<Vec<u8>>,
    /// Upgrade sequence, fencing legacy records.
    #[serde(default)]
    pub upgrade_seq: Option<u64>,
    #[serde(default)]
    pub(super) succession: Option<super::succession::Succession>,
    #[serde(default)]
    pub(super) successor: Option<String>,
    /// The seq of the activation that set `successor` (F, §15.1).
    #[serde(default)]
    pub(super) successor_seq: Option<u64>,
    #[serde(default)]
    /// Owner asserted migration manifest, when recorded.
    pub migration: Option<Value>,
    /// `(seq, digest)` of the entry each `resolve` activation on this branch kept.
    #[serde(default)]
    pub(super) resolved: Vec<(u64, String)>,
    /// The control rule in force after each seq: `(threshold, countBy holders)`, so the keyring
    /// before a fork can be judged (§8.4 `resolve`).
    #[serde(default)]
    pub(super) rule_at: Vec<(u64, bool)>,
}

impl State {
    pub(super) fn check_checkpoint_shape(&self) -> Result<()> {
        let len = self.digests.len();
        crate::v05::require(
            len > 0
                && self.issued.len() == len
                && self.keyring_at.len() == len
                && self.delay_at.len() == len
                && self.delay_at.iter().all(|d| *d <= 2_592_000)
                && self
                    .epochs
                    .values()
                    .chain(self.v.values())
                    .all(|n| *n < (1u64 << 53))
                && self.policies.iter().all(|(_, p)| {
                    p.recovery_delay() <= 2_592_000
                        && p.call_window() <= 3_600
                        && p.link_max_age() <= 2_592_000
                        && p.head_max_age() <= 86_400
                        && p.head_quorum() <= 8
                }),
            "invalid folded checkpoint shape",
        )?;
        // This is corruption detection, not authentication of a peer's state.
        let parsed = Keyring::parse(self.keyring.raw.clone(), 0)?;
        crate::v05::require(
            serde_json::to_value(parsed).ok() == serde_json::to_value(&self.keyring).ok(),
            "checkpoint keyring differs from its validated representation",
        )?;
        crate::v05::require(
            self.rule_at.len() == len && self.rule_at.iter().all(|(t, _)| (1..=64).contains(t)),
            "checkpoint rule history differs from the entries",
        )?;
        Ok(())
    }

    /// Whether the verified branch holds `digest` at `seq`.
    pub(super) fn on_branch_digest(&self, seq: u64, digest: &str) -> bool {
        self.on_branch(seq, digest)
    }

    /// The `(seq, digest)` of the entry each `resolve` activation on this branch discarded.
    pub fn resolved_forks(&self) -> &[(u64, String)] {
        &self.resolved
    }

    /// The account.
    /// Verified predecessor final reference, if established.
    pub fn verified_succession(&self) -> Option<(u64, &str)> {
        self.succession
            .as_ref()?
            .verified
            .as_ref()
            .map(|(n, d)| (*n, d.as_str()))
    }
    /// Malformed evidence after the predecessor final entry.
    pub fn predecessor_evidence(&self) -> &[u64] {
        self.succession
            .as_ref()
            .map_or(&[], |p| p.evidence_after_final.as_slice())
    }
    /// Account identifier.
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    /// Held history digests from seq 1.
    pub fn history(&self) -> &[String] {
        &self.digests
    }
    /// The current keyring.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }
    /// True while the vault is retiring (§8.3).
    pub fn vault_retiring(&self) -> bool {
        self.retiring.is_some()
    }
    /// Members.
    pub fn members(&self) -> &[MemberRecord] {
        &self.members
    }
    /// Activations and their finality.
    pub fn activations(&self) -> &[Activation] {
        &self.activations
    }
    /// Suspensions that remain in force at the caller's clock (§8.7 Clock).
    /// Expired records remain in the folded state for checks of historical entries.
    pub fn active_suspensions(&self, now_ms: i64) -> Vec<&Suspension> {
        self.suspensions
            .iter()
            .filter(|sp| now_ms <= sp.ends_ms())
            .collect()
    }
    /// v(u) per unit.
    pub fn veto_counts(&self) -> &BTreeMap<String, u64> {
        &self.v
    }
    /// The provisional activation that added controller `id`, if any.
    pub fn controller_provisional(&self, id: &str) -> Option<u64> {
        self.meta.get(id).and_then(|m| m.provisional)
    }
    /// Whether the activation of the `successor` transition (F) is final: nothing more is
    /// admitted (§15.2). A state saved without F's seq counts as final.
    pub(super) fn successor_final(&self) -> bool {
        self.successor.is_some()
            && self
                .successor_seq
                .is_none_or(|f| self.activations.iter().any(|a| a.seq == f && a.final_))
    }
    pub(super) fn seq(&self) -> u64 {
        self.digests.len() as u64
    }
    pub(super) fn last_issued(&self) -> i64 {
        self.issued.last().copied().unwrap_or(i64::MIN)
    }
    /// A controller counts: present and not added by a provisional activation.
    fn current(&self, id: &str) -> Option<&Controller> {
        let c = self.keyring.controllers.get(id)?;
        if self.meta.get(id).is_some_and(|m| m.provisional.is_some()) {
            return None;
        }
        Some(c)
    }
    fn suspended(&self, id: &str, at_ms: i64) -> bool {
        self.suspensions
            .iter()
            .any(|s| s.key == id && at_ms <= s.ends_ms())
    }
    fn unit(&self, id: &str) -> Option<String> {
        self.keyring
            .controllers
            .get(id)
            .map(|c| self.keyring.unit_of(c))
    }
    /// Homes current in this state: final home members not finally revoked, not excused.
    /// A home whose revocation is pending stays current (§8.7).
    pub fn current_homes(&self) -> Vec<&MemberRecord> {
        self.members
            .iter()
            .filter(|m| {
                m.home != HomeStatus::NotHome
                    && m.provisional.is_none()
                    && m.revoked_seq.is_none()
                    && !self.excused.contains(&m.request.member_id())
            })
            .collect()
    }
    pub(super) fn home_key(&self, id: &str) -> Option<Vec<u8>> {
        self.current_homes()
            .into_iter()
            .find(|m| m.request.member_id() == id)
            .map(|m| m.request.signing.clone())
    }
    pub(super) fn primary_home(&self) -> Option<String> {
        if let Some(p) = self.keyring.policy.primary_home() {
            return Some(p.to_string());
        }
        self.current_homes().first().map(|m| m.request.member_id())
    }
    fn on_branch(&self, seq: u64, d: &str) -> bool {
        seq >= 1 && self.digests.get((seq - 1) as usize).is_some_and(|x| x == d)
    }
}

/// Seq of a raw entry, for reporting an entry whose header doesn't parse.
pub(crate) fn raw_seq(bytes: &[u8]) -> Option<u64> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    let b = crate::v05::encoding::decode_base64(v.get("body")?.as_str()?, bounds::AUTHORITY_BODY)
        .ok()?;
    let body: Value = serde_json::from_slice(&b).ok()?;
    body.get("seq")?.as_u64()
}

// ---------------------------------------------------------------------------------------------
// Pending objects and heads.

/// Transitions, vetoes and receipts held outside the history.
#[derive(Clone, Debug, Default)]
pub(crate) struct Pending {
    pub transitions: BTreeMap<String, Vec<u8>>,
}
impl Pending {
    pub fn parse(objs: &[Vec<u8>]) -> Self {
        let mut p = Self::default();
        for o in objs {
            if let Ok(e) = AuthEnvelope::parse(
                o,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                false,
            ) {
                if e.value.get("protocol").and_then(Value::as_str) == Some("colophon/transition/5")
                {
                    p.transitions.insert(e.digest.clone(), o.clone());
                }
            }
        }
        p
    }
}
/// A head as parsed (not yet verified against a key).
#[derive(Clone, Debug)]
pub(crate) struct RawHead {
    pub env: RawEnvelope,
    pub by: String,
    pub seq: u64,
    pub digest: String,
    pub issued: i64,
}
fn parse_head(bytes: &[u8], embedded: bool) -> Result<RawHead> {
    let env = RawEnvelope::parse(bytes, bounds::HEAD_BODY, embedded)?;
    let mut o = Obj::new(env.value.clone(), "head")?;
    crate::v05::require(o.string("protocol")? == "colophon/head/5", "not a head")?;
    let _account = o.string("account")?;
    let mut a = o.obj("authority")?;
    let seq = a.uint("seq")?;
    let digest = a.digest("digest")?;
    let (_, issued) = o.date("issued")?;
    let by = o.key_id("by")?;
    Ok(RawHead {
        env,
        by,
        seq,
        digest,
        issued,
    })
}
#[derive(Clone, Debug, Default)]
pub(crate) struct HeadSet {
    pub heads: Vec<RawHead>,
}
impl HeadSet {
    pub fn parse(objs: &[Vec<u8>]) -> Self {
        Self {
            heads: objs
                .iter()
                .filter_map(|h| parse_head(h, false).ok())
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Signatures.

fn check_item(
    c: &Controller,
    body: &[u8],
    item: &SigItem,
    rule: AuthorityRule,
    undecidable: &mut bool,
) -> Result<()> {
    match verify_authority_signature(c, body, &item.signature, item.assertion_bytes(), rule)? {
        Checked::Verified => Ok(()),
        Checked::UndecidableForm => {
            *undecidable = true;
            Ok(())
        }
    }
}

/// Signer units holding a role.
fn units(k: &Keyring, ids: &[String], role: &Role) -> BTreeSet<String> {
    ids.iter()
        .filter_map(|i| k.controllers.get(i))
        .filter(|c| c.has(role))
        .map(|c| k.unit_of(c))
        .collect()
}
fn all_units(k: &Keyring, ids: &[String]) -> BTreeSet<String> {
    ids.iter()
        .filter_map(|i| k.controllers.get(i))
        .map(|c| k.unit_of(c))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Genesis.

pub(crate) fn genesis(e: &Entry, now_ms: i64, predecessor: &[Vec<u8>]) -> Step<State> {
    if e.seq != 1 || e.kind != "genesis" {
        return Err(malformed("seq 1 must be a genesis").into());
    }
    if e.issued > now_ms.saturating_add(60 * SEC) {
        return Err(Outcome::Held("issued more than 60 s ahead".into()));
    }
    let v = &e.env.value;
    let succession = super::succession::prepare(e, predecessor, now_ms)?;
    // Step 1 reads the keyring's controllers to bind the signer.
    let keyring = Keyring::parse(v.get("keyring").cloned().unwrap_or(Value::Null), 1)?;
    let by = keyring
        .controllers
        .get(&e.by)
        .ok_or_else(|| bad_signature("by is not a controller of the genesis keyring"))?;
    let primary = e
        .env
        .primary
        .as_ref()
        .ok_or_else(|| bad_signature("genesis is unsigned"))?;
    let mut undecidable = false;
    check_item(
        by,
        &e.env.body,
        primary,
        AuthorityRule::Control,
        &mut undecidable,
    )?;
    for c in &e.env.cosignatures {
        let k = keyring
            .controllers
            .get(&c.signer)
            .ok_or_else(|| bad_signature("foreign cosigner"))?;
        check_item(k, &e.env.body, c, AuthorityRule::Control, &mut undecidable)?;
    }
    for a in &e.env.additions {
        let k = keyring
            .controllers
            .get(&a.signer)
            .ok_or_else(|| bad_signature("foreign possession proof"))?;
        crate::v05::require(
            a.signer != e.by,
            "the primary signer needs no additions item",
        )
        .map_err(Outcome::from)?;
        check_item(
            k,
            &e.env.body,
            a,
            AuthorityRule::Possession,
            &mut undecidable,
        )?;
    }
    // Control rule over its keyring; possession by every other controller (§8.4).
    let signers = e.env.signer_ids();
    let control = units(&keyring, &signers, &Role::Control);
    if (control.len() as u64) < keyring.threshold
        || signers.iter().any(|s| {
            !keyring.controllers[s].has(&Role::Control)
                && !keyring.controllers[s].has(&Role::Recover)
        })
    {
        return Err(bad_signature("genesis: control rule not met").into());
    }
    // A carried key is exempt only when the succession is authorized (§8.4 Possession): for Swift
    // the genesis's `handover` meets the rule that may write F at `head`; for `/5` the succession
    // is verified, F final. A genesis that needs the exemption while a `/5` succession is still
    // undecided is held; once decided it is `ok` or `badSignature`, never `ok` then refused.
    let mut held = false;
    for id in keyring.controllers.keys() {
        if id == &e.by || e.env.additions.iter().any(|a| &a.signer == id) {
            continue;
        }
        let carried = succession
            .as_ref()
            .is_some_and(|p| p.carried(id, &keyring.controllers[id]));
        match succession.as_ref() {
            Some(p) if carried && p.authorized => {}
            Some(p) if carried && p.undecided => held = true,
            _ => return Err(bad_signature("genesis: possession proof missing").into()),
        }
    }
    if held {
        return Err(Outcome::Held(
            "genesis: possession proof missing and the succession is not decided yet".into(),
        ));
    }
    // Step 4: unknown content.
    let mut unknown = super::prescan("genesis", v);
    unknown.0.extend(keyring.unknown.0.iter().cloned());
    unknown.check()?;
    if undecidable {
        return Err(Failure::NewerFormat("a signer's key form is unknown".into()).into());
    }
    // Step 5: schema.
    let (_, mut o) = AuthorityHeader::split(v.clone())?;
    let label = o.string("label")?;
    crate::v05::require(
        (1..=200).contains(&label.len()),
        "label must be 1–200 bytes",
    )?;
    let ns = o.array("namespaces")?;
    let mut namespaces = Vec::new();
    for n in ns {
        let n = n
            .as_str()
            .ok_or_else(|| malformed("namespace"))?
            .to_string();
        crate::v05::require(crate::v05::terms::valid_namespace(&n), "invalid namespace")?;
        crate::v05::require(
            namespaces.last().is_none_or(|l: &String| l < &n),
            "namespaces sorted and distinct",
        )?;
        namespaces.push(n);
    }
    crate::v05::require(namespaces.len() <= 64, "at most 64 namespaces")?;
    keyring.policy.check_homes(&[])?;
    let mut points = BTreeSet::new();
    let mut uses = Vec::new();
    for c in keyring.controllers.values() {
        uses.push((
            crate::v05::members::Principal::Controller(c.id()),
            crate::v05::members::Usage::Signing,
            c.key().signing().to_vec(),
        ));
        if let Some(a) = c.key().agreement() {
            uses.push((
                crate::v05::members::Principal::Controller(c.id()),
                crate::v05::members::Usage::Agreement,
                a.to_vec(),
            ));
        }
    }
    uses.push((
        crate::v05::members::Principal::Vault(0),
        crate::v05::members::Usage::Signing,
        keyring.vault.0.clone(),
    ));
    uses.push((
        crate::v05::members::Principal::Vault(0),
        crate::v05::members::Usage::Agreement,
        keyring.vault.1.clone(),
    ));
    crate::v05::members::check_principals(&uses)?;
    for (_, _, p) in &uses {
        points.insert(p.clone());
        points.insert(key_id(p).into_bytes());
    }
    let ids: BTreeSet<String> = keyring.controllers.keys().cloned().collect();
    let mut ever = BTreeMap::new();
    let mut meta = BTreeMap::new();
    for (id, c) in &keyring.controllers {
        ever.insert(id.clone(), vec![(1, Some(c.clone()))]);
        meta.insert(
            id.clone(),
            CtrlMeta {
                added_seq: 1,
                planter: None,
                provisional: None,
            },
        );
    }
    let delay = keyring.policy.recovery_delay();
    let rule0 = (keyring.threshold, keyring.holders);
    let policy = keyring.policy.clone();
    let epochs = namespaces.iter().map(|n| (n.clone(), 0)).collect();
    Ok(State {
        account: AccountId::of_genesis(&e.env.body),
        digests: vec![e.env.digest.clone()],
        issued: vec![e.issued],
        keyring,
        keyring_at: vec![ids],
        delay_at: vec![delay],
        rule_at: vec![rule0],
        policies: vec![(1, policy)],
        meta,
        ever,
        namespaces,
        epochs,
        members: Vec::new(),
        recorded: BTreeSet::new(),
        activations: Vec::new(),
        v: BTreeMap::new(),
        suspensions: Vec::new(),
        rate: Vec::new(),
        retiring: None,
        excused: BTreeSet::new(),
        points,
        upgrade_seq: None,
        succession,
        successor: None,
        successor_seq: None,
        migration: None,
        resolved: Vec::new(),
    })
}

// ---------------------------------------------------------------------------------------------
// Transitions.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    Control,
    Recovery,
}

/// A transition judged in a state (§8.7 "Validity of T at an entry E").
#[derive(Clone, Debug)]
pub(crate) struct TCheck {
    pub digest: String,
    pub by: String,
    /// The unit of the primary signer (`by`): the proposer a home charges (§13.1 step 1).
    pub proposer: String,
    pub units: BTreeSet<String>,
    pub anchor_seq: u64,
    pub change: Map<String, Value>,
    pub full_set: bool,
    pub due_ms: i64,
    pub deadline_ms: i64,
    pub removal_only: bool,
    pub revokes: Vec<String>,
    pub undecidable: bool,
    pub unknown: crate::v05::Unknown,
}

/// Which rules each component allows, consent, and removal-only (§8.4, §8.7).
struct Classified {
    control_ok: bool,
    recovery_ok: bool,
    recovery_ok_if_full: bool,
    consent: bool,
    removal_only: bool,
    adds_anything: bool,
    new_threshold: Option<u64>,
    added_ids: Vec<String>,
    holder_set_ids: Vec<String>,
    revokes: Vec<String>,
    unknown: crate::v05::Unknown,
}

fn policy_loosens(old: &Policy, f: &str, v: &Value) -> bool {
    let n = v.as_u64();
    match f {
        "headMaxAge" => n.is_some_and(|n| n > old.head_max_age()),
        "callWindow" => n.is_some_and(|n| n > old.call_window()),
        "linkMaxAge" => n.is_some_and(|n| n > old.link_max_age()),
        "memberRule" => v.as_str() == Some("single"),
        "history" => v.as_str() == Some("public"),
        "rate" => true,
        _ => true,
    }
}
fn policy_tightens(old: &Policy, f: &str, v: &Value) -> bool {
    let n = v.as_u64();
    match f {
        "headMaxAge" => n.is_some_and(|n| n < old.head_max_age()),
        "callWindow" => n.is_some_and(|n| n < old.call_window()),
        "linkMaxAge" => n.is_some_and(|n| n < old.link_max_age()),
        "memberRule" => v.as_str() == Some("control"),
        "history" => v.as_str() == Some("members"),
        _ => false,
    }
}

fn classify(s: &State, change: &Map<String, Value>) -> Result<Classified> {
    let k = &s.keyring;
    let mut c = Classified {
        control_ok: true,
        recovery_ok: true,
        recovery_ok_if_full: true,
        consent: false,
        removal_only: true,
        adds_anything: false,
        new_threshold: None,
        added_ids: Vec::new(),
        holder_set_ids: Vec::new(),
        revokes: Vec::new(),
        unknown: crate::v05::Unknown::default(),
    };
    crate::v05::require(!change.is_empty(), "change has no component")?;
    let recover_of = |id: &str| k.controllers.get(id).is_some_and(|x| x.has(&Role::Recover));
    for (name, comp) in change {
        match name.as_str() {
            "keyring" => {
                let m = comp
                    .as_object()
                    .ok_or_else(|| malformed("keyring component"))?;
                for (f, v) in m {
                    match f.as_str() {
                        "remove" => {
                            for id in v.as_array().ok_or_else(|| malformed("remove"))? {
                                let id = id.as_str().ok_or_else(|| malformed("remove id"))?;
                                if recover_of(id) {
                                    c.consent = true;
                                }
                            }
                        }
                        "keep" => {
                            c.control_ok = false;
                            c.recovery_ok_if_full &= true;
                            let _ = v.as_array().ok_or_else(|| malformed("keep"))?;
                        }
                        "add" => {
                            for x in v.as_array().ok_or_else(|| malformed("add"))? {
                                let ctl = Controller::parse(x.clone(), "keyring.add[]")?;
                                c.unknown.0.extend(ctl.unknown().0.iter().cloned());
                                c.adds_anything = true;
                                c.removal_only = false;
                                if ctl.has(&Role::Recover) {
                                    c.recovery_ok = false;
                                    c.recovery_ok_if_full = false;
                                    c.consent = true;
                                }
                                if ctl.holder().is_some() {
                                    c.holder_set_ids.push(ctl.id());
                                }
                                if !k.controllers.contains_key(&ctl.id()) {
                                    c.added_ids.push(ctl.id());
                                }
                            }
                        }
                        "update" => {
                            for x in v.as_array().ok_or_else(|| malformed("update"))? {
                                let ctl = Controller::parse(x.clone(), "keyring.update[]")?;
                                c.unknown.0.extend(ctl.unknown().0.iter().cloned());
                                let id = ctl.id();
                                if let Some(old) = k.controllers.get(&id) {
                                    let demote_only = ctl.roles().iter().all(|r| old.has(r))
                                        && ctl.key() == old.key()
                                        && ctl.verification() == old.verification()
                                        && ctl.holder() == old.holder();
                                    if !demote_only {
                                        c.recovery_ok = false;
                                        c.recovery_ok_if_full = false;
                                        c.removal_only = false;
                                        c.adds_anything = true;
                                    }
                                    if old.has(&Role::Recover)
                                        && (ctl.key() != old.key()
                                            || ctl.roles() != old.roles()
                                            || ctl.holder() != old.holder()
                                            || ctl.verification() != old.verification())
                                    {
                                        c.consent = true;
                                    }
                                    if ctl.has(&Role::Recover) && !old.has(&Role::Recover) {
                                        c.consent = true;
                                    }
                                    if ctl.holder() != old.holder() {
                                        c.holder_set_ids.push(id);
                                    }
                                }
                            }
                        }
                        "threshold" => {
                            let t = v.as_u64().ok_or_else(|| malformed("threshold"))?;
                            c.recovery_ok = false;
                            c.recovery_ok_if_full = false;
                            c.new_threshold = Some(t);
                            if t > k.threshold {
                                c.consent = true;
                            } else {
                                c.removal_only = false;
                            }
                        }
                        "recoverThreshold" | "addThreshold" | "countBy" => {
                            c.recovery_ok = false;
                            c.recovery_ok_if_full = false;
                            if f != "addThreshold" {
                                c.consent = true;
                            }
                            let raises = v.as_u64().is_some_and(|n| {
                                n > if f == "recoverThreshold" {
                                    k.recover_threshold
                                } else {
                                    k.add_threshold
                                }
                            });
                            if !raises {
                                c.removal_only = false;
                            }
                        }
                        other => c.unknown.push(format!("change.keyring.{other}")),
                    }
                }
            }
            "policy" => {
                let m = comp
                    .as_object()
                    .ok_or_else(|| malformed("policy component"))?;
                for (f, v) in m {
                    match f.as_str() {
                        "primaryHome" | "headQuorum" => {
                            c.consent = true;
                            c.removal_only = false;
                            if k.recover_threshold < k.threshold {
                                c.recovery_ok = false;
                            }
                        }
                        "recoveryDelay" | "rate" => {
                            c.consent = true;
                            c.recovery_ok = false;
                            c.recovery_ok_if_full = false;
                            c.removal_only = false;
                        }
                        _ => {
                            c.recovery_ok = false;
                            c.recovery_ok_if_full = false;
                            if !policy_tightens(&k.policy, f, v) {
                                c.removal_only = false;
                            }
                            let _ = policy_loosens(&k.policy, f, v);
                        }
                    }
                }
            }
            "vault" => {
                c.removal_only = false;
                c.adds_anything = true;
                let has_removal = change
                    .get("keyring")
                    .and_then(Value::as_object)
                    .is_some_and(|m| m.contains_key("remove") || m.contains_key("keep"));
                if !has_removal {
                    c.recovery_ok = false;
                    c.recovery_ok_if_full = false;
                }
                if k.slots
                    .iter()
                    .any(|sl| Keyring::slot_ids(sl).iter().any(|id| recover_of(id)))
                {
                    c.consent = true;
                }
            }
            "homes" => {
                let m = comp
                    .as_object()
                    .ok_or_else(|| malformed("homes component"))?;
                c.consent = true;
                for (f, v) in m {
                    match f.as_str() {
                        "revoke" => {
                            for id in v.as_array().ok_or_else(|| malformed("homes.revoke"))? {
                                c.revokes.push(
                                    id.as_str().ok_or_else(|| malformed("home id"))?.to_string(),
                                );
                            }
                        }
                        "appoint" => {
                            c.adds_anything = true;
                            c.removal_only = false;
                            if k.recover_threshold < k.threshold {
                                c.recovery_ok = false;
                            }
                        }
                        other => c.unknown.push(format!("change.homes.{other}")),
                    }
                }
            }
            "grant" => {
                c.adds_anything = true;
                c.removal_only = false;
                c.recovery_ok = false;
                c.recovery_ok_if_full = false;
            }
            "resolve" => {
                let (_, _, extra) = resolve_target(comp)?;
                for f in extra {
                    c.unknown.push(format!("change.resolve.{f}"));
                }
                c.consent = true;
                c.removal_only = false;
                c.adds_anything = true;
                c.recovery_ok = false;
                c.recovery_ok_if_full = false;
            }
            "layout" | "migration" | "successor" => {
                c.consent = true;
                c.removal_only = false;
                c.adds_anything = true;
                c.recovery_ok = false;
                c.recovery_ok_if_full = false;
            }
            other => {
                c.unknown.push(format!("change.{other}"));
                c.removal_only = false;
                c.recovery_ok = false;
                c.recovery_ok_if_full = false;
            }
        }
    }
    if !c.revokes.is_empty() && c.adds_anything {
        return Err(malformed(
            "a transition that revokes a home and adds anything",
        ));
    }
    Ok(c)
}

/// A `resolve` component (§8.7): `{kept: {seq, digest}}`, the entry at a forked seq that the
/// activation's own branch keeps. Returns its seq, its digest and any unknown member names.
fn resolve_target(comp: &Value) -> Result<(u64, String, Vec<String>)> {
    let m = comp
        .as_object()
        .ok_or_else(|| malformed("resolve component"))?;
    let d = m
        .get("kept")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("resolve.kept"))?;
    let seq = d
        .get("seq")
        .and_then(Value::as_u64)
        .filter(|n| (2..=crate::v05::encoding::bounds::MAX_INTEGER).contains(n))
        .ok_or_else(|| malformed("resolve.kept.seq"))?;
    let digest = d
        .get("digest")
        .and_then(Value::as_str)
        .filter(|x| x.len() == 64 && x.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| malformed("resolve.kept.digest"))?
        .to_string();
    crate::v05::require(d.len() == 2, "resolve.kept has other members")?;
    let extra = m.keys().filter(|k| *k != "kept").cloned().collect();
    Ok((seq, digest, extra))
}

/// The signer units that held `control` in the keyring before seq `fork_seq` (the state after
/// seq `fork_seq − 1`), and that keyring's threshold.
fn control_units_before(
    s: &State,
    fork_seq: u64,
    signers: &[String],
) -> Option<(BTreeSet<String>, u64)> {
    let idx = usize::try_from(fork_seq.checked_sub(2)?).ok()?;
    let (threshold, holders) = *s.rule_at.get(idx)?;
    let ids = s.keyring_at.get(idx)?;
    let before = fork_seq - 1;
    let mut units = BTreeSet::new();
    for id in signers.iter().filter(|id| ids.contains(*id)) {
        let c = s
            .ever
            .get(id)?
            .iter()
            .rev()
            .find(|(q, _)| *q <= before)
            .and_then(|(_, c)| c.as_ref());
        if let Some(c) = c.filter(|c| c.has(&Role::Control)) {
            units.insert(if holders {
                format!("holder:{}", c.holder().unwrap_or_default())
            } else {
                c.id()
            });
        }
    }
    Some((units, threshold))
}

fn delay_at(s: &State, seq: u64) -> u64 {
    usize::try_from(seq.saturating_sub(1))
        .ok()
        .and_then(|i| s.delay_at.get(i))
        .copied()
        .unwrap_or(0)
}

/// Judge a transition in state `s`. `receipts` are the entry's chosen receipts (embedded
/// envelopes); `with_receipts` false judges it as a held object (no receipt check).
pub(crate) fn check_transition(
    s: &State,
    t_bytes: &[u8],
    receipts: &[Vec<u8>],
    with_receipts: bool,
    embedded: bool,
) -> Result<TCheck> {
    let env = AuthEnvelope::parse(
        t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        embedded,
    )?;
    let mut o = Obj::new(env.value.clone(), "transition")?;
    crate::v05::require(
        o.string("protocol")? == "colophon/transition/5",
        "not a colophon/transition/5 transition",
    )?;
    crate::v05::require(
        o.string("account")? == s.account.as_str(),
        "transition names another account",
    )?;
    let mut a = o.obj("anchor")?;
    let anchor_seq = a.uint("seq")?;
    let anchor_digest = a.digest("digest")?;
    a.finish_closed()?;
    let (_, issued) = o.date("issued")?;
    let by = o.key_id("by")?;
    let signers_field: Vec<String> = o
        .array("signers")?
        .into_iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| malformed("signers"))
        })
        .collect::<Result<_>>()?;
    let change = match o.value("change")? {
        Value::Object(m) => m,
        _ => return Err(malformed("change must be an object")),
    };
    let mut unknown = crate::v05::Unknown::default();
    o.finish(&mut unknown);
    // `signers` must match the envelope, checked before the rule (§8.5).
    let signers = env.signer_ids();
    crate::v05::require(
        signers == signers_field,
        "signers doesn't match the envelope",
    )?;
    crate::v05::require(
        env.primary.as_ref().is_some_and(|p| p.signer == by),
        "transition is unsigned",
    )?;
    // Signatures (§8.5 step 2): every signer is a controller of S.
    let mut undecidable = false;
    for item in env.primary.iter().chain(&env.cosignatures) {
        let c = s
            .keyring
            .controllers
            .get(&item.signer)
            .ok_or_else(|| bad_signature("transition signer is not a controller"))?;
        check_item(
            c,
            &env.body,
            item,
            AuthorityRule::Transition,
            &mut undecidable,
        )?;
    }
    let cls = classify(s, &change)?;
    unknown.0.extend(cls.unknown.0.iter().cloned());
    // Possession by every added controller and every key whose holder is set.
    let added: BTreeMap<String, Controller> = change
        .get("keyring")
        .and_then(|k| k.get("add"))
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(|x| Controller::parse(x.clone(), "add").ok())
                .map(|c| (c.id(), c))
                .collect()
        })
        .unwrap_or_default();
    for item in &env.additions {
        let c = added
            .get(&item.signer)
            .or_else(|| s.keyring.controllers.get(&item.signer))
            .ok_or_else(|| bad_signature("foreign possession proof"))?;
        check_item(
            c,
            &env.body,
            item,
            AuthorityRule::Possession,
            &mut undecidable,
        )?;
    }
    for id in cls.added_ids.iter().chain(&cls.holder_set_ids) {
        crate::v05::require(
            env.additions.iter().any(|a| &a.signer == id),
            "possession proof missing",
        )
        .map_err(|_| bad_signature("possession proof missing"))?;
    }
    // Rule, consent, escalation, currency (§8.7 validity 1).
    for id in &signers {
        if s.current(id).is_none() {
            return Err(bad_signature("a transition signer is not current"));
        }
    }
    let k = &s.keyring;
    let all = all_units(k, &signers);
    let control = units(k, &signers, &Role::Control);
    let recover = units(k, &signers, &Role::Recover);
    let all_control_or_recover = signers
        .iter()
        .all(|id| k.controllers[id].has(&Role::Control) || k.controllers[id].has(&Role::Recover));
    let all_recover = signers
        .iter()
        .all(|id| k.controllers[id].has(&Role::Recover));
    let need = cls.new_threshold.unwrap_or(k.threshold).max(k.threshold);
    let control_met = all_control_or_recover && control.len() as u64 >= need;
    let recovery_met =
        k.recover_threshold > 0 && all_recover && recover.len() as u64 >= k.recover_threshold;
    let current_ids: Vec<&String> = k
        .controllers
        .keys()
        .filter(|id| s.current(id).is_some())
        .collect();
    let every = |role: &Role| {
        current_ids
            .iter()
            .filter(|id| k.controllers[**id].has(role))
            .all(|id| signers.contains(id))
    };
    let full_a = all.len() >= 2 && recovery_met && every(&Role::Recover);
    let consent_met =
        k.recover_threshold == 0 || !cls.consent || recover.len() as u64 >= k.recover_threshold;
    let full_b = all.len() >= 2
        && control_met
        && every(&Role::Control)
        && (!cls.consent || every(&Role::Recover));
    let rule = if control_met && cls.control_ok && consent_met {
        Rule::Control
    } else if recovery_met && (cls.recovery_ok || (full_a && cls.recovery_ok_if_full)) {
        Rule::Recovery
    } else {
        return Err(bad_signature("the transition's rule or consent is not met"));
    };
    // `resolve` needs BOTH the ordinary control rule in S (above: the keyring of the branch the
    // activation is recorded on) AND the control rule of the keyring before the fork (§8.4):
    // the signers that held `control` then must reach that keyring's threshold, so a controller
    // added after the fork adds nothing.
    if let Some(comp) = change.get("resolve") {
        let (seq, _, _) = resolve_target(comp)?;
        if let Some((pre, threshold)) = control_units_before(s, seq, &signers) {
            if (pre.len() as u64) < threshold {
                return Err(bad_signature(
                    "resolve: the control rule of the keyring before the fork is not met",
                ));
            }
        }
    }
    let full_set = match rule {
        Rule::Recovery => full_a,
        Rule::Control => full_b,
    };
    let max_v = all
        .iter()
        .map(|u| s.v.get(u).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    if (all.len() as u64) < 1 + max_v {
        return Err(bad_signature("escalation: too few signer units"));
    }
    // Receipts (§8.7 validity 2).
    let homes = s.current_homes();
    let quorum = k.policy.head_quorum() as usize;
    let mut latest_receipt = issued;
    if with_receipts {
        if homes.is_empty() {
            crate::v05::require(receipts.is_empty(), "receipts without a home")?;
        } else {
            crate::v05::require(
                receipts.len() == quorum.min(homes.len()),
                "receipts: wrong count",
            )?;
            let mut last: Option<String> = None;
            for r in receipts {
                let (home, received) = check_receipt(s, r, &env.digest, issued)?;
                crate::v05::require(
                    last.as_ref().is_none_or(|l| l < &home),
                    "receipts: not sorted by home or not distinct",
                )?;
                last = Some(home);
                latest_receipt = latest_receipt.max(received);
            }
        }
    }
    // Anchor on this branch (validity 3) and issued not before the anchor's.
    crate::v05::require(
        s.on_branch(anchor_seq, &anchor_digest),
        "anchor is not on this branch",
    )?;
    crate::v05::require(
        issued >= s.issued[(anchor_seq - 1) as usize],
        "issued earlier than the anchor's",
    )?;
    let delay = delay_at(s, anchor_seq).max(k.policy.recovery_delay()) as i64 * SEC;
    let due_ms = if full_set {
        if homes.is_empty() {
            issued
        } else {
            latest_receipt
        }
    } else if homes.is_empty() {
        issued
    } else {
        issued.saturating_add(RECEIPT_WINDOW).saturating_add(delay)
    };
    let witnesses_revoked = if full_set || rule == Rule::Recovery {
        cls.revokes.clone()
    } else {
        Vec::new()
    };
    let proposer = k
        .controllers
        .get(&by)
        .map(|c| k.unit_of(c))
        .unwrap_or_default();
    Ok(TCheck {
        digest: env.digest.clone(),
        by,
        proposer,
        units: all,
        anchor_seq,
        change,
        full_set,
        due_ms,
        deadline_ms: issued.saturating_add(delay),
        removal_only: cls.removal_only,
        revokes: witnesses_revoked,
        undecidable,
        unknown,
    })
}

/// A receipt (§13.5): returns the home and `received`.
pub(super) fn check_receipt(
    s: &State,
    bytes: &[u8],
    object: &str,
    object_issued: i64,
) -> Result<(String, i64)> {
    let env =
        RawEnvelope::parse_bounded(bytes, bounds::RECEIPT_BODY, bounds::RECEIPT_ENVELOPE, true)?;
    let mut o = Obj::new(env.value.clone(), "receipt")?;
    crate::v05::require(
        o.string("protocol")? == "colophon/receipt/5",
        "not a receipt",
    )?;
    crate::v05::require(
        o.string("account")? == s.account.as_str(),
        "receipt names another account",
    )?;
    let obj = o.digest("object")?;
    let (_, received) = o.date("received")?;
    let by = o.key_id("by")?;
    o.finish_closed()?;
    let key = s
        .home_key(&by)
        .ok_or_else(|| malformed("receipt by a key that is not a current home"))?;
    env.verify(&key)
        .map_err(|e| bad_signature(format!("receipt: {e}")))?;
    crate::v05::require(obj == object, "receipt names another object")?;
    crate::v05::require(
        received >= object_issued && received <= object_issued.saturating_add(RECEIPT_WINDOW),
        "receipt outside its window",
    )?;
    Ok((by, received))
}

fn embedded_list(v: &Value, field: &str, bound: usize) -> Result<Vec<Vec<u8>>> {
    v.get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(format!("{field} must be an array")))?
        .iter()
        .map(|x| embedded_bytes(x, field, bound))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Applying deltas.

pub(super) fn apply_delta(s: &State, t: &TCheck, act_seq: u64) -> Result<State> {
    let mut n = s.clone();
    let k = &s.keyring;
    let mut raw = k.raw_controllers();
    let mut overrides = Map::new();
    let mut changed = false;
    let mut removed: Vec<String> = Vec::new();
    let mut demoted: Vec<String> = Vec::new();
    // Controllers whose `agreement` changes: their slots drop like a demotion's (§8.3).
    let mut rekeyed: Vec<String> = Vec::new();
    let mut added: Vec<String> = Vec::new();
    let anchor = t.anchor_seq;
    if let Some(kc) = t.change.get("keyring").and_then(Value::as_object) {
        for x in kc
            .get("add")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let c = Controller::parse(x.clone(), "add")?;
            match k.controllers.get(&c.id()) {
                Some(old) if old.roles() == c.roles() => {}
                Some(_) => return Err(malformed("void: add of a present key with other roles")),
                None => {
                    raw.insert(c.id(), x.clone());
                    added.push(c.id());
                    changed = true;
                }
            }
        }
        for x in kc
            .get("update")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let c = Controller::parse(x.clone(), "update")?;
            let old = k
                .controllers
                .get(&c.id())
                .ok_or_else(|| malformed("void: update of an absent key"))?;
            if old.roles().iter().any(|r| !c.has(r)) {
                demoted.push(c.id());
            }
            if old.key().agreement() != c.key().agreement() {
                rekeyed.push(c.id());
            }
            if raw.get(&c.id()) != Some(x) {
                changed = true;
            }
            raw.insert(c.id(), x.clone());
        }
        for id in kc
            .get("remove")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = id.as_str().unwrap_or_default();
            if raw.remove(id).is_some() {
                removed.push(id.to_string());
                changed = true;
            }
        }
        if let Some(keep) = kc.get("keep").and_then(Value::as_array) {
            let keep: BTreeSet<&str> = keep.iter().filter_map(Value::as_str).collect();
            let ids: Vec<String> = raw.keys().cloned().collect();
            for id in ids {
                let is_recover = k
                    .controllers
                    .get(&id)
                    .is_some_and(|c| c.has(&Role::Recover));
                if !is_recover && !keep.contains(id.as_str()) && !added.contains(&id) {
                    raw.remove(&id);
                    removed.push(id);
                    changed = true;
                }
            }
        }
        for f in ["threshold", "recoverThreshold", "addThreshold", "countBy"] {
            if let Some(v) = kc.get(f) {
                if k.raw.get(f) != Some(v) {
                    changed = true;
                }
                overrides.insert(f.into(), v.clone());
            }
        }
    }
    // Keys a removed key planted after the anchor go too, unless kept (§8.3).
    let keep: BTreeSet<String> = t
        .change
        .get("keyring")
        .and_then(|k| k.get("keep"))
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut frontier = removed.clone();
    while let Some(r) = frontier.pop() {
        for (id, m) in &s.meta {
            if m.planter.as_deref() == Some(r.as_str())
                && m.added_seq > anchor
                && !keep.contains(id)
                && raw.remove(id).is_some()
            {
                removed.push(id.clone());
                frontier.push(id.clone());
            }
        }
    }
    if let Some(pc) = t.change.get("policy").and_then(Value::as_object) {
        let mut policy = k.raw.get("policy").cloned().unwrap_or(Value::Null);
        if let Some(pm) = policy.as_object_mut() {
            for (f, v) in pc {
                if v.is_null() && f == "primaryHome" {
                    pm.remove(f);
                } else {
                    pm.insert(f.clone(), v.clone());
                }
            }
        }
        if Some(&policy) != k.raw.get("policy") {
            changed = true;
        }
        overrides.insert("policy".into(), policy);
    }
    // Slots: drops for removed, demoted or re-keyed slotted controllers; a vault component.
    let mut slots: Vec<Value> = k.slots.clone();
    let gone: BTreeSet<&String> = removed.iter().chain(&demoted).collect();
    let before = slots.len();
    slots.retain(|sl| {
        !Keyring::slot_ids(sl)
            .iter()
            .any(|id| gone.contains(id) || rekeyed.contains(id))
    });
    let dropped = slots.len() != before;
    if let Some(vc) = t.change.get("vault").and_then(Value::as_object) {
        overrides.insert(
            "vault".into(),
            vc.get("vault").cloned().unwrap_or(Value::Null),
        );
        let mut new_slots: Vec<Value> = vc
            .get("slots")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        new_slots.retain(|sl| {
            !Keyring::slot_ids(sl)
                .iter()
                .any(|id| gone.contains(id) || added.contains(id))
        });
        slots = new_slots;
        n.retiring = None;
        changed = true;
    } else if dropped {
        n.retiring = Some(Retiring {
            current_at_anchor: s
                .keyring_at
                .get((anchor - 1) as usize)
                .cloned()
                .unwrap_or_default(),
        });
        changed = true;
    }
    overrides.insert("slots".into(), Value::Array(slots));
    let raw_keyring = k.rebuild(&raw, &overrides);
    // Homes.
    let mut new_members = Vec::new();
    if let Some(hc) = t.change.get("homes").and_then(Value::as_object) {
        for a in hc
            .get("appoint")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            new_members.push(member_from(s, a, act_seq, true)?);
            changed = true;
        }
        for id in hc
            .get("revoke")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = id.as_str().unwrap_or_default();
            let m = n
                .members
                .iter_mut()
                .find(|m| m.request.member_id() == id && m.home != HomeStatus::NotHome);
            match m {
                Some(m) if m.revoked_seq.is_none() => {
                    m.home = HomeStatus::RevocationPending(act_seq);
                    changed = true;
                }
                _ => {}
            }
        }
    }
    if let Some(g) = t.change.get("grant") {
        new_members.push(member_from(s, g, act_seq, false)?);
        changed = true;
    }
    if let Some(m) = t.change.get("migration") {
        super::succession::migration(&mut n, m)?;
        changed = true;
    }
    if let Some(a) = t.change.get("successor") {
        let id = a
            .get("account")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("successor account"))?;
        AccountId::parse(id)?;
        n.successor = Some(id.into());
        n.successor_seq = Some(act_seq);
        changed = true;
    }
    if t.change.contains_key("layout") {
        changed = true;
    }
    if let Some(comp) = t.change.get("resolve") {
        // Valid when the kept entry is on this branch. It discards every other candidate at
        // that seq for a verifier following this branch; with none held it changes nothing but
        // is still valid, so no honest verifier is stopped by it (§8.6 "Resolving a fork").
        let (seq, digest, _) = resolve_target(comp)?;
        if !s.on_branch(seq, &digest) {
            return Err(malformed(
                "void: the resolve keeps an entry not on this branch",
            ));
        }
        n.resolved.push((seq, digest));
        changed = true;
    }
    if !changed {
        return Err(malformed("void: the transition changes nothing"));
    }
    let new_k = Keyring::parse(raw_keyring, 0)
        .map_err(|e| malformed(format!("void: the result breaks §6: {}", e.detail())))?;
    for m in new_members {
        n.members.push(m);
    }
    for id in &added {
        n.meta.insert(
            id.clone(),
            CtrlMeta {
                added_seq: act_seq,
                planter: None,
                provisional: Some(act_seq),
            },
        );
    }
    for id in &removed {
        n.meta.remove(id);
    }
    n.keyring = new_k;
    let homes: Vec<String> = n
        .current_homes()
        .iter()
        .map(|m| m.request.member_id())
        .collect();
    n.keyring
        .policy
        .check_homes(&homes)
        .map_err(|e| malformed(format!("void: {}", e.detail())))?;
    Ok(n)
}

fn member_from(s: &State, v: &Value, seq: u64, home: bool) -> Result<MemberRecord> {
    let req_bytes = embedded_bytes(
        v.get("request").unwrap_or(&Value::Null),
        "request",
        bounds::REQUEST_BODY * 2 + 4_096,
    )?;
    let request = Request::parse(&req_bytes, true)?;
    crate::v05::require(
        &request.account == s.account(),
        "request names another account",
    )?;
    let terms = Terms::parse(
        v.get("terms").cloned().unwrap_or(Value::Null),
        TermsKind::Member,
    )?;
    crate::v05::require(
        terms.covered_by(&request.terms),
        "granted terms not covered by the request",
    )?;
    if home {
        crate::v05::require(terms.serves_home(), "an appointed home must serve home")?;
        crate::v05::require(
            request.kind != MemberKind::Agent,
            "serves is never granted to an agent",
        )?;
    }
    for p in [&request.signing, &request.agreement] {
        crate::v05::require(
            !s.points.contains(p),
            "member key already used by a principal (§3.3)",
        )?;
    }
    Ok(MemberRecord {
        expires_ms: terms.expires_ms(),
        request,
        terms,
        granted_seq: seq,
        renewals: Vec::new(),
        end_sessions: Vec::new(),
        revoked_seq: None,
        provisional: Some(seq),
        home: if home {
            HomeStatus::Home
        } else {
            HomeStatus::NotHome
        },
    })
}

/// Make an activation final, with what it added (§8.7).
fn make_final(n: &mut State, seq: u64) {
    let Some(a) = n.activations.iter_mut().find(|a| a.seq == seq) else {
        return;
    };
    if a.final_ {
        return;
    }
    a.final_ = true;
    let revokes = a.revokes.clone();
    let removal_only = a.removal_only;
    for m in n.meta.values_mut() {
        if m.provisional == Some(seq) {
            m.provisional = None;
        }
    }
    for m in n.members.iter_mut() {
        if m.provisional == Some(seq) {
            m.provisional = None;
        }
        if m.home == HomeStatus::RevocationPending(seq) {
            m.revoked_seq = Some(seq);
        }
    }
    if removal_only {
        for h in revokes {
            n.excused.insert(h);
        }
    }
}

/// Excusals can make other activations final, including removals that excuse more homes.
/// Reach the least fixed point after an entry; no empty `final` object is needed. Finality this
/// way obeys Order (§8.7): an activation that is not removal-only becomes final only when every
/// earlier activation that is not removal-only is final.
fn finalize_empty_witnesses(n: &mut State) {
    loop {
        let ready: Vec<u64> = n
            .activations
            .iter()
            .filter(|a| {
                !a.final_
                    && a.witnesses.iter().all(|h| n.excused.contains(h))
                    && (a.removal_only
                        || !n
                            .activations
                            .iter()
                            .any(|b| b.seq < a.seq && !b.removal_only && !b.final_))
            })
            .map(|a| a.seq)
            .collect();
        if ready.is_empty() {
            return;
        }
        for seq in ready {
            make_final(n, seq);
        }
    }
}

fn witnesses_of(s: &State, t: &TCheck, after: Option<&State>) -> BTreeSet<String> {
    let mut w: BTreeSet<String> = s
        .current_homes()
        .iter()
        .map(|m| m.request.member_id())
        .collect();
    for h in &t.revokes {
        w.remove(h);
    }
    if t.full_set {
        if let Some(a) = after {
            let remaining: BTreeSet<String> = a
                .members
                .iter()
                .filter(|m| m.home != HomeStatus::NotHome && m.revoked_seq.is_none())
                .map(|m| m.request.member_id())
                .collect();
            w.retain(|h| remaining.contains(h));
        }
    }
    w
}

// ---------------------------------------------------------------------------------------------
// Entries.

fn recorded_issued(prev: i64, at: i64) -> i64 {
    prev.max(at)
}

/// What a predecessor admits after a provisional `successor` activation F (§15.1), by kind:
/// - a `final` of F;
/// - a `final` of an earlier activation that is not removal-only, which Order may need first;
/// - a `final` of a later removal-only home revocation (see below);
/// - an `activate` of a removal-only home revocation, checked in `apply` once applied;
///
/// Nothing else is admitted. A `vetoed` that displaces F is a candidate at F's seq, not a later entry.
/// A `final` of an earlier removal-only activation is `malformed` evidence.
fn admit_after_provisional_f(s: &State, e: &Entry) -> Result<()> {
    match e.kind.as_str() {
        "activate" => Ok(()),
        "final" => {
            let f = s.successor_seq.unwrap_or(0);
            let seq = e
                .env
                .value
                .get("activation")
                .and_then(|a| a.get("seq"))
                .and_then(Value::as_u64);
            let digest = e
                .env
                .value
                .get("activation")
                .and_then(|a| a.get("digest"))
                .and_then(Value::as_str);
            let target = s
                .activations
                .iter()
                .find(|a| Some(a.seq) == seq && Some(a.digest.as_str()) == digest);
            let admitted = target.is_some_and(|a| {
                a.seq == f
                    || (a.seq < f && !a.removal_only)
                    || (a.seq > f && a.removal_only && !a.revokes.is_empty())
            });
            crate::v05::require(
                admitted,
                "after a provisional successor activation only the entries that settle it are admitted",
            )
        }
        _ => Err(malformed(
            "after a provisional successor activation only the entries that settle it are admitted",
        )),
    }
}

/// Apply entry `e` to state `s` (§8.7's table).
pub(crate) fn apply(
    s: &State,
    e: &Entry,
    pending: &Pending,
    heads: &super::state::HeadSet,
    all: Vec<&Entry>,
    now_ms: i64,
) -> Step<State> {
    let _ = (pending, heads);
    // After a `successor` activation F the account admits only the entries that settle it
    // (§8.7, §15.1): a `final`, or, as a conflicting candidate at F's seq, a `vetoed` that
    // displaces F while it is provisional. Once F is final the account is closed.
    if s.successor.is_some() {
        if s.successor_final() {
            return Err(malformed("entry after terminal successor").into());
        }
        admit_after_provisional_f(s, e)?;
    }
    // §8.5 step 1: header.
    if e.seq != s.seq() + 1 || e.previous.as_deref() != s.digests.last().map(String::as_str) {
        return Err(malformed("seq or previous doesn't follow").into());
    }
    if e.issued < s.last_issued() {
        return Err(malformed("issued earlier than the preceding entry's").into());
    }
    if e.issued > now_ms.saturating_add(60 * SEC) {
        return Err(Outcome::Held("issued more than 60 s ahead".into()));
    }
    let mut n = match e.kind.as_str() {
        "activate" => {
            let n = activate(s, e, now_ms)?;
            // After a provisional F only a removal-only home revocation's activation (§15.1).
            if s.successor.is_some()
                && !n
                    .activations
                    .last()
                    .is_some_and(|a| a.removal_only && !a.revokes.is_empty())
            {
                return Err(malformed(
                    "after a provisional successor activation only a home revocation activates",
                )
                .into());
            }
            n
        }
        "vetoed" => vetoed(s, e)?,
        "final" => final_entry(s, e, &all)?,
        "suspend" => suspend(s, e)?,
        "vault" => vault_entry(s, e)?,
        "genesis" => return Err(malformed("a second genesis").into()),
        "successionVetoed" => super::succession::vetoed(s, e)?,
        _ => immediate(s, e)?,
    };
    finalize_empty_witnesses(&mut n);
    super::succession::observe_window(&mut n, e);
    // Suspensions end with an entry past their due time + 7 days, or when the entry makes
    // their transition invalid at a hypothetical activate.
    let issued = e.issued;
    let keep: Vec<bool> = n
        .suspensions
        .iter()
        .map(|sp| {
            issued <= sp.ends_ms()
                && !n.recorded.contains(&sp.transition)
                && check_transition(&n, &sp.t_bytes, &sp.receipts, true, true).is_ok()
        })
        .collect();
    let mut i = 0;
    n.suspensions.retain(|_| {
        i += 1;
        keep[i - 1]
    });
    n.digests.push(e.env.digest.clone());
    n.issued.push(e.issued);
    n.keyring_at
        .push(n.keyring.controllers.keys().cloned().collect());
    n.delay_at.push(n.keyring.policy.recovery_delay());
    n.rule_at.push((n.keyring.threshold, n.keyring.holders));
    if n.policies.last().map(|(_, p)| p) != Some(&n.keyring.policy) {
        let p = n.keyring.policy.clone();
        n.policies.push((e.seq, p));
    }
    // Track every controller ever present.
    for (id, c) in &n.keyring.controllers {
        let list = n.ever.entry(id.clone()).or_default();
        if list.last().and_then(|(_, x)| x.as_ref()) != Some(c) {
            list.push((e.seq, Some(c.clone())));
        }
    }
    let present: BTreeSet<String> = n.keyring.controllers.keys().cloned().collect();
    for (id, list) in n.ever.iter_mut() {
        if !present.contains(id) && list.last().is_some_and(|(_, c)| c.is_some()) {
            list.push((e.seq, None));
        }
    }
    Ok(n)
}

fn unsigned(e: &Entry) -> Result<()> {
    crate::v05::require(e.env.primary.is_none(), "a recording entry is unsigned")
}

fn activate(s: &State, e: &Entry, now_ms: i64) -> Step<State> {
    unsigned(e)?;
    let v = &e.env.value;
    let t_bytes = embedded_bytes(
        v.get("transition").unwrap_or(&Value::Null),
        "transition",
        bounds::TRANSITION_ENVELOPE,
    )?;
    let receipts = embedded_list(v, "receipts", bounds::RECEIPT_ENVELOPE)?;
    // Table order: `by` = T's `by`; T not recorded on the branch; then T valid at E.
    let peek = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    if peek.value.get("by").and_then(Value::as_str) != Some(e.by.as_str()) {
        return Err(bad_signature("activate: by is not the transition's by").into());
    }
    if s.recorded.contains(&peek.digest) {
        return Err(malformed("the transition is already recorded on this branch").into());
    }
    let t = check_transition(s, &t_bytes, &receipts, true, true)?;
    // Determined issued; the 7-day bound; held until due.
    let want = recorded_issued(s.last_issued(), t.due_ms);
    if want > t.due_ms.saturating_add(7 * DAY) {
        return Err(malformed("activate more than 7 days after the due time").into());
    }
    if e.issued != want {
        return Err(malformed("activate: issued is not determined").into());
    }
    let mut unknown = super::prescan("activate", v);
    unknown.0.extend(t.unknown.0.iter().cloned());
    unknown.check()?;
    if t.undecidable {
        return Err(
            Failure::NewerFormat("a transition signer's key form is unknown".into()).into(),
        );
    }
    let mut n = apply_delta(s, &t, e.seq)?;
    if t.due_ms > now_ms {
        return Err(Outcome::Held(
            "the activate's due time is after the clock".into(),
        ));
    }
    n.recorded.insert(t.digest.clone());
    for u in &t.units {
        n.v.insert(u.clone(), 0);
    }
    n.suspensions.retain(|sp| sp.transition != t.digest);
    let witnesses = witnesses_of(s, &t, Some(&n));
    n.activations.push(Activation {
        seq: e.seq,
        digest: e.env.digest.clone(),
        transition: t.digest.clone(),
        by: t.by.clone(),
        witnesses: witnesses.clone(),
        removal_only: t.removal_only,
        final_: false,
        witnessed: false,
        due_ms: t.due_ms,
        revokes: t
            .change
            .get("homes")
            .and_then(|h| h.get("revoke"))
            .and_then(Value::as_array)
            .map(|l| {
                l.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    });
    // An activation with no witnesses is final by the fixed point, which `apply` reaches
    // after this entry and which obeys Order (§8.7).
    if t.full_set {
        let earlier: Vec<u64> = n
            .activations
            .iter()
            .filter(|a| a.seq <= t.anchor_seq)
            .map(|a| a.seq)
            .collect();
        for sq in earlier {
            make_final(&mut n, sq);
        }
    }
    Ok(n)
}

/// Validate a veto before or after receipts, sharing the recording-entry checks.
fn check_veto(
    s: &State,
    t: &TCheck,
    veto: &AuthEnvelope,
    receipts: &[Vec<u8>],
    with_receipts: bool,
) -> Step<(i64, bool)> {
    let mut o = Obj::new(veto.value.clone(), "veto")?;
    crate::v05::require(o.string("protocol")? == "colophon/veto/5", "not a veto")
        .map_err(Outcome::from)?;
    crate::v05::require(
        o.string("account")? == s.account.as_str(),
        "veto names another account",
    )
    .map_err(Outcome::from)?;
    crate::v05::require(
        o.digest("transition")? == t.digest,
        "veto names another transition",
    )
    .map_err(Outcome::from)?;
    let (_, v_issued) = o.date("issued")?;
    let v_by = o.key_id("by")?;
    let v_signers: Vec<String> = o
        .array("signers")?
        .into_iter()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    if veto.primary.as_ref().is_none_or(|p| p.signer != v_by) {
        return Err(bad_signature("vetoed: by is not the veto's by").into());
    }
    let signers = veto.signer_ids();
    crate::v05::require(
        signers == v_signers,
        "veto signers doesn't match its envelope",
    )
    .map_err(Outcome::from)?;
    let mut undecidable = t.undecidable;
    for item in veto.primary.iter().chain(&veto.cosignatures) {
        let c = s
            .keyring
            .controllers
            .get(&item.signer)
            .ok_or_else(|| bad_signature("veto signer is not a controller"))?;
        check_item(c, &veto.body, item, AuthorityRule::Veto, &mut undecidable)?;
    }
    if s.recorded.contains(&t.digest) {
        return Err(malformed("the transition is already recorded on this branch").into());
    }
    if t.full_set {
        return Err(malformed("a full set can't be vetoed").into());
    }
    let k = &s.keyring;
    for id in &signers {
        let c = s
            .current(id)
            .ok_or_else(|| malformed("a vetoer is not current"))?;
        if !(c.has(&Role::Control) || c.has(&Role::Recover)) {
            return Err(malformed("a vetoer holds neither control nor recover").into());
        }
    }
    let v_units = all_units(k, &signers);
    if v_units.len() < t.units.len() {
        return Err(malformed("the veto has fewer units than the transition").into());
    }
    if v_units.iter().any(|u| t.units.contains(u)) {
        return Err(malformed("a vetoing unit signed the transition").into());
    }
    // The veto's receipts: chosen, within 300 s of its issued, before the deadline.
    let homes = s.current_homes();
    let quorum = (k.policy.head_quorum() as usize).min(homes.len());
    crate::v05::require(
        !with_receipts || receipts.len() == quorum,
        "veto receipts: wrong count",
    )
    .map_err(Outcome::from)?;
    let mut latest = i64::MIN;
    let mut last: Option<String> = None;
    for r in receipts {
        let (home, received) = check_receipt(s, r, &veto.digest, v_issued)?;
        crate::v05::require(
            last.as_ref().is_none_or(|l| l < &home),
            "veto receipts not sorted or distinct",
        )
        .map_err(Outcome::from)?;
        last = Some(home);
        if received > t.deadline_ms {
            return Err(malformed("a veto receipt is after the veto deadline").into());
        }
        latest = latest.max(received);
    }
    let mut unknown = crate::v05::Unknown::default();
    o.finish(&mut unknown);
    unknown.check()?;
    Ok((latest, undecidable))
}

fn vetoed(s: &State, e: &Entry) -> Step<State> {
    unsigned(e)?;
    let v = &e.env.value;
    let t_bytes = embedded_bytes(
        v.get("transition").unwrap_or(&Value::Null),
        "transition",
        bounds::TRANSITION_ENVELOPE,
    )?;
    let t_receipts = embedded_list(v, "transitionReceipts", bounds::RECEIPT_ENVELOPE)?;
    let veto_bytes = embedded_bytes(
        v.get("veto").unwrap_or(&Value::Null),
        "veto",
        bounds::VETO_ENVELOPE,
    )?;
    let receipts = embedded_list(v, "receipts", bounds::RECEIPT_ENVELOPE)?;
    let veto = AuthEnvelope::parse(&veto_bytes, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)?;
    // Table order: `by` = V's `by`; T not recorded on the branch; then T valid at E.
    if veto.value.get("by").and_then(Value::as_str) != Some(e.by.as_str()) {
        return Err(bad_signature("vetoed: by is not the veto's by").into());
    }
    let peek = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    if s.recorded.contains(&peek.digest) {
        return Err(malformed("the transition is already recorded on this branch").into());
    }
    let t = check_transition(s, &t_bytes, &t_receipts, true, true)?;
    let (latest, undecidable) = check_veto(s, &t, &veto, &receipts, true)?;
    let want = recorded_issued(s.last_issued(), latest);
    if e.issued != want || want > latest.saturating_add(7 * DAY) {
        return Err(malformed("vetoed: issued is not determined").into());
    }
    let mut unknown = super::prescan("vetoed", v);
    unknown.0.extend(t.unknown.0.iter().cloned());
    unknown.check()?;
    if undecidable {
        return Err(Failure::NewerFormat("a signer's key form is unknown".into()).into());
    }
    let mut n = s.clone();
    n.recorded.insert(t.digest.clone());
    for u in &t.units {
        *n.v.entry(u.clone()).or_insert(0) += 1;
    }
    n.suspensions.retain(|sp| sp.transition != t.digest);
    Ok(n)
}

fn final_entry(s: &State, e: &Entry, all: &[&Entry]) -> Step<State> {
    unsigned(e)?;
    let v = &e.env.value;
    let act = v
        .get("activation")
        .ok_or_else(|| malformed("final: activation"))?;
    let a_seq = act
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("final: activation.seq"))?;
    let a_digest = act
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("final: activation.digest"))?;
    let a = s
        .activations
        .iter()
        .find(|a| a.seq == a_seq && a.digest == a_digest)
        .ok_or_else(|| malformed("final: not an activate on this branch"))?;
    if e.by != a.by {
        return Err(bad_signature("final: by is not the activation's by").into());
    }
    if a.final_ {
        return Err(malformed("final: the activation is already final").into());
    }
    if !a.removal_only
        && s.activations
            .iter()
            .any(|b| b.seq < a.seq && !b.removal_only && !b.final_)
    {
        return Err(malformed("final: an earlier activation is not final").into());
    }
    let heads = embedded_list(v, "heads", bounds::HEAD_BODY * 2 + 4_096)?;
    if heads.is_empty() {
        return Err(malformed("a final with no heads").into());
    }
    // Home keys in the state before A: the members that were homes then.
    let before_key = |id: &str| -> Option<Vec<u8>> {
        s.members
            .iter()
            .find(|m| {
                m.request.member_id() == id
                    && m.home != HomeStatus::NotHome
                    && m.granted_seq < a.seq
            })
            .map(|m| m.request.signing.clone())
    };
    let mut by_home: BTreeMap<String, u64> = BTreeMap::new();
    let mut latest = i64::MIN;
    let mut last: Option<String> = None;
    for h in &heads {
        let rh = parse_head(h, true)?;
        let key = before_key(&rh.by)
            .ok_or_else(|| malformed("final: a head by a key that was not a home"))?;
        rh.env
            .verify(&key)
            .map_err(|x| bad_signature(format!("final: head signature: {x}")))?;
        if !s.on_branch(rh.seq, &rh.digest) || rh.seq < a.seq {
            return Err(
                malformed("final: a head doesn't cover the activation on this branch").into(),
            );
        }
        crate::v05::require(
            last.as_ref().is_none_or(|l| l < &rh.by),
            "final: heads not sorted by home or not distinct",
        )
        .map_err(Outcome::from)?;
        last = Some(rh.by.clone());
        by_home.insert(rh.by.clone(), rh.seq);
        latest = latest.max(rh.issued);
    }
    let homes: BTreeSet<String> = by_home.keys().cloned().collect();
    let required: BTreeSet<String> = a
        .witnesses
        .iter()
        .filter(|h| !s.excused.contains(*h))
        .cloned()
        .collect();
    if homes != required {
        return Err(malformed("final: heads are not exactly one per witness").into());
    }
    if e.issued != recorded_issued(s.last_issued(), latest) {
        return Err(malformed("final: issued is not determined").into());
    }
    super::prescan("final", v).check()?;
    let _ = all;
    let mut n = s.clone();
    make_final(&mut n, a.seq);
    mark_witnessed(&mut n, a.seq);
    // Earlier activations whose witnesses all have a head here covering them.
    let earlier: Vec<(u64, BTreeSet<String>)> = n
        .activations
        .iter()
        .filter(|b| !b.final_ && b.seq < a_seq)
        .map(|b| (b.seq, b.witnesses.clone()))
        .collect();
    for (sq, w) in earlier {
        // Homes this very `final` excuses don't count yet: excusal follows A's finality.
        if w.iter()
            .filter(|h| !s.excused.contains(*h))
            .all(|h| by_home.get(h).is_some_and(|hs| *hs >= sq))
        {
            make_final(&mut n, sq);
            mark_witnessed(&mut n, sq);
        }
    }
    Ok(n)
}

/// An activation made final by a `final` entry's heads was witnessed by homes (§8.6 rule 3).
fn mark_witnessed(n: &mut State, seq: u64) {
    if let Some(a) = n.activations.iter_mut().find(|a| a.seq == seq && a.final_) {
        a.witnessed = true;
    }
}

fn suspend(s: &State, e: &Entry) -> Step<State> {
    let v = &e.env.value;
    let by = s
        .keyring
        .controllers
        .get(&e.by)
        .ok_or_else(|| bad_signature("by is not a controller"))?;
    let primary = e
        .env
        .primary
        .as_ref()
        .ok_or_else(|| bad_signature("suspend is unsigned"))?;
    let mut undecidable = false;
    check_item(
        by,
        &e.env.body,
        primary,
        AuthorityRule::Suspend,
        &mut undecidable,
    )?;
    crate::v05::require(
        e.env.cosignatures.is_empty() && e.env.additions.is_empty(),
        "suspend has one signer",
    )
    .map_err(Outcome::from)?;
    let t_bytes = embedded_bytes(
        v.get("transition").unwrap_or(&Value::Null),
        "transition",
        bounds::TRANSITION_ENVELOPE,
    )?;
    let receipts = embedded_list(v, "receipts", bounds::RECEIPT_ENVELOPE)?;
    let key = v
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("suspend: key"))?
        .to_string();
    // The signer must be a signer of T (badSignature) — read before validity.
    let t_env = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    if !t_env.signer_ids().contains(&e.by) {
        return Err(bad_signature("the suspending key is not a signer of the transition").into());
    }
    if s.current(&e.by).is_none() {
        return Err(bad_signature("the suspending key is not current").into());
    }
    let t = check_transition(s, &t_bytes, &receipts, true, true)?;
    if s.recorded.contains(&t.digest) {
        return Err(malformed("suspend: the transition is recorded").into());
    }
    let removes = t
        .change
        .get("keyring")
        .and_then(Value::as_object)
        .is_some_and(|kc| {
            kc.get("remove")
                .and_then(Value::as_array)
                .is_some_and(|l| l.iter().any(|x| x.as_str() == Some(key.as_str())))
                || kc.get("update").and_then(Value::as_array).is_some_and(|l| {
                    l.iter()
                        .filter_map(|x| Controller::parse(x.clone(), "u").ok())
                        .any(|c| {
                            c.id() == key
                                && s.keyring
                                    .controllers
                                    .get(&key)
                                    .is_some_and(|o| o.roles().iter().any(|r| !c.has(r)))
                        })
                })
                || kc.get("keep").and_then(Value::as_array).is_some_and(|l| {
                    !l.iter().any(|x| x.as_str() == Some(key.as_str()))
                        && s.keyring
                            .controllers
                            .get(&key)
                            .is_some_and(|c| !c.has(&Role::Recover))
                })
        });
    if !removes {
        return Err(malformed("suspend: the transition doesn't remove or demote the key").into());
    }
    apply_delta(s, &t, e.seq).map_err(Outcome::from)?;
    let unit = s.unit(&e.by).unwrap_or_default();
    if s.suspensions
        .iter()
        .any(|sp| sp.unit == unit && e.issued <= sp.ends_ms())
    {
        return Err(malformed("suspend: the unit already has a suspension outstanding").into());
    }
    let mut unknown = super::prescan("suspend", v);
    unknown.0.extend(t.unknown.0.iter().cloned());
    unknown.check()?;
    if undecidable {
        return Err(Failure::NewerFormat("a signer's key form is unknown".into()).into());
    }
    let mut n = s.clone();
    charge_rate(&mut n, e, false)?;
    n.suspensions.push(Suspension {
        key,
        unit,
        transition: t.digest.clone(),
        t_bytes,
        receipts,
        due_ms: t.due_ms,
    });
    Ok(n)
}

fn vault_entry(s: &State, e: &Entry) -> Step<State> {
    let v = &e.env.value;
    let by = s
        .keyring
        .controllers
        .get(&e.by)
        .ok_or_else(|| bad_signature("by is not a controller"))?;
    let primary = e
        .env
        .primary
        .as_ref()
        .ok_or_else(|| bad_signature("vault is unsigned"))?;
    let mut undecidable = false;
    check_item(
        by,
        &e.env.body,
        primary,
        AuthorityRule::KeyringEntry,
        &mut undecidable,
    )?;
    let ok = s.current(&e.by).is_some()
        && !s.suspended(&e.by, e.issued)
        && (by.has(&Role::Control) || by.has(&Role::Recover))
        && s.retiring
            .as_ref()
            .is_some_and(|r| r.current_at_anchor.contains(&e.by));
    if !ok {
        return Err(bad_signature("vault: the signer may not rotate the vault now").into());
    }
    super::prescan("vault", v).check()?;
    let slots = v
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("vault: slots"))?;
    if !slots.iter().any(|sl| Keyring::slot_ids(sl).contains(&e.by)) {
        return Err(malformed("vault: no slot names its signer").into());
    }
    if v.get("previousVault").is_none() {
        return Err(malformed("vault: previousVault missing").into());
    }
    let mut raw = s.keyring.raw.clone();
    if let Some(m) = raw.as_object_mut() {
        m.insert(
            "vault".into(),
            v.get("vault").cloned().unwrap_or(Value::Null),
        );
        m.insert("slots".into(), Value::Array(slots.clone()));
    }
    let mut n = s.clone();
    n.keyring = Keyring::parse(raw, 1)?;
    n.retiring = None;
    charge_rate(&mut n, e, false)?;
    Ok(n)
}

/// The charged signer of an immediate entry (§13.1).
fn charged(s: &State, by: &str) -> String {
    let mut c = by.to_string();
    let mut guard = 0;
    while let Some(p) = s.meta.get(&c).and_then(|m| m.planter.clone()) {
        c = p;
        guard += 1;
        if guard > 64 {
            break;
        }
    }
    c
}

fn charge_rate(n: &mut State, e: &Entry, account: bool) -> Result<()> {
    let who = charged(n, &e.by);
    let from = e.issued.saturating_sub(DAY);
    let window: Vec<&RateItem> = n
        .rate
        .iter()
        .filter(|r| r.issued > from && r.issued <= e.issued)
        .collect();
    let signer_entries = window.iter().filter(|r| r.charged == who).count() + 1;
    let signer_bytes: usize = window
        .iter()
        .filter(|r| r.charged == who)
        .map(|r| r.size)
        .sum::<usize>()
        + e.size;
    let p = &n.keyring.policy;
    crate::v05::require(
        signer_entries as u64 <= p.rate_signer().entries()
            && signer_bytes as u64 <= p.rate_signer().bytes(),
        "rate: the signer's limit is exceeded",
    )?;
    if account {
        let acc_entries = window.iter().filter(|r| r.account).count() + 1;
        let acc_bytes: usize = window
            .iter()
            .filter(|r| r.account)
            .map(|r| r.size)
            .sum::<usize>()
            + e.size;
        crate::v05::require(
            acc_entries as u64 <= p.rate_account().entries()
                && acc_bytes as u64 <= p.rate_account().bytes(),
            "rate: the account's limit is exceeded",
        )?;
    }
    n.rate.push(RateItem {
        issued: e.issued,
        charged: who,
        size: e.size,
        account,
    });
    let cutoff = e.issued.saturating_sub(DAY);
    n.rate.retain(|r| r.issued > cutoff);
    Ok(())
}

/// Immediate entries (§8.4) and unknown kinds.
fn immediate(s: &State, e: &Entry) -> Step<State> {
    let v = &e.env.value;
    let mut undecidable = false;
    let primary = e
        .env
        .primary
        .as_ref()
        .ok_or_else(|| bad_signature("unsigned entry"))?;
    // endSessions by the member itself (member rule).
    if e.kind == "endSessions" {
        if let Some(m) = s
            .members
            .iter()
            .find(|m| m.request.member_id() == e.by && m.revoked_seq.is_none())
        {
            crate::v05::require(
                e.env.cosignatures.is_empty() && primary.assertion.is_none(),
                "member rule: raw, one signer",
            )
            .map_err(|_| bad_signature("member rule"))?;
            verify_raw(&m.request.signing, &e.env.body, &primary.signature)
                .map_err(|x| bad_signature(x.to_string()))?;
            super::prescan("endSessions", v).check()?;
            let (_, mut o) = AuthorityHeader::split(v.clone())?;
            let member = o.key_id("member")?;
            crate::v05::require(
                member == e.by,
                "member rule: endSessions names another member",
            )
            .map_err(Outcome::from)?;
            let mut n = s.clone();
            charge_rate(&mut n, e, false)?;
            if let Some(m) = n
                .members
                .iter_mut()
                .find(|m| m.request.member_id() == member)
            {
                m.end_sessions.push(e.seq);
            }
            return Ok(n);
        }
    }
    let by = s
        .keyring
        .controllers
        .get(&e.by)
        .ok_or_else(|| bad_signature("by is not a controller"))?;
    let rule_for_sig = match e.kind.as_str() {
        "keyring" => AuthorityRule::KeyringEntry,
        "grant" | "renew" | "revoke" | "endSessions" | "rekey"
            if s.keyring.policy.member_rule() == crate::v05::descriptor::MemberRule::Single =>
        {
            AuthorityRule::Single
        }
        _ => AuthorityRule::Control,
    };
    check_item(by, &e.env.body, primary, rule_for_sig, &mut undecidable)?;
    for c in &e.env.cosignatures {
        let k = s
            .keyring
            .controllers
            .get(&c.signer)
            .ok_or_else(|| bad_signature("foreign cosigner"))?;
        check_item(k, &e.env.body, c, rule_for_sig, &mut undecidable)?;
    }
    let signers = e.env.signer_ids();
    for id in &signers {
        if s.current(id).is_none() || s.suspended(id, e.issued) {
            return Err(bad_signature(
                "a signer is not current, is suspended or was added provisionally",
            )
            .into());
        }
    }
    let k = &s.keyring;
    let control = units(k, &signers, &Role::Control);
    let control_rule = signers
        .iter()
        .all(|id| k.controllers[id].has(&Role::Control) || k.controllers[id].has(&Role::Recover))
        && control.len() as u64 >= k.threshold;
    let single = signers.len() == 1 && by.has(&Role::Approve);
    let member_rule_control = k.policy.member_rule() == crate::v05::descriptor::MemberRule::Control;
    let rule_ok = match e.kind.as_str() {
        "grant" | "renew" | "revoke" | "endSessions" => {
            if member_rule_control {
                control_rule
            } else {
                single
            }
        }
        "rekey" => {
            if member_rule_control {
                control_rule
            } else {
                single || (signers.len() == 1 && (by.has(&Role::Control) || by.has(&Role::Recover)))
            }
        }
        "keyring" => true, // checked with the change below
        _ => control_rule,
    };
    if !rule_ok {
        return Err(bad_signature("the entry's rule is not met").into());
    }
    let mut n = s.clone();
    match e.kind.as_str() {
        "grant" => {
            let mut unknown = super::prescan("grant", v);
            unknown.check()?;
            let (_, fields) = AuthorityHeader::split(v.clone())?;
            let ctx = GrantContext {
                account: &s.account,
                issued_ms: e.issued,
                namespaces: &s.namespaces,
                known_keys: &s.points,
                epochs: Some(&s.epochs),
            };
            let g = Grant::parse(fields, ctx)?;
            unknown.0.extend(g.unknown.0.iter().cloned());
            unknown.check()?;
            if g.terms.serves_home() || g.terms.import() {
                return Err(malformed("a home or import grant is a transition").into());
            }
            charge_rate(&mut n, e, true)?;
            for p in [&g.request.signing, &g.request.agreement] {
                n.points.insert(p.clone());
                n.points.insert(key_id(p).into_bytes());
            }
            n.members.push(MemberRecord {
                expires_ms: g.terms.expires_ms(),
                request: g.request,
                terms: g.terms,
                granted_seq: e.seq,
                renewals: Vec::new(),
                end_sessions: Vec::new(),
                revoked_seq: None,
                provisional: None,
                home: HomeStatus::NotHome,
            });
        }
        "renew" => {
            super::prescan("renew", v).check()?;
            let (_, fields) = AuthorityHeader::split(v.clone())?;
            let member = fields_member(v)?;
            let m = s.members.iter().find(|m| m.request.member_id() == member);
            let current = m.is_some_and(|m| m.revoked_seq.is_none() && m.provisional.is_none());
            if m.is_some_and(|m| m.home != HomeStatus::NotHome) {
                return Err(malformed("renewing a home is a transition").into());
            }
            let r = Renew::parse(fields, e.issued, current, m.and_then(|m| m.expires_ms))?;
            charge_rate(&mut n, e, true)?;
            if let Some(m) = n
                .members
                .iter_mut()
                .find(|m| m.request.member_id() == r.member)
            {
                m.expires_ms = Some(r.expires_ms);
                m.renewals.push((e.seq, r.expires_ms));
            }
        }
        "revoke" => {
            super::prescan("revoke", v).check()?;
            let (_, fields) = AuthorityHeader::split(v.clone())?;
            let r = Revoke::parse(fields)?;
            // §8.3: while the vault is retiring hosts MUST NOT introduce epochs; a `revoke`
            // MAY carry empty `epochs`. A new epoch would be readable by the removed key.
            crate::v05::require(
                s.retiring.is_none() || r.epochs.is_empty(),
                "revoke: no epoch may be introduced while the vault is retiring",
            )
            .map_err(Outcome::from)?;
            let m = s
                .members
                .iter()
                .find(|m| m.request.member_id() == r.member && m.revoked_seq.is_none());
            let Some(m) = m else {
                return Err(malformed("revoke of a member that isn't current").into());
            };
            if m.home != HomeStatus::NotHome {
                return Err(malformed("revoking a home is a transition").into());
            }
            // §9.5: `epochs` introduces a new epoch in every namespace the member could read
            // (empty if none); while the vault is retiring none may be introduced (§8.3).
            if s.retiring.is_none() {
                let have: BTreeSet<&str> = r.epochs.iter().map(|e| e.namespace.as_str()).collect();
                let covered = m
                    .terms
                    .records()
                    .unwrap_or_default()
                    .iter()
                    .all(|e| have.contains(e.namespace.as_str()));
                crate::v05::require(
                    covered,
                    "revoke: a new epoch in every namespace the member could read",
                )
                .map_err(Outcome::from)?;
            }
            // The epochs a revoke introduces are checked like a `rekey`'s (consecutive, one per
            // declared namespace) and folded into `epochs`, so a later `rekey` and the grant
            // share-completeness check see them.
            let mut seen = BTreeSet::new();
            for ep in &r.epochs {
                crate::v05::require(
                    seen.insert(ep.namespace.clone()),
                    "revoke: at most one epoch per namespace",
                )
                .map_err(Outcome::from)?;
                let cur = s
                    .epochs
                    .get(&ep.namespace)
                    .copied()
                    .ok_or_else(|| malformed("revoke: undeclared namespace"))?;
                crate::v05::require(
                    cur.checked_add(1) == Some(ep.epoch),
                    "revoke: epochs are consecutive",
                )
                .map_err(Outcome::from)?;
            }
            charge_rate(&mut n, e, false)?;
            if let Some(m) = n
                .members
                .iter_mut()
                .find(|m| m.request.member_id() == r.member)
            {
                m.revoked_seq = Some(e.seq);
            }
            for ep in &r.epochs {
                n.epochs.insert(ep.namespace.clone(), ep.epoch);
            }
        }
        "endSessions" => {
            super::prescan("endSessions", v).check()?;
            let member = fields_member(v)?;
            crate::v05::require(
                s.members
                    .iter()
                    .any(|m| m.request.member_id() == member && m.revoked_seq.is_none()),
                "endSessions of a member that isn't current",
            )
            .map_err(Outcome::from)?;
            charge_rate(&mut n, e, false)?;
            if let Some(m) = n
                .members
                .iter_mut()
                .find(|m| m.request.member_id() == member)
            {
                m.end_sessions.push(e.seq);
            }
        }
        "rekey" => {
            let epochs = v
                .get("epochs")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("rekey: epochs"))?;
            crate::v05::require(!epochs.is_empty(), "rekey: epochs must not be empty")
                .map_err(Outcome::from)?;
            // §8.3: no epoch while the vault is retiring.
            crate::v05::require(
                s.retiring.is_none(),
                "rekey: no epoch may be introduced while the vault is retiring",
            )
            .map_err(Outcome::from)?;
            let mut seen = BTreeSet::new();
            for ep in epochs {
                let ns = ep
                    .get("namespace")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("rekey: namespace"))?;
                let no = ep
                    .get("epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| malformed("rekey: epoch"))?;
                crate::v05::require(
                    seen.insert(ns.to_string()),
                    "rekey: at most one epoch per namespace",
                )
                .map_err(Outcome::from)?;
                let cur = s
                    .epochs
                    .get(ns)
                    .copied()
                    .ok_or_else(|| malformed("rekey: undeclared namespace"))?;
                crate::v05::require(no == cur + 1, "rekey: epochs are consecutive")
                    .map_err(Outcome::from)?;
            }
            if e.seq == 2 && !s.namespaces.is_empty() {
                crate::v05::require(
                    seen.len() == s.namespaces.len(),
                    "seq 2 must introduce epoch 1 in every namespace",
                )
                .map_err(Outcome::from)?;
            }
            charge_rate(&mut n, e, false)?;
            for ep in epochs {
                if let (Some(ns), Some(no)) = (
                    ep.get("namespace").and_then(Value::as_str),
                    ep.get("epoch").and_then(Value::as_u64),
                ) {
                    n.epochs.insert(ns.to_string(), no);
                }
            }
        }
        "keyring" => keyring_entry(s, &mut n, e, &signers, &mut undecidable)?,
        other => {
            // Unknown kind: control rule passed; now its content is unknown.
            return Err(Failure::NewerFormat(format!("unknown kind {other}")).into());
        }
    }
    if s.namespaces.is_empty() || e.seq != 2 || e.kind == "rekey" {
    } else {
        return Err(malformed("seq 2 must be a rekey when the account declares namespaces").into());
    }
    if undecidable {
        return Err(Failure::NewerFormat("a signer's key form is unknown".into()).into());
    }
    Ok(n)
}

fn fields_member(v: &Value) -> Result<String> {
    v.get("member")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| malformed("member"))
}

fn keyring_entry(
    s: &State,
    n: &mut State,
    e: &Entry,
    signers: &[String],
    undecidable: &mut bool,
) -> Step<()> {
    let v = &e.env.value;
    let new_raw = v
        .get("keyring")
        .cloned()
        .ok_or_else(|| malformed("keyring: keyring"))?;
    let old = &s.keyring;
    let new = Keyring::parse(new_raw, 0)?;
    let mut unknown = new.unknown.clone();
    unknown.0.extend(super::prescan("keyring", v).0);
    let by = &e.by;
    // Added, removed and changed controllers.
    for id in old.controllers.keys() {
        if !new.controllers.contains_key(id) {
            return Err(malformed("keyring: a removal is a transition").into());
        }
    }
    let added: Vec<&Controller> = new
        .controllers
        .iter()
        .filter(|(id, _)| !old.controllers.contains_key(*id))
        .map(|(_, c)| c)
        .collect();
    crate::v05::require(
        added.len() <= 4,
        "keyring: at most four controllers per entry",
    )
    .map_err(Outcome::from)?;
    for c in &added {
        crate::v05::require(
            c.roles() == [Role::Approve] || c.roles() == [Role::Sign],
            "keyring: only approve or sign controllers are added at once",
        )
        .map_err(Outcome::from)?;
    }
    for (id, nc) in &new.controllers {
        let Some(oc) = old.controllers.get(id) else {
            continue;
        };
        if nc == oc {
            continue;
        }
        let same_but_label = nc.key() == oc.key()
            && nc.roles() == oc.roles()
            && nc.verification() == oc.verification()
            && nc.holder() == oc.holder()
            && nc.audiences() == oc.audiences();
        if same_but_label {
            continue;
        }
        // Tightening the signer's own authentication.
        let own = id == by;
        let tighten = own
            && nc.roles() == oc.roles()
            && nc.holder() == oc.holder()
            && nc.audiences() == oc.audiences()
            && nc.key().signing() == oc.key().signing()
            && (nc.verification() || !oc.verification())
            && match (nc.key().webauthn(), oc.key().webauthn()) {
                (Some(nw), Some(ow)) => {
                    nw.rp() == ow.rp()
                        && nw.credential() == ow.credential()
                        && nw.origins().iter().all(|x| ow.origins().contains(x))
                        && match (nw.authority_origins(), ow.authority_origins()) {
                            (Some(na), Some(oa)) => na.iter().all(|x| oa.contains(x)),
                            (None, None) => true,
                            _ => false,
                        }
                }
                (None, None) => nc.key() == oc.key(),
                _ => false,
            };
        if !tighten {
            return Err(malformed("keyring: this change of a controller is a transition").into());
        }
    }
    for (f, a, b) in [
        ("threshold", old.threshold, new.threshold),
        (
            "recoverThreshold",
            old.recover_threshold,
            new.recover_threshold,
        ),
        ("addThreshold", old.add_threshold, new.add_threshold),
    ] {
        crate::v05::require(a == b, &format!("keyring: changing {f} is a transition"))
            .map_err(Outcome::from)?;
    }
    crate::v05::require(
        old.holders == new.holders,
        "keyring: changing countBy is a transition",
    )
    .map_err(Outcome::from)?;
    crate::v05::require(
        old.vault == new.vault,
        "keyring: changing the vault is a transition",
    )
    .map_err(Outcome::from)?;
    // Policy: lowering only.
    let op = old
        .raw
        .get("policy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let np = new
        .raw
        .get("policy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (f, nv) in &np {
        if op.get(f) != Some(nv) && !policy_tightens(&old.policy, f, nv) {
            return Err(malformed(format!(
                "keyring: changing policy.{f} this way is a transition"
            ))
            .into());
        }
    }
    for f in op.keys() {
        crate::v05::require(
            np.contains_key(f),
            "keyring: removing a policy field is a transition",
        )
        .map_err(Outcome::from)?;
    }
    // Slots: every existing slot stays; new ones only for added or existing non-sign keys.
    let mut old_keys: Vec<Vec<u8>> = old.slots.iter().map(Keyring::slot_key).collect();
    let mut new_slots = Vec::new();
    for sl in &new.slots {
        let key = Keyring::slot_key(sl);
        if let Some(i) = old_keys.iter().position(|k| k == &key) {
            old_keys.remove(i);
        } else {
            new_slots.push(sl);
        }
    }
    crate::v05::require(
        old_keys.is_empty(),
        "keyring: deleting or changing a slot is a transition",
    )
    .map_err(Outcome::from)?;
    let controllers_changed = new.controllers.len() != old.controllers.len()
        || new
            .controllers
            .iter()
            .any(|(id, c)| old.controllers.get(id) != Some(c));
    let policy_changed = op != np;
    let self_slot = !controllers_changed
        && !policy_changed
        && !new_slots.is_empty()
        && new_slots
            .iter()
            .all(|sl| Keyring::slot_ids(sl) == [by.clone()])
        && signers.len() == 1
        && !s.keyring.controllers[by].has(&Role::Sign);
    if !self_slot {
        let control = units(old, signers, &Role::Control);
        let ok = signers
            .iter()
            .all(|id| old.controllers[id].has(&Role::Control))
            && control.len() as u64 >= old.add_threshold;
        if !ok {
            return Err(bad_signature("keyring: addThreshold control units are needed").into());
        }
        if !e.env.cosignatures.is_empty()
            || e.env
                .primary
                .as_ref()
                .is_some_and(|p| p.assertion.is_some())
        {
            // UV is enforced by the KeyringEntry rule on every signature.
        }
    }
    // Possession by every added controller.
    for c in &added {
        let item = e
            .env
            .additions
            .iter()
            .find(|a| a.signer == c.id())
            .ok_or_else(|| bad_signature("keyring: possession proof missing"))?;
        check_item(c, &e.env.body, item, AuthorityRule::Possession, undecidable)?;
    }
    crate::v05::require(
        new.controllers.len() <= 56,
        "keyring: more than 56 controllers",
    )
    .map_err(Outcome::from)?;
    crate::v05::require(new.slots.len() <= 224, "keyring: more than 224 slots")
        .map_err(Outcome::from)?;
    unknown.check()?;
    // Rate, charged to the adder for planted keys.
    charge_rate(n, e, true)?;
    let who = charged(s, by);
    for c in &added {
        n.meta.insert(
            c.id(),
            CtrlMeta {
                added_seq: e.seq,
                planter: Some(who.clone()),
                provisional: None,
            },
        );
        n.points.insert(c.key().signing().to_vec());
        n.points.insert(c.id().into_bytes());
        if let Some(a) = c.key().agreement() {
            n.points.insert(a.to_vec());
        }
    }
    n.keyring = new;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Conflicts (§8.6).

const RECORDING: [&str; 4] = ["activate", "vetoed", "final", "successionVetoed"];

fn due_and_object(s: &State, e: &Entry) -> (i64, String) {
    let v = &e.env.value;
    match e.kind.as_str() {
        "activate" | "vetoed" => {
            let tb = v
                .get("transition")
                .and_then(|t| embedded_bytes(t, "transition", bounds::TRANSITION_ENVELOPE).ok())
                .unwrap_or_default();
            let receipts = embedded_list(
                v,
                if e.kind == "activate" {
                    "receipts"
                } else {
                    "transitionReceipts"
                },
                bounds::RECEIPT_ENVELOPE,
            )
            .unwrap_or_default();
            match check_transition(s, &tb, &receipts, true, true) {
                Ok(t) => (t.due_ms, t.digest),
                Err(_) => (i64::MAX, String::new()),
            }
        }
        "successionVetoed" => s
            .succession
            .as_ref()
            .and_then(|p| {
                p.window.as_ref().map(|w| {
                    (
                        w.start
                            .saturating_add(300_000)
                            .saturating_add((w.delay as i64).saturating_mul(1000)),
                        p.genesis_digest.clone(),
                    )
                })
            })
            .unwrap_or((i64::MAX, String::new())),
        "final" => {
            let seq = v
                .get("activation")
                .and_then(|a| a.get("seq"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            s.activations
                .iter()
                .find(|a| a.seq == seq)
                .map(|a| (a.due_ms, a.transition.clone()))
                .unwrap_or((i64::MAX, String::new()))
        }
        _ => (i64::MAX, String::new()),
    }
}
/// The clock time from which a candidate held at `s` can be judged again: the earlier of its
/// issued-ahead release and (for an `activate`) its due time. A lower bound is safe; it only
/// brings a replay forward.
pub(crate) fn release_time(s: Option<&State>, e: &Entry) -> i64 {
    let ahead = e.issued.saturating_sub(60 * SEC);
    match (s, e.kind.as_str()) {
        (Some(s), "activate") => ahead.min(due_and_object(s, e).0),
        _ => ahead,
    }
}
fn kind_rank(k: &str) -> u8 {
    match k {
        "activate" => 0,
        "vetoed" => 1,
        "final" => 2,
        _ => 3,
    }
}
/// Digests of entries reachable from `from` by `previous` links (its descendants and itself).
pub(super) fn descendants(all: &[&Entry], from: &str) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = [from.to_string()].into();
    loop {
        let before = set.len();
        for e in all {
            if e.previous.as_ref().is_some_and(|p| set.contains(p)) {
                set.insert(e.env.digest.clone());
            }
        }
        if set.len() == before {
            return set;
        }
    }
}
/// What a conflict needs besides the candidates: the held objects and the clock.
struct Ctx<'a> {
    heads: &'a HeadSet,
    all: &'a [&'a Entry],
    pending: &'a Pending,
    now_ms: i64,
}
/// Whether a `final` covers the activate `act`, whose state after it is `after` (§8.6 rule 1,
/// §8.7 "Final"): the activation is final, in any of the ways §8.7 gives, in `after` or in the
/// state after any valid entry that follows it on its own branch. "Final" is `Activation::final_`,
/// the one predicate the rest of the engine uses, so a `vetoed` never rolls back anything §8.7
/// calls final. A parsed object that no branch contains, or one that fails its checks, covers
/// nothing. When a `vetoed` displaces the activation instead, the entries after it leave with it
/// (§8.7 rollback).
fn final_covers(ctx: &Ctx, act: &Entry, after: &State) -> bool {
    let is_final = |st: &State| {
        st.activations
            .iter()
            .any(|a| a.seq == act.seq && a.digest == act.env.digest && a.final_)
    };
    if is_final(after) {
        return true;
    }
    // Entries after `act`, in seq order, each applied to the state of its `previous`. Every step
    // raises seq, so the walk is bounded by the entries held.
    let mut later: Vec<&Entry> = ctx
        .all
        .iter()
        .copied()
        .filter(|e| e.seq > act.seq)
        .collect();
    later.sort_by(|x, y| (x.seq, &x.env.digest).cmp(&(y.seq, &y.env.digest)));
    let mut states: BTreeMap<&str, State> = BTreeMap::new();
    states.insert(act.env.digest.as_str(), after.clone());
    for f in later {
        let Some(prev) = f.previous.as_deref().and_then(|p| states.get(p)) else {
            continue;
        };
        let Ok(next) = apply(
            prev,
            f,
            ctx.pending,
            ctx.heads,
            ctx.all.to_vec(),
            ctx.now_ms,
        ) else {
            continue;
        };
        if is_final(&next) {
            return true;
        }
        states.insert(f.env.digest.as_str(), next);
    }
    false
}
pub(super) fn covered_by_home_head(
    s: &State,
    heads: &HeadSet,
    all: &[&Entry],
    y: &Entry,
    home: &str,
) -> bool {
    let Some(key) = s.home_key(home) else {
        return false;
    };
    let branch = descendants(all, &y.env.digest);
    heads.heads.iter().any(|h| {
        h.by == home && h.seq >= y.seq && branch.contains(&h.digest) && h.env.verify(&key).is_ok()
    })
}

/// Decide a conflict among valid candidates at one seq (§8.6). `None` is a fork.
pub(crate) fn resolve_conflict(
    s: &State,
    valid: &[(&Entry, State)],
    heads: &HeadSet,
    all: Vec<&Entry>,
    pending: &Pending,
    now_ms: i64,
) -> Option<usize> {
    let ctx = Ctx {
        heads,
        all: &all,
        pending,
        now_ms,
    };
    // The pairwise rules need not be transitive. A fold can return a loser in a
    // cycle, or stop at an unresolved pair before reaching a candidate that beats both.
    // Stand only a candidate that wins against every other valid candidate (§8.6).
    (0..valid.len())
        .find(|&i| (0..valid.len()).all(|j| i == j || pair(s, valid, i, j, &ctx) == Some(i)))
}
fn pair(s: &State, valid: &[(&Entry, State)], i: usize, j: usize, ctx: &Ctx) -> Option<usize> {
    let (heads, all) = (ctx.heads, ctx.all);
    let (x, y) = (valid[i].0, valid[j].0);
    let xr = RECORDING.contains(&x.kind.as_str());
    let yr = RECORDING.contains(&y.kind.as_str());
    match (xr, yr) {
        (true, false) | (false, true) => {
            let (rec, other, ri, oi) = if xr { (x, y, i, j) } else { (y, x, j, i) };
            let (due, _) = due_and_object(s, rec);
            let primary = s.primary_home();
            let covered = primary.is_some_and(|p| covered_by_home_head(s, heads, all, other, &p));
            let rec_idx = if xr { i } else { j };
            let finalized = rec.kind == "activate" && final_covers(ctx, rec, &valid[rec_idx].1);
            Some(if covered && other.issued <= due && !finalized {
                oi
            } else {
                ri
            })
        }
        (true, true) => {
            let (dx, ox) = due_and_object(s, x);
            let (dy, oy) = due_and_object(s, y);
            // activate vs vetoed of one transition: the vetoed stands unless a final covers it.
            if ox == oy
                && ((x.kind == "activate" && y.kind == "vetoed")
                    || (x.kind == "vetoed" && y.kind == "activate"))
            {
                let (act, ai, vi) = if x.kind == "activate" {
                    (x, i, j)
                } else {
                    (y, j, i)
                };
                return Some(if final_covers(ctx, act, &valid[ai].1) {
                    ai
                } else {
                    vi
                });
            }
            // A recording entry whose activation is final on its branch stands and is not
            // displaced by a recording entry of another object (§8.6 rule 1): final means
            // witnessed or excused, never undone. If both are final the order below decides.
            let finals = |e: &Entry, st: &State| match e.kind.as_str() {
                "activate" => final_covers(ctx, e, st),
                "final" => true,
                _ => false,
            };
            let (fx, fy) = (finals(x, &valid[i].1), finals(y, &valid[j].1));
            // Entries for one transition that differ only in receipts or heads keep the order
            // below (the lower digest stands, the other is dropped).
            if ox != oy && fx != fy {
                return Some(if fx { i } else { j });
            }
            let kx = (dx, ox, kind_rank(&x.kind), x.env.digest.clone());
            let ky = (dy, oy, kind_rank(&y.kind), y.env.digest.clone());
            Some(if kx <= ky { i } else { j })
        }
        (false, false) => {
            let homes: Vec<String> = s
                .current_homes()
                .iter()
                .map(|m| m.request.member_id())
                .collect();
            let quorum = s.keyring.policy.head_quorum() as usize;
            let cov = |e: &Entry| {
                homes
                    .iter()
                    .filter(|h| covered_by_home_head(s, heads, all, e, h))
                    .count()
            };
            let (cx, cy) = (cov(x), cov(y));
            if !homes.is_empty() && cx >= quorum && cy == 0 {
                Some(i)
            } else if !homes.is_empty() && cy >= quorum && cx == 0 {
                Some(j)
            } else {
                None
            }
        }
    }
}

/// Check a held transition against a state (as a home or verifier would before receipting).
pub fn check_pending_transition(s: &State, bytes: &[u8]) -> Result<()> {
    check_transition(s, bytes, &[], false, false).map(|_| ())
}

/// Check a pending veto against the latest verified state, before issuing its receipt.
/// The transition receipts are required; the veto's own receipts are not yet required.
pub fn check_pending_veto(
    s: &State,
    transition: &[u8],
    transition_receipts: &[Vec<u8>],
    bytes: &[u8],
) -> Result<()> {
    let t = check_transition(s, transition, transition_receipts, true, false)?;
    let veto = AuthEnvelope::parse(bytes, bounds::VETO_BODY, bounds::VETO_ENVELOPE, false)?;
    let (_, undecidable) = check_veto(s, &t, &veto, &[], false).map_err(|o| match o {
        Outcome::Fail(f) => f,
        Outcome::Held(why) => malformed(why),
    })?;
    t.unknown.check()?;
    super::prescan("veto", &veto.value).check()?;
    if undecidable {
        return Err(Failure::NewerFormat(
            "a signer's key form is unknown".into(),
        ));
    }
    Ok(())
}

pub(super) fn admission_transition(s: &State, bytes: &[u8]) -> Result<TCheck> {
    let t = check_transition(s, bytes, &[], false, false)?;
    t.unknown.check()?;
    if t.undecidable {
        return Err(Failure::NewerFormat(
            "a signer's key form is unknown".into(),
        ));
    }
    if s.recorded.contains(&t.digest) {
        return Err(malformed("transition is already recorded"));
    }
    apply_delta(s, &t, s.seq() + 1)?;
    Ok(t)
}

pub(super) fn receipted_veto(
    s: &State,
    transition: &[u8],
    transition_receipts: &[Vec<u8>],
    veto: &[u8],
    receipts: &[Vec<u8>],
) -> Result<()> {
    let t = check_transition(s, transition, transition_receipts, true, false)?;
    let env = AuthEnvelope::parse(veto, bounds::VETO_BODY, bounds::VETO_ENVELOPE, false)?;
    check_veto(s, &t, &env, receipts, true).map_err(|o| match o {
        Outcome::Fail(f) => f,
        Outcome::Held(why) => malformed(why),
    })?;
    Ok(())
}

/// Translate only after the complete incorporated prefix and upgrade authenticate.
pub(super) fn from_upgrade(
    prior: &crate::authority::Authority,
    keyring: Keyring,
    records: &crate::model::Records,
    seq: u64,
) -> Result<State> {
    let mut digests = Vec::new();
    let mut issued = Vec::new();
    for raw in records.values() {
        let env =
            crate::keys::AuthorityEnvelope::from_json(raw).map_err(|e| malformed(e.to_string()))?;
        let v = env.body_value().map_err(|e| malformed(e.to_string()))?;
        digests.push(crate::v05::encoding::digest(&env.body));
        issued.push(
            crate::v05::encoding::parse_date(
                v["issued"].as_str().ok_or_else(|| malformed("issued"))?,
            )
            .ok_or_else(|| malformed("issued"))?,
        );
    }
    let first = records
        .values()
        .next()
        .ok_or_else(|| malformed("missing genesis"))?;
    let first =
        crate::keys::AuthorityEnvelope::from_json(first).map_err(|e| malformed(e.to_string()))?;
    let account = AccountId::of_genesis(&first.body);
    let mut members = Vec::new();
    for old in prior.members.values() {
        let g = old
            .member
            .grant
            .as_ref()
            .ok_or_else(|| malformed("missing legacy grant"))?;
        let access = if g.access.contains(&crate::model::Access::Write) {
            "write"
        } else {
            "read"
        };
        let mut terms = serde_json::json!({"records":g.namespaces.iter().map(|n| serde_json::json!({"namespace":n,"access":access})).collect::<Vec<_>>()});
        for (field, value) in [
            ("expires", serde_json::to_value(&g.expires)),
            ("writes", serde_json::to_value(g.write_budget)),
            ("import", serde_json::to_value(g.import)),
        ] {
            let value = value.map_err(|e| malformed(e.to_string()))?;
            if !value.is_null() {
                terms[field] = value;
            }
        }
        let terms = Terms::parse(terms, TermsKind::Member)?;
        let kind = match old.member.kind {
            crate::model::MemberKind::Device => MemberKind::Device,
            crate::model::MemberKind::App => MemberKind::App,
            crate::model::MemberKind::Agent => MemberKind::Agent,
            crate::model::MemberKind::Server => MemberKind::Server,
        };
        members.push(MemberRecord {
            request: Request {
                body: Vec::new(),
                account: account.clone(),
                signing: old.public.signing.clone(),
                agreement: old.public.agreement.clone(),
                label: old.member.label.clone(),
                kind,
                terms: terms.clone(),
                created_ms: issued
                    .get(old.member.since.saturating_sub(1) as usize)
                    .copied()
                    .unwrap_or(0),
                custody: None,
                operator: None,
                endpoints: None,
                unknown: Default::default(),
            },
            expires_ms: terms.expires_ms(),
            terms,
            granted_seq: old.member.since,
            revoked_seq: old.member.revoked_at,
            renewals: Vec::new(),
            end_sessions: Vec::new(),
            provisional: None,
            home: HomeStatus::NotHome,
        });
    }
    let mut ever: BTreeMap<String, Vec<(u64, Option<Controller>)>> = BTreeMap::new();
    let mut points = BTreeSet::new();
    let mut historical_sets = Vec::new();
    let mut present = BTreeSet::new();
    // Retain every historical key so the one-principal rule survives the upgrade.
    for entry in &prior.entries {
        if let crate::authority::Action::Genesis { keyring: k, .. }
        | crate::authority::Action::Keyring { keyring: k, .. } = &entry.action
        {
            let next: BTreeSet<String> = k.controllers.iter().map(|c| c.id()).collect();
            for id in present.difference(&next) {
                ever.entry(id.clone()).or_default().push((entry.seq, None));
            }
            present = next;
            for c in &k.controllers {
                let raw = serde_json::to_value(c).map_err(|e| malformed(e.to_string()))?;
                let c = Controller::parse(raw, "legacy controller")?;
                ever.entry(c.id())
                    .or_default()
                    .push((entry.seq, Some(c.clone())));
                points.insert(c.key().signing().to_vec());
                points.insert(c.id().into_bytes());
                if let Some(a) = c.key().agreement() {
                    points.insert(a.to_vec());
                    points.insert(key_id(a).into_bytes());
                }
            }
            for p in [&k.vault.signing, &k.vault.agreement] {
                points.insert(p.clone());
                points.insert(key_id(p).into_bytes());
            }
        }
        historical_sets.push(present.clone());
    }
    historical_sets.push(present);
    for m in &members {
        for p in [&m.request.signing, &m.request.agreement] {
            points.insert(p.clone());
            points.insert(key_id(p).into_bytes());
        }
    }
    let ids: BTreeSet<String> = keyring.controllers.keys().cloned().collect();
    let meta = ids
        .iter()
        .map(|id| {
            (
                id.clone(),
                CtrlMeta {
                    added_seq: 1,
                    planter: None,
                    provisional: None,
                },
            )
        })
        .collect();
    let len = digests.len();
    Ok(State {
        account,
        digests,
        issued,
        keyring_at: historical_sets,
        delay_at: vec![keyring.policy.recovery_delay(); len],
        rule_at: vec![(keyring.threshold, keyring.holders); len],
        policies: vec![(seq, keyring.policy.clone())],
        keyring,
        meta,
        ever,
        namespaces: prior.namespaces.clone(),
        epochs: prior
            .epochs
            .iter()
            .filter_map(|(n, es)| es.keys().max().map(|e| (n.clone(), *e)))
            .collect(),
        members,
        recorded: Default::default(),
        activations: Vec::new(),
        v: Default::default(),
        suspensions: Vec::new(),
        rate: Vec::new(),
        retiring: None,
        excused: Default::default(),
        points,
        upgrade_seq: Some(seq),
        succession: None,
        successor: None,
        successor_seq: None,
        migration: None,
        resolved: Vec::new(),
    })
}
