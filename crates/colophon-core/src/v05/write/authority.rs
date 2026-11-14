//! Builders for authority entries, transitions, vetoes, recording entries and equivocation
//! evidence (§8, §13.3): prepare the exact bodies and the signers each rule needs, then
//! finish by assembling envelopes and running the history verifier over the result.
use super::{
    envelope, format_date, transition_body, unavailable, veto_body, Header, Kind, Records,
    Signature, SignatureResult, SigningStep, StepRole,
};
use crate::v05::descriptor::{Controller, KeyDescriptor, MemberRule, Role};
use crate::v05::encoding::{
    bounds, canonical, decode_base64, digest, encode_base64, parse_date, Obj,
};
use crate::v05::history::envelope::AuthEnvelope;
use crate::v05::history::keyring::Keyring;
use crate::v05::history::{
    check_admissible_transition, check_pending_transition, check_pending_veto, transition_timing,
    verify_history, HomeStatus, Objects, Persisted, State, Stop,
};
use crate::v05::signature::{AuthorityRule, RawEnvelope};
use crate::v05::slots::{validate_self_slot, validate_slots, validate_vault_entry_slots};
use crate::v05::{bad_signature, malformed, require, Failure, Reason, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const SEC: i64 = 1_000;
const RECEIPT_WINDOW_MS: i64 = 300 * SEC;

// ---------------------------------------------------------------------------------------------
// The batch.

#[derive(Debug)]
enum Plan {
    /// An authority entry. With no steps it is a recording entry (a body only).
    Entry {
        seq: u64,
        body: Vec<u8>,
    },
    /// A genesis (no earlier history).
    Genesis {
        body: Vec<u8>,
    },
    Transition {
        body: Vec<u8>,
    },
    Veto {
        body: Vec<u8>,
        transition: Vec<u8>,
        transition_receipts: Vec<Vec<u8>>,
    },
}

/// Exact signing work for one action, and what is needed to finish it. Steps appear in the
/// order the signatures must come back: the primary first, then cosignatures, then possession
/// proofs.
#[derive(Debug)]
pub struct PendingBatch {
    steps: Vec<SigningStep>,
    objects: Objects,
    now_ms: i64,
    plan: Plan,
}

impl PendingBatch {
    /// The signing work, read-only.
    pub fn steps(&self) -> &[SigningStep] {
        &self.steps
    }
    /// Assemble the envelopes from `signatures` (one per step, in order), verify the result
    /// under §8 with `verify_history`, and return the records. Nothing is returned unless the
    /// verifier says `ok`; a held result (a due time or `issued` in the future) is
    /// `unavailable`, and an unresolved fork is `refused:fork`.
    pub fn finish(self, signatures: Vec<SignatureResult>) -> Result<Records> {
        if signatures.len() != self.steps.len() {
            return Err(malformed("one signature per step"));
        }
        let mut primary = None;
        let (mut cosigs, mut adds) = (Vec::new(), Vec::new());
        for (step, sig) in self.steps.iter().zip(signatures) {
            if sig.assertion.is_some() != step.challenge.is_some() {
                return Err(bad_signature(
                    "an assertion is present if and only if the signer is webauthn",
                ));
            }
            let s = Signature {
                signer: step.signer.clone(),
                signature: sig.signature,
                assertion: sig.assertion,
            };
            match step.role {
                StepRole::Primary => primary = Some(s),
                StepRole::Cosignature => cosigs.push(s),
                StepRole::Possession => adds.push(s),
            }
        }
        match &self.plan {
            Plan::Entry { seq, body } => {
                let env = envelope(body, primary.as_ref(), &cosigs, &adds, &[])?;
                verify_appended(&self.objects, &env, *seq, body, self.now_ms)?;
                Ok(Records {
                    entries: vec![(*seq, env)],
                    ..Records::default()
                })
            }
            Plan::Genesis { body } => {
                let env = envelope(body, primary.as_ref(), &cosigs, &adds, &[])?;
                verify_appended(&self.objects, &env, 1, body, self.now_ms)?;
                Ok(Records {
                    entries: vec![(1, env)],
                    ..Records::default()
                })
            }
            Plan::Transition { body } => {
                let env = envelope(body, primary.as_ref(), &cosigs, &adds, &[])?;
                require(
                    env.len() <= bounds::TRANSITION_ENVELOPE,
                    "transition envelope exceeds 622,592 bytes",
                )?;
                let state = head_state(&self.objects, self.now_ms)?;
                check_pending_transition(&state, &env)?;
                check_admissible_transition(&state, &env)?;
                Ok(Records {
                    pending: vec![env],
                    ..Records::default()
                })
            }
            Plan::Veto {
                body,
                transition,
                transition_receipts,
            } => {
                let env = envelope(body, primary.as_ref(), &cosigs, &[], &[])?;
                require(
                    env.len() <= bounds::VETO_ENVELOPE,
                    "veto envelope exceeds 131,072 bytes",
                )?;
                let state = head_state(&self.objects, self.now_ms)?;
                check_pending_veto(&state, transition, transition_receipts, &env)?;
                Ok(Records {
                    pending: vec![env],
                    ..Records::default()
                })
            }
        }
    }
}

/// The verified state at the head of the held objects. Any stop of the verifier is the error.
fn head_state(objects: &Objects, now_ms: i64) -> Result<State> {
    let verdict = verify_history(objects, &Persisted::default(), now_ms);
    stop_to_error(&verdict.stop)?;
    verdict
        .state
        .ok_or_else(|| malformed("the held objects hold no genesis"))
}

fn stop_to_error(stop: &Option<Stop>) -> Result<()> {
    match stop {
        None => Ok(()),
        Some(Stop::Failed { failure, .. }) => Err(failure.clone()),
        Some(Stop::Held { why, .. }) => Err(unavailable(format!("held: {why}"))),
        Some(Stop::Fork { .. }) => Err(Failure::Refused(Reason::Fork)),
    }
}

/// Run the verifier over `objects` plus `env` and require it to be the entry at `seq`.
fn verify_appended(
    objects: &Objects,
    env: &[u8],
    seq: u64,
    body: &[u8],
    now_ms: i64,
) -> Result<()> {
    let mut all = objects.clone();
    all.entries.push(env.to_vec());
    let verdict = verify_history(&all, &Persisted::default(), now_ms);
    stop_to_error(&verdict.stop)?;
    let want = digest(body);
    require(
        verdict.branch.len() as u64 == seq && verdict.branch.last() == Some(&want),
        "the entry is not the head of the verified branch",
    )
}

fn step(
    path: &str,
    body: &[u8],
    c: &Controller,
    role: StepRole,
    rule: AuthorityRule,
) -> SigningStep {
    SigningStep::new(
        path.to_string(),
        body.to_vec(),
        c.id(),
        role,
        c.key().clone(),
        rule.requires_uv() || c.verification(),
    )
}

fn authority_path(seq: u64) -> String {
    format!("authority/{seq:08}.json")
}

// ---------------------------------------------------------------------------------------------
// Rules (§8.4).

fn units(k: &Keyring, ids: &[String], role: Option<&Role>) -> BTreeSet<String> {
    ids.iter()
        .filter_map(|i| k.controllers.get(i))
        .filter(|c| role.is_none_or(|r| c.has(r)))
        .map(|c| k.unit_of(c))
        .collect()
}

/// The control rule: every signer holds `control` or `recover`, and `control` units reach
/// `need` (§8.4).
fn control_rule(k: &Keyring, signers: &[String], need: u64) -> bool {
    signers.iter().all(|i| {
        k.controllers
            .get(i)
            .is_some_and(|c| c.has(&Role::Control) || c.has(&Role::Recover))
    }) && units(k, signers, Some(&Role::Control)).len() as u64 >= need
}

/// The recovery rule: every signer holds `recover`, at least `recoverThreshold` units.
fn recovery_rule(k: &Keyring, signers: &[String]) -> bool {
    k.recover_threshold > 0
        && signers
            .iter()
            .all(|i| k.controllers.get(i).is_some_and(|c| c.has(&Role::Recover)))
        && units(k, signers, Some(&Role::Recover)).len() as u64 >= k.recover_threshold
}

/// The single rule: exactly one signer holding `approve`.
fn single_rule(k: &Keyring, signers: &[String]) -> bool {
    signers.len() == 1
        && k.controllers
            .get(&signers[0])
            .is_some_and(|c| c.has(&Role::Approve))
}

fn check_signers_current(state: &State, signers: &[String], at_ms: i64) -> Result<()> {
    require(!signers.is_empty(), "at least one signer")?;
    let distinct: BTreeSet<&String> = signers.iter().collect();
    require(distinct.len() == signers.len(), "a signer appears twice")?;
    for id in signers {
        if !state.keyring().controllers.contains_key(id)
            || state.controller_provisional(id).is_some()
        {
            return Err(bad_signature("a signer is not a current controller"));
        }
        if state.active_suspensions(at_ms).iter().any(|s| &s.key == id) {
            return Err(bad_signature("a signer is suspended"));
        }
    }
    Ok(())
}

fn controller<'a>(state: &'a State, id: &str) -> Result<&'a Controller> {
    state
        .keyring()
        .controllers
        .get(id)
        .ok_or_else(|| bad_signature("a signer is not a controller"))
}

/// The signature rule an immediate entry's signers are counted under, or `badSignature`.
fn immediate_rule(
    state: &State,
    kind: &Kind,
    signers: &[String],
    issued_ms: i64,
) -> Result<AuthorityRule> {
    check_signers_current(state, signers, issued_ms)?;
    let k = state.keyring();
    let control_member = k.policy.member_rule() == MemberRule::Control;
    let unmet = || bad_signature("the entry's rule is not met by these signers");
    match kind {
        Kind::Grant { .. }
        | Kind::Renew { .. }
        | Kind::Revoke { .. }
        | Kind::EndSessions { .. } => {
            if control_member {
                control_rule(k, signers, k.threshold)
                    .then_some(AuthorityRule::Control)
                    .ok_or_else(unmet)
            } else {
                single_rule(k, signers)
                    .then_some(AuthorityRule::Single)
                    .ok_or_else(unmet)
            }
        }
        Kind::Rekey { .. } => {
            if control_member {
                control_rule(k, signers, k.threshold)
                    .then_some(AuthorityRule::Control)
                    .ok_or_else(unmet)
            } else {
                let one_control = signers.len() == 1
                    && controller(state, &signers[0])
                        .is_ok_and(|c| c.has(&Role::Control) || c.has(&Role::Recover));
                (single_rule(k, signers) || one_control)
                    .then_some(AuthorityRule::Single)
                    .ok_or_else(unmet)
            }
        }
        Kind::Keyring { keyring } => {
            let all_control = signers
                .iter()
                .all(|i| k.controllers.get(i).is_some_and(|c| c.has(&Role::Control)));
            let add_ok = all_control && units(k, signers, None).len() as u64 >= k.add_threshold;
            let self_slot = signers.len() == 1 && is_self_slot(k, keyring, &signers[0]);
            (add_ok || self_slot)
                .then_some(AuthorityRule::KeyringEntry)
                .ok_or_else(unmet)
        }
        Kind::Vault { .. } => {
            let one = signers.len() == 1
                && controller(state, &signers[0])
                    .is_ok_and(|c| c.has(&Role::Control) || c.has(&Role::Recover));
            (one && state.vault_retiring())
                .then_some(AuthorityRule::KeyringEntry)
                .ok_or_else(unmet)
        }
        Kind::Suspend { transition, .. } => {
            let t = AuthEnvelope::parse(
                transition,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                true,
            )?;
            (signers.len() == 1 && t.signer_ids().contains(&signers[0]))
                .then_some(AuthorityRule::Suspend)
                .ok_or_else(unmet)
        }
        _ => Err(malformed("not an immediate or signed entry kind")),
    }
}

/// §8.4 "Self-slot": the only change adds slots to the current vault naming only the signer,
/// and the signer is not a `sign` controller.
fn is_self_slot(old: &Keyring, new: &Value, signer: &str) -> bool {
    let Ok(new) = Keyring::parse(new.clone(), 0) else {
        return false;
    };
    let strip = |k: &Keyring| {
        let mut v = k.raw.clone();
        if let Some(m) = v.as_object_mut() {
            m.remove("slots");
        }
        v
    };
    if strip(old) != strip(&new)
        || old
            .controllers
            .get(signer)
            .is_none_or(|c| c.has(&Role::Sign))
    {
        return false;
    }
    validate_self_slot(&new.controllers, &old.slots, &new.slots, signer).is_ok()
}

// ---------------------------------------------------------------------------------------------
// Genesis.

/// Inputs of [`prepare_genesis`].
pub struct GenesisParams {
    /// 1–200 bytes.
    pub label: String,
    /// Declared namespaces: sorted, distinct.
    pub namespaces: Vec<String>,
    /// The whole keyring, with its first slots built elsewhere (§7.2); the slots are checked
    /// here with [`validate_slots`].
    pub keyring: Value,
    /// `issued`, in ms.
    pub issued_ms: i64,
    /// The signers: the first is `by`, the rest cosign. Together they meet the control rule
    /// over the new keyring. Every other controller signs a possession proof.
    pub signers: Vec<String>,
}

/// Prepare a genesis (§8.2, §8.4): the exact body, the primary signature, the cosignatures
/// that meet the control rule over the new keyring, and a possession proof for every other
/// controller.
pub fn prepare_genesis(p: &GenesisParams, now_ms: i64) -> Result<PendingBatch> {
    let k = Keyring::parse(p.keyring.clone(), 1)?;
    validate_slots(&k.controllers, &k.slots, 1)?;
    require(!p.signers.is_empty(), "genesis needs a signer")?;
    require(
        p.signers.iter().all(|s| k.controllers.contains_key(s)),
        "a genesis signer is not a controller of its keyring",
    )?;
    if !control_rule(&k, &p.signers, k.threshold) {
        return Err(bad_signature(
            "genesis: control rule not met by these signers",
        ));
    }
    super::check_issued(p.issued_ms)?;
    let by = p.signers[0].clone();
    let body = Kind::Genesis {
        label: p.label.clone(),
        namespaces: p.namespaces.clone(),
        keyring: p.keyring.clone(),
        predecessor: None,
    }
    .body(&Header {
        seq: 1,
        previous: None,
        issued: format_date(p.issued_ms),
        by: by.clone(),
    })?;
    let path = authority_path(1);
    let mut steps = vec![step(
        &path,
        &body,
        &k.controllers[&by],
        StepRole::Primary,
        AuthorityRule::Control,
    )];
    for s in &p.signers[1..] {
        steps.push(step(
            &path,
            &body,
            &k.controllers[s],
            StepRole::Cosignature,
            AuthorityRule::Control,
        ));
    }
    for (id, c) in &k.controllers {
        if id != &by {
            steps.push(step(
                &path,
                &body,
                c,
                StepRole::Possession,
                AuthorityRule::Possession,
            ));
        }
    }
    Ok(PendingBatch {
        steps,
        objects: Objects::default(),
        now_ms,
        plan: Plan::Genesis { body },
    })
}

// ---------------------------------------------------------------------------------------------
// Signed entries.

fn next_header(state: &State, issued_ms: i64, by: &str) -> Result<Header> {
    super::check_issued(issued_ms)?;
    require(
        issued_ms >= state.last_issued_ms(),
        "issued is earlier than the preceding entry's",
    )?;
    Ok(Header {
        seq: state.history().len() as u64 + 1,
        previous: state.history().last().cloned(),
        issued: format_date(issued_ms),
        by: by.to_string(),
    })
}

/// Controllers a `keyring` entry adds, or whose `holder` it sets or changes: each signs a
/// possession proof (§8.4).
fn possession_controllers(old: &Keyring, new: &Keyring) -> Vec<Controller> {
    new.controllers
        .iter()
        .filter(|(id, c)| {
            old.controllers
                .get(*id)
                .is_none_or(|o| o.holder() != c.holder())
                && (!old.controllers.contains_key(*id) || c.holder().is_some())
        })
        .map(|(_, c)| c.clone())
        .collect()
}

/// Prepare an immediate or otherwise signed entry: `grant`, `renew`, `revoke`, `endSessions`
/// (by a controller; for the member's own, [`prepare_end_sessions_by_member`]), `rekey`,
/// `keyring`, `vault` and `suspend`. `signers[0]` is `by`; the others cosign. The signers must
/// meet the rule §8.4 gives the kind, or the result is `badSignature` and nothing is prepared.
pub fn prepare_signed(
    objects: &Objects,
    now_ms: i64,
    kind: Kind,
    issued_ms: i64,
    signers: &[String],
) -> Result<PendingBatch> {
    if matches!(kind, Kind::Genesis { .. }) || kind.is_recording() {
        return Err(malformed("not a signed entry kind"));
    }
    super::check_issued(issued_ms)?;
    let state = head_state(objects, now_ms)?;
    if let Kind::EndSessions { member } | Kind::Renew { member, .. } | Kind::Revoke { member, .. } =
        &kind
    {
        require(
            state
                .members()
                .iter()
                .any(|m| &m.request.member_id() == member && m.revoked_seq.is_none()),
            "the member does not exist or is already revoked",
        )?;
    }
    let rule = immediate_rule(&state, &kind, signers, issued_ms)?;
    let header = next_header(&state, issued_ms, &signers[0])?;
    let body = kind.body(&header)?;
    let path = authority_path(header.seq);
    let mut steps = Vec::new();
    for (i, id) in signers.iter().enumerate() {
        steps.push(step(
            &path,
            &body,
            controller(&state, id)?,
            if i == 0 {
                StepRole::Primary
            } else {
                StepRole::Cosignature
            },
            rule,
        ));
    }
    if let Kind::Vault { slots, .. } = &kind {
        validate_vault_entry_slots(&state.keyring().controllers, slots, &signers[0])?;
    }
    if let Kind::Keyring { keyring } = &kind {
        let new = Keyring::parse(keyring.clone(), 0)?;
        validate_slots(&new.controllers, &new.slots, 0)?;
        for c in possession_controllers(state.keyring(), &new) {
            steps.push(step(
                &path,
                &body,
                &c,
                StepRole::Possession,
                AuthorityRule::Possession,
            ));
        }
    }
    Ok(PendingBatch {
        steps,
        objects: objects.clone(),
        now_ms,
        plan: Plan::Entry {
            seq: header.seq,
            body,
        },
    })
}

/// Prepare an `endSessions` the member signs for itself (§8.4 "Member rule": raw, one
/// signer, `by` is the member).
pub fn prepare_end_sessions_by_member(
    objects: &Objects,
    now_ms: i64,
    member: &str,
    issued_ms: i64,
) -> Result<PendingBatch> {
    let state = head_state(objects, now_ms)?;
    let m = state
        .members()
        .iter()
        .find(|m| m.request.member_id() == member && m.revoked_seq.is_none())
        .ok_or_else(|| malformed("endSessions of a member that isn't current"))?;
    let header = next_header(&state, issued_ms, member)?;
    let body = Kind::EndSessions {
        member: member.to_string(),
    }
    .body(&header)?;
    let descriptor = KeyDescriptor::new_raw(m.request.signing.clone(), None)?;
    Ok(PendingBatch {
        steps: vec![SigningStep::new(
            authority_path(header.seq),
            body.clone(),
            member.to_string(),
            StepRole::Primary,
            descriptor,
            false,
        )],
        objects: objects.clone(),
        now_ms,
        plan: Plan::Entry {
            seq: header.seq,
            body,
        },
    })
}

// ---------------------------------------------------------------------------------------------
// Receipts and pending objects.

/// A receipt (§13.5) parsed far enough to choose among them.
struct Receipt {
    bytes: Vec<u8>,
    by: String,
    object: String,
    received_ms: i64,
    body_digest: String,
}

fn parse_receipt(state: &State, held: &[u8]) -> Option<Receipt> {
    // Like a home, canonicalize a held receipt rather than skip it: the same object held
    // as a reformatted copy is the same receipt (§2.2: equality is body bytes).
    let canon = canonical(&crate::v05::encoding::strict_parse(held).ok()?).ok()?;
    let bytes = &canon[..];
    let env =
        RawEnvelope::parse_bounded(bytes, bounds::RECEIPT_BODY, bounds::RECEIPT_ENVELOPE, true)
            .ok()?;
    let mut o = Obj::new(env.value.clone(), "receipt").ok()?;
    if o.string("protocol").ok()? != "colophon/receipt/5"
        || o.string("account").ok()? != state.account().as_str()
    {
        return None;
    }
    let object = o.digest("object").ok()?;
    let (_, received_ms) = o.date("received").ok()?;
    let by = o.key_id("by").ok()?;
    o.finish_closed().ok()?;
    let key = state
        .current_homes()
        .into_iter()
        .find(|m| m.request.member_id() == by)
        .map(|m| m.request.signing.clone())?;
    env.verify(&key).ok()?;
    Some(Receipt {
        bytes: bytes.to_vec(),
        by,
        object,
        received_ms,
        body_digest: digest(&env.body),
    })
}

/// Choose the receipts an entry carries for an object (§8.7): exactly `headQuorum` (at most
/// the number of current homes), from the homes with the lowest member IDs whose valid
/// receipts are held, for each home its receipt with the lowest body digest, sorted by home
/// ID. A receipt is valid when its home is current, its signature verifies, it names the
/// object, and `received` is within 300 s after the object's `issued`; with `not_after_ms`
/// (a veto's receipts, before the transition's veto deadline), also not after that time, and a
/// later receipt is skipped, not chosen. With no home, none are
/// needed. Too few homes with receipts: `unavailable`.
pub fn choose_receipts(
    state: &State,
    held: &[Vec<u8>],
    object_digest: &str,
    object_issued_ms: i64,
    not_after_ms: Option<i64>,
) -> Result<Vec<Vec<u8>>> {
    let homes = state.current_homes();
    if homes.is_empty() {
        return Ok(Vec::new());
    }
    let quorum = (state.keyring().policy.head_quorum() as usize).min(homes.len());
    let mut best: BTreeMap<String, Receipt> = BTreeMap::new();
    for bytes in held {
        let Some(r) = parse_receipt(state, bytes) else {
            continue;
        };
        if r.object != object_digest
            || r.received_ms < object_issued_ms
            || r.received_ms > object_issued_ms.saturating_add(RECEIPT_WINDOW_MS)
            || not_after_ms.is_some_and(|d| r.received_ms > d)
        {
            continue;
        }
        match best.get(&r.by) {
            Some(old) if old.body_digest <= r.body_digest => {}
            _ => {
                best.insert(r.by.clone(), r);
            }
        }
    }
    if best.len() < quorum {
        return Err(unavailable(
            "fewer homes have receipted the object than headQuorum",
        ));
    }
    Ok(best.into_values().take(quorum).map(|r| r.bytes).collect())
}

fn receipt_received(state: &State, bytes: &[u8]) -> Result<i64> {
    parse_receipt(state, bytes)
        .map(|r| r.received_ms)
        .ok_or_else(|| malformed("a chosen receipt does not parse"))
}

/// The held transition or veto envelope whose body digest is `want`.
fn find_pending<'a>(objects: &'a Objects, want: &str, protocol: &str) -> Result<&'a Vec<u8>> {
    objects
        .pending
        .iter()
        .find(|b| {
            AuthEnvelope::parse(
                b,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                true,
            )
            .is_ok_and(|e| {
                e.digest == want
                    && e.value.get("protocol").and_then(Value::as_str) == Some(protocol)
            })
        })
        .ok_or_else(|| unavailable(format!("no held {protocol} object with that digest")))
}

fn issued_of(env: &AuthEnvelope) -> Result<i64> {
    env.value
        .get("issued")
        .and_then(Value::as_str)
        .and_then(parse_date)
        .ok_or_else(|| malformed("issued"))
}

fn by_of(env: &AuthEnvelope) -> Result<String> {
    env.value
        .get("by")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| malformed("by"))
}

// ---------------------------------------------------------------------------------------------
// Transitions, vetoes, suspend, resolve.

/// Which rule the signers of a transition are counted under (§8.4, §8.7: one rule for every
/// component).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionRule {
    /// The control rule.
    Control,
    /// The recovery rule.
    Recovery,
}

/// Inputs of [`prepare_transition`].
pub struct TransitionParams {
    /// `(seq, body digest)` of the entry the proposer verified; `None` is the head.
    pub anchor: Option<(u64, String)>,
    /// `issued`, in ms.
    pub issued_ms: i64,
    /// The signers: the first is `by`; the rest cosign.
    pub signers: Vec<String>,
    /// The rule they are counted under.
    pub rule: TransitionRule,
    /// The `change` object (§8.7): one or more components.
    pub change: Value,
}

fn added_by_change(state: &State, change: &Value) -> Result<Vec<Controller>> {
    let mut out = Vec::new();
    let Some(k) = change.get("keyring") else {
        return Ok(out);
    };
    for v in k.get("add").and_then(Value::as_array).into_iter().flatten() {
        out.push(Controller::parse(v.clone(), "add")?);
    }
    for v in k
        .get("update")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let c = Controller::parse(v.clone(), "update")?;
        let old = state.keyring().controllers.get(&c.id());
        if c.holder().is_some() && old.is_none_or(|o| o.holder() != c.holder()) {
            out.push(c);
        }
    }
    Ok(out)
}

fn transition_batch(
    objects: &Objects,
    state: &State,
    now_ms: i64,
    p: &TransitionParams,
) -> Result<PendingBatch> {
    check_signers_current(state, &p.signers, i64::MAX)?;
    let k = state.keyring();
    let new_threshold = p
        .change
        .get("keyring")
        .and_then(|k| k.get("threshold"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let met = match p.rule {
        TransitionRule::Control => control_rule(k, &p.signers, k.threshold.max(new_threshold)),
        TransitionRule::Recovery => recovery_rule(k, &p.signers),
    };
    if !met {
        return Err(bad_signature(
            "the transition's rule is not met by these signers",
        ));
    }
    transition_components_allowed(state, &p.signers, p.rule, &p.change)?;
    let (a_seq, a_digest) = match &p.anchor {
        Some((s, d)) => (*s, d.clone()),
        None => (
            state.history().len() as u64,
            state.history().last().cloned().unwrap_or_default(),
        ),
    };
    require(
        a_seq
            .checked_sub(1)
            .and_then(|i| state.history().get(i as usize))
            == Some(&a_digest),
        "anchor is not on this branch",
    )?;
    super::check_issued(p.issued_ms)?;
    let body = transition_body(
        state.account().as_str(),
        a_seq,
        &a_digest,
        &format_date(p.issued_ms),
        &p.signers[0],
        &p.signers,
        &p.change,
    )?;
    let path = format!("transitions/{}.json", digest(&body));
    let ctl = |id: &str| controller(state, id);
    let mut steps = vec![step(
        &path,
        &body,
        ctl(&p.signers[0])?,
        StepRole::Primary,
        AuthorityRule::Transition,
    )];
    for s in &p.signers[1..] {
        steps.push(step(
            &path,
            &body,
            ctl(s)?,
            StepRole::Cosignature,
            AuthorityRule::Transition,
        ));
    }
    for c in added_by_change(state, &p.change)? {
        steps.push(step(
            &path,
            &body,
            &c,
            StepRole::Possession,
            AuthorityRule::Possession,
        ));
    }
    Ok(PendingBatch {
        steps,
        objects: objects.clone(),
        now_ms,
        plan: Plan::Transition { body },
    })
}

/// Consent, escalation and the per-component rules of §8.4 and §8.7, as far as they are
/// certain from the change and the state: a host is never asked to sign a transition the
/// verifier is sure to refuse. A case this does not catch is still refused by the verifier at
/// [`PendingBatch::finish`]; nothing here refuses what the verifier accepts.
fn transition_components_allowed(
    state: &State,
    signers: &[String],
    rule: TransitionRule,
    change: &Value,
) -> Result<()> {
    let k = state.keyring();
    let unmet = |why: &str| bad_signature(format!("the transition's rule is not met: {why}"));
    let comps = change
        .as_object()
        .ok_or_else(|| malformed("change must be an object"))?;
    require(!comps.is_empty(), "change has no component")?;
    let keyring = comps.get("keyring");
    let kfield = |f: &str| keyring.and_then(|v| v.get(f));
    // Escalation: |U| >= 1 + max v(u) over the signer units (§8.7).
    let signer_units = units(k, signers, None);
    let max_v = signer_units
        .iter()
        .map(|u| state.veto_counts().get(u).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    if (signer_units.len() as u64) < max_v.saturating_add(1) {
        return Err(unmet("escalation needs more signer units"));
    }
    // Which components the table allows under which rule.
    let has = |c: &str| comps.contains_key(c);
    if matches!(rule, TransitionRule::Control) && kfield("keep").is_some() {
        return Err(unmet("`keep` needs the recovery rule"));
    }
    if matches!(rule, TransitionRule::Recovery) {
        let policy_blocked = comps
            .get("policy")
            .and_then(Value::as_object)
            .is_some_and(|m| m.keys().any(|f| f != "primaryHome" && f != "headQuorum"));
        let threshold_blocked = ["threshold", "addThreshold", "recoverThreshold", "countBy"]
            .iter()
            .any(|f| kfield(f).is_some());
        if policy_blocked
            || threshold_blocked
            || ["grant", "layout", "migration", "successor", "resolve"]
                .iter()
                .any(|c| has(c))
        {
            return Err(unmet(
                "a component of this change is not open to the recovery rule",
            ));
        }
        return Ok(());
    }
    // Recovery-set consent (§8.4), under the control rule.
    if k.recover_threshold >= 1 {
        let recover_unit = |id: &str| k.controllers.get(id).is_some_and(|c| c.has(&Role::Recover));
        let ids = |f: &str| -> Vec<String> {
            kfield(f)
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let ctrls = |f: &str| -> Vec<Controller> {
            kfield(f)
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .filter_map(|x| Controller::parse(x.clone(), f).ok())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut consent = ids("remove").iter().any(|i| recover_unit(i))
            || ctrls("add").iter().any(|c| c.has(&Role::Recover))
            || ["layout", "migration", "successor", "resolve", "homes"]
                .iter()
                .any(|c| has(c))
            || kfield("countBy").is_some_and(|v| v != &k.raw["countBy"])
            || kfield("recoverThreshold").is_some_and(|v| v.as_u64() != Some(k.recover_threshold))
            || kfield("threshold")
                .and_then(Value::as_u64)
                .is_some_and(|t| t > k.threshold);
        for c in ctrls("update") {
            if let Some(old) = k.controllers.get(&c.id()) {
                let mut a = serde_json::to_value(old).unwrap_or(Value::Null);
                let mut b = serde_json::to_value(&c).unwrap_or(Value::Null);
                for v in [&mut a, &mut b] {
                    if let Some(m) = v.as_object_mut() {
                        m.remove("label");
                    }
                }
                consent |= (old.has(&Role::Recover) || c.has(&Role::Recover)) && a != b;
            }
        }
        if let Some(pol) = comps.get("policy").and_then(Value::as_object) {
            consent |= ["recoveryDelay", "headQuorum", "primaryHome", "rate"]
                .iter()
                .any(|f| pol.contains_key(*f));
        }
        let recover_units = units(k, signers, Some(&Role::Recover)).len() as u64;
        if consent && recover_units < k.recover_threshold {
            return Err(unmet("recovery-set consent is missing"));
        }
    }
    Ok(())
}

/// Prepare a pending transition (§8.7): its exact body, anchored on the head unless
/// `anchor` says otherwise, the signers' authority signatures, and a possession proof for
/// every controller it adds or whose `holder` it sets. Consent, escalation, receipts and the
/// rest of §8.7 are judged by the verifier at [`PendingBatch::finish`].
pub fn prepare_transition(
    objects: &Objects,
    now_ms: i64,
    p: &TransitionParams,
) -> Result<PendingBatch> {
    let state = head_state(objects, now_ms)?;
    transition_batch(objects, &state, now_ms, p)
}

/// The `change` of a `resolve` transition (§8.7).
pub fn resolve_change(discarded_seq: u64, discarded_digest: &str) -> Value {
    json!({"resolve": {"discarded": {"seq": discarded_seq, "digest": discarded_digest}}})
}

/// Prepare a `resolve` transition (§8.4, §8.7) on the branch ending at `anchor`: the held
/// entries that follow `previous` links back from the anchor are the branch the state is
/// folded over, so the other branch of an unresolved fork does not stop the preparation.
pub fn prepare_resolve(
    objects: &Objects,
    now_ms: i64,
    anchor: (u64, String),
    discarded: (u64, String),
    issued_ms: i64,
    signers: Vec<String>,
    rule: TransitionRule,
) -> Result<PendingBatch> {
    let mut by_digest: BTreeMap<String, (u64, Option<String>, Vec<u8>)> = BTreeMap::new();
    for bytes in &objects.entries {
        if let Ok(e) = AuthEnvelope::parse(
            bytes,
            bounds::AUTHORITY_BODY,
            bounds::AUTHORITY_BODY.saturating_mul(2),
            false,
        ) {
            let seq = e.value.get("seq").and_then(Value::as_u64).unwrap_or(0);
            let prev = e
                .value
                .get("previous")
                .and_then(Value::as_str)
                .map(str::to_string);
            by_digest.insert(e.digest.clone(), (seq, prev, bytes.clone()));
        }
    }
    let mut branch = Vec::new();
    let mut at = Some(anchor.1.clone());
    while let Some(d) = at {
        let (seq, prev, bytes) = by_digest
            .get(&d)
            .ok_or_else(|| unavailable("the anchor's branch is not held back to the genesis"))?;
        branch.push((*seq, bytes.clone()));
        at = prev.clone();
    }
    branch.reverse();
    require(
        branch.first().is_some_and(|(s, _)| *s == 1) && branch.len() as u64 == anchor.0,
        "the anchor's branch is not contiguous from seq 1",
    )?;
    let scoped = Objects {
        entries: branch.into_iter().map(|(_, b)| b).collect(),
        pending: objects.pending.clone(),
        heads: objects.heads.clone(),
        predecessor: objects.predecessor.clone(),
    };
    let state = head_state(&scoped, now_ms)?;
    transition_batch(
        &scoped,
        &state,
        now_ms,
        &TransitionParams {
            anchor: Some(anchor),
            issued_ms,
            signers,
            rule,
            change: resolve_change(discarded.0, &discarded.1),
        },
    )
}

/// Inputs of [`prepare_veto`].
pub struct VetoParams {
    /// The transition envelope being vetoed.
    pub transition: Vec<u8>,
    /// Its chosen receipts.
    pub transition_receipts: Vec<Vec<u8>>,
    /// `issued`, in ms.
    pub issued_ms: i64,
    /// The signers: the first is `by`; the rest cosign.
    pub signers: Vec<String>,
}

/// Prepare a veto (§8.7): its exact body and the authority signatures of its signers, each a
/// current `control` or `recover` controller. Unit counts and disjointness are judged by the
/// verifier at finish.
pub fn prepare_veto(objects: &Objects, now_ms: i64, p: &VetoParams) -> Result<PendingBatch> {
    super::check_issued(p.issued_ms)?;
    let state = head_state(objects, now_ms)?;
    check_signers_current(&state, &p.signers, i64::MAX)?;
    for id in &p.signers {
        let c = controller(&state, id)?;
        require(
            c.has(&Role::Control) || c.has(&Role::Recover),
            "a vetoer holds neither control nor recover",
        )?;
    }
    let t = AuthEnvelope::parse(
        &p.transition,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    let body = veto_body(
        state.account().as_str(),
        &t.digest,
        &format_date(p.issued_ms),
        &p.signers[0],
        &p.signers,
    )?;
    let path = format!("vetoes/{}.json", digest(&body));
    let mut steps = Vec::new();
    for (i, id) in p.signers.iter().enumerate() {
        steps.push(step(
            &path,
            &body,
            controller(&state, id)?,
            if i == 0 {
                StepRole::Primary
            } else {
                StepRole::Cosignature
            },
            AuthorityRule::Veto,
        ));
    }
    Ok(PendingBatch {
        steps,
        objects: objects.clone(),
        now_ms,
        plan: Plan::Veto {
            body,
            transition: p.transition.clone(),
            transition_receipts: p.transition_receipts.clone(),
        },
    })
}

/// Prepare a `suspend` (§8.7): `signer`, a signer of the held transition `transition`,
/// suspends `key` while it is pending. The receipts are chosen from the held objects.
pub fn prepare_suspend(
    objects: &Objects,
    now_ms: i64,
    key: &str,
    transition_digest: &str,
    issued_ms: i64,
    signer: &str,
) -> Result<PendingBatch> {
    let state = head_state(objects, now_ms)?;
    let t_bytes = find_pending(objects, transition_digest, "colophon/transition/5")?.clone();
    let env = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    let receipts = choose_receipts(
        &state,
        &objects.pending,
        &env.digest,
        issued_of(&env)?,
        None,
    )?;
    prepare_signed(
        objects,
        now_ms,
        Kind::Suspend {
            key: key.to_string(),
            transition: t_bytes,
            receipts,
        },
        issued_ms,
        &[signer.to_string()],
    )
}

// ---------------------------------------------------------------------------------------------
// The determined recording entries (§8.6, §8.7): a body only, one possible value.

fn recording_batch(
    objects: &Objects,
    state: &State,
    now_ms: i64,
    kind: Kind,
    issued_ms: i64,
    by: &str,
) -> Result<PendingBatch> {
    let header = next_header(state, issued_ms, by)?;
    let body = kind.body(&header)?;
    Ok(PendingBatch {
        steps: Vec::new(),
        objects: objects.clone(),
        now_ms,
        plan: Plan::Entry {
            seq: header.seq,
            body,
        },
    })
}

/// The `activate` for a held transition (§8.7): its receipts chosen as §8.7 says, `by` the
/// transition's, and `issued` = max(due time, the preceding entry's `issued`). Before the due
/// time it is `unavailable` (held). The result is a function of the held objects and the
/// clock, so two homes holding the same objects build identical bytes.
pub fn prepare_activate(
    objects: &Objects,
    now_ms: i64,
    transition_digest: &str,
) -> Result<PendingBatch> {
    let state = head_state(objects, now_ms)?;
    let t_bytes = find_pending(objects, transition_digest, "colophon/transition/5")?.clone();
    let env = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    let receipts = choose_receipts(
        &state,
        &objects.pending,
        &env.digest,
        issued_of(&env)?,
        None,
    )?;
    let timing = transition_timing(&state, &t_bytes, &receipts)?;
    if timing.due_ms > now_ms {
        return Err(unavailable(format!(
            "held: the transition is due at {}",
            format_date(timing.due_ms)
        )));
    }
    let issued = timing.due_ms.max(state.last_issued_ms());
    recording_batch(
        objects,
        &state,
        now_ms,
        Kind::Activate {
            transition: t_bytes,
            receipts,
        },
        issued,
        &timing.by,
    )
}

/// The `vetoed` for a held transition and a held veto (§8.7): both receipt lists chosen, `by`
/// the veto's, `issued` = max(latest chosen veto receipt, the preceding entry's `issued`).
/// Whether the veto's units, receipts and deadline satisfy §8.7 is judged by the verifier at
/// finish.
pub fn prepare_vetoed(
    objects: &Objects,
    now_ms: i64,
    transition_digest: &str,
    veto_digest: &str,
) -> Result<PendingBatch> {
    let state = head_state(objects, now_ms)?;
    let t_bytes = find_pending(objects, transition_digest, "colophon/transition/5")?.clone();
    let v_bytes = find_pending(objects, veto_digest, "colophon/veto/5")?.clone();
    let t = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    let v = AuthEnvelope::parse(&v_bytes, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)?;
    let t_receipts = choose_receipts(&state, &objects.pending, &t.digest, issued_of(&t)?, None)?;
    // The veto's receipts are those before the transition's veto deadline (§8.7): a later
    // receipt is skipped, so one late receipt cannot block a valid `vetoed`.
    let deadline = transition_timing(&state, &t_bytes, &t_receipts)?.deadline_ms;
    let v_receipts = choose_receipts(
        &state,
        &objects.pending,
        &v.digest,
        issued_of(&v)?,
        Some(deadline),
    )?;
    let mut latest = i64::MIN;
    for r in &v_receipts {
        latest = latest.max(receipt_received(&state, r)?);
    }
    if v_receipts.is_empty() {
        latest = issued_of(&v)?;
    }
    let issued = latest.max(state.last_issued_ms());
    let by = by_of(&v)?;
    recording_batch(
        objects,
        &state,
        now_ms,
        Kind::Vetoed {
            transition: t_bytes,
            transition_receipts: t_receipts,
            veto: v_bytes,
            receipts: v_receipts,
        },
        issued,
        &by,
    )
}

/// The `final` for a provisional activation (§8.7): one held head per witness of the
/// activation that is still a current home, each signed by that home and covering the
/// activation on this branch; `by` the activation's; `issued` = max(latest head's `issued`,
/// the preceding entry's `issued`). When a witness has several covering heads the one with the
/// lowest body digest is taken: §8.7 does not say which (reported as a spec question).
pub fn prepare_final(objects: &Objects, now_ms: i64, activation_seq: u64) -> Result<PendingBatch> {
    let state = head_state(objects, now_ms)?;
    let act = state
        .activations()
        .iter()
        .find(|a| a.seq == activation_seq)
        .ok_or_else(|| malformed("no activation at that seq on this branch"))?
        .clone();
    require(!act.final_, "the activation is already final")?;
    let home_ids: BTreeSet<String> = state
        .current_homes()
        .iter()
        .map(|m| m.request.member_id())
        .collect();
    let required: Vec<String> = act
        .witnesses
        .iter()
        .filter(|h| home_ids.contains(*h))
        .cloned()
        .collect();
    let mut best: BTreeMap<String, (String, i64, Vec<u8>)> = BTreeMap::new();
    for bytes in &objects.heads {
        let Ok(env) = RawEnvelope::parse(bytes, bounds::HEAD_BODY, true) else {
            continue;
        };
        let (Some(by), Some(seq), Some(dg), Some(issued)) = (
            env.value.get("by").and_then(Value::as_str),
            env.value["authority"].get("seq").and_then(Value::as_u64),
            env.value["authority"].get("digest").and_then(Value::as_str),
            env.value
                .get("issued")
                .and_then(Value::as_str)
                .and_then(parse_date),
        ) else {
            continue;
        };
        // A head ahead of the clock by more than 60 s is not usable yet (§13.3): it must not
        // hold a `final` back when another head of the witness is usable. Open spec question.
        if issued > now_ms.saturating_add(60 * SEC) {
            continue;
        }
        if !required.iter().any(|h| h == by)
            || env.value.get("protocol").and_then(Value::as_str) != Some("colophon/head/5")
            || seq < act.seq
            || seq
                .checked_sub(1)
                .and_then(|i| state.history().get(i as usize))
                .map(String::as_str)
                != Some(dg)
        {
            continue;
        }
        let Some(key) = state
            .members()
            .iter()
            .find(|m| m.request.member_id() == by && m.home != HomeStatus::NotHome)
            .map(|m| m.request.signing.clone())
        else {
            continue;
        };
        if env.verify(&key).is_err() {
            continue;
        }
        let bd = digest(&env.body);
        match best.get(by) {
            Some((old, _, _)) if old <= &bd => {}
            _ => {
                best.insert(by.to_string(), (bd, issued, bytes.clone()));
            }
        }
    }
    if required.is_empty() || best.len() != required.len() {
        return Err(unavailable(
            "a head covering the activation is missing for a witness",
        ));
    }
    let latest = best.values().map(|(_, i, _)| *i).max().unwrap_or(i64::MIN);
    let heads: Vec<Vec<u8>> = best.into_values().map(|(_, _, b)| b).collect();
    recording_batch(
        objects,
        &state,
        now_ms,
        Kind::Final {
            activation_seq: act.seq,
            activation_digest: act.digest.clone(),
            heads,
        },
        latest.max(state.last_issued_ms()),
        &act.by,
    )
}

// ---------------------------------------------------------------------------------------------
// Equivocation evidence (§13.3).
//
// Evidence convicts a home or signers, so every form is judged from verified material only:
// every signature in it is checked, under the keys of the history the verifier holds, and a
// form that needs history the caller does not hold is `unavailable`, never a conviction.

/// The `protocol` of an evidence object.
pub const EVIDENCE_PROTOCOL: &str = "colophon/equivocation/5";

/// What evidence is judged against: the objects the verifier holds, and its clock.
#[derive(Clone, Copy, Debug)]
pub struct EvidenceContext<'a> {
    /// The account's held entries, pending objects and heads.
    pub objects: &'a Objects,
    /// The verifier's clock, in ms.
    pub now_ms: i64,
}

fn finish_evidence(value: Value) -> Result<Vec<u8>> {
    let bytes = canonical(&value)?;
    require(
        bytes.len() <= bounds::EQUIVOCATION,
        "equivocation evidence exceeds 2,097,152 bytes",
    )?;
    Ok(bytes)
}

fn parse_entry_env(bytes: &[u8]) -> Result<AuthEnvelope> {
    AuthEnvelope::parse(
        bytes,
        bounds::AUTHORITY_BODY,
        bounds::AUTHORITY_BODY.saturating_mul(2),
        true,
    )
}

fn head_facts(bytes: &[u8], account: &str) -> Result<(RawEnvelope, String, u64, String, i64)> {
    let env = RawEnvelope::parse(bytes, bounds::HEAD_BODY, true)?;
    let mut o = Obj::new(env.value.clone(), "head")?;
    require(
        o.string("protocol")? == "colophon/head/5",
        "not a colophon/head/5 head",
    )?;
    require(
        o.string("account")? == account,
        "head names another account",
    )?;
    let mut a = o.obj("authority")?;
    let seq = a.uint("seq")?;
    require(seq >= 1, "authority.seq must be at least 1")?;
    let dg = a.digest("digest")?;
    let (_, issued) = o.date("issued")?;
    let by = o.key_id("by")?;
    Ok((env, by, seq, dg, issued))
}

/// The held entries from the genesis to the entry with body digest `tip`, following
/// `previous`, with the pending objects and heads. `unavailable` when the chain is not held.
fn chain_to(objects: &Objects, tip: &str) -> Result<Objects> {
    let mut by_digest: BTreeMap<String, (Option<String>, Vec<u8>)> = BTreeMap::new();
    for bytes in &objects.entries {
        if let Ok(e) = parse_entry_env(bytes).or_else(|_| {
            AuthEnvelope::parse(
                bytes,
                bounds::AUTHORITY_BODY,
                bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            )
        }) {
            let prev = e
                .value
                .get("previous")
                .and_then(Value::as_str)
                .map(str::to_string);
            by_digest.insert(e.digest.clone(), (prev, bytes.clone()));
        }
    }
    let mut entries = Vec::new();
    let mut at = Some(tip.to_string());
    while let Some(d) = at {
        let (prev, bytes) = by_digest
            .get(&d)
            .ok_or_else(|| unavailable("the history is not held back to the genesis"))?;
        entries.push(bytes.clone());
        at = prev.clone();
    }
    entries.reverse();
    Ok(Objects {
        entries,
        pending: objects.pending.clone(),
        heads: objects.heads.clone(),
        predecessor: objects.predecessor.clone(),
    })
}

fn verified_state(objects: &Objects, account: &str, now_ms: i64) -> Result<State> {
    let st = head_state(objects, now_ms)?;
    require(
        st.account().as_str() == account,
        "the history is of another account",
    )?;
    Ok(st)
}

/// Verify one entry in its place: the entries before it (held back to the genesis) plus the
/// entry must verify `ok` with the entry as the head (§8.5, every signature included).
fn verify_entry_in_place(
    objects: &Objects,
    account: &str,
    entry: &AuthEnvelope,
    entry_bytes: &[u8],
    now_ms: i64,
) -> Result<()> {
    let seq = entry
        .value
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("seq"))?;
    require(seq >= 2, "an entry in evidence has a predecessor")?;
    let previous = entry
        .value
        .get("previous")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("previous"))?;
    let mut chain = chain_to(objects, previous)?;
    require(
        chain.entries.len() as u64 == seq.saturating_sub(1),
        "the entry does not follow its predecessors' seqs",
    )?;
    let genesis_ok = chain.entries.first().and_then(|g| {
        AuthEnvelope::parse(g, bounds::AUTHORITY_BODY, bounds::AUTHORITY_BODY * 2, false).ok()
    });
    require(
        genesis_ok.is_some_and(|g| g.digest == account),
        "the history is of another account",
    )?;
    chain.entries.push(entry_bytes.to_vec());
    let verdict = verify_history(&chain, &Persisted::default(), now_ms);
    stop_to_error(&verdict.stop)?;
    require(
        verdict.branch.len() as u64 == seq && verdict.branch.last() == Some(&entry.digest),
        "the entry is not the head of the verified branch",
    )
}

/// Two heads by one home with the same `seq` and different digests (§13.3), judged against
/// the held history.
///
/// Convicts only when both heads verify under the home's key, name the same seq with
/// different digests, the held history reaches that seq (otherwise `unavailable`), both
/// entries are held, and the later head's entry did not displace the earlier one under §8.6
/// rule 1 (a conflict with a recording entry, the later head over the entry that stands).
fn judge_heads(
    account: &str,
    head_a: &[u8],
    head_b: &[u8],
    ctx: &EvidenceContext<'_>,
) -> Result<Evidence> {
    let (ea, by_a, seq_a, dg_a, issued_a) = head_facts(head_a, account)?;
    let (eb, by_b, seq_b, dg_b, issued_b) = head_facts(head_b, account)?;
    require(by_a == by_b, "the heads are by different homes")?;
    require(seq_a == seq_b, "the heads cover different seqs")?;
    require(dg_a != dg_b, "the heads cover the same entry")?;
    let verdict = verify_history(ctx.objects, &Persisted::default(), ctx.now_ms);
    let st = verdict
        .state
        .ok_or_else(|| unavailable("no verified history is held"))?;
    require(
        st.account().as_str() == account,
        "the history is of another account",
    )?;
    let key = st
        .members()
        .iter()
        .find(|m| m.request.member_id() == by_a && m.home != HomeStatus::NotHome)
        .map(|m| m.request.signing.clone())
        .ok_or_else(|| bad_signature("the heads are not by a home of this account"))?;
    ea.verify(&key).map_err(|e| bad_signature(e.to_string()))?;
    eb.verify(&key).map_err(|e| bad_signature(e.to_string()))?;
    if (st.history().len() as u64) < seq_a {
        return Err(unavailable(
            "the held history does not reach the heads' seq: no conviction",
        ));
    }
    let standing = st.history()[(seq_a - 1) as usize].clone();
    let held = |d: &str| {
        ctx.objects.entries.iter().find_map(|b| {
            let e =
                AuthEnvelope::parse(b, bounds::AUTHORITY_BODY, bounds::AUTHORITY_BODY * 2, false)
                    .ok()?;
            (e.digest == d).then_some(e)
        })
    };
    let (Some(xa), Some(xb)) = (held(&dg_a), held(&dg_b)) else {
        return Err(unavailable(
            "an entry a head covers is not held: no conviction",
        ));
    };
    let previous = |e: &AuthEnvelope| e.value.get("previous").cloned();
    let recording = |e: &AuthEnvelope| {
        matches!(
            e.value.get("kind").and_then(Value::as_str),
            Some("activate" | "vetoed" | "final" | "successionVetoed")
        )
    };
    if previous(&xa) == previous(&xb) && (recording(&xa) || recording(&xb)) {
        // §8.6 rule 1 settles this conflict. An honest home signs a head over the entry that
        // was displaced and, later, over the one that displaced it.
        let (later_digest, earlier_digest) = if issued_a > issued_b {
            (&dg_a, &dg_b)
        } else {
            (&dg_b, &dg_a)
        };
        if issued_a != issued_b && *later_digest == standing && *earlier_digest != standing {
            return Err(malformed(
                "the later head's entry displaced the earlier under §8.6 rule 1: not equivocation",
            ));
        }
    }
    Ok(Evidence::Heads {
        home: by_a,
        seq: seq_a,
    })
}

/// Two heads by one home with the same `seq` and different digests: the evidence
/// `{"protocol","account","heads"}`, sorted by body digest, built only when it convicts
/// ([`verify_evidence`] on the result).
pub fn equivocation_of_heads(
    account: &str,
    head_a: &[u8],
    head_b: &[u8],
    ctx: &EvidenceContext<'_>,
) -> Result<Vec<u8>> {
    let (ea, ..) = head_facts(head_a, account)?;
    let (eb, ..) = head_facts(head_b, account)?;
    let mut pair = [(digest(&ea.body), head_a), (digest(&eb.body), head_b)];
    pair.sort_by(|x, y| x.0.cmp(&y.0));
    let bytes = finish_evidence(json!({
        "protocol": EVIDENCE_PROTOCOL,
        "account": account,
        "heads": pair.iter().map(|(_, b)| encode_base64(b)).collect::<Vec<_>>(),
    }))?;
    verify_evidence(&bytes, account, ctx)?;
    Ok(bytes)
}

fn judge_entries(account: &str, a: &[u8], b: &[u8], ctx: &EvidenceContext<'_>) -> Result<Evidence> {
    let (ea, eb) = (parse_entry_env(a)?, parse_entry_env(b)?);
    let key = |e: &AuthEnvelope| {
        (
            e.value.get("seq").and_then(Value::as_u64),
            e.value.get("previous").cloned(),
        )
    };
    require(
        key(&ea) == key(&eb),
        "the entries are not at one seq and previous",
    )?;
    require(ea.digest != eb.digest, "the entries are equal")?;
    // Each must be a valid entry in its place: signatures and rules included (§8.5).
    verify_entry_in_place(ctx.objects, account, &ea, a, ctx.now_ms)?;
    verify_entry_in_place(ctx.objects, account, &eb, b, ctx.now_ms)?;
    Ok(Evidence::Entries {
        seq: ea.value.get("seq").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// Two conflicting entries (§8.6 rule 2, §13.3): the same `seq` and `previous`, different
/// bodies, sorted by body digest, under `entries`. Built only when both are valid entries in
/// their place under the held history.
pub fn equivocation_of_entries(
    account: &str,
    a: &[u8],
    b: &[u8],
    ctx: &EvidenceContext<'_>,
) -> Result<Vec<u8>> {
    let (ea, eb) = (parse_entry_env(a)?, parse_entry_env(b)?);
    let mut pair = [(ea.digest.clone(), a), (eb.digest.clone(), b)];
    pair.sort_by(|x, y| x.0.cmp(&y.0));
    let bytes = finish_evidence(json!({
        "protocol": EVIDENCE_PROTOCOL,
        "account": account,
        "entries": pair.iter().map(|(_, e)| encode_base64(e)).collect::<Vec<_>>(),
    }))?;
    verify_evidence(&bytes, account, ctx)?;
    Ok(bytes)
}

/// A veto against a final activation (§8.7, §13.3). The evidence carries the **activation**
/// entry (which embeds the transition and its receipts) as well as the veto, the home's
/// receipt of the veto and the `final`; the spec's "verifiable from the keys it names alone"
/// does not hold for it (the deadline needs the transition), a spec change.
fn judge_veto(
    account: &str,
    activation: &[u8],
    veto: &[u8],
    receipt: &[u8],
    final_entry: &[u8],
    ctx: &EvidenceContext<'_>,
) -> Result<Evidence> {
    let act = parse_entry_env(activation)?;
    require(
        act.value.get("kind").and_then(Value::as_str) == Some("activate"),
        "not an activate entry",
    )?;
    let fin = parse_entry_env(final_entry)?;
    require(
        fin.value.get("kind").and_then(Value::as_str) == Some("final"),
        "not a final entry",
    )?;
    let link = &fin.value["activation"];
    require(
        link.get("digest").and_then(Value::as_str) == Some(act.digest.as_str())
            && link.get("seq") == act.value.get("seq"),
        "the final does not record this activation",
    )?;
    let t_bytes = decode_base64(
        act.value
            .get("transition")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("activate transition"))?,
        bounds::TRANSITION_ENVELOPE,
    )?;
    let receipts: Vec<Vec<u8>> = act
        .value
        .get("receipts")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("activate receipts"))?
        .iter()
        .map(|v| decode_base64(v.as_str().unwrap_or_default(), bounds::RECEIPT_ENVELOPE))
        .collect::<Result<_>>()?;
    let t = AuthEnvelope::parse(
        &t_bytes,
        bounds::TRANSITION_ENVELOPE,
        bounds::TRANSITION_ENVELOPE,
        true,
    )?;
    let v = AuthEnvelope::parse(veto, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)?;
    require(
        v.value.get("account").and_then(Value::as_str) == Some(account)
            && v.value.get("transition").and_then(Value::as_str) == Some(t.digest.as_str()),
        "the veto does not name the activated transition",
    )?;
    // The state before the activation: the veto's signers and the home's key are judged there.
    let act_previous = act
        .value
        .get("previous")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("previous"))?;
    let before = chain_to(ctx.objects, act_previous)?;
    let s = verified_state(&before, account, ctx.now_ms)?;
    check_pending_veto(&s, &t_bytes, &receipts, veto)?;
    let timing = transition_timing(&s, &t_bytes, &receipts)?;
    // The home's receipt of the veto, before the deadline.
    let r = RawEnvelope::parse_bounded(
        receipt,
        bounds::RECEIPT_BODY,
        bounds::RECEIPT_ENVELOPE,
        true,
    )?;
    let mut o = Obj::new(r.value.clone(), "receipt")?;
    require(
        o.string("protocol")? == "colophon/receipt/5" && o.string("account")? == account,
        "not a receipt of this account",
    )?;
    require(
        o.digest("object")? == v.digest,
        "the receipt is not of this veto",
    )?;
    let (_, received) = o.date("received")?;
    let home = o.key_id("by")?;
    o.finish_closed()?;
    let key = s
        .current_homes()
        .into_iter()
        .find(|m| m.request.member_id() == home)
        .map(|m| m.request.signing.clone())
        .ok_or_else(|| bad_signature("the receipt is not by a home current at the activation"))?;
    r.verify(&key).map_err(|e| bad_signature(e.to_string()))?;
    let v_issued = issued_of(&v)?;
    require(
        received >= v_issued && received <= v_issued.saturating_add(RECEIPT_WINDOW_MS),
        "the receipt is outside its window",
    )?;
    require(
        received <= timing.deadline_ms,
        "the home receipted the veto after the deadline",
    )?;
    // The `final` verifies in its place (every head under its home's key, covering the
    // activation), and the convicted home's head is among them.
    verify_entry_in_place(ctx.objects, account, &fin, final_entry, ctx.now_ms)?;
    let mut has_home = false;
    for h in fin
        .value
        .get("heads")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("final heads"))?
    {
        let bytes = decode_base64(
            h.as_str().ok_or_else(|| malformed("head"))?,
            bounds::HEAD_BODY * 2 + 4_096,
        )?;
        let (_, by, ..) = head_facts(&bytes, account)?;
        has_home |= by == home;
    }
    require(has_home, "the final carries no head by the receipting home")?;
    Ok(Evidence::Veto { home })
}

/// A veto against a final activation: `{"protocol","account","activation","veto","receipt",
/// "final"}`, built only when it convicts ([`verify_evidence`] on the result).
pub fn equivocation_of_veto(
    account: &str,
    activation: &[u8],
    veto: &[u8],
    receipt: &[u8],
    final_entry: &[u8],
    ctx: &EvidenceContext<'_>,
) -> Result<Vec<u8>> {
    let bytes = finish_evidence(json!({
        "protocol": EVIDENCE_PROTOCOL,
        "account": account,
        "activation": encode_base64(activation),
        "veto": encode_base64(veto),
        "receipt": encode_base64(receipt),
        "final": encode_base64(final_entry),
    }))?;
    verify_evidence(&bytes, account, ctx)?;
    Ok(bytes)
}

/// What an evidence object proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Two heads by `home` at one seq with different digests, not explained by §8.6 rule 1.
    Heads {
        /// The misbehaving home.
        home: String,
        /// The seq.
        seq: u64,
    },
    /// Two conflicting valid entries at `seq`.
    Entries {
        /// The seq.
        seq: u64,
    },
    /// A home receipted a valid, timely veto of a transition and then signed a head for the
    /// `final` of its activation.
    Veto {
        /// The receipting home.
        home: String,
    },
}

/// Verify an evidence object (§13.3) against the held objects: the bound, canonical bytes,
/// the protocol, the account, and the form's own checks, every signature included. It never
/// convicts on unverified material: history that is not held makes the result `unavailable`.
pub fn verify_evidence(bytes: &[u8], account: &str, ctx: &EvidenceContext<'_>) -> Result<Evidence> {
    require(
        bytes.len() <= bounds::EQUIVOCATION,
        "equivocation evidence exceeds 2,097,152 bytes",
    )?;
    let value = crate::v05::encoding::canonical_body(bytes, bounds::EQUIVOCATION)?;
    let mut o = Obj::new(value, "evidence")?;
    require(
        o.string("protocol")? == EVIDENCE_PROTOCOL,
        "not a colophon/equivocation/5 object",
    )?;
    require(
        o.string("account")? == account,
        "evidence names another account",
    )?;
    let embedded = |s: &str| decode_base64(s, bounds::EQUIVOCATION);
    let pair = |o: &mut Obj, f: &str| -> Result<Vec<Vec<u8>>> {
        let list = o.array(f)?;
        require(list.len() == 2, "two objects")?;
        list.iter()
            .map(|v| embedded(v.as_str().unwrap_or_default()))
            .collect()
    };
    if o.has("heads") {
        let h = pair(&mut o, "heads")?;
        o.finish_closed()?;
        let (ea, ..) = head_facts(&h[0], account)?;
        let (eb, ..) = head_facts(&h[1], account)?;
        require(
            digest(&ea.body) < digest(&eb.body),
            "heads are not sorted by body digest",
        )?;
        judge_heads(account, &h[0], &h[1], ctx)
    } else if o.has("entries") {
        let e = pair(&mut o, "entries")?;
        o.finish_closed()?;
        let (ea, eb) = (parse_entry_env(&e[0])?, parse_entry_env(&e[1])?);
        require(
            ea.digest < eb.digest,
            "entries are not sorted by body digest",
        )?;
        judge_entries(account, &e[0], &e[1], ctx)
    } else {
        let activation = embedded(&o.string("activation")?)?;
        let veto = embedded(&o.string("veto")?)?;
        let receipt = embedded(&o.string("receipt")?)?;
        let fin = embedded(&o.string("final")?)?;
        o.finish_closed()?;
        judge_veto(account, &activation, &veto, &receipt, &fin, ctx)
    }
}
