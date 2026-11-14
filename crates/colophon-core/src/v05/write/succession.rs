//! Succession builders (§15, §16.2, §16.3): a 0.5 successor account for a Swift keyring library
//! (the shipped apps' format) or for a native `/5` account, as prepare-then-finish builders.
//!
//! Built here:
//! * [`prepare_swift_genesis`]: the successor genesis for a Swift predecessor, with its `predecessor`,
//!   possession proofs for the keys that are not carried over, and the `handover` signatures of
//!   the keys that may write F at `head`. [`swift_carried_controllers`] builds the carried
//!   controllers with roles exactly as the predecessor held them (§16.2), and
//!   [`swift_slotted_controllers`] says which controllers had a slot (every one needs a rebuilt
//!   slot or the builder stops).
//! * [`prepare_swift_freeze`]: F, the freezing `layout` entry of a Swift predecessor (§16.3), as
//!   exact Swift-format record bytes.
//! * [`prepare_authority5_genesis`] and [`prepare_successor_transition`]: succession of a `/5`
//!   account (the genesis, and the `successor` transition whose activation is F).
//! * [`prepare_succession_vetoed`]: the unsigned `successionVetoed` entry for a successor home that
//!   holds a valid veto (§15.1 step 4).
//! * [`prepare_migration`]: the `migration` transition (§15.4) with real view digests.
//! * [`succession_status`] (re-exported): the window, due time, veto deadline and the keys that may
//!   veto, from a verified state.
//!
//! **What is guaranteed.** Every `finish` verifies the exact bytes it returns with
//! `v05::history::verify_history` (and, for F, the Swift verifier `history::swift::verify`) over the
//! whole object set, and returns nothing on failure. The rule that decides which keys may write F
//! at `head` (`history::succession::handover_authorized`), the Swift `layout` rule, the receipt
//! checks and the carried-key test are the verifier's own functions, not copies. Prepared state
//! has private fields. No secret passes through here: the module sees public keys, bodies,
//! signatures and the objects a home holds.
//!
//! **What the host is trusted with.** Signing the exact bytes of each step with the right key;
//! holding every predecessor entry it passes in (they are verified here); building the new slots
//! (`v05::slots`) and passing them in the new keyring; opening the old Swift vault through the
//! Swift code, which this module does not do; and writing F through the Swift code. The shipped
//! Swift `AuthorityEntry` has no `successor` field, so F's bytes here are the §16.3 bytes and the
//! shipped writer cannot yet produce them (reported as a question on the pull request).
use super::authority::{
    control_rule, find_pending, head_state, recording_batch, step, step_with_uv, PendingBatch,
    TransitionParams, TransitionRule,
};
use super::{envelope, format_date, Header, Kind, Records, Signature, SignatureResult};
use super::{SigningStep, StepRole};
use crate::v05::descriptor::{Controller, KeyDescriptor, Role, WebAuthnKey};
use crate::v05::encoding::{bounds, canonical, decode_base64, digest, encode_base64, parse_date};
use crate::v05::history::keyring::Keyring;
use crate::v05::history::succession::{
    choose_succession_receipts, handover_authorized, same_swift_key,
};
use crate::v05::history::swift::{self, layout_signers_meet_rule, Snapshot};
use crate::v05::history::{verify_history, Objects, Persisted, Stop};
use crate::v05::ids::{key_id, AccountId};
use crate::v05::signature::AuthorityRule;
use crate::v05::slots::validate_slots;
use crate::v05::{bad_signature, malformed, require, Failure, Reason, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub use crate::v05::history::{succession_status, SuccessionStatus, SuccessionTiming};

/// The format string of a Swift predecessor (§16.3).
pub const SWIFT_FORMAT: &str = "colophon/swift-keyring/2";
/// The format string of a `/5` predecessor (§15.1).
pub const AUTHORITY5_FORMAT: &str = "colophon/authority/5";

fn unavailable(why: impl Into<String>) -> Failure {
    Failure::Unavailable(why.into())
}

fn stop_error(stop: &Option<Stop>) -> Result<()> {
    match stop {
        None => Ok(()),
        Some(Stop::Failed { failure, .. }) => Err(failure.clone()),
        Some(Stop::Held { why, .. }) => Err(unavailable(format!("held: {why}"))),
        Some(Stop::Fork { .. }) => Err(Failure::Refused(Reason::Fork)),
    }
}

/// The verified state of the held objects. An entry that fails to verify is malformed evidence
/// (§8.5) and the accepted history ends before it, so a stop that is `Failed` leaves the state
/// before it and does not stop a builder; a held entry (a time in the future) or an unresolved
/// fork does, and so does a history with no state at all.
fn state_of(objects: &Objects, now_ms: i64) -> Result<crate::v05::history::State> {
    let verdict = verify_history(objects, &Persisted::default(), now_ms);
    match &verdict.stop {
        None | Some(Stop::Failed { .. }) => {}
        other => stop_error(other)?,
    }
    verdict
        .state
        .ok_or_else(|| malformed("the held objects hold no genesis"))
}

fn role_name(r: &Role) -> Option<&'static str> {
    match r {
        Role::Approve => Some("approve"),
        Role::Control => Some("control"),
        Role::Recover => Some("recover"),
        Role::Sign => Some("sign"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Reading a Swift predecessor.

/// The verified Swift history and its head (the last entry).
struct SwiftHead {
    history: swift::History,
    seq: u64,
    digest: String,
    issued_ms: i64,
}
impl SwiftHead {
    fn read(entries: &[Vec<u8>]) -> Result<Self> {
        let history = swift::verify(entries)?;
        let last = history
            .entries
            .last()
            .ok_or_else(|| malformed("Swift empty predecessor"))?;
        Ok(Self {
            seq: history.entries.len() as u64,
            digest: last.digest.clone(),
            issued_ms: last.issued_ms,
            history,
        })
    }
    fn snapshot(&self) -> Result<&Snapshot> {
        self.history
            .states
            .last()
            .ok_or_else(|| malformed("Swift empty predecessor"))
    }
    fn claim(&self) -> Value {
        json!({"format": SWIFT_FORMAT, "account": self.history.account,
               "head": {"seq": self.seq, "digest": self.digest}})
    }
}

fn b64_of(v: &Value, f: &str) -> Option<Vec<u8>> {
    decode_base64(v.get(f)?.as_str()?, 1_048_576).ok()
}

/// The controllers of the Swift predecessor at its head that hold a vault slot (§15.3, §16.2).
/// A controller holds a slot when a slot, or a part of a combined slot, names it in `controller`,
/// or is a `sealed` slot or part whose recipient is its signing key, or is a `prf` slot or part
/// for its WebAuthn credential. The union is taken, so a controller any of these point at needs a
/// rebuilt slot. (The spec does not say how a slot is attributed; this is the conservative
/// reading, reported as a question.) A library that has not adopted a keyring has no slots.
pub fn swift_slotted_controllers(entries: &[Vec<u8>]) -> Result<BTreeSet<String>> {
    let head = SwiftHead::read(entries)?;
    Ok(slotted(head.snapshot()?))
}

fn slotted(s: &Snapshot) -> BTreeSet<String> {
    fn walk(s: &Snapshot, slot: &Value, out: &mut BTreeSet<String>, depth: usize) {
        if depth > 2 {
            return;
        }
        if let Some(id) = slot.get("controller").and_then(Value::as_str) {
            if s.controllers.contains_key(id) {
                out.insert(id.to_string());
            }
        }
        if let Some(p) = slot.get("recipient").and_then(|r| b64_of(r, "signing")) {
            let id = key_id(&p);
            if s.controllers.contains_key(&id) {
                out.insert(id);
            }
        }
        if let Some(cred) = b64_of(slot, "credential") {
            for (id, c) in &s.controllers {
                if c.key().webauthn().is_some_and(|w| w.credential() == cred) {
                    out.insert(id.clone());
                }
            }
        }
        for part in slot
            .get("parts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(s, part, out, depth + 1);
        }
    }
    let mut out = BTreeSet::new();
    for slot in s
        .raw_keyring
        .get("slots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(s, slot, &mut out, 0);
    }
    out
}

/// Options of [`swift_carried_controllers`].
#[derive(Clone, Debug, Default)]
pub struct CarryOptions {
    /// Carry the stewards of a root library as `recover` controllers (§16.2: only if the person
    /// chooses). Ignored for a keyring library.
    pub include_stewards: bool,
    /// `authorityOrigins` per WebAuthn controller ID, 1–32 strictly ascending origins. A
    /// WebAuthn controller without an entry is carried without `authorityOrigins`.
    pub authority_origins: BTreeMap<String, Vec<String>>,
    /// Agreement points per controller ID, for a raw controller whose agreement key the
    /// predecessor does not show (a sealed slot needs one).
    pub agreements: BTreeMap<String, Vec<u8>>,
}

/// The controllers of the Swift predecessor at its head, as 0.5 controller objects (§16.2),
/// sorted by ID: the same signing keys (so the same IDs), the same WebAuthn `rp` and credential,
/// the same labels and `verification`, and **the same roles** (a root library's root is
/// `approve` + `control`, its recovery identity `recover`; the host changes roles afterwards by a
/// transition, never here). A raw controller carries the agreement point the predecessor shows
/// for its key (a root, recovery or steward identity, or a slot recipient), or the one in
/// `options`.
pub fn swift_carried_controllers(
    entries: &[Vec<u8>],
    options: &CarryOptions,
) -> Result<Vec<Value>> {
    let head = SwiftHead::read(entries)?;
    let agreements = known_agreements(&head.history);
    let s = head.snapshot()?;
    let mut out = Vec::new();
    for (id, c) in &s.controllers {
        let steward = !s.adopted && s.stewards.contains(id) && id != &s.root && id != &s.recovery;
        if steward && !options.include_stewards {
            continue;
        }
        let mut key_v = Map::new();
        key_v.insert("signing".into(), json!(encode_base64(c.key().signing())));
        match c.key().webauthn() {
            Some(w) => {
                let origins = options.authority_origins.get(id).cloned();
                // Validates the origins under the general rule.
                WebAuthnKey::new(
                    w.rp().to_string(),
                    w.credential().to_vec(),
                    None,
                    origins.clone(),
                )?;
                key_v.insert("form".into(), json!("webauthn"));
                key_v.insert("rp".into(), json!(w.rp()));
                key_v.insert("credential".into(), json!(encode_base64(w.credential())));
                if let Some(o) = origins {
                    key_v.insert("authorityOrigins".into(), json!(o));
                }
            }
            None => {
                key_v.insert("form".into(), json!("raw"));
                if let Some(a) = options.agreements.get(id).or_else(|| agreements.get(id)) {
                    KeyDescriptor::new_raw(c.key().signing().to_vec(), Some(a.clone()))?;
                    key_v.insert("agreement".into(), json!(encode_base64(a)));
                }
            }
        }
        let roles: Vec<&str> = c.roles().iter().filter_map(role_name).collect();
        require(
            roles.len() == c.roles().len(),
            "a predecessor controller holds a role with no 0.5 form",
        )?;
        let mut v = Map::new();
        v.insert("key".into(), Value::Object(key_v));
        v.insert("label".into(), json!(c.label()));
        v.insert("roles".into(), json!(roles));
        if c.verification() {
            v.insert("verification".into(), json!(true));
        }
        out.push(Value::Object(v));
    }
    out.sort_by_key(|v| {
        v["key"]["signing"]
            .as_str()
            .and_then(|s| decode_base64(s, 65).ok())
            .map(|p| key_id(&p))
            .unwrap_or_default()
    });
    Ok(out)
}

/// Agreement points the predecessor shows, by the ID of the signing key they pair with.
fn known_agreements(h: &swift::History) -> BTreeMap<String, Vec<u8>> {
    fn pair(v: &Value, out: &mut BTreeMap<String, Vec<u8>>) {
        if let (Some(s), Some(a)) = (b64_of(v, "signing"), b64_of(v, "agreement")) {
            out.insert(key_id(&s), a);
        }
    }
    fn slot(v: &Value, out: &mut BTreeMap<String, Vec<u8>>, depth: usize) {
        if depth > 2 {
            return;
        }
        if let Some(r) = v.get("recipient") {
            pair(r, out);
        }
        for p in v
            .get("parts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            slot(p, out, depth + 1);
        }
    }
    let mut out = BTreeMap::new();
    for e in &h.entries {
        let v = &e.value;
        for f in ["root", "recovery"] {
            if let Some(x) = v.get(f) {
                pair(x, &mut out);
            }
        }
        for x in v
            .get("stewards")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            pair(x, &mut out);
        }
        for x in v
            .get("slots")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            slot(x, &mut out, 0);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The successor genesis.

/// Inputs of [`prepare_swift_genesis`].
#[derive(Clone, Debug)]
pub struct SwiftGenesisParams {
    /// 1–200 bytes.
    pub label: String,
    /// Declared namespaces: sorted, distinct.
    pub namespaces: Vec<String>,
    /// The new keyring (§6.2) with its slots built: the carried controllers
    /// ([`swift_carried_controllers`]) and any others, `addThreshold`, `countBy`, `policy`.
    pub keyring: Value,
    /// `issued`, in ms: not earlier than `head`'s `issued`.
    pub issued_ms: i64,
    /// Every entry of the Swift predecessor the host holds: the last is `head`.
    pub predecessor: Vec<Vec<u8>>,
    /// The genesis's signers, controllers of the new keyring: the first is `by`. They meet the
    /// control rule over the new keyring.
    pub signers: Vec<String>,
    /// The predecessor's controller IDs whose `handover` signature the host can obtain. They must
    /// meet the rule that may write F at `head` (§15.1 step 1); every further key offered raises
    /// the number of keys a veto needs.
    pub handover: Vec<String>,
}

/// Exact signing work for a successor genesis, and what finishing it needs.
#[derive(Debug)]
pub struct PendingSuccession {
    steps: Vec<SigningStep>,
    body: Vec<u8>,
    predecessor: Vec<Vec<u8>>,
    now_ms: i64,
    swift: bool,
    held_ok: bool,
}

impl PendingSuccession {
    /// The signing work, read-only, in the order the signatures must come back: the primary, the
    /// cosignatures, the possession proofs, then the `handover` signatures.
    pub fn steps(&self) -> &[SigningStep] {
        &self.steps
    }
    /// The successor account's ID: the digest of the genesis body.
    pub fn account(&self) -> AccountId {
        AccountId::of_genesis(&self.body)
    }
    /// Assemble the genesis envelope from `signatures` (one per step, in order) and verify it
    /// with the history verifier over the predecessor. Returns the envelope only when the genesis
    /// is `ok`; for a Swift predecessor, also only when its `handover` meets the rule that may
    /// write F at `head`, so that the succession can be verified later.
    pub fn finish(self, signatures: Vec<SignatureResult>) -> Result<Records> {
        require(
            signatures.len() == self.steps.len(),
            "one signature per step",
        )?;
        let mut primary = None;
        let (mut cos, mut adds, mut hand) = (Vec::new(), Vec::new(), Vec::new());
        for (st, sig) in self.steps.iter().zip(signatures) {
            if sig.assertion.is_some() != st.challenge().is_some() {
                return Err(bad_signature(
                    "an assertion is present if and only if the signer is webauthn",
                ));
            }
            let s = Signature {
                signer: st.signer().to_string(),
                signature: sig.signature,
                assertion: sig.assertion,
            };
            match st.role() {
                StepRole::Primary => primary = Some(s),
                StepRole::Cosignature => cos.push(s),
                StepRole::Possession => adds.push(s),
                StepRole::Handover => hand.push(s),
            }
        }
        let env = envelope(&self.body, primary.as_ref(), &cos, &adds, &hand)?;
        let objects = Objects {
            entries: vec![env.clone()],
            predecessor: self.predecessor.clone(),
            ..Objects::default()
        };
        let verdict = verify_history(&objects, &Persisted::default(), self.now_ms);
        // A genesis that leans on the carried-key exemption of a `/5` predecessor is held until F
        // is final (§8.4, revision 12). That, and only that, is accepted for such a genesis: the
        // objects must then verify as soon as the predecessor's F is final, which the verifier
        // decides.
        if self.held_ok {
            if let Some(Stop::Held { why, .. }) = &verdict.stop {
                require(
                    why.contains("possession proof missing") && verdict.state.is_none(),
                    "the genesis is held for a reason other than a carried key's proof",
                )?;
                return Ok(Records {
                    entries: vec![(1, env)],
                    ..Records::default()
                });
            }
        }
        stop_error(&verdict.stop)?;
        let state = verdict
            .state
            .ok_or_else(|| malformed("the genesis does not verify"))?;
        require(
            verdict.branch.len() == 1 && verdict.branch[0] == digest(&self.body),
            "the genesis is not the head of the verified branch",
        )?;
        let status = succession_status(&state)
            .ok_or_else(|| malformed("the verified genesis claims no predecessor"))?;
        if self.swift {
            require(
                status.authorized,
                "handover does not meet the rule that may write F",
            )?;
        }
        Ok(Records {
            entries: vec![(1, env)],
            ..Records::default()
        })
    }
}

fn new_genesis_steps(
    k: &Keyring,
    body: &[u8],
    signers: &[String],
    proofs: &dyn Fn(&str, &Controller) -> bool,
) -> Vec<SigningStep> {
    let path = "authority/00000001.json";
    let by = &signers[0];
    let mut steps = vec![step(
        path,
        body,
        &k.controllers[by],
        StepRole::Primary,
        AuthorityRule::Control,
    )];
    for s in &signers[1..] {
        steps.push(step(
            path,
            body,
            &k.controllers[s],
            StepRole::Cosignature,
            AuthorityRule::Control,
        ));
    }
    for (id, c) in &k.controllers {
        if id != by && proofs(id, c) {
            steps.push(step(
                path,
                body,
                c,
                StepRole::Possession,
                AuthorityRule::Possession,
            ));
        }
    }
    steps
}

fn check_new_keyring(keyring: &Value, signers: &[String]) -> Result<Keyring> {
    let k = Keyring::parse(keyring.clone(), 1)?;
    validate_slots(&k.controllers, &k.slots, 1)?;
    require(!signers.is_empty(), "genesis needs a signer")?;
    let distinct: BTreeSet<&String> = signers.iter().collect();
    require(distinct.len() == signers.len(), "a signer appears twice")?;
    require(
        signers.iter().all(|s| k.controllers.contains_key(s)),
        "a genesis signer is not a controller of its keyring",
    )?;
    if !control_rule(&k, signers, k.threshold) {
        return Err(bad_signature(
            "genesis: control rule not met by these signers",
        ));
    }
    Ok(k)
}

/// Prepare the successor genesis for a Swift predecessor (§15.1, §16.2, §16.3).
///
/// Refused here, with the reason: a predecessor that does not verify as a Swift history; a
/// genesis `issued` before `head`'s; a slotted predecessor controller that the new keyring does
/// not carry with a rebuilt slot; a `handover` key that is not a controller current at `head` or
/// that the new keyring describes as another key; and a `handover` that does not meet the rule
/// that may write F (it would never verify). Possession proofs are asked of every new controller
/// except the primary signer and the controllers carried over (§8.4 "Possession": exempt because
/// the handover meets the rule).
pub fn prepare_swift_genesis(p: &SwiftGenesisParams, now_ms: i64) -> Result<PendingSuccession> {
    super::check_issued(p.issued_ms)?;
    let head = SwiftHead::read(&p.predecessor)?;
    let snap = head.snapshot()?;
    require(
        p.issued_ms >= head.issued_ms,
        "genesis issued before the predecessor's head",
    )?;
    let k = check_new_keyring(&p.keyring, &p.signers)?;
    // Slots (§15.3, §16.2): every slotted controller is carried and has a new slot.
    let new_slotted: BTreeSet<String> = k.slots.iter().flat_map(Keyring::slot_ids).collect();
    for id in slotted(snap) {
        let carried = k
            .controllers
            .get(&id)
            .zip(snap.controllers.get(&id))
            .is_some_and(|(new, old)| same_swift_key(old, new));
        require(
            carried && new_slotted.contains(&id),
            "a controller that had a slot is not carried with a rebuilt slot",
        )?;
    }
    // Handover.
    let distinct: BTreeSet<&String> = p.handover.iter().collect();
    require(
        distinct.len() == p.handover.len(),
        "a handover key appears twice",
    )?;
    let mut hand_ctl: Vec<Controller> = Vec::new();
    for id in &p.handover {
        let old = snap.controllers.get(id).ok_or_else(|| {
            bad_signature("a handover key is not a controller of the predecessor at head")
        })?;
        hand_ctl.push(match k.controllers.get(id) {
            Some(new) if same_swift_key(old, new) => new.clone(),
            Some(_) => {
                return Err(bad_signature(
                    "a handover key is described differently in the new keyring",
                ))
            }
            None => old.clone(),
        });
    }
    let ids: BTreeSet<String> = p.handover.iter().cloned().collect();
    if !handover_authorized(snap, &k, &ids) {
        return Err(bad_signature(
            "handover does not meet the rule that may write F at head",
        ));
    }
    let body = Kind::Genesis {
        label: p.label.clone(),
        namespaces: p.namespaces.clone(),
        keyring: p.keyring.clone(),
        predecessor: Some(head.claim()),
    }
    .body(&Header {
        seq: 1,
        previous: None,
        issued: format_date(p.issued_ms),
        by: p.signers[0].clone(),
    })?;
    let carried = |id: &str, c: &Controller| {
        snap.controllers
            .get(id)
            .is_some_and(|old| same_swift_key(old, c))
    };
    let mut steps = new_genesis_steps(&k, &body, &p.signers, &|id, c| !carried(id, c));
    for c in &hand_ctl {
        steps.push(step_with_uv(
            "authority/00000001.json",
            &body,
            c,
            StepRole::Handover,
            AuthorityRule::Handover.requires_uv(),
        ));
    }
    Ok(PendingSuccession {
        steps,
        body,
        predecessor: p.predecessor.clone(),
        now_ms,
        swift: true,
        held_ok: false,
    })
}

/// Inputs of [`prepare_authority5_genesis`].
#[derive(Clone, Debug)]
pub struct Authority5GenesisParams {
    /// 1–200 bytes.
    pub label: String,
    /// Declared namespaces: sorted, distinct.
    pub namespaces: Vec<String>,
    /// The new keyring, slots built.
    pub keyring: Value,
    /// `issued`, in ms.
    pub issued_ms: i64,
    /// The predecessor's objects (its entries, and the entries of its own predecessors in
    /// `predecessor`). They must verify with no stop; `head` is their last entry.
    pub predecessor: Objects,
    /// The genesis's signers: the first is `by`; they meet the control rule over the new keyring.
    pub signers: Vec<String>,
    /// Leave out the possession proof of every controller that is also a current controller of
    /// the predecessor (§8.4 "Possession": exempt once F is final). The genesis is then **held**
    /// by every verifier until F is final (revision 12), and `finish` accepts that, and only
    /// that, as its result. When false, every controller gives a proof and the genesis verifies
    /// at once.
    pub omit_carried_proofs: bool,
}

/// Prepare the successor genesis for a native `/5` predecessor (§15.1). It carries no
/// `handover`: the waiting and vetoing happen in the predecessor. The genesis names the
/// predecessor's current head, which F must follow directly, so the predecessor must not append
/// another entry before F.
pub fn prepare_authority5_genesis(
    p: &Authority5GenesisParams,
    now_ms: i64,
) -> Result<PendingSuccession> {
    super::check_issued(p.issued_ms)?;
    let state = head_state(&p.predecessor, now_ms)?;
    let k = check_new_keyring(&p.keyring, &p.signers)?;
    let n = state.history().len() as u64;
    let last = state
        .history()
        .last()
        .cloned()
        .ok_or_else(|| malformed("the predecessor holds no entry"))?;
    let claim = json!({"format": AUTHORITY5_FORMAT, "account": state.account().as_str(),
                       "head": {"seq": n, "digest": last}});
    let body = Kind::Genesis {
        label: p.label.clone(),
        namespaces: p.namespaces.clone(),
        keyring: p.keyring.clone(),
        predecessor: Some(claim),
    }
    .body(&Header {
        seq: 1,
        previous: None,
        issued: format_date(p.issued_ms),
        by: p.signers[0].clone(),
    })?;
    let carried = |id: &str, c: &Controller| {
        p.omit_carried_proofs
            && state
                .keyring()
                .controllers
                .get(id)
                .is_some_and(|old| old.key() == c.key())
    };
    let steps = new_genesis_steps(&k, &body, &p.signers, &|id, c| !carried(id, c));
    let held_ok = p.omit_carried_proofs
        && k.controllers
            .iter()
            .any(|(id, c)| id != &p.signers[0] && carried(id, c));
    // The set a verifier is given: the predecessor's entries and its own predecessors'.
    let mut set = p.predecessor.entries.clone();
    set.extend(p.predecessor.predecessor.iter().cloned());
    Ok(PendingSuccession {
        steps,
        body,
        predecessor: set,
        now_ms,
        swift: false,
        held_ok,
    })
}

/// The `successor` transition (§8.7) on a `/5` predecessor, for the successor genesis `genesis`
/// (its envelope): the account it names is the digest of that genesis's body, the genesis must
/// name this predecessor and its current head, and the transition is signed under the control
/// rule. Its activation, after the due time, is F (`prepare_activate`); then `prepare_final`.
pub fn prepare_successor_transition(
    objects: &Objects,
    now_ms: i64,
    genesis: &[u8],
    issued_ms: i64,
    signers: Vec<String>,
) -> Result<PendingBatch> {
    let env = crate::v05::history::envelope::AuthEnvelope::parse(
        genesis,
        bounds::AUTHORITY_BODY,
        bounds::AUTHORITY_BODY.saturating_mul(2),
        false,
    )?;
    let state = head_state(objects, now_ms)?;
    let claim = &env.value["predecessor"];
    require(
        env.value["kind"] == "genesis"
            && claim["format"] == AUTHORITY5_FORMAT
            && claim["account"] == state.account().as_str()
            && claim["head"]["seq"].as_u64() == Some(state.history().len() as u64)
            && state.history().last().map(String::as_str) == claim["head"]["digest"].as_str(),
        "the genesis does not name this account's current head as its predecessor",
    )?;
    super::authority::prepare_transition(
        objects,
        now_ms,
        &TransitionParams {
            anchor: None,
            issued_ms,
            signers,
            rule: TransitionRule::Control,
            change: json!({"successor": {"account": AccountId::of_genesis(&env.body).as_str()}}),
        },
    )
}

// ---------------------------------------------------------------------------------------------
// F on a Swift predecessor.

/// Inputs of [`prepare_swift_freeze`].
#[derive(Clone, Debug)]
pub struct SwiftFreezeParams {
    /// Every entry of the Swift predecessor the host holds.
    pub predecessor: Vec<Vec<u8>>,
    /// The successor's objects: its entries, the receipts and heads held (`pending`, `heads`).
    /// The `predecessor` field is replaced by `predecessor` above.
    pub successor: Objects,
    /// `issued` of F, in ms: a whole second, after the due time.
    pub issued_ms: i64,
    /// The predecessor controllers that sign: the first is the primary. For a root library, the
    /// root alone; for a keyring library, `control` signers, at least `threshold`.
    pub signers: Vec<String>,
}

/// Exact signing work for F, and what finishing it needs.
#[derive(Debug)]
pub struct PendingFreeze {
    steps: Vec<SigningStep>,
    body: Vec<u8>,
    predecessor: Vec<Vec<u8>>,
    successor: Objects,
    account: String,
    seq: u64,
    now_ms: i64,
}

/// The finished F.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frozen {
    /// F's Swift-format record bytes: the exact bytes the host writes to the predecessor's
    /// `authority/<seq>.json` through the Swift code.
    pub entry: Vec<u8>,
    /// F's seq: `head.seq + 1`.
    pub seq: u64,
    /// With F and the held heads, the succession verifies (§15.1 "Verified"). It need not yet:
    /// the fresh heads of the successor's homes may not exist before F is written.
    pub succession_verified: bool,
}

/// Prepare F (§15.1 step 5, §16.3): a Swift `layout` entry that follows `head`, names the
/// successor account and carries a layout above the predecessor's and above 2.
///
/// Refused: a successor that holds no genesis naming this predecessor and its last entry; one
/// whose handover does not meet the F rule, that is vetoed, whose window has not opened, or whose
/// genesis `headQuorum` homes have not receipted; a time before the due time (`now_ms` and
/// `issued_ms`); an `issued_ms` that is not a whole second (the Swift encoder writes none); signers
/// below the Swift rule for `layout` (root alone before a keyring is adopted; `control` signers,
/// at least `threshold`, after).
pub fn prepare_swift_freeze(p: &SwiftFreezeParams, now_ms: i64) -> Result<PendingFreeze> {
    super::check_issued(p.issued_ms)?;
    require(
        p.issued_ms % 1000 == 0,
        "the Swift date format has no fractions: issued must be a whole second",
    )?;
    let head = SwiftHead::read(&p.predecessor)?;
    let snap = head.snapshot()?;
    let mut objects = p.successor.clone();
    objects.predecessor = p.predecessor.clone();
    let state = state_of(&objects, now_ms)?;
    let status = succession_status(&state)
        .ok_or_else(|| malformed("the successor holds no genesis with a predecessor"))?;
    require(
        status.format == SWIFT_FORMAT
            && status.predecessor == head.history.account
            && status.head_seq == head.seq
            && status.head_digest == head.digest,
        "the successor's genesis does not name this predecessor and its last entry as head",
    )?;
    require(!status.vetoed, "the succession is vetoed")?;
    // A veto the home holds but has not recorded still vetoes (§15.1 step 4, §15.3 step 4:
    // F only after the succession is due and unvetoed): refuse when the recording entry would
    // be accepted for any held veto.
    for held in &objects.pending {
        let Ok(env) = crate::v05::history::envelope::AuthEnvelope::parse(
            held,
            bounds::VETO_BODY,
            bounds::VETO_ENVELOPE,
            true,
        ) else {
            continue;
        };
        if env.value.get("protocol").and_then(Value::as_str) != Some("colophon/veto/5")
            || env.value.get("transition").and_then(Value::as_str)
                != Some(status.genesis_digest.as_str())
        {
            continue;
        }
        if prepare_succession_vetoed(&objects, now_ms, &env.digest)
            .and_then(|b| b.finish(vec![]))
            .is_ok()
        {
            return Err(Failure::Malformed(
                "the succession is vetoed: a valid veto is held and not yet recorded".into(),
            ));
        }
    }
    require(
        status.authorized,
        "the genesis's handover does not meet the rule that may write F",
    )?;
    let t = status
        .timing
        .as_ref()
        .ok_or_else(|| unavailable("the succession window has not opened"))?;
    if now_ms < t.due_ms || p.issued_ms <= t.due_ms {
        return Err(unavailable(
            "F is written only after the succession's due time",
        ));
    }
    choose_succession_receipts(
        &state,
        &objects.pending,
        &status.genesis_digest,
        t.window_start_ms,
        i64::MAX,
    )?;
    let layout = snap.layout.saturating_add(1).max(3);
    let ids: BTreeSet<String> = p.signers.iter().cloned().collect();
    require(
        !p.signers.is_empty() && ids.len() == p.signers.len(),
        "at least one signer, each once",
    )?;
    for id in &p.signers {
        require(
            snap.controllers.contains_key(id),
            "a signer is not a controller of the predecessor at head",
        )?;
    }
    require(
        p.issued_ms >= head.issued_ms,
        "F issued before the predecessor's head",
    )?;
    let mut body = Map::new();
    body.insert("issued".into(), json!(format_date(p.issued_ms)));
    body.insert("kind".into(), json!("layout"));
    body.insert("layout".into(), json!(layout));
    body.insert("previous".into(), json!(head.digest));
    body.insert("seq".into(), json!(head.seq + 1));
    body.insert("successor".into(), json!(state.account().as_str()));
    if snap.adopted {
        if !layout_signers_meet_rule(snap, &ids) {
            return Err(bad_signature(
                "the Swift layout rule is not met by these signers",
            ));
        }
        body.insert("by".into(), json!("controller"));
        body.insert("signer".into(), json!(p.signers[0]));
    } else {
        if p.signers != [snap.root.clone()] {
            return Err(bad_signature(
                "a root library's F is signed by the current root alone",
            ));
        }
        body.insert("by".into(), json!("root"));
    }
    let body = canonical(&Value::Object(body))?;
    let path = format!("authority/{:08}.json", head.seq + 1);
    let uv = snap.adopted;
    let steps = p
        .signers
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let c = &snap.controllers[id];
            SigningStep::new(
                path.clone(),
                body.clone(),
                id.clone(),
                if i == 0 {
                    StepRole::Primary
                } else {
                    StepRole::Cosignature
                },
                c.key().clone(),
                uv || c.verification(),
            )
        })
        .collect();
    Ok(PendingFreeze {
        steps,
        body,
        predecessor: p.predecessor.clone(),
        successor: p.successor.clone(),
        account: state.account().as_str().to_string(),
        seq: head.seq + 1,
        now_ms,
    })
}

impl PendingFreeze {
    /// The signing work, read-only.
    pub fn steps(&self) -> &[SigningStep] {
        &self.steps
    }
    /// Assemble F's record from `signatures` and verify it: the Swift verifier over the
    /// predecessor plus F (the rule for `layout`, UV, `layout` increasing), F's `successor` and
    /// kind, and the history verifier over the successor. Nothing is returned on failure.
    pub fn finish(self, signatures: Vec<SignatureResult>) -> Result<Frozen> {
        require(
            signatures.len() == self.steps.len(),
            "one signature per step",
        )?;
        let (mut primary, mut cos) = (None, Vec::new());
        for (st, sig) in self.steps.iter().zip(signatures) {
            if sig.assertion.is_some() != st.challenge().is_some() {
                return Err(bad_signature(
                    "an assertion is present if and only if the signer is webauthn",
                ));
            }
            let s = Signature {
                signer: st.signer().to_string(),
                signature: sig.signature,
                assertion: sig.assertion,
            };
            match st.role() {
                StepRole::Primary => primary = Some(s),
                _ => cos.push(s),
            }
        }
        // Swift cosignatures are distinct controllers; the record has no `additions`.
        let entry = envelope(&self.body, primary.as_ref(), &cos, &[], &[])?;
        let mut all = self.predecessor.clone();
        all.push(entry.clone());
        let h = swift::verify(&all)?;
        let f = h
            .entries
            .last()
            .ok_or_else(|| malformed("F is not an entry"))?;
        require(
            h.entries.len() as u64 == self.seq
                && f.digest == digest(&self.body)
                && f.value["kind"] == "layout"
                && f.value["layout"].as_u64().is_some_and(|n| n > 2)
                && f.value["successor"] == self.account.as_str(),
            "F is not a freezing layout entry naming the successor",
        )?;
        let mut objects = self.successor.clone();
        objects.predecessor = all;
        let verdict = verify_history(&objects, &Persisted::default(), self.now_ms);
        match &verdict.stop {
            None | Some(Stop::Failed { .. }) => {}
            other => stop_error(other)?,
        }
        let verified = verdict
            .state
            .as_ref()
            .and_then(succession_status)
            .is_some_and(|s| s.verified.is_some());
        Ok(Frozen {
            entry,
            seq: self.seq,
            succession_verified: verified,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// A vetoed succession.

/// The `successionVetoed` entry (§15.1 step 4) for a successor home that holds a valid veto: the
/// veto (a `colophon/veto/5` object whose `transition` is the genesis body digest) among the
/// held `pending` objects, its receipts and the genesis's receipts chosen as §15.1 says, `by`
/// the veto's, `issued` the later of the latest chosen veto receipt and the preceding entry's.
/// Whether each signer is an eligible key under its predecessor descriptor, and the veto's count,
/// deadline and receipts, is judged by the verifier at `finish`.
pub fn prepare_succession_vetoed(
    objects: &Objects,
    now_ms: i64,
    veto_digest: &str,
) -> Result<PendingBatch> {
    let state = state_of(objects, now_ms)?;
    let status =
        succession_status(&state).ok_or_else(|| malformed("this account has no predecessor"))?;
    let t = status
        .timing
        .as_ref()
        .ok_or_else(|| unavailable("the succession window has not opened"))?;
    let v_bytes = find_pending(objects, veto_digest, "colophon/veto/5")?.clone();
    let v = crate::v05::history::envelope::AuthEnvelope::parse(
        &v_bytes,
        bounds::VETO_BODY,
        bounds::VETO_ENVELOPE,
        true,
    )?;
    let v_issued = v.value["issued"]
        .as_str()
        .and_then(parse_date)
        .ok_or_else(|| malformed("veto issued"))?;
    let by = v.value["by"]
        .as_str()
        .ok_or_else(|| malformed("veto by"))?
        .to_string();
    let genesis_receipts = choose_succession_receipts(
        &state,
        &objects.pending,
        &status.genesis_digest,
        t.window_start_ms,
        i64::MAX,
    )?;
    let receipts = choose_succession_receipts(
        &state,
        &objects.pending,
        &v.digest,
        v_issued,
        t.veto_deadline_ms,
    )?;
    let mut latest = v_issued;
    for r in &receipts {
        let e = crate::v05::signature::RawEnvelope::parse(r, bounds::RECEIPT_BODY, false)?;
        let at = e.value["received"]
            .as_str()
            .and_then(parse_date)
            .ok_or_else(|| malformed("receipt received"))?;
        latest = latest.max(at);
    }
    let issued = latest.max(state.last_issued_ms());
    recording_batch(
        objects,
        &state,
        now_ms,
        Kind::SuccessionVetoed {
            veto: v_bytes,
            receipts,
            genesis_receipts,
        },
        issued,
        &by,
    )
}

// ---------------------------------------------------------------------------------------------
// The migration entry (§15.4).

/// One namespace of a `migration` (§15.4).
#[derive(Clone, Debug)]
pub struct MigratedNamespace {
    /// The namespace.
    pub namespace: String,
    /// How many records the predecessor holds in it.
    pub source: u64,
    /// The body digests (lowercase hex) of the destination records copied into the namespace.
    /// `copied` is their number and `view` their digest.
    pub copied: Vec<String>,
    /// How many source records were not copied.
    pub omitted: u64,
}

/// A predecessor member's fate in a `migration`.
#[derive(Clone, Debug)]
pub struct MigratedMember {
    /// The member ID.
    pub id: String,
    /// The label the new account shows (1–200 bytes).
    pub label: String,
    /// The mapped kind: `device`, `app`, `agent` or `server`.
    pub kind: String,
    /// `None` is `rejoin`; `Some(reason)` is `dropped`.
    pub dropped: Option<String>,
}

/// Inputs of [`prepare_migration`].
#[derive(Clone, Debug)]
pub struct MigrationParams {
    /// Every entry of the Swift predecessor, F included.
    pub predecessor: Vec<Vec<u8>>,
    /// The drain window (§15.3).
    pub drain_from_ms: i64,
    /// The end of the drain window: at most 30 days after the start.
    pub drain_until_ms: i64,
    /// Every predecessor namespace.
    pub namespaces: Vec<MigratedNamespace>,
    /// Up to 4,096 source records not copied: `(body digest, reason)`.
    pub omitted: Vec<(String, String)>,
    /// Every predecessor member with its mapped kind and outcome.
    pub members: Vec<MigratedMember>,
    /// The transition's `issued`, in ms: not before the end of the drain window.
    pub issued_ms: i64,
    /// The signers under the control rule.
    pub signers: Vec<String>,
}

/// The view digest of §15.4: SHA-256 of the sorted, newline-joined lowercase hex body digests of
/// the destination records copied into the namespace.
pub fn view_digest(copied: &[String]) -> Result<String> {
    let mut v: Vec<&str> = copied.iter().map(String::as_str).collect();
    for d in &v {
        require(
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "a copied record digest is 64 lowercase hex characters",
        )?;
    }
    v.sort_unstable();
    Ok(digest(v.join("\n").as_bytes()))
}

/// The Swift member role to the kind of a 0.5 request (§16.2).
pub fn map_swift_role(role: &str) -> Option<&'static str> {
    match role {
        "device" => Some("device"),
        "app" | "web" => Some("app"),
        "agent" => Some("agent"),
        "service" => Some("server"),
        _ => None,
    }
}

/// Prepare the `migration` transition (§15.4, §16.2) on the successor. `controllers` is derived
/// here from the predecessor's controllers at `head` and the new account's slots; the namespaces
/// and members the host lists must be exactly the predecessor's (every namespace its grants and
/// shared keys name; every member current at `head`), with the kind each Swift role maps to.
/// Refused: a member with a `budget` caveat that is not dropped (no 0.5 form); a member whose
/// grant has no role (the kind is then not decided by the spec; reported as a question); more than
/// 4,096 omitted; counts that do not add up; a time before the drain window's end.
pub fn prepare_migration(
    objects: &Objects,
    now_ms: i64,
    p: &MigrationParams,
) -> Result<PendingBatch> {
    let all = swift::verify(&p.predecessor)?;
    let held = Objects {
        predecessor: p.predecessor.clone(),
        ..objects.clone()
    };
    let state = state_of(&held, now_ms)?;
    let status =
        succession_status(&state).ok_or_else(|| malformed("migration needs a predecessor"))?;
    require(
        status.format == SWIFT_FORMAT,
        "migration here is for a Swift predecessor",
    )?;
    let (f_seq, f_digest) = status
        .verified
        .clone()
        .ok_or_else(|| unavailable("migration needs a verified succession"))?;
    let at_f = usize::try_from(f_seq)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| all.entries.get(i))
        .ok_or_else(|| malformed("the predecessor does not hold F"))?;
    require(at_f.digest == f_digest, "the predecessor does not hold F")?;
    let head_idx = usize::try_from(status.head_seq)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| malformed("predecessor head"))?;
    let head = all
        .states
        .get(head_idx)
        .ok_or_else(|| malformed("predecessor head"))?;
    super::check_issued(p.drain_from_ms)?;
    super::check_issued(p.drain_until_ms)?;
    super::check_issued(p.issued_ms)?;
    require(
        p.drain_until_ms >= p.drain_from_ms
            && p.drain_until_ms.saturating_sub(p.drain_from_ms) <= 2_592_000_000,
        "the drain window is 0 to 30 days",
    )?;
    require(
        p.drain_from_ms >= at_f.issued_ms,
        "the drain window starts after F (§15.4: the migration follows F)",
    )?;
    require(
        p.issued_ms >= p.drain_until_ms && now_ms >= p.drain_until_ms,
        "the migration is written after the drain window",
    )?;
    require(
        p.omitted.len() <= 4096,
        "more than 4,096 omitted records: stop",
    )?;
    // Namespaces: exactly the predecessor's.
    let mut source_ns = BTreeSet::new();
    for e in all.entries.iter().take(head_idx + 1) {
        match e.value["kind"].as_str() {
            Some("grant") => {
                for n in e.value["namespaces"].as_array().into_iter().flatten() {
                    if let Some(n) = n.as_str() {
                        source_ns.insert(n.to_string());
                    }
                }
            }
            Some("shareKey") => {
                if let Some(n) = e.value["namespace"].as_str() {
                    source_ns.insert(n.to_string());
                }
            }
            _ => {}
        }
    }
    let listed: BTreeSet<String> = p.namespaces.iter().map(|n| n.namespace.clone()).collect();
    require(
        listed.len() == p.namespaces.len() && listed == source_ns,
        "the migration must list exactly the predecessor's namespaces",
    )?;
    let mut namespaces = Vec::new();
    for n in &p.namespaces {
        require(
            (n.copied.len() as u64).checked_add(n.omitted) == Some(n.source),
            "copied and omitted must add up to source",
        )?;
        namespaces.push(json!({"namespace": n.namespace, "source": n.source,
            "copied": n.copied.len() as u64, "omitted": n.omitted, "view": view_digest(&n.copied)?}));
    }
    namespaces.sort_by(|a, b| a["namespace"].as_str().cmp(&b["namespace"].as_str()));
    // Controllers: every predecessor controller at head, with whether it has a slot here.
    let new_slotted: BTreeSet<String> = state
        .keyring()
        .slots
        .iter()
        .flat_map(Keyring::slot_ids)
        .collect();
    let controllers: Vec<Value> = head
        .controllers
        .keys()
        .map(|id| json!({"id": id, "slot": new_slotted.contains(id)}))
        .collect();
    // Members: those current at head.
    let mut current: BTreeMap<String, &Value> = BTreeMap::new();
    for e in all.entries.iter().take(head_idx + 1) {
        match e.value["kind"].as_str() {
            Some("grant") => {
                if let Some(id) = e.value["member"]
                    .get("signing")
                    .and_then(Value::as_str)
                    .and_then(|s| decode_base64(s, 65).ok())
                    .map(|p| key_id(&p))
                {
                    current.insert(id, &e.value);
                }
            }
            Some("revoke") => {
                if let Some(id) = e.value["memberID"].as_str() {
                    current.remove(id);
                }
            }
            _ => {}
        }
    }
    let listed: BTreeSet<&String> = p.members.iter().map(|m| &m.id).collect();
    require(
        listed.len() == p.members.len()
            && listed.len() == current.len()
            && listed.iter().all(|i| current.contains_key(*i)),
        "the migration must list exactly the predecessor's current members",
    )?;
    let mut members = Vec::new();
    for m in &p.members {
        let grant = current[&m.id];
        require(
            (1..=200).contains(&m.label.len()),
            "a member label is 1-200 bytes",
        )?;
        let role = grant["role"].as_str().ok_or_else(|| {
            malformed("a predecessor grant has no role: its kind is not decided by the spec")
        })?;
        require(
            map_swift_role(role) == Some(m.kind.as_str()),
            "a member's kind is not the one its Swift role maps to",
        )?;
        let budget = grant["caveats"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c.get("budget").is_some() || c["kind"] == "budget");
        require(
            !budget || m.dropped.is_some(),
            "a member with a budget caveat has no 0.5 form: drop it or stop",
        )?;
        let mut o = json!({"id": m.id, "label": m.label, "kind": m.kind});
        match &m.dropped {
            None => o["outcome"] = json!("rejoin"),
            Some(why) => {
                require(!why.is_empty(), "a dropped member needs a reason")?;
                o["outcome"] = json!("dropped");
                o["reason"] = json!(why);
            }
        }
        members.push(o);
    }
    members.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let omitted: Vec<Value> = p
        .omitted
        .iter()
        .map(|(d, r)| json!({"ref": d, "reason": r}))
        .collect();
    let change = json!({"migration": {
        "predecessor": {"format": status.format, "account": status.predecessor,
                        "final": {"seq": f_seq, "digest": f_digest}},
        "drain": {"from": format_date(p.drain_from_ms), "until": format_date(p.drain_until_ms)},
        "namespaces": namespaces,
        "omitted": omitted,
        "controllers": controllers,
        "members": members,
    }});
    super::authority::prepare_transition(
        &held,
        now_ms,
        &TransitionParams {
            anchor: None,
            issued_ms: p.issued_ms,
            signers: p.signers.clone(),
            rule: TransitionRule::Control,
            change,
        },
    )
}
