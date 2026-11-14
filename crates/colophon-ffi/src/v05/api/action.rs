//! A prepared action: what the host signs, held by the core until it is finished.
//!
//! The host reads copies of the exact bodies and signs them. It cannot alter what is held:
//! finishing takes the signatures only, and the core assembles the bytes from its own retained
//! state and verifies them under the history verifier before anything changes.
use super::fault::AccountError;
use super::json::*;
use super::{guard, lock};
use colophon_core::v05::account::{
    Account, AddController, AddMode, CallTarget, Change, KeyringEdit, PendingAction, RevokeKeep,
    SignerChoice,
};
use colophon_core::v05::records::Level;
use colophon_core::v05::slots::{PrfAssertion, PrfRequest, PrfResult, SlotPlan};
use colophon_core::v05::vault::PrfOutput;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::{SignatureResult, SigningStep, StepRole};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

type R<T> = Result<T, AccountError>;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
/// A process-unique number for an engine or account object, so an action finished on another
/// object than the one that prepared it is refused.
pub(crate) fn next_owner() -> u64 {
    NEXT_OWNER.fetch_add(1, Ordering::Relaxed)
}

pub(crate) struct ActState {
    pub pending: Option<PendingAction>,
    pub denial: Option<Value>,
    pub owner: u64,
    pub kind: String,
}

/// A prepared action. One-shot: finishing (or a failed finish) consumes it.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountAction {
    pub(crate) st: Mutex<ActState>,
}

impl AccountAction {
    pub(crate) fn ready(pending: PendingAction, owner: u64, kind: &str) -> Self {
        Self {
            st: Mutex::new(ActState {
                pending: Some(pending),
                denial: None,
                owner,
                kind: kind.into(),
            }),
        }
    }
    pub(crate) fn denied(d: colophon_core::model::Denial, owner: u64, kind: &str) -> Self {
        Self {
            st: Mutex::new(ActState {
                pending: None,
                denial: Some(json!({"reason": d.reason, "detail": d.detail})),
                owner,
                kind: kind.into(),
            }),
        }
    }
    /// Take the pending action out for finishing, checking it belongs to `owner`.
    pub(crate) fn take(&self, owner: u64) -> R<PendingAction> {
        let mut s = lock(&self.st)?;
        if s.owner != owner {
            return Err(AccountError::wrong_object(
                "this action was prepared by another session",
            ));
        }
        s.pending
            .take()
            .ok_or_else(|| AccountError::consumed("this action is finished, failed or denied"))
    }
    pub(crate) fn put_back(&self, p: PendingAction) -> R<()> {
        lock(&self.st)?.pending = Some(p);
        Ok(())
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountAction {
    /// What kind of action this is (`approve`, `revoke`, `write`, ...).
    pub fn kind(&self) -> Result<String, AccountError> {
        guard(|| Ok(lock(&self.st)?.kind.clone()))
    }
    /// The refusal of a write the account would not allow (`{"reason","detail"}`), or an empty
    /// string. A denied action has no steps and cannot be finished.
    pub fn denial(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.st)?;
            match &s.denial {
                Some(d) => to_string(d),
                None => Ok(String::new()),
            }
        })
    }
    /// The action's facts for display, as JSON.
    pub fn info(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.st)?;
            let Some(p) = &s.pending else {
                return Ok(String::new());
            };
            let i = p.info();
            to_string(&json!({
                "name": i.name, "rekeyOwed": i.rekey_owed, "owedNamespaces": i.owed_namespaces,
                "walkIncomplete": i.walk_incomplete, "kept": i.kept,
                "heads": i.heads.iter().map(|(n, d)| json!([n, d])).collect::<Vec<_>>(),
            }))
        })
    }
    /// The account this action is for.
    pub fn account(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.st)?;
            Ok(s.pending
                .as_ref()
                .map(|p| p.account().as_str().to_string())
                .unwrap_or_default())
        })
    }
    /// The exact bodies to sign, in the order the signatures are returned, as a JSON array of
    /// steps. Empty while PRF assertions are still needed.
    pub fn steps(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.st)?;
            let Some(p) = &s.pending else {
                return Ok("[]".into());
            };
            to_string(&steps_json(p.steps()))
        })
    }
    /// The PRF assertions to make before the bodies exist, as a JSON array; empty when none.
    pub fn prf_requests(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.st)?;
            let Some(p) = &s.pending else {
                return Ok("[]".into());
            };
            to_string(&prf_requests_json(p.prf_requests()))
        })
    }
}

pub(crate) fn role(r: StepRole) -> &'static str {
    match r {
        StepRole::Primary => "primary",
        StepRole::Cosignature => "cosignature",
        StepRole::Possession => "possession",
        StepRole::Handover => "handover",
    }
}
/// One step as the host sees it: a copy of the exact bytes and who must sign them.
pub(crate) fn step_json(s: &SigningStep) -> Value {
    let (form, descriptor) = match s.descriptor() {
        Some(d) => (
            if d.webauthn().is_some() {
                "webauthn"
            } else {
                "raw"
            },
            serde_json::to_value(d).unwrap_or(Value::Null),
        ),
        None => (
            if s.challenge().is_some() {
                "webauthn"
            } else {
                "raw"
            },
            Value::Null,
        ),
    };
    json!({"path": s.path(), "body": enc(s.body()), "signer": s.signer(), "role": role(s.role()),
        "form": form, "descriptor": descriptor, "signingKey": enc(s.signing()),
        "challenge": s.challenge(), "uv": s.uv()})
}
pub(crate) fn steps_json(steps: &[SigningStep]) -> Value {
    Value::Array(steps.iter().map(step_json).collect())
}
pub(crate) fn prf_requests_json(r: &[PrfRequest]) -> Value {
    Value::Array(
        r.iter()
            .map(|r| {
                json!({"controller": r.controller, "rp": r.rp, "credential": enc(&r.credential),
                    "salt": enc(&r.salt), "challenge": enc(&r.challenge)})
            })
            .collect(),
    )
}

/// `[{"signature", "authenticatorData"?, "clientData"?}]` in step order.
pub(crate) fn signatures(text: &str) -> R<Vec<SignatureResult>> {
    let v = parse(text, "signatures")?;
    let a = v
        .as_array()
        .ok_or_else(|| AccountError::bad("signatures must be an array"))?;
    if a.len() > MAX_NAMES {
        return Err(AccountError::bound("too many signatures"));
    }
    a.iter()
        .map(|s| {
            let signature = b64(s, "signature")?;
            let ad = opt_b64(s, "authenticatorData")?;
            let cd = opt_b64(s, "clientData")?;
            let assertion = match (ad, cd) {
                (None, None) => None,
                (Some(a), Some(c)) => Some((a, c)),
                _ => {
                    return Err(AccountError::bad(
                        "an assertion needs both authenticatorData and clientData",
                    ))
                }
            };
            Ok(SignatureResult {
                signature,
                assertion,
            })
        })
        .collect()
}
/// `[{"authenticatorData","clientData","signature","output"}]`, one per PRF request. The
/// `output` is the 32-byte `results.first`; it is consumed and never returned.
pub(crate) fn prf_results(text: &str) -> R<Vec<PrfResult>> {
    let v = parse(text, "PRF results")?;
    let a = v
        .as_array()
        .ok_or_else(|| AccountError::bad("PRF results must be an array"))?;
    if a.len() > MAX_NAMES {
        return Err(AccountError::bound("too many PRF results"));
    }
    a.iter()
        .map(|r| {
            let output = b64(r, "output")?;
            Ok(PrfResult {
                assertion: PrfAssertion {
                    authenticator_data: b64(r, "authenticatorData")?,
                    client_data: b64(r, "clientData")?,
                    signature: b64(r, "signature")?,
                },
                output: PrfOutput::from_host(&output)?,
            })
        })
        .collect()
}

fn rule(v: &Value) -> R<TransitionRule> {
    match opt_text(v, "rule")?.unwrap_or("control") {
        "control" => Ok(TransitionRule::Control),
        "recovery" => Ok(TransitionRule::Recovery),
        _ => Err(AccountError::bad("rule is `control` or `recovery`")),
    }
}
fn plan(v: &Value) -> R<SlotPlan> {
    Ok(SlotPlan {
        controllers: names(v, "controllers")?,
        label: text(v, "label")?.to_string(),
    })
}
fn pair(v: &Value, what: &str) -> R<(u64, String)> {
    let a = v
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or_else(|| AccountError::bad(format!("{what} is [seq, digest]")))?;
    match (a[0].as_u64(), a[1].as_str()) {
        (Some(s), Some(d)) => Ok((s, d.to_string())),
        _ => Err(AccountError::bad(format!("{what} is [seq, digest]"))),
    }
}
fn seeds32(entropy: &[u8], n: usize) -> R<Vec<[u8; 32]>> {
    if entropy.len() != 32 * n {
        return Err(AccountError::bound(&format!(
            "this action takes {} bytes of fresh entropy",
            32 * n
        )));
    }
    entropy
        .chunks(32)
        .map(|c| fixed::<32>(c, "entropy"))
        .collect()
}
fn no_entropy(entropy: &[u8]) -> R<()> {
    if entropy.is_empty() {
        Ok(())
    } else {
        Err(AccountError::bound("this action takes no entropy"))
    }
}

/// What `begin` made.
pub(crate) enum Prepared {
    Action(PendingAction),
    Denied(colophon_core::model::Denial),
}
fn done(p: colophon_core::v05::Result<PendingAction>) -> R<Prepared> {
    Ok(Prepared::Action(p?))
}

/// The writes an engine prepares itself (its live heads, its import and budget checks) are
/// passed in as closures; everything else is the account's.
pub(crate) type WriteResult =
    colophon_core::v05::Result<Result<PendingAction, colophon_core::model::Denial>>;
pub(crate) type WriteFn<'a> = dyn Fn(&str, &str, Value, Level, [u8; 32]) -> WriteResult + 'a;
pub(crate) struct EngineWrites<'a> {
    pub write: &'a WriteFn<'a>,
}

/// Prepare the action `spec` names over `acc`. `entropy` is the host's fresh entropy, in 32-byte
/// parts, as many as the action takes.
pub(crate) fn begin(
    acc: &Account,
    engine: Option<&EngineWrites<'_>>,
    spec: &Value,
    entropy: &mut [u8],
) -> R<(String, Prepared)> {
    let out = begin_inner(acc, engine, spec, entropy);
    entropy.fill(0);
    out
}
fn begin_inner(
    acc: &Account,
    engine: Option<&EngineWrites<'_>>,
    spec: &Value,
    entropy: &[u8],
) -> R<(String, Prepared)> {
    obj(spec, "the action")?;
    let kind = text(spec, "action")?.to_string();
    let signers = || names(spec, "signers");
    let prepared = match kind.as_str() {
        "approve" => {
            let s = seeds32(entropy, 1)?;
            done(acc.begin_approve(
                &b64(spec, "request")?,
                spec.get("terms").cloned().unwrap_or(Value::Null),
                &signers()?,
                s[0],
            ))?
        }
        "renew" => {
            let s = seeds32(entropy, 1)?;
            done(acc.begin_renew(
                text(spec, "member")?,
                int(spec, "expiresMs")?,
                &signers()?,
                s[0],
            ))?
        }
        "renew_shares" => {
            let s = seeds32(entropy, 1)?;
            done(acc.begin_renew_shares(text(spec, "member")?, &signers()?, s[0]))?
        }
        "revoke" => {
            let s = seeds32(entropy, 1)?;
            let keep = match spec.get("keep") {
                None | Some(Value::Null) => RevokeKeep::Everything,
                Some(Value::String(t)) if t == "everything" => RevokeKeep::Everything,
                Some(Value::String(t)) if t == "nothing" => RevokeKeep::Nothing,
                Some(k @ Value::Object(_)) => RevokeKeep::Explicit {
                    kept: names(k, "kept")?,
                    heads: list(k, "heads")?
                        .iter()
                        .map(|h| {
                            match (
                                h.get(0).and_then(Value::as_str),
                                h.get(1).and_then(Value::as_str),
                            ) {
                                (Some(n), Some(d)) => Ok((n.to_string(), d.to_string())),
                                _ => Err(AccountError::bad("heads are [namespace, digest]")),
                            }
                        })
                        .collect::<R<Vec<_>>>()?,
                },
                _ => {
                    return Err(AccountError::bad(
                        "keep is `everything`, `nothing` or an object",
                    ))
                }
            };
            done(acc.begin_revoke(text(spec, "member")?, &keep, &signers()?, s[0]))?
        }
        "end_sessions" => {
            no_entropy(entropy)?;
            done(acc.begin_end_sessions(text(spec, "member")?, &signers()?))?
        }
        "end_my_sessions" => {
            no_entropy(entropy)?;
            done(acc.begin_end_my_sessions())?
        }
        "rekey" => {
            let s = seeds32(entropy, 1)?;
            done(acc.begin_rekey(&names(spec, "namespaces")?, &signers()?, s[0]))?
        }
        "keyring" => {
            no_entropy(entropy)?;
            let edit = KeyringEdit {
                add_controllers: list(spec, "addControllers")?.to_vec(),
                add_slots: list(spec, "addSlots")?.to_vec(),
                policy: spec.get("policy").filter(|p| !p.is_null()).cloned(),
            };
            done(acc.begin_keyring(&edit, &signers()?))?
        }
        "add_controller" => {
            no_entropy(entropy)?;
            let mode = match opt_text(spec, "mode")?.unwrap_or("immediate") {
                "immediate" => AddMode::Immediate {
                    signers: signers()?,
                },
                "transition" => AddMode::Transition {
                    signers: signers()?,
                    rule: rule(spec)?,
                },
                _ => return Err(AccountError::bad("mode is `immediate` or `transition`")),
            };
            done(
                acc.begin_add_controller(&AddController {
                    controller: spec
                        .get("controller")
                        .cloned()
                        .ok_or_else(|| AccountError::bad("`controller` is required"))?,
                    mode,
                }),
            )?
        }
        "add_slot" => {
            let s = seeds32(entropy, 1)?;
            let p = plan(
                spec.get("plan")
                    .ok_or_else(|| AccountError::bad("`plan` is required"))?,
            )?;
            done(acc.begin_add_slot(text(spec, "signer")?, p, s[0]))?
        }
        "rotate_vault" => {
            let s = seeds32(entropy, 2)?;
            let plans = match spec.get("plans") {
                None | Some(Value::Null) => None,
                Some(Value::Array(a)) if a.len() <= MAX_NAMES => {
                    Some(a.iter().map(plan).collect::<R<Vec<_>>>()?)
                }
                _ => return Err(AccountError::bad("plans is an array of slot plans")),
            };
            done(acc.begin_rotate_vault(text(spec, "signer")?, s[0], plans, s[1]))?
        }
        "remove_controller" => {
            let rotate = boolean(spec, "rotate", false)?;
            let rotation = if rotate {
                let s = seeds32(entropy, 2)?;
                Some((s[0], s[1]))
            } else {
                no_entropy(entropy)?;
                None
            };
            done(acc.begin_remove_controller(
                &names(spec, "remove")?,
                &names(spec, "keep")?,
                &signers()?,
                rule(spec)?,
                rotation,
            ))?
        }
        "transition" => {
            no_entropy(entropy)?;
            let c = obj(
                spec.get("change")
                    .ok_or_else(|| AccountError::bad("`change` is required"))?,
                "change",
            )?
            .clone();
            done(acc.begin_transition(&Change(c), &signers()?, rule(spec)?))?
        }
        "veto" => {
            no_entropy(entropy)?;
            done(acc.begin_veto(text(spec, "transition")?, &signers()?))?
        }
        "suspend" => {
            no_entropy(entropy)?;
            done(acc.begin_suspend(
                text(spec, "key")?,
                text(spec, "transition")?,
                text(spec, "signer")?,
            ))?
        }
        "resolve" => {
            no_entropy(entropy)?;
            done(acc.begin_resolve(
                pair(spec.get("anchor").unwrap_or(&Value::Null), "anchor")?,
                pair(spec.get("kept").unwrap_or(&Value::Null), "kept")?,
                &signers()?,
                rule(spec)?,
            ))?
        }
        "write" | "propose" => {
            let s = seeds32(entropy, 1)?;
            let level = if kind == "write" {
                Level::Write
            } else {
                Level::Propose
            };
            let ns = text(spec, "namespace")?;
            let k = text(spec, "kind")?;
            let payload = spec.get("payload").cloned().unwrap_or(Value::Null);
            let r = match engine {
                Some(e) => (e.write)(ns, k, payload, level, s[0])?,
                None if level == Level::Write => acc.begin_write(ns, k, payload, level, s[0])?,
                None => acc.begin_propose(ns, k, payload, s[0])?,
            };
            match r {
                Ok(p) => Prepared::Action(p),
                Err(d) => Prepared::Denied(d),
            }
        }
        "resolution" => {
            let s = seeds32(entropy, 1)?;
            done(acc.begin_resolution(
                text(spec, "namespace")?,
                boolean(spec, "accept", true)?,
                &names(spec, "proposals")?,
                s[0],
            ))?
        }
        "link" => {
            no_entropy(entropy)?;
            done(acc.begin_link(
                &b64_list(spec, "prior")?,
                &b64(spec, "toSigning")?,
                spec.get("terms").cloned().unwrap_or(Value::Null),
                int(spec, "notBeforeMs")?,
                int(spec, "expiresMs")?,
            ))?
        }
        "call" => {
            let s = seeds32(entropy, 1)?;
            let t = spec.get("target").cloned().unwrap_or(Value::Null);
            let mut target = CallTarget::default();
            if t.is_object() {
                target.audiences = names(&t, "audiences")?;
                target.controller_purposes = names(&t, "controllerPurposes")?;
                target.home_endpoints = names(&t, "homeEndpoints")?;
                if let Some(o) = t.get("callOrigins").and_then(Value::as_object) {
                    if o.len() > MAX_NAMES {
                        return Err(AccountError::bound("too many call origins"));
                    }
                    for (rp, v) in o {
                        target
                            .call_origins
                            .insert(rp.clone(), names_of(v, "callOrigins")?);
                    }
                }
            }
            done(acc.begin_call(
                &b64(spec, "key")?,
                &b64_list(spec, "links")?,
                text(spec, "audience")?,
                text(spec, "purpose")?,
                spec.get("args").cloned().unwrap_or(Value::Null),
                s[0],
                target,
            ))?
        }
        other => {
            return Err(AccountError::bad(format!("unknown action `{other}`")));
        }
    };
    Ok((kind, prepared))
}

pub(crate) fn signer_choice(name: &str) -> R<SignerChoice> {
    Ok(match name {
        "member" => SignerChoice::Member,
        "rekey" => SignerChoice::Rekey,
        "control" => SignerChoice::Control,
        "recovery" => SignerChoice::Recovery,
        "keyring_add" => SignerChoice::KeyringAdd,
        "veto" => SignerChoice::Veto,
        _ => return Err(AccountError::bad("unknown signer choice")),
    })
}
