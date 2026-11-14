//! Core values to typed records, and the host's typed answers back to core values. Secrets the
//! host passes are copied into the core's opaque types and every host-side copy is wiped here.
use super::fault::AccountError;
use super::types::*;
use colophon_core::v05::account as acc;
use colophon_core::v05::descriptor::{KeyDescriptor, KeyForm as CoreForm, WebAuthnKey};
use colophon_core::v05::slots as sl;
use colophon_core::v05::vault::{EcdhOutput, PrfOutput};
use colophon_core::v05::write as wr;
use serde_json::Value;

pub(crate) fn store_list(items: &[(String, Vec<u8>)]) -> Vec<Store> {
    items
        .iter()
        .map(|(p, b)| Store {
            path: p.clone(),
            bytes: b.clone(),
        })
        .collect()
}
pub(crate) fn descriptor_view(d: &KeyDescriptor) -> KeyDescriptorView {
    let (form, agreement, rp, credential, origins, authority_origins) = match d.form() {
        CoreForm::Raw { agreement } => {
            (SignForm::Raw, agreement.clone(), None, None, vec![], vec![])
        }
        CoreForm::WebAuthn(w) => (
            SignForm::Webauthn,
            None,
            Some(w.rp().to_string()),
            Some(w.credential().to_vec()),
            w.origins().to_vec(),
            w.authority_origins()
                .map(<[String]>::to_vec)
                .unwrap_or_default(),
        ),
        CoreForm::Unknown(_) => (SignForm::Raw, None, None, None, vec![], vec![]),
    };
    KeyDescriptorView {
        form,
        signing: d.signing().to_vec(),
        agreement,
        rp,
        credential,
        origins,
        authority_origins,
    }
}
pub(crate) fn descriptor_from_view(v: &KeyDescriptorView) -> Result<KeyDescriptor, AccountError> {
    bytes_ok(&v.signing, 65, "a signing point")?;
    Ok(match v.form {
        SignForm::Raw => KeyDescriptor::new_raw(v.signing.clone(), v.agreement.clone())?,
        SignForm::Webauthn => {
            let opt = |l: &Vec<String>| (!l.is_empty()).then(|| l.clone());
            KeyDescriptor::new_webauthn(
                v.signing.clone(),
                WebAuthnKey::new(
                    v.rp.clone().unwrap_or_default(),
                    v.credential.clone().unwrap_or_default(),
                    opt(&v.origins),
                    opt(&v.authority_origins),
                )?,
            )?
        }
    })
}
fn role(r: wr::StepRole) -> StepRole {
    match r {
        wr::StepRole::Primary => StepRole::Primary,
        wr::StepRole::Cosignature => StepRole::Cosignature,
        wr::StepRole::Possession => StepRole::Possession,
        wr::StepRole::Handover => StepRole::Handover,
    }
}
pub(crate) fn step(s: &wr::SigningStep) -> AccountSigningStep {
    let descriptor = s.descriptor().map(descriptor_view);
    let form = match (&descriptor, s.challenge()) {
        (Some(d), _) => d.form,
        (None, Some(_)) => SignForm::Webauthn,
        (None, None) => SignForm::Raw,
    };
    AccountSigningStep {
        path: s.path().to_string(),
        body: s.body().to_vec(),
        signer: s.signer().to_string(),
        role: role(s.role()),
        form,
        descriptor,
        signing_key: s.signing().to_vec(),
        challenge: s.challenge().map(str::to_string),
        uv: s.uv(),
    }
}
pub(crate) fn steps(s: &[wr::SigningStep]) -> Vec<AccountSigningStep> {
    s.iter().map(step).collect()
}
pub(crate) fn prf_requests(r: &[sl::PrfRequest]) -> Vec<PrfRequest> {
    r.iter()
        .map(|r| PrfRequest {
            controller: r.controller.clone(),
            rp: r.rp.clone(),
            credential: r.credential.clone(),
            salt: r.salt.to_vec(),
            challenge: r.challenge.to_vec(),
        })
        .collect()
}
pub(crate) fn signatures(v: Vec<Signature>) -> Result<Vec<wr::SignatureResult>, AccountError> {
    list_len(&v, "signatures")?;
    if v.len() > MAX_NAMES {
        return Err(AccountError::bound("too many signatures"));
    }
    v.into_iter()
        .map(|s| {
            bytes_ok(&s.signature, 1 << 16, "a signature")?;
            let assertion = match (s.authenticator_data, s.client_data) {
                (None, None) => None,
                (Some(a), Some(c)) => {
                    bytes_ok(&a, 1 << 16, "authenticator data")?;
                    bytes_ok(&c, 1 << 16, "client data")?;
                    Some((a, c))
                }
                _ => {
                    return Err(AccountError::bad(
                        "an assertion needs both authenticator data and client data",
                    ))
                }
            };
            Ok(wr::SignatureResult {
                signature: s.signature,
                assertion,
            })
        })
        .collect()
}
/// Consumes the answers: each `output` is copied into the core's opaque type and wiped.
pub(crate) fn prf_answers(mut v: Vec<PrfAnswer>) -> Result<Vec<sl::PrfResult>, AccountError> {
    let r = (|| {
        list_len(&v, "PRF answers")?;
        if v.len() > MAX_NAMES {
            return Err(AccountError::bound("too many PRF answers"));
        }
        v.iter()
            .map(|a| {
                bytes_ok(&a.authenticator_data, 1 << 16, "authenticator data")?;
                bytes_ok(&a.client_data, 1 << 16, "client data")?;
                bytes_ok(&a.signature, 1 << 16, "a signature")?;
                Ok(sl::PrfResult {
                    assertion: sl::PrfAssertion {
                        authenticator_data: a.authenticator_data.clone(),
                        client_data: a.client_data.clone(),
                        signature: a.signature.clone(),
                    },
                    output: PrfOutput::from_host(&a.output)?,
                })
            })
            .collect()
    })();
    for a in &mut v {
        wipe(&mut a.output);
    }
    r
}
pub(crate) fn unlock_inputs(i: &[sl::OpeningInput]) -> Vec<UnlockInput> {
    i.iter()
        .map(|i| match i {
            sl::OpeningInput::Ecdh { controller, enc } => UnlockInput {
                kind: UnlockKind::Ecdh,
                controller: controller.clone(),
                enc: enc.clone(),
                salt: vec![],
            },
            sl::OpeningInput::Prf { controller, salt } => UnlockInput {
                kind: UnlockKind::Prf,
                controller: controller.clone(),
                enc: vec![],
                salt: salt.clone(),
            },
        })
        .collect()
}
/// Consumes the secrets: each is copied into the core's opaque type and wiped.
pub(crate) fn unlock_secrets(
    mut v: Vec<UnlockSecret>,
) -> Result<Vec<sl::OpeningSecret>, AccountError> {
    let r = (|| {
        if v.len() > MAX_NAMES {
            return Err(AccountError::bound("too many secrets"));
        }
        v.iter()
            .map(|s| match s.kind {
                UnlockKind::Ecdh => Ok(sl::OpeningSecret::Ecdh(EcdhOutput::from_host(&s.secret)?)),
                UnlockKind::Prf => Ok(sl::OpeningSecret::Prf(PrfOutput::from_host(&s.secret)?)),
            })
            .collect()
    })();
    for s in &mut v {
        wipe(&mut s.secret);
    }
    r
}
pub(crate) fn agreements(a: Vec<acc::EpochAgreement>) -> Vec<EpochAgreement> {
    a.into_iter()
        .map(|s| EpochAgreement {
            namespace: s.namespace,
            epoch: s.epoch,
            recipient: s.recipient,
            recipient_point: s.recipient_point,
            peer: s.peer,
        })
        .collect()
}
/// Match the host's answers to the account's own request, then consume and wipe them.
pub(crate) fn epoch_secrets(
    want: Vec<acc::EpochAgreement>,
    mut v: Vec<EpochAnswer>,
) -> Result<Vec<acc::EpochSecret>, AccountError> {
    let r = (|| {
        list_len(&v, "answers")?;
        v.iter()
            .map(|a| {
                let step = want
                    .iter()
                    .find(|w| w.namespace == a.namespace && w.epoch == a.epoch)
                    .ok_or_else(|| AccountError::bad("an answer for a share not asked for"))?
                    .clone();
                Ok(acc::EpochSecret {
                    step,
                    shared: EcdhOutput::from_host(&a.shared)?,
                })
            })
            .collect()
    })();
    for a in &mut v {
        wipe(&mut a.shared);
    }
    r
}
pub(crate) fn slots(a: &acc::Account) -> Result<Vec<SlotInfo>, AccountError> {
    Ok(a.slots()?
        .into_iter()
        .map(|s| SlotInfo {
            index: s.index as u64,
            kind: s.kind,
            label: s.label,
            controllers: s
                .controllers
                .into_iter()
                .map(|(id, label)| SlotController { id, label })
                .collect(),
        })
        .collect())
}
pub(crate) fn status(s: &acc::Status) -> Status {
    Status {
        seq: s.seq,
        code: s.code.clone(),
        stop_seq: s.stop_seq,
        detail: s.detail.clone(),
        rollback: s.rollback,
    }
}
pub(crate) fn changes(c: &acc::Changes) -> Changes {
    Changes {
        authority_from_seq: c.authority.seq.0,
        authority_to_seq: c.authority.seq.1,
        entries: c
            .authority
            .entries
            .iter()
            .map(|(s, k)| EntryChange {
                seq: *s,
                kind: k.clone(),
            })
            .collect(),
        members_added: c.authority.members_added.clone(),
        members_revoked: c.authority.members_revoked.clone(),
        controllers_added: c.authority.controllers_added.clone(),
        controllers_removed: c.authority.controllers_removed.clone(),
        vault_changed: c.authority.vault_changed,
        policy_changed: c.authority.policy_changed,
        reorganized: c.authority.reorganized,
        namespaces: c
            .namespaces
            .iter()
            .map(|(n, r)| NamespaceRevision {
                namespace: n.clone(),
                revision: *r,
            })
            .collect(),
        pending_added: c.pending.added.clone(),
        pending_gone: c.pending.gone.clone(),
        pending_now: c.pending.now.clone(),
        heads_accepted: c.heads.accepted.clone(),
        heads_refused: c
            .heads
            .refused
            .iter()
            .map(|(h, code)| RefusedHead {
                home: h.clone(),
                code: code.clone(),
            })
            .collect(),
        foreign: c.foreign as u64,
        status: c.status.as_ref().map(status),
    }
}
pub(crate) fn controller(c: &acc::ControllerInfo) -> Controller {
    Controller {
        id: c.id.clone(),
        label: c.label.clone(),
        roles: c.roles.clone(),
        form: if c.form == "webauthn" {
            SignForm::Webauthn
        } else {
            SignForm::Raw
        },
        verification: c.verification,
        holder: c.holder.clone(),
        has_slot: c.has_slot,
        provisional: c.provisional,
        suspended: c.suspended,
    }
}
fn member_kind(s: Option<&str>) -> AccountMemberKind {
    match s {
        Some("app") => AccountMemberKind::App,
        Some("agent") => AccountMemberKind::Agent,
        Some("server") => AccountMemberKind::Server,
        _ => AccountMemberKind::Device,
    }
}
pub(crate) fn member_kind_of(k: AccountMemberKind) -> &'static str {
    match k {
        AccountMemberKind::Device => "device",
        AccountMemberKind::App => "app",
        AccountMemberKind::Agent => "agent",
        AccountMemberKind::Server => "server",
    }
}
pub(crate) fn member_kind_from(s: &str) -> AccountMemberKind {
    member_kind(Some(s))
}
pub(crate) fn member(m: &acc::MemberInfo) -> Result<AccountMember, AccountError> {
    let v = serde_json::to_value(&m.member)
        .map_err(|_| AccountError::internal("a member could not be read"))?;
    let grant = match v.get("grant") {
        Some(g) if g.is_object() => Some(AccountGrant {
            namespaces: strs(g.get("namespaces")),
            access: g
                .get("access")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|x| {
                            if x.as_str() == Some("write") {
                                AccessKind::Write
                            } else {
                                AccessKind::Read
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
            expires: g.get("expires").and_then(Value::as_str).map(str::to_string),
            write_budget: g.get("writeBudget").and_then(Value::as_u64),
            import: g.get("import").and_then(Value::as_bool).unwrap_or(false),
        }),
        _ => None,
    };
    Ok(AccountMember {
        id: v["id"].as_str().unwrap_or_default().to_string(),
        label: v["label"].as_str().unwrap_or_default().to_string(),
        kind: member_kind(v["kind"].as_str()),
        grant,
        since: v["since"].as_u64().unwrap_or(0),
        revoked_at: v["revokedAt"].as_u64(),
        writes: v["writes"].as_u64().unwrap_or(0),
        expires_ms: m.expires_ms,
        provisional: m.provisional,
        home: m.home,
        session: m.session,
    })
}
fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
pub(crate) fn standing(s: &acc::Standing) -> Result<Standing, AccountError> {
    Ok(match s {
        acc::Standing::Controller(c) => Standing {
            kind: StandingKind::Controller,
            controller: Some(controller(c)),
            member: None,
            unknown_id: None,
        },
        acc::Standing::Member(m) => Standing {
            kind: StandingKind::Member,
            controller: None,
            member: Some(member(m)?),
            unknown_id: None,
        },
        acc::Standing::Unknown(id) => Standing {
            kind: StandingKind::Unknown,
            controller: None,
            member: None,
            unknown_id: Some(id.clone()),
        },
    })
}
pub(crate) fn home(h: &acc::HomeInfo) -> Home {
    Home {
        id: h.id.clone(),
        label: h.label.clone(),
        status: h.status.clone(),
        endpoints: h.endpoints.clone(),
        primary: h.primary,
    }
}
pub(crate) fn policy(p: &acc::Policy) -> Policy {
    Policy {
        threshold: p.threshold,
        recover_threshold: p.recover_threshold,
        add_threshold: p.add_threshold,
        count_by_holders: p.count_by_holders,
        call_window: p.call_window,
        head_max_age: p.head_max_age,
        head_quorum: p.head_quorum,
        link_max_age: p.link_max_age,
        member_rule: p.member_rule.clone(),
        recovery_delay: p.recovery_delay,
        primary_home: p.primary_home.clone(),
    }
}
pub(crate) fn pending(p: &acc::PendingTransition) -> Pending {
    Pending {
        digest: p.digest.clone(),
        by: p.by.clone(),
        signers: p
            .signers
            .iter()
            .map(|(id, label)| Signer {
                id: id.clone(),
                label: label.clone(),
            })
            .collect(),
        issued_ms: p.issued_ms,
        anchor_seq: p.anchor_seq,
        first_seen_seq: p.first_seen_seq,
        due_ms: p.due_ms,
        veto_deadline_ms: p.veto_deadline_ms,
        full_set: p.full_set,
        components: p.components.clone(),
        removes: p.removes.clone(),
        adds: p.adds.clone(),
        vetoes: p.vetoes.clone(),
        vetoable: p.vetoable,
    }
}
pub(crate) fn owed(o: &acc::OwedInfo) -> Owed {
    Owed {
        member: o.member.clone(),
        namespace: o.namespace.clone(),
        epoch: o.epoch,
        provisional: o.provisional,
    }
}
pub(crate) fn notices(n: &acc::Notices) -> Notices {
    Notices {
        pending: n.pending.iter().map(pending).collect(),
        activations: n
            .activations
            .iter()
            .map(|a| SeenActivation {
                seq: a.seq,
                transition: a.transition.clone(),
                signers: a.signers.clone(),
                components: a.components.clone(),
                receipted: a
                    .receipted
                    .iter()
                    .map(|(h, ms)| Receipted {
                        home: h.clone(),
                        received_ms: *ms,
                    })
                    .collect(),
            })
            .collect(),
        owed: n.owed.iter().map(owed).collect(),
        controllers_without_slot: n.controllers_without_slot.clone(),
        vault_retiring: n.vault_retiring,
        no_home: n.no_home,
    }
}
pub(crate) fn denial(d: &colophon_core::model::Denial) -> AccountDenial {
    AccountDenial {
        reason: d.reason.clone(),
        detail: d.detail.clone(),
    }
}
pub(crate) fn action_info(i: &acc::ActionInfo) -> ActionInfo {
    ActionInfo {
        name: i.name.clone(),
        rekey_owed: i.rekey_owed,
        owed_namespaces: i.owed_namespaces.clone(),
        walk_incomplete: i.walk_incomplete,
        kept: i.kept.clone(),
        heads: i
            .heads
            .iter()
            .map(|(n, d)| HeadRef {
                namespace: n.clone(),
                digest: d.clone(),
            })
            .collect(),
    }
}
pub(crate) fn signer_need(n: SignerNeed) -> acc::SignerChoice {
    match n {
        SignerNeed::Member => acc::SignerChoice::Member,
        SignerNeed::Rekey => acc::SignerChoice::Rekey,
        SignerNeed::Control => acc::SignerChoice::Control,
        SignerNeed::Recovery => acc::SignerChoice::Recovery,
        SignerNeed::KeyringAdd => acc::SignerChoice::KeyringAdd,
        SignerNeed::Veto => acc::SignerChoice::Veto,
    }
}
pub(crate) fn rule(r: RuleKind) -> colophon_core::v05::write::authority::TransitionRule {
    match r {
        RuleKind::Control => colophon_core::v05::write::authority::TransitionRule::Control,
        RuleKind::Recovery => colophon_core::v05::write::authority::TransitionRule::Recovery,
    }
}
pub(crate) fn slot_plan(p: SlotPlan) -> Result<sl::SlotPlan, AccountError> {
    Ok(sl::SlotPlan {
        controllers: names(p.controllers, "slot controllers")?,
        label: p.label,
    })
}
