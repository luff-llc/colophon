//! Reading an account: views and queries through the unchanged domain modules, members,
//! controllers, homes, policy, the ledger, and what is pending and what the person must be
//! shown (§17.5).
use super::derived::{entry_digest, grant_of, model_kind, readable};
use super::{Account, Identity};
use crate::domain::{self, Spec};
use crate::model::{Denial, LedgerEntry, Member, NamespaceView, Outcome, Rejection};
use crate::v05::descriptor::Role;
use crate::v05::encoding::{bounds, decode_base64};
use crate::v05::history::envelope::AuthEnvelope;
use crate::v05::history::{transition_timing, HomeStatus, Objects, State};
use crate::v05::records::{Level, Outcome as Admission, OwedShare, ProposalState};
use crate::v05::slots::Slot;
use crate::v05::terms::Access;
use crate::v05::write::authority::choose_receipts;
use crate::v05::write::format_date;
use crate::v05::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// A controller, as the keyring holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerInfo {
    /// The controller ID.
    pub id: String,
    /// The label.
    pub label: String,
    /// Roles, as the protocol spells them.
    pub roles: Vec<String>,
    /// `raw` or `webauthn`.
    pub form: String,
    /// UV is required on its signatures.
    pub verification: bool,
    /// The holder it counts for under `countBy: holders`.
    pub holder: Option<String>,
    /// Some slot of the current vault names it.
    pub has_slot: bool,
    /// Added by an activation that is not final yet (§8.7).
    pub provisional: bool,
    /// Suspended by a pending transition at the account's clock.
    pub suspended: bool,
}

/// A member, with the 0.4 shape and what 0.5 adds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberInfo {
    /// The 0.4-shaped member: ID, label, kind, grant (the `records` entries as namespaces and
    /// access), admission seq, revocation seq and the count of admitted records.
    pub member: Member,
    /// The current expiry, ms.
    pub expires_ms: Option<i64>,
    /// Added by an activation that is not final yet.
    pub provisional: bool,
    /// A home of the account.
    pub home: bool,
    /// How many times its sessions were ended (the current session number, §9.6).
    pub session: u64,
}

/// A home (§13.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeInfo {
    /// The member ID.
    pub id: String,
    /// The label.
    pub label: String,
    /// `home`, or `revocationPending` (its removal has not activated finally).
    pub status: String,
    /// Its endpoints.
    pub endpoints: Vec<String>,
    /// The policy's `primaryHome` is this one.
    pub primary: bool,
}

/// The account policy (§6.3), as the verified keyring holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// `threshold`.
    pub threshold: u64,
    /// `recoverThreshold`.
    pub recover_threshold: u64,
    /// `addThreshold`.
    pub add_threshold: u64,
    /// `countBy: holders`.
    pub count_by_holders: bool,
    /// Seconds a call's `created` may differ from the clock.
    pub call_window: u64,
    /// Seconds a head stays fresh.
    pub head_max_age: u64,
    /// Homes whose heads count.
    pub head_quorum: u64,
    /// Seconds a link may live.
    pub link_max_age: u64,
    /// `single` or `control`.
    pub member_rule: String,
    /// Seconds a pending transition waits.
    pub recovery_delay: u64,
    /// The primary home.
    pub primary_home: Option<String>,
}
pub use PolicyInfo as Policy;

/// A pending transition, as §17.5 says it must be shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTransition {
    /// The transition's body digest.
    pub digest: String,
    /// Who proposed it.
    pub by: String,
    /// Its signers, with labels: `(ID, label)`.
    pub signers: Vec<(String, String)>,
    /// `issued`, ms.
    pub issued_ms: i64,
    /// The seq of the entry it is anchored on.
    pub anchor_seq: u64,
    /// The verified seq at which this account first held it (local memory, §17.5).
    pub first_seen_seq: Option<u64>,
    /// Its due time, when the held receipts decide it.
    pub due_ms: Option<i64>,
    /// Its veto deadline, when the held receipts decide it.
    pub veto_deadline_ms: Option<i64>,
    /// Not vetoable: every control key signed.
    pub full_set: Option<bool>,
    /// The components of the change, by name.
    pub components: Vec<String>,
    /// Controllers it removes.
    pub removes: Vec<String>,
    /// Controllers it adds.
    pub adds: Vec<String>,
    /// Digests of held vetoes naming it.
    pub vetoes: Vec<String>,
    /// Some key on this device may veto it (it holds `control` or `recover`) and the deadline
    /// has not passed.
    pub vetoable: bool,
}

/// An activation the person has not seen (§17.5 "Missed notices are visible afterwards").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenActivation {
    /// The `activate` entry's seq.
    pub seq: u64,
    /// The transition's digest.
    pub transition: String,
    /// The transition's signers.
    pub signers: Vec<String>,
    /// The components of its change.
    pub components: Vec<String>,
    /// When each home receipted it: `(home ID, received ms)`.
    pub receipted: Vec<(String, i64)>,
}

/// What the person must be shown (§17.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notices {
    /// Pending transitions the host has not shown.
    pub pending: Vec<PendingTransition>,
    /// Activations since the host last showed the history that no key on this device signed.
    pub activations: Vec<SeenActivation>,
    /// Members and namespaces owed shares (a `renew` carries them, §9.4).
    pub owed: Vec<OwedInfo>,
    /// Non-`sign` controllers no slot of the current vault names (§6.4, §8.3): they need the
    /// seed by §7.4 and a self-slot.
    pub controllers_without_slot: Vec<String>,
    /// The vault is retiring: a `vault` entry is owed (§8.3).
    pub vault_retiring: bool,
    /// The account has no home: no witness of time or order (§13.1).
    pub no_home: bool,
}

/// A share a member is owed (§9.4): an epoch of a namespace in its scope that no epoch object
/// sealed to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwedInfo {
    /// The member ID.
    pub member: String,
    /// The namespace.
    pub namespace: String,
    /// The epoch.
    pub epoch: u64,
    /// The member's admission is not final yet.
    pub provisional: bool,
}

/// A proposal and its standing (§11.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalInfo {
    /// The namespace.
    pub namespace: String,
    /// The proposal's operation ID.
    pub id: String,
    /// The proposer.
    pub proposer: String,
    /// The proposal's kind.
    pub kind: String,
    /// `pending`, `accepted` or `declined`.
    pub state: String,
    /// Who resolved it.
    pub by: Option<String>,
    /// An acceptance is never final (§11.6): an earlier-sorting resolution can still arrive.
    pub final_: bool,
}

pub use crate::model::LedgerEntry as LedgerLine;

/// The pending transitions held, not yet recorded on the branch, at `state`.
pub(super) fn pending_transitions(objects: &Objects, state: &State) -> Vec<PendingTransition> {
    let mut vetoes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut found: Vec<(AuthEnvelope, Vec<u8>)> = Vec::new();
    for b in &objects.pending {
        let Ok(env) = AuthEnvelope::parse(
            b,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            true,
        ) else {
            continue;
        };
        match env.value.get("protocol").and_then(Value::as_str) {
            // One body under several envelopes is one object (§2.2): listed once.
            Some("colophon/transition/5") => {
                if !found.iter().any(|(f, _)| f.digest == env.digest) {
                    found.push((env, b.clone()))
                }
            }
            Some("colophon/veto/5") => {
                if let Some(t) = env.value.get("transition").and_then(Value::as_str) {
                    let list = vetoes.entry(t.to_string()).or_default();
                    if !list.contains(&env.digest) {
                        list.push(env.digest);
                    }
                }
            }
            _ => {}
        }
    }
    let label = |id: &str| -> String {
        state
            .keyring()
            .controllers
            .get(id)
            .map(|c| c.label().to_string())
            .or_else(|| {
                state
                    .members()
                    .iter()
                    .find(|m| m.request.member_id() == id)
                    .map(|m| m.request.label.clone())
            })
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for (env, bytes) in found {
        if state.recorded.contains(&env.digest) {
            continue;
        }
        let v = &env.value;
        let issued = v
            .get("issued")
            .and_then(Value::as_str)
            .and_then(crate::v05::encoding::parse_date)
            .unwrap_or(0);
        let signers: Vec<String> = v
            .get("signers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let change = v.get("change").and_then(Value::as_object);
        let ids = |comp: &str, field: &str| -> Vec<String> {
            change
                .and_then(|c| c.get(comp))
                .and_then(|k| k.get(field))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| {
                            x.as_str().map(str::to_string).or_else(|| {
                                // An `add` entry is a controller object: its ID is the key ID.
                                crate::v05::descriptor::Controller::parse(x.clone(), "add")
                                    .ok()
                                    .map(|c| c.id())
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let receipts = choose_receipts(state, &objects.pending, &env.digest, issued, None).ok();
        let timing = receipts
            .as_ref()
            .and_then(|r| transition_timing(state, &bytes, r).ok());
        out.push(PendingTransition {
            digest: env.digest.clone(),
            by: v
                .get("by")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            signers: signers.iter().map(|s| (s.clone(), label(s))).collect(),
            issued_ms: issued,
            anchor_seq: v
                .get("anchor")
                .and_then(|a| a.get("seq"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            first_seen_seq: None,
            due_ms: timing.as_ref().map(|t| t.due_ms),
            veto_deadline_ms: timing.as_ref().map(|t| t.deadline_ms),
            full_set: timing.as_ref().map(|t| t.full_set),
            components: change
                .map(|c| c.keys().cloned().collect())
                .unwrap_or_default(),
            removes: ids("keyring", "remove"),
            adds: ids("keyring", "add"),
            vetoes: vetoes.remove(&env.digest).unwrap_or_default(),
            vetoable: false,
        });
    }
    out.sort_by(|a, b| a.digest.cmp(&b.digest));
    out
}

/// The `kind` of each branch entry, by body digest.
pub(super) fn entry_kinds(objects: &Objects, branch: &[String]) -> BTreeMap<String, String> {
    let on: BTreeSet<&String> = branch.iter().collect();
    let mut out = BTreeMap::new();
    for b in &objects.entries {
        let Ok(env) = AuthEnvelope::parse(
            b,
            bounds::AUTHORITY_BODY,
            bounds::AUTHORITY_BODY.saturating_mul(2),
            false,
        ) else {
            if let Some(d) = entry_digest(b) {
                if on.contains(&d) {
                    out.insert(d, "upgrade-prefix".to_string());
                }
            }
            continue;
        };
        if on.contains(&env.digest) {
            let kind = env
                .value
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            out.insert(env.digest, kind);
        }
    }
    out
}

fn english_access(entries: &[crate::v05::terms::RecordsEntry]) -> String {
    let parts: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                match e.access {
                    Access::Read => "read",
                    Access::Propose => "propose to",
                    Access::Write => "write",
                },
                e.namespace
            )
        })
        .collect();
    if parts.is_empty() {
        "no records".into()
    } else {
        parts.join(", ")
    }
}

impl Account {
    // -----------------------------------------------------------------------------------------
    // Standing.

    /// The controllers of the verified keyring.
    pub fn controllers(&self) -> Vec<ControllerInfo> {
        let st = self.d.auth.state();
        let k = st.keyring();
        let slotted: BTreeSet<String> = k
            .slots
            .iter()
            .filter_map(|v| Slot::from_value(v).ok())
            .flat_map(|s| s.controllers().to_vec())
            .collect();
        k.controllers
            .values()
            .map(|c| ControllerInfo {
                id: c.id(),
                label: c.label().to_string(),
                roles: c
                    .roles()
                    .iter()
                    .map(|r| match r {
                        Role::Approve => "approve".to_string(),
                        Role::Control => "control".into(),
                        Role::Recover => "recover".into(),
                        Role::Sign => "sign".into(),
                        Role::Unknown(s) => s.clone(),
                    })
                    .collect(),
                form: if c.key().webauthn().is_some() {
                    "webauthn"
                } else {
                    "raw"
                }
                .into(),
                verification: c.verification(),
                holder: c.holder().map(str::to_string),
                has_slot: slotted.contains(&c.id()),
                provisional: st.controller_provisional(&c.id()).is_some(),
                suspended: st
                    .active_suspensions(self.now_ms)
                    .iter()
                    .any(|s| s.key == c.id()),
            })
            .collect()
    }

    /// The members: 0.4's counts of admitted writes are derived from admission, not counters.
    pub fn members(&self) -> Vec<MemberInfo> {
        let mut writes: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for j in &self.d.judgement.records {
            if j.outcome == Admission::Admitted {
                if let (Some(a), Some(i)) = (&j.author, &j.id) {
                    writes.entry(a).or_default().insert(i);
                }
            }
        }
        self.d
            .auth
            .state()
            .members()
            .iter()
            .map(|m| {
                let id = m.request.member_id();
                MemberInfo {
                    member: Member {
                        id: id.clone(),
                        label: m.request.label.clone(),
                        kind: model_kind(&m.request.kind),
                        grant: Some(grant_of(m)),
                        since: m.granted_seq,
                        revoked_at: m.revoked_seq,
                        writes: writes.get(id.as_str()).map_or(0, |s| s.len() as u64),
                    },
                    expires_ms: m.expires_ms,
                    provisional: m.provisional.is_some(),
                    home: m.home != HomeStatus::NotHome,
                    session: m.end_sessions.len() as u64,
                }
            })
            .collect()
    }

    /// What this session is: its standing in the verified history, or an ungranted
    /// placeholder for a prospective identity (as 0.4 does).
    pub fn me(&self) -> Standing {
        let id = self.me.id().to_string();
        match &self.me {
            Identity::Controller(_) => match self.controllers().into_iter().find(|c| c.id == id) {
                Some(c) => Standing::Controller(c),
                None => Standing::Unknown(id),
            },
            Identity::Member(_) => match self.members().into_iter().find(|m| m.member.id == id) {
                Some(m) => Standing::Member(Box::new(m)),
                None => Standing::Unknown(id),
            },
        }
    }

    /// The homes (§13.1), current and pending removal.
    pub fn homes(&self) -> Vec<HomeInfo> {
        let st = self.d.auth.state();
        let primary = st.keyring().policy.primary_home().map(str::to_string);
        st.members()
            .iter()
            .filter(|m| m.home != HomeStatus::NotHome && m.revoked_seq.is_none())
            .map(|m| HomeInfo {
                id: m.request.member_id(),
                label: m.request.label.clone(),
                status: match m.home {
                    HomeStatus::RevocationPending(_) => "revocationPending".into(),
                    _ => "home".into(),
                },
                endpoints: m.request.endpoints.clone().unwrap_or_default(),
                primary: primary.as_deref() == Some(m.request.member_id().as_str()),
            })
            .collect()
    }

    /// The account policy and thresholds.
    pub fn policy(&self) -> PolicyInfo {
        let k = self.d.auth.state().keyring();
        let p = &k.policy;
        PolicyInfo {
            threshold: k.threshold,
            recover_threshold: k.recover_threshold,
            add_threshold: k.add_threshold,
            count_by_holders: k.holders,
            call_window: p.call_window(),
            head_max_age: p.head_max_age(),
            head_quorum: p.head_quorum(),
            link_max_age: p.link_max_age(),
            member_rule: match p.member_rule() {
                crate::v05::descriptor::MemberRule::Control => "control",
                _ => "single",
            }
            .into(),
            recovery_delay: p.recovery_delay(),
            primary_home: p.primary_home().map(str::to_string),
        }
    }

    /// Members owed shares (§9.4): each needs a `renew`.
    pub fn owed_shares(&self) -> Vec<OwedInfo> {
        self.d
            .auth
            .owed_shares()
            .into_iter()
            .map(|o: OwedShare| OwedInfo {
                member: o.member,
                namespace: o.namespace,
                epoch: o.epoch,
                provisional: o.provisional,
            })
            .collect()
    }

    /// The pending transitions, each as §17.5 requires it to be shown: signers with labels and
    /// key IDs, the verified seq at which this account first held it, and the veto deadline.
    pub fn pending(&self) -> Vec<PendingTransition> {
        let st = self.d.auth.state();
        let mine: Vec<&str> = match &self.me {
            Identity::Controller(id) => vec![id.as_str()],
            Identity::Member(_) => Vec::new(),
        };
        let may_veto = mine.iter().any(|id| {
            st.keyring()
                .controllers
                .get(*id)
                .is_some_and(|c| c.has(&Role::Control) || c.has(&Role::Recover))
        });
        pending_transitions(&self.d.effective, st)
            .into_iter()
            .map(|mut t| {
                t.first_seen_seq = self.first_seen.get(&t.digest).copied();
                t.vetoable = may_veto && t.veto_deadline_ms.is_some_and(|d| self.now_ms <= d);
                t
            })
            .collect()
    }

    /// Everything §17.5 says a host MUST show: each pending transition not yet shown, and every
    /// activation after `shown_seq` that no key in `local_keys` signed. `shown_transitions` are
    /// the transitions the host already showed. The host keeps both markers.
    pub fn notices(
        &self,
        shown_seq: u64,
        shown_transitions: &BTreeSet<String>,
        local_keys: &[String],
    ) -> Notices {
        let st = self.d.auth.state();
        let pending: Vec<PendingTransition> = self
            .pending()
            .into_iter()
            .filter(|t| !shown_transitions.contains(&t.digest))
            .collect();
        let mut activations = Vec::new();
        let branch: BTreeMap<&String, u64> = self
            .d
            .verdict
            .branch
            .iter()
            .enumerate()
            .map(|(i, d)| (d, i as u64 + 1))
            .collect();
        for b in &self.objects.entries {
            let Ok(env) = AuthEnvelope::parse(
                b,
                bounds::AUTHORITY_BODY,
                bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) else {
                continue;
            };
            let Some(&seq) = branch.get(&env.digest) else {
                continue;
            };
            if seq <= shown_seq || env.value.get("kind").and_then(Value::as_str) != Some("activate")
            {
                continue;
            }
            let Some(t) = env
                .value
                .get("transition")
                .and_then(Value::as_str)
                .and_then(|t| decode_base64(t, bounds::TRANSITION_ENVELOPE * 2).ok())
                .and_then(|raw| {
                    AuthEnvelope::parse(
                        &raw,
                        bounds::TRANSITION_ENVELOPE,
                        bounds::TRANSITION_ENVELOPE,
                        true,
                    )
                    .ok()
                })
            else {
                continue;
            };
            let signers: Vec<String> = t
                .value
                .get("signers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if signers.iter().any(|s| local_keys.contains(s)) {
                continue;
            }
            let receipted = env
                .value
                .get("receipts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|r| {
                            let raw =
                                decode_base64(r.as_str()?, bounds::RECEIPT_ENVELOPE * 2).ok()?;
                            let re = crate::v05::signature::RawEnvelope::parse_bounded(
                                &raw,
                                bounds::RECEIPT_BODY,
                                bounds::RECEIPT_ENVELOPE,
                                true,
                            )
                            .ok()?;
                            Some((
                                re.value.get("by")?.as_str()?.to_string(),
                                crate::v05::encoding::parse_date(
                                    re.value.get("received")?.as_str()?,
                                )?,
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            activations.push(SeenActivation {
                seq,
                transition: t.digest.clone(),
                signers,
                components: t
                    .value
                    .get("change")
                    .and_then(Value::as_object)
                    .map(|c| c.keys().cloned().collect())
                    .unwrap_or_default(),
                receipted,
            });
        }
        activations.sort_by_key(|a| a.seq);
        Notices {
            pending,
            activations,
            owed: self.owed_shares(),
            controllers_without_slot: self
                .controllers()
                .into_iter()
                .filter(|c| !c.has_slot && !c.roles.iter().any(|r| r == "sign"))
                .map(|c| c.id)
                .collect(),
            vault_retiring: st.vault_retiring(),
            no_home: st.current_homes().is_empty(),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Namespaces.

    /// Why `namespace` may not be read or written now, as 0.4's `authorize` says it.
    fn authorize(&self, namespace: &str, need: Access) -> Option<Denial> {
        let deny = |r: &str, d: &str| Some(Denial::new(r, d));
        if !self.d.auth.namespaces().iter().any(|n| n == namespace) {
            return deny("notGranted", "The account declares no such namespace");
        }
        match &self.me {
            Identity::Controller(id) => {
                if !self.d.auth.state().keyring().controllers.contains_key(id) {
                    return deny("notGranted", "This key is not a controller of the account");
                }
                if need == Access::Read {
                    None
                } else {
                    deny("notGranted", "A controller does not write records")
                }
            }
            Identity::Member(id) => {
                let Some(m) = self.d.auth.member(id) else {
                    return deny("notGranted", "This key is not a member of the account");
                };
                if m.revoked_seq.is_some() {
                    return deny("revoked", "This member's access was ended");
                }
                if m.expires_ms.is_some_and(|e| self.now_ms > e) {
                    return deny("expired", "This member's access has expired");
                }
                if m.provisional.is_some() {
                    return deny("notGranted", "This member's admission is not final yet");
                }
                let ok = m.terms.records().is_some_and(|r| {
                    r.iter()
                        .any(|e| e.namespace == namespace && e.access >= need)
                });
                if ok {
                    None
                } else {
                    deny("notGranted", "The grant does not include this access")
                }
            }
        }
    }

    fn notreadable(&self, namespace: &str) -> Option<Denial> {
        if self.d.folded.contains_key(namespace) {
            None
        } else {
            Some(Denial::new(
                "notReadable",
                "The namespace key has not been unlocked",
            ))
        }
    }

    /// The folded namespace and the evidence for it: admitted operations in fold order, held
    /// and refused records with their reasons (§11.5), the domain state.
    pub fn view(&self, namespace: &str) -> Result<Outcome<NamespaceView>> {
        if let Some(d) = self.authorize(namespace, Access::Read) {
            return Ok(Outcome::failure(d));
        }
        if let Some(d) = self.notreadable(namespace) {
            return Ok(Outcome::failure(d));
        }
        let folded = &self.d.folded[namespace];
        let mut view = NamespaceView {
            namespace: namespace.into(),
            admitted: folded.admitted.clone(),
            held: Vec::new(),
            refused: Vec::new(),
            state: folded
                .fold
                .query("read", &json!({}))
                .map_err(|e| crate::v05::malformed(e.to_string()))?,
        };
        for j in &self.d.judgement.records {
            let ns_ok = j.namespace.as_deref() == Some(namespace);
            let rej = |reason: String| Rejection {
                id: j.id.clone().unwrap_or_else(|| j.path.clone()),
                author: j.author.clone().unwrap_or_default(),
                reason,
            };
            match &j.outcome {
                Admission::Admitted => {}
                Admission::Held(w) if ns_ok => view.held.push(rej((*w).to_string())),
                Admission::Refused(r) if ns_ok => view.refused.push(rej((*r).to_string())),
                Admission::NewerFormat if ns_ok => view.held.push(rej("newerFormat".into())),
                Admission::Invalid(c)
                    if j.namespace.is_none() && j.path.contains(&format!("/{namespace}/")) =>
                {
                    view.refused.push(rej(c.clone()))
                }
                _ => {}
            }
        }
        Ok(Outcome::success(view))
    }

    /// A bounded projection of a namespace by a domain query (docs/engine.md).
    pub fn query(&self, namespace: &str, name: &str, args: Value) -> Result<Outcome<Value>> {
        if !args.is_object() {
            return Err(crate::v05::malformed("query arguments must be an object"));
        }
        if let Some(d) = self.authorize(namespace, Access::Read) {
            return Ok(Outcome::failure(d));
        }
        if let Some(d) = self.notreadable(namespace) {
            return Ok(Outcome::failure(d));
        }
        match self.d.folded[namespace].fold.query(name, &args) {
            Ok(v) => Ok(Outcome::success(v)),
            Err(e) => Err(crate::v05::malformed(e.to_string())),
        }
    }

    /// The tools this session's terms allow, from the domain modules' specs (0.4's `tools`).
    pub fn tools(&self) -> Vec<Spec> {
        let mut tools = Vec::new();
        let kind = match self.me() {
            Standing::Member(m) => Some(m.member.kind),
            _ => None,
        };
        for ns in domain::NAMESPACES {
            let Some(module) = domain::module(ns) else {
                continue;
            };
            if self.authorize(ns, Access::Read).is_none() {
                for mut spec in module
                    .queries()
                    .into_iter()
                    .chain(crate::imports::query_specs())
                {
                    spec.name = format!("{ns}__{}", spec.name);
                    tools.push(spec);
                }
            }
            if self.authorize(ns, Access::Write).is_none() {
                for mut spec in module.operations() {
                    if kind.is_some_and(|k| !domain::role_allows(ns, &spec.name, k)) {
                        continue;
                    }
                    spec.name = format!("{ns}__{}", spec.name);
                    tools.push(spec);
                }
            }
        }
        tools
    }

    /// Proposals and their standing in `namespace` (§11.6).
    pub fn proposals(&self, namespace: &str) -> Vec<ProposalInfo> {
        self.d
            .judgement
            .proposals
            .iter()
            .filter(|p| p.namespace == namespace)
            .map(|p| {
                let (state, by) = match &p.state {
                    ProposalState::Pending => ("pending", None),
                    ProposalState::Accepted { by, .. } => ("accepted", Some(by.clone())),
                    ProposalState::Declined { by, .. } => ("declined", Some(by.clone())),
                };
                ProposalInfo {
                    namespace: p.namespace.clone(),
                    id: p.id.clone(),
                    proposer: p.proposer.clone(),
                    kind: p.kind.clone(),
                    state: state.into(),
                    by,
                    final_: false,
                }
            })
            .collect()
    }

    /// The plain-language story: authority entries in order, then what each member wrote,
    /// with held and refused records marked.
    pub fn ledger(&self) -> Vec<LedgerEntry> {
        let st = self.d.auth.state();
        let label_of = |id: &str| -> String {
            st.keyring()
                .controllers
                .get(id)
                .map(|c| c.label().to_string())
                .or_else(|| {
                    st.members()
                        .iter()
                        .find(|m| m.request.member_id() == id)
                        .map(|m| m.request.label.clone())
                })
                .unwrap_or_else(|| id.to_string())
        };
        let kinds = entry_kinds(&self.objects, &self.d.verdict.branch);
        let mut by_digest: BTreeMap<String, AuthEnvelope> = BTreeMap::new();
        for b in &self.objects.entries {
            if let Ok(e) = AuthEnvelope::parse(
                b,
                bounds::AUTHORITY_BODY,
                bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) {
                by_digest.insert(e.digest.clone(), e);
            }
        }
        // (cited seq, phase, tie-break) with the line.
        let mut lines: Vec<((u64, u8, String), LedgerEntry)> = Vec::new();
        for (i, d) in self.d.verdict.branch.iter().enumerate() {
            let seq = i as u64 + 1;
            let Some(e) = by_digest.get(d) else { continue };
            let v = &e.value;
            let actor = v
                .get("by")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let who = label_of(&actor);
            let at = v
                .get("issued")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let kind = kinds.get(d).map(String::as_str).unwrap_or("unknown");
            let subject = v.get("member").and_then(Value::as_str).map(str::to_string);
            let (event, text) = match kind {
                "genesis" => (
                    "created",
                    format!("{who} created this account. Its namespaces are sealed with keys only its members hold."),
                ),
                "rekey" => ("rekeyed", format!("{who} introduced new namespace keys.")),
                "grant" => {
                    let granted = v
                        .get("request")
                        .and_then(Value::as_str)
                        .and_then(|r| decode_base64(r, bounds::REQUEST_BODY * 2).ok())
                        .and_then(|r| crate::v05::members::Request::parse(&r, true).ok());
                    match granted {
                        Some(r) => (
                            "granted",
                            format!(
                                "{who} let {} {}.",
                                r.label,
                                english_access(r.terms.records().unwrap_or_default())
                            ),
                        ),
                        None => ("granted", format!("{who} admitted a member.")),
                    }
                }
                "renew" => ("renewed", format!("{who} extended a member's access.")),
                "revoke" => (
                    "revoked",
                    format!(
                        "{who} ended {}'s access.",
                        subject.as_deref().map(label_of).unwrap_or_default()
                    ),
                ),
                "endSessions" => ("sessionsEnded", format!("{who} ended a member's sessions.")),
                "keyring" => ("keyring", format!("{who} changed the keyring.")),
                "vault" => ("vault", format!("{who} rotated the vault.")),
                "suspend" => ("suspended", format!("{who} suspended a key while a change is pending.")),
                "activate" => ("activated", format!("A pending change proposed by {who} took effect.")),
                "vetoed" => ("vetoed", format!("A pending change proposed by {who} was vetoed.")),
                "final" => ("final", "An activation became final.".to_string()),
                other => ("entry", format!("{who} recorded a {other} entry.")),
            };
            lines.push((
                (seq, 0, String::new()),
                LedgerEntry {
                    sequence: 0,
                    at,
                    actor,
                    actor_label: who,
                    event: event.into(),
                    subject,
                    namespace: None,
                    kind: None,
                    origin: None,
                    text,
                },
            ));
        }
        for j in &self.d.judgement.records {
            let (Some(author), Some(ns), Some(id)) = (&j.author, &j.namespace, &j.id) else {
                continue;
            };
            let cited = j
                .plaintext
                .as_ref()
                .and_then(|p| p.get("authority"))
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            let who = label_of(author);
            let origin = self
                .d
                .auth
                .member(author)
                .map(|m| {
                    if m.request.kind == crate::v05::members::MemberKind::Agent {
                        "ai"
                    } else {
                        "person"
                    }
                })
                .unwrap_or("person");
            let kind = j
                .plaintext
                .as_ref()
                .and_then(|p| p.get("kind"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let (event, text) = match &j.outcome {
                Admission::Admitted => {
                    let phrase = kind
                        .as_deref()
                        .and_then(|k| domain::module(ns).and_then(|m| m.write_phrase(k)))
                        .unwrap_or("wrote a record");
                    ("wrote", format!("{who} {phrase}."))
                }
                Admission::Held(w) => ("held", format!("A record by {who} is held: {w}.")),
                Admission::Refused(r) => {
                    ("refused", format!("A record by {who} was refused: {r}."))
                }
                _ => continue,
            };
            lines.push((
                (cited, 1, format!("{:012}-{author}-{id}", j.clock)),
                LedgerEntry {
                    sequence: 0,
                    at: j
                        .plaintext
                        .as_ref()
                        .and_then(|p| p.get("created"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    actor: author.clone(),
                    actor_label: who,
                    event: event.into(),
                    subject: Some(id.clone()),
                    namespace: Some(ns.clone()),
                    kind,
                    origin: Some(origin.into()),
                    text,
                },
            ));
        }
        lines.sort_by(|a, b| a.0.cmp(&b.0));
        lines
            .into_iter()
            .enumerate()
            .map(|(i, (_, mut l))| {
                l.sequence = i as u64 + 1;
                l
            })
            .collect()
    }

    /// Whether the epoch keys for `namespace`'s latest epoch are held (an unlock is done).
    pub fn is_namespace_open(&self, namespace: &str) -> bool {
        self.d.folded.contains_key(namespace)
    }

    /// Whether this session's identity may read `namespace` at all (not whether it holds keys).
    pub fn may_read(&self, namespace: &str) -> bool {
        readable(&self.d.auth, &self.me, namespace)
            && self.authorize(namespace, Access::Read).is_none()
    }

    /// The write access a member needs for `level` of `namespace`.
    pub(super) fn authorize_level(&self, namespace: &str, level: Level) -> Option<Denial> {
        self.authorize(
            namespace,
            match level {
                Level::Write => Access::Write,
                Level::Propose => Access::Propose,
            },
        )
    }

    /// The epoch the head of the history is at for `namespace`, for display.
    pub fn latest_epoch(&self, namespace: &str) -> u64 {
        self.d.auth.latest_epoch(namespace)
    }

    /// The first epoch time field formatted for display: the account's clock as a §2.2 date.
    pub fn now_text(&self) -> String {
        format_date(self.now_ms)
    }
}

/// What a session's identity is in the verified history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Standing {
    /// A controller.
    Controller(ControllerInfo),
    /// A member.
    Member(Box<MemberInfo>),
    /// Not in the verified history (a prospective identity).
    Unknown(String),
}
