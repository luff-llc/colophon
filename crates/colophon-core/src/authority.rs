//! Colophon 0.4 authority verification and keyring transitions.
use crate::{
    crypto::PublicIdentity,
    keys::{strict_json, AuthorityEnvelope, KeyDescriptor, VerifiedSigner},
    model::*,
    protocol,
    records::{self, bytes, SignedRecord},
    slots::{ControllerKey, Slot},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn malformed(reason: impl std::fmt::Display) -> Error {
    Error(format!("malformed: {reason}"))
}
fn bad(reason: impl std::fmt::Display) -> Error {
    Error(format!("badSignature: {reason}"))
}
fn newer(reason: impl std::fmt::Display) -> Error {
    Error(format!("newerFormat: {reason}"))
}
fn require(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(malformed(reason))
    }
}
/// A controller's authority roles, in protocol order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Approve members, revoke members and rekey.
    Approve,
    /// Change the keyring and storage layout.
    Control,
    /// Add recovery controllers under the only-adds rule.
    Recover,
}
/// One authority principal; controllers are never members.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Controller {
    /// Public signing descriptor and optional slot agreement key.
    pub key: KeyDescriptor,
    /// Display label, 1–200 bytes.
    pub label: String,
    /// Strictly sorted nonempty role set.
    pub roles: Vec<Role>,
    /// WebAuthn-only UV requirement, present only as true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<bool>,
}
impl Controller {
    /// Controller signing-key ID.
    pub fn id(&self) -> String {
        self.key.id()
    }
    /// Validate this controller independently of a keyring.
    pub fn validate(&self) -> Result<()> {
        self.key.validate()?;
        require((1..=200).contains(&self.label.len()), "controller label")?;
        require(
            !self.roles.is_empty() && self.roles.windows(2).all(|w| w[0] < w[1]),
            "controller roles",
        )?;
        require(
            self.verification.is_none()
                || (self.verification == Some(true) && self.key.is_webauthn()),
            "verification",
        )
    }
    /// Slot-facing descriptor used by W2's cryptography.
    pub fn slot_key(&self) -> ControllerKey<'_> {
        if self.key.is_webauthn() {
            ControllerKey::Webauthn
        } else {
            ControllerKey::Raw {
                agreement: self.key.agreement(),
            }
        }
    }
}
/// Current authority controllers, signing thresholds, vault and opening routes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Keyring {
    /// Controllers in strictly ascending ID order.
    pub controllers: Vec<Controller>,
    /// Required control signers.
    pub threshold: u64,
    /// Required recovery signers; zero exactly when no recovery role exists.
    pub recover_threshold: u64,
    /// Public identity derived from the vault seed.
    pub vault: PublicIdentity,
    /// Nonempty opening routes; duplicate routes retain multiset significance.
    pub slots: Vec<Slot>,
}
impl Keyring {
    /// Look up a current controller by signing ID.
    pub fn controller(&self, id: &str) -> Option<&Controller> {
        self.controllers.iter().find(|c| c.id() == id)
    }
    /// Validate the closed keyring's structure and slot/controller compatibility.
    pub fn validate(&self) -> Result<()> {
        require(
            !self.controllers.is_empty()
                && self.controllers.windows(2).all(|w| w[0].id() < w[1].id()),
            "controller ordering",
        )?;
        for c in &self.controllers {
            c.validate()?;
        }
        let controls = self
            .controllers
            .iter()
            .filter(|c| c.roles.contains(&Role::Control))
            .count() as u64;
        let recovers = self
            .controllers
            .iter()
            .filter(|c| c.roles.contains(&Role::Recover))
            .count() as u64;
        require(
            self.threshold > 0 && self.threshold <= controls,
            "threshold",
        )?;
        require(
            if recovers == 0 {
                self.recover_threshold == 0
            } else {
                self.recover_threshold > 0 && self.recover_threshold <= recovers
            },
            "recoverThreshold",
        )?;
        self.vault.validate().map_err(malformed)?;
        require(
            self.vault.signing != self.vault.agreement,
            "vault usage collision",
        )?;
        require(!self.slots.is_empty(), "empty slots")?;
        for s in &self.slots {
            s.validate(|id| self.controller(id).map(Controller::slot_key))?;
        }
        Ok(())
    }
}
/// Exact authority/4 body schema, applied only after authorization and unknown-content checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityEntry {
    /// Authority protocol marker.
    pub protocol: String,
    /// Contiguous sequence beginning at one.
    pub seq: u64,
    /// Previous exact body digest; null only at genesis.
    pub previous: Option<String>,
    /// Host-supplied UTC date.
    pub issued: String,
    /// Primary controller ID.
    pub by: String,
    /// Authority transition.
    #[serde(flatten)]
    pub action: Action,
}
/// The six authority/4 transitions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Action {
    /// Create a library with no implicit member or epoch.
    Genesis {
        /// Display label.
        label: String,
        /// Declared namespaces.
        namespaces: Vec<String>,
        /// Initial keyring.
        keyring: Keyring,
        /// Display-only old library ID.
        #[serde(rename = "importedFrom", skip_serializing_if = "Option::is_none")]
        imported_from: Option<String>,
    },
    /// Introduce consecutive namespace epochs.
    Rekey {
        /// Nonempty new epochs.
        epochs: Vec<Epoch>,
    },
    /// Approve a member's self-signed request.
    Grant {
        /// Exact signed raw request envelope.
        #[serde(with = "bytes")]
        request: Vec<u8>,
        /// Approved scope and restrictions, including optional import power.
        grant: Grant,
        /// Historical epoch shares for the member.
        shares: Vec<Epoch>,
    },
    /// Revoke a member and rotate its readable namespaces.
    Revoke {
        /// Revoked member ID.
        #[serde(rename = "memberID")]
        member_id: String,
        /// Accepted operation body digests.
        kept: BTreeSet<String>,
        /// New epochs excluding the revoked member.
        epochs: Vec<Epoch>,
    },
    /// Replace the keyring, optionally rotating the vault and every namespace.
    Keyring {
        /// Replacement keyring.
        keyring: Keyring,
        /// Every historical epoch sealed only to the fresh vault, on rotation.
        #[serde(skip_serializing_if = "Option::is_none")]
        shares: Option<Vec<Epoch>>,
        /// One fresh epoch per namespace, on rotation.
        #[serde(skip_serializing_if = "Option::is_none")]
        epochs: Option<Vec<Epoch>>,
    },
    /// Raise the required storage layout under the control rule.
    Layout {
        /// Required layout number.
        layout: u32,
    },
}
/// A member and its authenticated admission history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberState {
    /// Display metadata and immutable grant.
    pub member: Member,
    /// Member's separate signing and agreement points.
    pub public: PublicIdentity,
    /// Accepted signed-body digests preserved by revocation.
    pub kept: BTreeSet<String>,
}
/// Authenticated contiguous authority history. Persisted caches require device authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    /// Genesis exact-body ID.
    pub id: String,
    /// Library display label.
    pub label: String,
    /// Current keyring.
    pub keyring: Keyring,
    /// Declared namespaces.
    pub namespaces: Vec<String>,
    /// Latest verified sequence.
    pub latest: u64,
    /// Latest exact-body digest.
    pub last_digest: String,
    /// All admitted members, including revoked members.
    pub members: BTreeMap<String, MemberState>,
    /// Epochs and their introducing authority sequences.
    pub epochs: BTreeMap<String, BTreeMap<u64, (u64, Epoch)>>,
    /// Verified typed entries.
    pub entries: Vec<AuthorityEntry>,
    /// Required storage layout.
    pub layout: u32,
    points: BTreeMap<String, (String, String)>,
    ids: BTreeMap<String, (String, String)>,
}
impl Authority {
    /// Verify the chain using §6.3's authorization-before-extension order.
    pub fn replay(records: &Records) -> Result<Self> {
        Self::replay_inner(records).map_err(|e| {
            if ["malformed", "badSignature", "newerFormat"]
                .iter()
                .any(|p| e.0.starts_with(p))
            {
                e
            } else {
                malformed(e)
            }
        })
    }
    fn replay_inner(records: &Records) -> Result<Self> {
        let list: Vec<_> = records
            .iter()
            .filter(|(p, _)| p.starts_with("authority/"))
            .collect();
        let (_, raw) = list.first().ok_or_else(|| malformed("missing genesis"))?;
        let env = AuthorityEnvelope::from_json(raw)?;
        let value = strict_json::parse(&env.body)?;
        header(&value, 1, None)?;
        require(value["kind"] == "genesis", "expected genesis")?;
        // Genesis must expose its authorizing keyring before signatures can be checked.
        // Only unknown content in that keyring is inspected at this stage.
        scan(&serde_json::json!({"kind":"genesis","keyring":value["keyring"]}))?;
        let first: AuthorityEntry = serde_json::from_value(value).map_err(malformed)?;
        let Action::Genesis {
            label,
            namespaces,
            keyring,
            imported_from,
        } = &first.action
        else {
            return Err(malformed("expected genesis"));
        };
        keyring.validate()?;
        require(
            !namespaces.is_empty()
                && namespaces.iter().collect::<BTreeSet<_>>().len() == namespaces.len(),
            "namespaces",
        )?;
        for ns in namespaces {
            validate_namespace(ns)?;
        }
        if let Some(id) = imported_from {
            require(valid_hex(id, 32), "importedFrom")?;
        }
        let mut state = Self {
            id: records::id(&env.body),
            label: label.clone(),
            keyring: keyring.clone(),
            namespaces: namespaces.clone(),
            latest: 0,
            last_digest: String::new(),
            members: BTreeMap::new(),
            epochs: BTreeMap::new(),
            entries: Vec::new(),
            layout: protocol::DEFAULT_LAYOUT,
            points: BTreeMap::new(),
            ids: BTreeMap::new(),
        };
        state.register_keyring(None, keyring, 1)?;
        for (path, raw) in list {
            require(
                path == &format!("authority/{:08}.json", state.latest + 1),
                "authority path or gap",
            )?;
            let env = AuthorityEnvelope::from_json(raw)?;
            let value = strict_json::parse(&env.body)?;
            header(
                &value,
                state.latest + 1,
                if state.latest == 0 {
                    None
                } else {
                    Some(&state.last_digest)
                },
            )?;
            let by = value["by"].as_str().ok_or_else(|| malformed("by"))?;
            // Foreign attached signers, including the primary, always fail as badSignature.
            let signers =
                env.verify_all(|id| state.keyring.controller(id).map(|c| &c.key), false)?;
            for signer in &signers {
                let c = state
                    .keyring
                    .controller(&signer.id)
                    .ok_or_else(|| bad("foreign controller"))?;
                if c.verification == Some(true) && signer.uv != Some(true) {
                    return Err(bad("controller requires UV"));
                }
            }
            require(!by.is_empty(), "by")?;
            authorize(&state.keyring, &value, &signers)?;
            env.check_known_fields()?;
            scan(&value)?;
            reject_nulls(&value, true)?;
            let entry: AuthorityEntry = serde_json::from_value(value).map_err(malformed)?;
            if entry.seq == 2 {
                let Action::Rekey { epochs } = &entry.action else {
                    return Err(malformed("seq 2 must rekey"));
                };
                state.all_namespaces(epochs)?;
                require(epochs.iter().all(|e| e.epoch == 1), "seq 2 epoch 1")?;
            }
            state.apply(&entry)?;
            state.latest = entry.seq;
            state.last_digest = records::digest(&env.body);
            state.entries.push(entry);
        }
        if state.layout > protocol::LAYOUT {
            return Err(newer("storage layout"));
        }
        Ok(state)
    }
    /// Independently reverify an authority prefix (also used by background cache audits).
    pub fn verify_prefix(records: &Records, seq: u64) -> Result<()> {
        let prefix = records
            .iter()
            .filter(|(p, _)| {
                !p.starts_with("authority/") || *p <= &format!("authority/{seq:08}.json")
            })
            .map(|(p, r)| (p.clone(), r.clone()))
            .collect();
        Self::replay(&prefix).map(|_| ())
    }
    /// Epoch current at a signed authority sequence.
    pub fn epoch_at(&self, namespace: &str, seq: u64) -> Option<u64> {
        self.epochs
            .get(namespace)?
            .iter()
            .rev()
            .find(|(_, (s, _))| *s <= seq)
            .map(|(e, _)| *e)
    }
    /// Bound epoch HPKE application context.
    pub fn key_info(&self, namespace: &str, epoch: u64, recipient: &str) -> Vec<u8> {
        key_info(&self.id, namespace, epoch, recipient)
    }
    fn register(&mut self, principal: &str, usage: &str, point: &[u8], repeat: bool) -> Result<()> {
        let owner = (principal.to_owned(), usage.to_owned());
        for (map, key) in [
            (&mut self.points, records::hex(point)),
            (&mut self.ids, records::id(point)),
        ] {
            if let Some(old) = map.get(&key) {
                require(repeat && old == &owner, "one key, one principal and usage")?;
            }
            map.insert(key, owner.clone());
        }
        Ok(())
    }
    fn register_keyring(
        &mut self,
        prior: Option<&Keyring>,
        next: &Keyring,
        seq: u64,
    ) -> Result<()> {
        for c in &next.controllers {
            let repeat = prior.is_some_and(|p| p.controller(&c.id()).is_some());
            let principal = format!("controller:{}", c.id());
            self.register(&principal, "signing", c.key.signing(), repeat)?;
            if let Some(point) = c.key.agreement() {
                self.register(&principal, "agreement", point, repeat)?;
            }
        }
        if prior.is_none_or(|p| p.vault != next.vault) {
            let principal = format!("vault:{seq}");
            self.register(&principal, "signing", &next.vault.signing, false)?;
            self.register(&principal, "agreement", &next.vault.agreement, false)?;
        }
        Ok(())
    }
    fn all_namespaces(&self, epochs: &[Epoch]) -> Result<()> {
        require(
            epochs.len() == self.namespaces.len()
                && epochs.iter().map(|e| &e.namespace).collect::<BTreeSet<_>>()
                    == self.namespaces.iter().collect(),
            "must rotate every namespace",
        )
    }
    fn apply(&mut self, entry: &AuthorityEntry) -> Result<()> {
        match &entry.action {
            Action::Genesis { .. } => require(entry.seq == 1, "repeated genesis")?,
            Action::Rekey { epochs } => {
                require(!epochs.is_empty(), "empty rekey")?;
                self.add_epochs(epochs, entry.seq, &entry.issued)?;
            }
            Action::Grant {
                request,
                grant,
                shares,
            } => {
                let r = verify_request(request, &self.id)?;
                grant.validate()?;
                require(
                    !self.members.contains_key(&r.member.id()),
                    "member already known",
                )?;
                require(
                    grant
                        .namespaces
                        .iter()
                        .all(|n| self.namespaces.contains(n) && r.namespaces.contains(n))
                        && grant.access.iter().all(|a| r.access.contains(a)),
                    "grant exceeds request",
                )?;
                if grant.import.is_some() {
                    require(
                        grant.import == Some(true)
                            && grant.access.contains(&Access::Write)
                            && matches!(r.kind, MemberKind::Device | MemberKind::App),
                        "import grant",
                    )?;
                    require(
                        grant
                            .expires
                            .as_deref()
                            .map(time_key)
                            .transpose()?
                            .is_some_and(|t| {
                                time_key(&entry.issued).is_ok_and(|issued| t > issued)
                            }),
                        "import expiry",
                    )?;
                }
                let principal = format!("member:{}", r.member.id());
                self.register(&principal, "signing", &r.member.signing, false)?;
                self.register(&principal, "agreement", &r.member.agreement, false)?;
                self.add_shares(shares, &r.member.id(), &grant.namespaces)?;
                let id = r.member.id();
                self.members.insert(
                    id.clone(),
                    MemberState {
                        member: Member {
                            id,
                            label: r.label,
                            kind: r.kind,
                            grant: Some(grant.clone()),
                            since: entry.seq,
                            revoked_at: None,
                            writes: 0,
                        },
                        public: r.member,
                        kept: BTreeSet::new(),
                    },
                );
            }
            Action::Revoke {
                member_id,
                kept,
                epochs,
            } => {
                require(kept.iter().all(|d| valid_hex(d, 64)), "kept digest")?;
                let m = self
                    .members
                    .get_mut(member_id)
                    .ok_or_else(|| malformed("unknown member"))?;
                require(m.member.revoked_at.is_none(), "already revoked")?;
                let required: BTreeSet<_> = m
                    .member
                    .grant
                    .as_ref()
                    .filter(|g| g.access.contains(&Access::Read))
                    .map(|g| g.namespaces.iter().cloned().collect())
                    .unwrap_or_default();
                require(
                    epochs
                        .iter()
                        .map(|e| e.namespace.clone())
                        .collect::<BTreeSet<_>>()
                        == required,
                    "revoke namespaces",
                )?;
                m.member.revoked_at = Some(entry.seq);
                m.kept = kept.clone();
                self.add_epochs(epochs, entry.seq, &entry.issued)?;
            }
            Action::Keyring {
                keyring,
                shares,
                epochs,
            } => {
                keyring.validate()?;
                let old = self.keyring.clone();
                let rotated = old.vault != keyring.vault;
                let preserved = preserves_slots(&old.slots, &keyring.slots, false)?;
                let rotation_required = !preserved
                    || old.controllers.iter().any(|c| {
                        keyring.controller(&c.id()).is_none_or(|n| {
                            c.roles.iter().any(|r| !n.roles.contains(r))
                                || c.key.agreement() != n.key.agreement()
                        })
                    });
                require(!rotation_required || rotated, "vault rotation required")?;
                self.register_keyring(Some(&old), keyring, entry.seq)?;
                if rotated {
                    let shares = shares
                        .as_ref()
                        .ok_or_else(|| malformed("rotation shares missing"))?;
                    let epochs = epochs
                        .as_ref()
                        .ok_or_else(|| malformed("rotation epochs missing"))?;
                    self.all_namespaces(epochs)?;
                    self.add_shares(shares, &keyring.vault.id(), &self.namespaces.clone())?;
                    self.keyring = keyring.clone();
                    self.add_epochs(epochs, entry.seq, &entry.issued)?;
                } else {
                    require(
                        shares.is_none() && epochs.is_none() && preserved,
                        "shares or epochs without rotation",
                    )?;
                    self.keyring = keyring.clone();
                }
            }
            Action::Layout { layout } => {
                require(*layout >= 1 && *layout >= self.layout, "layout lowered")?;
                self.layout = *layout;
            }
        }
        Ok(())
    }
    /// Exactly the current vault and active, unexpired readers at introduction time.
    pub fn recipients(&self, namespace: &str, now: &str) -> Result<Vec<PublicIdentity>> {
        let mut recipients =
            BTreeMap::from([(self.keyring.vault.id(), self.keyring.vault.clone())]);
        for m in self.members.values() {
            if m.member.revoked_at.is_none() {
                if let Some(g) = &m.member.grant {
                    if g.allows(namespace, Access::Read) && !expired(&g.expires, now)? {
                        recipients.insert(m.public.id(), m.public.clone());
                    }
                }
            }
        }
        Ok(recipients.into_values().collect())
    }
    fn add_epochs(&mut self, epochs: &[Epoch], seq: u64, now: &str) -> Result<()> {
        let mut seen = BTreeSet::new();
        for e in epochs {
            require(
                self.namespaces.contains(&e.namespace) && seen.insert(&e.namespace),
                "duplicate or undeclared epoch",
            )?;
            require(
                e.epoch
                    == self
                        .epoch_at(&e.namespace, seq)
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or_else(|| malformed("epoch overflow"))?,
                "nonconsecutive epoch",
            )?;
            let required: BTreeSet<_> = self
                .recipients(&e.namespace, now)?
                .iter()
                .map(PublicIdentity::id)
                .collect();
            require(
                e.seals.keys().cloned().collect::<BTreeSet<_>>() == required,
                "epoch recipients",
            )?;
            validate_seals(e)?;
            self.epochs
                .entry(e.namespace.clone())
                .or_default()
                .insert(e.epoch, (seq, e.clone()));
        }
        Ok(())
    }
    fn add_shares(
        &mut self,
        shares: &[Epoch],
        recipient: &str,
        namespaces: &[String],
    ) -> Result<()> {
        let expected: BTreeSet<_> = namespaces
            .iter()
            .flat_map(|n| {
                self.epochs
                    .get(n)
                    .into_iter()
                    .flat_map(move |es| es.keys().map(move |e| (n.clone(), *e)))
            })
            .collect();
        let actual: BTreeSet<_> = shares
            .iter()
            .map(|e| (e.namespace.clone(), e.epoch))
            .collect();
        require(
            actual == expected && actual.len() == shares.len(),
            "historical shares incomplete",
        )?;
        for share in shares {
            require(
                share.seals.len() == 1 && share.seals.contains_key(recipient),
                "share recipient",
            )?;
            validate_seals(share)?;
            let (_, e) = self
                .epochs
                .get_mut(&share.namespace)
                .and_then(|es| es.get_mut(&share.epoch))
                .ok_or_else(|| malformed("unknown shared epoch"))?;
            e.seals.extend(share.seals.clone());
        }
        Ok(())
    }
}
fn valid_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn header(v: &Value, seq: u64, previous: Option<&str>) -> Result<()> {
    require(
        v.is_object() && v["protocol"] == protocol::AUTHORITY && v["seq"].as_u64() == Some(seq),
        "authority header",
    )?;
    require(
        if seq == 1 {
            v.get("previous") == Some(&Value::Null)
        } else {
            v["previous"].as_str() == previous
        },
        "previous digest",
    )?;
    time_key(v["issued"].as_str().ok_or_else(|| malformed("issued"))?).map_err(malformed)?;
    require(v["by"].as_str().is_some_and(|s| valid_hex(s, 32)), "by")?;
    require(v["kind"].is_string(), "kind")
}
fn control(k: &Keyring, s: &[VerifiedSigner]) -> bool {
    s.len() as u64 >= k.threshold
        && s.iter().all(|s| {
            s.uv != Some(false)
                && k.controller(&s.id)
                    .is_some_and(|c| c.roles.contains(&Role::Control))
        })
}
fn authorize(k: &Keyring, v: &Value, s: &[VerifiedSigner]) -> Result<()> {
    let kind = v["kind"].as_str().ok_or_else(|| malformed("kind"))?;
    let allowed = match kind {
        "keyring" => control(k, s) || recovery(k, v, s)?,
        "rekey" | "grant" | "revoke"
            if !(kind == "grant" && v["grant"].get("import").is_some()) =>
        {
            s.len() == 1
                && k.controller(&s[0].id).is_some_and(|c| {
                    c.roles.contains(&Role::Approve)
                        || (kind == "rekey" && c.roles.contains(&Role::Control))
                })
        }
        _ => control(k, s),
    };
    if allowed {
        Ok(())
    } else {
        Err(bad("authority rule"))
    }
}
fn recovery(k: &Keyring, v: &Value, s: &[VerifiedSigner]) -> Result<bool> {
    if k.recover_threshold == 0
        || (s.len() as u64) < k.recover_threshold
        || !s.iter().all(|s| {
            s.uv != Some(false)
                && k.controller(&s.id)
                    .is_some_and(|c| c.roles.contains(&Role::Recover))
        })
    {
        return Ok(false);
    }
    let old = serde_json::to_value(k)?;
    let next = &v["keyring"];
    for f in ["threshold", "recoverThreshold", "vault"] {
        if old[f] != next[f] {
            return Ok(false);
        }
    }
    let Some(cs) = next["controllers"].as_array() else {
        return Ok(false);
    };
    let old_cs = old["controllers"]
        .as_array()
        .ok_or_else(|| malformed("controllers"))?;
    if !old_cs.iter().all(|c| cs.contains(c)) {
        return Ok(false);
    }
    let mut new_ids = BTreeSet::new();
    for c in cs.iter().filter(|c| !old_cs.contains(c)) {
        if k.recover_threshold < k.threshold && c["roles"] != serde_json::json!(["approve"]) {
            return Ok(false);
        }
        let Some(signing) = c["key"]["signing"].as_str() else {
            return Ok(false);
        };
        use base64::Engine;
        let Ok(signing) = base64::engine::general_purpose::STANDARD.decode(signing) else {
            return Ok(false);
        };
        let id = records::id(&signing);
        if k.controller(&id).is_some() {
            return Ok(false);
        }
        new_ids.insert(id);
    }
    let Some(slots) = next["slots"].as_array() else {
        return Ok(false);
    };
    let Some(old_slots) = old["slots"].as_array() else {
        return Ok(false);
    };
    let mut remaining = slots.clone();
    for old in old_slots {
        let Some(i) = remaining.iter().position(|s| s == old) else {
            return Ok(false);
        };
        remaining.remove(i);
    }
    Ok(remaining.iter().all(|s| {
        s["controllers"].as_array().is_some_and(|ids| {
            ids.iter()
                .all(|id| id.as_str().is_some_and(|id| new_ids.contains(id)))
        })
    }))
}
fn preserves_slots(old: &[Slot], new: &[Slot], labels: bool) -> Result<bool> {
    let canonical = |s: &Slot| -> Result<Vec<u8>> {
        let mut v = serde_json::to_value(s)?;
        if !labels {
            if let Some(m) = v.as_object_mut() {
                m.remove("label");
            }
        }
        records::canonical(&v)
    };
    let mut rest = new.iter().map(canonical).collect::<Result<Vec<_>>>()?;
    for s in old {
        let bytes = canonical(s)?;
        let Some(i) = rest.iter().position(|s| s == &bytes) else {
            return Ok(false);
        };
        rest.remove(i);
    }
    Ok(true)
}
fn validate_seals(e: &Epoch) -> Result<()> {
    for s in e.seals.values() {
        require(
            s.enc.len() == 65 && s.enc.first() == Some(&4) && s.ciphertext.len() == 48,
            "epoch seal",
        )?;
        p256::PublicKey::from_sec1_bytes(&s.enc).map_err(malformed)?;
    }
    Ok(())
}
fn closed(v: &Value, fields: &[&str], extension: bool) -> Result<()> {
    let Some(map) = v.as_object() else {
        return if extension {
            Ok(())
        } else {
            Err(malformed("expected object"))
        };
    };
    if map.keys().any(|f| !fields.contains(&f.as_str())) {
        return Err(if extension {
            newer("unknown field")
        } else {
            malformed("unknown field")
        });
    }
    Ok(())
}
fn reject_nulls(v: &Value, top: bool) -> Result<()> {
    match v {
        Value::Null => return Err(malformed("null")),
        Value::Object(m) => {
            for (key, v) in m {
                if top && key == "previous" && v.is_null() {
                    continue;
                }
                reject_nulls(v, false)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                reject_nulls(v, false)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn scan(v: &Value) -> Result<()> {
    let kind = v["kind"].as_str().ok_or_else(|| malformed("kind"))?;
    let fields: &[&str] = match kind {
        "genesis" => &["label", "namespaces", "keyring", "importedFrom"],
        "rekey" => &["epochs"],
        "grant" => &["request", "grant", "shares"],
        "revoke" => &["memberID", "kept", "epochs"],
        "keyring" => &["keyring", "shares", "epochs"],
        "layout" => &["layout"],
        _ => return Err(newer("unknown authority kind")),
    };
    let mut allowed = vec!["protocol", "seq", "previous", "issued", "by", "kind"];
    allowed.extend(fields);
    closed(v, &allowed, true)?;
    if let Some(k) = v.get("keyring") {
        closed(
            k,
            &[
                "controllers",
                "threshold",
                "recoverThreshold",
                "vault",
                "slots",
            ],
            true,
        )?;
        if let Some(cs) = k["controllers"].as_array() {
            for c in cs {
                closed(c, &["key", "label", "roles", "verification"], true)?;
                let key = &c["key"];
                closed(
                    key,
                    &[
                        "form",
                        "signing",
                        "agreement",
                        "rp",
                        "credential",
                        "origins",
                    ],
                    true,
                )?;
                if key["form"]
                    .as_str()
                    .is_some_and(|f| !["raw", "webauthn"].contains(&f))
                {
                    return Err(newer("key form"));
                }
                if let Some(rs) = c["roles"].as_array() {
                    for r in rs {
                        if r.as_str()
                            .is_some_and(|r| !["approve", "control", "recover"].contains(&r))
                        {
                            return Err(newer("role"));
                        }
                    }
                }
            }
        }
        if let Some(v) = k.get("vault") {
            closed(v, &["signing", "agreement"], true)?;
        }
        if let Some(ss) = k["slots"].as_array() {
            for s in ss {
                let fields: &[&str] = match s["kind"].as_str() {
                    Some("sealed") => &["kind", "controllers", "label", "sealed"],
                    Some("prf") => &["kind", "controllers", "label", "salt", "box"],
                    Some("combined") => &["kind", "controllers", "label", "parts", "box"],
                    Some(_) => return Err(newer("slot kind")),
                    None => &[
                        "kind",
                        "controllers",
                        "label",
                        "sealed",
                        "salt",
                        "box",
                        "parts",
                    ],
                };
                closed(s, fields, true)?;
                if let Some(sealed) = s.get("sealed") {
                    closed(sealed, &["enc", "ciphertext"], true)?;
                }
                if let Some(ps) = s["parts"].as_array() {
                    for p in ps {
                        let fields: &[&str] = match p["kind"].as_str() {
                            Some("sealed") => &["kind", "sealed"],
                            Some("prf") => &["kind", "salt"],
                            Some(_) => return Err(newer("part kind")),
                            None => &["kind", "sealed", "salt"],
                        };
                        closed(p, fields, true)?;
                        if let Some(sealed) = p.get("sealed") {
                            closed(sealed, &["enc", "ciphertext"], true)?;
                        }
                    }
                }
            }
        }
    }
    if let Some(g) = v.get("grant") {
        closed(
            g,
            &["namespaces", "access", "expires", "writeBudget", "import"],
            true,
        )?;
    }
    for field in ["epochs", "shares"] {
        if let Some(es) = v[field].as_array() {
            for e in es {
                closed(e, &["namespace", "epoch", "seals"], true)?;
                if let Some(ss) = e["seals"].as_object() {
                    for s in ss.values() {
                        closed(s, &["enc", "ciphertext"], true)?;
                    }
                }
            }
        }
    }
    Ok(())
}
/// Parse a strict single-raw envelope for a request or operation.
/// Authority assertions and cosignatures are never accepted on member records.
pub fn raw_record(raw: &[u8]) -> Result<SignedRecord> {
    let v = strict_json::parse(raw)?;
    closed(&v, &["body", "signature"], false)?;
    let r: SignedRecord = serde_json::from_value(v).map_err(malformed)?;
    strict_json::parse(&r.body)?;
    Ok(r)
}
/// HPKE context encoding; fields cannot contain newlines under the namespace and ID rules.
pub fn key_info(library: &str, namespace: &str, epoch: u64, recipient: &str) -> Vec<u8> {
    format!(
        "{}\n{library}\n{namespace}\n{epoch}\n{recipient}",
        protocol::EPOCH
    )
    .into_bytes()
}
/// Verify self-signed access request and its library binding before displaying it.
pub fn verify_request(raw: &[u8], library: &str) -> Result<Request> {
    let record = raw_record(raw)?;
    let value = strict_json::parse(&record.body)?;
    closed(
        &value,
        &[
            "protocol",
            "libraryID",
            "member",
            "label",
            "kind",
            "namespaces",
            "access",
            "created",
        ],
        false,
    )?;
    closed(&value["member"], &["signing", "agreement"], false)?;
    reject_nulls(&value, false)?;
    let request: Request = serde_json::from_value(value).map_err(malformed)?;
    request.member.validate().map_err(malformed)?;
    require(
        request.member.signing != request.member.agreement,
        "member usage collision",
    )?;
    record.verify(&request.member.signing)?;
    require(
        request.protocol == protocol::REQUEST && request.library_id == library,
        "Request belongs to another protocol or library",
    )?;
    Grant {
        namespaces: request.namespaces.clone(),
        access: request.access.clone(),
        expires: None,
        write_budget: None,
        import: None,
    }
    .validate()?;
    time_key(&request.created)?;
    Ok(request)
}
/// Six-digit code both parties can compute from the library ID and signing key.
pub fn pairing_code(library: &str, signing: &[u8]) -> String {
    let digest = Sha256::digest([library.as_bytes(), signing].concat());
    let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{number:06}")
}
