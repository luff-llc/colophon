//! Verified authority history, including atomic revoke/rekey and recovery of every epoch.
use crate::{
    crypto::PublicIdentity,
    ensure,
    model::*,
    records::{self, bytes, SignedRecord},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// One signed authority body. Unknown action kinds stop replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorityEntry {
    /// Protocol marker.
    pub protocol: String,
    /// Contiguous sequence from one.
    pub seq: u64,
    /// SHA-256 of the previous exact body (null only at genesis).
    pub previous: Option<String>,
    /// Host-supplied date.
    pub issued: String,
    /// `root` or, only for recovery, `recovery`.
    pub by: String,
    /// Authority action.
    #[serde(flatten)]
    pub action: Action,
}
/// Closed authority vocabulary. Embedded key distributions make changes atomic.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Action {
    /// Initial identities and declared namespaces.
    Genesis {
        /// Human-readable library or replacement-member label.
        label: String,
        #[serde(rename = "ownerLabel")]
        /// Human-readable owner label.
        owner_label: String,
        /// Initial or replacement root public identity.
        root: PublicIdentity,
        /// Independent recovery public identity.
        recovery: PublicIdentity,
        /// Namespaces declared by this library.
        namespaces: Vec<String>,
    },
    /// Introduce consecutive epochs with complete eligible recipient lists.
    Rekey {
        /// Fresh consecutive epochs, each sealed to exactly the eligible recipients.
        epochs: Vec<Epoch>,
    },
    /// Admit a verified request with a possibly narrowed grant and historical key shares.
    Grant {
        #[serde(with = "bytes")]
        /// Exact self-signed access-request envelope.
        request: Vec<u8>,
        /// Approved closed-set restrictions, no broader than the request.
        grant: Grant,
        /// Every existing epoch in scope, sealed to the intended recipient.
        shares: Vec<Epoch>,
    },
    /// End access while keeping acknowledged operations and rotating readable namespaces.
    Revoke {
        #[serde(rename = "memberID")]
        /// Identity whose access ends.
        member_id: String,
        /// Acknowledged authenticated signed-body digests whose admission is preserved.
        kept: BTreeSet<String>,
        /// Fresh consecutive epochs, each sealed to exactly the eligible recipients.
        epochs: Vec<Epoch>,
    },
    /// Planned handover's prerequisite: seal every existing epoch to the new root.
    Reshare {
        /// Prospective root identity receiving historical keys.
        recipient: PublicIdentity,
        /// Human-readable library or replacement-member label.
        label: String,
        /// Every existing epoch in scope, sealed to the intended recipient.
        shares: Vec<Epoch>,
    },
    /// Replace the root only after a verified reshare.
    Handover {
        /// Initial or replacement root public identity.
        root: PublicIdentity,
        /// Acknowledged authenticated signed-body digests whose admission is preserved.
        kept: BTreeSet<String>,
        /// Fresh consecutive epochs, each sealed to exactly the eligible recipients.
        epochs: Vec<Epoch>,
    },
    /// Recovery-signed atomic replacement and redistribution of every recovered epoch.
    Recover {
        /// Initial or replacement root public identity.
        root: PublicIdentity,
        /// Human-readable library or replacement-member label.
        label: String,
        /// Acknowledged authenticated signed-body digests whose admission is preserved.
        kept: BTreeSet<String>,
        /// Every existing epoch in scope, sealed to the intended recipient.
        shares: Vec<Epoch>,
        /// Fresh consecutive epochs, each sealed to exactly the eligible recipients.
        epochs: Vec<Epoch>,
    },
}
/// Internal member identity and admission history, exposed for protocol inspectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberState {
    /// View metadata and grant.
    pub member: Member,
    /// Authenticated public keys.
    pub public: PublicIdentity,
    /// Operations explicitly preserved by revocation.
    pub kept: BTreeSet<String>,
}
/// A verified history produced by `replay`. Deserialized caches require device authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    /// Genesis-body ID.
    pub id: String,
    /// Human library name.
    pub label: String,
    /// Current root public identity.
    pub root: PublicIdentity,
    /// Recovery public identity.
    pub recovery: PublicIdentity,
    /// Declared namespaces.
    pub namespaces: Vec<String>,
    /// Current sequence.
    pub latest: u64,
    /// Digest of latest exact body.
    pub last_digest: String,
    /// Members indexed by signing ID.
    pub members: BTreeMap<String, MemberState>,
    /// Epochs, with the authority sequence at which each was introduced.
    pub epochs: BTreeMap<String, BTreeMap<u64, (u64, Epoch)>>,
    /// Verified entries for ledger generation.
    pub entries: Vec<AuthorityEntry>,
    roots: Vec<(u64, String)>,
    pending_roots: BTreeMap<String, (PublicIdentity, String)>,
}
impl Authority {
    /// Verify the complete contiguous chain. A gap, conflict, unknown kind or bad signature fails.
    pub fn replay(records: &Records) -> Result<Self> {
        let list: Vec<_> = records
            .iter()
            .filter(|(p, _)| p.starts_with("authority/"))
            .collect();
        let (_, first) = list.first().ok_or_else(|| missing("genesis"))?;
        let envelope: SignedRecord = serde_json::from_slice(first)?;
        let entry: AuthorityEntry = serde_json::from_slice(&envelope.body)?;
        ensure(
            entry.seq == 1 && entry.previous.is_none() && entry.by == "root",
            "Invalid genesis",
        )?;
        let Action::Genesis {
            label,
            owner_label,
            root,
            recovery,
            namespaces,
        } = &entry.action
        else {
            return Err(Error("Expected genesis".into()));
        };
        root.validate()?;
        recovery.validate()?;
        ensure(
            root.id() != recovery.id(),
            "Recovery must be a separate identity",
        )?;
        ensure(
            !namespaces.is_empty()
                && namespaces.iter().collect::<BTreeSet<_>>().len() == namespaces.len(),
            "Invalid namespaces",
        )?;
        for ns in namespaces {
            validate_namespace(ns)?;
        }
        let mut members = BTreeMap::new();
        members.insert(
            root.id(),
            MemberState {
                member: Member {
                    id: root.id(),
                    label: owner_label.clone(),
                    kind: MemberKind::Device,
                    grant: None,
                    since: 1,
                    revoked_at: None,
                    writes: 0,
                },
                public: root.clone(),
                kept: BTreeSet::new(),
            },
        );
        let mut state = Self {
            id: records::id(&envelope.body),
            label: label.clone(),
            root: root.clone(),
            recovery: recovery.clone(),
            namespaces: namespaces.clone(),
            latest: 0,
            last_digest: String::new(),
            members,
            epochs: BTreeMap::new(),
            entries: Vec::new(),
            roots: vec![(1, root.id())],
            pending_roots: BTreeMap::new(),
        };
        for (path, raw) in list {
            let record: SignedRecord = serde_json::from_slice(raw)?;
            let entry: AuthorityEntry = serde_json::from_slice(&record.body)?;
            ensure(
                path == &format!("authority/{:08}.json", state.latest + 1),
                "Authority gap or invalid path",
            )?;
            ensure(
                entry.protocol == "colophon/authority/2" && entry.seq == state.latest + 1,
                "Authority version or sequence",
            )?;
            ensure(
                entry.previous
                    == if state.latest == 0 {
                        None
                    } else {
                        Some(state.last_digest.clone())
                    },
                "Authority hash chain",
            )?;
            time_key(&entry.issued)?;
            match entry.by.as_str() {
                "root" => {
                    ensure(
                        !matches!(entry.action, Action::Recover { .. }),
                        "Recovery signer required",
                    )?;
                    record.verify(&state.root.signing)?;
                }
                "recovery" => {
                    ensure(
                        matches!(entry.action, Action::Recover { .. }),
                        "Recovery may only recover",
                    )?;
                    record.verify(&state.recovery.signing)?;
                }
                _ => {
                    return Err(Error(
                        "Unknown authority signer; newer client required".into(),
                    ))
                }
            }
            state.apply(&entry)?;
            state.latest = entry.seq;
            state.last_digest = records::digest(&record.body);
            state.entries.push(entry);
        }
        Ok(state)
    }
    /// Root in force at an authority sequence.
    pub fn root_at(&self, seq: u64) -> Option<&str> {
        self.roots
            .iter()
            .rev()
            .find(|(s, _)| *s <= seq)
            .map(|(_, id)| id.as_str())
    }
    /// Epoch current at an authority sequence.
    pub fn epoch_at(&self, namespace: &str, seq: u64) -> Option<u64> {
        self.epochs
            .get(namespace)?
            .iter()
            .rev()
            .find(|(_, (s, _))| *s <= seq)
            .map(|(e, _)| *e)
    }
    /// HPKE application context, bound to library, namespace, epoch and recipient.
    pub fn key_info(&self, namespace: &str, epoch: u64, recipient: &str) -> Vec<u8> {
        key_info(&self.id, namespace, epoch, recipient)
    }
    fn apply(&mut self, entry: &AuthorityEntry) -> Result<()> {
        match &entry.action {
            Action::Genesis { .. } => ensure(entry.seq == 1, "Repeated genesis")?,
            Action::Rekey { epochs } => self.add_epochs(epochs, entry.seq, &entry.issued)?,
            Action::Grant {
                request,
                grant,
                shares,
            } => {
                let request = verify_request(request, &self.id)?;
                grant.validate()?;
                ensure(
                    !self.members.contains_key(&request.member.id())
                        && request.member.id() != self.recovery.id(),
                    "Member already known",
                )?;
                ensure(
                    grant
                        .namespaces
                        .iter()
                        .all(|n| self.namespaces.contains(n) && request.namespaces.contains(n))
                        && grant.access.iter().all(|a| request.access.contains(a)),
                    "Grant exceeds request",
                )?;
                self.add_shares(shares, &request.member.id(), &grant.namespaces)?;
                let id = request.member.id();
                self.members.insert(
                    id.clone(),
                    MemberState {
                        member: Member {
                            id,
                            label: request.label,
                            kind: request.kind,
                            grant: Some(grant.clone()),
                            since: entry.seq,
                            revoked_at: None,
                            writes: 0,
                        },
                        public: request.member,
                        kept: BTreeSet::new(),
                    },
                );
            }
            Action::Revoke {
                member_id,
                kept,
                epochs,
            } => {
                ensure(member_id != &self.root.id(), "Cannot revoke current root")?;
                let member = self
                    .members
                    .get_mut(member_id)
                    .ok_or_else(|| missing("member"))?;
                ensure(member.member.revoked_at.is_none(), "Already revoked")?;
                let required: BTreeSet<_> = member
                    .member
                    .grant
                    .as_ref()
                    .filter(|g| g.access.contains(&Access::Read))
                    .map(|g| g.namespaces.iter().cloned().collect())
                    .unwrap_or_default();
                ensure(
                    epochs
                        .iter()
                        .map(|e| e.namespace.clone())
                        .collect::<BTreeSet<_>>()
                        == required,
                    "Revoke must rotate every readable namespace",
                )?;
                member.member.revoked_at = Some(entry.seq);
                member.kept = kept.clone();
                self.add_epochs(epochs, entry.seq, &entry.issued)?;
            }
            Action::Reshare {
                recipient,
                label,
                shares,
            } => {
                recipient.validate()?;
                ensure(
                    recipient.id() != self.recovery.id() && recipient.id() != self.root.id(),
                    "Invalid handover target",
                )?;
                self.add_shares(shares, &recipient.id(), &self.namespaces.clone())?;
                self.pending_roots
                    .insert(recipient.id(), (recipient.clone(), label.clone()));
            }
            Action::Handover { root, kept, epochs } => {
                let (shared, label) = self
                    .pending_roots
                    .get(&root.id())
                    .cloned()
                    .ok_or_else(|| missing("prior handover reshare"))?;
                ensure(&shared == root, "Handover identity mismatch")?;
                // New epochs could have arrived since reshare; all must be available before transfer.
                ensure(
                    self.epochs
                        .values()
                        .flat_map(|e| e.values())
                        .all(|(_, e)| e.seals.contains_key(&root.id())),
                    "Handover missing epoch",
                )?;
                self.replace_root(root, &label, kept, entry.seq)?;
                self.replace_epochs(epochs, entry)?;
            }
            Action::Recover {
                root,
                label,
                kept,
                shares,
                epochs,
            } => {
                root.validate()?;
                self.add_shares(shares, &root.id(), &self.namespaces.clone())?;
                self.replace_root(root, label, kept, entry.seq)?;
                self.replace_epochs(epochs, entry)?;
            }
        }
        Ok(())
    }
    fn replace_epochs(&mut self, epochs: &[Epoch], entry: &AuthorityEntry) -> Result<()> {
        ensure(
            epochs.iter().map(|e| &e.namespace).collect::<BTreeSet<_>>()
                == self.namespaces.iter().collect::<BTreeSet<_>>(),
            "Root replacement must rotate every namespace",
        )?;
        self.add_epochs(epochs, entry.seq, &entry.issued)
    }
    fn replace_root(
        &mut self,
        root: &PublicIdentity,
        label: &str,
        kept: &BTreeSet<String>,
        seq: u64,
    ) -> Result<()> {
        ensure(
            root.id() != self.root.id() && root.id() != self.recovery.id(),
            "Invalid replacement root",
        )?;
        let old = self
            .members
            .get_mut(&self.root.id())
            .ok_or_else(|| missing("root member"))?;
        old.member.revoked_at = Some(seq);
        old.kept = kept.clone();
        ensure(
            !self.members.contains_key(&root.id()),
            "Replacement root must be a fresh identity",
        )?;
        self.members.insert(
            root.id(),
            MemberState {
                member: Member {
                    id: root.id(),
                    label: label.into(),
                    kind: MemberKind::Device,
                    grant: None,
                    since: seq,
                    revoked_at: None,
                    writes: 0,
                },
                public: root.clone(),
                kept: BTreeSet::new(),
            },
        );
        self.root = root.clone();
        self.roots.push((seq, root.id()));
        self.pending_roots.clear();
        Ok(())
    }
    /// Eligible recipients for a newly introduced namespace epoch.
    pub fn recipients(&self, namespace: &str, now: &str) -> Result<Vec<PublicIdentity>> {
        let mut recipients = BTreeMap::from([
            (self.root.id(), self.root.clone()),
            (self.recovery.id(), self.recovery.clone()),
        ]);
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
        for epoch in epochs {
            ensure(
                self.namespaces.contains(&epoch.namespace) && seen.insert(&epoch.namespace),
                "Duplicate or undeclared namespace epoch",
            )?;
            ensure(
                epoch.epoch == self.epoch_at(&epoch.namespace, seq).unwrap_or(0) + 1,
                "Epoch must be consecutive",
            )?;
            let required: BTreeSet<_> = self
                .recipients(&epoch.namespace, now)?
                .iter()
                .map(PublicIdentity::id)
                .collect();
            ensure(
                epoch.seals.keys().cloned().collect::<BTreeSet<_>>() == required,
                "Epoch recipient list is incomplete or overbroad",
            )?;
            validate_seals(epoch)?;
            self.epochs
                .entry(epoch.namespace.clone())
                .or_default()
                .insert(epoch.epoch, (seq, epoch.clone()));
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
                    .flat_map(move |epochs| epochs.keys().map(move |e| (n.clone(), *e)))
            })
            .collect();
        let actual: BTreeSet<_> = shares
            .iter()
            .map(|e| (e.namespace.clone(), e.epoch))
            .collect();
        ensure(
            actual == expected && actual.len() == shares.len(),
            "Must reshare every granted historical epoch exactly once",
        )?;
        for share in shares {
            ensure(
                share.seals.len() == 1 && share.seals.contains_key(recipient),
                "Unexpected share recipient",
            )?;
            validate_seals(share)?;
            let (_, epoch) = self
                .epochs
                .get_mut(&share.namespace)
                .and_then(|e| e.get_mut(&share.epoch))
                .ok_or_else(|| missing("shared epoch"))?;
            epoch.seals.extend(share.seals.clone());
        }
        Ok(())
    }
}
fn validate_seals(epoch: &Epoch) -> Result<()> {
    for seal in epoch.seals.values() {
        ensure(
            seal.enc.len() == 65 && seal.enc[0] == 4 && seal.ciphertext.len() == 48,
            "Invalid epoch seal",
        )?;
        p256::PublicKey::from_sec1_bytes(&seal.enc)
            .map_err(|_| Error("Invalid HPKE point".into()))?;
    }
    Ok(())
}
/// HPKE context encoding; fields cannot contain newlines under the namespace and ID rules.
pub fn key_info(library: &str, namespace: &str, epoch: u64, recipient: &str) -> Vec<u8> {
    format!("colophon/epoch/2\n{library}\n{namespace}\n{epoch}\n{recipient}").into_bytes()
}
/// Verify self-signed access request and its library binding before displaying it.
pub fn verify_request(raw: &[u8], library: &str) -> Result<Request> {
    let record: SignedRecord = serde_json::from_slice(raw)?;
    let request: Request = serde_json::from_slice(&record.body)?;
    request.member.validate()?;
    record.verify(&request.member.signing)?;
    ensure(
        request.protocol == "colophon/request/2" && request.library_id == library,
        "Request belongs to another protocol or library",
    )?;
    Grant {
        namespaces: request.namespaces.clone(),
        access: request.access.clone(),
        expires: None,
        write_budget: None,
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
