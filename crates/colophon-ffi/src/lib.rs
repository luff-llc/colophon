//! Native transport for the public Colophon core API. No storage, clock, or entropy source.
//! Host calls always happen outside the session mutex. Prepared actions are optimistic:
//! a changed session rejects their commit, so a suspended signer cannot overwrite newer authority.
mod migration;
mod types;
use colophon_core::{
    library::{Call, CreateOptions, Library, PendingBatch},
    model::{self, Outcome},
};
pub use migration::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};
pub use types::*;
uniffi::setup_scaffolding!();

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Error)]
pub enum BindingError {
    InvalidData { detail: String },
    KeyProvider { detail: String },
    StaleAction,
    WrongSession,
    Poisoned,
}
impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData { detail } | Self::KeyProvider { detail } => f.write_str(detail),
            Self::StaleAction => {
                f.write_str("Library changed while signing; prepare again with fresh entropy")
            }
            Self::WrongSession => f.write_str("Action belongs to a different session"),
            Self::Poisoned => f.write_str("Library mutex poisoned"),
        }
    }
}
impl std::error::Error for BindingError {}
impl From<colophon_core::Error> for BindingError {
    fn from(e: colophon_core::Error) -> Self {
        Self::InvalidData {
            detail: e.to_string(),
        }
    }
}
impl From<serde_json::Error> for BindingError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidData {
            detail: e.to_string(),
        }
    }
}
pub type Result<T> = std::result::Result<T, BindingError>;
fn invalid(detail: &str) -> BindingError {
    BindingError::InvalidData {
        detail: detail.into(),
    }
}
fn seed(v: Vec<u8>) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| invalid("Expected a fresh 32-byte action seed"))
}
fn denial(reason: String, detail: String) -> Result<Denial> {
    Ok(Denial {
        reason: types::convert(reason)?,
        detail,
    })
}

/// Local synchronous provider convenience. Remote/asynchronous stores use signing_steps and
/// begin_unlock, await on the platform, then commit / finish_unlock. Never block on async here.
#[uniffi::export(callback_interface)]
pub trait KeyProvider: Send + Sync {
    fn signing_public_key(&self) -> Result<Vec<u8>>;
    fn agreement_public_key(&self) -> Result<Vec<u8>>;
    fn sign(&self, body: Vec<u8>) -> Result<Vec<u8>>;
    fn agree(&self, peer: Vec<u8>) -> Result<Vec<u8>>;
}

#[derive(Debug, uniffi::Object)]
pub struct HostAction {
    pending: PendingBatch,
    session: Option<(u64, u64)>,
}
#[uniffi::export]
impl HostAction {
    pub fn signing_steps(&self) -> Vec<SigningStep> {
        self.pending
            .steps
            .iter()
            .map(|s| SigningStep {
                path: s.path.clone(),
                body: s.body.clone(),
                signing_key: s.signing.clone(),
            })
            .collect()
    }
    /// Verify every host signature, returning an immutable batch for creation or a request.
    /// For a session mutation use commit, which also checks the revision.
    pub fn finish(&self, signatures: Vec<Vec<u8>>) -> Result<Records> {
        Ok(self
            .pending
            .clone()
            .finish(signatures)?
            .into_iter()
            .collect())
    }
    pub fn sign_with(&self, keys: Box<dyn KeyProvider>) -> Result<Vec<Vec<u8>>> {
        let public = keys.signing_public_key()?;
        self.pending
            .steps
            .iter()
            .map(|s| {
                if s.signing != public {
                    return Err(invalid("Unexpected signing identity"));
                }
                keys.sign(s.body.clone())
            })
            .collect()
    }
}

struct Session {
    library: Library,
    revision: u64,
}
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
/// Thread-safe in-memory session. All private keys remain in platform providers.
#[derive(uniffi::Object)]
pub struct NativeLibrary {
    session: Mutex<Session>,
    id: u64,
}
impl NativeLibrary {
    fn lock(&self) -> Result<MutexGuard<'_, Session>> {
        self.session.lock().map_err(|_| BindingError::Poisoned)
    }
    fn prepared(&self, s: &Session, value: Outcome<PendingBatch>) -> Result<PreparedAction> {
        match value {
            Outcome::Success { value, .. } => Ok(PreparedAction::Ready {
                action: Arc::new(HostAction {
                    pending: value,
                    session: Some((self.id, s.revision)),
                }),
            }),
            Outcome::Failure { reason, detail, .. } => Ok(PreparedAction::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    fn summary(s: &Session, records_added: u64, changed: bool) -> ChangeSummary {
        ChangeSummary {
            revision: s.revision,
            namespaces: if changed {
                s.library.authority().namespaces.clone()
            } else {
                vec![]
            },
            records_added,
        }
    }
}
#[uniffi::export]
impl NativeLibrary {
    #[uniffi::constructor]
    pub fn open(records: Records, me: PublicKeys) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            session: Mutex::new(Session {
                library: Library::open(records.into_iter().collect(), me.into())?,
                revision: 0,
            }),
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
        }))
    }
    pub fn id(&self) -> Result<String> {
        Ok(self.lock()?.library.id().into())
    }
    pub fn records(&self) -> Result<Records> {
        Ok(self.lock()?.library.records().clone().into_iter().collect())
    }
    pub fn revision(&self) -> Result<u64> {
        Ok(self.lock()?.revision)
    }
    pub fn me(&self) -> Result<Member> {
        types::convert(self.lock()?.library.me())
    }
    pub fn members(&self) -> Result<Vec<Member>> {
        types::convert(self.lock()?.library.members())
    }
    pub fn ledger(&self) -> Result<Vec<LedgerEntry>> {
        types::convert(self.lock()?.library.ledger())
    }
    /// Applies authority synchronously; call ready/finish_unlock before reading new keys.
    pub fn merge(&self, records: Records) -> Result<ChangeSummary> {
        let mut s = self.lock()?;
        let before = s.library.records().len();
        s.library.merge(records.into_iter().collect())?;
        let added = (s.library.records().len() - before) as u64;
        if added > 0 {
            s.revision += 1;
        }
        Ok(Self::summary(&s, added, added > 0))
    }
    pub fn commit(
        &self,
        action: Arc<HostAction>,
        signatures: Vec<Vec<u8>>,
    ) -> Result<ChangeSummary> {
        // Signature verification is independent of session state and can happen outside its lock.
        let records = action.pending.clone().finish(signatures)?;
        let mut s = self.lock()?;
        let Some((session, revision)) = action.session else {
            return Err(BindingError::WrongSession);
        };
        if session != self.id {
            return Err(BindingError::WrongSession);
        }
        if revision != s.revision {
            return Err(BindingError::StaleAction);
        }
        let before = s.library.records().len();
        s.library.merge(records)?;
        let added = (s.library.records().len() - before) as u64;
        if added > 0 {
            s.revision += 1;
        }
        Ok(Self::summary(&s, added, added > 0))
    }
    pub fn begin_unlock(&self) -> Result<Vec<AgreementStep>> {
        Ok(self
            .lock()?
            .library
            .begin_unlock()
            .into_iter()
            .map(|s| AgreementStep {
                namespace: s.namespace,
                epoch: s.epoch,
                peer: s.peer,
            })
            .collect())
    }
    pub fn finish_unlock(&self, step: AgreementStep, mut shared: Vec<u8>) -> Result<ChangeSummary> {
        let result = (|| {
            let mut s = self.lock()?;
            let pending = s.library.begin_unlock();
            let Some(current) = pending
                .iter()
                .find(|p| p.namespace == step.namespace && p.epoch == step.epoch)
            else {
                return Ok(Self::summary(&s, 0, false));
            };
            if current.peer != step.peer {
                return Err(BindingError::StaleAction);
            }
            s.library
                .finish_unlock(&step.namespace, step.epoch, &shared)?;
            s.revision += 1;
            Ok(ChangeSummary {
                revision: s.revision,
                namespaces: vec![step.namespace],
                records_added: 0,
            })
        })();
        shared.fill(0);
        result
    }
    /// Drives synchronous local callbacks without holding a session lock.
    pub fn ready_with(&self, keys: Box<dyn KeyProvider>) -> Result<ChangeSummary> {
        let identity = { self.lock()?.library.identity().clone() };
        if keys.signing_public_key()? != identity.signing
            || keys.agreement_public_key()? != identity.agreement
        {
            return Err(invalid("Provider does not match this session"));
        }
        let mut changed = false;
        for step in self.begin_unlock()? {
            let secret = keys.agree(step.peer.clone())?;
            self.finish_unlock(step, secret)?;
            changed = true;
        }
        Ok(Self::summary(&*self.lock()?, 0, changed))
    }
    pub fn begin_approve(
        &self,
        request: Vec<u8>,
        grant: Option<GrantOptions>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        let grant = if let Some(g) = grant {
            let info = Library::finish_request(request.clone(), s.library.id())?;
            Some(model::Grant {
                namespaces: g.namespaces.unwrap_or(info.namespaces),
                access: g
                    .access
                    .map(types::convert)
                    .transpose()?
                    .unwrap_or(info.access),
                expires: g.expires,
                write_budget: g.write_budget,
            })
        } else {
            None
        };
        self.prepared(
            &s,
            s.library
                .begin_approve(request, grant, &now, seed(entropy)?)?,
        )
    }
    pub fn begin_revoke(
        &self,
        member_id: String,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.library.begin_revoke(&member_id, &now, seed(entropy)?)?,
        )
    }
    pub fn begin_write(
        &self,
        namespace: String,
        kind: String,
        payload: Vec<u8>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.library.begin_write(
                &namespace,
                &kind,
                serde_json::from_slice(&payload)?,
                &now,
                seed(entropy)?,
            )?,
        )
    }
    pub fn begin_handover(
        &self,
        new_root: PublicKeys,
        label: String,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.library
                .begin_handover(new_root.into(), label, &now, seed(entropy)?)?,
        )
    }
    pub fn begin_recover(
        &self,
        new_root: PublicKeys,
        label: String,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.library
                .begin_recover(new_root.into(), label, &now, seed(entropy)?)?,
        )
    }
    /// Read a named domain query without tool-name collisions or preparing a write.
    pub fn query(
        &self,
        namespace: String,
        name: String,
        arguments: Vec<u8>,
        now: String,
    ) -> Result<JsonOutcome> {
        match self.lock()?.library.query(
            &namespace,
            &name,
            serde_json::from_slice(&arguments)?,
            &now,
        )? {
            Outcome::Success { value, .. } => Ok(JsonOutcome::Success {
                value: serde_json::to_vec(&value)?,
            }),
            Outcome::Failure { reason, detail, .. } => Ok(JsonOutcome::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    pub fn view(&self, namespace: String, now: String) -> Result<ViewOutcome> {
        match self.lock()?.library.view(&namespace, &now)? {
            Outcome::Success { value, .. } => Ok(ViewOutcome::Success {
                value: value.try_into()?,
            }),
            Outcome::Failure { reason, detail, .. } => Ok(ViewOutcome::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    /// Looks up the just-written operation without making the host parse protocol records.
    pub fn written_operation(
        &self,
        action: Arc<HostAction>,
        namespace: String,
        now: String,
    ) -> Result<OperationOutcome> {
        let step = action
            .pending
            .steps
            .first()
            .ok_or_else(|| invalid("Empty action"))?;
        let operation_id = step
            .path
            .rsplit('-')
            .next()
            .and_then(|s| s.strip_suffix(".json"))
            .ok_or_else(|| invalid("Not an operation action"))?;
        match self.view(namespace, now)? {
            ViewOutcome::Failure { denial } => Ok(OperationOutcome::Failure { denial }),
            ViewOutcome::Success { value } => Ok(value
                .admitted
                .into_iter()
                .find(|o| o.id == operation_id)
                .map(|value| OperationOutcome::Success { value })
                .unwrap_or_else(|| OperationOutcome::Failure {
                    denial: Denial {
                        reason: DenialReason::Unavailable,
                        detail: "Signed operation is held or refused under the merged authority"
                            .into(),
                    },
                })),
        }
    }
    /// JSON form of a write-tool result, matching the JavaScript OperationView shape.
    pub fn written_operation_json(
        &self,
        action: Arc<HostAction>,
        namespace: String,
        now: String,
    ) -> Result<JsonOutcome> {
        match self.written_operation(action, namespace, now)? {
            OperationOutcome::Failure { denial } => Ok(JsonOutcome::Failure { denial }),
            OperationOutcome::Success { value } => {
                let payload: serde_json::Value = serde_json::from_slice(&value.payload)?;
                let json = serde_json::json!({"id":value.id, "kind":value.kind, "author":value.author,
                    "authorLabel":value.author_label, "origin":value.origin, "clock":value.clock,
                    "created":value.created, "payload":payload});
                Ok(JsonOutcome::Success {
                    value: serde_json::to_vec(&json)?,
                })
            }
        }
    }
    pub fn tools(&self, now: String) -> Result<Vec<Tool>> {
        self.lock()?
            .library
            .tools(&now)?
            .into_iter()
            .map(|s| {
                Ok(Tool {
                    name: s.name,
                    description: s.description,
                    input_schema: serde_json::to_vec(&s.input_schema)?,
                })
            })
            .collect()
    }
    pub fn begin_call(
        &self,
        tool: String,
        input: Vec<u8>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedCall> {
        let s = self.lock()?;
        match s
            .library
            .begin_call(&tool, serde_json::from_slice(&input)?, &now, seed(entropy)?)?
        {
            Outcome::Success {
                value: Call::Read { value },
                ..
            } => Ok(PreparedCall::Read {
                value: serde_json::to_vec(&value)?,
            }),
            Outcome::Success {
                value: Call::Write { pending },
                ..
            } => Ok(PreparedCall::Write {
                action: Arc::new(HostAction {
                    pending,
                    session: Some((self.id, s.revision)),
                }),
            }),
            Outcome::Failure { reason, detail, .. } => Ok(PreparedCall::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
}
#[uniffi::export]
pub fn begin_create(
    owner: PublicKeys,
    recovery: PublicKeys,
    label: String,
    owner_label: String,
    namespaces: Vec<String>,
    now: String,
    entropy: Vec<u8>,
) -> Result<Arc<HostAction>> {
    Ok(Arc::new(HostAction {
        pending: Library::begin_create(
            CreateOptions {
                owner: owner.into(),
                recovery: recovery.into(),
                label,
                owner_label,
                namespaces,
            },
            &now,
            seed(entropy)?,
        )?,
        session: None,
    }))
}
#[uniffi::export]
pub fn begin_request(
    library_id: String,
    keys: PublicKeys,
    label: String,
    kind: MemberKind,
    namespaces: Vec<String>,
    access: Vec<Access>,
    now: String,
) -> Result<Arc<HostAction>> {
    Ok(Arc::new(HostAction {
        pending: Library::begin_request(model::Request {
            protocol: "colophon/request/2".into(),
            library_id,
            member: keys.into(),
            label,
            kind: types::convert(kind)?,
            namespaces,
            access: types::convert(access)?,
            created: now,
        })?,
        session: None,
    }))
}
#[uniffi::export]
pub fn request_info(record: Vec<u8>, library_id: String) -> Result<AccessRequest> {
    Library::finish_request(record, &library_id)?.try_into()
}
