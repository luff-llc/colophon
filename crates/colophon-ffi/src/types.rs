//! Transport types. Domain payloads and projections remain UTF-8 JSON bytes.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type Records = HashMap<String, Vec<u8>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "lowercase")]
pub enum MemberKind {
    Device,
    App,
    Agent,
    Server,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Person,
    Ai,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "lowercase")]
pub enum LedgerEvent {
    Created,
    Requested,
    Granted,
    Revoked,
    Rekeyed,
    Wrote,
    Held,
    Refused,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "camelCase")]
pub enum DenialReason {
    NotGranted,
    Revoked,
    Expired,
    BudgetSpent,
    NotReadable,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Denial {
    pub reason: DenialReason,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub namespaces: Vec<String>,
    pub access: Vec<Access>,
    pub expires: Option<String>,
    pub write_budget: Option<u64>,
}
/// Omitted scope fields inherit the request; supplied fields must narrow it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct GrantOptions {
    pub namespaces: Option<Vec<String>>,
    pub access: Option<Vec<Access>>,
    pub expires: Option<String>,
    pub write_budget: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: String,
    pub label: String,
    pub kind: MemberKind,
    pub grant: Option<Grant>,
    pub since: u64,
    pub revoked_at: Option<u64>,
    pub writes: u64,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PublicKeys {
    pub signing: Vec<u8>,
    pub agreement: Vec<u8>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct AccessRequest {
    pub id: String,
    pub label: String,
    pub kind: MemberKind,
    pub namespaces: Vec<String>,
    pub access: Vec<Access>,
    pub pairing_code: String,
    pub record: Vec<u8>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OperationView {
    pub id: String,
    pub kind: String,
    pub author: String,
    pub author_label: String,
    pub origin: Origin,
    pub clock: u64,
    pub created: String,
    pub payload: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Rejection {
    pub id: String,
    pub author: String,
    pub reason: String,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct NamespaceView {
    pub namespace: String,
    pub admitted: Vec<OperationView>,
    pub held: Vec<Rejection>,
    pub refused: Vec<Rejection>,
    pub state: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEntry {
    pub sequence: u64,
    pub at: String,
    pub actor: String,
    pub actor_label: String,
    pub event: LedgerEvent,
    pub subject: Option<String>,
    pub namespace: Option<String>,
    pub kind: Option<String>,
    pub origin: Option<Origin>,
    pub text: String,
}
/// Conservative invalidation: all declared namespaces on a record/key change.
/// Revision is local to this session, never a protocol ordering or persistence token.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChangeSummary {
    pub revision: u64,
    pub namespaces: Vec<String>,
    pub records_added: u64,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct SigningStep {
    pub path: String,
    pub body: Vec<u8>,
    pub signing_key: Vec<u8>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct AgreementStep {
    pub namespace: String,
    pub epoch: u64,
    pub peer: Vec<u8>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Vec<u8>,
}
#[derive(Debug, uniffi::Enum)]
pub enum ViewOutcome {
    Success { value: NamespaceView },
    Failure { denial: Denial },
}
#[derive(Debug, uniffi::Enum)]
pub enum OperationOutcome {
    Success { value: OperationView },
    Failure { denial: Denial },
}
#[derive(Debug, uniffi::Enum)]
pub enum PreparedAction {
    Ready {
        action: std::sync::Arc<crate::HostAction>,
    },
    Failure {
        denial: Denial,
    },
}
#[derive(Debug, uniffi::Enum)]
pub enum PreparedCall {
    Read {
        value: Vec<u8>,
    },
    Write {
        action: std::sync::Arc<crate::HostAction>,
    },
    Failure {
        denial: Denial,
    },
}

pub(crate) fn convert<T: Serialize, U: serde::de::DeserializeOwned>(value: T) -> crate::Result<U> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}
impl From<PublicKeys> for colophon_core::crypto::PublicIdentity {
    fn from(value: PublicKeys) -> Self {
        Self {
            signing: value.signing,
            agreement: value.agreement,
        }
    }
}
impl TryFrom<colophon_core::model::AccessRequest> for AccessRequest {
    type Error = crate::BindingError;
    fn try_from(v: colophon_core::model::AccessRequest) -> crate::Result<Self> {
        Ok(Self {
            id: v.id,
            label: v.label,
            kind: convert(v.kind)?,
            namespaces: v.namespaces,
            access: convert(v.access)?,
            pairing_code: v.pairing_code,
            record: v.record,
        })
    }
}
impl TryFrom<colophon_core::model::OperationView> for OperationView {
    type Error = crate::BindingError;
    fn try_from(v: colophon_core::model::OperationView) -> crate::Result<Self> {
        Ok(Self {
            id: v.id,
            kind: v.kind,
            author: v.author,
            author_label: v.author_label,
            origin: convert(v.origin)?,
            clock: v.clock,
            created: v.created,
            payload: serde_json::to_vec(&v.payload)?,
        })
    }
}
impl TryFrom<colophon_core::model::NamespaceView> for NamespaceView {
    type Error = crate::BindingError;
    fn try_from(v: colophon_core::model::NamespaceView) -> crate::Result<Self> {
        Ok(Self {
            namespace: v.namespace,
            admitted: v
                .admitted
                .into_iter()
                .map(TryInto::try_into)
                .collect::<crate::Result<_>>()?,
            held: convert(v.held)?,
            refused: convert(v.refused)?,
            state: serde_json::to_vec(&v.state)?,
        })
    }
}

/// A domain/tool result as UTF-8 JSON, with typed access refusals.
#[derive(Debug, uniffi::Enum)]
pub enum JsonOutcome {
    Success { value: Vec<u8> },
    Failure { denial: Denial },
}
