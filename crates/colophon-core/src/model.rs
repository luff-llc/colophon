//! Public wire and view types shared by native and WebAssembly hosts.
use crate::{crypto::PublicIdentity, ensure, hpke::SealedKey, records::bytes, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Immutable storage paths mapped to exact signed envelope bytes.
pub type Records = BTreeMap<String, Vec<u8>>;
/// The closed set of member kinds. Only `Agent` implies AI authorship.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MemberKind {
    /// A person’s device.
    Device,
    /// An invited application.
    App,
    /// An AI agent; all its writes are attributed AI.
    Agent,
    /// An explicitly granted server or service.
    Server,
}
/// Granted capabilities. Write requires read because writers hold the namespace key.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// May decrypt and query the namespace.
    Read,
    /// May append operations; requires read access.
    Write,
}
/// A closed set of grant restrictions. Unknown restriction fields fail closed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    /// Exact namespace names.
    pub namespaces: Vec<String>,
    /// Read and/or write.
    pub access: Vec<Access>,
    /// Optional UTC ISO 8601 expiry, inclusive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Maximum admitted operations across all granted namespaces, for this member's lifetime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_budget: Option<u64>,
}
impl Grant {
    /// Whether a namespace and capability are included.
    pub fn allows(&self, namespace: &str, access: Access) -> bool {
        self.namespaces.iter().any(|n| n == namespace) && self.access.contains(&access)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure(
            !self.namespaces.is_empty() && !self.access.is_empty(),
            "Empty grant",
        )?;
        ensure(
            !self.access.contains(&Access::Write) || self.access.contains(&Access::Read),
            "Write requires read",
        )?;
        for ns in &self.namespaces {
            validate_namespace(ns)?;
        }
        if let Some(expires) = &self.expires {
            time_key(expires)?;
        }
        Ok(())
    }
}
/// A member as displayed to people (public keys remain in authority records).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    /// Signing-key ID.
    pub id: String,
    /// Human label.
    pub label: String,
    /// Authenticated member kind.
    pub kind: MemberKind,
    /// Null for a root identity.
    pub grant: Option<Grant>,
    /// Authority sequence of admission.
    pub since: u64,
    /// Authority sequence of revocation, if any.
    pub revoked_at: Option<u64>,
    /// Count of admitted signed operations.
    pub writes: u64,
}
/// Request body, signed by the prospective member.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Protocol marker; must be `colophon/request/2`.
    pub protocol: String,
    /// Binds consent to one library.
    #[serde(rename = "libraryID")]
    pub library_id: String,
    /// Requester's public keys.
    pub member: PublicIdentity,
    /// Human label.
    pub label: String,
    /// Requested member kind.
    pub kind: MemberKind,
    /// Requested namespaces.
    pub namespaces: Vec<String>,
    /// Requested capabilities.
    pub access: Vec<Access>,
    /// Host-supplied UTC date.
    pub created: String,
}
/// Signed access request with the six-digit verification code.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRequest {
    /// Requester's ID.
    pub id: String,
    /// Human label.
    pub label: String,
    /// Requested kind.
    pub kind: MemberKind,
    /// Requested namespaces.
    pub namespaces: Vec<String>,
    /// Requested access.
    pub access: Vec<Access>,
    /// Six decimal digits, including leading zeroes.
    pub pairing_code: String,
    /// Signed envelope.
    #[serde(with = "bytes")]
    pub record: Vec<u8>,
}
/// An authenticated epoch with one HPKE seal per eligible identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Epoch {
    /// Namespace.
    pub namespace: String,
    /// Monotonically increasing epoch number, starting at one.
    pub epoch: u64,
    /// Recipient signing ID to HPKE ciphertext.
    pub seals: BTreeMap<String, SealedKey>,
}
/// Exact operation plaintext. Unknown payload fields are preserved.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Operation {
    /// Unique entropy-derived ID.
    pub id: String,
    /// Clean 0.2 domain kind.
    pub kind: String,
    /// Operation version (one).
    pub v: u32,
    /// Logical clock, independent of wall time.
    pub clock: u64,
    /// Latest authority sequence seen by the author.
    pub authority: u64,
    /// Host-supplied UTC date; never used to order.
    pub created: String,
    /// Domain payload, including uninterpreted fields.
    pub payload: Value,
}
/// Public metadata authenticated as AES-GCM AAD and by the author's signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationMeta {
    /// Protocol marker.
    pub protocol: String,
    /// Library binding.
    pub library: String,
    /// Namespace binding.
    pub namespace: String,
    /// Author signing-key ID.
    pub author: String,
    /// Encryption epoch.
    pub epoch: u64,
    /// Plaintext operation ID.
    pub id: String,
    /// Logical clock (public for grant-wide budget evaluation).
    pub clock: u64,
    /// Authority sequence (public for admission without decrypting other namespaces).
    pub authority: u64,
    /// Author's date (public for expiry evaluation).
    pub created: String,
}
/// Signed operation envelope body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationHeader {
    /// Authenticated metadata.
    #[serde(flatten)]
    pub meta: OperationMeta,
    /// Random 96-bit AES-GCM nonce.
    #[serde(with = "bytes")]
    pub nonce: Vec<u8>,
    /// Sealed plaintext, including tag.
    #[serde(with = "bytes")]
    pub ciphertext: Vec<u8>,
}
/// Admitted operation with trusted attribution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OperationView {
    /// Operation ID.
    pub id: String,
    /// Domain kind.
    pub kind: String,
    /// Author ID.
    pub author: String,
    /// Authority-derived label.
    pub author_label: String,
    /// `ai` iff the author is an agent; otherwise `person`.
    pub origin: String,
    /// Logical order.
    pub clock: u64,
    /// Author's timestamp.
    pub created: String,
    /// Exact payload fields.
    pub payload: Value,
}
/// A held or refused operation, with a stable reason code.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rejection {
    /// Operation ID, or path for a malformed envelope.
    pub id: String,
    /// Author if recoverable from the header.
    pub author: String,
    /// Admission reason.
    pub reason: String,
}
/// Folded namespace state and its admission evidence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NamespaceView {
    /// Namespace name.
    pub namespace: String,
    /// Admitted operations in (clock, author, id) order.
    pub admitted: Vec<OperationView>,
    /// Uncertain writes, excluded from the fold.
    pub held: Vec<Rejection>,
    /// Refused writes, excluded from the fold.
    pub refused: Vec<Rejection>,
    /// Domain state.
    pub state: Value,
}
/// Plain-language history. Sequence is deterministic display order, not wall time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEntry {
    /// One-based display sequence.
    pub sequence: u64,
    /// Host date.
    pub at: String,
    /// Actor ID.
    pub actor: String,
    /// Human label.
    pub actor_label: String,
    /// created/requested/granted/revoked/rekeyed/wrote/held/refused.
    pub event: String,
    /// Optional member or operation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Namespace on write entries, from the authenticated header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Operation kind on write entries, when the payload can be authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Authenticated author attribution on write entries: `person` or `ai`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Human-readable description.
    pub text: String,
}
/// Expected access failure, kept distinct from malformed protocol data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Denial {
    /// notGranted/revoked/expired/budgetSpent/notReadable/unavailable.
    pub reason: String,
    /// Plain-language explanation.
    pub detail: String,
}
impl Denial {
    pub(crate) fn new(reason: &str, detail: &str) -> Self {
        Self {
            reason: reason.into(),
            detail: detail.into(),
        }
    }
}
/// JavaScript-compatible outcome shape.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Outcome<T> {
    /// Successful operation (`ok` is true).
    Success {
        /// Always true.
        ok: bool,
        /// Result.
        value: T,
    },
    /// Refused action (`ok` is false).
    Failure {
        /// Always false.
        ok: bool,
        /// Machine-readable reason.
        reason: String,
        /// Human detail.
        detail: String,
    },
}
impl<T> Outcome<T> {
    /// Construct a successful outcome.
    pub fn success(value: T) -> Self {
        Self::Success { ok: true, value }
    }
    /// Construct a refused outcome.
    pub fn failure(denial: Denial) -> Self {
        Self::Failure {
            ok: false,
            reason: denial.reason,
            detail: denial.detail,
        }
    }
}

pub(crate) fn validate_namespace(ns: &str) -> Result<()> {
    ensure(
        !ns.is_empty()
            && ns.len() <= 128
            && ns
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_'),
        "Invalid namespace",
    )
}
/// Parse supported UTC ISO 8601 dates into an orderable, millisecond-precision tuple.
/// Accepts seconds or three fractional digits; no local zones or leap seconds.
pub fn time_key(s: &str) -> Result<[u32; 7]> {
    let b = s.as_bytes();
    ensure(
        (b.len() == 20 || b.len() == 24)
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[b.len() - 1] == b'Z',
        "Expected UTC ISO 8601 date",
    )?;
    let number = |start: usize, end: usize| -> Result<u32> {
        ensure(
            b[start..end].iter().all(u8::is_ascii_digit),
            "Invalid date digits",
        )?;
        b[start..end]
            .iter()
            .try_fold(0u32, |v, c| Ok(v * 10 + u32::from(c - b'0')))
    };
    let [y, m, d, h, min, sec] = [
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    ];
    ensure(
        (1..=12).contains(&m) && h < 24 && min < 60 && sec < 60,
        "Invalid date components",
    )?;
    let days = match m {
        2 => {
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    ensure(d >= 1 && d <= days, "Invalid calendar day")?;
    let ms = if b.len() == 24 {
        ensure(b[19] == b'.', "Invalid fraction")?;
        number(20, 23)?
    } else {
        0
    };
    Ok([y, m, d, h, min, sec, ms])
}
pub(crate) fn expired(expires: &Option<String>, now: &str) -> Result<bool> {
    let now = time_key(now)?;
    expires
        .as_deref()
        .map(time_key)
        .transpose()
        .map(|e| e.is_some_and(|e| now > e))
}
pub(crate) fn missing(what: &str) -> Error {
    Error(format!("Missing {what}"))
}
