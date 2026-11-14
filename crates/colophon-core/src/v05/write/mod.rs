//! Colophon 0.5 write side: the bodies a host signs, and the envelopes assembled from what it
//! signed (§17.1, guide §4).
//!
//! Two layers, both sans-IO (no RNG, no clock: seeds, signatures and the time come in):
//!
//! * **Bodies and envelopes.** [`Kind::body`] writes the canonical body of one authority entry
//!   from a [`Header`] and the kind's fields; [`envelope`] assembles an authority-style envelope
//!   (§4.1) from a body and its signatures. Neither looks at any history.
//! * **Prepare, then finish** ([`authority`]). `prepare_*` reads the account's held objects,
//!   chooses the signers a rule needs (§8.4) and returns a [`PendingBatch`] of exact
//!   [`SigningStep`]s. [`PendingBatch::finish`] takes the signatures, assembles the envelopes
//!   and runs `v05::history::verify_history` over the account's objects plus the new one. It
//!   returns [`Records`] only when the verifier says `ok`. Nothing is returned on failure.
//!
//! Other packages add `pub mod calls;` here (links, calls, heads, receipts) at merge.
pub mod authority;

use crate::v05::encoding::{bounds, canonical, encode_base64};
use crate::v05::{malformed, Failure, Result};
use serde_json::{json, Map, Value};

/// The protocol marker of a `/5` authority body.
pub const AUTHORITY_PROTOCOL: &str = "colophon/authority/5";

/// `YYYY-MM-DDTHH:mm:ssZ`, or with `.sss` when the milliseconds are not zero (§2.2).
pub fn format_date(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let frac = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (h, mi, s) = (rem / 3_600, rem % 3_600 / 60, rem % 60);
    if frac == 0 {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{frac:03}Z")
    }
}

/// The header every authority body has (§8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Contiguous from 1.
    pub seq: u64,
    /// SHA-256 hex of the exact preceding body; `None` only at seq 1.
    pub previous: Option<String>,
    /// A §2.2 date.
    pub issued: String,
    /// The primary signer's ID (for a recording entry, the `by` of the embedded object).
    pub by: String,
}

/// A `{namespace, digest}` item of a `revoke`'s `heads` (§9.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptHead {
    /// The namespace.
    pub namespace: String,
    /// The body digest of a header of the revoked member in it.
    pub digest: String,
}

/// An authority entry kind with its fields (§8.2). Embedded envelopes are the raw envelope
/// bytes; they are written as standard padded base64 (§2.2).
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Creates the account. `keyring` is the whole keyring object; its slots are opaque values
    /// built elsewhere.
    Genesis {
        /// 1–200 bytes.
        label: String,
        /// Sorted, distinct namespace names.
        namespaces: Vec<String>,
        /// The keyring (§6.2).
        keyring: Value,
        /// A successor genesis's `predecessor` (§15.1), when there is one.
        predecessor: Option<Value>,
    },
    /// Introduces epochs (§11.1 epoch objects).
    Rekey {
        /// Epoch objects sorted by namespace.
        epochs: Vec<Value>,
    },
    /// Admits a member (§9.2).
    Grant {
        /// The embedded request envelope.
        request: Vec<u8>,
        /// Granted terms.
        terms: Value,
        /// Epoch objects sealing every historical epoch to the member.
        shares: Vec<Value>,
    },
    /// Extends a member's expiry (§9.4).
    Renew {
        /// The member ID.
        member: String,
        /// A §2.2 date.
        expires: String,
        /// Epoch objects.
        shares: Vec<Value>,
    },
    /// Ends a member (§9.5).
    Revoke {
        /// The member ID.
        member: String,
        /// Header-body digests kept explicitly, sorted and distinct.
        kept: Vec<String>,
        /// Heads of the walk, sorted by namespace then digest.
        heads: Vec<KeptHead>,
        /// Epoch objects introduced by the revocation.
        epochs: Vec<Value>,
    },
    /// Ends every link under a member (§9.6).
    EndSessions {
        /// The member ID.
        member: String,
    },
    /// An immediate additive keyring change (§8.4); the whole new keyring.
    Keyring {
        /// The keyring.
        keyring: Value,
    },
    /// Rotates a retiring vault (§8.3).
    Vault {
        /// The new vault's public identity.
        vault: Value,
        /// The new vault's slots.
        slots: Vec<Value>,
        /// The old seed sealed to the new vault.
        previous_vault: Value,
    },
    /// Suspends a key while a transition removing it is pending (§8.7).
    Suspend {
        /// The suspended key's ID.
        key: String,
        /// The embedded transition envelope.
        transition: Vec<u8>,
        /// Its chosen receipts.
        receipts: Vec<Vec<u8>>,
    },
    /// Applies a due transition (§8.7). Unsigned.
    Activate {
        /// The embedded transition envelope.
        transition: Vec<u8>,
        /// Its chosen receipts.
        receipts: Vec<Vec<u8>>,
    },
    /// Records a vetoed transition (§8.7). Unsigned.
    Vetoed {
        /// The embedded transition envelope.
        transition: Vec<u8>,
        /// Its chosen receipts.
        transition_receipts: Vec<Vec<u8>>,
        /// The embedded veto envelope.
        veto: Vec<u8>,
        /// The veto's chosen receipts.
        receipts: Vec<Vec<u8>>,
    },
    /// Records that an activation is final (§8.7). Unsigned.
    Final {
        /// The activation's seq.
        activation_seq: u64,
        /// The activation's body digest.
        activation_digest: String,
        /// Embedded head envelopes, one per witness, sorted by home.
        heads: Vec<Vec<u8>>,
    },
    /// Records a veto of this account's own succession (§15.1). Unsigned.
    SuccessionVetoed {
        /// The embedded veto envelope.
        veto: Vec<u8>,
        /// The veto's receipts.
        receipts: Vec<Vec<u8>>,
        /// Receipts of the genesis.
        genesis_receipts: Vec<Vec<u8>>,
    },
}

fn embed(list: &[Vec<u8>]) -> Value {
    Value::Array(
        list.iter()
            .map(|b| Value::String(encode_base64(b)))
            .collect(),
    )
}

impl Kind {
    /// The `kind` field.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::Rekey { .. } => "rekey",
            Self::Grant { .. } => "grant",
            Self::Renew { .. } => "renew",
            Self::Revoke { .. } => "revoke",
            Self::EndSessions { .. } => "endSessions",
            Self::Keyring { .. } => "keyring",
            Self::Vault { .. } => "vault",
            Self::Suspend { .. } => "suspend",
            Self::Activate { .. } => "activate",
            Self::Vetoed { .. } => "vetoed",
            Self::Final { .. } => "final",
            Self::SuccessionVetoed { .. } => "successionVetoed",
        }
    }
    /// True for `activate`, `vetoed`, `final` and `successionVetoed`: a body only, no signature.
    pub fn is_recording(&self) -> bool {
        matches!(
            self,
            Self::Activate { .. }
                | Self::Vetoed { .. }
                | Self::Final { .. }
                | Self::SuccessionVetoed { .. }
        )
    }
    fn fields(&self) -> Map<String, Value> {
        let mut m = Map::new();
        let mut put = |k: &str, v: Value| {
            m.insert(k.into(), v);
        };
        match self {
            Self::Genesis {
                label,
                namespaces,
                keyring,
                predecessor,
            } => {
                put("label", json!(label));
                put("namespaces", json!(namespaces));
                put("keyring", keyring.clone());
                if let Some(p) = predecessor {
                    put("predecessor", p.clone());
                }
            }
            Self::Rekey { epochs } => put("epochs", Value::Array(epochs.clone())),
            Self::Grant {
                request,
                terms,
                shares,
            } => {
                put("request", json!(encode_base64(request)));
                put("terms", terms.clone());
                put("shares", Value::Array(shares.clone()));
            }
            Self::Renew {
                member,
                expires,
                shares,
            } => {
                put("member", json!(member));
                put("expires", json!(expires));
                put("shares", Value::Array(shares.clone()));
            }
            Self::Revoke {
                member,
                kept,
                heads,
                epochs,
            } => {
                put("member", json!(member));
                put("kept", json!(kept));
                put(
                    "heads",
                    Value::Array(
                        heads
                            .iter()
                            .map(|h| json!({"namespace": h.namespace, "digest": h.digest}))
                            .collect(),
                    ),
                );
                put("epochs", Value::Array(epochs.clone()));
            }
            Self::EndSessions { member } => put("member", json!(member)),
            Self::Keyring { keyring } => put("keyring", keyring.clone()),
            Self::Vault {
                vault,
                slots,
                previous_vault,
            } => {
                put("vault", vault.clone());
                put("slots", Value::Array(slots.clone()));
                put("previousVault", previous_vault.clone());
            }
            Self::Suspend {
                key,
                transition,
                receipts,
            } => {
                put("key", json!(key));
                put("transition", json!(encode_base64(transition)));
                put("receipts", embed(receipts));
            }
            Self::Activate {
                transition,
                receipts,
            } => {
                put("transition", json!(encode_base64(transition)));
                put("receipts", embed(receipts));
            }
            Self::Vetoed {
                transition,
                transition_receipts,
                veto,
                receipts,
            } => {
                put("transition", json!(encode_base64(transition)));
                put("transitionReceipts", embed(transition_receipts));
                put("veto", json!(encode_base64(veto)));
                put("receipts", embed(receipts));
            }
            Self::Final {
                activation_seq,
                activation_digest,
                heads,
            } => {
                put(
                    "activation",
                    json!({"seq": activation_seq, "digest": activation_digest}),
                );
                put("heads", embed(heads));
            }
            Self::SuccessionVetoed {
                veto,
                receipts,
                genesis_receipts,
            } => {
                put("veto", json!(encode_base64(veto)));
                put("receipts", embed(receipts));
                put("genesisReceipts", embed(genesis_receipts));
            }
        }
        m
    }
    /// The canonical body (§2.1) of this entry under `header`: at most 1,048,576 bytes (§2.4),
    /// a genesis only at seq 1 with `previous` null, any other kind never.
    pub fn body(&self, header: &Header) -> Result<Vec<u8>> {
        let genesis = matches!(self, Self::Genesis { .. });
        if genesis != (header.seq == 1) {
            return Err(malformed("only seq 1 is a genesis, and seq 1 must be one"));
        }
        if header.previous.is_none() != genesis {
            return Err(malformed("previous is null at seq 1 and only there"));
        }
        let mut m = self.fields();
        m.insert("protocol".into(), json!(AUTHORITY_PROTOCOL));
        m.insert("seq".into(), json!(header.seq));
        m.insert("previous".into(), json!(header.previous));
        m.insert("issued".into(), json!(header.issued));
        m.insert("by".into(), json!(header.by));
        m.insert("kind".into(), json!(self.name()));
        let body = canonical(&Value::Object(m))?;
        if body.len() > bounds::AUTHORITY_BODY {
            return Err(malformed("authority body exceeds 1,048,576 bytes"));
        }
        Ok(body)
    }
}

/// The canonical body of a transition (§8.7). `signers` is sorted here and must contain `by`.
pub fn transition_body(
    account: &str,
    anchor_seq: u64,
    anchor_digest: &str,
    issued: &str,
    by: &str,
    signers: &[String],
    change: &Value,
) -> Result<Vec<u8>> {
    let mut signers = signers.to_vec();
    signers.sort();
    if !signers.iter().any(|s| s == by) {
        return Err(malformed("signers must contain by"));
    }
    canonical(&json!({
        "protocol": "colophon/transition/5",
        "account": account,
        "anchor": {"seq": anchor_seq, "digest": anchor_digest},
        "issued": issued,
        "by": by,
        "signers": signers,
        "change": change,
    }))
}

/// The canonical body of a veto (§8.7). `signers` is sorted here and must contain `by`.
pub fn veto_body(
    account: &str,
    transition_digest: &str,
    issued: &str,
    by: &str,
    signers: &[String],
) -> Result<Vec<u8>> {
    let mut signers = signers.to_vec();
    signers.sort();
    if !signers.iter().any(|s| s == by) {
        return Err(malformed("signers must contain by"));
    }
    let body = canonical(&json!({
        "protocol": "colophon/veto/5",
        "account": account,
        "transition": transition_digest,
        "issued": issued,
        "by": by,
        "signers": signers,
    }))?;
    if body.len() > bounds::VETO_BODY {
        return Err(malformed("veto body exceeds 4,096 bytes"));
    }
    Ok(body)
}

/// One signature over a body, as the host returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signer's controller (or member) ID.
    pub signer: String,
    /// Raw `r ‖ s`, or the DER signature of a WebAuthn assertion.
    pub signature: Vec<u8>,
    /// `(authenticatorData, clientData)` for a WebAuthn signer; absent for raw.
    pub assertion: Option<(Vec<u8>, Vec<u8>)>,
}

fn sig_item(s: &Signature, with_signer: bool) -> Value {
    let mut m = Map::new();
    if with_signer {
        m.insert("signer".into(), json!(s.signer));
    }
    m.insert("signature".into(), json!(encode_base64(&s.signature)));
    if let Some((data, client)) = &s.assertion {
        m.insert(
            "assertion".into(),
            json!({
                "authenticatorData": encode_base64(data),
                "clientData": encode_base64(client),
            }),
        );
    }
    Value::Object(m)
}

fn sorted_items(list: &[Signature], primary: Option<&str>) -> Result<Option<Value>> {
    if list.is_empty() {
        return Ok(None);
    }
    let mut v: Vec<&Signature> = list.iter().collect();
    v.sort_by(|a, b| a.signer.cmp(&b.signer));
    if v.windows(2).any(|w| w[0].signer == w[1].signer) {
        return Err(malformed("a signer appears twice in one list"));
    }
    if primary.is_some_and(|p| v.iter().any(|s| s.signer == p)) {
        return Err(malformed("a cosignature repeats the primary signer"));
    }
    Ok(Some(Value::Array(
        v.into_iter().map(|s| sig_item(s, true)).collect(),
    )))
}

/// Assemble an authority-style envelope (§4.1): `body`, then the primary `signature` (and
/// `assertion`), `cosignatures`, `additions` and `handover`, each list sorted by signer. A
/// recording entry has no primary and no lists. The result is canonical JSON, so it can be
/// embedded as it is.
pub fn envelope(
    body: &[u8],
    primary: Option<&Signature>,
    cosignatures: &[Signature],
    additions: &[Signature],
    handover: &[Signature],
) -> Result<Vec<u8>> {
    let mut m = Map::new();
    m.insert("body".into(), json!(encode_base64(body)));
    match primary {
        Some(p) => {
            if let Value::Object(item) = sig_item(p, false) {
                m.extend(item);
            }
        }
        None => {
            if !(cosignatures.is_empty() && additions.is_empty() && handover.is_empty()) {
                return Err(malformed("an unsigned envelope carries only its body"));
            }
        }
    }
    let by = primary.map(|p| p.signer.as_str());
    if let Some(v) = sorted_items(cosignatures, by)? {
        m.insert("cosignatures".into(), v);
    }
    if let Some(v) = sorted_items(additions, None)? {
        m.insert("additions".into(), v);
    }
    if let Some(v) = sorted_items(handover, None)? {
        m.insert("handover".into(), v);
    }
    canonical(&Value::Object(m))
}

/// What a signature is for in a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StepRole {
    /// The primary signature: the body's `by`.
    Primary,
    /// A cosignature by another signer toward the rule.
    Cosignature,
    /// A possession proof by a controller the entry adds (`additions`, §8.4).
    Possession,
}

/// One exact body and signer for a host signature. Cosignatures and possession proofs share
/// the primary step's body.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SigningStep {
    /// Where the object will live: `authority/<seq, 8 digits>.json`, or `transitions/<digest>.json`
    /// and `vetoes/<digest>.json` for pending objects.
    pub path: String,
    /// The exact bytes to sign.
    pub body: Vec<u8>,
    /// The signer's controller (or member) ID.
    pub signer: String,
    /// What the signature is for.
    pub role: StepRole,
    /// The signer's key descriptor.
    pub descriptor: crate::v05::descriptor::KeyDescriptor,
    /// The WebAuthn challenge, unpadded base64url SHA-256 of `body`; absent for a raw key.
    pub challenge: Option<String>,
    /// UV is required on this signature (§8.4 "UV").
    pub uv: bool,
}
impl SigningStep {
    pub(crate) fn new(
        path: String,
        body: Vec<u8>,
        signer: String,
        role: StepRole,
        descriptor: crate::v05::descriptor::KeyDescriptor,
        uv: bool,
    ) -> Self {
        let challenge = descriptor
            .webauthn()
            .map(|_| crate::v05::signature::challenge(&body));
        Self {
            path,
            body,
            signer,
            role,
            descriptor,
            challenge,
            uv,
        }
    }
}

/// One host signature, in the order of the batch's steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureResult {
    /// Raw `r ‖ s` (raw key) or DER (WebAuthn).
    pub signature: Vec<u8>,
    /// `(authenticatorData, clientData)` for a WebAuthn signer.
    pub assertion: Option<(Vec<u8>, Vec<u8>)>,
}

/// What a finished batch produces. Returned only when the verifier said `ok`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Records {
    /// Authority entry envelopes with their seq.
    pub entries: Vec<(u64, Vec<u8>)>,
    /// Transition and veto envelopes, held outside the history until recorded.
    pub pending: Vec<Vec<u8>>,
    /// Equivocation evidence objects (§13.3).
    pub evidence: Vec<Vec<u8>>,
}

pub(crate) fn unavailable(why: impl Into<String>) -> Failure {
    Failure::Unavailable(why.into())
}
