//! Authority-style envelopes (§4.1): `body`, and optionally `signature`, `assertion`,
//! `cosignatures`, `additions` and `handover`. Used for authority entries, transitions and
//! vetoes. Recording entries carry only `body`.
use crate::v05::encoding::{canonical_body, decode_base64, strict_parse, Obj};
use crate::v05::ids::is_key_id;
use crate::v05::signature::AssertionBytes;
use crate::v05::{malformed, require, Result};
use serde_json::Value;

/// One signature item.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SigItem {
    /// Signer ID (for the primary signature: the body's `by`).
    pub signer: String,
    /// Signature bytes (raw 64 or DER).
    pub signature: Vec<u8>,
    /// `(authenticatorData, clientData)` for a WebAuthn signer.
    pub assertion: Option<(Vec<u8>, Vec<u8>)>,
}
impl SigItem {
    /// The assertion as borrowed bytes.
    pub fn assertion_bytes(&self) -> Option<AssertionBytes<'_>> {
        self.assertion.as_ref().map(|(d, c)| AssertionBytes {
            authenticator_data: d,
            client_data: c,
        })
    }
}

/// A parsed authority-style envelope.
#[derive(Clone, Debug)]
pub struct AuthEnvelope {
    /// Exact body bytes.
    pub body: Vec<u8>,
    /// The parsed body.
    pub value: Value,
    /// Body digest.
    pub digest: String,
    /// The primary signature, when present (its `signer` is filled in from the body's `by`).
    pub primary: Option<SigItem>,
    /// Cosignatures, sorted by signer.
    pub cosignatures: Vec<SigItem>,
    /// Possession proofs, sorted by signer.
    pub additions: Vec<SigItem>,
    /// Hand-over signatures (only on a successor genesis).
    pub handover: Vec<SigItem>,
}

fn assertion(o: &mut Obj) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    match o.opt_obj("assertion")? {
        None => Ok(None),
        Some(mut a) => {
            // Bounds are checked here: an oversized clientData is malformed in every envelope.
            let data = a.bytes(
                "authenticatorData",
                crate::v05::encoding::bounds::CLIENT_DATA,
            )?;
            let client = a.bytes("clientData", crate::v05::encoding::bounds::CLIENT_DATA)?;
            a.finish_closed()?;
            Ok(Some((data, client)))
        }
    }
}
fn items(o: &mut Obj, field: &str) -> Result<Vec<SigItem>> {
    let Some(list) = o.opt_nonempty_array(field)? else {
        return Ok(Vec::new());
    };
    let mut out: Vec<SigItem> = Vec::with_capacity(list.len());
    for v in list {
        let mut i = Obj::new(v, field)?;
        let signer = i.key_id("signer")?;
        let signature = i.bytes("signature", 80)?;
        let assertion = assertion(&mut i)?;
        i.finish_closed()?;
        out.push(SigItem {
            signer,
            signature,
            assertion,
        });
    }
    require(
        out.windows(2).all(|w| w[0].signer < w[1].signer),
        &format!("{field} must be sorted by signer and distinct"),
    )?;
    Ok(out)
}

impl AuthEnvelope {
    /// Parse an envelope within `envelope_bound` bytes whose body is canonical and within
    /// `body_bound`. With `embedded`, the envelope bytes must be canonical too (§2.2).
    pub fn parse(
        bytes: &[u8],
        body_bound: usize,
        envelope_bound: usize,
        embedded: bool,
    ) -> Result<Self> {
        require(bytes.len() <= envelope_bound, "envelope exceeds its bound")?;
        let outer = if embedded {
            canonical_body(bytes, envelope_bound)?
        } else {
            strict_parse(bytes)?
        };
        let mut o = Obj::new(outer, "envelope")?;
        let body = decode_base64(&o.string("body")?, body_bound)?;
        let primary_sig = o.opt_bytes("signature", 80)?;
        let primary_assertion = assertion(&mut o)?;
        let cosignatures = items(&mut o, "cosignatures")?;
        let additions = items(&mut o, "additions")?;
        let handover = items(&mut o, "handover")?;
        o.finish_closed()?;
        let value = canonical_body(&body, body_bound)?;
        let by = value
            .get("by")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let primary = match primary_sig {
            Some(signature) => Some(SigItem {
                signer: by.clone(),
                signature,
                assertion: primary_assertion,
            }),
            None => {
                require(primary_assertion.is_none(), "assertion without a signature")?;
                None
            }
        };
        require(
            cosignatures.iter().all(|c| c.signer != by),
            "cosignatures must be distinct from by",
        )?;
        if primary.is_none() {
            require(
                cosignatures.is_empty() && additions.is_empty() && handover.is_empty(),
                "an unsigned envelope carries only its body",
            )?;
        }
        if !by.is_empty() {
            require(is_key_id(&by), "by is not a key ID")?;
        }
        Ok(Self {
            digest: crate::v05::encoding::digest(&body),
            body,
            value,
            primary,
            cosignatures,
            additions,
            handover,
        })
    }
    /// The primary signer and cosigners, sorted (the transition's `signers`, §8.7).
    pub fn signer_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .primary
            .iter()
            .chain(&self.cosignatures)
            .map(|s| s.signer.clone())
            .collect();
        v.sort();
        v
    }
}

/// Decode an embedded envelope string field (§2.2).
pub fn embedded_bytes(v: &Value, field: &str, bound: usize) -> Result<Vec<u8>> {
    match v {
        Value::String(s) => decode_base64(s, bound),
        _ => Err(malformed(format!("{field} must be an embedded envelope"))),
    }
}
