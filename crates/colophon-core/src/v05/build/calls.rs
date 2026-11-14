//! Call-side builders (§9.1, §12, §13): the request body, links, calls, heads and receipts.
//!
//! Every builder is **prepare, then finish**, as 0.4's `SigningStep` and `SignatureResult` are:
//! `prepare_*` returns the exact body bytes, the signer and (for a WebAuthn signer) the
//! challenge; the host signs; `finish_*` assembles the envelope, runs the matching 0.5
//! verifier over it and returns the envelope bytes only on `ok`. A builder never returns bytes
//! the verifier would refuse. `prepare_*` checks shape and bounds only; authority checks
//! (narrowing, windows, homes) are the verifier's and happen in `finish_*`.
//!
//! No RNG and no clock: request IDs, times and keys come in as arguments. No private key is
//! ever held here.
//!
//! Notices (§17.5) are not built: the spec defines no signed notice object, only host
//! behaviour (push routes, polling, display). See the E3 report.
//!
//! The step and signature-result types below are local to this package; a shared
//! `build/mod.rs` should own them (see the E3 report).
use crate::v05::calls::{verify_call, AccountView, CallConfig};
use crate::v05::encoding::{
    bounds, canonical, date, decode_request_id, digest, encode_base64, encode_base64url,
};
use crate::v05::heads::{verify_head, HeadContext};
use crate::v05::history::home::{finish_receipt as home_finish_receipt, HomeState, ReceiptToSign};
use crate::v05::ids::{is_key_id, key_id, AccountId};
use crate::v05::members::Request;
use crate::v05::replay::MemoryReplayStore;
use crate::v05::signature::{challenge, RawEnvelope};
use crate::v05::terms::{Terms, TermsKind};
use crate::v05::{malformed, require, Failure, Reason, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Most links a call carries (§12.2: `depth` allows at most 4).
pub const MAX_LINKS: usize = 4;

/// What the host must sign: exact bytes, who signs, and the WebAuthn challenge where the
/// signer is a WebAuthn key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningStep {
    /// Where the finished object is stored (host label), or a descriptive name for objects
    /// that are embedded or sent.
    pub path: String,
    /// The exact canonical body bytes to sign.
    pub body: Vec<u8>,
    /// The signer's key ID.
    pub signer: String,
    /// The signer's signing point.
    pub signing: Vec<u8>,
    /// For a WebAuthn signer: the unpadded base64url of SHA-256(body) that `clientData` must
    /// carry (§4.3). `None` for a `raw` signer.
    pub challenge: Option<String>,
}

/// A signature from the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureResult {
    /// `raw`: 64 bytes, `r ‖ s` (§4.2).
    Raw(Vec<u8>),
    /// `webauthn`: the DER signature and the assertion's two byte strings (§4.3).
    WebAuthn {
        /// The DER-encoded ES256 signature.
        signature: Vec<u8>,
        /// `authenticatorData`.
        authenticator_data: Vec<u8>,
        /// `clientData`.
        client_data: Vec<u8>,
    },
}

fn raw_signature(sig: &SignatureResult) -> Result<&[u8]> {
    match sig {
        SignatureResult::Raw(s) if s.len() == 64 => Ok(s),
        SignatureResult::Raw(_) => Err(malformed("a raw signature is 64 bytes")),
        SignatureResult::WebAuthn { .. } => Err(malformed(
            "this object is signed raw, not with an assertion",
        )),
    }
}

/// `{"body","signature"}` as canonical bytes (§4.1, §2.2).
fn raw_envelope(body: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    canonical(&json!({"body": encode_base64(body), "signature": encode_base64(signature)}))
}

fn account_text(account: &AccountId) -> Value {
    Value::String(account.as_str().to_string())
}

fn point(p: &[u8], what: &str) -> Result<()> {
    require(
        crate::v05::descriptor::valid_point(p),
        &format!("{what} is not a valid P-256 point"),
    )
}

// ---------------------------------------------------------------------------------------------
// The request body (§9.1).

/// A membership request to build (§9.1).
#[derive(Clone, Debug)]
pub struct RequestSpec<'a> {
    /// The account asked to admit the member.
    pub account: &'a AccountId,
    /// `member.signing`: also the signer.
    pub signing: &'a [u8],
    /// `member.agreement`.
    pub agreement: &'a [u8],
    /// 1–200 bytes.
    pub label: &'a str,
    /// `device`, `app`, `agent` or `server`.
    pub kind: &'a str,
    /// The terms asked for (§10); must not contain `import`.
    pub terms: Value,
    /// `created`, a §2.2 date.
    pub created: &'a str,
    /// `hardware`, `platform`, `software` or `custodial`.
    pub custody: Option<&'a str>,
    /// Required when `custody` is `custodial`.
    pub operator: Option<&'a str>,
    /// `service.endpoints`: present iff `terms.serves` is, sorted, 1–8 `https://` entries.
    pub endpoints: Option<Vec<String>>,
}

/// A prepared request, to sign `raw` by `member.signing`.
#[derive(Clone, Debug)]
pub struct PreparedRequest {
    /// The step: stored at `requests/<memberID>.json`.
    pub step: SigningStep,
    account: AccountId,
}

/// §9.1: the exact request body and its signer. Shape errors are `malformed` at once; the
/// authoritative check is [`finish_request`].
pub fn prepare_request(spec: &RequestSpec<'_>) -> Result<PreparedRequest> {
    point(spec.signing, "member.signing")?;
    point(spec.agreement, "member.agreement")?;
    date(spec.created, "created")?;
    let mut body = json!({
        "protocol": "colophon/request/5",
        "account": account_text(spec.account),
        "member": {
            "signing": encode_base64(spec.signing),
            "agreement": encode_base64(spec.agreement),
        },
        "label": spec.label,
        "kind": spec.kind,
        "terms": spec.terms,
        "created": spec.created,
    });
    if let Some(c) = spec.custody {
        body["custody"] = json!(c);
    }
    if let Some(o) = spec.operator {
        body["operator"] = json!(o);
    }
    if let Some(e) = &spec.endpoints {
        body["service"] = json!({"endpoints": e});
    }
    let bytes = canonical(&body)?;
    require(
        bytes.len() <= bounds::REQUEST_BODY,
        "request body exceeds its bound",
    )?;
    let id = key_id(spec.signing);
    Ok(PreparedRequest {
        step: SigningStep {
            path: format!("requests/{id}.json"),
            body: bytes,
            signer: id,
            signing: spec.signing.to_vec(),
            challenge: None,
        },
        account: spec.account.clone(),
    })
}

/// Assemble the request envelope, parse it with the 0.5 request parser (shape, terms,
/// signature under `member.signing`) and return it only if it is known content for this
/// account.
pub fn finish_request(prepared: &PreparedRequest, sig: &SignatureResult) -> Result<Vec<u8>> {
    let env = raw_envelope(&prepared.step.body, raw_signature(sig)?)?;
    let request = Request::parse(&env, false)?;
    require(
        request.account == prepared.account && request.body == prepared.step.body,
        "request differs from its preparation",
    )?;
    request.unknown.check()?;
    Ok(env)
}

// ---------------------------------------------------------------------------------------------
// Links (§12.1).

/// What a link narrows: the member (first link) or the previous link.
#[derive(Clone, Copy, Debug)]
pub struct LinkParent<'a> {
    /// The parent's signing point: the member's, or the previous link's `to.signing`. It signs
    /// the link.
    pub signing: &'a [u8],
    /// The parent's terms (the member's, or the previous link's).
    pub terms: &'a Terms,
    /// The parent's expiry in ms: the member's current one, or the previous link's `expires`.
    pub expires_ms: Option<i64>,
    /// `Some(session number)` when this is the first link (the member's current session,
    /// §9.6); `None` for later links.
    pub member_session: Option<u64>,
}

/// A link to build (§12.1).
#[derive(Clone, Debug)]
pub struct LinkSpec<'a> {
    /// The account.
    pub account: &'a AccountId,
    /// The `to.signing` the link grants authority to.
    pub to_signing: &'a [u8],
    /// Link terms (§10.1: no `records`, `expires`, `writes`, `serves` or `import`).
    pub terms: Value,
    /// `session`: exactly on the first link.
    pub session: Option<u64>,
    /// `notBefore`.
    pub not_before: &'a str,
    /// `expires`: at most `notBefore + policy.linkMaxAge`, within the parent's expiry.
    pub expires: &'a str,
    /// `created`.
    pub created: &'a str,
}

/// A prepared link, to sign `raw` by its parent's key.
#[derive(Clone, Debug)]
pub struct PreparedLink {
    /// The step.
    pub step: SigningStep,
    to: Vec<u8>,
    terms: Terms,
    session: Option<u64>,
    not_before_ms: i64,
    expires_ms: i64,
    parent_signing: Vec<u8>,
    parent_terms: Terms,
    parent_expires_ms: Option<i64>,
    parent_session: Option<u64>,
}

/// What a link is checked against at finish.
#[derive(Clone, Copy, Debug)]
pub struct LinkContext<'a> {
    /// The clock, in ms. A link already past `expires` is refused (it could never be used).
    pub now_ms: i64,
    /// `policy.linkMaxAge` in seconds at the state the call will be evaluated at (§18).
    pub link_max_age_s: u64,
    /// Every principal's point in the held history (§3.3 rule 4).
    pub principal_points: &'a BTreeSet<Vec<u8>>,
}

/// §12.1: the exact link body and its signer (the parent's key).
pub fn prepare_link(parent: &LinkParent<'_>, spec: &LinkSpec<'_>) -> Result<PreparedLink> {
    point(parent.signing, "link parent key")?;
    point(spec.to_signing, "to.signing")?;
    let nb = date(spec.not_before, "notBefore")?;
    let exp = date(spec.expires, "expires")?;
    date(spec.created, "created")?;
    require(nb <= exp, "link notBefore is after expires")?;
    require(
        spec.session.is_some() == parent.member_session.is_some(),
        "session is present exactly on the first link",
    )?;
    let terms = Terms::parse(spec.terms.clone(), TermsKind::Link)?;
    let mut body = json!({
        "protocol": "colophon/link/5",
        "account": account_text(spec.account),
        "from": key_id(parent.signing),
        "to": {"signing": encode_base64(spec.to_signing)},
        "terms": spec.terms,
        "notBefore": spec.not_before,
        "expires": spec.expires,
        "created": spec.created,
    });
    if let Some(s) = spec.session {
        body["session"] = json!(s);
    }
    let bytes = canonical(&body)?;
    require(
        bytes.len() <= bounds::LINK_BODY,
        "link body exceeds its bound",
    )?;
    Ok(PreparedLink {
        step: SigningStep {
            path: "link".into(),
            body: bytes,
            signer: key_id(parent.signing),
            signing: parent.signing.to_vec(),
            challenge: None,
        },
        to: spec.to_signing.to_vec(),
        terms,
        session: spec.session,
        not_before_ms: nb,
        expires_ms: exp,
        parent_signing: parent.signing.to_vec(),
        parent_terms: parent.terms.clone(),
        parent_expires_ms: parent.expires_ms,
        parent_session: parent.member_session,
    })
}

/// Assemble the link envelope and check it as §12.3 steps 6 do, link by link: the binding
/// (`badSignature`), `session` (`refused:ended`), window, parent expiry and `linkMaxAge`
/// (`refused:expired`), narrowing (`refused:notNarrower`) and `to.signing` not a principal's
/// point (`malformed`). The returned bytes are the embedded envelope (canonical JSON).
pub fn finish_link(
    prepared: &PreparedLink,
    sig: &SignatureResult,
    ctx: &LinkContext<'_>,
) -> Result<Vec<u8>> {
    let env = raw_envelope(&prepared.step.body, raw_signature(sig)?)?;
    let parsed = RawEnvelope::parse(&env, bounds::LINK_BODY, true)?;
    if parsed.body != prepared.step.body || parsed.verify(&prepared.parent_signing).is_err() {
        return Err(crate::v05::bad_signature(
            "link does not verify under its parent's key",
        ));
    }
    if let Some(expected) = prepared.parent_session {
        if prepared.session != Some(expected) {
            return Err(Failure::Refused(Reason::Ended));
        }
    }
    let span_ms = i128::from(prepared.expires_ms) - i128::from(prepared.not_before_ms);
    let in_time = ctx.now_ms <= prepared.expires_ms
        && prepared
            .parent_expires_ms
            .is_none_or(|e| prepared.expires_ms <= e)
        && span_ms <= i128::from(ctx.link_max_age_s) * 1_000;
    if !in_time {
        return Err(Failure::Refused(Reason::Expired));
    }
    if !prepared.terms.narrows(&prepared.parent_terms) {
        return Err(Failure::Refused(Reason::NotNarrower));
    }
    if ctx.principal_points.contains(&prepared.to) {
        return Err(malformed(
            "a link's to.signing is a principal's key (§3.3 rule 4)",
        ));
    }
    prepared.terms.unknown_outside_conditions().check()?;
    Ok(env)
}

// ---------------------------------------------------------------------------------------------
// Calls (§12.2, §12.3).

/// Who signs a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallSignerSpec {
    /// A member, by ID.
    Member(String),
    /// A controller, by ID.
    Controller(String),
}

/// A call to build (§12.2).
#[derive(Clone, Debug)]
pub struct CallSpec<'a> {
    /// The account.
    pub account: &'a AccountId,
    /// `asOf`: an entry the signer had seen, `(seq, body digest)`.
    pub as_of: (u64, &'a str),
    /// The signer.
    pub signer: CallSignerSpec,
    /// The acting key's signing point.
    pub key: &'a [u8],
    /// The finished link envelopes, member outward; empty for the member's own key and
    /// always for a controller.
    pub links: &'a [Vec<u8>],
    /// `audience`.
    pub audience: &'a str,
    /// `purpose`.
    pub purpose: &'a str,
    /// `args`: a JSON object of at most 16,384 bytes.
    pub args: Value,
    /// `requestId`: 32 random bytes the host supplies.
    pub request_id: [u8; 32],
    /// `created`.
    pub created: &'a str,
    /// True when the acting key is a WebAuthn controller key: the step carries the challenge
    /// and `finish_call` needs an assertion.
    pub webauthn: bool,
}

/// A prepared call.
#[derive(Clone, Debug)]
pub struct PreparedCall {
    /// The step.
    pub step: SigningStep,
    webauthn: bool,
}

/// §12.2: the exact call body and the acting key as signer.
pub fn prepare_call(spec: &CallSpec<'_>) -> Result<PreparedCall> {
    point(spec.key, "key")?;
    date(spec.created, "created")?;
    require(spec.as_of.0 >= 1, "asOf.seq must be at least 1")?;
    require(
        crate::v05::encoding::is_digest(spec.as_of.1),
        "asOf.digest must be 64 lowercase hex",
    )?;
    require(spec.links.len() <= MAX_LINKS, "at most 4 links")?;
    let signer = match &spec.signer {
        CallSignerSpec::Member(id) => {
            require(is_key_id(id), "member ID is not a key ID")?;
            json!({"member": id})
        }
        CallSignerSpec::Controller(id) => {
            require(is_key_id(id), "controller ID is not a key ID")?;
            require(spec.links.is_empty(), "a controller call carries no links")?;
            json!({"controller": id})
        }
    };
    require(
        matches!(spec.signer, CallSignerSpec::Controller(_)) || !spec.webauthn,
        "only a controller's call carries an assertion",
    )?;
    require(spec.args.is_object(), "args must be an object")?;
    require(
        canonical(&spec.args)?.len() <= bounds::CALL_ARGS,
        "args exceed 16,384 bytes",
    )?;
    let request_id = encode_base64url(&spec.request_id);
    decode_request_id(&request_id)?;
    let mut body = json!({
        "protocol": "colophon/call/5",
        "account": account_text(spec.account),
        "asOf": {"seq": spec.as_of.0, "digest": spec.as_of.1},
        "signer": signer,
        "key": encode_base64(spec.key),
        "audience": spec.audience,
        "purpose": spec.purpose,
        "args": spec.args,
        "requestId": request_id,
        "created": spec.created,
    });
    if !spec.links.is_empty() {
        body["links"] = Value::Array(
            spec.links
                .iter()
                .map(|l| Value::String(encode_base64(l)))
                .collect(),
        );
    }
    let bytes = canonical(&body)?;
    require(
        bytes.len() <= bounds::CALL_BODY,
        "call body exceeds its bound",
    )?;
    let challenge = spec.webauthn.then(|| challenge(&bytes));
    Ok(PreparedCall {
        step: SigningStep {
            path: "call".into(),
            body: bytes,
            signer: key_id(spec.key),
            signing: spec.key.to_vec(),
            challenge,
        },
        webauthn: spec.webauthn,
    })
}

/// Assemble the call envelope and run the full call verifier (§12.3) over it, against `view`
/// and `cfg`, with a fresh replay store (the service's store is not touched: that interaction
/// stays the verifier's, §12.4). The bytes are returned only on `ok`.
pub fn finish_call(
    prepared: &PreparedCall,
    sig: &SignatureResult,
    view: &AccountView,
    cfg: &CallConfig<'_>,
) -> Result<Vec<u8>> {
    let env = match (prepared.webauthn, sig) {
        (
            true,
            SignatureResult::WebAuthn {
                signature,
                authenticator_data,
                client_data,
            },
        ) => canonical(&json!({
            "body": encode_base64(&prepared.step.body),
            "signature": encode_base64(signature),
            "assertion": {
                "authenticatorData": encode_base64(authenticator_data),
                "clientData": encode_base64(client_data),
            },
        }))?,
        (true, SignatureResult::Raw(_)) => {
            return Err(malformed("a WebAuthn signer needs an assertion"))
        }
        (false, s) => raw_envelope(&prepared.step.body, raw_signature(s)?)?,
    };
    let mut store = MemoryReplayStore::new();
    let verified = verify_call(&env, view, cfg, &mut store)?;
    require(
        verified.call.digest == digest(&prepared.step.body),
        "verified call differs from its preparation",
    )?;
    Ok(env)
}

// ---------------------------------------------------------------------------------------------
// Heads (§13.2, §13.3).

/// A head to build (§13.2).
#[derive(Clone, Debug)]
pub struct HeadSpec<'a> {
    /// The account.
    pub account: &'a AccountId,
    /// `authority.seq` (at least 1): the highest entry this home has verified.
    pub seq: u64,
    /// `authority.digest`: that entry's body digest. A home that signs two different digests
    /// for one seq equivocates (§13.3); the pair `(by, seq, digest)` is what a verifier
    /// compares.
    pub digest: &'a str,
    /// `issued`.
    pub issued: &'a str,
    /// The home's member ID.
    pub by: &'a str,
}

/// A prepared head, to sign `raw` by the home's member key.
#[derive(Clone, Debug)]
pub struct PreparedHead {
    /// The step. `signing` is empty: the home's key is looked up in the verifier's homes.
    pub step: SigningStep,
}

/// §13.2: the exact head body; the signer is the home member `by`.
pub fn prepare_head(spec: &HeadSpec<'_>) -> Result<PreparedHead> {
    require(spec.seq >= 1, "authority.seq must be at least 1")?;
    require(
        crate::v05::encoding::is_digest(spec.digest),
        "authority.digest must be 64 lowercase hex",
    )?;
    require(is_key_id(spec.by), "by is not a key ID")?;
    date(spec.issued, "issued")?;
    let bytes = canonical(&json!({
        "protocol": "colophon/head/5",
        "account": account_text(spec.account),
        "authority": {"seq": spec.seq, "digest": spec.digest},
        "issued": spec.issued,
        "by": spec.by,
    }))?;
    require(
        bytes.len() <= bounds::HEAD_BODY,
        "head body exceeds its bound",
    )?;
    Ok(PreparedHead {
        step: SigningStep {
            path: format!("heads/{}.json", spec.by),
            body: bytes,
            signer: spec.by.to_string(),
            signing: Vec::new(),
            challenge: None,
        },
    })
}

/// Assemble the head envelope and verify it as §13.3 says against `ctx` (`by` a current home
/// whose key verifies, `issued` not more than 60 s ahead, the held history containing
/// `authority.seq` with that digest). A head for an entry the home has not verified is
/// `unavailable`; a different digest is `refused:fork`.
pub fn finish_head(
    prepared: &PreparedHead,
    sig: &SignatureResult,
    ctx: HeadContext<'_>,
) -> Result<Vec<u8>> {
    let env = raw_envelope(&prepared.step.body, raw_signature(sig)?)?;
    verify_head(&env, ctx)?;
    Ok(env)
}

// ---------------------------------------------------------------------------------------------
// Receipts (§13.5). The body is the one `history::home` asks the host to sign.

/// A receipt to sign, from a home's signing request.
#[derive(Clone, Debug)]
pub struct PreparedReceipt {
    /// The step: stored beside its object as `<home member ID>.receipt.json`.
    pub step: SigningStep,
    /// The receipted object's body digest.
    pub object: String,
}

/// Turn the signing request that `home::admit` returned into a step, unchanged. The body is
/// taken from the request, never rebuilt, so retries reuse the original `received`.
pub fn prepare_receipt(request: &ReceiptToSign) -> Result<PreparedReceipt> {
    let value = crate::v05::encoding::strict_parse(&request.body)?;
    require(
        value.get("protocol").and_then(Value::as_str) == Some("colophon/receipt/5")
            && value.get("object").and_then(Value::as_str) == Some(request.object.as_str()),
        "not this object's receipt body",
    )?;
    let by = value
        .get("by")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("receipt names no home"))?
        .to_string();
    Ok(PreparedReceipt {
        step: SigningStep {
            path: format!("{by}.receipt.json"),
            body: request.body.clone(),
            signer: by,
            signing: Vec::new(),
            challenge: None,
        },
        object: request.object.clone(),
    })
}

/// Assemble the receipt envelope, have the home module verify it (`finish_receipt`: the exact
/// body, the home's key, the 300 s signing window) and return the envelope with the home's
/// next state. Nothing is returned on failure.
pub fn finish_receipt(
    home: &HomeState,
    prepared: &PreparedReceipt,
    sig: &SignatureResult,
    now: &str,
) -> Result<(Vec<u8>, HomeState)> {
    let env = raw_envelope(&prepared.step.body, raw_signature(sig)?)?;
    require(
        env.len() <= bounds::RECEIPT_ENVELOPE,
        "receipt envelope exceeds its bound",
    )?;
    let next = home_finish_receipt(home, &prepared.object, &env, now)?;
    Ok((env, next))
}
