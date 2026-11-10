//! Raw ES256 delegation links, proofs, signed requests and §5.3's pure six-step check.
use super::{terms::Terms, timestamp, Refusal, Verdict};
use crate::{keys, records};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};

type CheckResult<T> = std::result::Result<T, Verdict>;

fn obj(v: &Value) -> CheckResult<&Map<String, Value>> {
    v.as_object().ok_or(Verdict::Malformed)
}
fn field<'a>(v: &'a Map<String, Value>, k: &str) -> CheckResult<&'a Value> {
    v.get(k).ok_or(Verdict::Malformed)
}
fn str_field<'a>(v: &'a Map<String, Value>, k: &str) -> CheckResult<&'a str> {
    field(v, k)?.as_str().ok_or(Verdict::Malformed)
}
fn number(v: &Value) -> CheckResult<u64> {
    v.as_u64().ok_or(Verdict::Malformed)
}
fn hex_id(s: &str, size: usize) -> bool {
    s.len() == size && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn check_hex(s: &str, size: usize) -> CheckResult<String> {
    if hex_id(s, size) { Ok(s.into()) } else { Err(Verdict::Malformed) }
}
fn bytes(v: &Value) -> CheckResult<Vec<u8>> {
    let s = v.as_str().ok_or(Verdict::Malformed)?;
    let decoded = STANDARD.decode(s).map_err(|_| Verdict::Malformed)?;
    if STANDARD.encode(&decoded) != s { return Err(Verdict::Malformed); }
    Ok(decoded)
}
fn point(v: &Value) -> CheckResult<Vec<u8>> {
    let key = bytes(v)?;
    if key.len() != 65 || key[0] != 4
        || p256::PublicKey::from_sec1_bytes(&key).is_err()
    {
        return Err(Verdict::Malformed);
    }
    Ok(key)
}
fn valid_date(s: &str) -> CheckResult<String> {
    timestamp(s).ok_or(Verdict::Malformed)?;
    Ok(s.into())
}
fn known(o: &Map<String, Value>, names: &[&str]) -> CheckResult<()> {
    if o.keys().any(|key| !names.contains(&key.as_str())) {
        Err(Verdict::NewerFormat)
    } else {
        Ok(())
    }
}

/// A raw ES256 envelope; body bytes are authenticated exactly as received, never rewritten.
#[derive(Clone, Debug, PartialEq)]
pub struct RawEnvelope {
    /// Exact original signed JSON body bytes.
    pub body: Vec<u8>,
    /// Raw 64-byte P-256 signature.
    pub signature: Vec<u8>,
    extra: Map<String, Value>,
}
impl RawEnvelope {
    /// Parse and preserve an envelope's unknown fields until after signature verification.
    pub fn from_json(bytes: &[u8]) -> CheckResult<Self> {
        let v = keys::strict_json::parse(bytes).map_err(|_| Verdict::Malformed)?;
        let mut m = obj(&v)?.clone();
        let body = bytes_field(&mut m, "body")?;
        let signature = bytes_field(&mut m, "signature")?;
        Ok(Self { body, signature, extra: m })
    }
    /// Begin a two-phase host signature: returns the exact bytes the host must sign.
    pub fn begin(body: &Value) -> CheckResult<Vec<u8>> {
        records::canonical(body).map_err(|_| Verdict::Malformed)
    }
    /// Finish a host signature, verifying it before returning the envelope.
    pub fn finish(body: Vec<u8>, signature: Vec<u8>, signing: &[u8]) -> CheckResult<Self> {
        let envelope = Self { body, signature, extra: Map::new() };
        envelope.verify(signing)?;
        Ok(envelope)
    }
    /// Verify the raw ES256 signature using Colophon 0.4's verifier.
    pub fn verify(&self, signing: &[u8]) -> CheckResult<()> {
        keys::verify_raw(signing, &self.body, &self.signature)
            .map_err(|_| Verdict::BadSignature)
    }
    /// Emit the canonical envelope, with the exact original body bytes still encoded in base64.
    pub fn encode(&self) -> CheckResult<Vec<u8>> {
        records::canonical(&self.to_value()).map_err(|_| Verdict::Malformed)
    }
    fn to_value(&self) -> Value {
        let mut o = self.extra.clone();
        o.insert("body".into(), json!(STANDARD.encode(&self.body)));
        o.insert("signature".into(), json!(STANDARD.encode(&self.signature)));
        Value::Object(o)
    }
    fn has_unknown_fields(&self) -> bool {
        !self.extra.is_empty()
    }
}
fn bytes_field(m: &mut Map<String, Value>, field: &str) -> CheckResult<Vec<u8>> {
    bytes(&m.remove(field).ok_or(Verdict::Malformed)?)
}

/// Delegation target; ECDH agreement is optional and never used to authenticate a link.
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    /// The next holder's uncompressed P-256 signing point.
    pub signing: Vec<u8>,
    /// Optional ECDH point for out-of-band epoch delivery.
    pub agreement: Option<Vec<u8>>,
}
impl Target {
    fn from_value(v: &Value) -> CheckResult<Self> {
        let o = obj(v)?;
        known(o, &["signing", "agreement"])?;
        Ok(Self {
            signing: point(field(o, "signing")?)?,
            agreement: o.get("agreement").map(point).transpose()?,
        })
    }
    fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("signing".into(), json!(STANDARD.encode(&self.signing)));
        if let Some(agreement) = &self.agreement {
            o.insert("agreement".into(), json!(STANDARD.encode(agreement)));
        }
        Value::Object(o)
    }
}

/// Canonical `colophon/link/5` body (the envelope is signed by `from`).
#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    /// Full 64-character account digest.
    pub account: String,
    /// Key ID of the preceding signing key.
    pub from: String,
    /// Next signing key and optional agreement key.
    pub to: Target,
    /// Member session number, only on the first link.
    pub session: Option<u64>,
    /// Narrowed grant.
    pub terms: Terms,
    /// Inclusive start of this delegation.
    pub not_before: String,
    /// Inclusive expiry of this delegation.
    pub expires: String,
    /// Claimed creation date.
    pub created: String,
}
impl Link {
    /// Parse a strict link body, including terms and all known fields.
    /// Call only after its envelope has verified.
    pub fn from_value(v: &Value) -> CheckResult<Self> {
        let o = obj(v)?;
        known(o, &["protocol", "account", "from", "to", "session", "terms",
            "notBefore", "expires", "created"])?;
        if str_field(o, "protocol")? != "colophon/link/5" { return Err(Verdict::NewerFormat); }
        Ok(Self {
            account: check_hex(str_field(o, "account")?, 64)?,
            from: check_hex(str_field(o, "from")?, 32)?,
            to: Target::from_value(field(o, "to")?)?,
            session: o.get("session").map(number).transpose()?,
            terms: Terms::from_value(field(o, "terms")?)?,
            not_before: valid_date(str_field(o, "notBefore")?)?,
            expires: valid_date(str_field(o, "expires")?)?,
            created: valid_date(str_field(o, "created")?)?,
        })
    }
    /// Canonical value for a new, locally constructed delegation.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("protocol".into(), json!("colophon/link/5"));
        o.insert("account".into(), json!(self.account));
        o.insert("from".into(), json!(self.from));
        o.insert("to".into(), self.to.to_value());
        o.insert("terms".into(), self.terms.to_value());
        o.insert("notBefore".into(), json!(self.not_before));
        o.insert("expires".into(), json!(self.expires));
        o.insert("created".into(), json!(self.created));
        if let Some(session) = self.session { o.insert("session".into(), json!(session)); }
        Value::Object(o)
    }
    /// The exact canonical bytes a host signs for a link; no private-key operation.
    pub fn begin_sign(&self) -> CheckResult<Vec<u8>> {
        let b = RawEnvelope::begin(&self.to_value())?;
        Self::from_value(&keys::strict_json::parse(&b).map_err(|_| Verdict::Malformed)?)?;
        Ok(b)
    }
}

/// Authority entry named by a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsOf {
    /// One-based authority sequence.
    pub seq: u64,
    /// SHA-256 of the authority entry's exact body.
    pub digest: String,
}
impl AsOf {
    fn from_value(v: &Value) -> CheckResult<Self> {
        let o = obj(v)?;
        known(o, &["seq", "digest"])?;
        let seq = number(field(o, "seq")?)?;
        if seq == 0 { return Err(Verdict::Malformed); }
        Ok(Self { seq, digest: check_hex(str_field(o, "digest")?, 64)? })
    }
    fn to_value(&self) -> Value { json!({"seq":self.seq,"digest":self.digest}) }
}

/// A proof references verified history and up to eight sequential signed links.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    /// Full account identifier.
    pub account: String,
    /// Existing member key ID.
    pub member: String,
    /// Exact authority entry at which the proof claims its chain.
    pub as_of: AsOf,
    /// Delegation envelopes, member first; never authority-history records.
    pub links: Vec<RawEnvelope>,
    unknown: Map<String, Value>,
    protocol: String,
}
impl Proof {
    /// Construct a new proof using canonical link envelopes.
    pub fn new(account: String, member: String, as_of: AsOf, links: Vec<RawEnvelope>) -> CheckResult<Self> {
        if !hex_id(&account, 64) || !hex_id(&member, 32) || as_of.seq == 0
            || !hex_id(&as_of.digest, 64) || links.len() > 8
        {
            return Err(Verdict::Malformed);
        }
        Ok(Self { account, member, as_of, links, unknown: Map::new(), protocol: "colophon/proof/5".into() })
    }
    /// Strictly parse a proof and its base64-encoded envelope JSON values.
    pub fn from_json(bytes: &[u8]) -> CheckResult<Self> {
        let v = keys::strict_json::parse(bytes).map_err(|_| Verdict::Malformed)?;
        let mut m = obj(&v)?.clone();
        let protocol = m.remove("protocol").and_then(|x| x.as_str().map(str::to_owned)).ok_or(Verdict::Malformed)?;
        let account = check_hex(m.remove("account").and_then(|x| x.as_str().map(str::to_owned)).as_deref().ok_or(Verdict::Malformed)?,64)?;
        let member = check_hex(m.remove("member").and_then(|x| x.as_str().map(str::to_owned)).as_deref().ok_or(Verdict::Malformed)?,32)?;
        let as_of = AsOf::from_value(&m.remove("asOf").ok_or(Verdict::Malformed)?)?;
        let encoded = m.remove("links").ok_or(Verdict::Malformed)?;
        let links = encoded.as_array().ok_or(Verdict::Malformed)?;
        if links.len() > 8 { return Err(Verdict::Malformed); }
        let links = links.iter().map(|v| RawEnvelope::from_json(&bytes(v)?)).collect::<CheckResult<Vec<_>>>()?;
        Ok(Self { account, member, as_of, links, unknown: m, protocol })
    }
    /// Return the protocol's canonical JSON, including any preserved unknown proof fields.
    pub fn canonical(&self) -> CheckResult<Vec<u8>> {
        let mut o = self.unknown.clone();
        o.insert("protocol".into(), json!(self.protocol));
        o.insert("account".into(), json!(self.account));
        o.insert("member".into(), json!(self.member));
        o.insert("asOf".into(), self.as_of.to_value());
        let links = self.links.iter().map(|l| l.encode().map(|b| STANDARD.encode(b)))
            .collect::<CheckResult<Vec<_>>>()?;
        o.insert("links".into(), json!(links));
        records::canonical(&Value::Object(o)).map_err(|_| Verdict::Malformed)
    }
    /// SHA-256 of the proof's canonical JSON, not the envelope or history bytes.
    pub fn digest(&self) -> CheckResult<String> {
        Ok(records::digest(&self.canonical()?))
    }
}
/// A `colophon/request/5` body signed by the actual acting key.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestBody {
    /// Full account identifier.
    pub account: String,
    /// Digest of canonical proof JSON.
    pub proof: String,
    /// Exact verifier/audience identifier.
    pub audience: String,
    /// Purpose covered by grant terms.
    pub purpose: String,
    /// SHA-256 digest of the requested action's body.
    pub body: String,
    /// Fresh, exactly 16-byte opaque nonce.
    pub nonce: Vec<u8>,
    /// UTC creation time.
    pub created: String,
}
impl RequestBody {
    /// Strict parsing of the authenticated request body.
    pub fn from_value(v: &Value) -> CheckResult<Self> {
        let o = obj(v)?;
        known(o, &["protocol", "account", "proof", "audience", "purpose", "body", "nonce", "created"])?;
        if str_field(o, "protocol")? != "colophon/request/5" { return Err(Verdict::NewerFormat); }
        let nonce = bytes(field(o, "nonce")?)?;
        if nonce.len() != 16 { return Err(Verdict::Malformed); }
        let audience = str_field(o, "audience")?;
        let purpose = str_field(o, "purpose")?;
        if audience.is_empty() || audience.len() > 512 || purpose.is_empty() || purpose.len() > 512 {
            return Err(Verdict::Malformed);
        }
        Ok(Self {
            account: check_hex(str_field(o, "account")?, 64)?,
            proof: check_hex(str_field(o, "proof")?, 64)?,
            audience: audience.into(), purpose: purpose.into(),
            body: check_hex(str_field(o, "body")?, 64)?,
            nonce, created: valid_date(str_field(o, "created")?)?,
        })
    }
    /// Canonical value to sign in the host.
    pub fn to_value(&self) -> Value {
        json!({"protocol":"colophon/request/5","account":self.account,
            "proof":self.proof,"audience":self.audience,"purpose":self.purpose,
            "body":self.body,"nonce":STANDARD.encode(&self.nonce),"created":self.created})
    }
    /// First phase: validate the request shape and return exact canonical signing bytes.
    pub fn begin_sign(&self) -> CheckResult<Vec<u8>> {
        let b = RawEnvelope::begin(&self.to_value())?;
        Self::from_value(&keys::strict_json::parse(&b).map_err(|_| Verdict::Malformed)?)?;
        Ok(b)
    }
}

/// One active member returned by a verified, latest account history.
#[derive(Clone, Debug)]
pub struct Member {
    /// Valid P-256 signing public key.
    pub signing: Vec<u8>,
    /// Validated member grant terms.
    pub terms: Terms,
    /// Additional current grant expiry if distinct from terms expiry.
    pub expires: Option<String>,
    /// Whether latest verified authority revoked this member.
    pub revoked: bool,
}
/// Read-only authenticated history interface. The core never fetches a home or stores state.
pub trait VerifiedHistory {
    /// Was this exact account authority sequence and body digest verified?
    fn contains(&self, account: &str, seq: u64, digest: &str) -> bool;
    /// Latest member record (or None if absent); must already be verified by the caller.
    fn member(&self, account: &str, id: &str) -> Option<Member>;
    /// Latest guarded session number if the caller follows authenticated guarded state.
    /// None explicitly means unguarded verification, not session zero.
    fn session_number(&self, account: &str, id: &str) -> Option<u64>;
}
/// Complete input to the pure §5.3 verification; the request supplies proof-of-possession.
pub struct CheckInput<'a> {
    /// Proof presented by the acting key.
    pub proof: &'a Proof,
    /// Claimed acting P-256 public key.
    pub acting_signing: &'a [u8],
    /// Purpose the verifier is authorizing.
    pub purpose: &'a str,
    /// Trusted verifier clock, in 0.3 UTC format.
    pub now: &'a str,
    /// Operation or transition arguments used for condition evaluation.
    pub arguments: &'a Value,
    /// Signed exact-byte request envelope.
    pub request: &'a RawEnvelope,
    /// Audience identifier of this verifier.
    pub audience: &'a str,
    /// Digest of the operation or transition being requested.
    pub body_digest: &'a str,
    /// Trusted assertion of whether the acting key satisfied user verification.
    pub uv: bool,
}
/// Pure speaks-for check in §5.3 order. Nonce observations are caller-owned and sans I/O.
/// `nonce_seen` returns true when that nonce has appeared within the request window.
pub fn check<H, F>(input: CheckInput<'_>, history: &H, mut nonce_seen: F) -> Verdict
where
    H: VerifiedHistory,
    F: FnMut(&[u8]) -> bool,
{
    match check_inner(input, history, &mut nonce_seen) {
        Ok(unguarded) => Verdict::Ok { unguarded },
        Err(v) => v,
    }
}
fn check_inner<H: VerifiedHistory>(
    input: CheckInput<'_>, history: &H, nonce_seen: &mut impl FnMut(&[u8]) -> bool,
) -> CheckResult<bool> {
    let proof = input.proof;
    let now = timestamp(input.now).ok_or(Verdict::Malformed)?;
    // 1. Verified immutable authority head (no network calls inside this function).
    if !history.contains(&proof.account, proof.as_of.seq, &proof.as_of.digest) {
        return Err(Verdict::Refused(Refusal::Stale));
    }
    // 2. Member in the *latest* verified history (not historical snapshot).
    let member = history.member(&proof.account, &proof.member)
        .ok_or(Verdict::Refused(Refusal::Revoked))?;
    if member.revoked {
        return Err(Verdict::Refused(Refusal::Revoked));
    }
    if records::id(&member.signing) != proof.member {
        return Err(Verdict::Malformed);
    }
    if member.expires.as_deref().map(|s| timestamp(s).ok_or(Verdict::Malformed))
        .transpose()?.is_some_and(|t| now > t)
        || member.terms.expires.as_deref().map(|s| timestamp(s).ok_or(Verdict::Malformed))
            .transpose()?.is_some_and(|t| now > t)
    {
        return Err(Verdict::Refused(Refusal::Expired));
    }
    // 3a. Verify EVERY link signature before inspecting unknown fields or terms.
    // Carry forward signed target keys only; the typed decoder runs after all signatures.
    let mut key = member.signing.clone();
    let mut raw = Vec::with_capacity(proof.links.len());
    if proof.links.len() > 8 { return Err(Verdict::Malformed); }
    for envelope in &proof.links {
        envelope.verify(&key)?;
        let body = keys::strict_json::parse(&envelope.body).map_err(|_| Verdict::Malformed)?;
        let target = obj(field(obj(&body)?, "to")?)?;
        key = point(field(target, "signing")?)?;
        raw.push(body);
    }
    // Authentication precedes forward-format errors, even for zero-link proofs.
    // A forged request must not coerce the verifier to announce an upgrade.
    input.request.verify(input.acting_signing)?;
    if proof.protocol != "colophon/proof/5" || !proof.unknown.is_empty()
        || proof.links.iter().any(RawEnvelope::has_unknown_fields)
        || input.request.has_unknown_fields()
    {
        return Err(Verdict::NewerFormat);
    }
    // 3b. Validate chain binding, temporal bounds, scope narrowing, and depth.
    let mut prior_key = member.signing.clone();
    let mut parent_terms = member.terms.clone();
    let mut prior_expiry = member.expires.as_deref()
        .and_then(timestamp).unwrap_or(i64::MAX);
    if let Some(expires) = &member.terms.expires {
        prior_expiry = prior_expiry.min(timestamp(expires).ok_or(Verdict::Malformed)?);
    }
    let mut first_session = None;
    let mut all_terms = vec![member.terms.clone()];
    for (i, body) in raw.iter().enumerate() {
        let link = Link::from_value(body)?;
        if link.account != proof.account || link.from != records::id(&prior_key) {
            return Err(Verdict::BadSignature);
        }
        if i == 0 {
            first_session = Some(link.session.ok_or(Verdict::Malformed)?);
        } else if link.session.is_some() {
            return Err(Verdict::Malformed);
        }
        let start = timestamp(&link.not_before).ok_or(Verdict::Malformed)?;
        let end = timestamp(&link.expires).ok_or(Verdict::Malformed)?;
        if now < start || now > end {
            return Err(Verdict::Refused(Refusal::Expired));
        }
        if end > prior_expiry || !parent_terms.narrows(&link.terms) {
            return Err(Verdict::Refused(Refusal::NotNarrower));
        }
        prior_expiry = end;
        parent_terms = link.terms.clone();
        prior_key = link.to.signing;
        all_terms.push(parent_terms.clone());
    }
    // 4. Session numbers are guarded state; absent means unguarded, not zero.
    let current_session = history.session_number(&proof.account, &proof.member);
    if let (Some(expected), Some(actual)) = (first_session, current_session) {
        if expected != actual { return Err(Verdict::Refused(Refusal::Ended)); }
    }
    let unguarded = current_session.is_none();
    // 5. Every link and the member must allow purpose and key/argument constraints.
    if all_terms.iter().any(|t| !t.allows(input.purpose) || !t.conditions_hold(input.arguments, input.uv)) {
        return Err(Verdict::Refused(Refusal::OutOfScope));
    }
    // 6. Possession and exact signed request binding.
    if input.acting_signing != prior_key {
        return Err(Verdict::BadSignature);
    }
    let body = keys::strict_json::parse(&input.request.body).map_err(|_| Verdict::Malformed)?;
    let request = RequestBody::from_value(&body)?;
    if request.account != proof.account || request.proof != proof.digest()?
        || request.purpose != input.purpose || request.body != input.body_digest
        || request.audience != input.audience
    {
        return Err(Verdict::Refused(Refusal::OutOfScope));
    }
    let created = timestamp(&request.created).ok_or(Verdict::Malformed)?;
    if created.abs_diff(now) > 300_000 {
        return Err(Verdict::Refused(Refusal::Expired));
    }
    if nonce_seen(&request.nonce) {
        return Err(Verdict::Refused(Refusal::OutOfScope));
    }
    Ok(unguarded)
}
