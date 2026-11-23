//! The §S3 wire format: the outer frame, its AAD and signed body, and the plaintext encoding.
//!
//! Everything here is pure byte layout. Keys, signatures and sealing are in
//! [`super::codec`]; session-key delegations in [`super::keys`].
//!
//! A frame on the wire is one canonical JSON object (0.5 §2.1):
//!
//! ```json
//! {"account":"<64 hex>","cell":"now-playing","ciphertext":"<base64>","delegation":{…},
//!  "epoch":3,"from":"<memberID>","key":"<keyID>","n":41,"namespace":"listening.podcasts",
//!  "protocol":"colophon/session/6","retain":true,"signature":"<base64>","to":"<memberID>"}
//! ```
//!
//! The **signed body** is the canonical JSON of the same object without `delegation` and
//! `signature`. The **AAD** is the canonical JSON of the object without `ciphertext`,
//! `delegation` and `signature`. `to`, `retain` and `delegation` are omitted when absent;
//! `retain` is present only as `true`.
use super::types::{Body, MAX_INT};
use crate::v05::encoding::{
    canonical, decode_base64, encode_base64, is_lower_hex, strict_parse,
};
use crate::v05::ids::is_key_id;
use crate::v05::terms::valid_namespace;
use serde_json::{Map, Value};

/// The `protocol` of a frame.
pub const FRAME_PROTOCOL: &str = "colophon/session/6";
/// The largest encoded frame, in bytes (§S3).
pub const MAX_FRAME_BYTES: usize = 16_384;
/// A raw ES256 signature: `r ‖ s` (0.5 §4.2).
pub const SIGNATURE_BYTES: usize = 64;
/// The AES-GCM tag appended to every ciphertext.
pub const TAG_BYTES: usize = 16;
/// The largest delegation envelope accepted inside a frame, as canonical JSON bytes.
pub const MAX_DELEGATION_BYTES: usize = 2_048;

/// Why a received frame was dropped. Every drop is silent on the wire (§S3); the reason is
/// for tests, logs and conformance vectors. [`DropReason::code`] gives a stable spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The encoded frame is over [`MAX_FRAME_BYTES`].
    Oversize,
    /// The frame is not strict canonical JSON with exactly the §S3 fields.
    Malformed(String),
    /// `account` is not this member's account.
    Account,
    /// `namespace` is not this cell's namespace.
    Namespace,
    /// `cell` is not this cell.
    Cell,
    /// The frame claims to be from this member.
    FromSelf,
    /// A `delegation` is present and does not verify under §S2 for `(from, key)`.
    Delegation(String),
    /// No accepted session key for `(from, key)`.
    NoKey,
    /// The accepted session key's window does not include the verifier's clock (± 60 s).
    KeyWindow,
    /// The frame signature does not verify under the session key.
    Signature,
    /// `n` was already accepted for this key.
    Replay,
    /// `n` is more than 128 below the highest accepted for this key.
    TooOld,
    /// The receiver lacks namespace epoch `epoch`; it should sync.
    NoEpoch(u64),
    /// AES-GCM failed: wrong key, AAD, nonce or a modified ciphertext.
    Open,
    /// The plaintext is not a strict canonical `{"kind":…}` with that kind's exact fields.
    Plaintext(String),
    /// The plaintext names an unknown `kind`.
    UnknownKind,
    /// An integer, a payload or a snapshot is out of the §S3 bounds or the cell's `maxPayload`.
    Range,
}
impl DropReason {
    /// A stable code, as used by the conformance vectors.
    pub fn code(&self) -> &'static str {
        match self {
            DropReason::Oversize => "oversize",
            DropReason::Malformed(_) => "malformed",
            DropReason::Account => "account",
            DropReason::Namespace => "namespace",
            DropReason::Cell => "cell",
            DropReason::FromSelf => "fromSelf",
            DropReason::Delegation(_) => "delegation",
            DropReason::NoKey => "noKey",
            DropReason::KeyWindow => "keyWindow",
            DropReason::Signature => "signature",
            DropReason::Replay => "replay",
            DropReason::TooOld => "tooOld",
            DropReason::NoEpoch(_) => "noEpoch",
            DropReason::Open => "open",
            DropReason::Plaintext(_) => "plaintext",
            DropReason::UnknownKind => "unknownKind",
            DropReason::Range => "range",
        }
    }
}
impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DropReason::Malformed(s) | DropReason::Delegation(s) | DropReason::Plaintext(s) => {
                write!(f, "{}: {s}", self.code())
            }
            DropReason::NoEpoch(e) => write!(f, "{}: {e}", self.code()),
            other => f.write_str(other.code()),
        }
    }
}

/// `cell` grammar (§S1): 1–64 bytes of `a–z 0–9 . -`.
pub fn valid_cell(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// An account ID: 64 lowercase hex characters (0.5 §5.1).
pub fn valid_account(s: &str) -> bool {
    is_lower_hex(s, 64)
}

/// The fields of a frame that the AAD covers (§S3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Outer {
    /// The account (64 hex).
    pub account: String,
    /// The namespace.
    pub namespace: String,
    /// The cell.
    pub cell: String,
    /// The sender's member ID.
    pub from: String,
    /// The key ID of the sender's session key.
    pub key: String,
    /// Advice: the member the frame is for.
    pub to: Option<String>,
    /// The frame's number under `key`, from 1.
    pub n: u64,
    /// The namespace epoch the ciphertext is sealed under.
    pub epoch: u64,
    /// Ask carriers to keep it (§S9).
    pub retain: bool,
}
impl Outer {
    fn map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("protocol".into(), FRAME_PROTOCOL.into());
        m.insert("account".into(), self.account.clone().into());
        m.insert("namespace".into(), self.namespace.clone().into());
        m.insert("cell".into(), self.cell.clone().into());
        m.insert("from".into(), self.from.clone().into());
        m.insert("key".into(), self.key.clone().into());
        if let Some(to) = &self.to {
            m.insert("to".into(), to.clone().into());
        }
        m.insert("n".into(), self.n.into());
        m.insert("epoch".into(), self.epoch.into());
        if self.retain {
            m.insert("retain".into(), true.into());
        }
        m
    }
    /// The AAD: canonical JSON of `{account, cell, epoch, from, key, n, namespace, protocol,
    /// retain, to}`, absent fields omitted.
    pub fn aad(&self) -> Vec<u8> {
        encode_map(self.map())
    }
    /// The signed body: the AAD's object with `ciphertext` added, canonical JSON.
    pub fn signed_body(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut m = self.map();
        m.insert("ciphertext".into(), encode_base64(ciphertext).into());
        encode_map(m)
    }
    /// Whether every field is in its grammar and range.
    pub fn well_formed(&self) -> bool {
        valid_account(&self.account)
            && valid_namespace(&self.namespace)
            && valid_cell(&self.cell)
            && is_key_id(&self.from)
            && is_key_id(&self.key)
            && self.to.as_deref().is_none_or(is_key_id)
            && (1..=MAX_INT).contains(&self.n)
            && (1..=MAX_INT).contains(&self.epoch)
    }
}

/// Canonical JSON of a map of strings, integers and booleans. Such a value always encodes.
fn encode_map(m: Map<String, Value>) -> Vec<u8> {
    canonical(&Value::Object(m)).unwrap_or_default()
}

/// A parsed or assembled wire frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireFrame {
    /// The fields the AAD covers.
    pub outer: Outer,
    /// AES-256-GCM ciphertext with its 16-byte tag.
    pub ciphertext: Vec<u8>,
    /// The raw ES256 signature over [`Outer::signed_body`].
    pub signature: [u8; SIGNATURE_BYTES],
    /// The §S2 envelope for `key`, as its canonical JSON bytes, when carried.
    pub delegation: Option<Vec<u8>>,
}
impl WireFrame {
    /// The signed body bytes.
    pub fn signed_body(&self) -> Vec<u8> {
        self.outer.signed_body(&self.ciphertext)
    }
    /// The encoded frame: canonical JSON of every field.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = self.outer.map();
        m.insert("ciphertext".into(), encode_base64(&self.ciphertext).into());
        m.insert("signature".into(), encode_base64(&self.signature).into());
        if let Some(d) = &self.delegation {
            // The envelope is canonical JSON we produced or parsed; it always reparses.
            if let Ok(v) = strict_parse(d) {
                m.insert("delegation".into(), v);
            }
        }
        encode_map(m)
    }
    /// Parse a received frame: at most [`MAX_FRAME_BYTES`], strict canonical JSON (no
    /// duplicate names, no lone surrogates, nesting at most 64), exactly the §S3 fields, every
    /// field in its grammar. Nothing is verified here.
    pub fn parse(bytes: &[u8]) -> Result<Self, DropReason> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(DropReason::Oversize);
        }
        let bad = |s: &str| DropReason::Malformed(s.to_owned());
        let value = strict_parse(bytes).map_err(|e| DropReason::Malformed(e.to_string()))?;
        let Value::Object(mut m) = value.clone() else {
            return Err(bad("a frame is a JSON object"));
        };
        if canonical(&value).map_err(|e| DropReason::Malformed(e.to_string()))? != bytes {
            return Err(bad("a frame is canonical JSON"));
        }
        let mut string = |k: &str| match m.remove(k) {
            Some(Value::String(s)) => Ok(s),
            Some(_) => Err(DropReason::Malformed(format!("{k} is not a string"))),
            None => Err(DropReason::Malformed(format!("{k} is missing"))),
        };
        let protocol = string("protocol")?;
        let account = string("account")?;
        let namespace = string("namespace")?;
        let cell = string("cell")?;
        let from = string("from")?;
        let key = string("key")?;
        let ciphertext = string("ciphertext")?;
        let signature = string("signature")?;
        let to = match m.remove("to") {
            None => None,
            Some(Value::String(s)) => Some(s),
            Some(_) => return Err(bad("to is not a string")),
        };
        let int = |v: Option<Value>, k: &str| match v {
            Some(Value::Number(n)) if !n.is_f64() => n
                .as_u64()
                .filter(|x| (1..=MAX_INT).contains(x))
                .ok_or_else(|| DropReason::Malformed(format!("{k} out of range"))),
            Some(_) => Err(DropReason::Malformed(format!("{k} is not an integer"))),
            None => Err(DropReason::Malformed(format!("{k} is missing"))),
        };
        let n = int(m.remove("n"), "n")?;
        let epoch = int(m.remove("epoch"), "epoch")?;
        let retain = match m.remove("retain") {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(bad("retain is present only as true")),
        };
        let delegation = match m.remove("delegation") {
            None => None,
            Some(v @ Value::Object(_)) => {
                let b = canonical(&v).map_err(|e| DropReason::Malformed(e.to_string()))?;
                if b.len() > MAX_DELEGATION_BYTES {
                    return Err(bad("delegation exceeds its bound"));
                }
                Some(b)
            }
            Some(_) => return Err(bad("delegation is not an object")),
        };
        if let Some(k) = m.keys().next() {
            return Err(DropReason::Malformed(format!("unknown field {k}")));
        }
        if protocol != FRAME_PROTOCOL {
            return Err(bad("unknown protocol"));
        }
        let outer = Outer {
            account,
            namespace,
            cell,
            from,
            key,
            to,
            n,
            epoch,
            retain,
        };
        if !outer.well_formed() {
            return Err(bad("an outer field is outside its grammar"));
        }
        let ciphertext = decode_base64(&ciphertext, MAX_FRAME_BYTES)
            .map_err(|e| DropReason::Malformed(format!("ciphertext: {e}")))?;
        if ciphertext.len() < TAG_BYTES {
            return Err(bad("ciphertext is shorter than its tag"));
        }
        let signature: [u8; SIGNATURE_BYTES] = decode_base64(&signature, SIGNATURE_BYTES)
            .map_err(|e| DropReason::Malformed(format!("signature: {e}")))?
            .try_into()
            .map_err(|_| bad("signature is not 64 bytes"))?;
        Ok(Self {
            outer,
            ciphertext,
            signature,
            delegation,
        })
    }
}

// ---------------------------------------------------------------------------------------
// Plaintext.

/// The exact fields of each kind (§S3 table): required, then optional.
fn fields(kind: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match kind {
        "hello" => (&["kind", "fresh", "echo", "seen", "lapsed"], &[]),
        "state" => (&["kind", "claim", "seq", "snapshot"], &[]),
        "beat" => (&["kind", "claim", "seq"], &[]),
        "msg" => (&["kind", "claim", "seq", "origin", "id", "payload"], &[]),
        "submit" => (&["kind", "id", "payload"], &[]),
        "refuse" => (&["kind", "id", "reason"], &[]),
        "presence" => (&["kind", "payload"], &[]),
        "ask" => (&["kind", "claim"], &[]),
        "pass" => (&["kind", "claim", "next", "seq", "snapshot"], &[]),
        "decline" => (&["kind", "claim"], &[]),
        "take" => (&["kind", "claim"], &[]),
        "ping" => (&["kind", "t"], &[]),
        "pong" => (&["kind", "t", "echo", "hold"], &[]),
        "yielded" => (&["kind", "claim", "seq", "snapshot"], &[]),
        "ack" => (&["kind"], &["yielded", "passed"]),
        "bye" => (&["kind", "leaving"], &["claim"]),
        _ => return None,
    })
}

fn closed(
    o: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    path: &str,
) -> Result<(), DropReason> {
    for k in required {
        if !o.contains_key(*k) {
            return Err(DropReason::Plaintext(format!("{path}{k} is missing")));
        }
    }
    for k in o.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Err(DropReason::Plaintext(format!("unknown field {path}{k}")));
        }
    }
    Ok(())
}

/// A claim object (`{term, rank, holder, via?}`), plus `seq` for `hello.seen`.
fn claim_shape(v: &Value, path: &str, seen: bool) -> Result<(), DropReason> {
    let Value::Object(o) = v else {
        return Err(DropReason::Plaintext(format!("{path} is not an object")));
    };
    let required: &[&str] = if seen {
        &["term", "rank", "holder", "seq"]
    } else {
        &["term", "rank", "holder"]
    };
    closed(o, required, &["via"], &format!("{path}."))?;
    for k in ["holder", "via"] {
        if let Some(m) = o.get(k) {
            member_id(m, &format!("{path}.{k}"))?;
        }
    }
    Ok(())
}

fn member_id(v: &Value, path: &str) -> Result<(), DropReason> {
    match v {
        Value::String(s) if is_key_id(s) => Ok(()),
        _ => Err(DropReason::Plaintext(format!("{path} is not a member ID"))),
    }
}

/// Every number in `v` is an integer token from 0 to 2^53 − 1 (§S3).
fn integers_in_range(v: &Value) -> bool {
    match v {
        Value::Number(n) => !n.is_f64() && n.as_u64().is_some_and(|x| x <= MAX_INT),
        Value::Array(a) => a.iter().all(integers_in_range),
        Value::Object(o) => o.values().all(integers_in_range),
        _ => true,
    }
}

/// Encode a plaintext body: canonical JSON of `{"kind": …, …}` with exactly that kind's
/// fields. A `bye` without a claim omits `claim` (0.5 §2.3: optional fields are omitted).
pub fn encode_body(body: &Body) -> Result<Vec<u8>, String> {
    let mut v = serde_json::to_value(body).map_err(|e| e.to_string())?;
    if let (Body::Bye { claim: None, .. }, Value::Object(o)) = (body, &mut v) {
        o.remove("claim");
    }
    canonical(&v).map_err(|e| e.to_string())
}

/// Decode a plaintext body strictly: strict canonical JSON, a known `kind` with exactly its
/// fields (claims and `seen` closed too, member IDs as key IDs), every integer at most
/// 2^53 − 1, ids and `fresh` as 22-character unpadded base64url, payloads and snapshots as
/// canonical padded base64 of at most `max_payload` bytes. The bytes must be exactly what
/// [`encode_body`] produces for the decoded body.
pub fn decode_body(bytes: &[u8], max_payload: u64) -> Result<Body, DropReason> {
    let value = strict_parse(bytes).map_err(|e| DropReason::Plaintext(e.to_string()))?;
    let Value::Object(o) = &value else {
        return Err(DropReason::Plaintext("the plaintext is not an object".into()));
    };
    let Some(Value::String(kind)) = o.get("kind") else {
        return Err(DropReason::Plaintext("kind is missing".into()));
    };
    let Some((required, optional)) = fields(kind) else {
        return Err(DropReason::UnknownKind);
    };
    closed(o, required, optional, "")?;
    for k in ["claim", "next", "yielded", "passed"] {
        if let Some(c) = o.get(k) {
            // `bye.claim` is optional, never `null` (0.5 §2.3).
            claim_shape(c, k, false)?;
        }
    }
    if let Some(seen) = o.get("seen") {
        if !seen.is_null() {
            claim_shape(seen, "seen", true)?;
        }
    }
    if let Some(origin) = o.get("origin") {
        member_id(origin, "origin")?;
    }
    if !integers_in_range(&value) {
        return Err(DropReason::Range);
    }
    let body: Body =
        serde_json::from_value(value.clone()).map_err(|e| DropReason::Plaintext(e.to_string()))?;
    if !body.in_range(max_payload) {
        return Err(DropReason::Range);
    }
    if encode_body(&body).map_err(DropReason::Plaintext)? != bytes {
        return Err(DropReason::Plaintext("not the canonical encoding".into()));
    }
    Ok(body)
}
