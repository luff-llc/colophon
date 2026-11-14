//! Encoding, keys, signing, dates and the chain builder for the 0.5 candidate generator.
//!
//! Nothing here calls the 0.5 verifier (`colophon_core::v05`): the canonical encoder, the
//! signatures and the entry builders are written out again, so the vectors stay independent of
//! the code they test.
#![allow(clippy::unwrap_used)]
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{
    alphabet,
    engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig},
    Engine,
};
use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer as EcSigner, Verifier as EcVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub type Out = BTreeMap<String, Vec<u8>>;
pub type Sl<'a> = &'a [&'a dyn Signer];

/// The group order of P-256, big endian.
pub const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

// ---------------------------------------------------------------------------------------
// Canonical JSON: sorted keys, no whitespace, slashes unescaped, UTF-8, integers only.

fn escape(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn encode(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            assert!(!n.is_f64(), "floats are not used in these vectors");
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => escape(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut pairs: Vec<(&String, &Value)> = m.iter().collect();
            pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, x)) in pairs.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                escape(k, out);
                out.push(b':');
                encode(x, out);
            }
            out.push(b'}');
        }
    }
}

pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode(v, &mut out);
    out
}

/// Top-level names in reverse order, everything below canonical (the non-canonical-JSON case).
pub fn reverse_top_level(v: &Value) -> Vec<u8> {
    let m = v.as_object().unwrap();
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    keys.reverse();
    let mut out = vec![b'{'];
    for (i, k) in keys.into_iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        escape(k, &mut out);
        out.push(b':');
        encode(&m[k], &mut out);
    }
    out.push(b'}');
    out
}

// ---------------------------------------------------------------------------------------
// Base64, hashes.

static LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

pub fn b64(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}
pub fn unb64(s: &str) -> Vec<u8> {
    LENIENT
        .decode(s)
        .unwrap_or_else(|e| panic!("base64 {s}: {e}"))
}
pub fn b64url(d: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d)
}
pub fn sha_raw(d: &[u8]) -> Vec<u8> {
    Sha256::digest(d).to_vec()
}
pub fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn sha(d: &[u8]) -> String {
    hex(&sha_raw(d))
}
pub fn key_id(point: &[u8]) -> String {
    sha(point)[..32].to_string()
}

// ---------------------------------------------------------------------------------------
// Keys.

#[derive(Clone)]
pub struct Key {
    pub scalar: [u8; 32],
    sk: SigningKey,
    pub point: Vec<u8>,
    pub id: String,
    /// The agreement public key, where the vectors publish one for this signing key.
    pub agreement: Option<Vec<u8>>,
}

impl Key {
    pub fn new(scalar: [u8; 32]) -> Key {
        let sk = SigningKey::from_slice(&scalar).unwrap();
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let id = key_id(&point);
        Key {
            scalar,
            sk,
            point,
            id,
            agreement: None,
        }
    }
    pub fn with_agreement(mut self, agreement: Vec<u8>) -> Key {
        self.agreement = Some(agreement);
        self
    }
    /// Raw 64-byte ES256, deterministic (RFC 6979), `s` as it comes (no low-S rewriting).
    pub fn sign(&self, body: &[u8]) -> Vec<u8> {
        let sig: Signature = self.sk.sign(body);
        sig.to_bytes().as_slice().to_vec()
    }
    /// DER ES256 over `msg` (WebAuthn signs `authenticatorData || SHA-256(clientData)`).
    pub fn sign_der(&self, msg: &[u8]) -> Vec<u8> {
        der(&self.sign(msg))
    }
}

fn der_int(x: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < x.len() - 1 && x[i] == 0 {
        i += 1;
    }
    let mut v = x[i..].to_vec();
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    let mut out = vec![0x02, v.len() as u8];
    out.extend(v);
    out
}
fn der(raw: &[u8]) -> Vec<u8> {
    let mut body = der_int(&raw[..32]);
    body.extend(der_int(&raw[32..]));
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

pub fn verify_raw(point: &[u8], body: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(point) else {
        return false;
    };
    let Ok(s) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(body, &s).is_ok()
}

/// `SHA-256('colophon-0.5-candidate/' + name) mod n` as a key.
pub fn derived(name: &str) -> Key {
    let mut d: [u8; 32] = sha_raw(format!("colophon-0.5-candidate/{name}").as_bytes())
        .try_into()
        .unwrap();
    if d >= N {
        d = sub32(&d, &N);
    }
    Key::new(d)
}

pub fn sub32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u8;
    }
    out
}

/// A signer of entries: a raw key or the synthetic WebAuthn authenticator.
pub trait Signer {
    fn id(&self) -> String;
    /// `{signer, signature[, assertion]}`.
    fn sig_item(&self, body: &[u8], origin: Option<&str>, flags: u8) -> Value;
    /// The `key` descriptor of a controller.
    fn descriptor(&self) -> Value;
    fn is_authenticator(&self) -> bool {
        false
    }
    fn webauthn_sign(&self, _body: &[u8], _origin: &str, _flags: u8) -> (Vec<u8>, Value) {
        panic!("not an authenticator")
    }
}

impl Signer for Key {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn sig_item(&self, body: &[u8], _origin: Option<&str>, _flags: u8) -> Value {
        json!({"signer": self.id, "signature": b64(&self.sign(body))})
    }
    fn descriptor(&self) -> Value {
        let mut d = json!({"form": "raw", "signing": b64(&self.point)});
        if let Some(a) = &self.agreement {
            d["agreement"] = json!(b64(a));
        }
        d
    }
}

impl<T: Signer> Signer for LazyLock<T> {
    fn id(&self) -> String {
        (**self).id()
    }
    fn sig_item(&self, body: &[u8], origin: Option<&str>, flags: u8) -> Value {
        (**self).sig_item(body, origin, flags)
    }
    fn descriptor(&self) -> Value {
        (**self).descriptor()
    }
    fn is_authenticator(&self) -> bool {
        (**self).is_authenticator()
    }
    fn webauthn_sign(&self, body: &[u8], origin: &str, flags: u8) -> (Vec<u8>, Value) {
        (**self).webauthn_sign(body, origin, flags)
    }
}

/// Synthetic WebAuthn authenticator: authenticatorData = SHA-256(rp) || flags || counter.
pub struct Authenticator {
    pub k: Key,
    pub rp: String,
    pub credential: Vec<u8>,
    extra: Value,
    pub id: String,
    pub point: Vec<u8>,
}

impl Authenticator {
    pub fn new(name: &str, rp: &str, extra: Value) -> Authenticator {
        let k = derived(&format!("webauthn/{name}"));
        Authenticator {
            rp: rp.to_string(),
            credential: sha_raw(name.as_bytes())[..16].to_vec(),
            extra,
            id: k.id.clone(),
            point: k.point.clone(),
            k,
        }
    }
}

impl Signer for Authenticator {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn is_authenticator(&self) -> bool {
        true
    }
    fn descriptor(&self) -> Value {
        let mut d = json!({"form": "webauthn", "signing": b64(&self.point), "rp": self.rp,
                           "credential": b64(&self.credential)});
        if let Value::Object(m) = &self.extra {
            for (k, v) in m {
                d[k] = v.clone();
            }
        }
        d
    }
    fn webauthn_sign(&self, body: &[u8], origin: &str, flags: u8) -> (Vec<u8>, Value) {
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\",\"crossOrigin\":false}}",
            b64url(&sha_raw(body)),
            origin
        )
        .into_bytes();
        let mut auth = sha_raw(self.rp.as_bytes());
        auth.push(flags);
        auth.extend_from_slice(&7u32.to_be_bytes());
        let mut msg = auth.clone();
        msg.extend(sha_raw(&client));
        let der = self.k.sign_der(&msg);
        (
            der,
            json!({"authenticatorData": b64(&auth), "clientData": b64(&client)}),
        )
    }
    fn sig_item(&self, body: &[u8], origin: Option<&str>, flags: u8) -> Value {
        let o = origin
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://{}", self.rp));
        let (der, assertion) = self.webauthn_sign(body, &o, flags);
        json!({"signer": self.id, "signature": b64(&der), "assertion": assertion})
    }
}

/// `&[&dyn Signer]` from a list of signers.
#[macro_export]
macro_rules! sg {
    ($($x:expr),* $(,)?) => { &[$(&$x as &dyn $crate::kit::Signer),*] };
}

// ---------------------------------------------------------------------------------------
// Envelopes.

pub fn envelope(body: &Value, signer: &Key) -> Value {
    let b = canonical(body);
    json!({"body": b64(&b), "signature": b64(&signer.sign(&b))})
}
pub fn env_bytes(env: &Value) -> Vec<u8> {
    canonical(env)
}
pub fn body_of(env: &Value) -> Vec<u8> {
    unb64(env["body"].as_str().unwrap())
}
pub fn field(env: &Value, name: &str) -> Value {
    let v: Value = serde_json::from_slice(&body_of(env)).unwrap();
    v[name].clone()
}
pub fn fstr(env: &Value, name: &str) -> String {
    field(env, name).as_str().unwrap().to_string()
}
pub fn body_json(env: &Value) -> Value {
    serde_json::from_slice(&body_of(env)).unwrap()
}
pub fn emb(env: &Value) -> String {
    b64(&env_bytes(env))
}

pub fn write(o: &mut Out, rel: &str, value: &Value) {
    let mut d = canonical(value);
    d.push(b'\n');
    o.insert(rel.to_string(), d);
}
pub fn write_raw(o: &mut Out, rel: &str, data: Vec<u8>) {
    o.insert(rel.to_string(), data);
}

#[derive(Clone, Copy, Default)]
pub struct Opt<'a> {
    pub cos: Sl<'a>,
    pub adds: Sl<'a>,
    pub handover: Sl<'a>,
    pub origin: Option<&'a str>,
}

pub fn seal_bytes(body: &[u8], primary: &dyn Signer, o: Opt) -> Value {
    let p = primary.sig_item(body, o.origin, 0x05);
    let mut env = Map::new();
    env.insert("body".into(), json!(b64(body)));
    env.insert("signature".into(), p["signature"].clone());
    if let Some(a) = p.get("assertion") {
        env.insert("assertion".into(), a.clone());
    }
    for (name, group) in [
        ("cosignatures", o.cos),
        ("additions", o.adds),
        ("handover", o.handover),
    ] {
        if !group.is_empty() {
            let mut items: Vec<Value> = group
                .iter()
                .map(|s| s.sig_item(body, o.origin, 0x05))
                .collect();
            items.sort_by(|a, b| a["signer"].as_str().cmp(&b["signer"].as_str()));
            env.insert(name.into(), Value::Array(items));
        }
    }
    Value::Object(env)
}
pub fn seal(body: &Value, primary: &dyn Signer, o: Opt) -> Value {
    seal_bytes(&canonical(body), primary, o)
}

#[derive(Clone, Default)]
pub struct Chain {
    pub envs: Vec<Value>,
}

impl Chain {
    pub fn new() -> Chain {
        Chain::default()
    }
    pub fn last(&self) -> Vec<u8> {
        body_of(self.envs.last().unwrap())
    }
    pub fn add(
        &mut self,
        kind: &str,
        by: &dyn Signer,
        issued: &str,
        signer: &dyn Signer,
        o: Opt,
        fields: Value,
    ) -> Value {
        let previous = if self.envs.is_empty() {
            Value::Null
        } else {
            json!(sha(&self.last()))
        };
        let mut body = json!({"protocol": "colophon/authority/5", "seq": self.envs.len() + 1, "previous": previous,
                              "issued": issued, "by": by.id(), "kind": kind});
        if let Value::Object(m) = fields {
            for (k, v) in m {
                body[k] = v;
            }
        }
        let env = seal(&body, signer, o);
        self.envs.push(env.clone());
        env
    }
}

// ---------------------------------------------------------------------------------------
// Dates (seconds from 2026-11-11T08:00:00Z).

pub const T0: &str = "2026-11-11T08:00:00Z";

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn base_epoch() -> i64 {
    days_from_civil(2026, 11, 11) * 86400 + 8 * 3600
}
/// T0 + seconds as a 0.5 date.
pub fn ts(seconds: i64) -> String {
    let t = base_epoch() + seconds;
    let (y, m, d) = civil_from_days(t.div_euclid(86400));
    let s = t.rem_euclid(86400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}
/// Seconds of a `YYYY-MM-DDTHH:MM:SSZ` date after T0.
pub fn secs(date: &str) -> i64 {
    let b = date.as_bytes();
    assert!(date.len() == 20 && b[19] == b'Z', "bad date {date}");
    let n = |a: usize, z: usize| date[a..z].parse::<i64>().unwrap();
    days_from_civil(n(0, 4), n(5, 7), n(8, 10)) * 86400
        + n(11, 13) * 3600
        + n(14, 16) * 60
        + n(17, 19)
        - base_epoch()
}

// ---------------------------------------------------------------------------------------
// Parsing with duplicate-name detection (an independent strict pass for the 0.4 self-check).

pub struct Tracked(pub Value, pub bool);

impl<'de> Deserialize<'de> for Tracked {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Tracked;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("json")
            }
            fn visit_unit<E>(self) -> Result<Tracked, E> {
                Ok(Tracked(Value::Null, false))
            }
            fn visit_bool<E>(self, b: bool) -> Result<Tracked, E> {
                Ok(Tracked(Value::Bool(b), false))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Tracked, E> {
                Ok(Tracked(json!(n), false))
            }
            fn visit_u64<E>(self, n: u64) -> Result<Tracked, E> {
                Ok(Tracked(json!(n), false))
            }
            fn visit_f64<E>(self, n: f64) -> Result<Tracked, E> {
                Ok(Tracked(json!(n), false))
            }
            fn visit_str<E>(self, s: &str) -> Result<Tracked, E> {
                Ok(Tracked(json!(s), false))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Tracked, A::Error> {
                let (mut items, mut dup) = (Vec::new(), false);
                while let Some(Tracked(v, d)) = a.next_element()? {
                    items.push(v);
                    dup |= d;
                }
                Ok(Tracked(Value::Array(items), dup))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Tracked, A::Error> {
                let (mut m, mut dup) = (Map::new(), false);
                while let Some((k, Tracked(v, d))) = a.next_entry::<String, Tracked>()? {
                    dup |= d || m.contains_key(&k);
                    m.insert(k, v);
                }
                Ok(Tracked(Value::Object(m), dup))
            }
        }
        d.deserialize_any(V)
    }
}

// ---------------------------------------------------------------------------------------
// Files.

pub fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
pub fn sorted_dir(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------------------
// Published keys and the shared keys.

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
pub fn conformance() -> PathBuf {
    repo().join("conformance")
}
pub fn candidate() -> PathBuf {
    conformance().join("0.5/candidate")
}
pub fn v4() -> PathBuf {
    conformance().join("0.4")
}

pub const AUD: &str = "https://projects.example/scopes/7";

pub static PUBLISHED: LazyLock<Value> = LazyLock::new(|| read_json(&v4().join("keys/keys.json")));

/// The published 0.4 software keys, in file order.
pub static SOFTWARE: LazyLock<Vec<Key>> = LazyLock::new(|| {
    PUBLISHED["software"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let k = Key::new(
                unb64(item["signingScalar"].as_str().unwrap())
                    .try_into()
                    .unwrap(),
            )
            .with_agreement(unb64(item["public"]["agreement"].as_str().unwrap()));
            assert_eq!(
                k.id,
                item["id"].as_str().unwrap(),
                "published scalar does not match its key ID"
            );
            k
        })
        .collect()
});

pub fn software(id: &str) -> Option<Key> {
    SOFTWARE.iter().find(|k| k.id == id).cloned()
}

macro_rules! published_key {
    ($name:ident, $i:expr) => {
        pub static $name: LazyLock<Key> = LazyLock::new(|| SOFTWARE[$i].clone());
    };
}
published_key!(A, 0);
published_key!(B, 1);
published_key!(K1, 2);
published_key!(K2, 3);
published_key!(NK, 4);
published_key!(MK, 5);

pub static AGENT_K: LazyLock<Key> = LazyLock::new(|| derived("r2/agent/signing"));
pub static AGENT_A: LazyLock<Key> = LazyLock::new(|| derived("r2/agent/agreement"));

/// The 0.4 genesis whose keyring (and slot and vault) the 0.5 vectors reuse.
pub static G4: LazyLock<Value> = LazyLock::new(|| {
    let env = read_json(&v4().join("keys/genesis-one-raw/records/authority/00000001.json"));
    body_json(&env)
});

pub fn default_policy() -> Value {
    json!({"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members", "linkMaxAge": 86400,
           "memberRule": "single", "recoveryDelay": 259200,
           "rate": {"account": {"bytes": 16777216, "entries": 256}, "signer": {"bytes": 4194304, "entries": 64}}})
}

// ---------------------------------------------------------------------------------------
// Keyrings and controllers.

pub fn ctrl(k: &dyn Signer, roles: &[&str], label: Option<&str>, extra: Value) -> Value {
    let mut r: Vec<&str> = roles.to_vec();
    r.sort();
    let label = label
        .map(str::to_string)
        .unwrap_or_else(|| format!("key {}", &k.id()[..6]));
    let mut c = json!({"key": k.descriptor(), "label": label, "roles": r});
    if let Value::Object(m) = extra {
        for (a, b) in m {
            c[a] = b;
        }
    }
    c
}
pub fn cid(c: &Value) -> String {
    key_id(&unb64(c["key"]["signing"].as_str().unwrap()))
}
pub fn sorted_ctrls(mut v: Vec<Value>) -> Vec<Value> {
    v.sort_by_key(cid);
    v
}

pub struct Kr<'a> {
    pub threshold: i64,
    pub rt: i64,
    pub add: i64,
    pub count: &'a str,
    pub policy: Option<Value>,
}
impl Default for Kr<'_> {
    fn default() -> Self {
        Kr {
            threshold: 1,
            rt: 0,
            add: 1,
            count: "keys",
            policy: None,
        }
    }
}
pub fn keyring(ctrls: Vec<Value>, o: Kr) -> Value {
    json!({"controllers": sorted_ctrls(ctrls), "threshold": o.threshold, "recoverThreshold": o.rt, "addThreshold": o.add,
           "countBy": o.count, "policy": o.policy.unwrap_or_else(default_policy),
           "vault": G4["keyring"]["vault"], "slots": [G4["keyring"]["slots"][0].clone()]})
}
/// `dict(POLICY, name=value, ...)`.
pub fn policy_with(extra: &[(&str, Value)]) -> Value {
    let mut p = default_policy();
    for (k, v) in extra {
        p[*k] = v.clone();
    }
    p
}

/// A copy of `kr` with fields replaced (`policy` is merged) and controllers re-sorted.
pub fn change(kr: &Value, delta: &[(&str, Value)]) -> Value {
    let mut new = kr.clone();
    for (k, v) in delta {
        if *k == "policy" {
            for (a, b) in v.as_object().unwrap() {
                new["policy"][a] = b.clone();
            }
        } else {
            new[*k] = v.clone();
        }
    }
    let cs = new["controllers"].as_array().unwrap().clone();
    new["controllers"] = Value::Array(sorted_ctrls(cs));
    new
}

pub fn ids_sorted(keys: &[&dyn Signer]) -> Vec<String> {
    let mut v: Vec<String> = keys.iter().map(|k| k.id()).collect();
    v.sort();
    v
}

pub fn account_id(chain: &Chain) -> String {
    sha(&body_of(&chain.envs[0]))
}

pub fn request(
    account: &str,
    member: &Key,
    agree: &Key,
    kind: &str,
    terms: Value,
    label: &str,
    service: Option<Value>,
) -> String {
    let mut body = json!({"protocol": "colophon/request/5", "account": account,
                          "member": {"agreement": b64(&agree.point), "signing": b64(&member.point)},
                          "label": label, "kind": kind, "terms": terms, "created": T0});
    if let Some(s) = service {
        body["service"] = s;
    }
    b64(&env_bytes(&envelope(&body, member)))
}

pub fn grant_agent_with(
    chain: &mut Chain,
    by: &dyn Signer,
    issued: &str,
    signer: &dyn Signer,
    key: &Key,
    agree: &Key,
    expires: &str,
) -> Value {
    let acct = account_id(chain);
    let terms =
        json!({"services": [{"audience": AUD, "purposes": ["task.read"]}], "expires": expires});
    let req = request(
        &acct,
        key,
        agree,
        "agent",
        json!({"services": [{"audience": AUD, "purposes": ["task.read"]}]}),
        "Agent",
        None,
    );
    chain.add(
        "grant",
        by,
        issued,
        signer,
        Opt::default(),
        json!({"request": req, "terms": terms, "shares": []}),
    )
}
pub fn grant_agent(chain: &mut Chain, by: &dyn Signer, issued: &str, signer: &dyn Signer) -> Value {
    grant_agent_with(
        chain,
        by,
        issued,
        signer,
        &AGENT_K,
        &AGENT_A,
        "2026-11-18T08:00:00Z",
    )
}

pub struct Gen<'a> {
    pub label: &'a str,
    pub namespaces: Vec<&'a str>,
    pub predecessor: Option<Value>,
    pub opt: Opt<'a>,
}
impl Default for Gen<'_> {
    fn default() -> Self {
        Gen {
            label: "Account",
            namespaces: vec![],
            predecessor: None,
            opt: Opt::default(),
        }
    }
}
/// `genesis`: the first signer is primary and the rest cosign.
pub fn genesis(chain: &mut Chain, kr: &Value, signers: Sl, g: Gen) -> Value {
    let (primary, cos) = signers.split_first().unwrap();
    let mut fields = json!({"label": g.label, "namespaces": g.namespaces, "keyring": kr});
    if let Some(p) = g.predecessor {
        fields["predecessor"] = p;
    }
    let o = Opt { cos, ..g.opt };
    chain.add("genesis", *primary, T0, *primary, o, fields)
}

pub fn ok_at(seq: i64) -> Value {
    json!({"result": "ok", "seq": seq})
}
pub fn bad(result: &str, seq: i64) -> Value {
    json!({"result": result, "seq": seq})
}

#[allow(clippy::too_many_arguments)]
pub fn write_case(
    o: &mut Out,
    name: &str,
    chain: &Chain,
    expected: Value,
    description: &str,
    sections: &[&str],
    extra: Vec<(String, Value)>,
    verifier: Option<Value>,
    branches: Vec<(String, Vec<(i64, Value)>)>,
) {
    for (i, env) in chain.envs.iter().enumerate() {
        write(
            o,
            &format!("rules/{name}/records/authority/{:08}.json", i + 1),
            env,
        );
    }
    for (rel, value) in &extra {
        write(o, &format!("rules/{name}/{rel}"), value);
    }
    for (label, envs) in &branches {
        for (seq, env) in envs {
            write(
                o,
                &format!("rules/{name}/branch-{label}/authority/{seq:08}.json"),
                env,
            );
        }
    }
    let verifier = match verifier {
        Some(v) if v.as_object().map(|m| !m.is_empty()).unwrap_or(true) => v,
        _ => json!({"now": "2026-11-20T00:00:00Z"}),
    };
    write(
        o,
        &format!("rules/{name}/case.json"),
        &json!({"description": description, "sections": sections, "expected": expected, "verifier": verifier}),
    );
}

// ---------------------------------------------------------------------------------------
// Sealed seed for the Swift keyring (matches the shipped Swift app's `colophon/sealed-key/1`).

pub fn swift_sealed(
    seed: &[u8],
    recipient_sign: &[u8],
    recipient_agree: &[u8],
    eph_name: &str,
) -> Value {
    let eph = derived(eph_name);
    let secret = p256::SecretKey::from_slice(&eph.scalar).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(recipient_agree).unwrap();
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(recipient_sign), shared.raw_secret_bytes().as_slice())
        .expand(b"colophon/sealed-key/1", &mut key)
        .unwrap();
    let nonce = sha_raw(eph_name.as_bytes())[..12].to_vec();
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), seed)
        .unwrap();
    let mut boxed = nonce;
    boxed.extend(ct);
    json!({"box": b64(&boxed), "ephemeral": b64(&eph.point)})
}
