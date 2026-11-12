//! Unit and property tests for `colophon_core::v05` with synthetic keys only.
//!
//! - canonical JSON: acceptance and rejection fuzzing against an independent model writer;
//! - DER: mutation fuzzing against an independent reading of §4.3 step 5;
//! - WebAuthn: every negative case of §4.3, in order;
//! - calls: the §12.3 pipeline and the §12.4 reservation over a hand-built view;
//! - records and members: header round trip, admission order, grant rules, §3.3.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use colophon_core::v05::{
    calls::{
        verify_call, AccountView, CallConfig, ControllerStatus, HistoryVerifierOutput,
        MemberStatus, ViewController, ViewMember, HISTORY_READ,
    },
    descriptor::{Controller, KeyDescriptor, Policy, WebAuthnKey},
    encoding::{canonical, canonical_body, digest, encode_base64, parse_date, strict_parse, Obj},
    floor::{FloorCounter, FLOOR},
    ids::{key_id, AccountId},
    members::{check_members_never_controllers, AuthorityHeader, Grant, GrantContext, MemberKind},
    records::{
        admit, admit_opened, operation_id, Admission, AuthorView, Kept, NamespaceView,
        OperationHeader,
    },
    replay::{retained, MemoryReplayStore, ReplayState, ReplayStore, MAX_WINDOW_MS, RETENTION_MS},
    signature::{
        parse_der, verify_authority_signature, AssertionBytes, AuthorityRule, Checked, SigFailure,
    },
    terms::{Terms, TermsKind},
    Reason,
};
#[path = "v05_attack_support/mod.rs"]
mod support;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use support::webauthn::{verify_webauthn, OriginRule, Strictness};

// ---------------------------------------------------------------------------------------
// A tiny deterministic PRNG (no new dependency).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ---------------------------------------------------------------------------------------
// Canonical JSON: an independent model writer. It formats integers itself and floats only
// from a fixed table of (value, canonical spelling), so it shares no code path with the
// engine's writer.
const FLOATS: &[(f64, &str)] = &[
    (1.0, "1.0"),
    (-0.0, "-0.0"),
    (0.1, "0.1"),
    (1.5, "1.5"),
    (1e21, "1e21"),
    (1e-7, "1e-7"),
    (123456.789, "123456.789"),
    (-2.5e-10, "-2.5e-10"),
];
fn model_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
fn model(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string())
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string())
            } else {
                let f = n.as_f64().unwrap();
                let (_, s) = FLOATS
                    .iter()
                    .find(|(x, _)| x.to_bits() == f.to_bits())
                    .expect("float from table");
                out.push_str(s)
            }
        }
        Value::String(s) => model_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                model(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                model_string(k, out);
                out.push(':');
                model(&m[k], out);
            }
            out.push('}');
        }
    }
}
const ALPHABET: &[&str] = &[
    "a", "b", "Z", "é", "/", "\"", "\\", "\n", "\u{1}", "\u{7f}", "😀", " ", "ab", "b0",
];
fn random_string(r: &mut Rng) -> String {
    (0..r.below(4))
        .map(|_| ALPHABET[r.below(ALPHABET.len() as u64) as usize])
        .collect()
}
fn random_value(r: &mut Rng, depth: u32) -> Value {
    match r.below(if depth > 3 { 6 } else { 8 }) {
        0 => Value::Null,
        1 => Value::Bool(r.below(2) == 0),
        2 => json!(r.next() as i64 >> r.below(64)),
        3 => json!(r.next() >> r.below(64)),
        4 => json!(FLOATS[r.below(FLOATS.len() as u64) as usize].0),
        5 => Value::String(random_string(r)),
        6 => Value::Array(
            (0..r.below(4))
                .map(|_| random_value(r, depth + 1))
                .collect(),
        ),
        _ => Value::Object(random_object(r, depth + 1)),
    }
}
fn random_object(r: &mut Rng, depth: u32) -> Map<String, Value> {
    let mut m = Map::new();
    for _ in 0..r.below(5) {
        m.insert(random_string(r), random_value(r, depth));
    }
    m
}

#[test]
fn canonical_json_agrees_with_an_independent_model() {
    let mut r = Rng(0x5eed_cafe_f00d_1234);
    let mut accepted_mutants = 0;
    for _ in 0..3_000 {
        let v = Value::Object(random_object(&mut r, 0));
        let mut text = String::new();
        model(&v, &mut text);
        // The engine's writer and the model agree, and the model's text is accepted as is.
        assert_eq!(
            canonical(&v).unwrap(),
            text.as_bytes(),
            "writer disagrees with model"
        );
        assert_eq!(canonical_body(text.as_bytes(), usize::MAX).unwrap(), v);
        // Mutations: whatever the engine accepts must be exactly the model's encoding of
        // its own parse; otherwise it must be refused.
        for _ in 0..8 {
            let mut bytes = text.clone().into_bytes();
            match r.below(6) {
                0 if !bytes.is_empty() => {
                    let i = r.below(bytes.len() as u64) as usize;
                    bytes.insert(i, b' ');
                }
                1 if !bytes.is_empty() => {
                    let i = r.below(bytes.len() as u64) as usize;
                    bytes.remove(i);
                }
                2 if !bytes.is_empty() => {
                    let i = r.below(bytes.len() as u64) as usize;
                    bytes[i] = b"{}[],:\"0123456789eE.-+/\\un"[r.below(26) as usize];
                }
                3 => bytes.extend_from_slice(b"\n"),
                4 => {
                    let s = String::from_utf8_lossy(&bytes).replace('/', "\\/");
                    bytes = s.into_bytes();
                }
                _ => {
                    let s = String::from_utf8_lossy(&bytes)
                        .replace("1.0", "1.00")
                        .replace("1e21", "1E21");
                    bytes = s.into_bytes();
                }
            }
            if let Ok(parsed) = canonical_body(&bytes, usize::MAX) {
                let mut again = String::new();
                if FLOATS_ONLY(&parsed) {
                    model(&parsed, &mut again);
                    assert_eq!(
                        again.as_bytes(),
                        &bytes[..],
                        "accepted a non-canonical mutant"
                    );
                }
                accepted_mutants += 1;
            }
        }
    }
    // Some mutations are no-ops (for example replacing a byte with itself) and stay canonical.
    assert!(accepted_mutants < 3_000 * 8 / 2);
}
#[allow(non_snake_case)]
fn FLOATS_ONLY(v: &Value) -> bool {
    match v {
        Value::Number(n) if n.is_f64() => FLOATS
            .iter()
            .any(|(x, _)| x.to_bits() == n.as_f64().unwrap().to_bits()),
        Value::Array(a) => a.iter().all(FLOATS_ONLY),
        Value::Object(m) => m.values().all(FLOATS_ONLY),
        _ => true,
    }
}

#[test]
fn canonical_refuses_duplicates_and_reordering_everywhere() {
    for bad in [
        r#"{"a":{"x":1,"x":1}}"#,
        r#"{"a":[{"b":1,"b":1}]}"#,
        r#"{"b":0,"a":0}"#,
        r#"{"a":{"d":0,"c":0}}"#,
        r#"{"é":0,"z":0}"#,
    ] {
        assert!(canonical_body(bad.as_bytes(), usize::MAX).is_err(), "{bad}");
    }
    // Sort is by UTF-8 bytes: "z" (0x7a) before "é" (0xc3 0xa9), and "Z" before "a".
    canonical_body("{\"Z\":0,\"a\":0,\"z\":0,\"é\":0}".as_bytes(), usize::MAX).unwrap();
}

// ---------------------------------------------------------------------------------------
// DER: an independent reading of §4.3 step 5's grammar (ignoring the scalar range).
fn model_der(b: &[u8]) -> bool {
    fn int(b: &[u8], i: usize) -> Option<usize> {
        if *b.get(i)? != 2 {
            return None;
        }
        let len = *b.get(i + 1)? as usize;
        if len == 0 || len > 33 || len >= 0x80 {
            return None;
        }
        let v = b.get(i + 2..i + 2 + len)?;
        if v[0] & 0x80 != 0 {
            return None;
        }
        if v[0] == 0 && len > 1 && v[1] & 0x80 == 0 {
            return None;
        }
        if len == 33 && v[0] != 0 {
            return None;
        }
        Some(i + 2 + len)
    }
    if b.len() < 2 || b[0] != 0x30 || b[1] >= 0x80 || b[1] as usize != b.len() - 2 {
        return false;
    }
    match int(b, 2).and_then(|j| int(b, j)) {
        Some(end) => end == b.len(),
        None => false,
    }
}

#[test]
fn der_mutations_agree_with_an_independent_grammar() {
    let k = SigningKey::from_slice(&[9; 32]).unwrap();
    let mut r = Rng(42);
    let mut checked = 0;
    for m in 0..200u32 {
        let sig: Signature = k.sign(&m.to_be_bytes());
        let der = sig.to_der().as_bytes().to_vec();
        assert!(parse_der(&der).is_ok() && model_der(&der));
        for _ in 0..50 {
            let mut b = der.clone();
            match r.below(5) {
                0 => {
                    let i = r.below(b.len() as u64) as usize;
                    b[i] ^= 1 << r.below(8);
                }
                1 => b.push(r.below(256) as u8),
                2 => {
                    let i = r.below(b.len() as u64) as usize;
                    b.remove(i);
                }
                3 => {
                    let i = 2 + r.below(b.len() as u64 - 2) as usize;
                    b.insert(i, 0);
                }
                _ => {
                    b[1] = b[1].wrapping_add(1);
                }
            }
            let engine = parse_der(&b);
            match engine {
                Ok(_) => assert!(
                    model_der(&b),
                    "engine accepted what the grammar refuses: {b:02x?}"
                ),
                Err(SigFailure::Der) => {
                    assert!(!model_der(&b), "engine refused valid grammar: {b:02x?}")
                }
                Err(SigFailure::Scalar) => {
                    assert!(model_der(&b), "scalar failure on invalid grammar")
                }
                Err(e) => panic!("{e:?}"),
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 10_000);
}

// ---------------------------------------------------------------------------------------
// WebAuthn.
struct Authn {
    k: SigningKey,
    rp: String,
}
impl Authn {
    fn new(seed: u8, rp: &str) -> Self {
        Self {
            k: SigningKey::from_slice(&[seed; 32]).unwrap(),
            rp: rp.into(),
        }
    }
    fn point(&self) -> Vec<u8> {
        self.k
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
    fn key(&self, authority: Option<Vec<String>>) -> WebAuthnKey {
        WebAuthnKey::new(self.rp.clone(), vec![1], None, authority).unwrap()
    }
    fn client(&self, body: &[u8], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false,"other":1}}"#,
            URL_SAFE_NO_PAD.encode(Sha256::digest(body))
        )
        .into_bytes()
    }
    fn data(&self, flags: u8) -> Vec<u8> {
        let mut d = Sha256::digest(self.rp.as_bytes()).to_vec();
        d.push(flags);
        d.extend_from_slice(&[0, 0, 0, 7]);
        d
    }
    fn sign(&self, data: &[u8], client: &[u8]) -> Vec<u8> {
        let mut m = data.to_vec();
        m.extend_from_slice(&Sha256::digest(client));
        let s: Signature = self.k.sign(&m);
        s.to_der().as_bytes().to_vec()
    }
}
fn wa(
    a: &Authn,
    key: &WebAuthnKey,
    body: &[u8],
    data: &[u8],
    client: &[u8],
    uv: bool,
    rule: OriginRule<'_>,
) -> Result<(), SigFailure> {
    let sig = a.sign(data, client);
    verify_webauthn(
        &a.point(),
        key,
        body,
        &sig,
        AssertionBytes {
            authenticator_data: data,
            client_data: client,
        },
        uv,
        rule,
        Strictness::Current,
    )
    .map(|_| ())
}

#[test]
fn webauthn_negative_cases_in_order() {
    let a = Authn::new(7, "id.example");
    let open = a.key(None);
    let pinned = a.key(Some(vec!["https://keys.id.example".into()]));
    let body = b"{\"x\":1}";
    let ok_client = a.client(body, "https://id.example");
    let d = a.data(0x05);
    wa(&a, &open, body, &d, &ok_client, true, OriginRule::Authority).unwrap();
    // Bytes after 36 and other flags are ignored; the counter is ignored.
    let mut ext = a.data(0x05 | 0x08 | 0x10 | 0x40 | 0x80);
    ext.extend_from_slice(&[0xaa; 20]);
    wa(
        &a,
        &open,
        body,
        &ext,
        &ok_client,
        true,
        OriginRule::Authority,
    )
    .unwrap();
    // clientData.
    let dup = br#"{"type":"webauthn.get","type":"webauthn.get","challenge":"x","origin":"https://id.example"}"#;
    assert_eq!(
        wa(&a, &open, body, &d, dup, false, OriginRule::General),
        Err(SigFailure::ClientData)
    );
    assert_eq!(
        wa(&a, &open, body, &d, b"[1]", false, OriginRule::General),
        Err(SigFailure::ClientData)
    );
    let big = format!(r#"{{"type":"webauthn.get","pad":"{}"}}"#, "x".repeat(8_200)).into_bytes();
    assert_eq!(
        wa(&a, &open, body, &d, &big, false, OriginRule::General),
        Err(SigFailure::ClientDataBound)
    );
    let wrong_type = String::from_utf8(ok_client.clone())
        .unwrap()
        .replace("webauthn.get", "webauthn.create")
        .into_bytes();
    assert_eq!(
        wa(&a, &open, body, &d, &wrong_type, false, OriginRule::General),
        Err(SigFailure::Type)
    );
    let other_body = a.client(b"{}", "https://id.example");
    assert_eq!(
        wa(&a, &open, body, &d, &other_body, false, OriginRule::General),
        Err(SigFailure::Challenge)
    );
    // Origins.
    let sub = a.client(body, "https://keys.id.example");
    wa(&a, &open, body, &d, &sub, false, OriginRule::General).unwrap();
    assert_eq!(
        wa(&a, &open, body, &d, &sub, false, OriginRule::Authority),
        Err(SigFailure::Origin),
        "no pin: subdomain is not an authority origin"
    );
    wa(&a, &pinned, body, &d, &sub, false, OriginRule::Authority).unwrap();
    assert_eq!(
        wa(
            &a,
            &pinned,
            body,
            &d,
            &ok_client,
            false,
            OriginRule::Authority
        ),
        Err(SigFailure::Origin),
        "pinned: bare rp refused"
    );
    let evil = a.client(body, "https://id.example.evil");
    assert_eq!(
        wa(&a, &open, body, &d, &evil, false, OriginRule::General),
        Err(SigFailure::Origin)
    );
    let call_origins = vec!["https://sign.id.example".to_string()];
    let sign = a.client(body, "https://sign.id.example");
    wa(
        &a,
        &open,
        body,
        &d,
        &sign,
        false,
        OriginRule::Call(&call_origins),
    )
    .unwrap();
    assert_eq!(
        wa(
            &a,
            &open,
            body,
            &d,
            &sub,
            false,
            OriginRule::Call(&call_origins)
        ),
        Err(SigFailure::CallOrigin)
    );
    // Swift predecessors: the general rule only, whatever pins would say.
    let sig = a.sign(&d, &sub);
    verify_webauthn(
        &a.point(),
        &pinned,
        body,
        &sig,
        AssertionBytes {
            authenticator_data: &d,
            client_data: &sub,
        },
        false,
        OriginRule::Authority,
        Strictness::SwiftPredecessor,
    )
    .unwrap();
    // crossOrigin.
    for co in ["true", "\"false\"", "null"] {
        let c = String::from_utf8(ok_client.clone())
            .unwrap()
            .replace("\"crossOrigin\":false", &format!("\"crossOrigin\":{co}"))
            .into_bytes();
        assert_eq!(
            wa(&a, &open, body, &d, &c, false, OriginRule::General),
            Err(SigFailure::CrossOrigin),
            "{co}"
        );
    }
    // Authenticator data.
    assert_eq!(
        wa(
            &a,
            &open,
            body,
            &d[..36],
            &ok_client,
            false,
            OriginRule::General
        ),
        Err(SigFailure::RelyingParty)
    );
    let other_rp = Authn::new(7, "other.example").data(0x05);
    assert_eq!(
        wa(
            &a,
            &open,
            body,
            &other_rp,
            &ok_client,
            false,
            OriginRule::General
        ),
        Err(SigFailure::RelyingParty)
    );
    assert_eq!(
        wa(
            &a,
            &open,
            body,
            &a.data(0x04),
            &ok_client,
            false,
            OriginRule::General
        ),
        Err(SigFailure::UserPresence)
    );
    assert_eq!(
        wa(
            &a,
            &open,
            body,
            &a.data(0x01),
            &ok_client,
            true,
            OriginRule::General
        ),
        Err(SigFailure::UserVerification)
    );
    wa(
        &a,
        &open,
        body,
        &a.data(0x01),
        &ok_client,
        false,
        OriginRule::General,
    )
    .unwrap();
    // Signature: wrong key, raw instead of DER.
    let sig = Authn::new(8, "id.example").sign(&d, &ok_client);
    assert_eq!(
        verify_webauthn(
            &a.point(),
            &open,
            body,
            &sig,
            AssertionBytes {
                authenticator_data: &d,
                client_data: &ok_client
            },
            false,
            OriginRule::General,
            Strictness::Current
        ),
        Err(SigFailure::Verify)
    );
    let raw: Signature = a.k.sign(b"x");
    assert_eq!(
        verify_webauthn(
            &a.point(),
            &open,
            body,
            &raw.to_bytes(),
            AssertionBytes {
                authenticator_data: &d,
                client_data: &ok_client
            },
            false,
            OriginRule::General,
            Strictness::Current
        ),
        Err(SigFailure::Der)
    );
}

// ---------------------------------------------------------------------------------------
// Calls over views built by the sealed builder.
const AUD: &str = "https://projects.example/scopes/7";
const HOME_EP: &str = "https://home.example/v1/accounts/x";
const NOW: &str = "2026-11-11T09:01:00Z";
fn k(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn pt(k: &SigningKey) -> Vec<u8> {
    k.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn raw_env(body: &Value, signer: &SigningKey) -> Vec<u8> {
    let b = canonical(body).unwrap();
    let s: Signature = signer.sign(&b);
    canonical(&json!({"body": STANDARD.encode(&b), "signature": STANDARD.encode(s.to_bytes())}))
        .unwrap()
}
fn terms(v: Value, kind: TermsKind) -> Terms {
    Terms::parse(v, kind).unwrap()
}
fn now() -> i64 {
    parse_date(NOW).unwrap()
}
fn raw_ctrl(key: &SigningKey, roles: &[&str]) -> Controller {
    Controller::parse(
        json!({"key":{"form":"raw","signing":encode_base64(&pt(key))},"label":"k","roles":roles}),
        "c",
    )
    .unwrap()
}
fn passkey_ctrl(a: &Authn) -> Controller {
    Controller::parse(
        json!({"key":{"form":"webauthn","signing":encode_base64(&a.point()),"rp":a.rp,"credential":"AQ==",
               "authorityOrigins":["https://keys.id.example"]},"label":"p","roles":["approve","control"],"verification":true}),
        "c",
    )
    .unwrap()
}

type CtrlParts = (String, Vec<(u64, Option<Controller>)>, ControllerStatus);
/// The inputs of a view, which tests vary before building.
#[derive(Clone)]
struct Parts {
    account: AccountId,
    history: Vec<String>,
    member_terms: Value,
    member_granted: u64,
    member_end_sessions: Vec<u64>,
    member_revoked: Option<u64>,
    member_status: MemberStatus,
    home_status: MemberStatus,
    controllers: Vec<CtrlParts>,
    policies: Vec<(u64, Policy)>,
    head_seq: u64,
    head_issued: String,
}
struct Fx {
    parts: Parts,
    member: SigningKey,
    home: SigningKey,
    passkey: Authn,
    recover: SigningKey,
}
fn fixture() -> Fx {
    let member = k(21);
    let home = k(22);
    let passkey = Authn::new(23, "id.example");
    let recover = k(24);
    let pc = passkey_ctrl(&passkey);
    let rc = raw_ctrl(&recover, &["recover"]);
    let parts = Parts {
        account: AccountId::parse(&"e".repeat(64)).unwrap(),
        history: (1..=3)
            .map(|i| digest(format!("entry {i}").as_bytes()))
            .collect(),
        member_terms: json!({"services":[{"audience":AUD,"purposes":["task.propose","task.read"]}],"depth":2,
                             "expires":"2026-11-18T08:00:00Z","conditions":[{"prefix":["args.task","T-"]}]}),
        member_granted: 2,
        member_end_sessions: vec![],
        member_revoked: None,
        member_status: MemberStatus::Active,
        home_status: MemberStatus::Active,
        controllers: vec![
            (pc.id(), vec![(1, Some(pc))], ControllerStatus::Active),
            (rc.id(), vec![(1, Some(rc))], ControllerStatus::Active),
        ],
        policies: vec![(1, Policy::default_person())],
        head_seq: 3,
        head_issued: "2026-11-11T09:00:00Z".into(),
    };
    Fx {
        parts,
        member,
        home,
        passkey,
        recover,
    }
}
fn head_env(fx: &Fx, p: &Parts) -> Vec<u8> {
    raw_env(
        &json!({"protocol":"colophon/head/5","account":p.account.as_str(),
                "authority":{"seq":p.head_seq,"digest":p.history[p.head_seq as usize - 1]},
                "issued":p.head_issued,"by":key_id(&pt(&fx.home))}),
        &fx.home,
    )
}
fn build(fx: &Fx, p: &Parts) -> AccountView {
    let members = vec![
        ViewMember::new(
            pt(&fx.member),
            MemberKind::Agent,
            Terms::parse(p.member_terms.clone(), TermsKind::Member).unwrap(),
            p.member_granted,
            vec![],
            p.member_end_sessions.clone(),
            p.member_revoked,
            p.member_status,
        )
        .unwrap(),
        ViewMember::new(
            pt(&fx.home),
            MemberKind::Server,
            terms(json!({"serves":["home"]}), TermsKind::Member),
            3,
            vec![],
            vec![],
            None,
            p.home_status,
        )
        .unwrap(),
    ];
    let controllers = p
        .controllers
        .iter()
        .map(|(id, v, st)| ViewController::new(id.clone(), v.clone(), *st).unwrap())
        .collect();
    let points: BTreeSet<Vec<u8>> = [
        pt(&fx.member),
        pt(&fx.home),
        fx.passkey.point(),
        pt(&fx.recover),
    ]
    .into_iter()
    .collect();
    AccountView::from_history_verifier(HistoryVerifierOutput {
        account: p.account.clone(),
        history: p.history.clone(),
        policies: p.policies.clone(),
        controllers,
        members,
        heads: vec![head_env(fx, p)],
        vouched_fork: false,
        principal_points: points,
    })
    .unwrap()
}
fn call_body(
    fx: &Fx,
    signer: Value,
    key: &[u8],
    links: Option<Vec<String>>,
    purpose: &str,
    args: Value,
    rid: u8,
) -> Value {
    let mut b = json!({"protocol":"colophon/call/5","account":fx.parts.account.as_str(),"asOf":{"seq":3,"digest":fx.parts.history[2]},
        "signer":signer,"key":encode_base64(key),"audience":AUD,"purpose":purpose,"args":args,
        "requestId":URL_SAFE_NO_PAD.encode([rid; 32]),"created":NOW});
    if let Some(l) = links {
        b["links"] = json!(l);
    }
    b
}
fn link(fx: &Fx, from: &SigningKey, to: &SigningKey, t: Value, session: Option<u64>) -> String {
    let mut b = json!({"protocol":"colophon/link/5","account":fx.parts.account.as_str(),"from":key_id(&pt(from)),
        "to":{"signing":encode_base64(&pt(to))},"terms":t,"notBefore":"2026-11-11T09:00:00Z","expires":"2026-11-11T09:10:00Z","created":"2026-11-11T09:00:00Z"});
    if let Some(s) = session {
        b["session"] = json!(s);
    }
    STANDARD.encode(raw_env(&b, from))
}
fn run_at(
    view: &AccountView,
    env: &[u8],
    store: &mut MemoryReplayStore,
    purposes: &[&str],
    homes: &[&str],
    at: i64,
) -> String {
    let aud = vec![AUD.to_string(), HOME_EP.to_string()];
    let origins: BTreeMap<String, Vec<String>> = [(
        "id.example".to_string(),
        vec!["https://sign.id.example".to_string()],
    )]
    .into();
    let purposes: Vec<String> = purposes.iter().map(|s| s.to_string()).collect();
    let homes: Vec<String> = homes.iter().map(|s| s.to_string()).collect();
    let cfg = CallConfig {
        now_ms: at,
        audiences: &aud,
        call_origins: &origins,
        controller_purposes: &purposes,
        home_endpoints: &homes,
    };
    match verify_call(env, view, &cfg, store) {
        Ok(_) => "ok".into(),
        Err(e) => e.code(),
    }
}
fn run(view: &AccountView, env: &[u8], store: &mut MemoryReplayStore, purposes: &[&str]) -> String {
    run_at(view, env, store, purposes, &[], now())
}
const NARROW: &str = r#"{"services":[{"audience":"https://projects.example/scopes/7","purposes":["task.read"]}],"conditions":[{"prefix":["args.task","T-"]}]}"#;
fn narrow() -> Value {
    serde_json::from_str(NARROW).unwrap()
}

#[test]
fn member_calls_links_and_reservations() {
    let fx = fixture();
    let view = build(&fx, &fx.parts);
    let mid = json!({"member": key_id(&pt(&fx.member))});
    let mut store = MemoryReplayStore::new();
    let own = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-1"}),
            1,
        ),
        &fx.member,
    );
    assert_eq!(run(&view, &own, &mut store, &[]), "ok");
    assert_eq!(store.len(), 1);
    assert_eq!(run(&view, &own, &mut store, &[]), "refused:replay");
    let other = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-2"}),
            1,
        ),
        &fx.member,
    );
    assert_eq!(run(&view, &other, &mut store, &[]), "refused:conflict");
    let bad = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.member),
            None,
            "task.delete",
            json!({"task":"T-1"}),
            2,
        ),
        &fx.member,
    );
    assert_eq!(run(&view, &bad, &mut store, &[]), "refused:outOfScope");
    assert_eq!(store.len(), 1, "refusals don't reserve");
    let session = k(31);
    let l = link(&fx, &fx.member, &session, narrow(), Some(0));
    let via = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&session),
            Some(vec![l.clone()]),
            "task.read",
            json!({"task":"T-1"}),
            3,
        ),
        &session,
    );
    assert_eq!(run(&view, &via, &mut store, &[]), "ok");
    let dropped = link(
        &fx,
        &fx.member,
        &session,
        json!({"services":[{"audience":AUD,"purposes":["task.read"]}]}),
        Some(0),
    );
    let via2 = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&session),
            Some(vec![dropped]),
            "task.read",
            json!({"task":"T-1"}),
            4,
        ),
        &session,
    );
    assert_eq!(run(&view, &via2, &mut store, &[]), "refused:notNarrower");
    let attacker = k(32);
    let copied = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&attacker),
            Some(vec![l.clone()]),
            "task.read",
            json!({"task":"T-1"}),
            5,
        ),
        &attacker,
    );
    assert_eq!(run(&view, &copied, &mut store, &[]), "badSignature");
    let ended = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&session),
            Some(vec![link(&fx, &fx.member, &session, narrow(), Some(1))]),
            "task.read",
            json!({"task":"T-1"}),
            6,
        ),
        &session,
    );
    assert_eq!(run(&view, &ended, &mut store, &[]), "refused:ended");
    let s2 = k(33);
    let two = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&s2),
            Some(vec![l.clone(), link(&fx, &session, &s2, narrow(), None)]),
            "task.read",
            json!({"task":"T-1"}),
            7,
        ),
        &s2,
    );
    assert_eq!(run(&view, &two, &mut store, &[]), "refused:notNarrower");
    let to_principal = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.recover),
            Some(vec![link(&fx, &fx.member, &fx.recover, narrow(), Some(0))]),
            "task.read",
            json!({"task":"T-1"}),
            8,
        ),
        &fx.recover,
    );
    assert_eq!(run(&view, &to_principal, &mut store, &[]), "malformed");
    let mut body = call_body(
        &fx,
        json!({"account": "x"}),
        &pt(&fx.member),
        None,
        "task.read",
        json!({"task":"T-1"}),
        9,
    );
    assert_eq!(
        run(&view, &raw_env(&body, &fx.member), &mut store, &[]),
        "malformed"
    );
    body["signer"] = mid.clone();
    body["protocol"] = json!("colophon/call/6");
    assert_eq!(
        run(&view, &raw_env(&body, &fx.member), &mut store, &[]),
        "malformed"
    );
    let mut future = call_body(
        &fx,
        mid.clone(),
        &pt(&fx.member),
        None,
        "task.read",
        json!({"task":"T-1"}),
        10,
    );
    future["future"] = json!(1);
    assert_eq!(
        run(&view, &raw_env(&future, &fx.member), &mut store, &[]),
        "newerFormat"
    );
    future["purpose"] = json!("task.delete");
    assert_eq!(
        run(&view, &raw_env(&future, &fx.member), &mut store, &[]),
        "refused:outOfScope"
    );
}

#[test]
fn unknown_condition_operators_are_three_valued() {
    let fx = fixture();
    let mid = json!({"member": key_id(&pt(&fx.member))});
    // A view whose member terms carry an unknown operator: the pipeline re-checks them.
    let mut p = fx.parts.clone();
    p.member_terms = json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"depth":1,"conditions":[{"not":{"future":["task",1]}}]});
    let view = build(&fx, &p);
    let env = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-1"}),
            1,
        ),
        &fx.member,
    );
    assert_eq!(
        run(&view, &env, &mut MemoryReplayStore::new(), &[]),
        "newerFormat",
        "not(unknown) is unknown, not outOfScope"
    );
    p.member_terms = json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"depth":1,"conditions":[{"future":1},{"eq":["task","X"]}]});
    let view = build(&fx, &p);
    assert_eq!(
        run(&view, &env, &mut MemoryReplayStore::new(), &[]),
        "refused:outOfScope",
        "a false predicate decides"
    );
    // An unknown term (not a condition) in view terms is newerFormat too.
    p.member_terms = json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"later":1});
    let view = build(&fx, &p);
    let mut store = MemoryReplayStore::new();
    assert_eq!(run(&view, &env, &mut store, &[]), "newerFormat");
    assert!(store.is_empty());
    // An unknown operator in a link.
    let view = build(&fx, &fx.parts);
    let session = k(31);
    let t = json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"conditions":[{"prefix":["args.task","T-"]},{"future":1}]});
    let via = raw_env(
        &call_body(
            &fx,
            mid,
            &pt(&session),
            Some(vec![link(&fx, &fx.member, &session, t, Some(0))]),
            "task.read",
            json!({"task":"T-1"}),
            2,
        ),
        &session,
    );
    assert_eq!(
        run(&view, &via, &mut MemoryReplayStore::new(), &[]),
        "newerFormat"
    );
}

#[test]
fn replay_window_and_retention_boundary() {
    // H1: a call created at T + 3,600 s is accepted at T and must stay refused at T + 7,200 s.
    const _: () = assert!(RETENTION_MS > 2 * MAX_WINDOW_MS);
    let t = 1_000_000_000_000i64;
    assert!(retained(t, t + 2 * MAX_WINDOW_MS));
    assert!(retained(t, t + RETENTION_MS));
    assert!(!retained(t, t + RETENTION_MS + 1));
    assert!(
        retained(i64::MIN, i64::MIN) && !retained(i64::MIN, i64::MAX),
        "no overflow"
    );
    let mut fx = fixture();
    // A policy with callWindow 3,600 so that only step 3's window binds.
    let pol = Policy::parse(
        json!({"callWindow":3600,"headMaxAge":86400,"headQuorum":1,"history":"members","linkMaxAge":86400,"memberRule":"single",
               "rate":{"signer":{"entries":64,"bytes":4194304},"account":{"entries":256,"bytes":16777216}},"recoveryDelay":259200}),
        "policy",
    )
    .unwrap();
    fx.parts.policies = vec![(1, pol)];
    let created = now() + MAX_WINDOW_MS;
    let mut p = fx.parts.clone();
    let iso = |ms: i64| -> String {
        let s = (ms / 1000) % 86_400;
        format!(
            "2026-11-{:02}T{:02}:{:02}:{:02}Z",
            11 + ms / 1000 / 86_400 - now() / 1000 / 86_400,
            s / 3600,
            s / 60 % 60,
            s % 60
        )
    };
    let mid = json!({"member": key_id(&pt(&fx.member))});
    let mut body = call_body(
        &fx,
        mid,
        &pt(&fx.member),
        None,
        "task.read",
        json!({"task":"T-1"}),
        1,
    );
    body["created"] = json!(iso(created));
    let env = raw_env(&body, &fx.member);
    let mut store = MemoryReplayStore::new();
    for (at, want) in [
        (now(), "ok"),
        (now() + 2 * MAX_WINDOW_MS, "refused:replay"),
        (now() + 2 * MAX_WINDOW_MS + 1, "refused:window"),
    ] {
        p.head_issued = iso(at - 1000);
        let view = build(&fx, &p);
        assert_eq!(
            run_at(&view, &env, &mut store, &[], &[], at),
            want,
            "at {at}"
        );
    }
}

#[test]
fn sealed_view_refuses_invalid_input_and_never_panics() {
    let fx = fixture();
    let ok = || HistoryVerifierOutput {
        account: fx.parts.account.clone(),
        history: fx.parts.history.clone(),
        policies: fx.parts.policies.clone(),
        controllers: vec![],
        members: vec![],
        heads: vec![],
        vouched_fork: false,
        principal_points: BTreeSet::new(),
    };
    assert!(AccountView::from_history_verifier(ok()).is_ok());
    for bad in [
        HistoryVerifierOutput {
            history: vec![],
            ..ok()
        },
        HistoryVerifierOutput {
            history: vec!["x".into()],
            ..ok()
        },
        HistoryVerifierOutput {
            policies: vec![],
            ..ok()
        },
        HistoryVerifierOutput {
            policies: vec![(2, Policy::default_person())],
            ..ok()
        },
        HistoryVerifierOutput {
            policies: vec![(1, Policy::default_person()), (9, Policy::default_person())],
            ..ok()
        },
        HistoryVerifierOutput {
            heads: vec![vec![0; 20_000]],
            ..ok()
        },
    ] {
        assert!(AccountView::from_history_verifier(bad).is_err());
    }
    let pc = passkey_ctrl(&fx.passkey);
    assert!(ViewController::new(
        pc.id(),
        vec![(0, Some(pc.clone()))],
        ControllerStatus::Active
    )
    .is_err());
    assert!(ViewController::new(
        pc.id(),
        vec![(2, Some(pc.clone())), (2, None)],
        ControllerStatus::Active
    )
    .is_err());
    assert!(ViewController::new(pc.id(), vec![(1, None)], ControllerStatus::Active).is_err());
    assert!(ViewController::new(
        "0".repeat(32),
        vec![(1, Some(pc.clone()))],
        ControllerStatus::Active
    )
    .is_err());
    assert!(ViewController::new(pc.id(), vec![], ControllerStatus::Active).is_err());
    let t = || {
        terms(
            json!({"services":[{"audience":AUD,"purposes":["x"]}]}),
            TermsKind::Member,
        )
    };
    assert!(ViewMember::new(
        pt(&fx.member),
        MemberKind::Agent,
        t(),
        0,
        vec![],
        vec![],
        None,
        MemberStatus::Active
    )
    .is_err());
    assert!(ViewMember::new(
        pt(&fx.member),
        MemberKind::Agent,
        t(),
        2,
        vec![(2, 0)],
        vec![],
        None,
        MemberStatus::Active
    )
    .is_err());
    assert!(ViewMember::new(
        pt(&fx.member),
        MemberKind::Agent,
        t(),
        2,
        vec![],
        vec![],
        Some(1),
        MemberStatus::Active
    )
    .is_err());
    assert!(ViewMember::new(
        vec![4; 65],
        MemberKind::Agent,
        t(),
        2,
        vec![],
        vec![],
        None,
        MemberStatus::Active
    )
    .is_err());
    let m = ViewMember::new(
        pt(&fx.member),
        MemberKind::Agent,
        t(),
        9,
        vec![],
        vec![],
        None,
        MemberStatus::Active,
    )
    .unwrap();
    assert!(
        AccountView::from_history_verifier(HistoryVerifierOutput {
            members: vec![m],
            ..ok()
        })
        .is_err(),
        "grant beyond history"
    );
    // Extreme clocks never panic.
    let view = build(&fx, &fx.parts);
    let env = raw_env(
        &call_body(
            &fx,
            json!({"member": key_id(&pt(&fx.member))}),
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-1"}),
            1,
        ),
        &fx.member,
    );
    for at in [i64::MIN, i64::MAX, 0, -1] {
        assert_eq!(
            run_at(&view, &env, &mut MemoryReplayStore::new(), &[], &[], at),
            "refused:window"
        );
    }
}

#[test]
fn evaluation_point_and_removals_after_s() {
    let fx = fixture();
    let mid = json!({"member": key_id(&pt(&fx.member))});
    let env = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-1"}),
            1,
        ),
        &fx.member,
    );
    let mut p = fx.parts.clone();
    p.history.push(digest(b"entry 4"));
    p.member_granted = 4;
    assert_eq!(
        run(&build(&fx, &p), &env, &mut MemoryReplayStore::new(), &[]),
        "refused:revoked",
        "grant after S"
    );
    p.member_granted = 2;
    p.member_end_sessions = vec![4];
    let session = k(31);
    let via = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&session),
            Some(vec![link(&fx, &fx.member, &session, narrow(), Some(0))]),
            "task.read",
            json!({"task":"T-1"}),
            2,
        ),
        &session,
    );
    assert_eq!(
        run(&build(&fx, &p), &via, &mut MemoryReplayStore::new(), &[]),
        "refused:ended"
    );
    p.member_end_sessions = vec![];
    p.member_revoked = Some(4);
    assert_eq!(
        run(&build(&fx, &p), &env, &mut MemoryReplayStore::new(), &[]),
        "refused:revoked"
    );
    p.member_revoked = None;
    p.member_status = MemberStatus::AddedNotFinal;
    assert_eq!(
        run(&build(&fx, &p), &env, &mut MemoryReplayStore::new(), &[]),
        "refused:revoked",
        "member not final"
    );
    p.member_status = MemberStatus::Active;
    p.home_status = MemberStatus::AddedNotFinal;
    assert_eq!(
        run(&build(&fx, &p), &env, &mut MemoryReplayStore::new(), &[]),
        "unavailable",
        "a non-final home's heads don't count"
    );
    p.home_status = MemberStatus::Active;
    p.head_issued = "2026-11-11T08:50:00Z".into();
    assert_eq!(
        run(&build(&fx, &p), &env, &mut MemoryReplayStore::new(), &[]),
        "unavailable",
        "stale head"
    );
    let mut f = fx.parts.clone();
    f.history[2] = digest(b"other");
    assert_eq!(
        run(&build(&fx, &f), &env, &mut MemoryReplayStore::new(), &[]),
        "refused:fork",
        "asOf names another digest"
    );
}

#[test]
fn controller_calls_origins_roles_and_statuses() {
    let fx = fixture();
    let pid = key_id(&fx.passkey.point());
    let body = call_body(
        &fx,
        json!({"controller": pid}),
        &fx.passkey.point(),
        None,
        "sign-in",
        json!({}),
        1,
    );
    let make = |origin: &str, flags: u8, b: &Value| -> Vec<u8> {
        let bytes = canonical(b).unwrap();
        let client = fx.passkey.client(&bytes, origin);
        let data = fx.passkey.data(flags);
        let sig = fx.passkey.sign(&data, &client);
        canonical(&json!({"body":STANDARD.encode(&bytes),"signature":STANDARD.encode(sig),
            "assertion":{"authenticatorData":STANDARD.encode(&data),"clientData":STANDARD.encode(&client)}})).unwrap()
    };
    let p = ["sign-in"];
    let view = build(&fx, &fx.parts);
    assert_eq!(
        run(
            &view,
            &make("https://sign.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "ok"
    );
    assert_eq!(
        run(
            &view,
            &make("https://keys.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "refused:origin"
    );
    assert_eq!(
        run(
            &view,
            &make("https://sign.id.example", 0x01, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "badSignature"
    );
    assert_eq!(
        run(
            &view,
            &make("https://sign.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &["other"]
        ),
        "refused:outOfScope"
    );
    let with_status = |st: ControllerStatus| {
        let mut q = fx.parts.clone();
        q.controllers[0].2 = st;
        build(&fx, &q)
    };
    for st in [
        ControllerStatus::PendingAddition,
        ControllerStatus::Suspended,
        ControllerStatus::AddedNotFinal,
    ] {
        assert_eq!(
            run(
                &with_status(st),
                &make("https://sign.id.example", 0x05, &body),
                &mut MemoryReplayStore::new(),
                &p
            ),
            "refused:revoked",
            "{st:?}"
        );
    }
    assert_eq!(
        run(
            &with_status(ControllerStatus::PendingRemoval),
            &make("https://sign.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "ok"
    );
    // A suspended controller may still read the history (§12.3 step 5, revision 6).
    let read = call_body(
        &fx,
        json!({"controller": pid}),
        &fx.passkey.point(),
        None,
        HISTORY_READ,
        json!({}),
        2,
    );
    assert_eq!(
        run(
            &with_status(ControllerStatus::Suspended),
            &make("https://sign.id.example", 0x05, &read),
            &mut MemoryReplayStore::new(),
            &[HISTORY_READ]
        ),
        "ok"
    );
    // A recover-only key: only colophon.history.read; a home accepts it at its own endpoint.
    let rid = key_id(&pt(&fx.recover));
    let mut read = call_body(
        &fx,
        json!({"controller": rid}),
        &pt(&fx.recover),
        None,
        HISTORY_READ,
        json!({}),
        3,
    );
    read["audience"] = json!(HOME_EP);
    let read_env = raw_env(&read, &fx.recover);
    assert_eq!(
        run(&view, &read_env, &mut MemoryReplayStore::new(), &[]),
        "refused:outOfScope",
        "not configured, not a home"
    );
    assert_eq!(
        run_at(
            &view,
            &read_env,
            &mut MemoryReplayStore::new(),
            &[],
            &[HOME_EP],
            now()
        ),
        "ok",
        "home purposes need no configuration"
    );
    let mut write = read.clone();
    write["purpose"] = json!("colophon.home.write");
    assert_eq!(
        run_at(
            &view,
            &raw_env(&write, &fx.recover),
            &mut MemoryReplayStore::new(),
            &[],
            &[HOME_EP],
            now()
        ),
        "refused:outOfScope"
    );
    // L2: removed after S (even if re-added after S) is revoked at once.
    let rc = raw_ctrl(&fx.recover, &["recover"]);
    let mut q = fx.parts.clone();
    q.history.push(digest(b"entry 4"));
    q.history.push(digest(b"entry 5"));
    q.controllers[1].1 = vec![(1, Some(rc.clone())), (4, None), (5, Some(rc))];
    assert_eq!(
        run_at(
            &build(&fx, &q),
            &read_env,
            &mut MemoryReplayStore::new(),
            &[],
            &[HOME_EP],
            now()
        ),
        "refused:revoked"
    );
    // L1: WebAuthn with verification at S and raw at the latest state: a raw call fails.
    let raw_same = Controller::parse(json!({"key":{"form":"raw","signing":encode_base64(&fx.passkey.point())},"label":"p","roles":["approve","control"]}), "c").unwrap();
    let mut q = fx.parts.clone();
    q.history.push(digest(b"entry 4"));
    q.controllers[0].1.push((4, Some(raw_same)));
    let raw_call = raw_env(&body, &fx.passkey.k);
    assert_eq!(
        run(
            &build(&fx, &q),
            &raw_call,
            &mut MemoryReplayStore::new(),
            &p
        ),
        "badSignature"
    );
    // M3: a controller whose key form is unknown: newerFormat only after every other check.
    let unknown = Controller::parse(json!({"key":{"form":"future","signing":encode_base64(&pt(&k(25)))},"label":"u","roles":["approve"]}), "c").unwrap();
    let mut q = fx.parts.clone();
    q.controllers.push((
        unknown.id(),
        vec![(1, Some(unknown.clone()))],
        ControllerStatus::Active,
    ));
    let uview = build(&fx, &q);
    let ub = call_body(
        &fx,
        json!({"controller": unknown.id()}),
        &pt(&k(25)),
        None,
        "sign-in",
        json!({}),
        4,
    );
    let mut store = MemoryReplayStore::new();
    assert_eq!(
        run(&uview, &raw_env(&ub, &k(25)), &mut store, &p),
        "newerFormat"
    );
    assert!(store.is_empty());
    assert_eq!(
        run(
            &uview,
            &raw_env(&ub, &k(25)),
            &mut MemoryReplayStore::new(),
            &["other"]
        ),
        "refused:outOfScope",
        "authorization first"
    );
    assert_eq!(
        run(
            &uview,
            &raw_env(&ub, &k(26)),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "badSignature",
        "possession first"
    );
}

#[test]
fn authority_signatures_apply_the_rule() {
    let a = Authn::new(7, "id.example");
    let c = passkey_ctrl(&a);
    let plain = Controller::parse(
        json!({"key":{"form":"webauthn","signing":encode_base64(&a.point()),"rp":"id.example","credential":"AQ=="},"label":"p","roles":["approve"]}),
        "c",
    )
    .unwrap();
    let body = b"{\"x\":1}";
    let sig_of = |origin: &str, flags: u8| {
        let client = a.client(body, origin);
        let data = a.data(flags);
        (a.sign(&data, &client), data, client)
    };
    let check = |c: &Controller, origin: &str, flags: u8, rule: AuthorityRule| {
        let (s, d, cl) = sig_of(origin, flags);
        verify_authority_signature(
            c,
            body,
            &s,
            Some(AssertionBytes {
                authenticator_data: &d,
                client_data: &cl,
            }),
            rule,
        )
    };
    assert_eq!(
        check(&c, "https://keys.id.example", 0x05, AuthorityRule::Veto),
        Ok(Checked::Verified)
    );
    assert!(
        check(&plain, "https://id.example", 0x01, AuthorityRule::Veto).is_err(),
        "vetoes need UV"
    );
    assert_eq!(
        check(&plain, "https://id.example", 0x01, AuthorityRule::Single),
        Ok(Checked::Verified),
        "single rule: UV only with verification"
    );
    assert!(
        check(&c, "https://keys.id.example", 0x01, AuthorityRule::Single).is_err(),
        "verification forces UV"
    );
    assert!(
        check(
            &plain,
            "https://sign.id.example",
            0x05,
            AuthorityRule::Transition
        )
        .is_err(),
        "not an authority origin"
    );
    // Oversized clientData is malformed in every envelope.
    let big = format!(r#"{{"type":"webauthn.get","pad":"{}"}}"#, "x".repeat(8_200)).into_bytes();
    let d = a.data(0x05);
    let s = a.sign(&d, &big);
    let e = verify_authority_signature(
        &c,
        body,
        &s,
        Some(AssertionBytes {
            authenticator_data: &d,
            client_data: &big,
        }),
        AuthorityRule::Control,
    )
    .unwrap_err();
    assert_eq!(e.code(), "malformed");
    // A raw signature for a WebAuthn signer, and an unknown form.
    assert_eq!(
        verify_authority_signature(&c, body, &[0; 64], None, AuthorityRule::Control)
            .unwrap_err()
            .code(),
        "badSignature"
    );
    let u = Controller::parse(json!({"key":{"form":"future","signing":encode_base64(&a.point())},"label":"u","roles":["approve"]}), "c").unwrap();
    assert_eq!(
        verify_authority_signature(&u, body, &[0; 64], None, AuthorityRule::Control),
        Ok(Checked::UndecidableForm)
    );
}

#[test]
fn replay_store_crash_recovery_after_ok() {
    let fx = fixture();
    let view = build(&fx, &fx.parts);
    let mut store = MemoryReplayStore::new();
    let env = raw_env(
        &call_body(
            &fx,
            json!({"member": key_id(&pt(&fx.member))}),
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-1"}),
            1,
        ),
        &fx.member,
    );
    assert_eq!(run(&view, &env, &mut store, &[]), "ok");
    assert_eq!(run(&view, &env, &mut store, &[]), "refused:replay");
    let call = colophon_core::v05::calls::Call::parse(&env).unwrap();
    assert!(matches!(
        store.recover(&call.replay_key(), None).unwrap(),
        ReplayState::Abandoned { .. }
    ));
    assert_eq!(run(&view, &env, &mut store, &[]), "refused:replay");
}

#[test]
fn json_spec_gaps_take_the_safe_reading() {
    // Lone surrogates are refused everywhere, including inside members a reader ignores.
    for bad in [
        r#"{"a":"\ud800"}"#,
        r#"{"a":"\udc00x"}"#,
        r#"{"ignored":{"x":"\ud83d"}}"#,
    ] {
        assert!(strict_parse(bad.as_bytes()).is_err(), "{bad}");
    }
    let client = br#"{"type":"webauthn.get","challenge":"x","origin":"https://id.example","other":"\ud800"}"#;
    let a = Authn::new(7, "id.example");
    let d = a.data(0x05);
    let w = a.key(None);
    assert_eq!(
        wa(&a, &w, b"{}", &d, client, false, OriginRule::General),
        Err(SigFailure::ClientData)
    );
    // Nesting: 64 levels parse, 65 do not, and neither overflows the stack.
    let deep = |n: usize| {
        format!(
            "{}{}",
            "{\"a\":".repeat(n),
            "1".to_string() + &"}".repeat(n)
        )
    };
    assert!(strict_parse(deep(64).as_bytes()).is_ok());
    assert!(strict_parse(deep(65).as_bytes()).is_err());
    assert!(strict_parse(deep(100_000).as_bytes()).is_err());
    // Ryū picks the shortest round-tripping decimal; spot-check values with two candidates.
    for (f, s) in [
        (5e-324, "5e-324"),
        (9007199254740993.0, "9007199254740992.0"),
        (1.7976931348623157e308, "1.7976931348623157e308"),
    ] {
        assert_eq!(String::from_utf8(canonical(&json!(f)).unwrap()).unwrap(), s);
    }
}

#[test]
fn floor_counters_saturate() {
    let mut c = FloorCounter::new(FLOOR);
    assert!(c.signatures(u64::MAX).is_err());
    assert!(c.signatures(u64::MAX).is_err());
    assert_eq!(c.counts().3, u64::MAX);
    assert!(c.past_half_floor());
}

// ---------------------------------------------------------------------------------------
// Records and members.
#[test]
fn operation_header_round_trip_and_admission_order() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let author = k(41);
    let account = "e".repeat(64);
    let nonce = [3u8; 12];
    let mut plain = json!({"id":"","kind":"addNote","v":1,"clock":7,"authority":2,"created":"2026-11-11T12:00:00Z","payload":{"text":"hi"}});
    let id = operation_id("notes", &key_id(&pt(&author)), 1, &nonce, &plain).unwrap();
    plain["id"] = json!(id);
    let mut header = json!({"protocol":"colophon/operation/5","account":account,"namespace":"notes","author":key_id(&pt(&author)),
        "epoch":1,"id":id,"clock":7,"authority":2,"created":"2026-11-11T12:00:00Z","level":"write","previous":null,"nonce":encode_base64(&nonce)});
    let aad = canonical(&json!({"account":account,"author":key_id(&pt(&author)),"authority":2,"clock":7,"created":"2026-11-11T12:00:00Z",
        "epoch":1,"id":id,"level":"write","namespace":"notes","previous":null,"protocol":"colophon/operation/5"})).unwrap();
    let key = [9u8; 32];
    let ct = aes_gcm::Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: &canonical(&plain).unwrap(),
                aad: &aad,
            },
        )
        .unwrap();
    header["ciphertext"] = json!(encode_base64(&ct));
    let env = raw_env(&header, &author);
    let (h, raw) = OperationHeader::parse(&env).unwrap();
    OperationHeader::verify(&raw, &pt(&author)).unwrap();
    assert!(OperationHeader::verify(&raw, &pt(&k(42))).is_err());
    assert_eq!(h.aad().unwrap(), aad);
    h.check_path(&format!(
        "ops/{}/notes/000000000007-{id}.json",
        key_id(&pt(&author))
    ))
    .unwrap();
    assert!(h.check_path("ops/x/notes/7.json").is_err());
    assert_eq!(h.open(&key).unwrap(), plain);
    assert!(h.open(&[8u8; 32]).is_err());
    // A live stamp needs write and previous null.
    let mut live = header.clone();
    live["live"] = json!({"account":account,"slot":"s","generation":7,"operationID":id});
    live["level"] = json!("propose");
    assert!(OperationHeader::parse(&raw_env(&live, &author)).is_err());
    // Admission order (§11.5 steps 1–8).
    let author_view = AuthorView {
        access: Some(colophon_core::v05::terms::Access::Write),
        expires_ms: None,
        revoked_seq: None,
        kept: Kept::NotKept,
        writes_left: None,
        provisional: false,
    };
    let ns = NamespaceView {
        authority_seq: 5,
        fork_seq: None,
        epoch_at_cited: 1,
        highest_clock: 6,
    };
    assert_eq!(admit(&h, &author_view, &ns), Admission::Admitted);
    let propose = AuthorView {
        access: Some(colophon_core::v05::terms::Access::Propose),
        ..author_view.clone()
    };
    assert_eq!(
        admit(&h, &propose, &ns),
        Admission::Refused(Reason::NotGranted)
    );
    let expired = AuthorView {
        expires_ms: Some(0),
        ..author_view.clone()
    };
    assert_eq!(
        admit(&h, &expired, &ns),
        Admission::Refused(Reason::Expired)
    );
    let revoked_later = AuthorView {
        revoked_seq: Some(3),
        ..author_view.clone()
    };
    assert_eq!(
        admit(&h, &revoked_later, &ns),
        Admission::Held("revokedBackdated")
    );
    let revoked_before = AuthorView {
        revoked_seq: Some(2),
        ..author_view.clone()
    };
    assert_eq!(
        admit(&h, &revoked_before, &ns),
        Admission::Refused(Reason::Revoked)
    );
    let incomplete = AuthorView {
        revoked_seq: Some(3),
        kept: Kept::Incomplete,
        ..author_view.clone()
    };
    assert_eq!(admit(&h, &incomplete, &ns), Admission::Held("unavailable"));
    let kept = AuthorView {
        revoked_seq: Some(3),
        kept: Kept::Kept,
        ..author_view.clone()
    };
    assert_eq!(admit(&h, &kept, &ns), Admission::Admitted);
    assert_eq!(
        admit(
            &h,
            &author_view,
            &NamespaceView {
                authority_seq: 1,
                ..ns.clone()
            }
        ),
        Admission::Held("authorityBehind")
    );
    assert_eq!(
        admit(
            &h,
            &author_view,
            &NamespaceView {
                fork_seq: Some(2),
                ..ns.clone()
            }
        ),
        Admission::Held("authorityBehind")
    );
    assert_eq!(
        admit(
            &h,
            &author_view,
            &NamespaceView {
                epoch_at_cited: 2,
                ..ns.clone()
            }
        ),
        Admission::Refused(Reason::WrongEpoch)
    );
    assert_eq!(
        admit(
            &h,
            &author_view,
            &NamespaceView {
                highest_clock: 0,
                ..ns.clone()
            }
        ),
        Admission::Admitted
    );
    let budget = AuthorView {
        writes_left: Some(0),
        ..author_view
    };
    assert_eq!(
        admit(&h, &budget, &ns),
        Admission::Refused(Reason::BudgetSpent)
    );
}

#[test]
fn grants_requests_and_principals() {
    let account = AccountId::parse(&"e".repeat(64)).unwrap();
    let (m, ma) = (k(51), k(52));
    let req = |kind: &str, t: Value| -> String {
        let mut b = json!({"protocol":"colophon/request/5","account":account.as_str(),
            "member":{"signing":encode_base64(&pt(&m)),"agreement":encode_base64(&pt(&ma))},
            "label":"Agent","kind":kind,"terms":t,"created":"2026-11-11T08:00:00Z"});
        if t_has_serves(&b["terms"]) {
            b["service"] = json!({"endpoints":["https://home.example/v1"]});
        }
        STANDARD.encode(raw_env(&b, &m))
    };
    fn t_has_serves(t: &Value) -> bool {
        t.get("serves").is_some()
    }
    let grant = |r: String, t: Value| -> Value {
        json!({"protocol":"colophon/authority/5","seq":2,"previous":"a".repeat(64),"issued":"2026-11-11T08:00:01Z","by":"b".repeat(32),
               "kind":"grant","request":r,"terms":t,"shares":[]})
    };
    let known: BTreeSet<Vec<u8>> = BTreeSet::new();
    let ns = vec!["notes".to_string()];
    let ctx = GrantContext {
        account: &account,
        issued_ms: parse_date("2026-11-11T08:00:01Z").unwrap(),
        namespaces: &ns,
        known_keys: &known,
        epochs: None,
    };
    let parse = |g: Value, ctx: GrantContext<'_>| -> String {
        let (_, fields): (AuthorityHeader, Obj) = AuthorityHeader::split(g).unwrap();
        match Grant::parse(fields, ctx) {
            Ok(_) => "ok".into(),
            Err(e) => format!("{}: {}", e.code(), e.detail()),
        }
    };
    let svc = json!({"services":[{"audience":AUD,"purposes":["task.read","task.propose"]}]});
    assert_eq!(
        parse(grant(req("agent", svc.clone()), svc.clone()), ctx),
        "ok"
    );
    let wider = json!({"services":[{"audience":AUD,"purposes":["*"]}]});
    assert!(parse(grant(req("agent", svc.clone()), wider), ctx).starts_with("malformed"));
    let home = json!({"serves":["home"]});
    assert!(parse(grant(req("agent", home.clone()), home.clone()), ctx).contains("agent"));
    assert_eq!(
        parse(grant(req("server", home.clone()), home.clone()), ctx),
        "ok"
    );
    let records = json!({"records":[{"namespace":"notes","access":"write"}],"expires":"2026-12-01T00:00:00Z"});
    let import = json!({"records":[{"namespace":"notes","access":"write"}],"expires":"2026-12-01T00:00:00Z","import":true});
    assert!(
        parse(grant(req("agent", records.clone()), import.clone()), ctx).contains("device or app")
    );
    assert_eq!(
        parse(grant(req("app", records.clone()), import.clone()), ctx),
        "ok"
    );
    assert!(parse(
        grant(
            req("app", records.clone()),
            json!({"records":[{"namespace":"other","access":"read"}]})
        ),
        ctx
    )
    .starts_with("malformed"));
    assert!(
        parse(grant(req("app", import.clone()), import.clone()), ctx).contains("import"),
        "requests never contain import"
    );
    // §3.3: a key a principal already used can't be granted.
    let used: BTreeSet<Vec<u8>> = [pt(&m)].into_iter().collect();
    let ctx2 = GrantContext {
        known_keys: &used,
        ..ctx
    };
    assert!(parse(grant(req("agent", svc.clone()), svc.clone()), ctx2).contains("§3.3"));
    // A request naming another account, and a forged request signature.
    let ctx3 = GrantContext {
        account: &AccountId::parse(&"f".repeat(64)).unwrap(),
        ..ctx
    };
    assert!(parse(grant(req("agent", svc.clone()), svc.clone()), ctx3).contains("another account"));
    // §9.7: an agent's key never becomes a controller.
    let controller = KeyDescriptor::new_raw(pt(&m), None).unwrap();
    assert!(check_members_never_controllers(
        &[controller],
        &[(pt(&m), pt(&ma), MemberKind::Agent)]
    )
    .is_err());
    let other = KeyDescriptor::new_raw(pt(&k(53)), Some(pt(&ma))).unwrap();
    assert!(
        check_members_never_controllers(&[other], &[(pt(&m), pt(&ma), MemberKind::Agent)]).is_err()
    );
    let fine = KeyDescriptor::new_raw(pt(&k(54)), None).unwrap();
    check_members_never_controllers(&[fine], &[(pt(&m), pt(&ma), MemberKind::Agent)]).unwrap();
}

#[test]
fn admission_lows() {
    use colophon_core::v05::terms::Access;
    let author = k(41);
    let nonce = [3u8; 12];
    let id = "a".repeat(32);
    let header = json!({"protocol":"colophon/operation/5","account":"e".repeat(64),"namespace":"notes","author":key_id(&pt(&author)),
        "epoch":1,"id":id,"clock":7,"authority":2,"created":"2026-11-11T12:00:00Z","level":"write","previous":null,
        "nonce":encode_base64(&nonce),"ciphertext":encode_base64(&[0u8; 32])});
    let (h, _) = OperationHeader::parse(&raw_env(&header, &author)).unwrap();
    // L3: an incomplete walk on a header citing the revocation or later is refused, not held.
    let av = AuthorView {
        access: Some(Access::Write),
        expires_ms: None,
        revoked_seq: Some(2),
        kept: Kept::Incomplete,
        writes_left: None,
        provisional: false,
    };
    let ns = NamespaceView {
        authority_seq: 5,
        fork_seq: None,
        epoch_at_cited: 1,
        highest_clock: 6,
    };
    assert_eq!(admit(&h, &av, &ns), Admission::Refused(Reason::Revoked));
    // A member added by a non-final activation: its records are held authorityBehind.
    let av = AuthorView {
        revoked_seq: None,
        kept: Kept::NotKept,
        provisional: true,
        ..av
    };
    assert_eq!(admit(&h, &av, &ns), Admission::Held("authorityBehind"));
    // L4: invalidPayload on opening; after opening, kinds and conditions.
    assert_eq!(
        h.open(&[9u8; 32]).unwrap_err().code(),
        "refused:invalidPayload"
    );
    let t = Terms::parse(json!({"records":[{"namespace":"notes","access":"write","kinds":["addNote"]}],"conditions":[{"lte":["amount",5]}]}), TermsKind::Member).unwrap();
    let entry = &t.records().unwrap()[0];
    assert_eq!(
        admit_opened(&json!({"kind":"addNote","payload":{"amount":5}}), entry, &t),
        Admission::Admitted
    );
    assert_eq!(
        admit_opened(&json!({"kind":"delete","payload":{"amount":5}}), entry, &t),
        Admission::Refused(Reason::OutOfScope)
    );
    assert_eq!(
        admit_opened(&json!({"kind":"addNote","payload":{"amount":6}}), entry, &t),
        Admission::Refused(Reason::OutOfScope)
    );
    let u = Terms::parse(
        json!({"records":[{"namespace":"notes","access":"write"}],"conditions":[{"future":1}]}),
        TermsKind::Member,
    )
    .unwrap();
    assert_eq!(
        admit_opened(
            &json!({"kind":"x","payload":{}}),
            &u.records().unwrap()[0],
            &u
        ),
        Admission::NewerFormat
    );
}

#[test]
fn a_malleated_signature_is_the_same_reservation() {
    use p256::elliptic_curve::ops::Neg;
    let fx = fixture();
    let view = build(&fx, &fx.parts);
    let body = canonical(&call_body(
        &fx,
        json!({"member": key_id(&pt(&fx.member))}),
        &pt(&fx.member),
        None,
        "task.read",
        json!({"task":"T-1"}),
        1,
    ))
    .unwrap();
    let sig: Signature = fx.member.sign(&body);
    let (r, s) = sig.split_scalars();
    let high = Signature::from_scalars(r, s.neg()).unwrap();
    let env = |sig: &Signature| {
        canonical(
            &json!({"body":STANDARD.encode(&body),"signature":STANDARD.encode(sig.to_bytes())}),
        )
        .unwrap()
    };
    let mut store = MemoryReplayStore::new();
    assert_eq!(run(&view, &env(&sig), &mut store, &[]), "ok");
    assert_eq!(
        run(&view, &env(&high), &mut store, &[]),
        "refused:replay",
        "signature bytes are never identifiers"
    );
}

#[test]
fn nesting_bound_is_64() {
    let obj = |n: usize| {
        format!(
            "{}{}",
            "{\"a\":".repeat(n),
            "1".to_string() + &"}".repeat(n)
        )
    };
    let max = (1..300)
        .take_while(|n| strict_parse(obj(*n).as_bytes()).is_ok())
        .last()
        .unwrap();
    println!("deepest accepted nesting: {max}");
    assert_eq!(max, 64);
}
