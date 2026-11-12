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
        verify_call, AccountView, CallConfig, ControllerStatus, ViewController, ViewMember,
        HISTORY_READ,
    },
    descriptor::{Controller, KeyDescriptor, KeyForm, Policy, Role, WebAuthnKey},
    encoding::{canonical, canonical_body, digest, encode_base64, parse_date, Obj},
    heads::Head,
    ids::{key_id, AccountId},
    members::{check_members_never_controllers, AuthorityHeader, Grant, GrantContext, MemberKind},
    records::{
        admit, operation_id, Admission, AuthorView, Kept, Level, NamespaceView, OperationHeader,
    },
    replay::{MemoryReplayStore, ReplayState, ReplayStore},
    signature::{parse_der, verify_webauthn, AssertionBytes, OriginRule, SigFailure, Strictness},
    terms::{Terms, TermsKind},
    Reason, Unknown,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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
        WebAuthnKey {
            rp: self.rp.clone(),
            credential: vec![1],
            origins: None,
            authority_origins: authority,
        }
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
        Err(SigFailure::ClientData)
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
// Calls over a hand-built view.
const AUD: &str = "https://projects.example/scopes/7";
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
    Terms::parse(v, kind, &mut Unknown::default()).unwrap()
}
struct Fx {
    view: AccountView,
    member: SigningKey,
    passkey: Authn,
    recover: SigningKey,
}
fn fixture() -> Fx {
    let account = AccountId::parse(&"e".repeat(64)).unwrap();
    let history: Vec<String> = (1..=3)
        .map(|i| digest(format!("entry {i}").as_bytes()))
        .collect();
    let member = k(21);
    let home = k(22);
    let passkey = Authn::new(23, "id.example");
    let recover = k(24);
    let mem_terms = terms(
        json!({"services":[{"audience":AUD,"purposes":["task.propose","task.read"]}],"depth":2,
               "expires":"2026-11-18T08:00:00Z","conditions":[{"prefix":["args.task","T-"]}]}),
        TermsKind::Member,
    );
    let members = vec![
        ViewMember {
            id: key_id(&pt(&member)),
            signing: pt(&member),
            kind: MemberKind::Agent,
            terms: mem_terms,
            granted_seq: 2,
            renewals: vec![],
            end_sessions: vec![],
            revoked_seq: None,
        },
        ViewMember {
            id: key_id(&pt(&home)),
            signing: pt(&home),
            kind: MemberKind::Server,
            terms: terms(json!({"serves":["home"]}), TermsKind::Member),
            granted_seq: 3,
            renewals: vec![],
            end_sessions: vec![],
            revoked_seq: None,
        },
    ];
    let pk = KeyDescriptor {
        signing: passkey.point(),
        form: KeyForm::WebAuthn(passkey.key(Some(vec!["https://keys.id.example".into()]))),
    };
    let ctrl = |key: KeyDescriptor, roles: Vec<Role>, verification: bool| Controller {
        key,
        label: "k".into(),
        roles,
        verification,
        holder: None,
        audiences: None,
    };
    let rk = KeyDescriptor {
        signing: pt(&recover),
        form: KeyForm::Raw { agreement: None },
    };
    let controllers = vec![
        ViewController {
            id: pk.id(),
            versions: vec![(
                1,
                Some(ctrl(pk.clone(), vec![Role::Approve, Role::Control], true)),
            )],
            status: ControllerStatus::Active,
        },
        ViewController {
            id: rk.id(),
            versions: vec![(1, Some(ctrl(rk.clone(), vec![Role::Recover], false)))],
            status: ControllerStatus::Active,
        },
    ];
    let heads = vec![Head {
        by: key_id(&pt(&home)),
        seq: 3,
        digest: history[2].clone(),
        issued_ms: parse_date("2026-11-11T09:00:00Z").unwrap(),
        body_digest: "0".repeat(64),
    }];
    let view = AccountView {
        account,
        history,
        policies: vec![(1, Policy::default_person())],
        controllers,
        members,
        heads,
        vouched_fork: false,
        principal_points: [pt(&member), pt(&home), passkey.point(), pt(&recover)]
            .into_iter()
            .collect(),
    };
    Fx {
        view,
        member,
        passkey,
        recover,
    }
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
    let mut b = json!({"protocol":"colophon/call/5","account":fx.view.account.as_str(),"asOf":{"seq":3,"digest":fx.view.history[2]},
        "signer":signer,"key":encode_base64(key),"audience":AUD,"purpose":purpose,"args":args,
        "requestId":URL_SAFE_NO_PAD.encode([rid; 32]),"created":NOW});
    if let Some(l) = links {
        b["links"] = json!(l);
    }
    b
}
fn link(fx: &Fx, from: &SigningKey, to: &SigningKey, t: Value, session: Option<u64>) -> String {
    let mut b = json!({"protocol":"colophon/link/5","account":fx.view.account.as_str(),"from":key_id(&pt(from)),
        "to":{"signing":encode_base64(&pt(to))},"terms":t,"notBefore":"2026-11-11T09:00:00Z","expires":"2026-11-11T09:10:00Z","created":"2026-11-11T09:00:00Z"});
    if let Some(s) = session {
        b["session"] = json!(s);
    }
    STANDARD.encode(raw_env(&b, from))
}
fn run(fx: &Fx, env: &[u8], store: &mut MemoryReplayStore, purposes: &[&str]) -> String {
    let aud = vec![AUD.to_string()];
    let origins: BTreeMap<String, Vec<String>> = [(
        "id.example".to_string(),
        vec!["https://sign.id.example".to_string()],
    )]
    .into();
    let purposes: Vec<String> = purposes.iter().map(|s| s.to_string()).collect();
    let cfg = CallConfig {
        now_ms: parse_date(NOW).unwrap(),
        audiences: &aud,
        call_origins: &origins,
        controller_purposes: &purposes,
    };
    match verify_call(env, &fx.view, &cfg, store) {
        Ok(_) => "ok".into(),
        Err(e) => e.code(),
    }
}

#[test]
fn member_calls_links_and_reservations() {
    let fx = fixture();
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
    assert_eq!(run(&fx, &own, &mut store, &[]), "ok");
    // Reserved and left pending for the service; an identical call is a replay.
    assert_eq!(store.len(), 1);
    assert_eq!(run(&fx, &own, &mut store, &[]), "refused:replay");
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
    assert_eq!(run(&fx, &other, &mut store, &[]), "refused:conflict");
    // Refusals don't reserve.
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
    assert_eq!(run(&fx, &bad, &mut store, &[]), "refused:outOfScope");
    assert_eq!(store.len(), 1);
    // A link carrying the member's condition narrows; one dropping it doesn't.
    let session = k(31);
    let narrow = json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"conditions":[{"prefix":["args.task","T-"]}]});
    let l = link(&fx, &fx.member, &session, narrow.clone(), Some(0));
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
    assert_eq!(run(&fx, &via, &mut store, &[]), "ok");
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
    assert_eq!(run(&fx, &via2, &mut store, &[]), "refused:notNarrower");
    // A copied (narrowing) link signed by another key: badSignature at the end of step 6.
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
    assert_eq!(run(&fx, &copied, &mut store, &[]), "badSignature");
    // Wrong session number, two links, a repeated to.signing, a link to a principal's key.
    let ended = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&session),
            Some(vec![link(
                &fx,
                &fx.member,
                &session,
                narrow.clone(),
                Some(1),
            )]),
            "task.read",
            json!({"task":"T-1"}),
            6,
        ),
        &session,
    );
    assert_eq!(run(&fx, &ended, &mut store, &[]), "refused:ended");
    let s2 = k(33);
    let l2 = link(&fx, &session, &s2, narrow.clone(), None);
    let two = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&s2),
            Some(vec![l.clone(), l2]),
            "task.read",
            json!({"task":"T-1"}),
            7,
        ),
        &s2,
    );
    assert_eq!(
        run(&fx, &two, &mut store, &[]),
        "refused:notNarrower",
        "second link needs depth < first link's 0"
    );
    let to_principal = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&fx.recover),
            Some(vec![link(
                &fx,
                &fx.member,
                &fx.recover,
                narrow.clone(),
                Some(0),
            )]),
            "task.read",
            json!({"task":"T-1"}),
            8,
        ),
        &fx.recover,
    );
    assert_eq!(run(&fx, &to_principal, &mut store, &[]), "malformed");
    // Shape refusals at step 1: unknown signer kind, assertion on a member call, protocol.
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
        run(&fx, &raw_env(&body, &fx.member), &mut store, &[]),
        "malformed"
    );
    body["signer"] = mid.clone();
    body["protocol"] = json!("colophon/call/6");
    assert_eq!(
        run(&fx, &raw_env(&body, &fx.member), &mut store, &[]),
        "malformed"
    );
    // Unknown content is newerFormat only when authentic and authorized.
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
        run(&fx, &raw_env(&future, &fx.member), &mut store, &[]),
        "newerFormat"
    );
    future["purpose"] = json!("task.delete");
    assert_eq!(
        run(&fx, &raw_env(&future, &fx.member), &mut store, &[]),
        "refused:outOfScope"
    );
}

#[test]
fn evaluation_point_and_removals_after_s() {
    let mut fx = fixture();
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
    // A grant after S doesn't count.
    fx.view.members[0].granted_seq = 4;
    fx.view.history.push(digest(b"entry 4"));
    assert_eq!(
        run(&fx, &env, &mut MemoryReplayStore::new(), &[]),
        "refused:revoked"
    );
    fx.view.members[0].granted_seq = 2;
    // endSessions and revocation after S apply at once.
    fx.view.members[0].end_sessions = vec![4];
    let session = k(31);
    let l = link(
        &fx,
        &fx.member,
        &session,
        json!({"services":[{"audience":AUD,"purposes":["task.read"]}],"conditions":[{"prefix":["args.task","T-"]}]}),
        Some(0),
    );
    let via = raw_env(
        &call_body(
            &fx,
            mid.clone(),
            &pt(&session),
            Some(vec![l]),
            "task.read",
            json!({"task":"T-1"}),
            2,
        ),
        &session,
    );
    assert_eq!(
        run(&fx, &via, &mut MemoryReplayStore::new(), &[]),
        "refused:ended"
    );
    fx.view.members[0].revoked_seq = Some(4);
    assert_eq!(
        run(&fx, &env, &mut MemoryReplayStore::new(), &[]),
        "refused:revoked"
    );
    fx.view.members[0].revoked_seq = None;
    // A head beyond the held history, no fresh head, a fork at asOf.
    fx.view.heads[0].issued_ms -= 400_000;
    assert_eq!(
        run(&fx, &env, &mut MemoryReplayStore::new(), &[]),
        "unavailable"
    );
    fx.view.heads[0].issued_ms += 400_000;
    fx.view.history[2] = digest(b"other");
    fx.view.heads[0].digest = fx.view.history[2].clone();
    assert_eq!(
        run(&fx, &env, &mut MemoryReplayStore::new(), &[]),
        "refused:fork"
    );
}

#[test]
fn controller_calls_origins_roles_and_statuses() {
    let mut fx = fixture();
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
    let make = |fx: &Fx, origin: &str, flags: u8, b: &Value| -> Vec<u8> {
        let bytes = canonical(b).unwrap();
        let client = fx.passkey.client(&bytes, origin);
        let data = fx.passkey.data(flags);
        let sig = fx.passkey.sign(&data, &client);
        canonical(&json!({"body":STANDARD.encode(&bytes),"signature":STANDARD.encode(sig),
            "assertion":{"authenticatorData":STANDARD.encode(&data),"clientData":STANDARD.encode(&client)}})).unwrap()
    };
    let p = ["sign-in"];
    assert_eq!(
        run(
            &fx,
            &make(&fx, "https://sign.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "ok"
    );
    assert_eq!(
        run(
            &fx,
            &make(&fx, "https://keys.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "refused:origin"
    );
    assert_eq!(
        run(
            &fx,
            &make(&fx, "https://sign.id.example", 0x01, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "badSignature",
        "verification needs UV"
    );
    assert_eq!(
        run(
            &fx,
            &make(&fx, "https://sign.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &["other"]
        ),
        "refused:outOfScope"
    );
    for status in [
        ControllerStatus::PendingAddition,
        ControllerStatus::Suspended,
        ControllerStatus::AddedNotFinal,
    ] {
        fx.view.controllers[0].status = status;
        assert_eq!(
            run(
                &fx,
                &make(&fx, "https://sign.id.example", 0x05, &body),
                &mut MemoryReplayStore::new(),
                &p
            ),
            "refused:revoked",
            "{status:?}"
        );
    }
    fx.view.controllers[0].status = ControllerStatus::PendingRemoval;
    assert_eq!(
        run(
            &fx,
            &make(&fx, "https://sign.id.example", 0x05, &body),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "ok"
    );
    // A recover-only key: only colophon.history.read.
    let rid = key_id(&pt(&fx.recover));
    let read = call_body(
        &fx,
        json!({"controller": rid}),
        &pt(&fx.recover),
        None,
        HISTORY_READ,
        json!({}),
        2,
    );
    assert_eq!(
        run(
            &fx,
            &raw_env(&read, &fx.recover),
            &mut MemoryReplayStore::new(),
            &[HISTORY_READ]
        ),
        "ok"
    );
    let other = call_body(
        &fx,
        json!({"controller": rid}),
        &pt(&fx.recover),
        None,
        "sign-in",
        json!({}),
        3,
    );
    assert_eq!(
        run(
            &fx,
            &raw_env(&other, &fx.recover),
            &mut MemoryReplayStore::new(),
            &p
        ),
        "refused:outOfScope"
    );
    // A controller removed after S: revoked at once.
    fx.view.controllers[1].versions.push((4, None));
    fx.view.history.push(digest(b"entry 4"));
    assert_eq!(
        run(
            &fx,
            &raw_env(&read, &fx.recover),
            &mut MemoryReplayStore::new(),
            &[HISTORY_READ]
        ),
        "refused:revoked"
    );
    // A controller call carrying links is malformed.
    let mut with_links = call_body(
        &fx,
        json!({"controller": rid}),
        &pt(&fx.recover),
        None,
        HISTORY_READ,
        json!({}),
        4,
    );
    with_links["links"] = json!(["AA=="]);
    assert_eq!(
        run(
            &fx,
            &raw_env(&with_links, &fx.recover),
            &mut MemoryReplayStore::new(),
            &[HISTORY_READ]
        ),
        "malformed"
    );
}

#[test]
fn replay_store_crash_recovery_after_ok() {
    let fx = fixture();
    let mid = json!({"member": key_id(&pt(&fx.member))});
    let mut store = MemoryReplayStore::new();
    let env = raw_env(
        &call_body(
            &fx,
            mid,
            &pt(&fx.member),
            None,
            "task.read",
            json!({"task":"T-1"}),
            1,
        ),
        &fx.member,
    );
    assert_eq!(run(&fx, &env, &mut store, &[]), "ok");
    let aud = vec![AUD.to_string()];
    let empty = BTreeMap::new();
    let cfg = CallConfig {
        now_ms: parse_date(NOW).unwrap(),
        audiences: &aud,
        call_origins: &empty,
        controller_purposes: &[],
    };
    let err = verify_call(&env, &fx.view, &cfg, &mut store).unwrap_err();
    assert_eq!(err.code(), "refused:replay");
    // The service crashed before its effect committed: recovery abandons, never re-runs.
    let call = colophon_core::v05::calls::Call::parse(&env).unwrap();
    let state = store.recover(&call.replay_key(), None).unwrap();
    assert!(matches!(state, ReplayState::Abandoned { .. }));
    assert_eq!(
        verify_call(&env, &fx.view, &cfg, &mut store)
            .unwrap_err()
            .code(),
        "refused:replay"
    );
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
    let (h, raw) = OperationHeader::parse(&env, &mut Unknown::default()).unwrap();
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
    assert!(OperationHeader::parse(&raw_env(&live, &author), &mut Unknown::default()).is_err());
    // Admission order (§11.5 steps 1–8).
    let author_view = AuthorView {
        access: Some(colophon_core::v05::terms::Access::Write),
        expires_ms: None,
        revoked_seq: None,
        kept: Kept::NotKept,
        writes_left: None,
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
    let _ = Level::Write;
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
        match Grant::parse(fields, ctx, &mut Unknown::default()) {
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
    let controller = KeyDescriptor {
        signing: pt(&m),
        form: KeyForm::Raw { agreement: None },
    };
    assert!(check_members_never_controllers(
        &[controller],
        &[(pt(&m), pt(&ma), MemberKind::Agent)]
    )
    .is_err());
    let other = KeyDescriptor {
        signing: pt(&k(53)),
        form: KeyForm::Raw {
            agreement: Some(pt(&ma)),
        },
    };
    assert!(
        check_members_never_controllers(&[other], &[(pt(&m), pt(&ma), MemberKind::Agent)]).is_err()
    );
    let fine = KeyDescriptor {
        signing: pt(&k(54)),
        form: KeyForm::Raw { agreement: None },
    };
    check_members_never_controllers(&[fine], &[(pt(&m), pt(&ma), MemberKind::Agent)]).unwrap();
}
