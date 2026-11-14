//! The host's side for the E7 tests: keys by published scalar, signing of every step, and
//! helpers to read vector directories. Written independently of the vector generator.
#![allow(dead_code, clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::ids::key_id;
use colophon_core::v05::write::{SignatureResult, SigningStep};
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use p256::elliptic_curve::{bigint::Encoding, Curve};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
pub fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
pub fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}
pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
pub fn strip(mut b: Vec<u8>) -> Vec<u8> {
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    b
}
/// The `*.json` files of a directory, sorted, without a trailing newline.
pub fn files_in(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    v.sort();
    v.into_iter().map(|p| strip(std::fs::read(p).unwrap())).collect()
}
pub fn body_value(env: &[u8]) -> Value {
    let e: Value = serde_json::from_slice(env).unwrap();
    serde_json::from_slice(&dec(e["body"].as_str().unwrap())).unwrap()
}
pub fn body_digest(env: &[u8]) -> String {
    let e: Value = serde_json::from_slice(env).unwrap();
    colophon_core::v05::encoding::digest(&dec(e["body"].as_str().unwrap()))
}

pub struct Key {
    pub sk: SigningKey,
}
pub fn key_from_scalar(scalar: &[u8]) -> Key {
    Key {
        sk: SigningKey::from_slice(scalar).unwrap(),
    }
}
fn der_int(x: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = x.iter().copied().skip_while(|b| *b == 0).collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    let mut out = vec![2, v.len() as u8];
    out.extend(v);
    out
}
pub fn der(raw: &[u8]) -> Vec<u8> {
    let mut inner = der_int(&raw[..32]);
    inner.extend(der_int(&raw[32..]));
    let mut out = vec![0x30, inner.len() as u8];
    out.extend(inner);
    out
}
impl Key {
    pub fn sign_raw(&self, body: &[u8]) -> Vec<u8> {
        let s: P256Signature = self.sk.sign(body);
        s.to_bytes().to_vec()
    }
    /// A WebAuthn assertion over `challenge` with the given authenticator data and client data.
    pub fn sign_assertion(&self, auth: &[u8], client: &[u8]) -> SignatureResult {
        let mut m = auth.to_vec();
        m.extend(Sha256::digest(client));
        SignatureResult {
            signature: der(&self.sign_raw(&m)),
            assertion: Some((auth.to_vec(), client.to_vec())),
        }
    }
    /// A synthetic authenticator: UP and UV set (`flags`), the step's challenge, the origin.
    pub fn sign_webauthn(&self, rp: &str, origin: &str, flags: u8, challenge: &str) -> SignatureResult {
        let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend([0, 0, 0, 1]);
        let client = canonical(&json!({
            "type": "webauthn.get", "challenge": challenge, "origin": origin,
        }))
        .unwrap();
        self.sign_assertion(&auth, &client)
    }
}

pub fn published_scalars() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut put = |public: &str, scalar: &str| {
        out.insert(key_id(&dec(public)), dec(scalar));
    };
    let c = repo().join("conformance/0.5/candidate");
    for f in ["keys.json", "rules/keys-r4.json"] {
        for k in read_json(&c.join(f))["keys"].as_object().unwrap().values() {
            put(k["signing"].as_str().unwrap(), k["scalar"].as_str().unwrap());
        }
    }
    let v = read_json(&repo().join("conformance/0.4/keys/keys.json"));
    for a in v["authenticators"].as_array().unwrap() {
        put(
            a["descriptor"]["signing"].as_str().unwrap(),
            a["signingScalar"].as_str().unwrap(),
        );
    }
    for s in v["software"].as_array().unwrap() {
        put(
            s["public"]["signing"].as_str().unwrap(),
            s["signingScalar"].as_str().unwrap(),
        );
    }
    // The candidate's published derivation (keys.json `derivation`): scalar = SHA-256(
    // 'colophon-0.5-candidate/' + name) mod n. The names the vectors use that keys.json does not
    // list are found by trying every plain string literal of the generator's source as a name (the
    // source is read as text, never compiled in or called).
    for lit in literals() {
        for name in [lit.clone(), format!("webauthn/{lit}"), format!("{lit}/signing")] {
            let k = derived(&name);
            let public = k.sk.verifying_key().to_encoded_point(false);
            out.entry(key_id(public.as_bytes()))
                .or_insert_with(|| k.sk.to_bytes().to_vec());
        }
    }
    out
}

/// SHA-256('colophon-0.5-candidate/' + name) mod n.
pub fn derived(name: &str) -> Key {
    let d = Sha256::digest(format!("colophon-0.5-candidate/{name}").as_bytes());
    let n = p256::NistP256::ORDER;
    let mut x = p256::U256::from_be_slice(&d);
    if x >= n {
        x = x.wrapping_sub(&n);
    }
    key_from_scalar(&x.to_be_bytes())
}

fn literals() -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let dir = repo().join("crates/colophon-core/tests/v5_candidate");
    for e in std::fs::read_dir(dir).unwrap() {
        let text = std::fs::read_to_string(e.unwrap().path()).unwrap();
        for (i, part) in text.split('"').enumerate() {
            if i % 2 == 1
                && (3..=48).contains(&part.len())
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'-' || b == b'_')
            {
                out.insert(part.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// Sign every step: raw keys over the body; WebAuthn keys with a synthetic authenticator whose
/// origin is `https://<rp of the step's descriptor>`.
pub fn sign_steps(steps: &[SigningStep], scalars: &BTreeMap<String, Vec<u8>>) -> Vec<SignatureResult> {
    steps
        .iter()
        .map(|s| {
            let k = key_from_scalar(&scalars[s.signer()]);
            match s.challenge() {
                None => SignatureResult {
                    signature: k.sign_raw(s.body()),
                    assertion: None,
                },
                Some(ch) => {
                    let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                    k.sign_webauthn(&rp, &format!("https://{rp}"), 0x05, ch)
                }
            }
        })
        .collect()
}
