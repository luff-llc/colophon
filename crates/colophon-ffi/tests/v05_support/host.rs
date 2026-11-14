//! The host's side of the 0.5 journeys, written the way an app would write it against the
//! exports: it holds the keys (software keys and a synthetic passkey), answers signing steps,
//! PRF assertions and unlock inputs from the JSON the exports return, implements the record
//! source callback, and simulates a home from the exchange values the engine emits.
#![allow(dead_code, clippy::unwrap_used, clippy::too_many_arguments)]
use colophon_core::crypto::SoftwareKeys;
use colophon_core::keys::testing::SyntheticAuthenticator;
use colophon_core::v05::encoding::{canonical, decode_base64, digest, encode_base64};
use colophon_core::v05::ids::key_id;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const T0: i64 = 1_794_384_000_000;
pub const HOUR: i64 = 3_600_000;
pub const RP: &str = "id.luff.works";
pub const ORIGIN: &str = "https://id.luff.works";
pub const DEVICE_KEY: [u8; 32] = [0x77; 32];

/// SHA-256 as bytes (the core's digest function is hex text).
pub fn sha(b: &[u8]) -> Vec<u8> {
    let h = digest(b);
    (0..32)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
pub fn b64(b: &[u8]) -> String {
    encode_base64(b)
}
pub fn unb64(s: &str) -> Vec<u8> {
    decode_base64(s, 1 << 28).unwrap()
}
pub fn j(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}
pub fn s(v: &Value) -> String {
    serde_json::to_string(v).unwrap()
}

/// The host's key custody: software keys and a synthetic passkey.
pub struct Host {
    pub keys: BTreeMap<String, SoftwareKeys>,
    pub passkey: Option<(SyntheticAuthenticator, String)>,
    pub counter: u32,
}
impl Host {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            passkey: None,
            counter: 0,
        }
    }
    pub fn identity(&mut self, n: u8) -> String {
        let k = SoftwareKeys::from_seed([n; 32]).unwrap();
        let id = key_id(&k.public().signing);
        self.keys.insert(id.clone(), k);
        id
    }
    pub fn kit(&mut self, n: u8) -> String {
        let k = SoftwareKeys::recovery([n; 32]).unwrap();
        let id = key_id(&k.public().signing);
        self.keys.insert(id.clone(), k);
        id
    }
    pub fn passkey(&mut self) -> String {
        let a = SyntheticAuthenticator::new().unwrap();
        let point = passkey_point(&a);
        let id = key_id(&point);
        self.passkey = Some((a, id.clone()));
        id
    }
    pub fn raw_controller(&self, id: &str, label: &str, roles: &[&str]) -> Value {
        let p = self.keys[id].public();
        json!({"key": {"form": "raw", "signing": b64(&p.signing), "agreement": b64(&p.agreement)},
               "label": label, "roles": roles})
    }
    pub fn passkey_controller(&self, label: &str, roles: &[&str]) -> Value {
        let (a, _) = self.passkey.as_ref().unwrap();
        json!({"key": {"form": "webauthn", "signing": b64(&passkey_point(a)), "rp": RP, "credential": "AQ=="},
               "label": label, "roles": roles, "verification": true})
    }
    pub fn fresh(&mut self, n: usize) -> Vec<u8> {
        self.counter += 1;
        let mut out = Vec::new();
        for i in 0..n.div_ceil(32) {
            let mut seed = [0u8; 32];
            let h = sha(&[&self.counter.to_le_bytes()[..], &[i as u8]].concat());
            seed.copy_from_slice(&h);
            out.extend(seed);
        }
        out.truncate(n);
        out
    }
    /// Sign the steps an export returned; the host signs exactly the bodies it was shown.
    pub fn sign(&self, steps_json: &str) -> String {
        let steps = j(steps_json);
        let out: Vec<Value> = steps
            .as_array()
            .unwrap()
            .iter()
            .map(|st| {
                let body = unb64(st["body"].as_str().unwrap());
                let signer = st["signer"].as_str().unwrap();
                if st["challenge"].is_null() {
                    json!({"signature": b64(&self.keys[signer].sign(&body))})
                } else {
                    let (auth, id) = self.passkey.as_ref().unwrap();
                    assert_eq!(id, signer);
                    let a = auth.assertion(&body, RP, ORIGIN, 0x05, false).unwrap();
                    json!({"signature": b64(&a.signature),
                           "authenticatorData": b64(&a.assertion.authenticator_data),
                           "clientData": b64(&a.assertion.client_data)})
                }
            })
            .collect();
        s(&Value::Array(out))
    }
    pub fn prf(&self, salt: &[u8]) -> Vec<u8> {
        sha(&[&b"test-prf"[..], salt].concat())
    }
    pub fn answer_prf(&self, requests_json: &str) -> String {
        let out: Vec<Value> = j(requests_json)
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let (auth, _) = self.passkey.as_ref().unwrap();
                let challenge = unb64(r["challenge"].as_str().unwrap());
                let client = canonical(&json!({
                    "type": "webauthn.get",
                    "challenge": base64_url(&challenge),
                    "origin": ORIGIN,
                }))
                .unwrap();
                let mut ad = sha(RP.as_bytes());
                ad.push(0x05);
                ad.extend([0, 0, 0, 0]);
                let a = auth.sign_bytes(ad, client, false).unwrap();
                json!({"authenticatorData": b64(&a.assertion.authenticator_data),
                       "clientData": b64(&a.assertion.client_data),
                       "signature": b64(&a.signature),
                       "output": b64(&self.prf(&unb64(r["salt"].as_str().unwrap())))})
            })
            .collect();
        s(&Value::Array(out))
    }
    pub fn answer_slot(&self, inputs_json: &str) -> String {
        let out: Vec<Value> = j(inputs_json)
            .as_array()
            .unwrap()
            .iter()
            .map(|i| match i["type"].as_str().unwrap() {
                "ecdh" => {
                    let c = i["controller"].as_str().unwrap();
                    let enc = unb64(i["enc"].as_str().unwrap());
                    json!({"type": "ecdh", "secret": b64(&self.keys[c].agree(&enc).unwrap())})
                }
                _ => json!({"type": "prf", "output": b64(&self.prf(&unb64(i["salt"].as_str().unwrap())))}),
            })
            .collect();
        s(&Value::Array(out))
    }
    pub fn answer_epochs(&self, member: &str, agreements_json: &str) -> String {
        let out: Vec<Value> = j(agreements_json)
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let peer = unb64(a["peer"].as_str().unwrap());
                json!({"namespace": a["namespace"], "epoch": a["epoch"],
                       "shared": b64(&self.keys[member].agree(&peer).unwrap())})
            })
            .collect();
        s(&Value::Array(out))
    }
}
fn base64_url(b: &[u8]) -> String {
    colophon_core::v05::encoding::encode_base64url(b)
}
fn passkey_point(a: &SyntheticAuthenticator) -> Vec<u8> {
    match a.descriptor(RP, None).unwrap() {
        colophon_core::keys::KeyDescriptor::WebAuthn { signing, .. } => signing,
        _ => panic!("a synthetic authenticator is webauthn"),
    }
}
