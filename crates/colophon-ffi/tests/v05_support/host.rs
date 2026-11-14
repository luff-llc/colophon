//! The host's key custody for the journeys, written the way an app writes it against the typed
//! surface: software keys and a synthetic passkey, answering signing steps, PRF requests and
//! unlock inputs from the records the exports return. Shared with the wasm crate's test, which
//! includes it with `pub use <crate>::v05::*;` in scope at its root.
#![allow(dead_code, clippy::unwrap_used, clippy::too_many_arguments)]
use super::*;
use colophon_core::crypto::SoftwareKeys;
use colophon_core::keys::testing::SyntheticAuthenticator;
use colophon_core::v05::encoding::{canonical, digest, encode_base64url};
use colophon_core::v05::ids::key_id;
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
        let id = key_id(&passkey_point(&a));
        self.passkey = Some((a, id.clone()));
        id
    }
    /// A raw controller object (protocol JSON, §6.1).
    pub fn raw_controller(&self, id: &str, label: &str, roles: &[&str]) -> String {
        let b = colophon_core::v05::encoding::encode_base64;
        let p = self.keys[id].public();
        serde_json::json!({"key": {"form": "raw", "signing": b(&p.signing), "agreement": b(&p.agreement)},
               "label": label, "roles": roles})
        .to_string()
    }
    pub fn passkey_controller(&self, label: &str, roles: &[&str]) -> String {
        let b = colophon_core::v05::encoding::encode_base64;
        let (a, _) = self.passkey.as_ref().unwrap();
        serde_json::json!({"key": {"form": "webauthn", "signing": b(&passkey_point(a)), "rp": RP, "credential": "AQ=="},
               "label": label, "roles": roles, "verification": true})
        .to_string()
    }
    pub fn fresh(&mut self, n: usize) -> Vec<u8> {
        self.counter += 1;
        let mut out = Vec::new();
        for i in 0..n.div_ceil(32) {
            out.extend(sha(&[&self.counter.to_le_bytes()[..], &[i as u8]].concat()));
        }
        out.truncate(n);
        out
    }
    /// Sign (body, signer, challenge) the way the exports ask: raw for a software key, an
    /// assertion for the passkey.
    pub fn sign_one(&self, body: &[u8], signer: &str, webauthn: bool) -> Signature {
        if !webauthn {
            Signature {
                signature: self.keys[signer].sign(body),
                authenticator_data: None,
                client_data: None,
            }
        } else {
            let (auth, id) = self.passkey.as_ref().unwrap();
            assert_eq!(id, signer);
            let a = auth.assertion(body, RP, ORIGIN, 0x05, false).unwrap();
            Signature {
                signature: a.signature,
                authenticator_data: Some(a.assertion.authenticator_data),
                client_data: Some(a.assertion.client_data),
            }
        }
    }
    pub fn sign(&self, steps: &[AccountSigningStep]) -> Vec<Signature> {
        steps
            .iter()
            .map(|s| self.sign_one(&s.body, &s.signer, s.challenge.is_some()))
            .collect()
    }
    pub fn prf(&self, salt: &[u8]) -> Vec<u8> {
        sha(&[&b"test-prf"[..], salt].concat())
    }
    pub fn answer_prf(&self, requests: &[PrfRequest]) -> Vec<PrfAnswer> {
        requests
            .iter()
            .map(|r| {
                let (auth, _) = self.passkey.as_ref().unwrap();
                let client = canonical(&serde_json::json!({
                    "type": "webauthn.get",
                    "challenge": encode_base64url(&r.challenge),
                    "origin": ORIGIN,
                }))
                .unwrap();
                let mut ad = sha(RP.as_bytes());
                ad.push(0x05);
                ad.extend([0, 0, 0, 0]);
                let a = auth.sign_bytes(ad, client, false).unwrap();
                PrfAnswer {
                    authenticator_data: a.assertion.authenticator_data,
                    client_data: a.assertion.client_data,
                    signature: a.signature,
                    output: self.prf(&r.salt),
                }
            })
            .collect()
    }
    pub fn answer_slot(&self, inputs: &[UnlockInput]) -> Vec<UnlockSecret> {
        inputs
            .iter()
            .map(|i| match i.kind {
                UnlockKind::Ecdh => UnlockSecret {
                    kind: UnlockKind::Ecdh,
                    secret: self.keys[&i.controller].agree(&i.enc).unwrap(),
                },
                UnlockKind::Prf => UnlockSecret {
                    kind: UnlockKind::Prf,
                    secret: self.prf(&i.salt),
                },
            })
            .collect()
    }
    pub fn answer_epochs(&self, member: &str, agreements: &[EpochAgreement]) -> Vec<EpochAnswer> {
        agreements
            .iter()
            .map(|a| EpochAnswer {
                namespace: a.namespace.clone(),
                epoch: a.epoch,
                shared: self.keys[member].agree(&a.peer).unwrap(),
            })
            .collect()
    }
}
fn passkey_point(a: &SyntheticAuthenticator) -> Vec<u8> {
    match a.descriptor(RP, None).unwrap() {
        colophon_core::keys::KeyDescriptor::WebAuthn { signing, .. } => signing,
        _ => panic!("a synthetic authenticator is webauthn"),
    }
}
