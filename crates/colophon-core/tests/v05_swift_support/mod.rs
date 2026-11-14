//! Swift-format fixtures for the moving tests, written from the Swift source's algorithms and
//! not from the vector generator or from the code under test: every wrapping key, nonce layout
//! and info string below is the test's own reading of Marginalia `packages/Colophon/Sources` at
//! `origin/main` `c8280332` (file and line beside each function). Nothing here proves agreement
//! with the Swift *code*; the one fixture Swift itself produced is `conformance/keyring`.
#![allow(dead_code, clippy::unwrap_used)]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::slots::{answer_with_identity, OpeningInput, OpeningSecret};
use colophon_core::v05::swift_copy::SourceFile;
use colophon_core::v05::vault::{PrfOutput, SoftwareIdentity};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
pub fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}
pub fn key_id(signing: &[u8]) -> String {
    digest(signing)[..32].to_string()
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .unwrap();
    out
}
fn gcm_seal(key: &[u8; 32], nonce_from: &str, plain: &[u8]) -> Vec<u8> {
    let nonce = sha(nonce_from.as_bytes())[..12].to_vec();
    let ct = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), plain)
        .unwrap();
    [nonce, ct].concat()
}

/// A P-256 scalar from a name: SHA-256 of it (a fixture, not a derivation of any shipped code).
pub fn scalar(name: &str) -> SecretKey {
    SecretKey::from_slice(&sha(name.as_bytes())).unwrap()
}
pub fn point(k: &SecretKey) -> Vec<u8> {
    k.public_key().to_encoded_point(false).as_bytes().to_vec()
}
fn ecdh(k: &SecretKey, peer: &[u8]) -> Vec<u8> {
    let p = PublicKey::from_sec1_bytes(peer).unwrap();
    p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), p.as_affine())
        .raw_secret_bytes()
        .to_vec()
}

/// `SealedKey.init(_:to:)` (`ColophonCore/SealedKey.swift:13-22`): an ephemeral P-256 key, ECDH
/// with the recipient's agreement key, HKDF-SHA256 with the recipient's **signing** point as
/// salt and `colophon/sealed-key/1` as info, AES-256-GCM `nonce ‖ ciphertext ‖ tag`, no AAD.
pub fn swift_sealed(
    plain: &[u8],
    recipient_signing: &[u8],
    recipient_agreement: &[u8],
    eph: &str,
) -> Value {
    let e = scalar(eph);
    let wrap = hkdf32(
        &ecdh(&e, recipient_agreement),
        recipient_signing,
        b"colophon/sealed-key/1",
    );
    json!({"ephemeral": b64(&point(&e)), "box": b64(&gcm_seal(&wrap, eph, plain))})
}
/// `VaultSlot.prf` (`VaultSlot.swift:47-57`, `:121-123`).
pub fn swift_prf_slot(
    seed: &[u8],
    prf: &[u8],
    salt: &[u8],
    credential: &[u8],
    controller: &str,
    label: &str,
) -> Value {
    let wrap = hkdf32(prf, salt, b"colophon/vault-prf/1");
    json!({"kind": "prf", "controller": controller, "label": label, "credential": b64(credential),
           "salt": b64(salt), "box": b64(&gcm_seal(&wrap, label, seed))})
}
/// `VaultSlot.sealed` (`VaultSlot.swift:39-44`).
pub fn swift_sealed_slot(
    seed: &[u8],
    signing: &[u8],
    agreement: &[u8],
    controller: &str,
    label: &str,
) -> Value {
    json!({"kind": "sealed", "controller": controller, "label": label,
           "recipient": {"signing": b64(signing), "agreement": b64(agreement)},
           "sealed": swift_sealed(seed, signing, agreement, &format!("slot/{label}"))})
}
/// `VaultSlot.combined` over a sealed part (device) and a PRF part (passkey)
/// (`VaultSlot.swift:61-74`, `VaultSlotPart.swift:34-49`, `:71-73`).
pub fn swift_combined_slot(
    seed: &[u8],
    device: (&[u8], &[u8], &str),
    prf: &[u8],
    salt: &[u8],
    credential: &[u8],
    label: &str,
) -> Value {
    let secret0 = sha(format!("part-secret/{label}").as_bytes());
    let part0 = json!({"kind": "sealed", "controller": device.2,
        "recipient": {"signing": b64(device.0), "agreement": b64(device.1)},
        "sealed": swift_sealed(&secret0, device.0, device.1, &format!("part/{label}"))});
    let secret1 = hkdf32(prf, salt, b"colophon/vault-part/1");
    let part1 = json!({"kind": "prf", "credential": b64(credential), "salt": b64(salt)});
    let material = [secret0.clone(), secret1.to_vec()].concat();
    let wrap = hkdf32(&material, &[], b"colophon/vault-combined/1");
    json!({"kind": "combined", "label": label, "parts": [part0, part1],
           "box": b64(&gcm_seal(&wrap, label, seed))})
}
/// `P256Derivation` (`ColophonCore/VaultKey.swift:6-21`) with salt `colophon/vault/1`.
pub fn swift_vault_identity(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let one = |purpose: &str| {
        for c in 0..256 {
            let mut out = [0u8; 32];
            Hkdf::<Sha256>::new(Some(b"colophon/vault/1"), seed)
                .expand(format!("{purpose}/{c}").as_bytes(), &mut out)
                .unwrap();
            if let Ok(k) = SecretKey::from_slice(&out) {
                return point(&k);
            }
        }
        panic!("no scalar")
    };
    (one("signing"), one("agreement"))
}

// ---------------------------------------------------------------------------------------------
// The host: keys by ID.

pub struct Host {
    pub ids: BTreeMap<String, SoftwareIdentity>,
}
impl Host {
    pub fn new() -> Self {
        Self {
            ids: BTreeMap::new(),
        }
    }
    pub fn identity(&mut self, n: u8) -> (String, Vec<u8>, Vec<u8>) {
        let i = SoftwareIdentity::from_seed(&[n; 32]).unwrap();
        let p = i.public();
        let id = i.id();
        self.ids.insert(id.clone(), i);
        (id, p.signing, p.agreement)
    }
    pub fn sign(&self, id: &str, body: &[u8]) -> Vec<u8> {
        self.ids[id].sign(body).to_vec()
    }
    /// The PRF output of a passkey: a fixed function of its salt.
    pub fn prf(salt: &[u8]) -> PrfOutput {
        PrfOutput::from_host(&sha(&[b"e8-prf".as_slice(), salt].concat())).unwrap()
    }
    /// Answer opening inputs with the keys this host holds.
    pub fn answer(&self, inputs: &[OpeningInput]) -> Vec<OpeningSecret> {
        inputs
            .iter()
            .map(|i| match i {
                OpeningInput::Ecdh { controller, .. } => {
                    answer_with_identity(&self.ids[controller], i).unwrap()
                }
                OpeningInput::Prf { salt, .. } => OpeningSecret::Prf(Self::prf(salt)),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// A Swift keyring library.

pub const T_PRED: &str = "2026-11-01T08:00:00Z";
pub fn swift_date(day_secs: u32) -> String {
    let (h, m, s) = (day_secs / 3600, day_secs % 3600 / 60, day_secs % 60);
    format!("2026-11-01T{h:02}:{m:02}:{s:02}Z")
}

/// An entry's envelope: `{body, signature, cosignatures?}`, the body canonical (Swift's sorted
/// keys) and signed raw by a software identity.
pub fn entry(host: &Host, signer: &str, body: &Value) -> Vec<u8> {
    let b = canonical(body).unwrap();
    canonical(&json!({"body": b64(&b), "signature": b64(&host.sign(signer, &b))})).unwrap()
}
pub fn body_digest(env: &[u8]) -> String {
    let v: Value = serde_json::from_slice(env).unwrap();
    digest(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap())
}
pub fn pid(signing: &[u8], agreement: &[u8]) -> Value {
    json!({"signing": b64(signing), "agreement": b64(agreement)})
}

pub struct Member {
    pub id: String,
    pub signing: Vec<u8>,
    pub agreement: Vec<u8>,
}
pub struct SwiftFixture {
    pub entries: Vec<Vec<u8>>,
    pub files: Vec<SourceFile>,
    pub library: String,
    pub vault_seed: Vec<u8>,
    pub vault: (Vec<u8>, Vec<u8>),
    pub device: Member,
    pub passkey_key: p256::ecdsa::SigningKey,
    pub passkey_id: String,
    pub security_key: p256::ecdsa::SigningKey,
    pub security_id: String,
    pub credential: Vec<u8>,
    pub old_salt: Vec<u8>,
    pub m1: Member,
    pub m2: Member,
    pub root: Member,
    pub nskeys: BTreeMap<String, [u8; 32]>,
}

impl SwiftFixture {
    /// The recovery identity's signing point (host identity 2).
    pub fn root_recovery_signing(&self) -> Vec<u8> {
        colophon_core::v05::vault::SoftwareIdentity::from_seed(&[2; 32])
            .unwrap()
            .public()
            .signing
    }
}

pub fn webauthn_controller(
    key: &p256::ecdsa::SigningKey,
    credential: &[u8],
    roles: &[&str],
    label: &str,
) -> Value {
    let p = key.verifying_key().to_encoded_point(false);
    json!({"kind": "webauthn", "key": b64(p.as_bytes()), "rpID": "id.example", "credential": b64(credential),
           "label": label, "roles": roles, "verification": true})
}

/// A keyring library: root genesis, a root-signed keyring that adopts a device key (sealed
/// slot), a passkey (PRF slot) and a security key (no slot); two members granted by the device;
/// two namespaces whose epoch-1 keys are sealed to the vault and each member; and operations by
/// both members in both namespaces (`ops/<author>/<namespace>/<clock>-<id>.json`).
pub fn keyring_library(host: &mut Host, combined: bool) -> SwiftFixture {
    let root = host.identity(1);
    let recovery = host.identity(2);
    let device = host.identity(3);
    let m1 = host.identity(4);
    let m2 = host.identity(5);
    let vault_seed = sha(b"e8/swift/vault-seed");
    let vault = swift_vault_identity(&vault_seed);
    let passkey_key = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
    let security_key = p256::ecdsa::SigningKey::from_slice(&[10; 32]).unwrap();
    let passkey_id = key_id(
        passkey_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let security_id = key_id(
        security_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let credential = sha(b"e8/credential");
    let old_salt = sha(b"e8/old-salt");
    let genesis = json!({"by": "root", "issued": T_PRED, "kind": "genesis", "label": "Library", "seq": 1,
        "recovery": pid(&recovery.1, &recovery.2), "root": pid(&root.1, &root.2)});
    let mut entries = vec![entry(host, &root.0, &genesis)];
    let prev = |e: &Vec<Vec<u8>>| body_digest(e.last().unwrap());
    let prf_out = Host::prf(&old_salt);
    drop(prf_out);
    // The PRF output the host will produce for the old salt, as bytes for the fixture.
    let prf_bytes = sha(&[b"e8-prf".as_slice(), &old_salt].concat());
    let slots = if combined {
        vec![swift_combined_slot(
            &vault_seed,
            (&device.1, &device.2, &device.0),
            &prf_bytes,
            &old_salt,
            &credential,
            "Device and passkey",
        )]
    } else {
        vec![
            swift_sealed_slot(&vault_seed, &device.1, &device.2, &device.0, "Mac"),
            swift_prf_slot(
                &vault_seed,
                &prf_bytes,
                &old_salt,
                &credential,
                &passkey_id,
                "Passkey",
            ),
        ]
    };
    let device_ctl = json!({"kind": "p256", "key": b64(&device.1), "label": "Mac", "roles": ["approve", "control"]});
    let keyring = json!({"by": "root", "issued": swift_date(60), "kind": "keyring", "previous": prev(&entries), "seq": 2,
        "controllers": [device_ctl,
            webauthn_controller(&passkey_key, &credential, &["approve", "recover"], "Passkey"),
            webauthn_controller(&security_key, &sha(b"e8/credential2"), &["approve", "control"], "Security key")],
        "slots": slots, "threshold": 1, "vault": pid(&vault.0, &vault.1)});
    entries.push(entry(host, &root.0, &keyring));
    let mut seq = 2u64;
    let controller_entry =
        |host: &Host, entries: &mut Vec<Vec<u8>>, mut body: Value, kind_seq: &mut u64| {
            *kind_seq += 1;
            body["seq"] = json!(*kind_seq);
            body["previous"] = json!(prev(entries));
            body["by"] = json!("controller");
            body["signer"] = json!(device.0);
            body["issued"] = json!(swift_date(60 + *kind_seq as u32 * 60));
            entries.push(entry(host, &device.0, &body));
        };
    for (m, label, role) in [(&m1, "Phone", "device"), (&m2, "Tablet", "app")] {
        controller_entry(
            host,
            &mut entries,
            json!({"kind": "grant", "member": pid(&m.1, &m.2), "role": role, "custody": "software", "label": label,
                   "namespaces": ["notes", "reading.saved"], "write": true}),
            &mut seq,
        );
    }
    let mut nskeys = BTreeMap::new();
    for ns in ["notes", "reading.saved"] {
        let key: [u8; 32] = sha(format!("e8/nskey/{ns}").as_bytes()).try_into().unwrap();
        nskeys.insert(ns.to_string(), key);
        let vault_id = key_id(&vault.0);
        for (id, s, a) in [
            (vault_id, vault.0.clone(), vault.1.clone()),
            (m1.0.clone(), m1.1.clone(), m1.2.clone()),
            (m2.0.clone(), m2.1.clone(), m2.2.clone()),
        ] {
            controller_entry(
                host,
                &mut entries,
                json!({"kind": "shareKey", "memberID": id, "namespace": ns, "epoch": 1,
                       "key": swift_sealed(&key, &s, &a, &format!("share/{ns}/{id}"))}),
                &mut seq,
            );
        }
    }
    let library = body_digest(&entries[0])[..32].to_string();
    let authority = seq;
    // Operations: each member writes one in each namespace; clocks 1 and 2.
    let mut files = Vec::new();
    let mem = |t: &(String, Vec<u8>, Vec<u8>)| Member {
        id: t.0.clone(),
        signing: t.1.clone(),
        agreement: t.2.clone(),
    };
    let (m1m, m2m) = (mem(&m1), mem(&m2));
    let ops: [(&str, &str, &Member, u64, &str, Value); 4] = [
        (
            "notes",
            "createNotebook",
            &m1m,
            1,
            "11111111-aaaa-4aaa-8aaa-000000000001",
            json!({"id": "nb1", "title": "Alpha"}),
        ),
        (
            "notes",
            "createNotebook",
            &m2m,
            2,
            "22222222-bbbb-4bbb-8bbb-000000000002",
            json!({"id": "nb2", "title": "Beta"}),
        ),
        (
            "reading.saved",
            "capture",
            &m1m,
            1,
            "33333333-cccc-4ccc-8ccc-000000000003",
            json!({"id": "i1", "title": "One", "url": "https://example.com/1"}),
        ),
        (
            "reading.saved",
            "capture",
            &m2m,
            2,
            "44444444-dddd-4ddd-8ddd-000000000004",
            json!({"id": "i2", "title": "Two", "url": "https://example.com/2"}),
        ),
    ];
    for (ns, kind, m, clock, id, payload) in ops {
        files.push(swift_op(
            host,
            &library,
            &nskeys[ns],
            ns,
            m,
            1,
            clock,
            id,
            kind,
            payload,
            authority,
        ));
    }
    SwiftFixture {
        entries,
        files,
        library,
        vault_seed,
        vault,
        device: Member {
            id: device.0,
            signing: device.1,
            agreement: device.2,
        },
        passkey_key,
        passkey_id,
        security_key,
        security_id,
        credential,
        old_salt,
        m1: Member {
            id: m1.0,
            signing: m1.1,
            agreement: m1.2,
        },
        m2: Member {
            id: m2.0,
            signing: m2.1,
            agreement: m2.2,
        },
        root: Member {
            id: root.0,
            signing: root.1,
            agreement: root.2,
        },
        nskeys,
    }
}

/// A Swift operation record: `Replica.perform` (`ColophonReplica/Replica.swift:989-1016`): the
/// canonical operation sealed with AES-GCM under the namespace key (no AAD), a header
/// `{author, epoch, namespace, sealed}` signed raw by the member, at the layout-2 path.
#[allow(clippy::too_many_arguments)]
pub fn swift_op(
    host: &Host,
    _library: &str,
    key: &[u8; 32],
    ns: &str,
    author: &Member,
    epoch: u64,
    clock: u64,
    id: &str,
    kind: &str,
    payload: Value,
    authority: u64,
) -> SourceFile {
    let plain = canonical(
        &json!({"authority": authority, "clock": clock, "created": "2026-11-01T09:00:00Z",
        "id": id, "kind": kind, "payload": payload, "v": 1}),
    )
    .unwrap();
    let sealed = gcm_seal(key, id, &plain);
    let header = canonical(
        &json!({"author": author.id, "epoch": epoch, "namespace": ns, "sealed": b64(&sealed)}),
    )
    .unwrap();
    let rec = canonical(
        &json!({"body": b64(&header), "signature": b64(&host.sign(&author.id, &header))}),
    )
    .unwrap();
    SourceFile {
        path: format!("ops/{}/{ns}/{clock:012}-{id}.json", author.id),
        bytes: rec,
    }
}
