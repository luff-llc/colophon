//! Swift vault-slot and seal fixtures (spec §16.2, §16.3), written from the Swift source's
//! algorithm (Marginalia `packages/Colophon/Sources` at `origin/main` `c8280332`), not from the
//! code that opens them. They prove agreement with this reading of the Swift source, **not**
//! with the Swift code: a Swift-side test must produce the same five forms and check that this
//! core opens them (see the pull request, "what the Swift side must produce").
//!
//! One directory per form under `swift-slots/`, each with a `fixture.json` (no `case.json`, so the
//! candidate runner does not treat it as a verdict case).
use super::kit::*;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::Sha256;

fn hk(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .unwrap();
    out
}
fn gcm(key: &[u8; 32], nonce_name: &str, plain: &[u8]) -> Vec<u8> {
    let nonce = sha_raw(nonce_name.as_bytes())[..12].to_vec();
    let ct = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), plain)
        .unwrap();
    [nonce, ct].concat()
}
fn secret(name: &str) -> SecretKey {
    SecretKey::from_slice(&derived(name).scalar).unwrap()
}
fn pt(k: &SecretKey) -> Vec<u8> {
    k.public_key().to_encoded_point(false).as_bytes().to_vec()
}
fn dh(k: &SecretKey, peer: &[u8]) -> Vec<u8> {
    let p = PublicKey::from_sec1_bytes(peer).unwrap();
    p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), p.as_affine())
        .raw_secret_bytes()
        .to_vec()
}
/// `SealedKey` (`ColophonCore/SealedKey.swift:13-22`).
fn sealed(plain: &[u8], r_sign: &[u8], r_agree: &[u8], eph: &str) -> Value {
    let e = secret(eph);
    let wrap = hk(&dh(&e, r_agree), r_sign, b"colophon/sealed-key/1");
    json!({"ephemeral": b64(&pt(&e)), "box": b64(&gcm(&wrap, eph, plain))})
}
/// `VaultKey.identity()` (`VaultKey.swift:6-21`, salt `colophon/vault/1`).
fn vault_identity(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let one = |purpose: &str| {
        for c in 0..256 {
            let mut out = [0u8; 32];
            Hkdf::<Sha256>::new(Some(b"colophon/vault/1"), seed)
                .expand(format!("{purpose}/{c}").as_bytes(), &mut out)
                .unwrap();
            if let Ok(k) = SecretKey::from_slice(&out) {
                return pt(&k);
            }
        }
        panic!("no scalar")
    };
    (one("signing"), one("agreement"))
}

pub fn part(o: &mut Out) {
    let seed = sha_raw(b"swift-slots/vault-seed");
    let (v_sign, v_agree) = vault_identity(&seed);
    let vault = json!({"signing": b64(&v_sign), "agreement": b64(&v_agree)});
    let device_sign = secret("swift-slots/device/signing");
    let device_agree = secret("swift-slots/device/agreement");
    let (ds, da) = (pt(&device_sign), pt(&device_agree));
    let prf_out = sha_raw(b"swift-slots/prf-output");
    let salt = sha_raw(b"swift-slots/salt");
    let credential = sha_raw(b"swift-slots/credential");
    let controller = key_id(&ds);
    let common = |form: &str, src: &str, slot: Value, answers: Value| {
        json!({
            "description": format!("A Swift `{form}` vault slot and the host answers that open it (§16.2)."),
            "sections": ["16.2", "16.3"],
            "swiftSource": src,
            "seed": b64(&seed),
            "vault": vault,
            "vaultID": key_id(&v_sign),
            "slot": slot,
            "answers": answers,
            "expected": {"opens": true, "vaultID": key_id(&v_sign)},
        })
    };
    // sealed: VaultSlot.swift:39-44, open :76-89.
    let sealed_slot = json!({"kind": "sealed", "controller": controller, "label": "Mac",
        "recipient": {"signing": b64(&ds), "agreement": b64(&da)},
        "sealed": sealed(&seed, &ds, &da, "swift-slots/eph/sealed")});
    write(
        o,
        "swift-slots/sealed/fixture.json",
        &common(
            "sealed",
            "ColophonAuthority/VaultSlot.swift:39-44; ColophonCore/SealedKey.swift:13-30",
            sealed_slot,
            json!({"ecdhAgreementScalars": [b64(&device_agree.to_bytes())]}),
        ),
    );
    // prf: VaultSlot.swift:47-57, wrapping key :121-123.
    let wrap = hk(&prf_out, &salt, b"colophon/vault-prf/1");
    let prf_slot = json!({"kind": "prf", "controller": controller, "label": "Passkey",
        "credential": b64(&credential), "salt": b64(&salt), "box": b64(&gcm(&wrap, "swift-slots/nonce/prf", &seed))});
    write(
        o,
        "swift-slots/prf/fixture.json",
        &common(
            "prf",
            "ColophonAuthority/VaultSlot.swift:47-57, :91-101, :121-123",
            prf_slot,
            json!({"prfOutputs": [b64(&prf_out)]}),
        ),
    );
    // combined: VaultSlot.swift:61-74; parts VaultSlotPart.swift:34-49, :71-73.
    let part_secret = sha_raw(b"swift-slots/part-secret");
    let part0 = json!({"kind": "sealed", "controller": controller,
        "recipient": {"signing": b64(&ds), "agreement": b64(&da)},
        "sealed": sealed(&part_secret, &ds, &da, "swift-slots/eph/part")});
    let part1 = json!({"kind": "prf", "credential": b64(&credential), "salt": b64(&salt)});
    let part1_secret = hk(&prf_out, &salt, b"colophon/vault-part/1");
    let wrap = hk(
        &[part_secret.clone(), part1_secret.to_vec()].concat(),
        &[],
        b"colophon/vault-combined/1",
    );
    let combined = json!({"kind": "combined", "label": "Mac and passkey", "parts": [part0, part1],
        "box": b64(&gcm(&wrap, "swift-slots/nonce/combined", &seed))});
    write(
        o,
        "swift-slots/combined/fixture.json",
        &common(
            "combined",
            "ColophonAuthority/VaultSlot.swift:61-74, :104-119; VaultSlotPart.swift:34-49, :71-73",
            combined,
            json!({"ecdhAgreementScalars": [b64(&device_agree.to_bytes())], "prfOutputs": [b64(&prf_out)],
                   "order": "parts in order: the sealed part, then the PRF part"}),
        ),
    );
    // A namespace key sealed to the vault, and an operation sealed under it
    // (Replica.swift:989-1004; AuthorityEntry shareKey).
    let ns_key = sha_raw(b"swift-slots/namespace-key");
    let share = sealed(&ns_key, &v_sign, &v_agree, "swift-slots/eph/share");
    let author = secret("swift-slots/author/signing");
    let plain = canonical(
        &json!({"authority": 5, "clock": 1, "created": "2026-11-01T09:00:00Z",
        "id": "11111111-aaaa-4aaa-8aaa-000000000001", "kind": "capture", "payload": {"id": "i", "title": "T"}, "v": 1}),
    );
    let header = canonical(
        &json!({"author": key_id(&pt(&author)), "epoch": 1, "namespace": "reading.saved",
        "sealed": b64(&gcm(&ns_key.clone().try_into().unwrap(), "swift-slots/nonce/op", &plain))}),
    );
    write(
        o,
        "swift-slots/namespace-key/fixture.json",
        &json!({
            "description": "A namespace key sealed to the vault (a `shareKey` entry's `key`) and an operation header sealed under it.",
            "sections": ["16.2", "16.3"],
            "swiftSource": "ColophonCore/SealedKey.swift:13-30; ColophonReplica/Replica.swift:989-1004",
            "seed": b64(&seed),
            "vault": vault,
            "share": share,
            "namespaceKey": b64(&ns_key),
            "operationPlaintext": b64(&plain),
            "operationHeaderBody": b64(&header),
            "expected": {"namespaceKey": b64(&ns_key)},
        }),
    );
}
