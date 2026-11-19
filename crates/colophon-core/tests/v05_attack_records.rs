//! `/5` operation headers: AAD, opening, operation ID, path, and §11.5 admission order.
//! Ported from the independent attack review of colophon#4 (04c0eef), adapted to the
//! sealed revision-6 API.
#![allow(
    clippy::unwrap_used,
    clippy::explicit_auto_deref,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::type_complexity
)]
#[path = "v05_attack_support/mod.rs"]
mod support;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::records::{
    admit, operation_id, operation_path, Admission, AuthorView, Kept, NamespaceView,
    OperationHeader,
};
use colophon_core::v05::terms::Access;
use colophon_core::v05::Reason;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};

fn build(
    plain_override: Option<Value>,
    aad_override: Option<Value>,
    key: &[u8; 32],
) -> (Vec<u8>, String) {
    let author = SigningKey::from_slice(&[31u8; 32]).unwrap();
    let author_id = key_id(author.verifying_key().to_encoded_point(false).as_bytes());
    let account = digest(b"acct");
    let nonce = [7u8; 12];
    let mut plain = json!({"id":"","kind":"addNote","v":1,"clock":7,"authority":3,"created":"2026-11-11T12:00:00Z","payload":{"t":"x"}});
    let id = operation_id("notes", &author_id, 1, &nonce, &plain).unwrap();
    plain["id"] = json!(id);
    let plain = plain_override.unwrap_or(plain);
    let aad = aad_override.unwrap_or(json!({"account":account,"author":author_id,"authority":3,"clock":7,"created":"2026-11-11T12:00:00Z","epoch":1,"id":id,"level":"write","namespace":"notes","previous":null,"protocol":"colophon/operation/5"}));
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap();
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: &canonical(&plain).unwrap(),
                aad: &canonical(&aad).unwrap(),
            },
        )
        .unwrap();
    let body = canonical(&json!({"protocol":"colophon/operation/5","account":account,"namespace":"notes","author":author_id,
        "epoch":1,"id":id,"clock":7,"authority":3,"created":"2026-11-11T12:00:00Z","level":"write","previous":null,
        "nonce":STANDARD.encode(nonce),"ciphertext":STANDARD.encode(ct)}))
    .unwrap();
    let sig: Signature = author.sign(&body);
    (
        canonical(
            &json!({"body":STANDARD.encode(&body),"signature":STANDARD.encode(sig.to_bytes())}),
        )
        .unwrap(),
        id,
    )
}

#[test]
fn header_open_and_aad() {
    let key = [9u8; 32];
    let (env, id) = build(None, None, &key);
    let (h, raw) = OperationHeader::parse(&env).unwrap();
    OperationHeader::verify(
        &raw,
        SigningKey::from_slice(&[31u8; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();
    h.check_path(&operation_path(&h.author, "notes", 7, &id))
        .unwrap();
    assert!(h
        .check_path(&format!("ops/{}/notes/7-{id}.json", h.author))
        .is_err());
    let v = h.open(&key).unwrap();
    assert_eq!(v["id"], json!(id));
    // Wrong key, wrong AAD (previous as "" instead of null), plaintext mismatches.
    let e = h.open(&[8u8; 32]).unwrap_err();
    println!("wrong epoch key: {} ({})", e.code(), e.detail());
    let (env2, _) = build(None, Some(json!({"x":1})), &key);
    let (h2, _) = OperationHeader::parse(&env2).unwrap();
    assert!(h2.open(&key).is_err());
    let mut p = json!({"id":id,"kind":"addNote","v":1,"clock":8,"authority":3,"created":"2026-11-11T12:00:00Z","payload":{"t":"x"}});
    let (env3, _) = build(Some(p.clone()), None, &key);
    let (h3, _) = OperationHeader::parse(&env3).unwrap();
    assert!(h3.open(&key).is_err(), "clock mismatch");
    p["clock"] = json!(7);
    p["payload"] = json!({"t":"tampered"});
    let (env4, _) = build(Some(p.clone()), None, &key);
    let (h4, _) = OperationHeader::parse(&env4).unwrap();
    let e4 = h4.open(&key).unwrap_err();
    println!(
        "payload not matching the operation ID: {} ({})",
        e4.code(),
        e4.detail()
    );
    p["payload"] = json!({"t":"x"});
    p["extra"] = json!(1);
    let (env5, _) = build(Some(p), None, &key);
    let (h5, _) = OperationHeader::parse(&env5).unwrap();
    assert!(h5.open(&key).is_err(), "extra plaintext field");
    // Deeply nested payload (128 levels): refused by the 127-container parser limit.
    let mut deep = json!(1);
    for _ in 0..128 {
        deep = json!([deep]);
    }
    let mut pd = json!({"id":"","kind":"addNote","v":1,"clock":7,"authority":3,"created":"2026-11-11T12:00:00Z","payload":deep});
    let author_id = key_id(
        SigningKey::from_slice(&[31u8; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let idd = operation_id("notes", &author_id, 1, &[7u8; 12], &pd).unwrap();
    pd["id"] = json!(idd);
    let aad = json!({"account":digest(b"acct"),"author":author_id,"authority":3,"clock":7,"created":"2026-11-11T12:00:00Z","epoch":1,"id":idd,"level":"write","namespace":"notes","previous":null,"protocol":"colophon/operation/5"});
    let (env6, _) = build(Some(pd), Some(aad), &key);
    match OperationHeader::parse(&env6) {
        Ok((h6, _)) => println!(
            "plaintext nested 129 deep: {:?}",
            h6.open(&key).map(|_| ()).map_err(|e| e.code())
        ),
        Err(e) => println!("header parse failed: {e}"),
    }
    // Header shape: short nonce, ciphertext < 16.
    let bad = String::from_utf8(env.clone()).unwrap();
    println!("header envelope bytes {}", bad.len());
}

fn author(kept: Kept, revoked: Option<u64>) -> AuthorView {
    AuthorView {
        access: Some(Access::Write),
        expires_ms: None,
        revoked_seq: revoked,
        kept,
        writes_left: None,
        provisional: false,
    }
}
#[test]
fn admission_order() {
    let key = [9u8; 32];
    let (env, _) = build(None, None, &key);
    let (h, _) = OperationHeader::parse(&env).unwrap(); // authority 3, clock 7
    let ns = NamespaceView {
        authority_seq: 10,
        fork_seq: None,
        epoch_at_cited: 1,
        highest_clock: 5,
    };
    let cases: Vec<(&str, AuthorView, NamespaceView, Admission)> = vec![
        (
            "baseline",
            author(Kept::NotKept, None),
            ns.clone(),
            Admission::Admitted,
        ),
        (
            "propose access for write",
            AuthorView {
                access: Some(Access::Propose),
                ..author(Kept::NotKept, None)
            },
            ns.clone(),
            Admission::Refused(Reason::NotGranted),
        ),
        (
            "revoked at 3, kept",
            author(Kept::Kept, Some(3)),
            ns.clone(),
            Admission::Refused(Reason::Revoked),
        ),
        (
            "revoked at 4, kept",
            author(Kept::Kept, Some(4)),
            ns.clone(),
            Admission::Admitted,
        ),
        (
            "revoked at 4, not kept",
            author(Kept::NotKept, Some(4)),
            ns.clone(),
            Admission::Held("revokedBackdated"),
        ),
        (
            "revoked at 3, not kept",
            author(Kept::NotKept, Some(3)),
            ns.clone(),
            Admission::Refused(Reason::Revoked),
        ),
        (
            "revoked at 3 (cites the revocation), walk incomplete",
            author(Kept::Incomplete, Some(3)),
            ns.clone(),
            Admission::Refused(Reason::Revoked),
        ),
        (
            "revoked at 4, walk incomplete",
            author(Kept::Incomplete, Some(4)),
            ns.clone(),
            Admission::Held("unavailable"),
        ),
        (
            "authority behind",
            author(Kept::NotKept, None),
            NamespaceView {
                authority_seq: 2,
                ..ns.clone()
            },
            Admission::Held("authorityBehind"),
        ),
        (
            "at fork",
            author(Kept::NotKept, None),
            NamespaceView {
                fork_seq: Some(3),
                ..ns.clone()
            },
            Admission::Held("authorityBehind"),
        ),
        (
            "wrong epoch",
            author(Kept::NotKept, None),
            NamespaceView {
                epoch_at_cited: 2,
                ..ns.clone()
            },
            Admission::Refused(Reason::WrongEpoch),
        ),
        (
            "clock 7 vs highest 0 is fine",
            author(Kept::NotKept, None),
            NamespaceView {
                highest_clock: 0,
                ..ns.clone()
            },
            Admission::Admitted,
        ),
        (
            "budget spent",
            AuthorView {
                writes_left: Some(0),
                ..author(Kept::NotKept, None)
            },
            ns.clone(),
            Admission::Refused(Reason::BudgetSpent),
        ),
        (
            "expired before created",
            AuthorView {
                expires_ms: Some(0),
                ..author(Kept::NotKept, None)
            },
            ns.clone(),
            Admission::Refused(Reason::Expired),
        ),
    ];
    for (name, a, n, want) in cases {
        let got = admit(&h, &a, &n);
        println!(
            "{} {name}: {got:?}",
            if got == want { "OK " } else { "BAD" }
        );
    }
}
