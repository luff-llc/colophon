#![allow(clippy::unwrap_used)]
use colophon_core::{
    crypto::{Entropy, SoftwareKeys},
    hpke::{kem_shared_secret, key_schedule, SealedKey},
    records::{canonical, SignedRecord},
};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn rfc9180_a3_base() {
    let sk = hex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    let recipient = SoftwareKeys::from_scalars(&sk, &sk).unwrap();
    let enc = hex("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    assert_eq!(recipient.public().agreement, hex("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"));
    let shared = kem_shared_secret(
        &recipient.agree(&enc).unwrap(),
        &enc,
        &recipient.public().agreement,
    )
    .unwrap();
    assert_eq!(
        shared,
        hex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8")
    );
    let (key, nonce, exporter) =
        key_schedule(&shared, &hex("4f6465206f6e2061204772656369616e2055726e"), 1).unwrap();
    assert_eq!(key, hex("868c066ef58aae6dc589b6cfdd18f97e"));
    assert_eq!(nonce, hex("4e0bc5018beba4bf004cca59"));
    assert_eq!(
        exporter,
        hex("14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f")
    );
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes128Gcm, KeyInit, Nonce,
    };
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &hex("4265617574792069732074727574682c20747275746820626561757479"),
                aad: b"Count-0",
            },
        )
        .unwrap();
    assert_eq!(ciphertext, hex("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"));
}
#[test]
fn stored_bytes_and_hpke_context_are_authenticated() {
    let keys = SoftwareKeys::from_seed([1; 32]).unwrap();
    let body = br#"{ "z":1, "a":"https://example.org/" }"#.to_vec();
    let sig = keys.sign(&body);
    let mut record = SignedRecord::finish_sign(body, sig, &keys.public().signing).unwrap();
    record.body =
        canonical(&serde_json::from_slice::<serde_json::Value>(&record.body).unwrap()).unwrap();
    assert!(record.verify(&keys.public().signing).is_err());
    assert_eq!(record.body, br#"{"a":"https://example.org/","z":1}"#);
    let mut entropy = Entropy::new([2; 32]);
    let sealed = SealedKey::seal(
        &keys.public().agreement,
        b"data key",
        b"context",
        &mut entropy,
    )
    .unwrap();
    let dh = keys.agree(sealed.begin_open()).unwrap();
    assert_eq!(
        sealed
            .finish_open(&keys.public().agreement, &dh, b"context")
            .unwrap(),
        b"data key"
    );
    assert!(sealed
        .finish_open(&keys.public().agreement, &dh, b"wrong epoch")
        .is_err());
    assert!(sealed
        .finish_open(&keys.public().agreement, &[0; 31], b"context")
        .is_err());
}
