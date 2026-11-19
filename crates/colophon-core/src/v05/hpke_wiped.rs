//! RFC 9180 base mode as `crate::hpke` has it (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//! AES-256-GCM, AEAD 2), written again for the `v05` paths so that every temporary that holds a
//! key share is wiped when it is dropped. `crate::hpke` is a 0.4 file and is not changed.
//!
//! **What this wipes.** The extract input (`"HPKE-v1" ‖ suite ‖ label ‖ ikm`, which holds the
//! ECDH shared secret), the pseudo-random keys, the labelled `info` of each expand, the key
//! schedule's context, secret, AEAD key and nonce, and the KEM shared secret once the key
//! schedule has taken it.
//!
//! **What it cannot.** The `Hkdf` and HMAC objects of the RustCrypto crates keep their key
//! block inside the object and do not erase it on drop (the crates are not built with
//! `zeroize` here); the allocator and the stack may hold copies of a freed buffer that a
//! `black_box`ed overwrite did not reach (a `Vec` that grew); and the ECDH bytes the host gives
//! are the host's. The 0.4 path (`crate::hpke::{kem_shared_secret, key_schedule, SealedKey}`)
//! wipes none of its temporaries and is used by 0.4 code only.
use crate::{
    crypto::{self, Entropy},
    ensure,
    hpke::SealedKey,
    Error, Result,
};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;

const KEM_SUITE: &[u8] = b"KEM\x00\x10";

/// Overwrite `b` with zeros in a way the optimiser may not drop.
pub(crate) fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
    std::hint::black_box(&*b);
}

fn extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut input = [b"HPKE-v1".as_slice(), suite, label, ikm].concat();
    let prk = Hkdf::<Sha256>::extract(Some(salt), &input).0.to_vec();
    wipe(&mut input);
    prk
}
fn expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let len16 = u16::try_from(len).map_err(|_| Error("HPKE output length".into()))?;
    let mut labeled = [&len16.to_be_bytes()[..], b"HPKE-v1", suite, label, info].concat();
    let mut out = vec![0; len];
    let r = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| Error("HPKE PRK".into()))
        .and_then(|h| {
            h.expand(&labeled, &mut out)
                .map_err(|_| Error("HPKE expand".into()))
        });
    wipe(&mut labeled);
    match r {
        Ok(()) => Ok(out),
        Err(e) => {
            wipe(&mut out);
            Err(e)
        }
    }
}
fn kem_shared_secret(dh: &[u8], enc: &[u8], recipient: &[u8]) -> Result<Vec<u8>> {
    ensure(dh.len() == 32, "Expected 32-byte ECDH secret")?;
    for point in [enc, recipient] {
        ensure(
            point.len() == 65 && point[0] == 4,
            "Expected uncompressed HPKE point",
        )?;
        p256::PublicKey::from_sec1_bytes(point).map_err(|_| Error("Invalid HPKE point".into()))?;
    }
    let mut prk = extract(KEM_SUITE, &[], b"eae_prk", dh);
    let shared = expand(
        KEM_SUITE,
        &prk,
        b"shared_secret",
        &[enc, recipient].concat(),
        32,
    );
    wipe(&mut prk);
    shared
}
/// Base-mode key schedule for AEAD 2: `(key, nonce)`, both to be wiped by the caller.
fn key_schedule(shared: &[u8], info: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let suite = [b"HPKE\x00\x10\x00\x01".as_slice(), &2u16.to_be_bytes()].concat();
    let mut psk_hash = extract(&suite, &[], b"psk_id_hash", &[]);
    let mut info_hash = extract(&suite, &[], b"info_hash", info);
    let mut context = [&[0][..], &psk_hash, &info_hash].concat();
    let mut secret = extract(&suite, shared, b"secret", &[]);
    let key = expand(&suite, &secret, b"key", &context, 32);
    let nonce = expand(&suite, &secret, b"base_nonce", &context, 12);
    for b in [&mut psk_hash, &mut info_hash, &mut context, &mut secret] {
        wipe(b);
    }
    match (key, nonce) {
        (Ok(k), Ok(n)) => Ok((k, n)),
        (k, n) => {
            for mut v in [k, n].into_iter().flatten() {
                wipe(&mut v);
            }
            Err(Error("HPKE key schedule".into()))
        }
    }
}

/// Seal `plaintext` to `recipient` (a 65-byte agreement point) under `info`.
pub(crate) fn seal(
    recipient: &[u8],
    plaintext: &[u8],
    info: &[u8],
    entropy: &mut Entropy,
) -> Result<SealedKey> {
    let ephemeral = entropy.scalar()?;
    let enc = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let mut dh = crypto::agree(&ephemeral, recipient)?;
    let shared = kem_shared_secret(&dh, &enc, recipient);
    wipe(&mut dh);
    let mut shared = shared?;
    let schedule = key_schedule(&shared, info);
    wipe(&mut shared);
    let (mut key, mut nonce) = schedule?;
    let ciphertext = crypto::seal(&key, &nonce, plaintext, info);
    wipe(&mut key);
    wipe(&mut nonce);
    Ok(SealedKey {
        enc,
        ciphertext: ciphertext?,
    })
}

/// Open with the host's raw ECDH result `dh` (the host owns those bytes).
pub(crate) fn finish_open(
    sealed: &SealedKey,
    recipient: &[u8],
    dh: &[u8],
    info: &[u8],
) -> Result<Vec<u8>> {
    let shared = kem_shared_secret(dh, &sealed.enc, recipient);
    let mut shared = shared?;
    let schedule = key_schedule(&shared, info);
    wipe(&mut shared);
    let (mut key, mut nonce) = schedule?;
    let plain = crypto::open(&key, &nonce, &sealed.ciphertext, info);
    wipe(&mut key);
    wipe(&mut nonce);
    plain
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The wiping implementation and `crate::hpke` seal and open each other's boxes.
    #[test]
    fn it_interoperates_with_the_0_4_implementation() {
        let mut e = Entropy::new([5; 32]);
        let recipient = e.scalar().unwrap();
        let point = recipient
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let info = b"colophon/test";
        let mut e2 = Entropy::new([6; 32]);
        // New seal, old open.
        let sealed = seal(&point, b"a secret of 32 bytes ..........", info, &mut e2).unwrap();
        let dh = crypto::agree(&recipient, sealed.begin_open()).unwrap();
        assert_eq!(
            sealed.finish_open(&point, &dh, info).unwrap(),
            b"a secret of 32 bytes .........."
        );
        assert_eq!(
            finish_open(&sealed, &point, &dh, info).unwrap(),
            b"a secret of 32 bytes .........."
        );
        // Old seal, new open.
        let old = SealedKey::seal(&point, b"other", info, &mut e2).unwrap();
        let dh = crypto::agree(&recipient, old.begin_open()).unwrap();
        assert_eq!(finish_open(&old, &point, &dh, info).unwrap(), b"other");
        assert!(finish_open(&old, &point, &dh, b"another info").is_err());
    }
}
