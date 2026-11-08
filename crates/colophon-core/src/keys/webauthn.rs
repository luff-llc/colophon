//! ES256 and exact-byte WebAuthn authority verification (§3.2–§3.3).
use super::{bad_signature, point, KeyDescriptor};
use crate::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// The unpadded base64url SHA-256 challenge for the exact authority body bytes.
pub fn challenge(body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(body))
}

/// Verify a raw 64-byte ES256 signature over the exact body bytes (§3.2).
pub fn verify_raw(signing: &[u8], body: &[u8], signature: &[u8]) -> Result<()> {
    point(signing).map_err(|_| bad_signature("invalid signing point"))?;
    let key = VerifyingKey::from_sec1_bytes(signing)
        .map_err(|_| bad_signature("invalid signing point"))?;
    let signature =
        Signature::from_slice(signature).map_err(|_| bad_signature("invalid raw signature"))?;
    key.verify(body, &signature)
        .map_err(|_| bad_signature("raw ES256 verification failed"))
}

/// The failed WebAuthn check, in the normative verification order.
///
/// These check failures deliberately have no standalone protocol error mapping:
/// §3.1 and §10 disagree on `badSignature` versus `malformed` for WebAuthn
/// refuse cases. An authority envelope maps every failure to `badSignature` (§3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebAuthnFailure {
    /// Not a valid WebAuthn descriptor; callers must supply a validated key.
    Descriptor,
    /// Client data is not strict JSON with the required shape.
    ClientData,
    /// The assertion type is not `webauthn.get`.
    Type,
    /// The challenge does not bind the exact authority body bytes.
    Challenge,
    /// The origin is outside the RP web origins and explicit allowlist.
    Origin,
    /// `crossOrigin` is present with a value other than false.
    CrossOrigin,
    /// Authenticator data is shorter than 37 bytes or has the wrong RP hash.
    RelyingParty,
    /// The user-presence flag is missing.
    UserPresence,
    /// The required user-verification flag is missing.
    UserVerification,
    /// Signature bytes do not meet the exact DER grammar and scalar range.
    Der,
    /// The ES256 signature does not verify.
    Signature,
}
impl std::fmt::Display for WebAuthnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebAuthn check failed: {self:?}")
    }
}
impl std::error::Error for WebAuthnFailure {}

/// Verify a WebAuthn authority signature in §3.3 order, returning its UV flag.
/// The credential hint is ignored. Exact client data and signature bytes remain unchanged.
/// `uv_required` combines the controller's requirement and the authority rule's requirement.
/// See [`WebAuthnFailure`] for the unresolved standalone protocol error mapping.
pub fn verify_webauthn(
    key: &KeyDescriptor,
    body: &[u8],
    signature: &[u8],
    authenticator_data: &[u8],
    client_data: &[u8],
    uv_required: bool,
) -> std::result::Result<bool, WebAuthnFailure> {
    use WebAuthnFailure as F;
    let KeyDescriptor::WebAuthn {
        signing,
        rp,
        origins,
        ..
    } = key
    else {
        return Err(F::Descriptor);
    };
    // Descriptors are checked at the typed keyring boundary. Do not perform any
    // signature, DER or authenticator checks ahead of clientData.
    let client = super::strict_json::parse(client_data).map_err(|_| F::ClientData)?;
    let client = client.as_object().ok_or(F::ClientData)?;
    if client.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(F::Type);
    }
    if client.get("challenge").and_then(|v| v.as_str()) != Some(challenge(body).as_str()) {
        return Err(F::Challenge);
    }
    let origin = client
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or(F::Origin)?;
    if !allowed_origin(origin, rp, origins.as_deref().unwrap_or(&[])) {
        return Err(F::Origin);
    }
    if client
        .get("crossOrigin")
        .is_some_and(|v| v != &serde_json::Value::Bool(false))
    {
        return Err(F::CrossOrigin);
    }
    if authenticator_data.len() < 37
        || authenticator_data[..32] != Sha256::digest(rp.as_bytes())[..]
    {
        return Err(F::RelyingParty);
    }
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 {
        return Err(F::UserPresence);
    }
    let uv = flags & 0x04 != 0;
    if uv_required && !uv {
        return Err(F::UserVerification);
    }
    // The counter and all remaining authenticatorData bytes are opaque signed bytes.
    let signature = parse_der(signature).ok_or(F::Der)?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    point(signing).map_err(|_| F::Descriptor)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(signing).map_err(|_| F::Descriptor)?;
    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&Sha256::digest(client_data));
    verifying_key
        .verify(&message, &normalized)
        .map_err(|_| F::Signature)?;
    Ok(uv)
}

fn allowed_origin(origin: &str, rp: &str, origins: &[String]) -> bool {
    if origins.iter().any(|allowed| allowed == origin) {
        return true;
    }
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    if host.bytes().any(|b| b"/:?#@\\".contains(&b)) {
        return false;
    }
    if host == rp {
        return true;
    }
    let Some(prefix) = host.strip_suffix(rp).and_then(|s| s.strip_suffix('.')) else {
        return false;
    };
    !prefix.is_empty()
        && !prefix.starts_with('.')
        && !prefix.ends_with('.')
        && !prefix.contains("..")
}

// Deliberately independent of a general-purpose ASN.1 decoder. All lengths are
// short-form, positive scalars are minimally encoded, and the input is consumed.
fn parse_der(bytes: &[u8]) -> Option<Signature> {
    if bytes.len() < 8
        || bytes[0] != 0x30
        || bytes[1] >= 0x80
        || usize::from(bytes[1]) + 2 != bytes.len()
    {
        return None;
    }
    let mut offset = 2;
    let r = integer(bytes, &mut offset)?;
    let s = integer(bytes, &mut offset)?;
    if offset != bytes.len() {
        return None;
    }
    Signature::from_scalars(r, s).ok()
}
fn integer(bytes: &[u8], offset: &mut usize) -> Option<[u8; 32]> {
    if *bytes.get(*offset)? != 0x02 {
        return None;
    }
    *offset += 1;
    let length = usize::from(*bytes.get(*offset)?);
    *offset += 1;
    if !(1..=33).contains(&length) {
        return None;
    }
    let value = bytes.get(*offset..*offset + length)?;
    *offset += length;
    if value[0] > 0x7f {
        return None;
    }
    let magnitude = if value[0] == 0 && length > 1 {
        if value[1] < 0x80 {
            return None;
        }
        &value[1..]
    } else {
        value
    };
    if magnitude.len() > 32 {
        return None;
    }
    let mut scalar = [0; 32];
    scalar[32 - magnitude.len()..].copy_from_slice(magnitude);
    Some(scalar)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::keys::{
        testing::{SyntheticAssertion, SyntheticAuthenticator},
        Assertion,
    };
    use serde_json::{json, Value};
    const BODY: &[u8] = b"  {\"by\":\"body bytes matter\"}\n";
    const RP: &str = "id.luff.works";
    fn fixture() -> (SyntheticAuthenticator, KeyDescriptor, SyntheticAssertion) {
        let authenticator = SyntheticAuthenticator::new().unwrap();
        let key = authenticator.descriptor(RP, None).unwrap();
        let signed = authenticator
            .assertion(BODY, RP, "https://id.luff.works", 5, false)
            .unwrap();
        (authenticator, key, signed)
    }
    fn verify(
        key: &KeyDescriptor,
        signed: &SyntheticAssertion,
        uv: bool,
    ) -> std::result::Result<bool, WebAuthnFailure> {
        verify_webauthn(
            key,
            BODY,
            &signed.signature,
            &signed.assertion.authenticator_data,
            &signed.assertion.client_data,
            uv,
        )
    }
    fn client_mutation(
        authenticator: &SyntheticAuthenticator,
        signed: &SyntheticAssertion,
        mutate: impl FnOnce(&mut Value),
    ) -> SyntheticAssertion {
        let mut client: Value = serde_json::from_slice(&signed.assertion.client_data).unwrap();
        mutate(&mut client);
        authenticator
            .sign_bytes(
                signed.assertion.authenticator_data.clone(),
                serde_json::to_vec(&client).unwrap(),
                false,
            )
            .unwrap()
    }
    #[test]
    fn high_and_low_s_accept_preserve_bytes_and_ignore_counter_and_extensions() {
        let (authenticator, key, low) = fixture();
        let high = authenticator
            .assertion(BODY, RP, "https://id.luff.works", 5, true)
            .unwrap();
        assert!(Signature::from_der(&low.signature)
            .unwrap()
            .normalize_s()
            .is_none());
        assert!(Signature::from_der(&high.signature)
            .unwrap()
            .normalize_s()
            .is_some());
        assert_ne!(low.signature, high.signature);
        for signed in [low, high] {
            let before = signed.signature.clone();
            assert_eq!(verify(&key, &signed, true), Ok(true));
            assert_eq!(signed.signature, before);
        }
        let (_, _, signed) = fixture();
        let mut data = signed.assertion.authenticator_data.clone();
        data[33..37].copy_from_slice(&[255, 42, 1, 9]);
        data.extend_from_slice(&[99, 0, 1]);
        let mut client = serde_json::from_slice::<Value>(&signed.assertion.client_data).unwrap();
        client["unknown"] = json!({"nested":[null,3]});
        client["crossOrigin"] = json!(false);
        let bytes = format!("  {}\n", serde_json::to_string_pretty(&client).unwrap()).into_bytes();
        let signed = authenticator.sign_bytes(data, bytes, false).unwrap();
        assert_eq!(verify(&key, &signed, true), Ok(true));
    }
    #[test]
    fn multi_label_and_android_origins_accept() {
        let (authenticator, _, _) = fixture();
        let android = "android:apk-key-hash:abcdef_-";
        let key = authenticator
            .descriptor(RP, Some(vec![android.into()]))
            .unwrap();
        for origin in [
            "https://a.b.id.luff.works",
            "https://id.luff.works",
            android,
        ] {
            assert_eq!(
                verify(
                    &key,
                    &authenticator.assertion(BODY, RP, origin, 5, false).unwrap(),
                    true
                ),
                Ok(true)
            );
        }
        // The specification constrains web prefixes only by the listed delimiters
        // and dot rules, not by an additional DNS-label validator.
        assert!(allowed_origin("https://UPPER.id.luff.works", RP, &[]));
    }
    #[test]
    fn foreign_userinfo_port_and_all_forbidden_origin_delimiters_refuse() {
        let (authenticator, key, signed) = fixture();
        for origin in [
            "https://foreign.example",
            "https://id.luff.works.evil",
            "https://evilid.luff.works",
            "https://id.luff.works:443",
            "https://user@id.luff.works",
            "https://id.luff.works/",
            "https://id.luff.works?q",
            "https://id.luff.works#f",
            "https://a\\b.id.luff.works",
            "http://id.luff.works",
            "HTTPS://id.luff.works",
            "https://.id.luff.works",
            "https://a..id.luff.works",
            "https://.a.id.luff.works",
            "https://a..b.id.luff.works",
            "https://id.luff.works.",
            "android:apk-key-hash:foreign",
            "null",
        ] {
            let signed = client_mutation(&authenticator, &signed, |c| c["origin"] = json!(origin));
            assert_eq!(
                verify(&key, &signed, true),
                Err(WebAuthnFailure::Origin),
                "{origin}"
            );
        }
    }
    #[test]
    fn challenge_type_cross_origin_and_client_json_refuse() {
        let (authenticator, key, signed) = fixture();
        for (field, value, failure) in [
            ("challenge", json!("wrong"), WebAuthnFailure::Challenge),
            (
                "challenge",
                json!(format!("{}=", challenge(BODY))),
                WebAuthnFailure::Challenge,
            ),
            ("challenge", json!(null), WebAuthnFailure::Challenge),
            ("type", json!("webauthn.create"), WebAuthnFailure::Type),
            ("crossOrigin", json!(true), WebAuthnFailure::CrossOrigin),
            ("crossOrigin", json!(null), WebAuthnFailure::CrossOrigin),
            ("crossOrigin", json!(0), WebAuthnFailure::CrossOrigin),
        ] {
            let changed = client_mutation(&authenticator, &signed, |c| c[field] = value);
            assert_eq!(verify(&key, &changed, true), Err(failure));
        }
        for field in ["type", "challenge", "origin"] {
            let changed = client_mutation(&authenticator, &signed, |c| {
                c.as_object_mut().unwrap().remove(field);
            });
            assert!(verify(&key, &changed, true).is_err());
        }
        for client in [
            b"[]".as_slice(),
            b"{} {}",
            b"null",
            b"{",
            br#"{"type":"webauthn.get","type":"webauthn.get"}"#,
            br#"{"ignored":{"x":1,"x":2}}"#,
        ] {
            let changed = authenticator
                .sign_bytes(
                    signed.assertion.authenticator_data.clone(),
                    client.to_vec(),
                    false,
                )
                .unwrap();
            assert_eq!(
                verify(&key, &changed, true),
                Err(WebAuthnFailure::ClientData)
            );
        }
    }
    #[test]
    fn rp_hash_up_uv_and_foreign_key_refuse() {
        let (authenticator, key, signed) = fixture();
        for len in [0, 32, 33, 36] {
            let changed = authenticator
                .sign_bytes(
                    signed.assertion.authenticator_data[..len].to_vec(),
                    signed.assertion.client_data.clone(),
                    false,
                )
                .unwrap();
            assert_eq!(
                verify(&key, &changed, true),
                Err(WebAuthnFailure::RelyingParty)
            );
        }
        let mut data = signed.assertion.authenticator_data.clone();
        data[0] ^= 1;
        let changed = authenticator
            .sign_bytes(data, signed.assertion.client_data.clone(), false)
            .unwrap();
        assert_eq!(
            verify(&key, &changed, true),
            Err(WebAuthnFailure::RelyingParty)
        );
        for flags in [0, 4] {
            let changed = authenticator
                .assertion(BODY, RP, "https://id.luff.works", flags, false)
                .unwrap();
            assert_eq!(
                verify(&key, &changed, false),
                Err(WebAuthnFailure::UserPresence)
            );
        }
        let changed = authenticator
            .assertion(BODY, RP, "https://id.luff.works", 1, false)
            .unwrap();
        assert_eq!(
            verify(&key, &changed, true),
            Err(WebAuthnFailure::UserVerification)
        );
        assert_eq!(verify(&key, &changed, false), Ok(false));
        let foreign = SyntheticAuthenticator::from_scalar(&[2; 32]).unwrap();
        let changed = foreign
            .assertion(BODY, RP, "https://id.luff.works", 5, false)
            .unwrap();
        assert_eq!(
            verify(&key, &changed, true),
            Err(WebAuthnFailure::Signature)
        );
        let mut hint = key.clone();
        if let KeyDescriptor::WebAuthn { credential, .. } = &mut hint {
            *credential = vec![42; 23];
        }
        assert_eq!(verify(&hint, &signed, true), Ok(true));
    }
    #[test]
    fn exact_client_data_is_signed_and_digest_is_hashed_once() {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        let (_, key, mut signed) = fixture();
        let signing = SigningKey::from_slice(&[1; 32]).unwrap();
        let mut message = signed.assertion.authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&signed.assertion.client_data));
        let signature: Signature = signing.sign_prehash(&Sha256::digest(&message)).unwrap();
        signed.signature = signature.to_der().as_bytes().to_vec();
        assert_eq!(verify(&key, &signed, true), Ok(true));
        // A semantically identical clientData document has different signed bytes.
        signed.assertion.client_data.push(b' ');
        assert_eq!(verify(&key, &signed, true), Err(WebAuthnFailure::Signature));
    }
    #[test]
    fn exact_verification_order() {
        let (_, key, mut signed) = fixture();
        signed.signature = vec![];
        signed.assertion.authenticator_data = vec![];
        signed.assertion.client_data = b"{".to_vec();
        assert_eq!(
            verify(&key, &signed, true),
            Err(WebAuthnFailure::ClientData)
        );
        signed.assertion.client_data = serde_json::to_vec(
            &json!({"type":"webauthn.create","challenge":"bad","origin":"bad","crossOrigin":true}),
        )
        .unwrap();
        assert_eq!(verify(&key, &signed, true), Err(WebAuthnFailure::Type));
        signed.assertion.client_data = serde_json::to_vec(
            &json!({"type":"webauthn.get","challenge":"bad","origin":"bad","crossOrigin":true}),
        )
        .unwrap();
        assert_eq!(verify(&key, &signed, true), Err(WebAuthnFailure::Challenge));
        signed.assertion.client_data=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":challenge(BODY),"origin":"bad","crossOrigin":true})).unwrap();
        assert_eq!(verify(&key, &signed, true), Err(WebAuthnFailure::Origin));
        signed.assertion.client_data=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":challenge(BODY),"origin":"https://id.luff.works","crossOrigin":true})).unwrap();
        assert_eq!(
            verify(&key, &signed, true),
            Err(WebAuthnFailure::CrossOrigin)
        );
        signed.assertion.client_data=serde_json::to_vec(&json!({"type":"webauthn.get","challenge":challenge(BODY),"origin":"https://id.luff.works"})).unwrap();
        assert_eq!(
            verify(&key, &signed, true),
            Err(WebAuthnFailure::RelyingParty)
        );
        signed.assertion.authenticator_data = Sha256::digest(RP.as_bytes()).to_vec();
        signed
            .assertion
            .authenticator_data
            .extend_from_slice(&[0; 5]);
        assert_eq!(
            verify(&key, &signed, true),
            Err(WebAuthnFailure::UserPresence)
        );
        signed.assertion.authenticator_data[32] = 1;
        assert_eq!(
            verify(&key, &signed, true),
            Err(WebAuthnFailure::UserVerification)
        );
        signed.assertion.authenticator_data[32] = 5;
        assert_eq!(verify(&key, &signed, true), Err(WebAuthnFailure::Der));
    }
    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        [
            vec![0x30, (r.len() + s.len() + 4) as u8, 2, r.len() as u8],
            r.to_vec(),
            vec![2, s.len() as u8],
            s.to_vec(),
        ]
        .concat()
    }
    #[test]
    fn der_exact_grammar_and_scalar_ranges() {
        let (_, key, signed) = fixture();
        let mut invalid = vec![
            vec![],
            der(&[], &[1]),
            der(&[1], &[]),
            der(&[0], &[1]),
            der(&[1], &[0]),
            der(&[0, 1], &[1]),
            der(&[1], &[0, 1]),
            der(&[0x80], &[1]),
            der(&[1], &[0x80]),
            der(&[1; 33], &[1]),
            der(&[0; 34], &[1]),
        ];
        let order = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        invalid.push(der(&[vec![0], order.to_vec()].concat(), &[1]));
        invalid.push(der(&[1], &[vec![0], order.to_vec()].concat()));
        let bytes = &signed.signature;
        invalid.push([vec![0x30, 0x81, bytes[1]], bytes[2..].to_vec()].concat());
        invalid.push([bytes.clone(), vec![0]].concat());
        let mut padded = bytes.clone();
        padded.insert(4, 0);
        padded[1] += 1;
        padded[3] += 1;
        invalid.push(padded);
        let mut wrong_tag = bytes.clone();
        wrong_tag[2] = 3;
        invalid.push(wrong_tag);
        let mut long_integer = bytes.clone();
        long_integer.insert(4, bytes[3]);
        long_integer[3] = 0x81;
        long_integer[1] += 1;
        invalid.push(long_integer);
        for n in 0..bytes.len() {
            invalid.push(bytes[..n].to_vec());
        }
        for signature in invalid {
            let changed = SyntheticAssertion {
                assertion: signed.assertion.clone(),
                signature,
            };
            assert_eq!(verify(&key, &changed, true), Err(WebAuthnFailure::Der));
        }
        assert!(parse_der(&der(&[1], &[1])).is_some());
        assert!(parse_der(&der(&[0, 0x80], &[1])).is_some());
        let mut below = order;
        below[31] -= 1;
        assert!(parse_der(&der(&[vec![0], below.to_vec()].concat(), &[1])).is_some());
    }
    #[test]
    fn raw_es256_and_exact_byte_binding() {
        use p256::ecdsa::signature::Signer;
        let signing = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        let signature: Signature = signing.sign(BODY);
        assert!(verify_raw(public.as_bytes(), BODY, &signature.to_bytes()).is_ok());
        let low = signature.normalize_s().unwrap_or(signature);
        let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
        assert!(verify_raw(public.as_bytes(), BODY, &high.to_bytes()).is_ok());
        assert!(verify_raw(public.as_bytes(), b"other", &signature.to_bytes()).is_err());
        assert!(verify_raw(public.as_bytes(), BODY, signature.to_der().as_bytes()).is_err());
        assert!(verify_raw(&public.as_bytes()[..33], BODY, &signature.to_bytes()).is_err());
        let (_, key, signed) = fixture();
        let Assertion {
            authenticator_data,
            client_data,
            ..
        } = signed.assertion;
        assert_eq!(
            verify_webauthn(
                &key,
                b"other",
                &signed.signature,
                &authenticator_data,
                &client_data,
                true
            ),
            Err(WebAuthnFailure::Challenge)
        );
    }
}
