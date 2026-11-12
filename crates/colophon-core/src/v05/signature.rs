//! Signature verification: `raw` ES256 (§4.2), the strict DER grammar and WebAuthn assertions
//! (§4.3), and the standalone WebAuthn check (§17.2, contract R2).
//!
//! Verification never changes stored bytes. High-S signatures are valid: `s` is normalized to
//! `min(s, n − s)` only *after* every grammar check, and only for the verifying library.
use super::descriptor::{general_origin_allowed, KeyDescriptor, WebAuthnKey};
use super::encoding::{bounds, encode_base64url};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Which check failed, in the normative order of §4.3. Callers map any failure of an attached
/// signature to `badSignature` (§19), with this as the diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigFailure {
    /// The signing point is not a valid uncompressed P-256 point.
    Point,
    /// A raw signature is not exactly 64 bytes.
    RawLength,
    /// `r` or `s` is outside [1, n − 1].
    Scalar,
    /// The DER bytes break §4.3 step 5's grammar.
    Der,
    /// ES256 verification failed.
    Verify,
    /// `clientData` is over 8,192 bytes, not strict JSON, has a duplicate member or is not an
    /// object.
    ClientData,
    /// `type` is not `"webauthn.get"`.
    Type,
    /// `challenge` is not the unpadded base64url of SHA-256(body).
    Challenge,
    /// The origin is not allowed under the requested origin rule.
    Origin,
    /// `crossOrigin` is present and not `false`.
    CrossOrigin,
    /// `authenticatorData` is shorter than 37 bytes or its first 32 bytes aren't SHA-256(rp).
    RelyingParty,
    /// UP (0x01) is not set.
    UserPresence,
    /// UV (0x04) is required and not set.
    UserVerification,
    /// The descriptor is not of the form this check needs.
    Form,
    /// The origin passed §4.3 but is not one of the configured call-ceremony origins.
    CallOrigin,
}
impl std::fmt::Display for SigFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signature check failed: {self:?}")
    }
}
impl std::error::Error for SigFailure {}

fn verifying_key(signing: &[u8]) -> Result<VerifyingKey, SigFailure> {
    if !super::descriptor::valid_point(signing) {
        return Err(SigFailure::Point);
    }
    VerifyingKey::from_sec1_bytes(signing).map_err(|_| SigFailure::Point)
}

/// Verify a `raw` signature: exactly 64 bytes `r ‖ s`, both in [1, n − 1], ES256 over the
/// exact body bytes (§4.2). High-S is valid.
pub fn verify_raw(signing: &[u8], body: &[u8], signature: &[u8]) -> Result<(), SigFailure> {
    let key = verifying_key(signing)?;
    if signature.len() != 64 {
        return Err(SigFailure::RawLength);
    }
    // `from_slice` refuses r or s equal to zero or not below n.
    let sig = Signature::from_slice(signature).map_err(|_| SigFailure::Scalar)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    key.verify(body, &sig).map_err(|_| SigFailure::Verify)
}

/// Parse a DER ECDSA signature under exactly §4.3 step 5's grammar:
/// `0x30 ‖ len ‖ 0x02 ‖ rlen ‖ r ‖ 0x02 ‖ slen ‖ s`, nothing after; every length one byte
/// below 0x80; `len = rlen + slen + 4`; `r` and `s` 1–33 bytes, first byte at most 0x7F, a
/// leading 0x00 only before a byte of 0x80 or more; both in [1, n − 1].
///
/// This is also exactly what the released Swift verifier accepted (§16.3), so predecessor
/// entries use it unchanged.
pub fn parse_der(bytes: &[u8]) -> Result<Signature, SigFailure> {
    use SigFailure::Der;
    if bytes.len() < 8 || bytes[0] != 0x30 || bytes[1] >= 0x80 {
        return Err(Der);
    }
    if usize::from(bytes[1]) + 2 != bytes.len() {
        return Err(Der);
    }
    let mut at = 2;
    let r = der_integer(bytes, &mut at)?;
    let s = der_integer(bytes, &mut at)?;
    if at != bytes.len() {
        return Err(Der);
    }
    Signature::from_scalars(r, s).map_err(|_| SigFailure::Scalar)
}
fn der_integer(bytes: &[u8], at: &mut usize) -> Result<[u8; 32], SigFailure> {
    use SigFailure::Der;
    if bytes.get(*at) != Some(&0x02) {
        return Err(Der);
    }
    let len = usize::from(*bytes.get(*at + 1).ok_or(Der)?);
    *at += 2;
    if !(1..=33).contains(&len) {
        return Err(Der);
    }
    let value = bytes.get(*at..*at + len).ok_or(Der)?;
    *at += len;
    if value[0] > 0x7f {
        return Err(Der);
    }
    let magnitude = if value[0] == 0 && len > 1 {
        if value[1] < 0x80 {
            return Err(Der);
        }
        &value[1..]
    } else {
        value
    };
    if magnitude.len() > 32 {
        return Err(Der);
    }
    let mut out = [0u8; 32];
    out[32 - magnitude.len()..].copy_from_slice(magnitude);
    Ok(out)
}

/// The origin rule a WebAuthn signature is checked under.
#[derive(Clone, Copy, Debug)]
pub enum OriginRule<'a> {
    /// Authority signatures (§4.3 "Authority origins", revision 5): authority entries,
    /// transitions, vetoes, `additions` and `handover` items. The caller sets this flag for
    /// each of them; this module does not implement transitions or vetoes.
    Authority,
    /// The general rule only (`origins`, `https://<rp>` and its subdomains).
    General,
    /// The general rule, then exactly one of these call-ceremony origins (§4.3 "Call origins").
    Call(&'a [String]),
}

/// How strictly to read an assertion.
///
/// Revision 4 of the spec gives predecessor (§16.3) entries **the same** DER grammar as 0.5
/// (§4.3 step 5) and the same `clientData` rules (duplicates refused). The only difference is
/// that a Swift controller has no `origins` or `authorityOrigins`, so its origin is checked by
/// the general rule alone, whatever rule an authority entry would otherwise use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strictness {
    /// A 0.5 object.
    Current,
    /// An entry of a `colophon/swift-keyring/2` predecessor (§16.3).
    SwiftPredecessor,
}

/// The parts of an assertion.
#[derive(Clone, Copy, Debug)]
pub struct AssertionBytes<'a> {
    /// Exact `authenticatorData` bytes.
    pub authenticator_data: &'a [u8],
    /// Exact `clientData` bytes.
    pub client_data: &'a [u8],
}

/// A verified assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnOk {
    /// The UV flag as asserted.
    pub uv: bool,
    /// The `origin` member of `clientData`.
    pub origin: String,
    /// The sign counter (bytes 33–36), for display only; never used for validity (§4.3 step 4).
    pub counter: u32,
}

/// The unpadded base64url SHA-256 of the exact body: the expected `challenge`.
pub fn challenge(body: &[u8]) -> String {
    encode_base64url(&Sha256::digest(body))
}

struct Client {
    origin: String,
}
/// §4.3 step 1 without the origin rule: strict parse, `type`, `challenge`, `crossOrigin`.
fn check_client(body: &[u8], client_data: &[u8]) -> Result<Client, SigFailure> {
    if client_data.len() > bounds::CLIENT_DATA {
        return Err(SigFailure::ClientData);
    }
    let value = crate::keys::strict_json::parse(client_data).map_err(|_| SigFailure::ClientData)?;
    let map = value.as_object().ok_or(SigFailure::ClientData)?;
    if map.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(SigFailure::Type);
    }
    if map.get("challenge").and_then(|v| v.as_str()) != Some(challenge(body).as_str()) {
        return Err(SigFailure::Challenge);
    }
    let origin = match map.get("origin") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return Err(SigFailure::Origin),
    };
    if map
        .get("crossOrigin")
        .is_some_and(|v| v != &serde_json::Value::Bool(false))
    {
        return Err(SigFailure::CrossOrigin);
    }
    Ok(Client { origin })
}
fn check_der_signature(
    signing: &[u8],
    assertion: AssertionBytes<'_>,
    der: &[u8],
) -> Result<(), SigFailure> {
    let sig = parse_der(der)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let key = verifying_key(signing)?;
    let mut message = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    message.extend_from_slice(assertion.authenticator_data);
    message.extend_from_slice(&Sha256::digest(assertion.client_data));
    key.verify(&message, &sig).map_err(|_| SigFailure::Verify)
}

/// Verify a WebAuthn signature under all of §4.3, in order. `uv_required` is the controller's
/// `verification` combined with any "with UV" rule. Returns the UV bit and the origin.
#[allow(clippy::too_many_arguments)]
pub fn verify_webauthn(
    signing: &[u8],
    key: &WebAuthnKey,
    body: &[u8],
    der_signature: &[u8],
    assertion: AssertionBytes<'_>,
    uv_required: bool,
    rule: OriginRule<'_>,
    strictness: Strictness,
) -> Result<WebAuthnOk, SigFailure> {
    let client = check_client(body, assertion.client_data)?;
    let origin_ok = match strictness {
        Strictness::SwiftPredecessor => general_origin_allowed(&client.origin, &key.rp, &[]),
        Strictness::Current => match rule {
            OriginRule::Authority => key.authority_origin_allowed(&client.origin),
            OriginRule::General | OriginRule::Call(_) => {
                general_origin_allowed(&client.origin, &key.rp, key.origins())
            }
        },
    };
    if !origin_ok {
        return Err(SigFailure::Origin);
    }
    let data = assertion.authenticator_data;
    if data.len() < 37 || data[..32] != Sha256::digest(key.rp.as_bytes())[..] {
        return Err(SigFailure::RelyingParty);
    }
    let flags = data[32];
    if flags & 0x01 == 0 {
        return Err(SigFailure::UserPresence);
    }
    let uv = flags & 0x04 != 0;
    if uv_required && !uv {
        return Err(SigFailure::UserVerification);
    }
    let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    check_der_signature(signing, assertion, der_signature)?;
    if let OriginRule::Call(origins) = rule {
        if !origins.iter().any(|o| o == &client.origin) {
            return Err(SigFailure::CallOrigin);
        }
    }
    Ok(WebAuthnOk {
        uv,
        origin: client.origin,
        counter,
    })
}

/// §12.3 step 2 for a call with an assertion: `clientData` `type`, `challenge` and
/// `crossOrigin`, then §4.3 step 5 under `key`. No origin, `rp` or flag checks (those are
/// step 5, once the signer is known). Returns the asserted origin.
pub fn verify_assertion_possession(
    signing: &[u8],
    body: &[u8],
    der_signature: &[u8],
    assertion: AssertionBytes<'_>,
) -> Result<String, SigFailure> {
    let client = check_client(body, assertion.client_data)?;
    check_der_signature(signing, assertion, der_signature)?;
    Ok(client.origin)
}

/// The standalone WebAuthn check (§17.2): `Ok` with the UV bit, or the failed check.
pub fn webauthn_check(
    descriptor: &KeyDescriptor,
    body: &[u8],
    der_signature: &[u8],
    assertion: AssertionBytes<'_>,
    uv_required: bool,
    rule: OriginRule<'_>,
) -> Result<WebAuthnOk, SigFailure> {
    let key = descriptor.webauthn().ok_or(SigFailure::Form)?;
    verify_webauthn(
        &descriptor.signing,
        key,
        body,
        der_signature,
        assertion,
        uv_required,
        rule,
        Strictness::Current,
    )
}

/// An envelope that carries exactly `body` and `signature` (§4.1: requests, links, heads,
/// receipts and operation headers), signed `raw`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEnvelope {
    /// Exact body bytes (canonical JSON, checked).
    pub body: Vec<u8>,
    /// The body, parsed.
    pub value: serde_json::Value,
    /// The 64-byte signature.
    pub signature: Vec<u8>,
}
impl RawEnvelope {
    /// Parse an envelope with exactly `body` and `signature`. The body must be canonical and
    /// within `bound`. With `embedded`, the envelope bytes themselves must also be canonical
    /// (§2.2: embedded envelopes are base64 of canonical JSON). No signature is checked here.
    pub fn parse(bytes: &[u8], bound: usize, embedded: bool) -> super::Result<Self> {
        use super::encoding::{canonical_body, decode_base64, strict_parse, Obj};
        super::require(
            bytes.len() <= bound.saturating_mul(2).saturating_add(4_096),
            "envelope exceeds its bound",
        )?;
        let value = if embedded {
            canonical_body(bytes, usize::MAX)?
        } else {
            strict_parse(bytes)?
        };
        let mut o = Obj::new(value, "envelope")?;
        let body = decode_base64(&o.string("body")?, bound)?;
        let signature = decode_base64(&o.string("signature")?, 64)?;
        o.finish_closed()?;
        let value = canonical_body(&body, bound)?;
        Ok(Self {
            body,
            value,
            signature,
        })
    }
    /// Verify the raw signature under `signing`.
    pub fn verify(&self, signing: &[u8]) -> Result<(), SigFailure> {
        verify_raw(signing, &self.body, &self.signature)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut v = i16::from(a[i]) - i16::from(b[i]) - borrow;
            borrow = if v < 0 { 1 } else { 0 };
            if v < 0 {
                v += 256;
            }
            out[i] = v as u8;
        }
        out
    }
    fn der_int(v: &[u8]) -> Vec<u8> {
        let mut m: Vec<u8> = v.iter().copied().skip_while(|b| *b == 0).collect();
        if m.is_empty() {
            m.push(0);
        }
        if m[0] >= 0x80 {
            m.insert(0, 0);
        }
        let mut out = vec![2, m.len() as u8];
        out.extend(m);
        out
    }
    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let (r, s) = (der_int(r), der_int(s));
        let mut out = vec![0x30, (r.len() + s.len()) as u8];
        out.extend(r);
        out.extend(s);
        out
    }

    #[test]
    fn raw_accepts_high_s_and_refuses_bad_scalars() {
        let k = SigningKey::from_slice(&[3; 32]).unwrap();
        let point = k
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let sig: Signature = k.sign(b"body");
        let bytes = sig.to_bytes();
        verify_raw(&point, b"body", &bytes).unwrap();
        let mut high = bytes.to_vec();
        let s: [u8; 32] = bytes[32..].try_into().unwrap();
        high[32..].copy_from_slice(&sub(&N, &s));
        verify_raw(&point, b"body", &high).unwrap();
        assert_eq!(
            verify_raw(&point, b"other", &bytes),
            Err(SigFailure::Verify)
        );
        assert_eq!(
            verify_raw(&point, b"body", &bytes[..63]),
            Err(SigFailure::RawLength)
        );
        let mut zero = bytes.to_vec();
        zero[32..].fill(0);
        assert_eq!(verify_raw(&point, b"body", &zero), Err(SigFailure::Scalar));
        let mut n = bytes.to_vec();
        n[32..].copy_from_slice(&N);
        assert_eq!(verify_raw(&point, b"body", &n), Err(SigFailure::Scalar));
        assert_eq!(
            verify_raw(&point[..64], b"body", &bytes),
            Err(SigFailure::Point)
        );
    }

    #[test]
    fn der_grammar_is_exact() {
        let k = SigningKey::from_slice(&[5; 32]).unwrap();
        let sig: Signature = k.sign(b"m");
        let b = sig.to_bytes();
        let (r, s) = (&b[..32], &b[32..]);
        let good = der(r, s);
        parse_der(&good).unwrap();
        // High-S, minimally encoded, is valid.
        let hs = sub(&N, &s.try_into().unwrap());
        parse_der(&der(r, &hs)).unwrap();
        // Trailing byte.
        let mut t = good.clone();
        t.push(0);
        assert_eq!(parse_der(&t), Err(SigFailure::Der));
        // Long-form length.
        let mut long = vec![0x30, 0x81, good[1]];
        long.extend_from_slice(&good[2..]);
        assert_eq!(parse_der(&long), Err(SigFailure::Der));
        // Extra leading zero on r.
        let mut r_pad = vec![0u8];
        r_pad.extend_from_slice(&der_int(r)[2..]);
        let mut extra = vec![0x02, r_pad.len() as u8];
        extra.extend(&r_pad);
        let s_enc = der_int(s);
        let mut e = vec![0x30, (extra.len() + s_enc.len()) as u8];
        e.extend(&extra);
        e.extend(&s_enc);
        assert_eq!(parse_der(&e), Err(SigFailure::Der));
        // A top-bit-set integer without its 0x00 pad.
        let hi = [0x80u8; 32];
        let mut unpadded = vec![0x02, 32];
        unpadded.extend(hi);
        let mut u = vec![0x30, (unpadded.len() + s_enc.len()) as u8];
        u.extend(&unpadded);
        u.extend(&s_enc);
        assert_eq!(parse_der(&u), Err(SigFailure::Der));
        // Wrong outer length, wrong tags, zero scalar, scalar = n.
        let mut wl = good.clone();
        wl[1] += 1;
        assert_eq!(parse_der(&wl), Err(SigFailure::Der));
        let mut tag = good.clone();
        tag[0] = 0x31;
        assert_eq!(parse_der(&tag), Err(SigFailure::Der));
        assert_eq!(parse_der(&der(&[0], s)), Err(SigFailure::Scalar));
        assert_eq!(parse_der(&der(r, &N)), Err(SigFailure::Scalar));
        assert_eq!(parse_der(&[]), Err(SigFailure::Der));
        assert_eq!(
            parse_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01]),
            Err(SigFailure::Der)
        );
        // Small scalars are valid DER.
        parse_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).unwrap();
    }
}
