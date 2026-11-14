//! Raw ES256, the §4.3 DER grammar (mutation fuzz against an independent grammar) and WebAuthn.
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
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use colophon_core::v05::descriptor::KeyDescriptor;
use colophon_core::v05::signature::{
    parse_der, verify_assertion_possession, verify_raw, webauthn_check, AssertionBytes, SigFailure,
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, signature::Signer, Signature, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use support::webauthn::{verify_webauthn, OriginRule, Strictness};
use support::Rng;

const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut v = a[i] as i16 - b[i] as i16 - borrow;
        borrow = (v < 0) as i16;
        if v < 0 {
            v += 256;
        }
        out[i] = v as u8;
    }
    out
}
/// Independent §4.3 step 5 grammar + range check.
fn model_der(b: &[u8]) -> bool {
    fn int(b: &[u8], at: &mut usize) -> Option<Vec<u8>> {
        if *b.get(*at)? != 0x02 {
            return None;
        }
        let len = *b.get(*at + 1)? as usize;
        if len >= 0x80 || !(1..=33).contains(&len) {
            return None;
        }
        let v = b.get(*at + 2..*at + 2 + len)?.to_vec();
        *at += 2 + len;
        if v[0] > 0x7f {
            return None;
        }
        if v[0] == 0 && (len == 1 || v[1] < 0x80) {
            // a leading 0x00 only before a byte >= 0x80; a lone 0x00 is zero (out of range)
            return None;
        }
        Some(v)
    }
    fn in_range(v: &[u8]) -> bool {
        let m: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0).collect();
        if m.is_empty() || m.len() > 32 {
            return false;
        }
        let mut p = [0u8; 32];
        p[32 - m.len()..].copy_from_slice(&m);
        p < N
    }
    if b.len() < 2 || b[0] != 0x30 || b[1] >= 0x80 || b[1] as usize + 2 != b.len() {
        return false;
    }
    let mut at = 2;
    let (Some(r), Some(s)) = (int(b, &mut at), int(b, &mut at)) else {
        return false;
    };
    at == b.len() && r.len() + s.len() + 4 == b[1] as usize && in_range(&r) && in_range(&s)
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
fn der_differential_fuzz() {
    let mut r = Rng(0xDE5);
    let (mut n, mut acc) = (0u64, 0u64);
    let mut dis = Vec::new();
    let one = {
        let mut x = [0u8; 32];
        x[31] = 1;
        x
    };
    let nm1 = sub(&N, &one);
    for i in 0..300_000u64 {
        let pick = |r: &mut Rng| -> [u8; 32] {
            match r.below(8) {
                0 => one,
                1 => nm1,
                2 => N,
                3 => [0u8; 32],
                4 => {
                    let mut x = [0u8; 32];
                    x[31] = r.below(256) as u8;
                    x
                }
                5 => [0xffu8; 32],
                _ => {
                    let mut x = [0u8; 32];
                    x.copy_from_slice(&r.bytes(32));
                    x
                }
            }
        };
        let (rv, sv) = (pick(&mut r), pick(&mut r));
        let mut b = der(&rv, &sv);
        let muts = if i % 3 == 0 { 0 } else { 1 + r.below(3) };
        for _ in 0..muts {
            match r.below(12) {
                0 if !b.is_empty() => {
                    let k = r.below(b.len() as u64) as usize;
                    b[k] ^= 1 << r.below(8);
                }
                1 => {
                    let k = r.below(b.len() as u64 + 1) as usize;
                    b.insert(k, r.next() as u8);
                }
                2 if !b.is_empty() => {
                    let k = r.below(b.len() as u64) as usize;
                    b.remove(k);
                }
                3 => b.push(0), // trailing byte
                4 if b.len() > 2 => {
                    // long-form outer length
                    let l = b[1];
                    b.splice(1..2, [0x81, l]);
                }
                5 if b.len() > 4 => {
                    // pad r with an extra 0x00 and fix lengths
                    b.insert(4, 0);
                    b[3] = b[3].wrapping_add(1);
                    b[1] = b[1].wrapping_add(1);
                }
                6 if b.len() > 4 && b[4] == 0 => {
                    // strip the sign pad (negative integer)
                    b.remove(4);
                    b[3] = b[3].wrapping_sub(1);
                    b[1] = b[1].wrapping_sub(1);
                }
                7 if b.len() > 2 => b[2] = *r.pick(&[0x03u8, 0x04, 0x30, 0x22, 0x82]),
                8 if b.len() > 3 => {
                    // empty r integer
                    let rl = b[3] as usize;
                    if b.len() >= 4 + rl {
                        b.drain(4..4 + rl);
                        b[1] = b[1].wrapping_sub(rl as u8);
                        b[3] = 0;
                    }
                }
                9 if b.len() > 3 => b[3] = *r.pick(&[0x81u8, 0x80, 0x00, 0x21, 0x22, 0x7f]),
                10 if !b.is_empty() => b[0] = *r.pick(&[0x31u8, 0x10, 0x70, 0x30]),
                _ => b.truncate(r.below(b.len() as u64 + 1) as usize),
            }
        }
        n += 1;
        let m = model_der(&b);
        let e = parse_der(&b).is_ok();
        acc += m as u64;
        if m != e && dis.len() < 30 {
            dis.push(format!("{:02x?}: engine {e} model {m}", b));
        }
    }
    println!(
        "DER differential: {n} encodings, {acc} accepted by the model, disagreements {}",
        dis.len()
    );
    for d in &dis {
        println!("  {d}");
    }
    assert!(dis.is_empty());
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn point(k: &SigningKey) -> Vec<u8> {
    k.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

#[test]
fn raw_scalars_and_points() {
    let k = key(3);
    let p = point(&k);
    let sig: Signature = k.sign(b"body");
    let b = sig.to_bytes();
    verify_raw(&p, b"body", &b).unwrap();
    let s: [u8; 32] = b[32..].try_into().unwrap();
    let mut high = b.to_vec();
    high[32..].copy_from_slice(&sub(&N, &s));
    verify_raw(&p, b"body", &high).expect("high-S valid");
    let mut zero_r = b.to_vec();
    zero_r[..32].fill(0);
    assert_eq!(verify_raw(&p, b"body", &zero_r), Err(SigFailure::Scalar));
    let mut n_s = b.to_vec();
    n_s[32..].copy_from_slice(&N);
    assert_eq!(verify_raw(&p, b"body", &n_s), Err(SigFailure::Scalar));
    let mut n_plus_s = b.to_vec(); // s + n does not fit 32 bytes; s' = s with r replaced by r+n impossible: use 0xff..
    n_plus_s[..32].fill(0xff);
    assert_eq!(verify_raw(&p, b"body", &n_plus_s), Err(SigFailure::Scalar));
    // Points: infinity encodings, compressed, off-curve, x >= p.
    let mut off = p.clone();
    off[64] ^= 1;
    let mut xbig = vec![4u8];
    xbig.extend([0xffu8; 64]);
    for (name, bad) in [
        ("infinity 0x00", vec![0u8]),
        ("zeros", vec![0u8; 65]),
        ("04+zeros", {
            let mut v = vec![4u8];
            v.extend([0u8; 64]);
            v
        }),
        (
            "compressed",
            k.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
        ),
        ("off-curve", off),
        ("x,y >= p", xbig),
        ("hybrid", {
            let mut v = p.clone();
            v[0] = 6 | (p[64] & 1);
            v
        }),
    ] {
        assert_eq!(
            verify_raw(&bad, b"body", &b),
            Err(SigFailure::Point),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// WebAuthn.
const RP: &str = "id.example";
fn desc(k: &SigningKey, origins: Option<&[&str]>, authority: Option<&[&str]>) -> KeyDescriptor {
    let mut d =
        json!({"form":"webauthn","signing":STANDARD.encode(point(k)),"rp":RP,"credential":"AQ=="});
    if let Some(o) = origins {
        d["origins"] = json!(o);
    }
    if let Some(a) = authority {
        d["authorityOrigins"] = json!(a);
    }
    KeyDescriptor::parse(d, "key").unwrap()
}
fn auth_data(flags: u8, extra: &[u8]) -> Vec<u8> {
    let mut a = Sha256::digest(RP.as_bytes()).to_vec();
    a.push(flags);
    a.extend([0, 0, 0, 9]);
    a.extend_from_slice(extra);
    a
}
fn cd(body: &[u8], origin: &str) -> String {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":{}}}"#,
        URL_SAFE_NO_PAD.encode(Sha256::digest(body)),
        serde_json::to_string(origin).unwrap()
    )
}
fn sign_assert(k: &SigningKey, ad: &[u8], client: &[u8]) -> Vec<u8> {
    let mut m = ad.to_vec();
    m.extend(Sha256::digest(client));
    let sig: Signature = k.sign_prehash(&Sha256::digest(&m)).unwrap();
    sig.to_der().as_bytes().to_vec()
}
fn check(
    k: &SigningKey,
    d: &KeyDescriptor,
    body: &[u8],
    ad: &[u8],
    client: &str,
    uv: bool,
    rule: OriginRule<'_>,
    strict: Strictness,
) -> Result<(), SigFailure> {
    let der = sign_assert(k, ad, client.as_bytes());
    verify_webauthn(
        d.signing(),
        d.webauthn().unwrap(),
        body,
        &der,
        AssertionBytes {
            authenticator_data: ad,
            client_data: client.as_bytes(),
        },
        uv,
        rule,
        strict,
    )
    .map(|_| ())
}

#[test]
fn webauthn_origin_matrix() {
    let k = key(7);
    let body = br#"{"x":1}"#;
    let ad = auth_data(0x05, &[]);
    let origins: &[&str] = &["android:apk-key-hash:abc", "https://partner.example"];
    let auth: &[&str] = &["android:apk-key-hash:abc", "https://auth.id.example"];
    let d_plain = desc(&k, Some(origins), None);
    let d_auth = desc(&k, Some(origins), Some(auth));
    let call_origins = vec![
        "https://app.id.example".to_string(),
        "https://evil.example".to_string(),
    ];
    use SigFailure::*;
    let general: &[(&str, Result<(), SigFailure>)] = &[
        ("https://id.example", Ok(())),
        ("https://a.id.example", Ok(())),
        ("https://a.b.id.example", Ok(())),
        ("https://xn--d1acufc.id.example", Ok(())),
        ("https://partner.example", Ok(())),
        ("android:apk-key-hash:abc", Ok(())),
        ("https://ID.example", Err(Origin)),
        ("https://A.id.example", Err(Origin)), // safe reading: the prefix follows the rp label grammar
        ("https://id.example.", Err(Origin)),
        ("https://a.id.example.", Err(Origin)),
        ("https://id.example:443", Err(Origin)),
        ("https://a.id.example:8443", Err(Origin)),
        ("http://id.example", Err(Origin)),
        ("HTTPS://id.example", Err(Origin)),
        ("https://u@id.example", Err(Origin)),
        ("https://u:p@a.id.example", Err(Origin)),
        ("https://a\\.id.example", Err(Origin)),
        ("https://evil.example\\@id.example", Err(Origin)),
        ("https://evil.example#.id.example", Err(Origin)),
        ("https://evil.example?.id.example", Err(Origin)),
        ("https://evil.example/.id.example", Err(Origin)),
        ("https://.id.example", Err(Origin)),
        ("https://a..id.example", Err(Origin)),
        ("https://xid.example", Err(Origin)),
        ("https://id.example.evil.example", Err(Origin)),
        ("https://id.example/", Err(Origin)),
        (" https://id.example", Err(Origin)),
        ("https://id.example ", Err(Origin)),
        ("https://partner.example.", Err(Origin)),
        ("https://sub.partner.example", Err(Origin)),
        ("android:apk-key-hash:ABC", Err(Origin)),
        ("https://évil.id.example", Err(Origin)), // safe reading (literal rule would allow)
        ("https://a b.id.example", Err(Origin)),  // safe reading (literal rule would allow)
        ("https://%2e.id.example", Err(Origin)),  // safe reading (literal rule would allow)
        ("", Err(Origin)),
    ];
    let mut lines = Vec::new();
    for (o, want) in general {
        let got = check(
            &k,
            &d_plain,
            body,
            &ad,
            &cd(body, o),
            false,
            OriginRule::General,
            Strictness::Current,
        );
        if &got != want {
            lines.push(format!("General {o:?}: got {got:?}, expected {want:?}"));
        }
    }
    // Authority rule without authorityOrigins: exactly https://<rp> or a listed platform origin.
    for (o, want) in [
        ("https://id.example", Ok(())),
        ("android:apk-key-hash:abc", Ok(())),
        ("https://a.id.example", Err(Origin)),
        ("https://partner.example", Err(Origin)),
        ("https://id.example.", Err(Origin)),
        ("https://ID.example", Err(Origin)),
    ] {
        let got = check(
            &k,
            &d_plain,
            body,
            &ad,
            &cd(body, o),
            true,
            OriginRule::Authority,
            Strictness::Current,
        );
        if got != want {
            lines.push(format!(
                "Authority(no list) {o:?}: got {got:?}, expected {want:?}"
            ));
        }
    }
    // Authority rule with authorityOrigins: only the list.
    for (o, want) in [
        ("https://auth.id.example", Ok(())),
        ("android:apk-key-hash:abc", Ok(())),
        ("https://id.example", Err(Origin)),
        ("https://x.auth.id.example", Err(Origin)),
        ("https://partner.example", Err(Origin)),
        ("https://app.id.example", Err(Origin)),
    ] {
        let got = check(
            &k,
            &d_auth,
            body,
            &ad,
            &cd(body, o),
            true,
            OriginRule::Authority,
            Strictness::Current,
        );
        if got != want {
            lines.push(format!(
                "Authority(list) {o:?}: got {got:?}, expected {want:?}"
            ));
        }
    }
    // Call rule: general rule first, then exactly one configured call origin.
    for (o, want) in [
        ("https://app.id.example", Ok(())),
        ("https://id.example", Err(CallOrigin)),
        ("https://evil.example", Err(Origin)),
        ("https://APP.id.example", Err(Origin)), // safe reading: fails the general rule first
    ] {
        let got = check(
            &k,
            &d_plain,
            body,
            &ad,
            &cd(body, o),
            false,
            OriginRule::Call(&call_origins),
            Strictness::Current,
        );
        if got != want {
            lines.push(format!("Call {o:?}: got {got:?}, expected {want:?}"));
        }
    }
    // Swift predecessor: general rule with no origins/authorityOrigins at all.
    for (o, want) in [
        ("https://a.id.example", Ok(())),
        ("android:apk-key-hash:abc", Err(Origin)),
        ("https://partner.example", Err(Origin)),
    ] {
        let got = check(
            &k,
            &d_auth,
            body,
            &ad,
            &cd(body, o),
            true,
            OriginRule::Authority,
            Strictness::SwiftPredecessor,
        );
        if got != want {
            lines.push(format!("Swift {o:?}: got {got:?}, expected {want:?}"));
        }
    }
    for l in &lines {
        println!("  {l}");
    }
    assert!(lines.is_empty());
}

#[test]
fn webauthn_client_and_authenticator_data() {
    let k = key(8);
    let body = br#"{"y":2}"#;
    let d = desc(&k, None, None);
    let ch = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    let o = "https://id.example";
    let ad = auth_data(0x01, &[]);
    use SigFailure::*;
    let cases: Vec<(&str, String, Vec<u8>, bool, Result<(), SigFailure>)> = vec![
        ("baseline", cd(body, o), ad.clone(), false, Ok(())),
        (
            "member order and whitespace",
            format!(r#" {{ "origin" : "{o}" , "challenge":"{ch}", "type":"webauthn.get" }} "#),
            ad.clone(),
            false,
            Ok(()),
        ),
        (
            "extra and topOrigin ignored",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","topOrigin":"https://evil.example","other":[1,{{}}]}}"#
            ),
            ad.clone(),
            false,
            Ok(()),
        ),
        (
            "crossOrigin false",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","crossOrigin":false}}"#
            ),
            ad.clone(),
            false,
            Ok(()),
        ),
        (
            "crossOrigin true",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","crossOrigin":true}}"#
            ),
            ad.clone(),
            false,
            Err(CrossOrigin),
        ),
        (
            "crossOrigin \"false\"",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","crossOrigin":"false"}}"#
            ),
            ad.clone(),
            false,
            Err(CrossOrigin),
        ),
        (
            "crossOrigin null",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","crossOrigin":null}}"#
            ),
            ad.clone(),
            false,
            Err(CrossOrigin),
        ),
        (
            "duplicate origin",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"https://evil.example","origin":"{o}"}}"#
            ),
            ad.clone(),
            false,
            Err(ClientData),
        ),
        (
            "duplicate type escaped",
            format!(
                r#"{{"type":"webauthn.create","type":"webauthn.get","challenge":"{ch}","origin":"{o}"}}"#
            ),
            ad.clone(),
            false,
            Err(ClientData),
        ),
        (
            "duplicate in ignored member",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","x":{{"a":1,"a":2}}}}"#
            ),
            ad.clone(),
            false,
            Err(ClientData),
        ),
        (
            "lone surrogate in ignored member",
            format!(r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"{o}","x":"\ud800"}}"#),
            ad.clone(),
            false,
            Err(ClientData),
        ),
        (
            "type create",
            format!(r#"{{"type":"webauthn.create","challenge":"{ch}","origin":"{o}"}}"#),
            ad.clone(),
            false,
            Err(Type),
        ),
        (
            "type missing",
            format!(r#"{{"challenge":"{ch}","origin":"{o}"}}"#),
            ad.clone(),
            false,
            Err(Type),
        ),
        (
            "challenge padded",
            format!(r#"{{"type":"webauthn.get","challenge":"{ch}=","origin":"{o}"}}"#),
            ad.clone(),
            false,
            Err(Challenge),
        ),
        (
            "challenge std alphabet",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{o}"}}"#,
                STANDARD.encode(Sha256::digest(body)).trim_end_matches('=')
            ),
            ad.clone(),
            false,
            if STANDARD.encode(Sha256::digest(body)).contains(['+', '/']) {
                Err(Challenge)
            } else {
                Ok(())
            },
        ),
        (
            "challenge of another body",
            cd(b"{}", o),
            ad.clone(),
            false,
            Err(Challenge),
        ),
        (
            "origin number",
            format!(r#"{{"type":"webauthn.get","challenge":"{ch}","origin":1}}"#),
            ad.clone(),
            false,
            Err(Origin),
        ),
        (
            "origin missing",
            format!(r#"{{"type":"webauthn.get","challenge":"{ch}"}}"#),
            ad.clone(),
            false,
            Err(Origin),
        ),
        (
            "not an object",
            "[]".into(),
            ad.clone(),
            false,
            Err(ClientData),
        ),
        (
            "BOM",
            format!("\u{feff}{}", cd(body, o)),
            ad.clone(),
            false,
            Err(ClientData),
        ),
        (
            "authData 36 bytes",
            cd(body, o),
            ad[..36].to_vec(),
            false,
            Err(RelyingParty),
        ),
        (
            "authData empty",
            cd(body, o),
            vec![],
            false,
            Err(RelyingParty),
        ),
        (
            "authData 37 + trailing",
            cd(body, o),
            auth_data(0x01, &[0xa1, 1, 2, 3]),
            false,
            Ok(()),
        ),
        (
            "rpIdHash of another rp",
            cd(body, o),
            {
                let mut a = ad.clone();
                a[0] ^= 1;
                a
            },
            false,
            Err(RelyingParty),
        ),
        (
            "UP unset",
            cd(body, o),
            auth_data(0x04, &[]),
            false,
            Err(UserPresence),
        ),
        (
            "UV unset but required",
            cd(body, o),
            auth_data(0x01, &[]),
            true,
            Err(UserVerification),
        ),
        (
            "UV set, required",
            cd(body, o),
            auth_data(0x05, &[]),
            true,
            Ok(()),
        ),
        (
            "BE BS AT ED flags ignored",
            cd(body, o),
            auth_data(0x01 | 0x08 | 0x10 | 0x40 | 0x80, &[]),
            false,
            Ok(()),
        ),
        (
            "RFU bit 0x02 ignored",
            cd(body, o),
            auth_data(0x03, &[]),
            false,
            Ok(()),
        ),
    ];
    let mut bad = Vec::new();
    for (name, client, ad, uv, want) in cases {
        let got = check(
            &k,
            &d,
            body,
            &ad,
            &client,
            uv,
            OriginRule::Authority,
            Strictness::Current,
        );
        if got != want {
            bad.push(format!("{name}: got {got:?}, expected {want:?}"));
        }
    }
    // Oversized clientData: 8,192 accepted, 8,193 refused.
    let base = cd(body, o);
    for (extra, want) in [
        (8192 - base.len() - 7, true),
        (8193 - base.len() - 7, false),
    ] {
        let client = format!(
            "{},\"p\":\"{}\"}}",
            &base[..base.len() - 1],
            "a".repeat(extra)
        );
        let got = check(
            &k,
            &d,
            body,
            &ad,
            &client,
            false,
            OriginRule::Authority,
            Strictness::Current,
        );
        if got.is_ok() != want {
            bad.push(format!("clientData of {} bytes: {got:?}", client.len()));
        }
    }
    // Signature over another message; a valid signature from another key.
    let der_other = sign_assert(&key(9), &ad, base.as_bytes());
    let r = verify_webauthn(
        d.signing(),
        d.webauthn().unwrap(),
        body,
        &der_other,
        AssertionBytes {
            authenticator_data: &ad,
            client_data: base.as_bytes(),
        },
        false,
        OriginRule::Authority,
        Strictness::Current,
    );
    if r != Err(Verify) {
        bad.push(format!("other key: {r:?}"));
    }
    // A raw descriptor through the standalone check is Form.
    let raw = KeyDescriptor::parse(
        json!({"form":"raw","signing":STANDARD.encode(point(&k))}),
        "k",
    )
    .unwrap();
    let der = sign_assert(&k, &ad, base.as_bytes());
    assert_eq!(
        webauthn_check(
            &raw,
            body,
            &der,
            AssertionBytes {
                authenticator_data: &ad,
                client_data: base.as_bytes()
            },
            colophon_core::v05::signature::CheckMode::Call {
                origins: &[],
                uv_required: false
            }
        ),
        Err(Form)
    );
    // Possession (call step 2) checks no origin, rp or flags, but does check type/challenge/crossOrigin.
    let ad_bad_rp = vec![0u8; 37];
    let client_evil = cd(body, "https://evil.example");
    let der2 = sign_assert(&k, &ad_bad_rp, client_evil.as_bytes());
    assert!(verify_assertion_possession(
        &point(&k),
        body,
        &der2,
        AssertionBytes {
            authenticator_data: &ad_bad_rp,
            client_data: client_evil.as_bytes()
        }
    )
    .is_ok());
    for l in &bad {
        println!("  {l}");
    }
    assert!(bad.is_empty());
}

/// Descriptor-level checks: authorityOrigins must each be allowed by the general rule.
#[test]
fn descriptor_rules() {
    let k = key(10);
    let base = || json!({"form":"webauthn","signing":STANDARD.encode(point(&k)),"rp":RP,"credential":"AQ=="});
    let mut bad_auth = base();
    bad_auth["authorityOrigins"] = json!(["https://evil.example"]);
    assert!(KeyDescriptor::parse(bad_auth, "k").is_err());
    let mut unsorted = base();
    unsorted["origins"] = json!(["https://b.example", "https://a.example"]);
    assert!(KeyDescriptor::parse(unsorted, "k").is_err());
    let mut unknown_form = base();
    unknown_form["form"] = json!("future");
    let r = KeyDescriptor::parse(unknown_form, "k");
    println!(
        "unknown key form (unauthenticated): {:?}",
        r.map(|_| ()).map_err(|e| e.code())
    );
    let mut http = base();
    http["origins"] = json!(["http://x.example"]);
    assert!(KeyDescriptor::parse(http, "k").is_err());
}
