//! Base64, requestId, dates, integers, number comparison, terms/narrowing and §3.3 checks.
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
use colophon_core::v05::encoding::{
    compare_numbers, decode_base64, decode_request_id, parse_date, uint,
};
use colophon_core::v05::terms::{Terms, TermsKind};
use colophon_core::v05::Unknown;
use serde_json::{json, Number, Value};
use std::cmp::Ordering;
use support::Rng;

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Independent strict decoder: padded, standard alphabet, zero pad bits.
fn model_b64(s: &str, alphabet: &[u8; 64], padded: bool) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let val = |c: u8| alphabet.iter().position(|x| *x == c).map(|v| v as u32);
    let (body, pad) = if padded {
        if b.len() % 4 != 0 {
            return None;
        }
        let pad = b.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 {
            return None;
        }
        (&b[..b.len() - pad], pad)
    } else {
        if b.len() % 4 == 1 {
            return None;
        }
        (b, 0)
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut nbits = 0;
    for &c in body {
        acc = (acc << 6) | val(c)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    if acc != 0 {
        return None; // non-zero pad bits
    }
    let _ = pad;
    Some(out)
}

#[test]
fn base64_differential() {
    let mut r = Rng(5);
    let mut n = 0;
    let mut dis = Vec::new();
    for _ in 0..150_000 {
        let len = r.below(20) as usize;
        let bytes = r.bytes(len);
        let mut s = String::new();
        // canonical encoding by hand
        for chunk in bytes.chunks(3) {
            let v = (chunk[0] as u32) << 16
                | (*chunk.get(1).unwrap_or(&0) as u32) << 8
                | *chunk.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= chunk.len() {
                    s.push(STD[((v >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        let mut t: Vec<u8> = s.into_bytes();
        if r.chance(2, 3) && !t.is_empty() {
            match r.below(7) {
                0 => {
                    let i = r.below(t.len() as u64) as usize;
                    t[i] = *r.pick(b"ABZaz09+/-_=\n .");
                }
                1 => t.push(b'='),
                2 => {
                    while t.last() == Some(&b'=') {
                        t.pop();
                    }
                }
                3 => {
                    // flip a pad bit in the last data character
                    let i = t.iter().rposition(|c| *c != b'=').unwrap();
                    let v = STD.iter().position(|x| *x == t[i]).unwrap();
                    t[i] = STD[v ^ 1];
                }
                4 => t.insert(r.below(t.len() as u64) as usize, b'\n'),
                5 => {
                    let i = r.below(t.len() as u64) as usize;
                    t.remove(i);
                }
                _ => t.extend_from_slice(b"===="),
            }
        }
        let text = String::from_utf8(t).unwrap();
        n += 1;
        let m = model_b64(&text, STD, true);
        let e = decode_base64(&text, 1000).ok();
        if m != e {
            dis.push(format!("{text:?}: engine {e:?} model {m:?}"));
        }
    }
    println!("base64: {n} inputs, disagreements {}", dis.len());
    for d in dis.iter().take(20) {
        println!("  {d}");
    }
    assert!(dis.is_empty());
    // Bound before decoding: a 10 MB string with max 64 is refused without decoding.
    let big = "A".repeat(10_000_000);
    let t = std::time::Instant::now();
    assert!(decode_base64(&big, 64).is_err());
    println!(
        "10 MB base64 over a 64-byte bound refused in {:?}",
        t.elapsed()
    );
    // Bound arithmetic: exactly max bytes OK, max+1 refused.
    for max in 0..70usize {
        let ok = model_b64(&base64_std(&vec![7u8; max]), STD, true).unwrap();
        assert_eq!(decode_base64(&base64_std(&ok), max).ok(), Some(ok.clone()));
        assert!(
            decode_base64(&base64_std(&vec![7u8; max + 1]), max).is_err(),
            "max {max}"
        );
    }
}
fn base64_std(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn request_id_spellings() {
    use base64::Engine;
    let mut r = Rng(9);
    let mut n = 0;
    for _ in 0..50_000 {
        let bytes = r.bytes(32);
        let canon = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        assert_eq!(decode_request_id(&canon).unwrap().to_vec(), bytes);
        // Every other spelling of the same bytes is refused: non-zero pad bits in the last char.
        let last = canon.as_bytes()[42];
        let v = URL.iter().position(|x| *x == last).unwrap();
        for d in 1..4 {
            let mut alt = canon.clone().into_bytes();
            alt[42] = URL[v ^ d];
            let alt = String::from_utf8(alt).unwrap();
            assert!(decode_request_id(&alt).is_err(), "{alt}");
            assert_eq!(model_b64(&alt, URL, false), None);
            n += 1;
        }
        for alt in [
            format!("{canon}="),
            canon.replace('-', "+").replace('_', "/"),
            canon[..42].to_string(),
            format!("{canon}A"),
            format!(" {}", &canon[1..]),
        ] {
            if alt != canon {
                assert!(decode_request_id(&alt).is_err(), "{alt}");
                n += 1;
            }
        }
    }
    println!("requestId: {n} alternative spellings refused");
}

fn model_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if !(b.len() == 20 || b.len() == 24) || !b.is_ascii() {
        return None;
    }
    let d = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = &s[r];
        if t.bytes().all(|c| c.is_ascii_digit()) {
            t.parse().ok()
        } else {
            None
        }
    };
    if &s[4..5] != "-"
        || &s[7..8] != "-"
        || &s[10..11] != "T"
        || &s[13..14] != ":"
        || &s[16..17] != ":"
    {
        return None;
    }
    let ms = if b.len() == 20 {
        if &s[19..] != "Z" {
            return None;
        }
        0
    } else {
        if &s[19..20] != "." || &s[23..] != "Z" {
            return None;
        }
        d(20..23)?
    };
    let (y, mo, da, h, mi, se) = (
        d(0..4)?,
        d(5..7)?,
        d(8..10)?,
        d(11..13)?,
        d(14..16)?,
        d(17..19)?,
    );
    if !(1..=9999).contains(&y) || !(1..=12).contains(&mo) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][(mo - 1) as usize];
    if da < 1 || da > dim {
        return None;
    }
    // days since 1970-01-01 by counting (independent of the engine's formula)
    let mut days: i64 = 0;
    let isleap = |y: i64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if y >= 1970 {
        for yy in 1970..y {
            days += if isleap(yy) { 366 } else { 365 };
        }
    } else {
        for yy in y..1970 {
            days -= if isleap(yy) { 366 } else { 365 };
        }
    }
    for m in 1..mo {
        days += [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ][(m - 1) as usize];
    }
    days += da - 1;
    Some(((days * 86400 + h * 3600 + mi * 60 + se) * 1000) + ms)
}

#[test]
fn dates_differential() {
    let mut r = Rng(11);
    let mut n = 0;
    let mut dis = Vec::new();
    for i in 0..300_000u64 {
        let y = match i % 5 {
            0 => r.below(10000),
            1 => *r.pick(&[0, 1, 1600, 1700, 1900, 1969, 1970, 2000, 2024, 2100, 9999]),
            _ => 1900 + r.below(300),
        };
        let mut s = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            y,
            r.below(14),
            r.below(33),
            r.below(26),
            r.below(62),
            r.below(62)
        );
        match r.below(6) {
            0 => s.push('Z'),
            1 => s.push_str(&format!(".{:03}Z", r.below(1000))),
            2 => s.push_str(*r.pick(&[
                ".0Z", ".00Z", ".0000Z", "z", "+00:00", "", ".000z", "Z ", ".1234",
            ])),
            _ => s.push_str(&format!(".{:03}Z", r.below(1000))),
        }
        if r.chance(1, 20) {
            let mut b = s.into_bytes();
            let k = r.below(b.len() as u64) as usize;
            b[k] = *r.pick(b"0 9-T:Z.x/");
            s = String::from_utf8(b).unwrap();
        }
        n += 1;
        let (m, e) = (model_date(&s), parse_date(&s));
        if m != e {
            dis.push(format!("{s}: engine {e:?} model {m:?}"));
        }
    }
    // Non-ASCII digits and multibyte characters at fixed positions never panic.
    for s in [
        "２０２６-11-11T09:00:00Z",
        "2026-11-11T09:00:00é",
        "2026-11-11T09:00:0éZ",
        "é026-11-11T09:00:00.000Z",
    ] {
        assert_eq!(parse_date(s), None);
    }
    println!("dates: {n} inputs, disagreements {}", dis.len());
    for d in dis.iter().take(20) {
        println!("  {d}");
    }
    assert!(dis.is_empty());
}

#[test]
fn integers() {
    for (v, ok) in [
        (json!(0), true),
        (json!(9007199254740991u64), true),
        (json!(9007199254740992u64), false),
        (json!(-1), false),
        (json!(1.0), false),
        (json!(u64::MAX), false),
    ] {
        assert_eq!(uint(&v, "x").is_ok(), ok, "{v}");
    }
}

/// Exact int-vs-binary64 comparison against a rational model.
#[test]
fn number_comparison_exact() {
    fn exact_cmp_int_float(i: i128, f: f64) -> Ordering {
        // f = m * 2^e exactly
        let bits = f.to_bits();
        let sign = if bits >> 63 == 1 { -1i128 } else { 1 };
        let exp = ((bits >> 52) & 0x7ff) as i32;
        let frac = (bits & ((1u64 << 52) - 1)) as i128;
        let (m, e) = if exp == 0 {
            (frac, -1074)
        } else {
            (frac | (1 << 52), exp - 1075)
        };
        let m = sign * m;
        // compare i with m*2^e
        if e >= 0 {
            if e > 70 {
                return if m > 0 {
                    Ordering::Less
                } else if m < 0 {
                    Ordering::Greater
                } else {
                    i.cmp(&0)
                };
            }
            i.cmp(&(m << e))
        } else {
            let sh = (-e) as u32;
            if sh > 120 {
                // |f| < 2^-67: compare i with 0, then sign of f
                return match i.cmp(&0) {
                    Ordering::Equal => 0.cmp(&m),
                    o => o,
                };
            }
            (i << sh.min(60))
                .cmp(&(m >> (sh - sh.min(60))))
                .then_with(|| {
                    // tie-break when low bits were shifted out
                    if sh > 60 && (i << 60) == (m >> (sh - 60)) {
                        let rem = m - ((m >> (sh - 60)) << (sh - 60));
                        0.cmp(&rem)
                    } else {
                        Ordering::Equal
                    }
                })
        }
    }
    let mut r = Rng(13);
    let mut n = 0;
    for _ in 0..200_000 {
        let i: i128 = match r.below(4) {
            0 => r.below(1 << 20) as i128 - (1 << 19),
            1 => (r.next() as i64) as i128,
            2 => r.next() as i128,
            _ => (1i128 << 53) + r.below(5) as i128 - 2,
        };
        let f = match r.below(4) {
            0 => i as f64,
            1 => i as f64 + *r.pick(&[0.5, -0.5, 0.25, 1.0, -1.0]),
            2 => f64::from_bits(r.next()),
            _ => (i as f64) * 1.0000000000000002,
        };
        if !f.is_finite() || i > u64::MAX as i128 || i < i64::MIN as i128 {
            continue;
        }
        let ni: Number = if i >= 0 {
            Number::from(i as u64)
        } else {
            Number::from(i as i64)
        };
        let nf = Number::from_f64(f).unwrap();
        let want = exact_cmp_int_float(i, f);
        assert_eq!(compare_numbers(&ni, &nf), Some(want), "{i} vs {f:e}");
        assert_eq!(
            compare_numbers(&nf, &ni),
            Some(want.reverse()),
            "{f:e} vs {i}"
        );
        n += 1;
    }
    println!("number comparisons: {n} exact");
}

fn terms(v: Value, kind: TermsKind) -> (Terms, Unknown) {
    let t = Terms::parse(v, kind).unwrap();
    let u = t.unknown().clone();
    (t, u)
}
const AUD: &str = "https://s.example/x";

#[test]
fn conditions_and_unknown_operators() {
    // Finding M1, fixed: unknown operators are three-valued and the result says so.
    use colophon_core::v05::terms::Truth;
    let (t, u) = terms(
        json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"not":{"future":["a",1]}}]}),
        TermsKind::Member,
    );
    assert_eq!(t.conditions_on(&json!({})), Truth::Unknown);
    assert!(!u.is_empty());
    let (t2, u2) = terms(
        json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"future":["amount",1]}]}),
        TermsKind::Member,
    );
    assert_eq!(
        t2.conditions_on(&json!({"amount": 1_000_000})),
        Truth::Unknown
    );
    assert!(!u2.is_empty());
    // A predicate object with two operators is malformed.
    assert!(Terms::parse(json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"eq":["a",1],"lte":["a",2]}]}), TermsKind::Member).is_err());
    // lte with a huge integer bound vs float arg.
    let (t3, _) = terms(
        json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"lte":["args.n", 9007199254740993u64]}]}),
        TermsKind::Member,
    );
    assert!(!t3.conditions_hold(&json!({"n": 9007199254740994.0})));
    assert!(t3.conditions_hold(&json!({"n": 9007199254740992.0})));
    assert!(!t3.conditions_hold(&json!({"n": "1"})));
    assert!(!t3.conditions_hold(&json!({})));
    // eq compares canonical bytes: 1 vs 1.0 differ.
    let (t4, _) = terms(
        json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"eq":["n", 1]}]}),
        TermsKind::Member,
    );
    assert!(t4.conditions_hold(&json!({"n": 1})) && !t4.conditions_hold(&json!({"n": 1.0})));
    // Path: "args" alone and "args.args".
    let (t5, _) = terms(
        json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"eq":["args", 1]}]}),
        TermsKind::Member,
    );
    println!(
        "path \"args\" reads member args.args: {}",
        t5.conditions_hold(&json!({"args": 1}))
    );
    // 33 predicates counting logical ones; depth 5.
    let leaf = json!({"eq":["a",1]});
    assert!(Terms::parse(json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"all":(0..31).map(|_| leaf.clone()).collect::<Vec<_>>()}]}), TermsKind::Member).is_ok());
    assert!(Terms::parse(json!({"services":[{"audience":AUD,"purposes":["p"]}],"conditions":[{"all":(0..32).map(|_| leaf.clone()).collect::<Vec<_>>()}]}), TermsKind::Member).is_err());
}

#[test]
fn narrowing_judgement() {
    // §10.3: every parent predicate must appear in the child.
    let (parent, _) = terms(
        json!({"services":[{"audience":AUD,"purposes":["a","b"]}],"depth":2,"conditions":[{"prefix":["args.task","T-"]},{"lte":["n",5]}]}),
        TermsKind::Member,
    );
    let cases = [
        (
            json!({"services":[{"audience":AUD,"purposes":["a"]}],"conditions":[{"lte":["n",5]},{"prefix":["args.task","T-"]}]}),
            true,
        ),
        (
            json!({"services":[{"audience":AUD,"purposes":["a"]}],"conditions":[{"prefix":["args.task","T-"]}]}),
            false,
        ),
        (
            json!({"services":[{"audience":AUD,"purposes":["a"]}]}),
            false,
        ),
        // the same predicate spelt with the path's optional "args." prefix differently: different canonical JSON
        (
            json!({"services":[{"audience":AUD,"purposes":["a"]}],"conditions":[{"prefix":["task","T-"]},{"lte":["n",5]}]}),
            false,
        ),
        // 5 vs 5.0 differ by canonical JSON
        (
            json!({"services":[{"audience":AUD,"purposes":["a"]}],"conditions":[{"prefix":["args.task","T-"]},{"lte":["n",5.0]}]}),
            false,
        ),
        (
            json!({"services":[{"audience":AUD,"purposes":["*"]}],"conditions":[{"prefix":["args.task","T-"]},{"lte":["n",5]}]}),
            false,
        ),
        (
            json!({"services":[{"audience":AUD,"purposes":["a"]}],"depth":2,"conditions":[{"prefix":["args.task","T-"]},{"lte":["n",5]}]}),
            false,
        ),
        (
            json!({"services":[{"audience":"https://other.example","purposes":["a"]}],"conditions":[{"prefix":["args.task","T-"]},{"lte":["n",5]}]}),
            false,
        ),
    ];
    for (child, want) in cases {
        let (c, _) = terms(child.clone(), TermsKind::Link);
        assert_eq!(c.narrows(&parent), want, "{child}");
    }
}

#[test]
fn principals() {
    use colophon_core::v05::members::{check_principals, Principal, Usage};
    use p256::ecdsa::SigningKey;
    let k = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let un = k
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let comp = k.verifying_key().to_encoded_point(true).as_bytes().to_vec();
    // The same point under two encodings for two principals: check_principals compares bytes.
    let r = check_principals(&[
        (
            Principal::Controller("c".into()),
            Usage::Signing,
            un.clone(),
        ),
        (Principal::Member("m".into()), Usage::Signing, comp.clone()),
    ]);
    println!(
        "same point, compressed vs uncompressed, two principals: {:?}",
        r.is_ok()
    );
    // Every parser path refuses compressed points (valid_point requires 65 bytes 0x04).
    assert!(!colophon_core::v05::descriptor::valid_point(&comp));
    let mut hybrid = un.clone();
    hybrid[0] = 6 | (un[64] & 1);
    assert!(!colophon_core::v05::descriptor::valid_point(&hybrid));
    assert!(check_principals(&[
        (
            Principal::Controller("c".into()),
            Usage::Signing,
            un.clone()
        ),
        (
            Principal::Controller("c".into()),
            Usage::Agreement,
            un.clone()
        ),
    ])
    .is_err());
}

/// The pre-fix boolean view of three-valued conditions, for the ported assertions.
trait Holds {
    fn conditions_hold(&self, v: &serde_json::Value) -> bool;
}
impl Holds for colophon_core::v05::terms::Terms {
    fn conditions_hold(&self, v: &serde_json::Value) -> bool {
        self.conditions_on(v) == colophon_core::v05::terms::Truth::True
    }
}
