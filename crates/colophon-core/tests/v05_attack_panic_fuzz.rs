//! Panic fuzzing of every public v05 parser with structure-aware mutations (debug assertions and
//! overflow checks on via the test profile). Any panic is a finding.
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
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::calls::Call;
use colophon_core::v05::descriptor::{Controller, KeyDescriptor, Policy};
use colophon_core::v05::heads::{verify_head, HeadContext};
use colophon_core::v05::ids::{AccountId, Reference};
use colophon_core::v05::members::{AuthorityHeader, Request, Revoke};
use colophon_core::v05::records::OperationHeader;
use colophon_core::v05::signature::RawEnvelope;
use colophon_core::v05::terms::{Terms, TermsKind};
use serde_json::{json, Map, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};
use support::Rng;

fn rand_value(r: &mut Rng, d: u32) -> Value {
    match r.below(if d == 0 { 7 } else { 9 }) {
        0 => Value::Null,
        1 => json!(r.chance(1, 2)),
        2 => json!(*r.pick(&[
            0i64,
            -1,
            1,
            9007199254740991,
            9007199254740992,
            i64::MIN,
            i64::MAX
        ])),
        3 => json!(*r.pick(&[u64::MAX, 1u64 << 63])),
        4 => json!(*r.pick(&[0.5f64, -0.0, 1e308, 5e-324, 1.0])),
        5 => json!(*r.pick(&[
            "",
            "a",
            "AAAA",
            "AAE=",
            "colophon/call/5",
            "2026-11-11T09:00:00Z",
            "2026-02-30T00:00:00Z",
            "https://a.example",
            "urn:x",
            "*",
            "home",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "é\u{0}",
            "write",
            "raw",
            "webauthn",
            "sign",
            "approve"
        ])),
        6 => json!("A".repeat(r.below(200) as usize)),
        7 => Value::Array((0..r.below(5)).map(|_| rand_value(r, d - 1)).collect()),
        _ => {
            let mut m = Map::new();
            for _ in 0..r.below(4) {
                m.insert(
                    r.pick(&["a", "eq", "all", "not", "in", "lte", "x"])
                        .to_string(),
                    rand_value(r, d - 1),
                );
            }
            Value::Object(m)
        }
    }
}
fn mutate(r: &mut Rng, v: &mut Value, depth: u32) {
    match v {
        Value::Object(m) if !m.is_empty() && depth < 6 => {
            let keys: Vec<String> = m.keys().cloned().collect();
            let k = r.pick(&keys).clone();
            match r.below(5) {
                0 => {
                    m.remove(&k);
                }
                1 => {
                    m.insert(k, rand_value(r, 3));
                }
                2 => {
                    m.insert("future".into(), rand_value(r, 2));
                }
                _ => mutate(r, m.get_mut(&k).unwrap(), depth + 1),
            }
        }
        Value::Array(a) if !a.is_empty() && depth < 6 => {
            let i = r.below(a.len() as u64) as usize;
            match r.below(4) {
                0 => {
                    a.remove(i);
                }
                1 => a.push(rand_value(r, 2)),
                2 => {
                    let x = a[i].clone();
                    a.push(x);
                }
                _ => mutate(r, &mut a[i], depth + 1),
            }
        }
        _ => *v = rand_value(r, 3),
    }
}
fn pt(seed: u8) -> String {
    let k = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    STANDARD.encode(k.verifying_key().to_encoded_point(false).as_bytes())
}
fn env(body: &Value) -> Vec<u8> {
    let b = colophon_core::v05::encoding::canonical(body).unwrap_or_default();
    serde_json::to_vec(&json!({"body":STANDARD.encode(&b),"signature":STANDARD.encode([1u8; 64])}))
        .unwrap()
}

#[test]
fn no_panics_anywhere() {
    let acct = "e51f0474f5b30d7b31fb52483d8da5ea7d8208515871b12644bd5c37b7baddca";
    let terms = json!({"records":[{"namespace":"notes","access":"propose","kinds":["a"]}],"services":[{"audience":"https://s.example/x","purposes":["p"]}],"expires":"2026-11-18T09:00:00Z","writes":5,"depth":1,"conditions":[{"lte":["args.n",5]},{"all":[{"not":{"eq":["a",1]}},{"in":["b",[1,"x"]]},{"prefix":["c","d"]}]}],"serves":["home"]});
    let ctrl = json!({"key":{"form":"webauthn","signing":pt(1),"rp":"id.example","credential":"AQ==","origins":["android:x"],"authorityOrigins":["android:x","https://id.example"]},"label":"x","roles":["approve","control"],"verification":true,"holder":"h"});
    let policy = json!({"callWindow":300,"headMaxAge":300,"headQuorum":1,"history":"members","linkMaxAge":86400,"memberRule":"single","recoveryDelay":259200,"primaryHome":"00000000000000000000000000000000"});
    let link = json!({"protocol":"colophon/link/5","account":acct,"from":"00000000000000000000000000000000","to":{"signing":pt(2)},"session":0,"terms":{"services":[{"audience":"https://s.example/x","purposes":["p"]}]},"notBefore":"2026-11-11T09:00:00Z","expires":"2026-11-11T09:10:00Z","created":"2026-11-11T09:00:00Z"});
    let call = json!({"protocol":"colophon/call/5","account":acct,"asOf":{"seq":3,"digest":acct},"signer":{"member":"00000000000000000000000000000000"},"key":pt(2),"links":[STANDARD.encode(env(&link))],"audience":"https://s.example/x","purpose":"p","args":{"n":1},"requestId":"u_GHaCYSyc5qBSlBsxLnLttpRm6KlvjgtpZJ39YbY9g","created":"2026-11-11T09:01:00Z"});
    let header = json!({"protocol":"colophon/operation/5","account":acct,"namespace":"notes","author":"00000000000000000000000000000000","epoch":1,"id":"00000000000000000000000000000000","clock":7,"authority":3,"created":"2026-11-11T12:00:00Z","level":"write","previous":null,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA==","live":{"account":acct,"slot":"s","generation":1,"operationID":"00000000000000000000000000000000"}});
    let request = json!({"protocol":"colophon/request/5","account":acct,"member":{"signing":pt(3),"agreement":pt(4)},"label":"x","kind":"agent","terms":{"services":[{"audience":"https://s.example/x","purposes":["p"]}],"serves":["home"]},"created":"2026-11-11T09:00:00Z","custody":"custodial","operator":"o","service":{"endpoints":["https://h.example"]}});
    let head = json!({"protocol":"colophon/head/5","account":acct,"authority":{"seq":1,"digest":acct},"issued":"2026-11-11T09:00:00Z","by":"00000000000000000000000000000000"});
    let revoke = json!({"member":"00000000000000000000000000000000","kept":[acct],"heads":[{"namespace":"n","digest":acct}],"epochs":[{"namespace":"n","epoch":1,"seals":{"00000000000000000000000000000000":{"enc":pt(5),"ciphertext":STANDARD.encode([0u8;48])}}}]});
    let reference = json!({"account":acct,"hints":["https://h.example/x"]});
    let auth_hdr = json!({"protocol":"colophon/authority/5","seq":2,"previous":acct,"issued":"2026-11-11T09:00:00Z","by":"00000000000000000000000000000000","kind":"grant"});
    let account = AccountId::parse(acct).unwrap();
    let history = vec![acct.to_string()];
    let homes = vec![(
        "00000000000000000000000000000000".to_string(),
        vec![4u8; 65],
    )];
    let mut r = Rng(0xFA11);
    let mut panics = Vec::new();
    let mut n = 0u64;
    for i in 0..60_000u64 {
        let which = i % 11;
        let mut v = [
            &terms,
            &ctrl,
            &policy,
            &call,
            &header,
            &request,
            &head,
            &revoke,
            &reference,
            &auth_hdr,
            &ctrl["key"],
        ][which as usize]
            .clone();
        for _ in 0..1 + r.below(4) {
            mutate(&mut r, &mut v, 0);
        }
        n += 1;
        let res = catch_unwind(AssertUnwindSafe(|| {
            match which {
                0 => {
                    let _ = Terms::parse(v.clone(), TermsKind::Member).map(|t| {
                        (
                            t.conditions_hold(&json!({"n":1,"a":{"b":[1]}})),
                            t.covered_by(&t),
                            t.narrows(&t),
                        )
                    });
                    let _ = Terms::parse(v.clone(), TermsKind::Link);
                }
                1 => drop(Controller::parse(v.clone(), "c")),
                2 => drop(Policy::parse(v.clone(), "p").map(|p| p.check_homes(&[]))),
                3 => drop(Call::parse(&env(&v))),
                4 => drop(
                    OperationHeader::parse(&env(&v)).map(|(h, _)| (h.aad(), h.open(&[0u8; 32]))),
                ),
                5 => drop(Request::parse(&env(&v), r.chance(1, 2))),
                6 => drop(verify_head(
                    &env(&v),
                    HeadContext {
                        account: &account,
                        history: &history,
                        homes: &homes,
                        now_ms: 0,
                    },
                )),
                7 => drop(
                    colophon_core::v05::encoding::Obj::new(v.clone(), "").and_then(Revoke::parse),
                ),
                8 => drop(Reference::parse(v.clone())),
                9 => drop(AuthorityHeader::split(v.clone())),
                _ => drop(KeyDescriptor::parse(v.clone(), "k")),
            }
            let _ = RawEnvelope::parse(&env(&v), 1 << 20, r.chance(1, 2));
        }));
        if res.is_err() && panics.len() < 10 {
            panics.push(format!("parser {which}: {v}"));
        }
    }
    // Raw byte garbage into the envelope parsers.
    for _ in 0..40_000 {
        let len = r.below(300) as usize;
        let mut b = r.bytes(len);
        if r.chance(1, 2) {
            b = env(&call);
            let k = r.below(b.len() as u64) as usize;
            b[k] = r.next() as u8;
        }
        n += 1;
        let res = catch_unwind(AssertUnwindSafe(|| {
            let _ = Call::parse(&b);
            let _ = OperationHeader::parse(&b);
            let _ = Request::parse(&b, true);
        }));
        if res.is_err() && panics.len() < 10 {
            panics.push(format!("bytes: {b:?}"));
        }
    }
    println!("panic fuzz: {n} inputs, panics {}", panics.len());
    for p in &panics {
        println!("  {p}");
    }
    assert!(panics.is_empty());
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
