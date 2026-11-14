//! Revision 8 and later: pending transitions with veto (spec §8.4, §8.6, §8.7, §13, §15),
//! the rows of changes §H, and Swift succession (`rules_v8.py`).
//!
//! New-vault slots and `previousVault` seals are structurally valid synthetic bytes: verifiers
//! can't open them (§8.3), and these vectors don't.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::type_complexity
)]
use crate::cases_a::P_PIN;
use crate::kit::*;
use crate::swift::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const D: i64 = 259200; // recoveryDelay default, seconds
const W: i64 = 300; // receipt window, seconds
const R0: i64 = 3600;
const DUE0: i64 = R0 + W + D; // due time of a transition issued at R0
const DL0: i64 = R0 + D; // its veto deadline

macro_rules! slots {
    ($(($k:expr, $l:expr)),* $(,)?) => { &[$((&$k as &dyn Signer, $l)),*] };
}

fn anchor(chain: &Chain) -> Value {
    json!({"seq": chain.envs.len(), "digest": sha(&body_of(chain.envs.last().unwrap()))})
}

#[derive(Default, Clone)]
struct TOpt<'a> {
    adds: Sl<'a>,
    origin: Option<&'a str>,
    signers_field: Option<Vec<String>>,
}

fn transition(chain: &Chain, change: Value, signers: Sl, issued: &str, t: TOpt) -> Value {
    let (primary, cos) = signers.split_first().unwrap();
    let body = json!({"protocol": "colophon/transition/5", "account": account_id(chain), "anchor": anchor(chain), "issued": issued,
                      "by": primary.id(), "signers": t.signers_field.unwrap_or_else(|| ids_sorted(signers)), "change": change});
    seal(
        &body,
        *primary,
        Opt {
            cos,
            adds: t.adds,
            origin: t.origin,
            handover: &[],
        },
    )
}

fn receipt_of(acct: &str, env: &Value, home: &Key, received: &str) -> Value {
    envelope(
        &json!({"protocol": "colophon/receipt/5", "account": acct, "object": sha(&body_of(env)), "received": received, "by": home.id}),
        home,
    )
}

fn veto_of(
    acct: &str,
    t_env: &Value,
    signers: Sl,
    issued: &str,
    origin: Option<&str>,
    flags: u8,
) -> Value {
    let (primary, cos) = signers.split_first().unwrap();
    let body = json!({"protocol": "colophon/veto/5", "account": acct, "transition": sha(&body_of(t_env)), "issued": issued,
                      "by": primary.id(), "signers": ids_sorted(signers)});
    if primary.is_authenticator() && flags != 0x05 {
        let b = canonical(&body);
        let origin = origin
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://{}", primary.descriptor()["rp"].as_str().unwrap()));
        let (der, asr) = primary.webauthn_sign(&b, &origin, flags);
        return json!({"body": b64(&b), "signature": b64(&der), "assertion": asr});
    }
    seal(
        &body,
        *primary,
        Opt {
            cos,
            origin,
            ..Opt::default()
        },
    )
}
fn veto(acct: &str, t_env: &Value, signers: Sl, issued: &str) -> Value {
    veto_of(acct, t_env, signers, issued, None, 0x05)
}

fn received_of(r: &Value) -> i64 {
    secs(&fstr(r, "received"))
}
fn t_issued(t: &Value) -> i64 {
    secs(&fstr(t, "issued"))
}

/// §8.7: issued + 300 s + delay; a full set at its latest chosen receipt; with no home, issued.
fn due_of(t: &Value, rs: &[Value], full: bool) -> i64 {
    if rs.is_empty() {
        t_issued(t)
    } else if full {
        rs.iter().map(received_of).max().unwrap()
    } else {
        t_issued(t) + W + D
    }
}

/// §8.7 "Choosing receipts": lowest home IDs, per home the lowest body digest, sorted by home.
fn choose(receipts: &[Value], quorum: usize) -> Vec<Value> {
    let mut best: BTreeMap<String, Value> = BTreeMap::new();
    for r in receipts {
        let h = fstr(r, "by");
        let better = match best.get(&h) {
            None => true,
            Some(cur) => sha(&body_of(r)) < sha(&body_of(cur)),
        };
        if better {
            best.insert(h, r.clone());
        }
    }
    best.into_values().take(quorum).collect()
}

fn append_unsigned(
    chain: &mut Chain,
    kind: &str,
    by_id: &str,
    issued: &str,
    fields: Value,
) -> Value {
    let mut body = json!({"protocol": "colophon/authority/5", "seq": chain.envs.len() + 1, "previous": sha(&chain.last()),
                          "issued": issued, "by": by_id, "kind": kind});
    for (k, v) in fields.as_object().unwrap() {
        body[k] = v.clone();
    }
    let env = json!({"body": b64(&canonical(&body))});
    chain.envs.push(env.clone());
    env
}

fn prev_issued(chain: &Chain) -> i64 {
    secs(
        body_json(chain.envs.last().unwrap())["issued"]
            .as_str()
            .unwrap(),
    )
}

fn embs(v: &[Value]) -> Vec<String> {
    v.iter().map(emb).collect()
}

/// Determined body: by = transition's by, issued = max(due, previous issued), chosen receipts.
fn activate_x(
    chain: &mut Chain,
    t: &Value,
    receipts: &[Value],
    full: bool,
    quorum: usize,
) -> Value {
    let rs = choose(receipts, quorum);
    let issued = ts(std::cmp::max(due_of(t, &rs, full), prev_issued(chain)));
    append_unsigned(
        chain,
        "activate",
        &fstr(t, "by"),
        &issued,
        json!({"transition": emb(t), "receipts": embs(&rs)}),
    )
}
fn activate(chain: &mut Chain, t: &Value, receipts: &[Value]) -> Value {
    activate_x(chain, t, receipts, false, 1)
}
fn activate_full(chain: &mut Chain, t: &Value, receipts: &[Value]) -> Value {
    activate_x(chain, t, receipts, true, 1)
}

fn record_veto_q(
    chain: &mut Chain,
    t: &Value,
    t_receipts: &[Value],
    v: &Value,
    receipts: &[Value],
    quorum: usize,
) -> Value {
    let rs = choose(receipts, quorum);
    let trs = choose(t_receipts, quorum);
    let issued = ts(std::cmp::max(
        rs.iter().map(received_of).max().unwrap(),
        prev_issued(chain),
    ));
    append_unsigned(
        chain,
        "vetoed",
        &fstr(v, "by"),
        &issued,
        json!({"transition": emb(t), "transitionReceipts": embs(&trs), "veto": emb(v), "receipts": embs(&rs)}),
    )
}
fn record_veto(
    chain: &mut Chain,
    t: &Value,
    t_receipts: &[Value],
    v: &Value,
    receipts: &[Value],
) -> Value {
    record_veto_q(chain, t, t_receipts, v, receipts, 1)
}

/// §8.7 `final`: by = the activation's by; heads sorted by home; issued = max(latest head, previous).
fn final_of(chain: &mut Chain, act_seq: usize, heads: Vec<Value>) -> Value {
    let act = body_json(&chain.envs[act_seq - 1]);
    let mut hs = heads;
    hs.sort_by_key(|h| fstr(h, "by"));
    let issued = ts(std::cmp::max(
        hs.iter().map(|h| secs(&fstr(h, "issued"))).max().unwrap(),
        prev_issued(chain),
    ));
    let digest = sha(&body_of(&chain.envs[act_seq - 1]));
    append_unsigned(
        chain,
        "final",
        act["by"].as_str().unwrap(),
        &issued,
        json!({"activation": {"seq": act_seq, "digest": digest}, "heads": embs(&hs)}),
    )
}

fn suspend(
    chain: &mut Chain,
    signer: &Key,
    key: &Key,
    t: &Value,
    receipts: &[Value],
    at: i64,
) -> Value {
    chain.add(
        "suspend",
        signer,
        &ts(at),
        signer,
        Opt::default(),
        json!({"key": key.id, "transition": emb(t), "receipts": embs(&choose(receipts, 1))}),
    )
}

fn new_vault(name: &str) -> Value {
    json!({"agreement": b64(&derived(&format!("r6/{name}/vault/agreement")).point),
           "signing": b64(&derived(&format!("r6/{name}/vault/signing")).point)})
}
fn synth48(label: &str) -> Vec<u8> {
    let mut v = sha_raw(label.as_bytes());
    v.extend_from_slice(&sha_raw(format!("{label}/2").as_bytes())[..16]);
    v
}
fn sealed_slot(name: &str, k: &dyn Signer, label: &str) -> Value {
    let id = k.id();
    json!({"kind": "sealed", "controllers": [id], "label": label,
           "sealed": {"enc": b64(&derived(&format!("r6/{name}/slot/{id}/enc")).point),
                      "ciphertext": b64(&synth48(&format!("r6/{name}/slot/{id}")))}})
}
fn vault_change_p(name: &str, slot_keys: &[(&dyn Signer, &str)], previous: bool) -> Value {
    let mut comp = json!({"vault": new_vault(name), "slots": slot_keys.iter().map(|(k, l)| sealed_slot(name, *k, l)).collect::<Vec<_>>()});
    if previous {
        comp["previousVault"] = json!({"enc": b64(&derived(&format!("r6/{name}/previous/enc")).point),
                                       "ciphertext": b64(&synth48(&format!("r6/{name}/previous")))});
    }
    comp
}
fn vault_change(name: &str, slot_keys: &[(&dyn Signer, &str)]) -> Value {
    vault_change_p(name, slot_keys, true)
}

fn home_appointment(acct: &str, home_k: &Key, home_a: &Key, label: &str) -> Value {
    let req = request(
        acct,
        home_k,
        home_a,
        "server",
        json!({"serves": ["home"]}),
        label,
        Some(
            json!({"endpoints": [format!("https://{}.example/v1/accounts/{acct}", label.to_lowercase().replace(' ', ""))]}),
        ),
    );
    json!({"request": req, "terms": {"serves": ["home"]}})
}

fn ver(at: i64) -> Value {
    json!({"now": ts(at)})
}
fn with(v: &Value, extra: &[(&str, Value)]) -> Value {
    let mut v = v.clone();
    for (k, x) in extra {
        v[*k] = x.clone();
    }
    v
}

type Objs<'a> = Vec<(&'a str, Value)>;
type Branches<'a> = Vec<(&'a str, Vec<(i64, Value)>)>;

fn case(
    o: &mut Out,
    name: &str,
    chain: &Chain,
    expected: Value,
    why: &str,
    sections: &[&str],
    objs: Objs,
    verifier: Option<Value>,
    branches: Branches,
) {
    let extra = objs
        .into_iter()
        .map(|(n, v)| (format!("objects/{n}.json"), v))
        .collect();
    write_case(
        o,
        name,
        chain,
        expected,
        why,
        sections,
        extra,
        verifier,
        branches
            .into_iter()
            .map(|(l, v)| (l.to_string(), v))
            .collect(),
    );
}
fn case_v(
    o: &mut Out,
    name: &str,
    chain: &Chain,
    expected: Value,
    why: &str,
    sections: &[&str],
    verifier: Option<Value>,
) {
    case(
        o,
        name,
        chain,
        expected,
        why,
        sections,
        vec![],
        verifier,
        vec![],
    );
}

struct Cx {
    base: Chain,
    acct: String,
    h1k: Key,
}

struct Pr<'a> {
    at: i64,
    chain: Option<&'a Chain>,
    adds: Sl<'a>,
    sf: Option<Vec<String>>,
}
impl Default for Pr<'_> {
    fn default() -> Self {
        Pr {
            at: R0,
            chain: None,
            adds: &[],
            sf: None,
        }
    }
}
fn prop(cx: &Cx, change: Value, signers: Sl, p: Pr) -> Value {
    transition(
        p.chain.unwrap_or(&cx.base),
        change,
        signers,
        &ts(p.at),
        TOpt {
            adds: p.adds,
            origin: None,
            signers_field: p.sf,
        },
    )
}
fn p(cx: &Cx, change: Value, signers: Sl) -> Value {
    prop(cx, change, signers, Pr::default())
}
fn pat(cx: &Cx, change: Value, signers: Sl, at: i64) -> Value {
    prop(
        cx,
        change,
        signers,
        Pr {
            at,
            ..Pr::default()
        },
    )
}
fn rec(cx: &Cx, t: &Value) -> Value {
    receipt_of(&cx.acct, t, &cx.h1k, &ts(R0 + 1))
}
fn rec_at(cx: &Cx, t: &Value, at: i64) -> Value {
    receipt_of(&cx.acct, t, &cx.h1k, &ts(at))
}
fn rec_h(cx: &Cx, t: &Value, home: &Key) -> Value {
    receipt_of(&cx.acct, t, home, &ts(R0 + 1))
}

fn head5(chain: &Chain, home: &Key, at: i64, seq: Option<usize>) -> Value {
    let s = seq.unwrap_or(chain.envs.len());
    envelope(
        &json!({"protocol": "colophon/head/5", "account": account_id(chain),
                     "authority": {"seq": s, "digest": sha(&body_of(&chain.envs[s - 1]))}, "issued": ts(at), "by": home.id}),
        home,
    )
}

fn call_on(
    chain: &Chain,
    signer: &Key,
    rid: &str,
    purpose: &str,
    audience: &str,
    created: i64,
) -> Value {
    let body = json!({"protocol": "colophon/call/5", "account": account_id(chain), "asOf": anchor(chain),
                      "signer": {"controller": signer.id}, "key": b64(&signer.point), "audience": audience, "purpose": purpose,
                      "args": {"nonce": rid}, "requestId": b64url(&sha_raw(format!("r5/{rid}").as_bytes())), "created": ts(created)});
    seal(&body, signer, Opt::default())
}

fn ct(k: &dyn Signer, roles: &[&str], label: &str) -> Value {
    ctrl(k, roles, Some(label), json!({}))
}
fn cx_(k: &dyn Signer, roles: &[&str], label: &str, extra: Value) -> Value {
    ctrl(k, roles, Some(label), extra)
}
const AC: &[&str] = &["approve", "control"];

fn add_ctrl(kr: &Value, extra: Vec<Value>) -> Vec<Value> {
    let mut v = kr["controllers"].as_array().unwrap().clone();
    v.extend(extra);
    v
}
fn without(kr: &Value, id: &str) -> Vec<Value> {
    kr["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| cid(x) != id)
        .cloned()
        .collect()
}
fn kr_with_ctrls(kr: &Value, controllers: Vec<Value>) -> Value {
    change(kr, &[("controllers", json!(controllers))])
}

pub fn part3(o: &mut Out) {
    let (a, b, k1, k2, mk) = (A.clone(), B.clone(), K1.clone(), K2.clone(), MK.clone());
    let nk = NK.clone();
    let h1k = derived("r4/home1/signing");
    let h1a = derived("r4/home1/agreement");
    let h2k = derived("r4/home2/signing");
    let h2a = derived("r4/home2/agreement");
    let p_key = derived("r4/passkey");
    let new = derived("r4/new-device");
    let appr = derived("r6/approve-only");
    let x = derived("r6/thief-x");
    let ph = derived("r5/phone").with_agreement(derived("r5/phone/agreement").point);
    let p_pin: &Authenticator = &P_PIN;

    // Base account (reference person): Mac device key A (the only slot), phone key Ph, passkey B,
    // security keys K1 and K2 (recover only, no slots), thresholds 1, homes H1 and H2 at quorum 1.
    let kr5 = keyring(
        vec![
            ct(&a, AC, "Mac"),
            ct(&ph, AC, "Phone"),
            ct(&b, AC, "Passkey"),
            ct(&k1, &["recover"], "Security key 1"),
            ct(&k2, &["recover"], "Security key 2"),
        ],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let mut base0 = Chain::new();
    genesis(
        &mut base0,
        &kr5,
        sg![a],
        Gen {
            opt: Opt {
                adds: sg![ph, b, k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let acct = account_id(&base0);
    let t_homes = transition(
        &base0,
        json!({"homes": {"appoint": [home_appointment(&acct, &h1k, &h1a, "Home one"),
                                                                   home_appointment(&acct, &h2k, &h2a, "Home two")]}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut base0, &t_homes, &[]); // no home before it: due when issued, final at once
    let cx = Cx {
        base: base0,
        acct: acct.clone(),
        h1k: h1k.clone(),
    };
    let base = &cx.base;
    let rm = |id: &str| json!({"keyring": {"remove": [id]}});

    // 1. Due time, determined activation, early, expired, identical and differing bytes.
    let t1 = p(&cx, rm(&b.id), sg![a]);
    let r1 = rec(&cx, &t1);
    let r1b = receipt_of(&acct, &t1, &h2k, &ts(R0 + 2));
    let mut c = base.clone();
    activate(&mut c, &t1, std::slice::from_ref(&r1));
    let tr1 = || vec![("transition", t1.clone()), ("receipt", r1.clone())];
    case(
        o,
        "t-remove-after-delay",
        &c,
        ok_at(3),
        "Pending removal, receipted, activated at issued + 300 s + D (determined bytes).",
        &["8.7"],
        tr1(),
        Some(ver(DUE0 + 60)),
        vec![],
    );
    case(
        o,
        "t-activate-early",
        &c,
        json!({"result": "held", "seq": 3}),
        "The same entry while the verifier's clock is before the due time.",
        &["8.5", "8.7"],
        tr1(),
        Some(ver(DUE0 - 60)),
        vec![],
    );
    let c_act1 = c.clone();
    let mut cx2 = base.clone();
    grant_agent(&mut cx2, &a, &ts(DUE0 + 8 * 86400), &a);
    activate(&mut cx2, &t1, std::slice::from_ref(&r1));
    case(
        o,
        "t-activate-expired",
        &cx2,
        bad("malformed", 4),
        "Its determined issued would be 8 days after the due time.",
        &["8.7"],
        tr1(),
        Some(ver(DUE0 + 9 * 86400)),
        vec![],
    );
    let mut c1 = base.clone();
    activate(&mut c1, &t1, &[r1.clone(), r1b.clone()]);
    let mut c2 = base.clone();
    activate(&mut c2, &t1, &[r1b.clone(), r1.clone()]);
    assert_eq!(
        env_bytes(c1.envs.last().unwrap()),
        env_bytes(c2.envs.last().unwrap())
    );
    write(
        o,
        "rules/t-activate-identical-bytes/home-1.json",
        c1.envs.last().unwrap(),
    );
    write(
        o,
        "rules/t-activate-identical-bytes/home-2.json",
        c2.envs.last().unwrap(),
    );
    write(
        o,
        "rules/t-activate-identical-bytes/case.json",
        &json!({"description": "Two homes holding both receipts build the activation independently.",
        "sections": ["8.7"], "expected": {"identical": true}}),
    );
    let mut c3 = base.clone();
    activate(&mut c3, &t1, std::slice::from_ref(&r1b));
    let mut pair = [
        c_act1.envs.last().unwrap().clone(),
        c3.envs.last().unwrap().clone(),
    ];
    pair.sort_by_key(|e| sha(&body_of(e)));
    let (lo, hi) = (pair[0].clone(), pair[1].clone());
    case(o, "t-activate-differing-receipts", base, json!({"standsAtSeq3": sha(&body_of(&lo)), "other": "rebuilt or dropped; effects identical"}),
         "Each home held only its own receipt: two activations of one transition at seq 3. The lower body digest stands.",
         &["8.6", "8.7"], vec![("transition", t1.clone())], Some(ver(DUE0 + 60)), vec![("low", vec![(3, lo)]), ("high", vec![(3, hi)])]);
    let mut c = base.clone();
    activate(&mut c, &t1, std::slice::from_ref(&r1));
    activate(&mut c, &t1, std::slice::from_ref(&r1));
    case_v(
        o,
        "t-activate-reappended",
        &c,
        bad("malformed", 4),
        "The same activation appended again later.",
        &["8.7"],
        Some(ver(DUE0 + 60)),
    );
    let mut c = base.clone();
    c.add(
        "keyring",
        &a,
        &ts(R0),
        &a,
        Opt::default(),
        json!({"keyring": kr_with_ctrls(&kr5, without(&kr5, &b.id))}),
    );
    case_v(
        o,
        "i-removal-as-immediate",
        &c,
        bad("malformed", 3),
        "A removal written as an immediate entry.",
        &["8.4"],
        None,
    );

    // 2. Evaluation point (§8.7).
    let mut pre = Chain::new();
    pre.envs = base.envs[..1].to_vec();
    let t_pre = transition(&pre, rm(&b.id), sg![a], &ts(R0), TOpt::default());
    let mut c = base.clone();
    activate(&mut c, &t_pre, &[]);
    case(o, "t-anchor-before-first-home", &c, bad("malformed", 3),
         "A control-only removal anchored at seq 1 (no home then) with no receipts: before the activate the account has homes, so it needs receipts (would be ok if judged at the anchor).",
         &["8.7"], vec![("transition", t_pre.clone())], None, vec![]);
    let t_rv = p(&cx, json!({"homes": {"revoke": [h2k.id]}}), sg![a, k1]);
    let mut c = base.clone();
    activate(&mut c, &t_rv, &[rec(&cx, &t_rv)]);
    let t_by2 = prop(
        &cx,
        rm(&b.id),
        sg![a],
        Pr {
            at: DUE0 + 120,
            chain: Some(&c),
            ..Pr::default()
        },
    );
    let mut c3 = c.clone();
    activate(
        &mut c3,
        &t_by2,
        &[receipt_of(&acct, &t_by2, &h2k, &ts(DUE0 + 121))],
    );
    case_v(o, "t-receipt-by-revoked-home", &c3, ok_at(4), "H2 remains current for receipts until its control-rule revocation is final; no final is held.",
           &["8.5", "8.7", "13.5"], Some(ver(DUE0 + 120 + W + D + 60)));
    let mut side = base.clone();
    grant_agent(&mut side, &a, &ts(R0 - 100), &a);
    let t_off = prop(
        &cx,
        rm(&b.id),
        sg![a],
        Pr {
            chain: Some(&side),
            ..Pr::default()
        },
    );
    let mut main = base.clone();
    let agent2 = derived("r6/agent2");
    grant_agent_with(
        &mut main,
        &ph,
        &ts(R0 - 50),
        &ph,
        &agent2,
        &derived("r6/agent2/agreement"),
        "2026-11-18T08:00:00Z",
    );
    activate(&mut main, &t_off, &[rec(&cx, &t_off)]);
    case(
        o,
        "t-anchor-off-branch",
        &main,
        bad("malformed", 4),
        "Anchored on a seq-3 entry this branch doesn't have.",
        &["8.7"],
        vec![("transition", t_off.clone())],
        Some(ver(DUE0 + 60)),
        vec![],
    );
    let t_early = pat(&cx, rm(&b.id), sg![a], 30);
    case(
        o,
        "t-issued-before-anchor",
        base,
        json!({"transition": "malformed"}),
        "issued is earlier than the anchor's.",
        &["8.7"],
        vec![("transition", t_early)],
        None,
        vec![],
    );

    // 3. signers, vetoes.
    let t_bad = prop(
        &cx,
        rm(&b.id),
        sg![a],
        Pr {
            sf: Some(ids_sorted(sg![a, k1])),
            ..Pr::default()
        },
    );
    case(
        o,
        "t-signers-mismatch",
        base,
        json!({"transition": "malformed"}),
        "`signers` names K1, who didn't sign.",
        &["8.7"],
        vec![("transition", t_bad)],
        None,
        vec![],
    );
    let v1 = veto(&acct, &t1, sg![b], &ts(R0 + 600));
    let rv1 = rec_at(&cx, &v1, R0 + 601);
    let mut c = base.clone();
    record_veto(
        &mut c,
        &t1,
        std::slice::from_ref(&r1),
        &v1,
        std::slice::from_ref(&rv1),
    );
    case_v(
        o,
        "t-vetoed-by-target",
        &c,
        ok_at(3),
        "The passkey vetoes its own removal; the entry carries both receipt sets.",
        &["8.7"],
        None,
    );
    let mut c = base.clone();
    record_veto(
        &mut c,
        &t1,
        std::slice::from_ref(&r1),
        &v1,
        std::slice::from_ref(&rv1),
    );
    record_veto(
        &mut c,
        &t1,
        std::slice::from_ref(&r1),
        &v1,
        std::slice::from_ref(&rv1),
    );
    case_v(
        o,
        "t-vetoed-duplicate",
        &c,
        bad("malformed", 4),
        "The same vetoed entry appended again: once only.",
        &["8.7"],
        None,
    );
    let t2 = p(&cx, rm(&k2.id), sg![a, k1]);
    let v2 = veto(&acct, &t2, sg![b], &ts(R0 + 600));
    let mut c = base.clone();
    record_veto(
        &mut c,
        &t2,
        &[rec(&cx, &t2)],
        &v2,
        &[rec_at(&cx, &v2, R0 + 601)],
    );
    case_v(
        o,
        "t-veto-too-few",
        &c,
        bad("malformed", 3),
        "A two-signer transition vetoed by one key.",
        &["8.7"],
        None,
    );
    let v2s = veto(&acct, &t2, sg![k1, b], &ts(R0 + 600));
    let mut c = base.clone();
    record_veto(
        &mut c,
        &t2,
        &[rec(&cx, &t2)],
        &v2s,
        &[rec_at(&cx, &v2s, R0 + 601)],
    );
    case_v(
        o,
        "t-veto-shares-a-unit",
        &c,
        bad("malformed", 3),
        "K1 signed the transition and its veto: vetoing units must be disjoint.",
        &["8.7"],
        None,
    );
    let mut ca = base.clone();
    ca.add("keyring", &a, &ts(R0 - 100), &a, Opt { adds: sg![appr], ..Opt::default() },
           json!({"keyring": kr_with_ctrls(&kr5, add_ctrl(&kr5, vec![ct(&appr, &["approve"], "Tablet")]))}));
    let t_a = prop(
        &cx,
        rm(&b.id),
        sg![a],
        Pr {
            chain: Some(&ca),
            ..Pr::default()
        },
    );
    let v_a = veto(&acct, &t_a, sg![appr], &ts(R0 + 600));
    let mut c = ca.clone();
    record_veto(
        &mut c,
        &t_a,
        &[rec(&cx, &t_a)],
        &v_a,
        &[rec_at(&cx, &v_a, R0 + 601)],
    );
    case_v(
        o,
        "t-veto-by-approve-only",
        &c,
        bad("malformed", 4),
        "An approve-only key can't veto.",
        &["8.7"],
        None,
    );
    let v_late = veto(&acct, &t1, sg![b], &ts(DL0 + 10));
    let mut c = base.clone();
    activate(&mut c, &t1, std::slice::from_ref(&r1));
    case(
        o,
        "t-late-veto",
        &c,
        ok_at(3),
        "A veto received after the deadline (and before the due time) doesn't count.",
        &["8.7"],
        vec![
            ("transition", t1.clone()),
            ("veto", v_late.clone()),
            ("veto-receipt", rec_at(&cx, &v_late, DL0 + 11)),
        ],
        Some(ver(DUE0 + 60)),
        vec![],
    );
    let mut c = base.clone();
    record_veto(
        &mut c,
        &t1,
        std::slice::from_ref(&r1),
        &v_late,
        &[rec_at(&cx, &v_late, DL0 + 11)],
    );
    case_v(
        o,
        "t-vetoed-after-deadline",
        &c,
        bad("malformed", 3),
        "Recording that late veto: its receipt is after the veto deadline.",
        &["8.7"],
        Some(ver(DUE0 + 60)),
    );

    // 4. Ordering at one seq (§8.6 rule 1), finality.
    let mut y_before = base.clone();
    grant_agent(&mut y_before, &a, &ts(R0 + 120), &a);
    let mut x_after = y_before.clone();
    activate(&mut x_after, &t1, std::slice::from_ref(&r1));
    let mut act_first = base.clone();
    activate(&mut act_first, &t1, std::slice::from_ref(&r1));
    case(o, "t-activate-after-covered-entry", &x_after, ok_at(4),
         "An ordinary entry issued before the due time and covered by the primary's head keeps its seq; the activation follows it.",
         &["8.6"], vec![("transition", t1.clone()), ("receipt", r1.clone()), ("head-H1-primary", head5(&y_before, &h1k, R0 + 130, None))],
         Some(ver(DUE0 + 60)), vec![("activate-first", vec![(3, act_first.envs[2].clone())])]);
    // A `final` that does not verify (it lacks H2's head) does not cover the activation (§8.6
    // rule 1): the covered entry still keeps its seq.
    let mut act_first_bad = act_first.clone();
    let hs_bad = vec![head5(&act_first, &h1k, DUE0 + 100, Some(3))];
    final_of(&mut act_first_bad, 3, hs_bad);
    case(o, "t-activate-after-covered-entry-invalid-final", &x_after, ok_at(4),
         "As t-activate-after-covered-entry, with a `final` after the activate on its branch that lacks H2's head. An invalid `final` covers nothing: the covered entry keeps seq 3.",
         &["8.6", "8.7"], vec![("transition", t1.clone()), ("receipt", r1.clone()), ("head-H1-primary", head5(&y_before, &h1k, R0 + 130, None))],
         Some(ver(DUE0 + 60)), vec![("activate-first", vec![(3, act_first_bad.envs[2].clone()), (4, act_first_bad.envs[3].clone())])]);
    let mut bd = base.clone();
    activate(&mut bd, &t1, std::slice::from_ref(&r1));
    let mut y_back = base.clone();
    grant_agent_with(
        &mut y_back,
        &b,
        &ts(DUE0 - 60),
        &b,
        &derived("r7/back"),
        &derived("r7/back/agreement"),
        "2026-11-18T08:00:00Z",
    );
    case(o, "t-backdated-entry-vs-provisional", &bd, ok_at(3),
         "B, whose removal activated, signs a grant at seq 3 dated before the due time. No primary head covers it: the activation stands.",
         &["8.6"], vec![("head-H1", head5(&bd, &h1k, DUE0 + 30, None))], Some(ver(DUE0 + 60)), vec![("backdated", vec![(3, y_back.envs[2].clone())])]);
    let mut c = base.clone();
    record_veto(
        &mut c,
        &t1,
        std::slice::from_ref(&r1),
        &v1,
        std::slice::from_ref(&rv1),
    );
    let mut alt = base.clone();
    activate(&mut alt, &t1, std::slice::from_ref(&r1));
    case(
        o,
        "t-vetoed-beats-activate",
        &c,
        ok_at(3),
        "vetoed and a provisional activate of one transition at seq 3: the veto stands.",
        &["8.6"],
        vec![],
        None,
        vec![("activate", vec![(3, alt.envs[2].clone())])],
    );
    let mut alt_bad = alt.clone();
    let hs_bad = vec![head5(&alt, &h1k, DUE0 + 100, Some(3))];
    final_of(&mut alt_bad, 3, hs_bad);
    case(
        o,
        "t-vetoed-beats-activate-invalid-final",
        &c,
        ok_at(3),
        "As t-vetoed-beats-activate, with a `final` after the activate on its branch that lacks H2's head. An invalid `final` covers nothing: the veto still stands.",
        &["8.6", "8.7"],
        vec![],
        None,
        vec![("activate", vec![(3, alt_bad.envs[2].clone()), (4, alt_bad.envs[3].clone())])],
    );
    let mut fin = base.clone();
    activate(&mut fin, &t1, std::slice::from_ref(&r1));
    let hs = vec![
        head5(&fin, &h1k, DUE0 + 100, Some(3)),
        head5(&fin, &h2k, DUE0 + 100, Some(3)),
    ];
    final_of(&mut fin, 3, hs);
    let v_hid = veto(&acct, &t1, sg![b], &ts(R0 + 600));
    let rv_hid = receipt_of(&acct, &v_hid, &h2k, &ts(R0 + 601));
    let mut vb = base.clone();
    record_veto(
        &mut vb,
        &t1,
        std::slice::from_ref(&r1),
        &v_hid,
        std::slice::from_ref(&rv_hid),
    );
    case(o, "t-vetoed-after-final", &fin, json!({"result": "ok", "seq": 4, "finality": {"3": "final"},
         "vetoed": "changes nothing; equivocation evidence against H2 (veto, receipt, final)"}),
         "seq 4 is the `final` for seq 3; a vetoed for the same transition at seq 3 appears. Same result in any order.",
         &["8.6", "8.7", "13.3"], vec![("veto", v_hid.clone()), ("veto-receipt", rv_hid.clone())], Some(ver(DUE0 + 200)), vec![("vetoed", vec![(3, vb.envs[2].clone())])]);
    let mut yb2 = base.clone();
    grant_agent_with(
        &mut yb2,
        &b,
        &ts(DUE0 - 60),
        &b,
        &derived("r7/back2"),
        &derived("r7/back2/agreement"),
        "2026-11-18T08:00:00Z",
    );
    case(o, "t-final-not-displaced", &fin, json!({"result": "ok", "seq": 4}),
         "Even a primary-covered entry dated before the due time can't displace an activation with a `final`.", &["8.6"],
         vec![("head-H1-primary", head5(&yb2, &h1k, DUE0 - 50, None))], Some(ver(DUE0 + 200)), vec![("covered", vec![(3, yb2.envs[2].clone())])]);
    let add_new = |label: &str| json!({"keyring": {"add": [ct(&new, AC, label)]}});
    let t_addc = prop(
        &cx,
        add_new("New phone"),
        sg![a],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let mut pa = base.clone();
    activate(&mut pa, &t_addc, &[rec(&cx, &t_addc)]);
    grant_agent(&mut pa, &new, &ts(DUE0 + 100), &new);
    case_v(o, "t-provisional-addition-signs", &pa, bad("badSignature", 4),
           "NEW was added by an activation with no `final`: NEW signs nothing, whatever heads the verifier has seen.", &["8.7"],
           Some(with(&ver(DUE0 + 200), &[("statuses", statuses(&new.id, "addedNotFinal"))])));
    let mut pf = base.clone();
    activate(&mut pf, &t_addc, &[rec(&cx, &t_addc)]);
    let hs = vec![
        head5(&pf, &h1k, DUE0 + 50, Some(3)),
        head5(&pf, &h2k, DUE0 + 60, Some(3)),
    ];
    final_of(&mut pf, 3, hs);
    grant_agent(&mut pf, &new, &ts(DUE0 + 100), &new);
    case_v(
        o,
        "t-final-then-addition-signs",
        &pf,
        ok_at(5),
        "With the `final` at seq 4 (heads of H1 and H2), NEW's grant is valid.",
        &["8.7"],
        Some(ver(DUE0 + 200)),
    );
    let mut pm = base.clone();
    activate(&mut pm, &t_addc, &[rec(&cx, &t_addc)]);
    let hs = vec![head5(&pm, &h1k, DUE0 + 50, Some(3))];
    final_of(&mut pm, 3, hs);
    case_v(
        o,
        "t-final-missing-witness",
        &pm,
        bad("malformed", 4),
        "The `final` lacks H2's head.",
        &["8.7"],
        Some(ver(DUE0 + 200)),
    );
    let h3k = derived("r7/home3/signing");
    let h3a = derived("r7/home3/agreement");
    let mut pw = base.clone();
    activate(&mut pw, &t_addc, &[rec(&cx, &t_addc)]);
    let hs = vec![
        head5(&pw, &h1k, DUE0 + 50, Some(3)),
        head5(&pw, &h3k, DUE0 + 60, Some(3)),
    ];
    final_of(&mut pw, 3, hs);
    case_v(
        o,
        "t-final-head-by-non-witness",
        &pw,
        bad("malformed", 4),
        "One head is by a key that was not a home before the activation.",
        &["8.7"],
        Some(ver(DUE0 + 200)),
    );
    let t_add2 = prop(
        &cx,
        json!({"keyring": {"add": [ct(&appr, AC, "Tablet")]}}),
        sg![ph],
        Pr {
            at: R0 + 10,
            adds: sg![appr],
            ..Pr::default()
        },
    );
    let mut po = base.clone();
    activate(&mut po, &t_addc, &[rec(&cx, &t_addc)]);
    activate(&mut po, &t_add2, &[rec_at(&cx, &t_add2, R0 + 11)]);
    let hs = vec![
        head5(&po, &h1k, DUE0 + 50, Some(4)),
        head5(&po, &h2k, DUE0 + 60, Some(4)),
    ];
    final_of(&mut po, 4, hs);
    case_v(
        o,
        "t-final-out-of-order",
        &po,
        bad("malformed", 5),
        "A `final` for seq 4 while seq 3 has none: activations become final in order.",
        &["8.7"],
        Some(ver(DUE0 + 200)),
    );

    // 5. Escalation and the full set.
    let mut vetoed_a = base.clone();
    record_veto(
        &mut vetoed_a,
        &t1,
        std::slice::from_ref(&r1),
        &v1,
        std::slice::from_ref(&rv1),
    );
    let t_alone = prop(
        &cx,
        rm(&b.id),
        sg![a],
        Pr {
            at: R0 + 800,
            chain: Some(&vetoed_a),
            ..Pr::default()
        },
    );
    let mut c = vetoed_a.clone();
    activate(&mut c, &t_alone, &[rec_at(&cx, &t_alone, R0 + 801)]);
    case_v(
        o,
        "t-escalation-alone",
        &c,
        bad("badSignature", 4),
        "v(A)=1: A alone can't propose.",
        &["8.7"],
        Some(ver(R0 + 800 + W + D + 60)),
    );
    let t_two = prop(
        &cx,
        rm(&b.id),
        sg![a, k1],
        Pr {
            at: R0 + 800,
            chain: Some(&vetoed_a),
            ..Pr::default()
        },
    );
    let mut c = vetoed_a.clone();
    activate(&mut c, &t_two, &[rec_at(&cx, &t_two, R0 + 801)]);
    case_v(
        o,
        "t-escalation-two",
        &c,
        ok_at(4),
        "A with K1: accepted; this compliant activation resets v(A) and v(K1).",
        &["8.7"],
        Some(ver(R0 + 800 + W + D + 60)),
    );
    let t_full = prop(
        &cx,
        add_new("New laptop"),
        sg![a, ph, b],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let mut c = base.clone();
    activate_full(&mut c, &t_full, &[rec_at(&cx, &t_full, R0 + 30)]);
    case(
        o,
        "t-full-set-b",
        &c,
        ok_at(3),
        "Every control key signs a control-only change (b): due at its receipt, no veto.",
        &["8.7"],
        vec![("transition", t_full.clone())],
        None,
        vec![],
    );
    let t_full_consent = p(
        &cx,
        json!({"policy": {"recoveryDelay": 86400}}),
        sg![a, ph, b, k1],
    );
    let mut c = base.clone();
    activate(&mut c, &t_full_consent, &[]);
    case(o, "t-full-set-b-missing-recover", &c, bad("malformed", 3),
         "A consent change signed by every control key and one of two recover keys, with `receipts: []`: receipts missing.", &["8.5", "8.7"],
         vec![("transition", t_full_consent.clone())], None, vec![]);
    let t_phone = prop(
        &cx,
        add_new("Thief laptop"),
        sg![ph, b],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let mut c = base.clone();
    activate(&mut c, &t_phone, &[]);
    case(
        o,
        "t-full-set-needs-every-control-key",
        &c,
        bad("malformed", 3),
        "The phone's two keys are not every control key while the Mac key exists.",
        &["8.7"],
        vec![("transition", t_phone.clone())],
        None,
        vec![],
    );

    // 6. Consent, composites, keep, vault changes, immediate classification, void cases.
    let mut k2d: Vec<Value> = kr5["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| cid(x) == k2.id)
        .cloned()
        .collect();
    for x in k2d.iter_mut() {
        x["roles"] = json!(["approve"]);
    }
    let (only_a, a_and_k1): (Sl, Sl) = (sg![a], sg![a, k1]);
    for (name, signers, exp) in [
        (
            "t-demote-recover-no-consent",
            only_a,
            bad("badSignature", 3),
        ),
        ("t-demote-recover-with-consent", a_and_k1, ok_at(3)),
    ] {
        let t = p(&cx, json!({"keyring": {"update": k2d}}), signers);
        let mut c = base.clone();
        activate(&mut c, &t, &[rec(&cx, &t)]);
        case_v(
            o,
            name,
            &c,
            exp,
            "Demoting K2.",
            &["8.4"],
            Some(ver(DUE0 + 60)),
        );
    }
    let t = p(&cx, json!({"keyring": {"threshold": 2}}), sg![a, ph]);
    let mut c = base.clone();
    activate(&mut c, &t, &[rec(&cx, &t)]);
    case_v(
        o,
        "t-raise-threshold-no-consent",
        &c,
        bad("badSignature", 3),
        "Raising threshold without a recover signer.",
        &["8.4"],
        Some(ver(DUE0 + 60)),
    );
    let t = p(
        &cx,
        json!({"keyring": {"remove": [ph.id]}, "policy": {"callWindow": 600}}),
        sg![k1],
    );
    let mut c = base.clone();
    activate(&mut c, &t, &[rec(&cx, &t)]);
    case_v(o, "t-composite-mixed-rules", &c, bad("badSignature", 3),
           "K1 meets the recovery rule for the removal, but raising callWindow allows only the control rule: one rule must serve all components.",
           &["8.7"], Some(ver(DUE0 + 60)));
    let t = p(&cx, json!({"keyring": {"keep": [ph.id, b.id]}}), sg![a, k1]);
    let mut c = base.clone();
    activate(&mut c, &t, &[rec(&cx, &t)]);
    case_v(
        o,
        "t-keep-needs-recovery-rule",
        &c,
        bad("badSignature", 3),
        "`keep` needs the recovery rule.",
        &["8.4", "8.7"],
        Some(ver(DUE0 + 60)),
    );
    let t_vc = p(
        &cx,
        json!({"keyring": {"remove": [ph.id]}, "vault": vault_change("vc", slots![(a, "Mac")])}),
        sg![a],
    );
    let mut c = base.clone();
    activate(&mut c, &t_vc, &[rec(&cx, &t_vc)]);
    case(o, "t-vault-change-previous", &c, ok_at(3),
         "A voluntary vault change with a removal: determined unsigned activate; previousVault reaches the old vault. No namespaces, so no rekey follows.",
         &["8.3", "8.7"], vec![("transition", t_vc.clone())], Some(ver(DUE0 + 60)), vec![]);
    let t_nv = p(&cx, rm(&a.id), sg![ph, b]);
    let mut c = base.clone();
    activate(&mut c, &t_nv, &[rec(&cx, &t_nv)]);
    case_v(o, "t-removal-slotted-without-vault", &c, json!({"result": "ok", "seq": 3, "vault": "retiring", "slots": 0}),
           "Removing the slotted Mac key needs no vault change: its slot is dropped and the vault is retiring.", &["8.3", "8.7"], Some(ver(DUE0 + 60)));
    let t_k1 = p(&cx, rm(&a.id), sg![k1]);
    let mut c_k1 = base.clone();
    activate(&mut c_k1, &t_k1, &[rec(&cx, &t_k1)]);
    case_v(
        o,
        "t-one-recovery-key-removes-slotted",
        &c_k1,
        json!({"result": "ok", "seq": 3, "vault": "retiring"}),
        "One recovery key starts and completes the removal of the slotted Mac key (no veto came).",
        &["8.3", "8.4", "8.7"],
        Some(ver(DUE0 + 60)),
    );
    let mut rot = c_k1.clone();
    rot.add(
        "vault",
        &k1,
        &ts(DUE0 + 120),
        &k1,
        Opt::default(),
        vault_change("rot", slots![(k1, "Security key 1")]),
    );
    case_v(o, "t-vault-rotation", &rot, json!({"result": "ok", "seq": 4, "vault": "not retiring"}),
           "While retiring, one recovery key holding the seed rotates the vault with previousVault and its own slot.", &["8.3", "8.4"], Some(ver(DUE0 + 200)));
    let kr_rot = change(
        &kr5,
        &[
            ("controllers", json!(without(&kr5, &a.id))),
            ("vault", new_vault("rot")),
            ("slots", json!([sealed_slot("rot", &k1, "Security key 1")])),
        ],
    );
    let mut ss = rot.clone();
    let mut slots2 = kr_rot["slots"].as_array().unwrap().clone();
    slots2.push(sealed_slot("rot", &k2, "Security key 2"));
    ss.add(
        "keyring",
        &k2,
        &ts(DUE0 + 300),
        &k2,
        Opt::default(),
        json!({"keyring": with(&kr_rot, &[("slots", json!(slots2))])}),
    );
    case_v(
        o,
        "t-self-slot",
        &ss,
        ok_at(5),
        "K2, recover only, adds its own slot to the new vault by itself.",
        &["8.3", "8.4"],
        Some(ver(DUE0 + 400)),
    );
    let mut c = base.clone();
    c.add(
        "vault",
        &a,
        &ts(R0),
        &a,
        Opt::default(),
        vault_change("rot2", slots![(a, "Mac")]),
    );
    case_v(
        o,
        "t-vault-entry-not-retiring",
        &c,
        bad("badSignature", 3),
        "A `vault` entry while the vault isn't retiring: the rule isn't met.",
        &["8.3", "8.4"],
        None,
    );
    let mut c = base.clone();
    activate(&mut c, &t_k1, &[rec(&cx, &t_k1)]);
    c.add(
        "vault",
        &k1,
        &ts(DUE0 + 120),
        &k1,
        Opt::default(),
        vault_change("rot3", slots![(ph, "Phone")]),
    );
    case_v(
        o,
        "t-vault-entry-without-own-slot",
        &c,
        bad("malformed", 4),
        "The new vault has no slot naming its signer.",
        &["8.3"],
        Some(ver(DUE0 + 200)),
    );
    let mut keep_c = base.clone();
    let t_tx = prop(
        &cx,
        json!({"keyring": {"add": [ct(&x, AC, "Thief X")]}}),
        sg![a, ph, b],
        Pr {
            at: R0 + 100,
            adds: sg![x],
            ..Pr::default()
        },
    );
    let t_keep = prop(
        &cx,
        json!({"keyring": {"keep": [], "add": [ct(&new, AC, "New phone")]},
                                  "vault": vault_change_p("keep", slots![(k1, "Security key 1")], false)}),
        sg![k1, k2],
        Pr {
            at: R0 + 200,
            adds: sg![new],
            ..Pr::default()
        },
    );
    activate_full(&mut keep_c, &t_tx, &[rec_at(&cx, &t_tx, R0 + 101)]);
    activate_full(&mut keep_c, &t_keep, &[rec_at(&cx, &t_keep, R0 + 201)]);
    case(o, "t-keep-removes-unknown-key", &keep_c, json!({"result": "ok", "seq": 4, "controllers": ids_sorted(sg![new, k1, k2])}),
         "A thief with every control key adds X at once (seq 3) after the owner read the history; the owner's full recovery set, anchored at seq 2, keeps no non-recover key, so X goes too.",
         &["8.7", "changes §H"], vec![("thief", t_tx.clone()), ("owner", t_keep.clone())], None, vec![]);
    let relabel: Vec<Value> = kr5["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let mut c = c.clone();
            if cid(&c) == b.id {
                c["label"] = json!("Mike's iPhone");
            }
            c
        })
        .collect();
    let mut c = base.clone();
    c.add(
        "keyring",
        &a,
        &ts(R0),
        &a,
        Opt::default(),
        json!({"keyring": kr_with_ctrls(&kr5, relabel)}),
    );
    case_v(
        o,
        "i-relabel-other",
        &c,
        ok_at(3),
        "Relabelling another key is immediate; hosts show key IDs beside labels.",
        &["6.1", "8.4"],
        None,
    );
    let mut c = base.clone();
    c.add(
        "keyring",
        &a,
        &ts(R0),
        &a,
        Opt::default(),
        json!({"keyring": change(&kr5, &[("policy", json!({"memberRule": "control"}))])}),
    );
    case_v(
        o,
        "i-tighten-policy",
        &c,
        ok_at(3),
        "Tightening memberRule is immediate.",
        &["8.4"],
        None,
    );
    let mut c = base.clone();
    c.add(
        "keyring",
        &a,
        &ts(R0),
        &a,
        Opt::default(),
        json!({"keyring": change(&kr5, &[("policy", json!({"headMaxAge": 3600}))])}),
    );
    case_v(
        o,
        "i-loosen-policy",
        &c,
        bad("malformed", 3),
        "Raising headMaxAge as an immediate entry.",
        &["8.4"],
        None,
    );
    let mut c = base.clone();
    c.add("keyring", &a, &ts(R0), &a, Opt { adds: sg![new], ..Opt::default() },
          json!({"keyring": kr_with_ctrls(&kr5, add_ctrl(&kr5, vec![ct(&new, &["approve"], "Tablet")]))}));
    case_v(
        o,
        "i-add-approve",
        &c,
        ok_at(3),
        "An approve-only key is added immediately.",
        &["8.4"],
        None,
    );
    let five: Vec<Key> = (0..5).map(|i| derived(&format!("r6/five/{i}"))).collect();
    let five_dyn: Vec<&dyn Signer> = five.iter().map(|k| k as &dyn Signer).collect();
    let mut c = base.clone();
    c.add("keyring", &a, &ts(R0), &a, Opt { adds: &five_dyn, ..Opt::default() },
          json!({"keyring": kr_with_ctrls(&kr5, add_ctrl(&kr5, five.iter().enumerate().map(|(i, k)| ct(k, &["approve"], &format!("Tablet {i}"))).collect()))}));
    case_v(
        o,
        "i-add-five-approve",
        &c,
        bad("malformed", 3),
        "An immediate keyring entry adds at most four controllers.",
        &["8.4"],
        None,
    );
    let t_mig = p(
        &cx,
        json!({"migration": {"predecessor": {"format": "colophon/authority/5", "account": "ab".repeat(32),
                                                            "final": {"seq": 2, "digest": "cd".repeat(32)}}, "namespaces": [],
                                            "controllers": [], "members": []}}),
        sg![a, k1],
    );
    let mut c = base.clone();
    activate(&mut c, &t_mig, &[rec(&cx, &t_mig)]);
    case_v(
        o,
        "t-migration-without-predecessor",
        &c,
        bad("malformed", 3),
        "A migration without a predecessor.",
        &["8.4", "15.4"],
        Some(ver(DUE0 + 60)),
    );
    let t_noop = p(&cx, rm(&new.id), sg![a]);
    let mut c = base.clone();
    activate(&mut c, &t_noop, &[rec(&cx, &t_noop)]);
    case_v(
        o,
        "t-noop-void",
        &c,
        bad("malformed", 3),
        "A transition that changes nothing is void.",
        &["8.7"],
        Some(ver(DUE0 + 60)),
    );
    let t_cf = p(
        &cx,
        json!({"keyring": {"add": [ct(&b, &["approve"], "Passkey")]}}),
        sg![a],
    );
    let mut c = base.clone();
    activate(&mut c, &t_cf, &[rec(&cx, &t_cf)]);
    case_v(
        o,
        "t-add-present-different-roles",
        &c,
        bad("malformed", 3),
        "Adding a present key with different roles voids.",
        &["8.7"],
        Some(ver(DUE0 + 60)),
    );
    let t_all = p(
        &cx,
        json!({"keyring": {"remove": [a.id, ph.id, b.id]}, "vault": vault_change_p("all", slots![(k1, "Key")], false)}),
        sg![a, ph, b],
    );
    let mut c = base.clone();
    activate_full(&mut c, &t_all, &[rec(&cx, &t_all)]);
    case_v(
        o,
        "t-breaks-keyring",
        &c,
        bad("malformed", 3),
        "Removing every control key breaks §6.2.",
        &["8.7"],
        None,
    );
    let mut c = base.clone();
    c.add("keyring", &a, &ts(R0), &a, Opt::default(), json!({"keyring": change(&kr5, &[("policy", json!({"rate": {
        "account": {"bytes": 16777216, "entries": 256}, "signer": {"bytes": 4194304, "entries": 128}}}))])}));
    case_v(
        o,
        "i-raise-rate",
        &c,
        bad("malformed", 3),
        "Raising the rate limit as an immediate entry.",
        &["6.3", "8.4"],
        None,
    );

    // 7. Suspension (the removal of the slotted Mac key carries its vault change, so it isn't void).
    let t_s = p(
        &cx,
        json!({"keyring": {"remove": [a.id]}, "vault": vault_change_p("s", slots![(ph, "Phone")], false)}),
        sg![ph, b],
    );
    let r_s = rec(&cx, &t_s);
    let mut c = base.clone();
    suspend(&mut c, &ph, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    case_v(o, "t-suspend", &c, ok_at(3), "A signer of a pending removal suspends its target; the entry carries the transition and receipt.", &["8.7"], None);
    let mut c2 = c.clone();
    grant_agent(&mut c2, &a, &ts(R0 + 120), &a);
    case_v(
        o,
        "t-suspended-immediate-entry",
        &c2,
        bad("badSignature", 4),
        "The suspended key signs a grant.",
        &["8.7"],
        None,
    );
    let t_void = p(
        &cx,
        json!({"keyring": {"remove": [a.id], "update": [ct(&new, &["approve"], "Absent")]}}),
        sg![ph, b],
    );
    let mut c = base.clone();
    suspend(&mut c, &ph, &a, &t_void, &[rec(&cx, &t_void)], R0 + 60);
    case_v(
        o,
        "t-suspend-void-transition",
        &c,
        bad("malformed", 3),
        "A suspension citing a removal that also updates an absent key: void.",
        &["8.7"],
        None,
    );
    let mut c = base.clone();
    suspend(&mut c, &k1, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    case_v(
        o,
        "t-suspend-by-non-signer",
        &c,
        bad("badSignature", 3),
        "K1 didn't sign the transition.",
        &["8.4", "8.7"],
        None,
    );
    let t_s2 = pat(&cx, rm(&b.id), sg![ph], R0 + 30);
    let mut c = base.clone();
    suspend(&mut c, &ph, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    suspend(
        &mut c,
        &ph,
        &b,
        &t_s2,
        &[rec_at(&cx, &t_s2, R0 + 31)],
        R0 + 90,
    );
    case_v(
        o,
        "t-suspend-second-by-unit",
        &c,
        bad("malformed", 4),
        "Ph already has a suspension outstanding.",
        &["8.7"],
        None,
    );
    let v_s = veto(&acct, &t_s, sg![a, k1], &ts(R0 + 300));
    let mut c = base.clone();
    suspend(&mut c, &ph, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    record_veto(
        &mut c,
        &t_s,
        std::slice::from_ref(&r_s),
        &v_s,
        &[rec_at(&cx, &v_s, R0 + 301)],
    );
    let mut c3 = c.clone();
    grant_agent(&mut c3, &a, &ts(R0 + 400), &a);
    case_v(
        o,
        "t-suspension-ends-with-veto",
        &c3,
        ok_at(5),
        "A (suspended) and K1 veto the removal; the suspension ends and A grants again.",
        &["8.7"],
        None,
    );
    let mut c = base.clone();
    suspend(&mut c, &ph, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    grant_agent(&mut c, &ph, &ts(DUE0 + 8 * 86400), &ph);
    grant_agent_with(
        &mut c,
        &a,
        &ts(DUE0 + 8 * 86400 + 60),
        &a,
        &derived("r6/agent3"),
        &derived("r6/agent3/agreement"),
        "2026-11-18T08:00:00Z",
    );
    case_v(
        o,
        "t-suspension-ends-at-expiry",
        &c,
        ok_at(5),
        "No activate came within 7 days of the due time; entry 4 ends the suspension.",
        &["8.7"],
        Some(ver(DUE0 + 9 * 86400)),
    );

    // 8. Rate limit, checked by every verifier (§13.1).
    let mut c = base.clone();
    for i in 0..65 {
        grant_agent_with(
            &mut c,
            &a,
            &ts(R0 + i),
            &a,
            &derived(&format!("r5/rate/{i}")),
            &derived(&format!("r5/rate/{i}/agreement")),
            "2026-11-18T08:00:00Z",
        );
    }
    wc(
        o,
        "i-rate-limit",
        &c,
        bad("malformed", 67),
        "The 65th immediate entry by A within 24 hours.",
        &["13.1"],
    );
    let plant: Vec<Key> = (0..4).map(|i| derived(&format!("r6/plant/{i}"))).collect();
    let plant_dyn: Vec<&dyn Signer> = plant.iter().map(|k| k as &dyn Signer).collect();
    let mut c = base.clone();
    c.add("keyring", &a, &ts(R0), &a, Opt { adds: &plant_dyn, ..Opt::default() },
          json!({"keyring": kr_with_ctrls(&kr5, add_ctrl(&kr5, plant.iter().enumerate().map(|(i, k)| ct(k, &["approve"], &format!("Planted {i}"))).collect()))}));
    for i in 0..59 {
        grant_agent_with(
            &mut c,
            &a,
            &ts(R0 + 1 + i),
            &a,
            &derived(&format!("r6/pa/{i}")),
            &derived(&format!("r6/pa/{i}/agreement")),
            "2026-11-18T08:00:00Z",
        );
    }
    for i in 0..5 {
        grant_agent_with(
            &mut c,
            &plant[0],
            &ts(R0 + 100 + i),
            &plant[0],
            &derived(&format!("r6/pb/{i}")),
            &derived(&format!("r6/pb/{i}/agreement")),
            "2026-11-18T08:00:00Z",
        );
    }
    wc(o, "i-rate-planted-keys", &c, bad("malformed", 67),
       "Entries by a key A planted count against A: the addition, 59 grants by A, then the planted key's 5th grant is A's 65th.", &["13.1"]);
    let kr_rate = keyring(
        vec![
            ct(&a, AC, "Mac"),
            ct(&ph, AC, "Phone"),
            ct(&b, AC, "Passkey"),
        ],
        Kr {
            policy: Some(policy_with(&[(
                "rate",
                json!({"account": {"bytes": 16777216, "entries": 64},
                                                                         "signer": {"bytes": 4194304, "entries": 64}}),
            )])),
            ..Kr::default()
        },
    );
    let mut c = Chain::new();
    genesis(
        &mut c,
        &kr_rate,
        sg![a],
        Gen {
            label: "Rate",
            opt: Opt {
                adds: sg![ph, b],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    for i in 0..32 {
        grant_agent_with(
            &mut c,
            &a,
            &ts(60 + i),
            &a,
            &derived(&format!("r6/ra/{i}")),
            &derived(&format!("r6/ra/{i}/agreement")),
            "2026-11-18T08:00:00Z",
        );
    }
    for i in 0..32 {
        grant_agent_with(
            &mut c,
            &ph,
            &ts(120 + i),
            &ph,
            &derived(&format!("r6/rb/{i}")),
            &derived(&format!("r6/rb/{i}/agreement")),
            "2026-11-18T08:00:00Z",
        );
    }
    c.add(
        "revoke",
        &a,
        &ts(200),
        &a,
        Opt::default(),
        json!({"member": derived("r6/ra/0").id, "kept": [], "heads": [], "epochs": []}),
    );
    grant_agent_with(
        &mut c,
        &b,
        &ts(210),
        &b,
        &derived("r6/rc"),
        &derived("r6/rc/agreement"),
        "2026-11-18T08:00:00Z",
    );
    wc(
        o,
        "i-rate-revoke-outside-account-limit",
        &c,
        json!({"result": "malformed", "seq": 67, "ok": "seq 66, the revoke, counts toward A only"}),
        "Account limit 64: after 64 grants a revoke is still accepted; the next grant is refused.",
        &["13.1"],
    );

    // 9. Calls.
    let svc = "https://service.example";
    let ver_c =
        json!({"now": ts(R0 + 1020), "audiences": [svc], "controllerPurposes": ["sign-in"]});
    let t_add = prop(
        &cx,
        add_new("New phone"),
        sg![k1],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let call = |chain: &Chain, signer: &Key, rid: &str| {
        call_on(chain, signer, rid, "sign-in", svc, R0 + 1010)
    };
    case(
        o,
        "call-by-pending-addition",
        base,
        json!({"call": "refused:revoked"}),
        "NEW's addition is pending.",
        &["8.7", "12.3"],
        vec![
            ("transition", t_add.clone()),
            ("receipt", rec(&cx, &t_add)),
            ("call", call(base, &new, "a")),
            ("head", head5(base, &h1k, R0 + 1000, None)),
        ],
        Some(with(
            &ver_c,
            &[("statuses", statuses(&new.id, "pendingAddition"))],
        )),
        vec![],
    );
    case(
        o,
        "call-by-pending-removal",
        base,
        json!({"call": "ok"}),
        "B's removal is pending: B works until activation.",
        &["8.7", "12.3"],
        vec![
            ("transition", t1.clone()),
            ("receipt", r1.clone()),
            ("call", call(base, &b, "b")),
            ("head", head5(base, &h1k, R0 + 1000, None)),
        ],
        Some(with(
            &ver_c,
            &[("statuses", statuses(&b.id, "pendingRemoval"))],
        )),
        vec![],
    );
    let mut cs = base.clone();
    suspend(&mut cs, &ph, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    case(
        o,
        "call-by-suspended",
        &cs,
        json!({"call": "refused:revoked"}),
        "A is suspended.",
        &["8.7", "12.3"],
        vec![
            ("call", call(&cs, &a, "c")),
            ("head", head5(&cs, &h1k, R0 + 1000, None)),
        ],
        Some(with(&ver_c, &[("statuses", statuses(&a.id, "suspended"))])),
        vec![],
    );
    let home_ep = format!("https://homeone.example/v1/accounts/{acct}");
    let ver_h = json!({"now": ts(R0 + 1020), "audiences": [home_ep], "role": "home"});
    case(
        o,
        "call-recover-history-read",
        base,
        json!({"call": "ok"}),
        "A recover-only key reads the history; a home accepts the purpose without configuration.",
        &["12.3", "13.4"],
        vec![
            (
                "call",
                call_on(base, &k1, "d", "colophon.history.read", &home_ep, R0 + 1010),
            ),
            ("head", head5(base, &h1k, R0 + 1000, None)),
        ],
        Some(ver_h.clone()),
        vec![],
    );
    case(
        o,
        "call-suspended-history-read",
        &cs,
        json!({"call": "ok"}),
        "The suspended key can still read the history, to see what to veto.",
        &["8.7", "12.3", "13.4"],
        vec![
            (
                "call",
                call_on(&cs, &a, "e", "colophon.history.read", &home_ep, R0 + 1010),
            ),
            ("head", head5(&cs, &h1k, R0 + 1000, None)),
        ],
        Some(with(&ver_h, &[("statuses", statuses(&a.id, "suspended"))])),
        vec![],
    );
    let ver_p = with(&ver_c, &[("now", json!(ts(DUE0 + 200)))]);
    let call_late = |chain: &Chain, signer: &Key, rid: &str| {
        call_on(chain, signer, rid, "sign-in", svc, DUE0 + 190)
    };

    let mut pa2 = base.clone();
    activate(&mut pa2, &t_addc, &[rec(&cx, &t_addc)]);
    case(
        o,
        "call-by-provisional-addition",
        &pa2,
        json!({"call": "refused:revoked"}),
        "NEW's addition activated, but H2's head doesn't cover it: provisional, so NEW can't call.",
        &["8.7", "12.3"],
        vec![
            ("call", call_late(&pa2, &new, "f")),
            ("head-H1", head5(&pa2, &h1k, DUE0 + 150, None)),
            ("head-H2", head5(base, &h2k, DUE0 + 150, None)),
        ],
        Some(with(
            &ver_p,
            &[("statuses", statuses(&new.id, "addedNotFinal"))],
        )),
        vec![],
    );
    let mut pf2 = pf.clone();
    pf2.envs = pf.envs[..4].to_vec();
    case(
        o,
        "call-after-final",
        &pf2,
        json!({"call": "ok"}),
        "With the `final` at seq 4, NEW calls.",
        &["8.7", "12.3"],
        vec![
            ("call", call_late(&pf2, &new, "g")),
            ("head-H1", head5(&pf2, &h1k, DUE0 + 150, None)),
            ("head-H2", head5(&pf2, &h2k, DUE0 + 150, None)),
        ],
        Some(ver_p.clone()),
        vec![],
    );
    let mut cse = base.clone();
    suspend(&mut cse, &ph, &a, &t_s, std::slice::from_ref(&r_s), R0 + 60);
    let late = DUE0 + 7 * 86400 + 600;
    case(o, "call-suspension-expired", &cse, json!({"call": "ok"}),
         "No entry after the suspension, but the verifier's clock is past its transition's due time + 7 days: it has ended.", &["8.7", "12.3"],
         vec![("call", call_on(&cse, &a, "h", "sign-in", svc, late - 10)), ("head", head5(&cse, &h1k, late - 30, None))],
         Some(with(&ver_c, &[("now", json!(ts(late)))])), vec![]);

    // 9b. Revision-7 statements without an engine.
    let kr_q = keyring(
        vec![
            ct(&a, AC, "Mac"),
            ct(&ph, AC, "Phone"),
            ct(&k1, &["recover"], "Security key"),
        ],
        Kr {
            threshold: 2,
            rt: 1,
            ..Kr::default()
        },
    );
    let mut q = Chain::new();
    genesis(
        &mut q,
        &kr_q,
        sg![a, ph],
        Gen {
            label: "Threshold two",
            opt: Opt {
                adds: sg![ph, k1],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let aq = account_id(&q);
    let t_hq = transition(
        &q,
        json!({"homes": {"appoint": [home_appointment(&aq, &h1k, &h1a, "Home one")]}}),
        sg![a, ph, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut q, &t_hq, &[]);
    let t_q = transition(
        &q,
        json!({"homes": {"appoint": [home_appointment(&aq, &h2k, &h2a, "Home two")]}}),
        sg![k1],
        &ts(R0),
        TOpt::default(),
    );
    let mut qa = q.clone();
    activate(&mut qa, &t_q, &[receipt_of(&aq, &t_q, &h1k, &ts(R0 + 1))]);
    case_v(o, "t-recovery-rule-appoints-home-low-threshold", &qa, bad("badSignature", 3),
           "recoverThreshold 1 < threshold 2: the recovery rule may revoke homes but not appoint them.", &["8.4"], Some(ver(DUE0 + 60)));
    let mut fs = base.clone();
    grant_agent(&mut fs, &a, &ts(R0 + 100), &a);
    let t_fsb = prop(
        &cx,
        add_new("New laptop"),
        sg![a, ph, b],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    activate_full(&mut fs, &t_fsb, &[rec_at(&cx, &t_fsb, R0 + 200)]);
    case_v(o, "t-full-set-due-from-receipt", &fs, ok_at(4),
           "A full set claims issued R0 but is received at R0 + 200: its due time is the receipt, so the grant at R0 + 100 keeps seq 3.", &["8.6", "8.7"], Some(ver(R0 + 300)));
    let nsv = key_id(&unb64(G4["keyring"]["vault"]["signing"].as_str().unwrap()));
    let epoch_obj = |ns: &str, n: i64, name: &str| {
        let mut seals = serde_json::Map::new();
        seals.insert(nsv.clone(), json!({"enc": b64(&derived(&format!("r7/{name}/enc")).point), "ciphertext": b64(&synth48(&format!("r7/{name}")))}));
        json!({"namespace": ns, "epoch": n, "seals": seals})
    };
    let mut nsc = Chain::new();
    genesis(
        &mut nsc,
        &kr5,
        sg![a],
        Gen {
            label: "Notes",
            namespaces: vec!["notes"],
            opt: Opt {
                adds: sg![ph, b, k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    nsc.add(
        "rekey",
        &a,
        &ts(30),
        &a,
        Opt::default(),
        json!({"epochs": [epoch_obj("notes", 1, "e1")]}),
    );
    nsc.add(
        "rekey",
        &k1,
        &ts(60),
        &k1,
        Opt::default(),
        json!({"epochs": [epoch_obj("notes", 2, "e2")]}),
    );
    case_v(
        o,
        "t-rekey-by-recover-key",
        &nsc,
        ok_at(3),
        "A recover-only key may sign a `rekey` (after a recovery, it may be the only key present).",
        &["8.3", "8.4"],
        None,
    );
    let mut many: Vec<Key> = vec![a.clone()];
    many.extend((1..23).map(|i| derived(&format!("r7/many/{i}")))); // A owns the default genesis slot.
    let kr_m = keyring(
        many.iter()
            .enumerate()
            .map(|(i, k)| ct(k, AC, &format!("Key {i}")))
            .collect(),
        Kr::default(),
    );
    let many_dyn: Vec<&dyn Signer> = many.iter().map(|k| k as &dyn Signer).collect();
    let mut mc = Chain::new();
    genesis(
        &mut mc,
        &kr_m,
        &many_dyn[..1],
        Gen {
            label: "Many",
            opt: Opt {
                adds: &many_dyn[1..],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let am = account_id(&mc);
    let t_mh = transition(
        &mc,
        json!({"homes": {"appoint": [home_appointment(&am, &h1k, &h1a, "Home one")]}}),
        &many_dyn[..1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut mc, &t_mh, &[]);
    let t_m = transition(
        &mc,
        rm(&many[1].id),
        &many_dyn[..1],
        &ts(R0),
        TOpt::default(),
    );
    let v_m = veto(&am, &t_m, &many_dyn[1..], &ts(R0 + 600));
    let vlen = body_of(&v_m).len();
    assert!(1024 < vlen && vlen <= 4096, "{vlen}");
    let mut mcv = mc.clone();
    record_veto(
        &mut mcv,
        &t_m,
        &[receipt_of(&am, &t_m, &h1k, &ts(R0 + 1))],
        &v_m,
        &[receipt_of(&am, &v_m, &h1k, &ts(R0 + 601))],
    );
    case_v(
        o,
        "t-veto-22-signers",
        &mcv,
        ok_at(3),
        &format!("A veto by 22 keys: its body is {vlen} bytes, within the 4,096 bound."),
        &["2.4", "8.7"],
        None,
    );
    let mut fe = base.clone();
    activate(&mut fe, &t_addc, &[rec(&cx, &t_addc)]);
    let t_fe = prop(
        &cx,
        json!({"keyring": {"add": [ct(&appr, AC, "Tablet")]}}),
        sg![k1, k2],
        Pr {
            at: DUE0 + 60,
            chain: Some(&fe),
            adds: sg![appr],
            ..Pr::default()
        },
    );
    activate_full(&mut fe, &t_fe, &[rec_at(&cx, &t_fe, DUE0 + 61)]);
    grant_agent(&mut fe, &new, &ts(DUE0 + 200), &new);
    case_v(o, "t-full-set-finalizes-earlier", &fe, ok_at(5),
           "seq 3 has no `final`; a full set anchored at seq 3 activates at seq 4 and makes seq 3 final, so NEW's grant is valid.", &["8.7"], Some(ver(DUE0 + 300)));
    let app3 = p(
        &cx,
        json!({"homes": {"appoint": [home_appointment(&acct, &h3k, &h3a, "Home three")]}}),
        sg![a, k1],
    );
    let mut hr = base.clone();
    activate(&mut hr, &app3, &[rec(&cx, &app3)]);
    let hs = vec![
        head5(&hr, &h1k, DUE0 + 30, Some(3)),
        head5(&hr, &h2k, DUE0 + 40, Some(3)),
    ];
    final_of(&mut hr, 3, hs);
    let rv1_t = prop(
        &cx,
        json!({"homes": {"revoke": [h1k.id]}}),
        sg![a, k1],
        Pr {
            at: DUE0 + 50,
            chain: Some(&hr),
            ..Pr::default()
        },
    );
    let dr = DUE0 + 50 + W + D;
    activate(
        &mut hr,
        &rv1_t,
        &[receipt_of(&acct, &rv1_t, &h1k, &ts(DUE0 + 51))],
    );
    let hs = vec![
        head5(&hr, &h1k, dr + 10, Some(5)),
        head5(&hr, &h2k, dr + 20, Some(5)),
        head5(&hr, &h3k, dr + 30, Some(5)),
    ];
    final_of(&mut hr, 5, hs);
    let t_hr = prop(
        &cx,
        add_new("New phone"),
        sg![a],
        Pr {
            at: dr + 100,
            chain: Some(&hr),
            adds: sg![new],
            ..Pr::default()
        },
    );
    let d2 = dr + 100 + W + D;
    activate(
        &mut hr,
        &t_hr,
        &[receipt_of(&acct, &t_hr, &h2k, &ts(dr + 101))],
    );
    let hs = vec![
        head5(&hr, &h2k, d2 + 30, Some(7)),
        head5(&hr, &h3k, d2 + 40, Some(7)),
    ];
    final_of(&mut hr, 7, hs);
    grant_agent(&mut hr, &new, &ts(d2 + 100), &new);
    case_v(o, "t-final-survives-home-rotation", &hr, ok_at(9),
           "H3 is appointed (final at 4), then H1 revoked under the control rule, so H1 stays a witness of its own revocation (final at 6 with H1's head); a verifier starting later, which can't accept heads from H1, still finds every activation final.",
           &["8.7", "13.3"], Some(ver(d2 + 200)));
    let mut backdated = base.clone();
    grant_agent(&mut backdated, &a, &ts(R0), &a);
    write_case(
        o,
        "i-rate-dormant-burst",
        base,
        json!({"home": "refuses an immediate entry whose issued is more than 300 s behind its clock",
                      "admission": {"object": "objects/backdated.json", "result": "refused:late", "home": h1k.id}}),
        "A stolen key on a quiet account tries to fill past days in one sitting.",
        &["13.1"],
        vec![(
            "objects/backdated.json".to_string(),
            backdated.envs[2].clone(),
        )],
        Some(json!({"now": ts(30 * 86400), "role": "home"})),
        vec![],
    );

    // 9c. Revision 8: one vector per High of the second review of revision 7.
    let mut y1 = base.clone();
    grant_agent_with(
        &mut y1,
        &a,
        &ts(R0),
        &a,
        &derived("r8/y1"),
        &derived("r8/y1/agreement"),
        "2026-11-18T08:00:00Z",
    );
    let mut y2 = base.clone();
    grant_agent_with(
        &mut y2,
        &ph,
        &ts(R0),
        &ph,
        &derived("r8/y2"),
        &derived("r8/y2/agreement"),
        "2026-11-18T08:00:00Z",
    );
    case(o, "t-conflict-no-evidence", base, json!({"result": "refused:fork", "seq": 3, "evidence": "both entries, against their signers", "sameForEveryVerifier": true}),
         "Two valid conflicting entries at seq 3 and no home head for either: the same verdict whether the verifier first held one or the other.",
         &["8.6", "13.3"], vec![],
         Some(json!({"now": ts(R0 + 100), "variants": [{"highWater": {"seq": 3, "digest": sha(&body_of(&y1.envs[2]))}},
                                                      {"highWater": {"seq": 3, "digest": sha(&body_of(&y2.envs[2]))}}]})),
         vec![("y1", vec![(3, y1.envs[2].clone())]), ("y2", vec![(3, y2.envs[2].clone())])]);
    let kr_q2 = keyring(
        kr5["controllers"].as_array().unwrap().clone(),
        Kr {
            rt: 1,
            policy: Some(policy_with(&[("headQuorum", json!(2))])),
            ..Kr::default()
        },
    );
    let mut q2 = Chain::new();
    genesis(
        &mut q2,
        &kr_q2,
        sg![a],
        Gen {
            label: "Three homes",
            opt: Opt {
                adds: sg![ph, b, k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let aq2 = account_id(&q2);
    let t_h3 = transition(
        &q2,
        json!({"homes": {"appoint": [home_appointment(&aq2, &h1k, &h1a, "Home one"), home_appointment(&aq2, &h2k, &h2a, "Home two"),
                                                            home_appointment(&aq2, &h3k, &h3a, "Home three")]}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut q2, &t_h3, &[]);
    let tq = transition(&q2, rm_two(&ph.id, &b.id), sg![a], &ts(R0), TOpt::default());
    let rq: Vec<Value> = [&h1k, &h2k]
        .iter()
        .map(|h| receipt_of(&aq2, &tq, h, &ts(R0 + 1)))
        .collect();
    let vq = veto(&aq2, &tq, sg![ph, b], &ts(R0 + 600));
    let rvq: Vec<Value> = [&h2k, &h3k]
        .iter()
        .map(|h| receipt_of(&aq2, &vq, h, &ts(R0 + 601)))
        .collect();
    let mut hostile_q2 = q2.clone();
    activate_x(&mut hostile_q2, &tq, &rq, false, 2);
    let mut honest_q2 = q2.clone();
    record_veto_q(&mut honest_q2, &tq, &rq, &vq, &rvq, 2);
    case(o, "t-quorum2-veto-beats-removal", &honest_q2, json!({"result": "ok", "seq": 3,
         "withActivateOnly": "the hostile home's activate is ok and provisional: Ph and B are removed for now",
         "withBoth": "the vetoed stands and displaces the activate, whatever order they arrived in",
         "why": "the removal has no final: H2 and H3 won't sign heads covering it"}),
         "Three homes at quorum 2, H1 hostile. A thief with the Mac key removes the owner's control keys; H1 and H2 receipt it; the owner's veto is receipted by H2 and H3; H1 activates anyway.",
         &["8.6", "8.7"], vec![("transition", tq.clone()), ("veto", vq.clone())], Some(ver(DUE0 + 60)), vec![("hostile", vec![(3, hostile_q2.envs[2].clone())])]);
    // Quorum 1 version: the hostile home hides the transition, so the owner can't veto; both security keys restore control at once.
    let t_q1 = p(&cx, rm_two(&ph.id, &b.id), sg![a]);
    let mut q1h = base.clone();
    activate(&mut q1h, &t_q1, &[rec(&cx, &t_q1)]);
    let t_fr = prop(
        &cx,
        json!({"keyring": {"keep": [], "add": [ct(&new, AC, "New laptop")]}}),
        sg![k1, k2],
        Pr {
            at: DUE0 + 600,
            chain: Some(&q1h),
            adds: sg![new],
            ..Pr::default()
        },
    );
    activate_full(
        &mut q1h,
        &t_fr,
        &[receipt_of(&acct, &t_fr, &h2k, &ts(DUE0 + 601))],
    );
    case(o, "row-13-quorum1-hidden-transition", &q1h, json!({"result": "ok", "seq": 4, "controllers": ids_sorted(sg![new, k1, k2]),
         "ownerCannot": "veto: H1 hid the transition until after its deadline",
         "ownerCan": "restore control at once with every recover key (full recovery)"}),
         "At quorum 1 a hostile home hides a thief's removal; both security keys install NEW with control and remove A.",
         &["8.4", "8.7", "changes §H"], vec![("thief", t_q1.clone()), ("owner", t_fr.clone())], Some(ver(DUE0 + 700)), vec![]);
    // High 4: keys a removed key planted after the anchor are dropped; an approve-only key never rotates the vault.
    let mut pl = base.clone();
    let t_pl = prop(
        &cx,
        rm(&a.id),
        sg![ph],
        Pr {
            chain: Some(&pl),
            ..Pr::default()
        },
    );
    pl.add("keyring", &a, &ts(R0 + 10), &a, Opt { adds: sg![appr], ..Opt::default() },
           json!({"keyring": kr_with_ctrls(&kr5, add_ctrl(&kr5, vec![ct(&appr, &["approve"], "Planted")]))}));
    activate(&mut pl, &t_pl, &[rec(&cx, &t_pl)]);
    let mut pl2 = pl.clone();
    pl2.add(
        "vault",
        &appr,
        &ts(DUE0 + 60),
        &appr,
        Opt::default(),
        vault_change("seize", slots![(appr, "Planted")]),
    );
    case_v(o, "t-planted-key-dropped", &pl2, bad("badSignature", 5),
           "A plants an approve-only key after the anchor of its own removal; the activation drops it too, so its vault rotation is refused.", &["8.3"], Some(ver(DUE0 + 200)));
    let mut ap = ca.clone();
    let t_ap = prop(
        &cx,
        rm(&a.id),
        sg![ph],
        Pr {
            chain: Some(&ap),
            ..Pr::default()
        },
    );
    activate(&mut ap, &t_ap, &[rec(&cx, &t_ap)]);
    ap.add(
        "vault",
        &appr,
        &ts(DUE0 + 60),
        &appr,
        Opt::default(),
        vault_change("seize2", slots![(appr, "Tablet")]),
    );
    case_v(
        o,
        "t-vault-by-approve-only",
        &ap,
        bad("badSignature", 5),
        "An approve-only key current at the anchor still can't rotate a retiring vault.",
        &["8.3", "8.4"],
        Some(ver(DUE0 + 200)),
    );
    // High 5: recovery keys restore control.
    let t_rp = prop(
        &cx,
        json!({"keyring": {"keep": [], "add": [ct(&new, AC, "New laptop")]}}),
        sg![k1],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let mut c = base.clone();
    activate(&mut c, &t_rp, &[rec(&cx, &t_rp)]);
    case_v(o, "t-recovery-installs-control-pending", &c, json!({"result": "ok", "seq": 3, "controllers": ids_sorted(sg![new, k1, k2])}),
           "One recovery key (recoverThreshold, not every one) installs a replacement control key and removes the rest: pending, after the delay.", &["8.4", "8.7"], Some(ver(DUE0 + 60)));
    let t_rr = prop(
        &cx,
        json!({"keyring": {"add": [ct(&new, &["recover"], "Third key")]}}),
        sg![k1, k2],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let mut c = base.clone();
    activate_full(&mut c, &t_rr, &[rec(&cx, &t_rr)]);
    case_v(
        o,
        "t-recovery-adds-recover-refused",
        &c,
        bad("badSignature", 3),
        "The recovery rule never adds `recover`.",
        &["8.4"],
        None,
    );
    let t_nc = p(&cx, json!({"keyring": {"keep": []}}), sg![k1, k2]);
    let mut c = base.clone();
    activate_full(&mut c, &t_nc, &[rec(&cx, &t_nc)]);
    case_v(
        o,
        "t-recovery-leaves-no-control",
        &c,
        bad("malformed", 3),
        "Removing every control key without a replacement breaks §6.2.",
        &["6.2", "8.4"],
        None,
    );

    // 9d. Revision 9: a home's revocation applies only when final.
    let t_rg = p(&cx, json!({"homes": {"revoke": [h2k.id]}}), sg![a, k1]);
    let mut rg9 = base.clone();
    activate(&mut rg9, &t_rg, &[rec(&cx, &t_rg)]);
    let t_own = prop(
        &cx,
        json!({"keyring": {"remove": [a.id, k1.id]}}),
        sg![ph, b, k2],
        Pr {
            at: DUE0 + 600,
            chain: Some(&rg9),
            ..Pr::default()
        },
    );
    activate(
        &mut rg9,
        &t_own,
        &[receipt_of(&acct, &t_own, &h2k, &ts(DUE0 + 601))],
    );
    let v_th = veto(&acct, &t_own, sg![a, k1], &ts(DUE0 + 900));
    case(o, "t-provisional-home-revocation-keeps-home", &rg9, json!({"result": "ok", "seq": 4, "controllers": ids_sorted(sg![ph, b, k2]),
         "homes": "H1 and H2: H2's revocation at seq 3 has no final (H2 won't witness it), so H2 is still current",
         "thiefVeto": "invalid: two units against three"}),
         "A hidden control-rule revocation of the honest home doesn't take it away: it receipts the owner's three-unit removal of M and K1.",
         &["8.7", "changes §H"], vec![("thief-veto", v_th.clone())], Some(ver(DUE0 + 600 + W + D + 60)), vec![]);

    // 9e. Revision 10: one recovery controller against one stolen control key is the equal-units stall.
    let kr_one = keyring(
        vec![
            ct(&a, AC, "Mac"),
            ct(&k1, &["recover"], "Only security key"),
        ],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let mut one = Chain::new();
    genesis(
        &mut one,
        &kr_one,
        sg![a],
        Gen {
            label: "One recovery key",
            opt: Opt {
                adds: sg![k1],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let a1 = account_id(&one);
    let t_o0 = transition(
        &one,
        json!({"homes": {"appoint": [home_appointment(&a1, &h1k, &h1a, "Home one")]}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut one, &t_o0, &[]);
    let recover_new = |label: &str| json!({"keyring": {"keep": [], "add": [ct(&new, AC, label)]}});
    let t_o1 = transition(
        &one,
        recover_new("New laptop"),
        sg![k1],
        &ts(R0),
        TOpt {
            adds: sg![new],
            ..TOpt::default()
        },
    );
    let r_o1 = receipt_of(&a1, &t_o1, &h1k, &ts(R0 + 1));
    let v_o1 = veto(&a1, &t_o1, sg![a], &ts(R0 + 600));
    record_veto(
        &mut one,
        &t_o1,
        &[r_o1],
        &v_o1,
        &[receipt_of(&a1, &v_o1, &h1k, &ts(R0 + 601))],
    );
    let t_o2 = transition(
        &one,
        recover_new("New laptop"),
        sg![k1],
        &ts(R0 + 900),
        TOpt {
            adds: sg![new],
            ..TOpt::default()
        },
    );
    let mut oc = one.clone();
    activate(
        &mut oc,
        &t_o2,
        &[receipt_of(&a1, &t_o2, &h1k, &ts(R0 + 901))],
    );
    case(o, "row-28-one-recovery-key-stall", &oc, bad("badSignature", 4),
         "One recovery key K1 against a stolen sole control key A: A vetoes K1's recovery once (one against one); v(K1) = 1, so K1 alone can't propose again. Stall.",
         &["8.7", "changes §H"], vec![("first-recovery", t_o1.clone()), ("veto", v_o1.clone())], Some(ver(R0 + 900 + W + D + 60)), vec![]);

    // Revision 11: two recovery keys of one holder are one unit, so they don't make a full set.
    let kr_h = keyring(
        vec![
            cx_(&a, AC, "Thief's device", json!({"holder": "alex"})),
            cx_(&k1, &["recover"], "Key 1", json!({"holder": "owner"})),
            cx_(&k2, &["recover"], "Key 2", json!({"holder": "owner"})),
        ],
        Kr {
            rt: 1,
            count: "holders",
            ..Kr::default()
        },
    );
    let mut oh = Chain::new();
    genesis(
        &mut oh,
        &kr_h,
        sg![a],
        Gen {
            label: "One holder, two keys",
            opt: Opt {
                adds: sg![k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let ah = account_id(&oh);
    let t_h0 = transition(
        &oh,
        json!({"homes": {"appoint": [home_appointment(&ah, &h1k, &h1a, "Home one")]}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut oh, &t_h0, &[]);
    let holder_new = || json!({"keyring": {"keep": [], "add": [cx_(&new, AC, "New laptop", json!({"holder": "owner"}))]}});
    let t_h1 = transition(
        &oh,
        holder_new(),
        sg![k1, k2],
        &ts(R0),
        TOpt {
            adds: sg![new],
            ..TOpt::default()
        },
    );
    let r_h1 = receipt_of(&ah, &t_h1, &h1k, &ts(R0 + 1));
    let v_h1 = veto(&ah, &t_h1, sg![a], &ts(R0 + 600));
    record_veto(
        &mut oh,
        &t_h1,
        &[r_h1],
        &v_h1,
        &[receipt_of(&ah, &v_h1, &h1k, &ts(R0 + 601))],
    );
    let t_h2 = transition(
        &oh,
        holder_new(),
        sg![k1, k2],
        &ts(R0 + 900),
        TOpt {
            adds: sg![new],
            ..TOpt::default()
        },
    );
    let mut ohc = oh.clone();
    activate(
        &mut ohc,
        &t_h2,
        &[receipt_of(&ah, &t_h2, &h1k, &ts(R0 + 901))],
    );
    case(o, "row-28-one-holder-two-keys-stall", &ohc, bad("badSignature", 4),
         "countBy holders: K1 and K2 are one holder's, so one unit. Not a full set; the thief's one unit vetoes; v(owner) = 1 and both keys still make one unit. Stall.",
         &["6.1", "8.7", "changes §H"], vec![("first-recovery", t_h1.clone()), ("veto", v_h1.clone())], Some(ver(R0 + 900 + W + D + 60)), vec![]);

    // 10. Veto signatures by a WebAuthn key.
    let kr_p = keyring(
        vec![
            ct(&a, AC, "Mac"),
            cx_(p_pin, AC, "Passkey", json!({"verification": true})),
            ct(&k1, &["recover"], "Key"),
        ],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let mut cc = Chain::new();
    genesis(
        &mut cc,
        &kr_p,
        sg![a],
        Gen {
            opt: Opt {
                adds: sg![k1, *p_pin],
                origin: Some("https://keys.id.example"),
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let acct_cc = account_id(&cc);
    let t_cch = transition(
        &cc,
        json!({"homes": {"appoint": [home_appointment(&acct_cc, &h1k, &h1a, "Home one")]}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut cc, &t_cch, &[]);
    let t_cc = transition(&cc, rm(&k1.id), sg![a, k1], &ts(R0), TOpt::default());
    for (name, origin, flags, exp) in [
        (
            "veto-webauthn-ok",
            "https://keys.id.example",
            0x05u8,
            "valid signature",
        ),
        (
            "veto-webauthn-no-uv",
            "https://keys.id.example",
            0x01,
            "invalid: no UV",
        ),
        (
            "veto-webauthn-call-origin",
            "https://sign.id.example",
            0x05,
            "invalid: not an authority origin",
        ),
    ] {
        let v = veto_of(
            &acct_cc,
            &t_cc,
            sg![*p_pin],
            &ts(R0 + 300),
            Some(origin),
            flags,
        );
        write(o, &format!("rules/{name}/veto.json"), &v);
        write(o, &format!("rules/{name}/transition.json"), &t_cc);
        write(
            o,
            &format!("rules/{name}/case.json"),
            &json!({"description": "Checks only the veto's signature rule (§4.3, §8.7).",
            "sections": ["4.3", "8.7"], "expected": {"vetoSignature": exp}}),
        );
    }

    // 11. Rows of changes §H as event sequences.
    let scenario = |o: &mut Out,
                    name: &str,
                    chain: &Chain,
                    events: Vec<(&str, Value, &str)>,
                    final_: Value,
                    why: &str| {
        let objs: Vec<(String, Value)> = events
            .iter()
            .enumerate()
            .map(|(i, (label, env, _))| (format!("{:02}-{label}", i + 1), env.clone()))
            .collect();
        let mut checks: Vec<Value> = Vec::new();
        let failures = [
            ("thief-again-alone", "badSignature"),
            ("thief-third", "badSignature"),
            ("thief-veto", "malformed"),
            ("owner-veto", "malformed"),
        ];
        for (i, (label, env, _)) in events.iter().enumerate() {
            let body = body_json(env);
            let at = secs(
                body.get("issued")
                    .or_else(|| body.get("created"))
                    .unwrap()
                    .as_str()
                    .unwrap(),
            );
            let after = chain
                .envs
                .iter()
                .filter(|e| secs(&fstr(e, "issued")) <= at)
                .count() as i64;
            let result = failures
                .iter()
                .find(|(l, _)| l == label)
                .map(|(_, r)| *r)
                .unwrap_or("ok");
            let mut check = json!({"object": format!("{:02}-{label}", i + 1), "after": after, "result": result});
            if body["protocol"] == "colophon/authority/5" {
                check["after"] = json!(body["seq"].as_i64().unwrap() - 1);
            }
            if body["protocol"] == "colophon/call/5" {
                let mut prefix = chain.clone();
                prefix.envs = chain.envs[..after as usize].to_vec();
                check["heads"] = json!([emb(&head5(&prefix, &h1k, at - 10, None))]);
            }
            checks.push(check);
        }
        // In row 8 the first owner veto is valid (equal units); row 17's is too small.
        if name == "row-8-equal-units-stall" {
            checks[1]["result"] = json!("ok");
            checks[3]["result"] = json!("ok");
        }
        if name == "row-4-thief-has-phone" {
            checks.push(json!({"object": "01-thief-proposes", "after": chain.envs.len(), "result": "badSignature"}));
        }
        let evs: Vec<Value> = events.iter().enumerate().map(|(i, (label, _, out))| json!({"object": format!("{:02}-{label}", i + 1), "outcome": out})).collect();
        write_case(
            o,
            name,
            chain,
            json!({"events": evs, "checks": checks, "final": final_, "result": "ok", "seq": chain.envs.len()}),
            why,
            &["8.7", "changes §H"],
            objs.into_iter()
                .map(|(n, v)| (format!("events/{n}.json"), v))
                .collect(),
            None,
            vec![],
        );
    };

    let mut s = base.clone();
    let ta = p(&cx, rm_two(&ph.id, &b.id), sg![a]);
    let ra = rec(&cx, &ta);
    let va = veto(&acct, &ta, sg![ph], &ts(R0 + 300));
    record_veto(&mut s, &ta, &[ra], &va, &[rec_at(&cx, &va, R0 + 301)]);
    let ta2 = prop(
        &cx,
        rm(&ph.id),
        sg![a],
        Pr {
            at: R0 + 500,
            chain: Some(&s),
            ..Pr::default()
        },
    );
    let to = prop(
        &cx,
        json!({"keyring": {"remove": [a.id]}, "vault": vault_change_p("row2", slots![(ph, "Phone")], false)}),
        sg![ph, b],
        Pr {
            at: R0 + 600,
            chain: Some(&s),
            ..Pr::default()
        },
    );
    let ro = rec_at(&cx, &to, R0 + 601);
    suspend(&mut s, &ph, &a, &to, std::slice::from_ref(&ro), R0 + 650);
    let vbad = veto(&acct, &to, sg![a], &ts(R0 + 700));
    activate(&mut s, &to, &[ro]);
    scenario(
        o,
        "row-2-thief-has-mac-key",
        &s,
        vec![
            ("thief-proposes", ta.clone(), "vetoed by Ph"),
            ("veto", va.clone(), "valid"),
            ("thief-again-alone", ta2.clone(), "refused: v(A)=1"),
            (
                "owner-removes-A-with-vault-change",
                to.clone(),
                "activates after D + 300 s; A suspended meanwhile",
            ),
            (
                "thief-veto",
                vbad.clone(),
                "invalid: one vetoer against two signers",
            ),
        ],
        json!({"controllers": ids_sorted(sg![ph, b, k1, k2])}),
        "Owner wins after the delay; the vault rotates away from the Mac.",
    );

    let mut s = base.clone();
    let tt = p(&cx, rm(&ph.id), sg![a]);
    let rt_ = rec(&cx, &tt);
    suspend(&mut s, &a, &ph, &tt, std::slice::from_ref(&rt_), R0 + 60);
    let vt = veto(&acct, &tt, sg![ph], &ts(R0 + 120));
    record_veto(&mut s, &tt, &[rt_], &vt, &[rec_at(&cx, &vt, R0 + 121)]);
    scenario(
        o,
        "row-3-thief-suspends-first",
        &s,
        vec![
            (
                "thief-proposes-and-suspends",
                tt.clone(),
                "vetoed by Ph itself",
            ),
            ("veto", vt.clone(), "valid"),
        ],
        json!({"controllers": ids_sorted(sg![a, ph, b, k1, k2]), "suspended": []}),
        "Ph vetoes its own removal; the suspension ends; A can't propose alone again.",
    );

    let mut s = base.clone();
    let tx = p(
        &cx,
        json!({"keyring": {"remove": [a.id]}, "vault": vault_change_p("row4", slots![(ph, "Phone")], false)}),
        sg![ph, b],
    );
    let toy = pat(
        &cx,
        json!({"keyring": {"keep": [a.id]}}),
        sg![k1, k2],
        R0 + 100,
    );
    activate_full(&mut s, &toy, &[rec_at(&cx, &toy, R0 + 101)]);
    scenario(
        o,
        "row-4-thief-has-phone",
        &s,
        vec![
            (
                "thief-proposes",
                tx.clone(),
                "pending; void once its signers are removed",
            ),
            (
                "owner-full-recovery-keep-A",
                toy.clone(),
                "full recovery set (a): immediate, final when both homes cover it",
            ),
        ],
        json!({"controllers": ids_sorted(sg![a, k1, k2])}),
        "Owner wins at once with both security keys.",
    );

    let kr4k = keyring(
        vec![
            ct(&a, AC, "Mac"),
            ct(&b, AC, "Passkey"),
            ct(&k1, &["recover"], "Security key 1"),
            ct(&k2, &["recover"], "Security key 2"),
        ],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let mut s = Chain::new();
    genesis(
        &mut s,
        &kr4k,
        sg![a],
        Gen {
            label: "Four keys",
            opt: Opt {
                adds: sg![b, k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let a4 = account_id(&s);
    let t_s4 = transition(
        &s,
        json!({"homes": {"appoint": [home_appointment(&a4, &h1k, &h1a, "Home one")]}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut s, &t_s4, &[]);
    let r4 = |env: &Value, at: i64| receipt_of(&a4, env, &h1k, &ts(at));
    let e1 = transition(
        &s,
        rm_two(&b.id, &k2.id),
        sg![a, k1],
        &ts(R0),
        TOpt::default(),
    );
    let ve1 = veto(&a4, &e1, sg![b, k2], &ts(R0 + 300));
    record_veto(&mut s, &e1, &[r4(&e1, R0 + 1)], &ve1, &[r4(&ve1, R0 + 301)]);
    let e2 = transition(
        &s,
        json!({"keyring": {"remove": [a.id, k1.id]}, "vault": vault_change_p("row8", slots![(b, "Passkey")], false)}),
        sg![b, k2],
        &ts(R0 + 400),
        TOpt::default(),
    );
    let ve2 = veto(&a4, &e2, sg![a, k1], &ts(R0 + 500));
    record_veto(
        &mut s,
        &e2,
        &[r4(&e2, R0 + 401)],
        &ve2,
        &[r4(&ve2, R0 + 501)],
    );
    let e3 = transition(
        &s,
        rm_two(&b.id, &k2.id),
        sg![a, k1],
        &ts(R0 + 600),
        TOpt::default(),
    );
    let ve3 = veto(&a4, &e3, sg![b, k2], &ts(R0 + 700));
    record_veto(
        &mut s,
        &e3,
        &[r4(&e3, R0 + 601)],
        &ve3,
        &[r4(&ve3, R0 + 701)],
    );
    let e4 = transition(
        &s,
        rm_two(&b.id, &k2.id),
        sg![a, k1],
        &ts(R0 + 800),
        TOpt::default(),
    );
    scenario(
        o,
        "row-8-equal-units-stall",
        &s,
        vec![
            ("thief", e1.clone(), "vetoed"),
            ("owner-veto", ve1.clone(), "valid"),
            ("owner", e2.clone(), "vetoed"),
            ("thief-veto", ve2.clone(), "valid"),
            ("thief-again", e3.clone(), "valid (v=1, two units), vetoed"),
            ("owner-veto-2", ve3.clone(), "valid"),
            ("thief-third", e4.clone(), "refused: v=2 needs three units"),
        ],
        json!({"controllers": ids_sorted(sg![a, b, k1, k2]), "state": "stall"}),
        "One control plus one recovery key each: stall.",
    );

    let mut s = base.clone();
    let tf = prop(
        &cx,
        json!({"keyring": {"keep": [], "add": [ct(&new, AC, "New phone")]},
                              "vault": vault_change_p("row9", slots![(k1, "Security key 1")], false)}),
        sg![k1, k2],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    activate_full(&mut s, &tf, &[rec_at(&cx, &tf, R0 + 1)]);
    let read = call_on(
        base,
        &k1,
        "row9",
        "colophon.history.read",
        &home_ep,
        R0 + 1010,
    );
    scenario(o, "row-9-both-recovery-keys-no-device", &s, vec![("read-history", read.clone(), "ok (recover may read)"),
        ("full-recovery", tf.clone(), "full recovery set (a): immediate; new vault, old data unreachable without a recovery-key slot")],
        json!({"controllers": ids_sorted(sg![new, k1, k2])}), "Back in at once.");
    scenario(
        o,
        "row-10-burglar-both-recovery-keys",
        &s,
        vec![(
            "burglar-full-recovery",
            tf.clone(),
            "immediate: the burglar wins",
        )],
        json!({"controllers": ids_sorted(sg![new, k1, k2])}),
        "The same bytes by a burglar.",
    );

    let mut s = base.clone();
    let th = prop(
        &cx,
        json!({"keyring": {"add": [ct(&new, AC, "New phone")], "remove": [ph.id]}}),
        sg![k1],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let vh = veto(&acct, &th, sg![ph], &ts(R0 + 3600));
    record_veto(
        &mut s,
        &th,
        &[rec(&cx, &th)],
        &vh,
        &[rec_at(&cx, &vh, R0 + 3601)],
    );
    scenario(
        o,
        "row-11-honest-mistake",
        &s,
        vec![
            ("recovery", th.clone(), "vetoed"),
            ("found-phone", vh.clone(), "valid"),
        ],
        json!({"controllers": ids_sorted(sg![a, ph, b, k1, k2])}),
        "Nothing changes.",
    );

    let mut s = base.clone();
    let r_h2 = rec_h(&cx, &t1, &h2k);
    activate(&mut s, &t1, std::slice::from_ref(&r_h2));
    case(o, "row-12-one-home-down", &s, json!({"result": "ok", "seq": 3, "finality": "provisional until H1's head covers seq 3"}),
         "H1 is down: H2's receipt makes the removal due; it applies at once and is final when H1 returns.", &["8.7", "changes §H"],
         vec![("transition", t1.clone()), ("receipt", r_h2.clone()), ("head-H2", head5(&s, &h2k, DUE0 + 100, None))], Some(ver(DUE0 + 200)), vec![]);
    let t_gone = p(&cx, json!({"homes": {"revoke": [h1k.id]}}), sg![k1]);
    let mut s = base.clone();
    activate(&mut s, &t_gone, &[rec_h(&cx, &t_gone, &h2k)]);
    let hs = vec![head5(&s, &h2k, DUE0 + 30, Some(3))];
    final_of(&mut s, 3, hs);
    let t_ng = prop(
        &cx,
        add_new("New phone"),
        sg![a],
        Pr {
            at: DUE0 + 60,
            chain: Some(&s),
            adds: sg![new],
            ..Pr::default()
        },
    );
    let dg = DUE0 + 60 + W + D;
    activate(
        &mut s,
        &t_ng,
        &[receipt_of(&acct, &t_ng, &h2k, &ts(DUE0 + 61))],
    );
    let hs = vec![head5(&s, &h2k, dg + 30, Some(5))];
    final_of(&mut s, 5, hs);
    grant_agent(&mut s, &new, &ts(dg + 100), &new);
    case_v(o, "row-12-gone-home-revoked", &s, ok_at(7),
           "H1 is gone for good. One recovery key (the stronger authority) revokes it: a removal-only transition whose witnesses leave H1 out. Final at 4 with H2's head; then an addition is final with H2's head alone.",
           &["8.7", "changes §H"], Some(ver(dg + 200)));
    let t_ra = prop(
        &cx,
        json!({"homes": {"revoke": [h2k.id]}, "keyring": {"add": [ct(&new, AC, "New phone")]}}),
        sg![k1],
        Pr {
            adds: sg![new],
            ..Pr::default()
        },
    );
    let mut c = base.clone();
    activate(&mut c, &t_ra, &[rec(&cx, &t_ra)]);
    case_v(
        o,
        "t-revoke-home-and-add",
        &c,
        bad("malformed", 3),
        "A transition may not both revoke a home and add anything.",
        &["8.7"],
        Some(ver(DUE0 + 60)),
    );
    let t_cr = p(&cx, json!({"homes": {"revoke": [h1k.id]}}), sg![a, k1]);
    let mut c = base.clone();
    activate(&mut c, &t_cr, &[rec_h(&cx, &t_cr, &h2k)]);
    let hs = vec![head5(&c, &h2k, DUE0 + 30, Some(3))];
    final_of(&mut c, 3, hs);
    case_v(o, "t-revoke-home-control-rule-needs-its-head", &c, bad("malformed", 4),
           "Revoked under the control rule, H1 stays a witness of its own revocation: a `final` without H1's head is malformed.", &["8.7"], Some(ver(DUE0 + 200)));
    // The deadlock of revision 7 (Codex7 High 2): an addition waits on a withholding home; a removal revokes it.
    let mut dl = base.clone();
    activate(&mut dl, &t_addc, &[rec(&cx, &t_addc)]);
    let t_dr = pat(
        &cx,
        json!({"homes": {"revoke": [h1k.id]}}),
        sg![k1],
        R0 + 20,
    );
    activate(
        &mut dl,
        &t_dr,
        &[receipt_of(&acct, &t_dr, &h2k, &ts(R0 + 21))],
    );
    let hs = vec![head5(&dl, &h2k, DUE0 + 50, Some(4))];
    final_of(&mut dl, 4, hs);
    let hs = vec![head5(&dl, &h2k, DUE0 + 60, Some(4))];
    final_of(&mut dl, 3, hs);
    grant_agent(&mut dl, &new, &ts(DUE0 + 100), &new);
    case_v(o, "t-removal-unblocks-addition", &dl, ok_at(7),
           "Seq 3 adds NEW and waits on H1, which withholds. Seq 4, removal-only, revokes H1 by the recovery rule; it waits for nothing and is final at 5 with H2's head. H1 is then excused, so seq 3 is final at 6 with H2's head.",
           &["8.7"], Some(ver(DUE0 + 200)));
    let tb = p(&cx, rm_two(&ph.id, &b.id), sg![a]);
    let rb = receipt_of(&acct, &tb, &h1k, &ts(R0 + 1));
    let mut hostile = base.clone();
    activate(&mut hostile, &tb, std::slice::from_ref(&rb));
    let v13 = veto(&acct, &tb, sg![ph, b], &ts(R0 + 7200));
    let mut honest = base.clone();
    record_veto(
        &mut honest,
        &tb,
        std::slice::from_ref(&rb),
        &v13,
        &[receipt_of(&acct, &v13, &h2k, &ts(R0 + 7201))],
    );
    case(o, "row-13-backdating-home", &honest, json!({"result": "ok", "seq": 3,
         "honestHome": "refuses the activate for ever, but stores and serves the transition, so the owner vetoes",
         "admission": {"object": "branch-hostile/authority/00000003.json", "result": "refused:late", "home": h2k.id},
         "ifVetoed": "vetoed stands at every verifier holding it (the activate has no final: H2 never covers it)",
         "ifNotVetoed": "the thief's removal applies at every verifier that hears from H1"}),
         "At quorum 1 a hostile home and one key: the owner wins only by vetoing before the deadline.", &["8.6", "13.1", "changes §H"],
         vec![("transition", tb.clone()), ("receipt", rb.clone()), ("veto", v13.clone())], Some(ver(DUE0 + 60)), vec![("hostile", vec![(3, hostile.envs[2].clone())])]);

    let mut s = base.clone();
    let t17 = p(
        &cx,
        json!({"keyring": {"remove": [a.id, k2.id]}, "vault": vault_change_p("row17", slots![(ph, "Phone")], false)}),
        sg![ph, b, k1],
    );
    let r17 = rec(&cx, &t17);
    let v17 = veto(&acct, &t17, sg![a, k2], &ts(R0 + 600));
    activate(&mut s, &t17, &[r17]);
    let act17 = s.envs.last().unwrap().clone();
    scenario(
        o,
        "row-17-phone-and-one-security-key",
        &s,
        vec![
            (
                "thief-proposes",
                t17.clone(),
                "three units, consent from K1",
            ),
            (
                "owner-veto",
                v17.clone(),
                "invalid: two units against three",
            ),
            ("activate", act17, "ok after D + 300 s: the thief wins"),
        ],
        json!({"controllers": ids_sorted(sg![ph, b, k1])}),
        "Losing row: more keys than the owner holds.",
    );

    // 12. Swift succession (§15.1, §13.5).
    let sh = derived("r4/successor-home/signing");
    let sha_ = derived("r4/successor-home/agreement");
    let sr0: i64 = 7200;
    let after = D + 600;
    let before = D - 600; // F at SR0 + AFTER is after the due time (window end SR0 + 240, plus D)
    let sp: &Authenticator = &SP;
    let sy: &Authenticator = &SY;
    let root_s: &Key = &ROOT_S;
    let rec_s: &Key = &REC_S;

    let successor_with_home = |g: &mut Chain, receipt_delay: i64, start: i64| -> Value {
        let acc = account_id(g);
        let known: Vec<&dyn Signer> = vec![
            &a as &dyn Signer,
            &b,
            &k1,
            &k2,
            &mk,
            &nk,
            sp,
            sy,
            root_s,
            rec_s,
        ];
        let ctrls = body_json(&g.envs[0])["keyring"]["controllers"]
            .as_array()
            .unwrap()
            .clone();
        let extra: Vec<&dyn Signer> = ctrls
            .iter()
            .filter(|x| {
                x["roles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r == "recover")
            })
            .filter_map(|x| known.iter().find(|k| k.id() == cid(x)).copied())
            .take(1)
            .collect();
        let mut signers: Vec<&dyn Signer> = vec![&a as &dyn Signer];
        signers.extend(extra);
        let t = transition(
            g,
            json!({"homes": {"appoint": [home_appointment(&acc, &sh, &sha_, "Successor home")]}}),
            &signers,
            &ts(start),
            TOpt {
                origin: Some("https://id.example"),
                ..TOpt::default()
            },
        );
        activate(g, &t, &[]);
        receipt_of(&acc, &g.envs[0], &sh, &ts(start + receipt_delay))
    };
    let record_succession_veto = |g: &mut Chain, v_env: &Value, v_rec: &Value, g_rec: &Value| {
        let issued = ts(std::cmp::max(received_of(v_rec), prev_issued(g)));
        append_unsigned(
            g,
            "successionVetoed",
            &fstr(v_env, "by"),
            &issued,
            json!({"veto": emb(v_env), "receipts": [emb(v_rec)], "genesisReceipts": [emb(g_rec)]}),
        );
    };
    let successor_head = |g: &Chain| -> Value {
        // Fresh coverage required by §15.1, covering the unvetoed prefix.
        envelope(
            &json!({"protocol": "colophon/head/5", "account": account_id(g),
                         "authority": {"seq": 2, "digest": sha(&body_of(&g.envs[1]))}, "issued": ts(sr0 + after), "by": sh.id}),
            &sh,
        )
    };
    let succ_extra = |g: &Chain, rg: &Value| -> Vec<(String, Value)> {
        let mut v = vec![
            ("genesis-receipt.json".to_string(), rg.clone()),
            ("successor-head.json".to_string(), successor_head(g)),
        ];
        for (i, e) in g.envs.iter().enumerate() {
            v.push((format!("successor/authority/{:08}.json", i + 1), e.clone()));
        }
        v
    };
    let swift_case = |o: &mut Out,
                      name: &str,
                      recs: &[Value],
                      g: &mut Chain,
                      f_at: i64,
                      expected: Value,
                      why: &str,
                      signer: &dyn Signer,
                      root: bool,
                      receipt_delay: i64,
                      vetoes: Vec<(Value, Value)>| {
        let rg = successor_with_home(g, receipt_delay, sr0 - 60);
        for (v_env, v_rec) in &vetoes {
            record_succession_veto(g, v_env, v_rec, &rg);
        }
        let f = if root {
            swift_freeze_root(recs, &account_id(g), &ts(sr0 + f_at))
        } else {
            swift_freeze_signed(recs, &account_id(g), signer, &ts(sr0 + f_at))
        };
        let mut all = recs.to_vec();
        all.push(f);
        write_swift(o, name, &all, Some(g), expected, why, succ_extra(g, &rg));
    };
    let gveto = |g: &Chain, key: &Key, at: i64| -> (Value, Value) {
        let v = envelope(
            &json!({"protocol": "colophon/veto/5", "account": account_id(g), "transition": sha(&body_of(&g.envs[0])),
                                 "issued": ts(at), "by": key.id, "signers": [key.id]}),
            key,
        );
        let r = receipt_of(&account_id(g), &v, &sh, &ts(at + 1));
        (v, r)
    };
    let sv = sr0 + 600;

    let recs = swift_library(true);
    let mut g = new_genesis(&recs, 2, sg![a], "Library");
    swift_case(
        o,
        "swift-keyring",
        &recs,
        &mut g,
        after,
        json!({"succession": "verified"}),
        "Receipt 60 s into the succession window; F after the due time.",
        &a,
        false,
        60,
        vec![],
    );
    // Revision 12, M4 (§8.4 Possession): a carried key is exempt from its possession proof only
    // when the genesis's `handover` meets the rule that may write F at `head`. The genesis lists
    // the kit, a predecessor key, and proves its possession in neither case.
    let mut g = new_genesis(&recs, 2, &[], "No handover");
    swift_case(
        o,
        "swift-no-handover-needs-possession",
        &recs,
        &mut g,
        after,
        json!({"succession": "unverified", "genesis": "badSignature"}),
        "The genesis lists the predecessor's kit and carries no `handover`: the kit's possession proof is missing, so the genesis is `badSignature`.",
        &a,
        false,
        60,
        vec![],
    );
    let mut g = new_genesis(&recs, 2, sg![k1], "Handover by the kit");
    swift_case(
        o,
        "swift-handover-below-rule-needs-possession",
        &recs,
        &mut g,
        after,
        json!({"succession": "unverified", "genesis": "badSignature"}),
        "The `handover` is signed by the kit alone, which holds `recover` and not the control threshold F needs: it does not meet the rule that may write F, so the kit's possession is still required and the genesis is `badSignature`.",
        &a,
        false,
        60,
        vec![],
    );
    // §16.3: a `layout` needs all signers to hold `control`; the kit holds only `recover`.
    let mut g = new_genesis(&recs, 2, sg![a], "Extra cosigner");
    let rg = successor_with_home(&mut g, 60, sr0 - 60);
    let f_body = json!({"by": "controller", "issued": ts(sr0 + after), "kind": "layout", "layout": 3,
                        "previous": sha(&unb64(recs.last().unwrap()["body"].as_str().unwrap())),
                        "seq": recs.len() + 1, "signer": a.id, "successor": account_id(&g)});
    let f_extra = swift_signed(&f_body, &a, &[&k1]);
    let mut all = recs.clone();
    all.push(f_extra);
    write_swift(o, "swift-layout-extra-noncontrol-cosigner", &all, Some(&g),
                json!({"succession": "unverified"}),
                "F is signed by the Mac (control) and cosigned by the kit, which holds only recover: a layout needs every signer to hold control.",
                succ_extra(&g, &rg));
    let mut g = new_genesis(&recs, 2, sg![a], "Late receipt");
    swift_case(o, "swift-late-genesis-receipt", &recs, &mut g, after, json!({"succession": "unverified"}),
               "The receipt is 400 s after the appointing entry, outside the succession window: never due.", &a, false, 400, vec![]);
    let mut g = new_genesis(&recs, 2, sg![a], "Too early");
    swift_case(
        o,
        "swift-freeze-before-window",
        &recs,
        &mut g,
        before,
        json!({"succession": "unverified"}),
        "F written before the due time.",
        &a,
        false,
        60,
        vec![],
    );
    let mut g = new_genesis(&recs, 2, sg![a], "Vetoed");
    let gv = gveto(&g, &k1, sv);
    swift_case(
        o,
        "swift-succession-vetoed",
        &recs,
        &mut g,
        after,
        json!({"succession": "unverified", "seq3": "successionVetoed ok"}),
        "K1 (current at head) vetoes; the successor home records a successionVetoed entry.",
        &a,
        false,
        60,
        vec![gv],
    );

    let kx = derived("swift/x");
    let ky = derived("swift/y");
    let xy_library = |t3: &str, t4: &str, t5: &str| -> Vec<Value> {
        let mut rs = swift_library(true);
        let k2b = body_json(&rs[1]);
        let mut ctrls_xy = k2b["controllers"].as_array().unwrap().clone();
        ctrls_xy.push(swift_ctrl(&kx, AC, "X"));
        ctrls_xy.push(swift_ctrl(&ky, AC, "Y"));
        let mut k3 = k2b.clone();
        k3.as_object_mut().unwrap().remove("recoverThreshold");
        let prev2 = sha(&unb64(rs[1]["body"].as_str().unwrap()));
        for (k, v) in [
            ("by", json!("controller")),
            ("controllers", json!(ctrls_xy)),
            ("issued", json!(t3)),
            ("previous", json!(prev2)),
            ("seq", json!(3)),
            ("signer", json!(a.id)),
        ] {
            k3[k] = v;
        }
        rs.push(swift_record(&k3, &a, &[]));
        let mut k4 = k3.clone();
        k4["controllers"] = json!(ctrls_xy
            .iter()
            .filter(|c| c["key"] != json!(b64(&kx.point)))
            .cloned()
            .collect::<Vec<_>>());
        k4["issued"] = json!(t4);
        k4["previous"] = json!(sha(&unb64(rs[2]["body"].as_str().unwrap())));
        k4["seq"] = json!(4);
        rs.push(swift_record(&k4, &a, &[]));
        let mut k5 = k4.clone();
        k5["controllers"] = json!(k4["controllers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["key"] != json!(b64(&ky.point)))
            .cloned()
            .collect::<Vec<_>>());
        k5["issued"] = json!(t5);
        k5["previous"] = json!(sha(&unb64(rs[3]["body"].as_str().unwrap())));
        k5["seq"] = json!(5);
        rs.push(swift_record(&k5, &a, &[]));
        rs
    };

    let recs_xy = xy_library(
        "2026-11-02T08:00:00Z",
        "2026-11-03T08:00:00Z",
        "2026-11-04T08:00:00Z",
    );
    let mut g = new_genesis(&recs_xy, 5, sg![a], "X vetoes");
    let gv = gveto(&g, &kx, sv);
    swift_case(o, "swift-veto-by-key-removed-earlier", &recs_xy, &mut g, after, json!({"succession": "verified", "seq3": "successionVetoed malformed"}),
               "X was removed at seq 4, before the last removal and more than the delay before the genesis: X's veto is invalid.", &a, false, 60, vec![gv]);
    let mut g = new_genesis(&recs_xy, 5, sg![a], "Y vetoes");
    let gv = gveto(&g, &ky, sv);
    swift_case(
        o,
        "swift-veto-by-last-removed",
        &recs_xy,
        &mut g,
        after,
        json!({"succession": "unverified"}),
        "Y was current immediately before the last removal: Y may veto.",
        &a,
        false,
        60,
        vec![gv],
    );
    // §15.1 step 3: the instant W0 minus the delay. An entry dated exactly then gives the state
    // after it, not the state before it: X, removed by that entry, can't veto.
    let w0 = {
        let mut probe = new_genesis(&recs, 2, sg![a], "probe");
        successor_with_home(&mut probe, 60, sr0 - 60);
        secs(&fstr(&probe.envs[1], "issued"))
    };
    let cutoff = w0 - D;
    let recs_c = xy_library(&ts(cutoff - 3600), &ts(cutoff), &ts(cutoff + 3600));
    let mut g = new_genesis(&recs_c, 5, sg![a], "X vetoes at the cutoff");
    let gv = gveto(&g, &kx, sv);
    swift_case(o, "swift-veto-by-key-removed-at-cutoff", &recs_c, &mut g, after, json!({"succession": "verified", "seq3": "successionVetoed malformed"}),
               "X was removed by an entry dated exactly W0 minus the delay: only the state after that entry is taken at that instant, so X is not eligible.", &a, false, 60, vec![gv]);
    let recs_w = xy_library(
        "2026-11-02T08:00:00Z",
        "2026-11-09T09:00:00Z",
        "2026-11-09T10:00:00Z",
    );
    let mut g = new_genesis(&recs_w, 5, sg![a], "X vetoes within delay");
    let gv = gveto(&g, &kx, sv);
    swift_case(o, "swift-veto-by-key-removed-within-delay", &recs_w, &mut g, after, json!({"succession": "unverified"}),
               "X was removed two replacements back, but was current within the successor's delay before the genesis: X may veto.", &a, false, 60, vec![gv]);

    let recs3 = swift_library(false);
    let pred3 = json!({"format": "colophon/swift-keyring/2", "account": &sha(&unb64(recs3[0]["body"].as_str().unwrap()))[..32],
                       "head": {"seq": 1, "digest": sha(&unb64(recs3[0]["body"].as_str().unwrap()))}});
    let root_ring = |label: &str, handover: Sl| {
        let mut g = Chain::new();
        genesis(
            &mut g,
            &keyring(
                vec![ct(&a, AC, "Mac"), ct(&k1, &["recover"], "Kit")],
                Kr {
                    rt: 1,
                    ..Kr::default()
                },
            ),
            sg![a],
            Gen {
                label,
                predecessor: Some(pred3.clone()),
                opt: Opt {
                    adds: sg![k1],
                    handover,
                    ..Opt::default()
                },
                ..Gen::default()
            },
        );
        g
    };
    let mut gr = root_ring("Root only", sg![*root_s]);
    swift_case(
        o,
        "swift-root-library",
        &recs3,
        &mut gr,
        after,
        json!({"succession": "verified"}),
        "Root library: the root alone signs handover.",
        &a,
        true,
        60,
        vec![],
    );
    let mut gr2 = root_ring("Kit vetoes", sg![*root_s]);
    let gv = gveto(&gr2, rec_s, sv);
    swift_case(
        o,
        "swift-root-library-kit-vetoes",
        &recs3,
        &mut gr2,
        after,
        json!({"succession": "unverified"}),
        "The current recovery kit vetoes the root's hand-over.",
        &a,
        true,
        60,
        vec![gv],
    );
    let mut gr3 = root_ring("Handover with kit", sg![*root_s, *rec_s]);
    let gv = gveto(&gr3, rec_s, sv);
    swift_case(
        o,
        "swift-handover-extra-key-raises-veto",
        &recs3,
        &mut gr3,
        after,
        json!({"succession": "verified", "seq3": "successionVetoed malformed"}),
        "handover carries the root and the kit: one key's veto is too few.",
        &a,
        true,
        60,
        vec![gv],
    );

    let wr = swift_webauthn_library();
    let same = vec![
        ct(&a, AC, "Mac"),
        cx_(
            sp,
            &["approve", "recover"],
            "Passkey",
            json!({"verification": true}),
        ),
        cx_(sy, AC, "Security key", json!({"verification": true})),
    ];
    let mut g = genesis_from(&wr, same, 1, sg![a], "Library");
    swift_case(
        o,
        "swift-webauthn",
        &wr,
        &mut g,
        after,
        json!({"succession": "verified"}),
        "Shipped-app keys with their roles carried over; F signed by WebAuthn.",
        sy,
        false,
        60,
        vec![],
    );
    let swap = || {
        vec![
            ct(&a, AC, "Mac"),
            cx_(sp, AC, "Passkey", json!({"verification": true})),
            cx_(
                sy,
                &["approve", "recover"],
                "Security key",
                json!({"verification": true}),
            ),
        ]
    };
    let mut g = genesis_from(&wr, swap(), 1, sg![a], "Swap");
    swift_case(
        o,
        "swift-webauthn-role-swap-without-consent",
        &wr,
        &mut g,
        after,
        json!({"succession": "unverified"}),
        "Recover set changed without SP.",
        sy,
        false,
        60,
        vec![],
    );
    let mut g = genesis_from(&wr, swap(), 1, sg![a, *sp], "Swap with consent");
    swift_case(o, "swift-webauthn-role-swap-with-consent", &wr, &mut g, after, json!({"succession": "verified"}),
               "A format test: the reference tool carries roles over, but a genesis may change them with consent.", sy, false, 60, vec![]);

    let g_thief = new_genesis(&recs, 2, sg![a], "Thief");
    let f_thief = swift_freeze_signed(&recs, &account_id(&g_thief), &a, &ts(sr0 + 60));
    let mut recs_t = recs.clone();
    recs_t.push(f_thief.clone());
    let mut g_owner = new_genesis(&recs_t, 3, sg![a], "Owner after premature freeze");
    let rg = successor_with_home(&mut g_owner, 60, sr0 + 120);
    let mut f2 = body_json(&f_thief);
    f2["layout"] = json!(4);
    f2["previous"] = json!(sha(&body_of(&f_thief)));
    f2["seq"] = json!(4);
    f2["issued"] = json!(ts(sr0 + after));
    f2["successor"] = json!(account_id(&g_owner));
    let mut all = recs_t.clone();
    all.push(swift_record(&f2, &a, &[]));
    let mut extra = succ_extra(&g_owner, &rg);
    extra.push(("thief-genesis.json".to_string(), g_thief.envs[0].clone()));
    write_swift(o, "swift-premature-freeze-then-owner", &all, Some(&g_owner),
                json!({"succession": "verified", "firstFreeze": "its succession was never due, so it doesn't end the predecessor"}),
                "A thief's premature freeze at seq 3, then the owner's verified attempt with a layout-4 freeze at seq 4.", extra);

    let mut g = new_genesis(&recs, 2, sg![a], "After final");
    let rg = successor_with_home(&mut g, 60, sr0 - 60);
    let f_af = swift_freeze_signed(&recs, &account_id(&g), &a, &ts(sr0 + after));
    let mut xo = body_json(&f_af);
    xo["seq"] = json!(4);
    xo["previous"] = json!(sha(&body_of(&f_af)));
    xo["issued"] = json!(ts(sr0 + after + 60));
    xo["layout"] = json!(4);
    let mut all = recs.clone();
    all.push(f_af);
    all.push(swift_record(&xo, &a, &[]));
    write_swift(
        o,
        "swift-entry-after-final",
        &all,
        Some(&g),
        json!({"succession": "verified", "evidence": "entry 4 is malformed evidence"}),
        "An entry after a verified F.",
        succ_extra(&g, &rg),
    );

    let mut keys = serde_json::Map::new();
    let mut listed: Vec<(String, Key)> = vec![
        ("home1".into(), h1k.clone()),
        ("home2".into(), h2k.clone()),
        ("successor-home".into(), sh.clone()),
        ("passkey".into(), p_key.clone()),
        ("new-device".into(), new.clone()),
        ("phone".into(), ph.clone()),
        ("phone/agreement".into(), derived("r5/phone/agreement")),
        ("approve-only".into(), appr.clone()),
        ("thief-x".into(), x.clone()),
        ("swift-x".into(), kx.clone()),
        ("swift-y".into(), ky.clone()),
    ];
    listed.extend((0..65).map(|i| (format!("rate/{i}"), derived(&format!("r5/rate/{i}")))));
    listed.extend(
        plant
            .iter()
            .enumerate()
            .map(|(i, k)| (format!("plant/{i}"), k.clone())),
    );
    listed.extend(
        five.iter()
            .enumerate()
            .map(|(i, k)| (format!("five/{i}"), k.clone())),
    );
    for (n, k) in &listed {
        keys.insert(
            n.clone(),
            json!({"id": k.id, "signing": b64(&k.point), "scalar": b64(&k.scalar)}),
        );
    }
    write(
        o,
        "rules/keys-r4.json",
        &json!({"warning": "PUBLIC TEST SECRETS. Never use these keys for real data.", "keys": keys}),
    );

    // Corrections after revision 11: builder questions 4 and 5.
    // An addition loses all of its witnesses through two later, final recovery revocations.
    let mut exc = base.clone();
    activate(&mut exc, &t_addc, &[rec(&cx, &t_addc)]);
    let exc_at1 = DUE0 + 60;
    let exc_t1 = prop(
        &cx,
        json!({"homes": {"revoke": [h1k.id]}}),
        sg![k1],
        Pr {
            at: exc_at1,
            chain: Some(&exc),
            ..Pr::default()
        },
    );
    activate(
        &mut exc,
        &exc_t1,
        &[receipt_of(&acct, &exc_t1, &h2k, &ts(exc_at1 + 1))],
    );
    let exc_due1 = exc_at1 + W + D;
    let hs = vec![head5(&exc, &h2k, exc_due1 + 10, Some(4))];
    final_of(&mut exc, 4, hs);
    let exc_at2 = exc_due1 + 60;
    let exc_t2 = prop(
        &cx,
        json!({"homes": {"revoke": [h2k.id]}}),
        sg![k1],
        Pr {
            at: exc_at2,
            chain: Some(&exc),
            ..Pr::default()
        },
    );
    activate(
        &mut exc,
        &exc_t2,
        &[receipt_of(&acct, &exc_t2, &h2k, &ts(exc_at2 + 1))],
    );
    let exc_due2 = exc_at2 + W + D;
    // No home remains; no `final` with empty heads is constructed.
    grant_agent(&mut exc, &new, &ts(exc_due2 + 60), &new);
    case_v(o, "t-all-witnesses-excused", &exc, json!({"result": "ok", "seq": 7, "finality": {"3": "final", "4": "final", "6": "final"}}),
           "Both original witnesses are finally revoked by recovery transitions. The earlier addition becomes final without an empty final, so NEW may sign.",
           &["8.7"], Some(ver(exc_due2 + 120)));

    // Revision 12, M1 (§8.6 rule 1, §8.7): finality by the fixed point counts as "a `final`
    // covers", and a `vetoed` that displaces an activation takes the later revocations with it.
    let v_addc = veto(&acct, &t_addc, sg![b], &ts(R0 + 600));
    let rv_addc = rec_at(&cx, &v_addc, R0 + 601);
    let mut addc_vetoed = base.clone();
    record_veto(
        &mut addc_vetoed,
        &t_addc,
        &[rec(&cx, &t_addc)],
        &v_addc,
        std::slice::from_ref(&rv_addc),
    );
    case(
        o,
        "t-excusal-final-not-displaced-by-vetoed",
        &exc,
        json!({"result": "ok", "seq": 7, "finality": {"3": "final", "4": "final", "6": "final"}}),
        "As t-all-witnesses-excused, with a valid `vetoed` of the addition at seq 3 held too. The addition is final by the fixed point on its own branch (both witnesses finally revoked), which counts as a `final` that covers it: it is not displaced, and NEW may sign.",
        &["8.6", "8.7"],
        vec![("veto", v_addc.clone()), ("veto-receipt", rv_addc.clone())],
        Some(ver(exc_due2 + 120)),
        vec![("vetoed", vec![(3, addc_vetoed.envs[2].clone())])],
    );
    case(
        o,
        "t-vetoed-displaces-activation-and-later-revocation",
        &addc_vetoed,
        ok_at(3),
        "A valid `vetoed` and a provisional activation of one addition at seq 3. On the activation's branch H1's revocation is final (seq 4, 5) but H2 still witnesses the addition, so no `final` covers it: the `vetoed` stands, the activation and the later revocation leave with the branch, and H1 and H2 stay current homes.",
        &["8.6", "8.7"],
        vec![("veto", v_addc.clone()), ("veto-receipt", rv_addc.clone())],
        Some(ver(exc_due2 + 120)),
        vec![(
            "activate",
            vec![
                (3, exc.envs[2].clone()),
                (4, exc.envs[3].clone()),
                (5, exc.envs[4].clone()),
            ],
        )],
    );

    // Revision 12 fix round, H1 (§8.6 rule 1, §8.7): an activation that is final in any way §8.7
    // gives is never displaced by a `vetoed`: here by a later `final` whose heads cover it, and
    // by a later full set whose anchor is the activation.
    let veto_objs = || vec![("veto", v_addc.clone()), ("veto-receipt", rv_addc.clone())];
    let mut casc = base.clone();
    activate(&mut casc, &t_addc, &[rec(&cx, &t_addc)]);
    let t_rm_ph = p(&cx, rm(&ph.id), sg![a]);
    activate(&mut casc, &t_rm_ph, &[rec(&cx, &t_rm_ph)]);
    let hs = vec![
        head5(&casc, &h1k, DUE0 + 100, Some(4)),
        head5(&casc, &h2k, DUE0 + 100, Some(4)),
    ];
    final_of(&mut casc, 4, hs);
    grant_agent(&mut casc, &new, &ts(DUE0 + 200), &new);
    case(
        o,
        "t-cascade-final-not-displaced-by-vetoed",
        &casc,
        json!({"result": "ok", "seq": 6, "finality": {"3": "final", "4": "final"}}),
        "The addition at seq 3 is final through the cascade: the `final` at seq 5 of the removal at seq 4 carries heads of both witnesses covering it. A valid `vetoed` of the addition at seq 3 is held too. A final activation is never displaced: the branch stands, and the grant signed by the added key at seq 6 is valid.",
        &["8.6", "8.7"],
        veto_objs(),
        Some(ver(DUE0 + 1000)),
        vec![("vetoed", vec![(3, addc_vetoed.envs[2].clone())])],
    );
    let mut fsc = base.clone();
    activate(&mut fsc, &t_addc, &[rec(&cx, &t_addc)]);
    let t_fs = prop(
        &cx,
        json!({"keyring": {"add": [ct(&x, AC, "Probe X")]}}),
        sg![a, ph, b],
        Pr {
            adds: sg![x],
            at: DUE0 + 30,
            chain: Some(&fsc),
            ..Pr::default()
        },
    );
    activate_full(&mut fsc, &t_fs, &[rec_at(&cx, &t_fs, DUE0 + 31)]);
    grant_agent(&mut fsc, &new, &ts(DUE0 + 200), &new);
    case(
        o,
        "t-full-set-final-not-displaced-by-vetoed",
        &fsc,
        json!({"result": "ok", "seq": 5, "finality": {"3": "final"}}),
        "The addition at seq 3 is final because a full set at seq 4 is anchored on it. A valid `vetoed` of the addition is held too. A final activation is never displaced: the unvetoable full set and the grant signed by the added key stay.",
        &["8.6", "8.7"],
        veto_objs(),
        Some(ver(DUE0 + 1000)),
        vec![("vetoed", vec![(3, addc_vetoed.envs[2].clone())])],
    );

    // Revision 12 fix round, M-a (§8.7 Order): a revocation of a home that also loosens policy is
    // not removal-only, so once final it revokes the home without excusing it. A later addition
    // whose witnesses are all excused still waits for the earlier provisional addition.
    let mut ord = base.clone();
    let t_rv = p(
        &cx,
        json!({"homes": {"revoke": [h2k.id]}, "policy": {"headMaxAge": 600}}),
        sg![a, k1],
    );
    activate(&mut ord, &t_rv, &[rec(&cx, &t_rv)]);
    activate(&mut ord, &t_addc, &[rec(&cx, &t_addc)]);
    let hs = vec![
        head5(&ord, &h1k, DUE0 + 100, Some(4)),
        head5(&ord, &h2k, DUE0 + 100, Some(4)),
    ];
    final_of(&mut ord, 3, hs);
    let t_a2 = prop(
        &cx,
        json!({"keyring": {"add": [ct(&x, AC, "Second addition")]}}),
        sg![a],
        Pr {
            adds: sg![x],
            ..Pr::default()
        },
    );
    activate(&mut ord, &t_a2, &[rec(&cx, &t_a2)]);
    let ord_at = DUE0 + 200;
    let t_r1 = prop(
        &cx,
        json!({"homes": {"revoke": [h1k.id]}}),
        sg![k1],
        Pr {
            at: ord_at,
            chain: Some(&ord),
            ..Pr::default()
        },
    );
    activate(
        &mut ord,
        &t_r1,
        &[receipt_of(&acct, &t_r1, &h1k, &ts(ord_at + 1))],
    );
    case_v(
        o,
        "t-order-guard-keeps-later-addition-provisional",
        &ord,
        json!({"result": "ok", "seq": 7, "finality": {"3": "final", "4": "provisional", "6": "provisional", "7": "final"}}),
        "Seq 3 revokes H2 and loosens a policy field (control rule), so it is not removal-only: final at seq 5, it revokes H2 without excusing it. Seq 4 adds a key (witnesses H1 and H2, still provisional); seq 6 adds another (witness H1 only); seq 7 revokes H1 by recovery and is final at once, excusing H1. Every witness of seq 6 is excused, but seq 4 is an earlier provisional addition, so Order keeps seq 6 provisional too.",
        &["8.7"],
        Some(ver(ord_at + W + D + 120)),
    );

    // Two activations of T with different receipts, with a final covering only the higher digest.
    let cy_t = p(&cx, rm(&b.id), sg![a]);
    let cy_r1 = rec(&cx, &cy_t);
    let cy_r2 = receipt_of(&acct, &cy_t, &h2k, &ts(R0 + 2));
    let mut cy_a1 = base.clone();
    activate(&mut cy_a1, &cy_t, std::slice::from_ref(&cy_r1));
    let mut cy_a2 = base.clone();
    activate(&mut cy_a2, &cy_t, std::slice::from_ref(&cy_r2));
    let mut cy = [cy_a1, cy_a2];
    cy.sort_by_key(|c_| sha(&c_.last()));
    let cy_hi_idx = 1;
    let mut cy_hi = cy[cy_hi_idx].clone();
    let cy_lo = cy[0].clone();
    let hs: Vec<Value> = [&h1k, &h2k]
        .iter()
        .map(|h| head5(&cy_hi, h, DUE0 + 30, Some(3)))
        .collect();
    final_of(&mut cy_hi, 3, hs);
    let cy_v = veto(&acct, &cy_t, sg![ph], &ts(R0 + 600));
    let mut cy_vc = base.clone();
    record_veto(
        &mut cy_vc,
        &cy_t,
        std::slice::from_ref(&cy_r1),
        &cy_v,
        &[rec_at(&cx, &cy_v, R0 + 601)],
    );
    case(o, "t-three-candidate-cycle", &cy_vc, json!({"result": "refused:fork", "seq": 3}),
         "Three valid candidates form a comparison cycle: low-digest activate, final-covered activate, and vetoed. Keep all as an unresolved fork.",
         &["8.6"], vec![], Some(ver(DUE0 + 60)),
         vec![("low", vec![(3, cy_lo.envs[2].clone())]), ("high", vec![(3, cy_hi.envs[2].clone()), (4, cy_hi.envs[3].clone())])]);

    // A unique winner may occur after an undecidable pair in digest order.
    let mut win_cs: Vec<Chain> = Vec::new();
    for i in 0..3 {
        let mut wc_ = base.clone();
        grant_agent_with(
            &mut wc_,
            &a,
            &ts(R0),
            &a,
            &derived(&format!("post11/winner/{i}")),
            &derived(&format!("post11/winner/{i}/agreement")),
            "2026-11-18T08:00:00Z",
        );
        win_cs.push(wc_);
    }
    win_cs.sort_by_key(|c_| sha(&c_.last()));
    case(o, "t-three-candidate-winner", base, json!({"standsAtSeq3": sha(&win_cs[2].last())}),
         "Only the greatest-digest candidate has a quorum head. It beats each other candidate even though their mutual comparison is undecided.",
         &["8.6"], vec![("head-winner", head5(&win_cs[2], &h1k, R0 + 30, None))], Some(ver(R0 + 60)),
         ["0", "1", "2"].iter().zip(win_cs.iter()).map(|(i, wc_)| (*i, vec![(3, wc_.envs[2].clone())])).collect());

    // A native /5 predecessor uses its own verifier and has terminal successor activation.
    let mut old5 = Chain::new();
    let old5kr = keyring(
        vec![ct(&a, AC, "Mac"), ct(&k1, &["recover"], "Kit")],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    genesis(
        &mut old5,
        &old5kr,
        sg![a],
        Gen {
            label: "Native predecessor",
            opt: Opt {
                adds: sg![k1],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let mut next5 = Chain::new();
    let pred5 = json!({"format": "colophon/authority/5", "account": account_id(&old5), "head": anchor(&old5)});
    genesis(
        &mut next5,
        &old5kr,
        sg![a],
        Gen {
            label: "Native successor",
            predecessor: Some(pred5),
            ..Gen::default()
        },
    );
    let t_succ = transition(
        &old5,
        json!({"successor": {"account": account_id(&next5)}}),
        sg![a, k1],
        &ts(60),
        TOpt::default(),
    );
    activate(&mut old5, &t_succ, &[]);
    // A chain A to B to C (§15.1): B is a successor of A and then hands over to C. C verifies
    // B through its own predecessor.
    let mut c5 = Chain::new();
    let pred_b = json!({"format": "colophon/authority/5", "account": account_id(&next5), "head": anchor(&next5)});
    genesis(
        &mut c5,
        &old5kr,
        sg![a],
        Gen {
            label: "Chained successor",
            predecessor: Some(pred_b),
            ..Gen::default()
        },
    );
    let mut b5 = next5.clone();
    let t_succ_b = transition(
        &b5,
        json!({"successor": {"account": account_id(&c5)}}),
        sg![a, k1],
        &ts(120),
        TOpt::default(),
    );
    activate(&mut b5, &t_succ_b, &[]);
    let mut chain_envs = old5.envs.clone();
    chain_envs.extend(b5.envs.iter().cloned());
    write_swift(
        o,
        "authority5-chain",
        &chain_envs,
        Some(&c5),
        json!({"succession": "verified"}),
        "A /5 predecessor that is itself a successor: A to B to C verifies with both histories.",
        vec![(
            "successor/authority/00000001.json".to_string(),
            c5.envs[0].clone(),
        )],
    );
    // Revision 12 fix round, H3 (§2.4, §15.1): the chain bound counts the accounts followed along
    // `predecessor` references. `k` predecessors are a chain of k accounts: 16 verify, 17 are
    // `malformed`. Each account is a `/5` successor of the one before, with no home.
    for (k, expected, why) in [
        (16, json!({"succession": "verified"}), "A chain of 16 predecessor accounts, each a `/5` successor of the one before: at the bound, so the succession is verified."),
        (17, json!({"succession": "unverified", "genesis": "malformed"}), "A chain of 17 predecessor accounts: one more than the bound, so the successor's genesis is `malformed`."),
    ] {
        let mut chains: Vec<Chain> = Vec::new();
        let adds_k1: Sl = sg![k1];
        for i in 0..=k {
            let mut c = Chain::new();
            let pred = (i > 0).then(|| {
                json!({"format": "colophon/authority/5", "account": account_id(&chains[i - 1]), "head": anchor(&chains[i - 1])})
            });
            genesis(
                &mut c,
                &old5kr,
                sg![a],
                Gen {
                    label: &format!("Chain account {i}"),
                    predecessor: pred,
                    opt: Opt {
                        adds: if i == 0 { adds_k1 } else { &[] },
                        ..Opt::default()
                    },
                    ..Gen::default()
                },
            );
            chains.push(c);
        }
        for i in 0..k {
            let t = transition(
                &chains[i],
                json!({"successor": {"account": account_id(&chains[i + 1])}}),
                sg![a, k1],
                &ts(60),
                TOpt::default(),
            );
            activate(&mut chains[i], &t, &[]);
        }
        let entries: Vec<Value> = chains[..k].iter().flat_map(|c| c.envs.clone()).collect();
        write_swift(
            o,
            &format!("authority5-chain-{k}"),
            &entries,
            Some(&chains[k]),
            expected,
            why,
            vec![(
                "successor/authority/00000001.json".to_string(),
                chains[k].envs[0].clone(),
            )],
        );
    }
    write_swift(
        o,
        "authority5-successor",
        &old5.envs,
        Some(&next5),
        json!({"succession": "verified"}),
        "A /5 predecessor terminates at its successor activation.",
        vec![(
            "successor/authority/00000001.json".to_string(),
            next5.envs[0].clone(),
        )],
    );

    // Revision 12, M2 (§8.7, §15.1): a /5 succession is verified only when F, the `successor`
    // activation, is final. The predecessor is the reference account with homes H1 and H2, so F
    // has witnesses and starts provisional.
    let mut sc = Chain::new();
    genesis(
        &mut sc,
        &kr5,
        sg![a],
        Gen {
            label: "Successor of a predecessor with homes",
            predecessor: Some(
                json!({"format": "colophon/authority/5", "account": acct, "head": anchor(base)}),
            ),
            ..Gen::default()
        },
    );
    let t_sf = p(
        &cx,
        json!({"successor": {"account": account_id(&sc)}}),
        sg![a, k1],
    );
    let r_sf = rec(&cx, &t_sf);
    let sc_extra = || {
        vec![(
            "successor/authority/00000001.json".to_string(),
            sc.envs[0].clone(),
        )]
    };
    let mut pm_prov = base.clone();
    activate(&mut pm_prov, &t_sf, std::slice::from_ref(&r_sf));
    write_swift(
        o,
        "authority5-successor-provisional",
        &pm_prov.envs,
        Some(&sc),
        json!({"succession": "unverified", "genesis": "held"}),
        "The predecessor has homes, so its `successor` activation F is provisional: its witnesses H1 and H2 have signed no head covering it, and no `final` follows. The succession is not verified. The successor's genesis lists the predecessor's keys with no possession proofs and so leans on the carried-key exemption, which needs a verified succession: it is held, neither `ok` nor refused.",
        sc_extra(),
    );
    let mut pm_final = pm_prov.clone();
    let hs = vec![
        head5(&pm_final, &h1k, DUE0 + 100, Some(3)),
        head5(&pm_final, &h2k, DUE0 + 100, Some(3)),
    ];
    final_of(&mut pm_final, 3, hs);
    write_swift(
        o,
        "authority5-successor-final",
        &pm_final.envs,
        Some(&sc),
        json!({"succession": "verified"}),
        "As authority5-successor-provisional, with the `final` of F (the heads of H1 and H2) at seq 4. F is final: the succession is verified, and the `final` is the only entry the predecessor admitted after F. The same genesis that was held is now `ok`.",
        sc_extra(),
    );
    // The vetoed succession's genesis carries a possession proof for every key, so it is valid
    // whether or not F stands (§8.4 Possession): the case is about the predecessor.
    let mut sc2 = Chain::new();
    genesis(
        &mut sc2,
        &kr5,
        sg![a],
        Gen {
            label: "Successor of a vetoed succession",
            predecessor: Some(
                json!({"format": "colophon/authority/5", "account": acct, "head": anchor(base)}),
            ),
            opt: Opt {
                adds: sg![ph, b, k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let t_sf2 = p(
        &cx,
        json!({"successor": {"account": account_id(&sc2)}}),
        sg![a, k1],
    );
    let r_sf2 = rec(&cx, &t_sf2);
    let mut pm_prov2 = base.clone();
    activate(&mut pm_prov2, &t_sf2, std::slice::from_ref(&r_sf2));
    let v_sf = veto(&acct, &t_sf2, sg![b, ph], &ts(R0 + 600));
    let rv_sf = rec_at(&cx, &v_sf, R0 + 601);
    let mut pm_vetoed = base.clone();
    record_veto(
        &mut pm_vetoed,
        &t_sf2,
        std::slice::from_ref(&r_sf2),
        &v_sf,
        std::slice::from_ref(&rv_sf),
    );
    grant_agent(&mut pm_vetoed, &a, &ts(DUE0 + 100), &a);
    let mut vetoed_recs = pm_vetoed.envs.clone();
    vetoed_recs.push(pm_prov2.envs[2].clone());
    write_swift(
        o,
        "authority5-successor-vetoed",
        &vetoed_recs,
        Some(&sc2),
        json!({"succession": "unverified", "predecessor": "continues: the `vetoed` stands at seq 3 and a grant follows at seq 4"}),
        "F (the `activate` of the `successor` transition) and a valid `vetoed` of that transition are both held at seq 3. The `vetoed` displaces the provisional F: the succession is not verified, and the predecessor continues with a grant at seq 4.",
        vec![(
            "successor/authority/00000001.json".to_string(),
            sc2.envs[0].clone(),
        )],
    );

    // The genesis of the first successor lists carried keys with no proofs. Held while F is
    // provisional, it is `badSignature` once a `vetoed` displaces F.
    let v_sf1 = veto(&acct, &t_sf, sg![b, ph], &ts(R0 + 600));
    let rv_sf1 = rec_at(&cx, &v_sf1, R0 + 601);
    let mut pm_vetoed1 = base.clone();
    record_veto(
        &mut pm_vetoed1,
        &t_sf,
        std::slice::from_ref(&r_sf),
        &v_sf1,
        std::slice::from_ref(&rv_sf1),
    );
    grant_agent(&mut pm_vetoed1, &a, &ts(DUE0 + 100), &a);
    let mut vetoed_recs1 = pm_vetoed1.envs.clone();
    vetoed_recs1.push(pm_prov.envs[2].clone());
    write_swift(
        o,
        "authority5-successor-vetoed-no-proofs",
        &vetoed_recs1,
        Some(&sc),
        json!({"succession": "unverified", "genesis": "badSignature"}),
        "As authority5-successor-provisional (a genesis with no possession proofs), but a valid `vetoed` displaces F at seq 3 and the predecessor continues. The succession is never verified, so the carried-key exemption never applies: the genesis that was held is `badSignature`.",
        sc_extra(),
    );

    // Revision 12 fix round, M-c (§15.1): a witness home that never signs cannot freeze the
    // predecessor. After a provisional F the predecessor admits a removal-only revocation of that
    // home (recovery rule, so the dead home isn't its own witness); once it is final the home is
    // excused for F, and F becomes final with the remaining witness's head.
    let mut pd = pm_prov.clone();
    let dead_at = DUE0 + 60;
    let t_dead = prop(
        &cx,
        json!({"homes": {"revoke": [h2k.id]}}),
        sg![k1],
        Pr {
            at: dead_at,
            chain: Some(&pd),
            ..Pr::default()
        },
    );
    activate(
        &mut pd,
        &t_dead,
        &[receipt_of(&acct, &t_dead, &h1k, &ts(dead_at + 1))],
    );
    let dead_due = dead_at + W + D;
    let hs = vec![head5(&pd, &h1k, dead_due + 100, Some(4))];
    final_of(&mut pd, 4, hs);
    let hs = vec![head5(&pd, &h1k, dead_due + 110, Some(3))];
    final_of(&mut pd, 3, hs);
    write_swift(
        o,
        "authority5-successor-dead-witness",
        &pd.envs,
        Some(&sc),
        json!({"succession": "verified", "now": "2026-11-18T00:00:00Z"}),
        "F (seq 3) is provisional and H2, one of its two witnesses, never signs a head. The owner revokes H2 under the recovery rule (seq 4, a removal-only home revocation the predecessor admits after F); its `final` carries H1's head (seq 5), which excuses H2; F's `final` with H1's head alone (seq 6) makes F final. The succession is verified.",
        sc_extra(),
    );
    // Not every `final` is admitted after a provisional F: a `final` of an earlier removal-only
    // activation is `malformed` evidence.
    let mut pe = base.clone();
    let t_x = p(&cx, rm(&b.id), sg![a]);
    activate(&mut pe, &t_x, &[rec(&cx, &t_x)]);
    let mut sc3 = Chain::new();
    genesis(
        &mut sc3,
        &kr5,
        sg![a],
        Gen {
            label: "Successor after an earlier removal",
            predecessor: Some(
                json!({"format": "colophon/authority/5", "account": acct, "head": anchor(&pe)}),
            ),
            opt: Opt {
                adds: sg![ph, b, k1, k2],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let f3_at = DUE0 + 10;
    let t_f3 = prop(
        &cx,
        json!({"successor": {"account": account_id(&sc3)}}),
        sg![a, k1],
        Pr {
            at: f3_at,
            chain: Some(&pe),
            ..Pr::default()
        },
    );
    activate(
        &mut pe,
        &t_f3,
        &[receipt_of(&acct, &t_f3, &h1k, &ts(f3_at + 1))],
    );
    let hs = vec![
        head5(&pe, &h1k, DUE0 + 100, Some(3)),
        head5(&pe, &h2k, DUE0 + 100, Some(3)),
    ];
    final_of(&mut pe, 3, hs);
    write_swift(
        o,
        "authority5-successor-final-of-earlier-removal",
        &pe.envs,
        Some(&sc3),
        json!({"succession": "unverified", "now": "2026-11-18T00:00:00Z", "predecessor": "stops at seq 4: the `final` at seq 5 is malformed evidence"}),
        "A removal-only activation at seq 3 is provisional, F follows at seq 4 (provisional), and a `final` of the seq 3 activation is appended at seq 5. After a provisional F the predecessor admits a `final` of F, of an earlier activation that is not removal-only, or of a home revocation; a `final` of an earlier removal-only activation is none of these, so the predecessor ends at seq 4 and the succession is not verified.",
        vec![(
            "successor/authority/00000001.json".to_string(),
            sc3.envs[0].clone(),
        )],
    );
}

fn statuses(id: &str, status: &str) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(id.to_string(), json!(status));
    json!({"controllers": m})
}

fn rm_two(x: &str, y: &str) -> Value {
    json!({"keyring": {"remove": [x, y]}})
}

fn wc(o: &mut Out, name: &str, chain: &Chain, expected: Value, why: &str, sections: &[&str]) {
    write_case(
        o,
        name,
        chain,
        expected,
        why,
        sections,
        vec![],
        None,
        vec![],
    );
}
