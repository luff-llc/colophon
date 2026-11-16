//! Freeze package, stream W1-A authority: the 0.5 candidate vectors this stream generates.
//! Only that stream edits this file (`docs/design-freeze-package.md`, §0 "Order of work").
//!
//! Every case is built from the published test keys and keys derived from fixed labels
//! (synthetic, never real data). Helpers are local copies of the shapes `cases_v8.rs` uses, so
//! this file depends only on `kit.rs`.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
use super::kit::*;
use serde_json::{json, Value};

const D: i64 = 259_200; // recoveryDelay default, seconds
const W: i64 = 300; // receipt window, seconds
const R0: i64 = 3_600;
const DUE0: i64 = R0 + W + D;
const AC: &[&str] = &["approve", "control"];
const EXPIRES: &str = "2026-11-18T08:00:00Z";

fn anchor(chain: &Chain) -> Value {
    json!({"seq": chain.envs.len(), "digest": sha(&body_of(chain.envs.last().unwrap()))})
}

fn transition_body(chain: &Chain, change: Value, signers: Sl, issued: &str) -> Value {
    json!({"protocol": "colophon/transition/5", "account": account_id(chain), "anchor": anchor(chain),
           "issued": issued, "by": signers[0].id(), "signers": ids_sorted(signers), "change": change})
}

fn seal_t(body: &Value, signers: Sl, adds: Sl) -> Value {
    let (primary, cos) = signers.split_first().unwrap();
    seal(
        body,
        *primary,
        Opt {
            cos,
            adds,
            ..Opt::default()
        },
    )
}

fn transition(chain: &Chain, change: Value, signers: Sl, issued: &str) -> Value {
    seal_t(
        &transition_body(chain, change, signers, issued),
        signers,
        &[],
    )
}

fn receipt_body(acct: &str, env: &Value, home: &Key, received: &str) -> Value {
    json!({"protocol": "colophon/receipt/5", "account": acct, "object": sha(&body_of(env)),
           "received": received, "by": home.id})
}

fn receipt_of(acct: &str, env: &Value, home: &Key, received: &str) -> Value {
    envelope(&receipt_body(acct, env, home, received), home)
}

fn prev_issued(chain: &Chain) -> i64 {
    secs(
        body_json(chain.envs.last().unwrap())["issued"]
            .as_str()
            .unwrap(),
    )
}

fn append_unsigned(chain: &mut Chain, kind: &str, by_id: &str, issued: &str, fields: Value) {
    let mut body = json!({"protocol": "colophon/authority/5", "seq": chain.envs.len() + 1,
                          "previous": sha(&chain.last()), "issued": issued, "by": by_id, "kind": kind});
    for (k, v) in fields.as_object().unwrap() {
        body[k] = v.clone();
    }
    chain.envs.push(json!({"body": b64(&canonical(&body))}));
}

/// `activate` of `t` with its receipts (quorum 1); due at issued without a home, else issued +
/// W + D.
fn activate_with(chain: &mut Chain, t: &Value, receipts: &[Value], extra: Value) {
    let issued = secs(&fstr(t, "issued"));
    let due = if receipts.is_empty() {
        issued
    } else {
        issued + W + D
    };
    let at = ts(due.max(prev_issued(chain)));
    let mut fields = json!({"transition": emb(t), "receipts": receipts.iter().map(emb).collect::<Vec<_>>()});
    if let Value::Object(m) = extra {
        for (k, v) in m {
            fields[k] = v;
        }
    }
    append_unsigned(chain, "activate", &fstr(t, "by"), &at, fields);
}
fn activate(chain: &mut Chain, t: &Value, receipts: &[Value]) {
    activate_with(chain, t, receipts, json!({}));
}

fn home_appointment(acct: &str, home_k: &Key, home_a: &Key, label: &str) -> Value {
    let req = request(
        acct,
        home_k,
        home_a,
        "server",
        json!({"serves": ["home"]}),
        label,
        Some(json!({"endpoints": [format!("https://{}.example/v1/accounts/{acct}", label.to_lowercase().replace(' ', ""))]})),
    );
    json!({"request": req, "terms": {"serves": ["home"]}})
}

fn agent_component(acct: &str, k: &Key, a: &Key) -> Value {
    let t = json!({"services": [{"audience": AUD, "purposes": ["task.read"]}]});
    let req = request(acct, k, a, "agent", t.clone(), "Agent", None);
    let mut terms = t;
    terms["expires"] = json!(EXPIRES);
    json!({"request": req, "terms": terms})
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

/// An account of one controller A (approve, control), threshold 1, no home.
fn plain() -> (Chain, Value) {
    let a = A.clone();
    let kr = keyring(vec![ctrl(&a, AC, Some("Mac"), json!({}))], Kr::default());
    let mut c = Chain::new();
    genesis(&mut c, &kr, sg![a], Gen::default());
    (c, kr)
}

/// An account of A (approve, control) and B (approve only), with one home H1 appointed and
/// final at seq 2.
fn with_home() -> (Chain, Key) {
    with_home_b(&["approve"])
}

/// As [`with_home`], with B holding `b_roles`.
fn with_home_b(b_roles: &[&str]) -> (Chain, Key) {
    let (a, b) = (A.clone(), B.clone());
    let (h1k, h1a) = (derived("w1a/home1/signing"), derived("w1a/home1/agreement"));
    let kr = keyring(
        vec![
            ctrl(&a, AC, Some("Mac"), json!({})),
            ctrl(&b, b_roles, Some("Passkey"), json!({})),
        ],
        Kr::default(),
    );
    let mut c = Chain::new();
    genesis(
        &mut c,
        &kr,
        sg![a],
        Gen {
            opt: Opt {
                adds: sg![b],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let acct = account_id(&c);
    let t = transition(
        &c,
        json!({"homes": {"appoint": [home_appointment(&acct, &h1k, &h1a, "Home one")]}}),
        sg![a],
        &ts(60),
    );
    activate(&mut c, &t, &[]);
    (c, h1k)
}

fn end_sessions(chain: &mut Chain, member: &Key, issued: &str, extra: Value) {
    let mut fields = json!({"member": member.id});
    if let Value::Object(m) = extra {
        for (k, v) in m {
            fields[k] = v;
        }
    }
    chain.add(
        "endSessions",
        member,
        issued,
        member,
        Opt::default(),
        fields,
    );
}

pub fn part(o: &mut Out) {
    f2(o);
    f3(o);
    f3_final(o);
    fix_round(o);
    head_expiry(o);
    drop_home(o);
}

fn head_of(chain: &Chain, home: &Key, at: i64, seq: usize) -> Value {
    envelope(
        &json!({"protocol": "colophon/head/5", "account": account_id(chain),
                "authority": {"seq": seq, "digest": sha(&body_of(&chain.envs[seq - 1]))},
                "issued": ts(at), "by": home.id}),
        home,
    )
}

/// §8.7 `final` of the activation at `act_seq`, with one head.
fn final_of(chain: &mut Chain, act_seq: usize, head: &Value) {
    let act = body_json(&chain.envs[act_seq - 1]);
    let issued = ts(secs(&fstr(head, "issued")).max(prev_issued(chain)));
    let digest = sha(&body_of(&chain.envs[act_seq - 1]));
    append_unsigned(
        chain,
        "final",
        act["by"].as_str().unwrap(),
        &issued,
        json!({"activation": {"seq": act_seq, "digest": digest}, "heads": [emb(head)]}),
    );
}

fn veto_of(acct: &str, t: &Value, signer: &Key, issued: &str) -> Value {
    envelope(
        &json!({"protocol": "colophon/veto/5", "account": acct, "transition": sha(&body_of(t)),
                "issued": issued, "by": signer.id, "signers": [signer.id]}),
        signer,
    )
}

/// The stop comes when the raise is final (§8.7 "Final"; owner's decision of 2026-11-16), so a
/// raise that is vetoed or loses a fork never strands a 0.5 reader. Account: A and B (approve,
/// control), threshold 1, home H1 (quorum 1); the raise is signed by A at R0 and receipted by H1.
fn f3_final(o: &mut Out) {
    let (a, b) = (A.clone(), B.clone());
    let (base, h1k) = with_home_b(AC);
    let acct = account_id(&base);
    let t = transition(&base, json!({"layout": 3}), sg![a], &ts(R0));
    let r = receipt_of(&acct, &t, &h1k, &ts(R0 + 1));
    let mut provisional = base.clone();
    activate(&mut provisional, &t, std::slice::from_ref(&r));
    wc(
        o,
        "f3-raise-provisional",
        &provisional,
        ok_at(3),
        "A layout raise activated but not final (its home has signed no head over it): it changes no rule this reader applies, so the reader is not stopped.",
        &["8.7", "20"],
    );
    let head = head_of(&provisional, &h1k, DUE0 + 60, 3);
    let mut fin = provisional.clone();
    final_of(&mut fin, 3, &head);
    wc(
        o,
        "f3-raise-final",
        &fin,
        bad("newerFormat", 3),
        "A layout raise made final by its home's head: the reader is stopped at the raising activation.",
        &["1", "8.7", "20"],
    );
    let mut after = fin.clone();
    grant_agent(&mut after, &a, &ts(DUE0 + 120), &a);
    wc(
        o,
        "f3-raise-final-then-entry",
        &after,
        bad("newerFormat", 3),
        "An entry after a final layout raise is not applied: the reader is stopped at the raise.",
        &["1", "20"],
    );

    // Vetoed in its window by B: the vetoed entry displaces the provisional activation (§8.6),
    // nothing stops, and the history continues.
    let v = veto_of(&acct, &t, &b, &ts(R0 + 10));
    let vr = receipt_of(&acct, &v, &h1k, &ts(R0 + 11));
    let mut vetoed = base.clone();
    append_unsigned(
        &mut vetoed,
        "vetoed",
        &b.id,
        &ts(R0 + 11),
        json!({"transition": emb(&t), "transitionReceipts": [emb(&r)], "veto": emb(&v), "receipts": [emb(&vr)]}),
    );
    grant_agent(&mut vetoed, &a, &ts(R0 + 20), &a);
    write_case(
        o,
        "f3-raise-vetoed",
        &vetoed,
        ok_at(4),
        "A layout raise vetoed in its window, with the provisional activation also held: the vetoed entry stands, the reader is not stopped, and a later grant applies.",
        &["8.6", "8.7", "20"],
        vec![],
        None,
        vec![("activate".into(), vec![(3, provisional.envs[2].clone())])],
    );

    // A fork at seq 3 between a grant covered by the primary home's head and the provisional
    // raise: the grant stands (§8.6), so the raise is on the losing branch and stops nothing.
    let mut granted = base.clone();
    grant_agent(&mut granted, &a, &ts(R0 + 100), &a);
    let gh = head_of(&granted, &h1k, R0 + 200, 3);
    write_case(
        o,
        "f3-raise-losing-fork",
        &granted,
        ok_at(3),
        "A provisional layout raise loses a conflict at its seq to a grant the primary home's head covers: the reader follows the grant and is not stopped.",
        &["8.6", "20"],
        vec![("objects/head.json".into(), gh)],
        None,
        vec![("raise".into(), vec![(3, provisional.envs[2].clone())])],
    );
}

/// F3, the upgrade door (§8.2 "Layout", §20; design §3).
fn f3(o: &mut Out) {
    let (a, k1) = (A.clone(), K1.clone());
    let layout = |v: Value, signers: Sl| {
        let (mut c, _) = plain();
        let t = transition(&c, json!({"layout": v}), signers, &ts(60));
        activate(&mut c, &t, &[]);
        c
    };
    wc(
        o,
        "f3-layout-3",
        &layout(json!(3), sg![a]),
        bad("newerFormat", 2),
        "A transition raising the layout to 3 under the control rule (no recovery set). With no home its activation is final at once, so the reader is stopped there: newerFormat at the activate.",
        &["8.2", "8.7", "20"],
    );
    wc(
        o,
        "f3-layout-2",
        &layout(json!(2), sg![a]),
        bad("malformed", 2),
        "A layout component of 2 in an account at layout 2 does not raise the layout: the transition is void, malformed at its activate.",
        &["8.2", "8.7"],
    );
    wc(
        o,
        "f3-layout-not-integer",
        &layout(json!("3"), sg![a]),
        bad("malformed", 2),
        "A layout component that is not an integer is malformed.",
        &["8.2"],
    );
    let mut c = layout(json!(3), sg![a]);
    grant_agent(&mut c, &a, &ts(120), &a);
    wc(
        o,
        "f3-layout-then-entry",
        &c,
        bad("newerFormat", 2),
        "A layout raise, then a grant: the reader stops at the raise and applies nothing after it.",
        &["1", "8.2"],
    );
    // With a recovery set, raising the layout needs its consent (§8.4).
    let kr = keyring(
        vec![
            ctrl(&a, AC, Some("Mac"), json!({})),
            ctrl(&k1, &["recover"], Some("Security key"), json!({})),
        ],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let mut c = Chain::new();
    genesis(
        &mut c,
        &kr,
        sg![a],
        Gen {
            opt: Opt {
                adds: sg![k1],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let t = transition(&c, json!({"layout": 3}), sg![a], &ts(60));
    activate(&mut c, &t, &[]);
    wc(
        o,
        "f3-layout-3-no-consent",
        &c,
        bad("badSignature", 2),
        "A layout raise signed by the control rule without the recovery set's consent: badSignature.",
        &["8.4", "8.5"],
    );

    // `upgrade/then-v5-layout` (built by `cases_a.rs`) sets layout 2 in an account already at
    // layout 2: under F3 that transition is void. Its entries are unchanged; its expectation is
    // replaced here. `upgrade/then-v5-layout-3` keeps the case's intent with a real raise.
    let dir = "upgrade/then-v5-layout";
    let case: Value = serde_json::from_slice(&o[&format!("{dir}/case.json")]).unwrap();
    let mut voided = case.clone();
    voided["description"] =
        json!("A layout component that does not raise the layout voids the transition.");
    voided["expected"]["colophon-0.5"] = json!("malformed");
    voided["sections"] = json!(["5.1", "8.2", "8.5", "16.1"]);
    write(o, &format!("{dir}/case.json"), &voided);
    let mut raised = case;
    raised["description"] = json!(
        "After the upgrade, a /5 transition raising the layout to 3 under the control rule: the upgrade door, newerFormat."
    );
    raised["expected"]["colophon-0.5"] = json!("newerFormat");
    raised["sections"] = json!(["5.1", "8.2", "16.1", "20"]);
    let dir3 = "upgrade/then-v5-layout-3";
    for seq in 1..=3 {
        let rel = format!("records/authority/{seq:08}.json");
        let data = o[&format!("{dir}/{rel}")].clone();
        write_raw(o, &format!("{dir3}/{rel}"), data);
    }
    let rel4 = "records/authority/00000004.json";
    let act: Value = serde_json::from_slice(&o[&format!("{dir}/{rel4}")]).unwrap();
    let mut act_body = body_json(&act);
    let t_env: Value =
        serde_json::from_slice(&unb64(act_body["transition"].as_str().unwrap())).unwrap();
    let mut t_body = body_json(&t_env);
    t_body["change"]["layout"] = json!(3);
    let signer = software(t_body["by"].as_str().unwrap()).unwrap();
    act_body["transition"] = json!(emb(&envelope(&t_body, &signer)));
    // As `cases_a.rs` writes the extension entry: canonical bytes, no trailing newline.
    write_raw(
        o,
        &format!("{dir3}/{rel4}"),
        canonical(&json!({"body": b64(&canonical(&act_body))})),
    );
    write(o, &format!("{dir3}/case.json"), &raised);
}

/// F2 (§8.5 "Current principal"; design §2).
fn f2(o: &mut Out) {
    let (a, b, k1) = (A.clone(), B.clone(), K1.clone());
    let (ak, aa) = (AGENT_K.clone(), AGENT_A.clone());

    // A member granted at seq 2 with expiry EXPIRES; its own endSessions after that instant.
    let (mut base, _) = plain();
    grant_agent(&mut base, &a, &ts(60), &a);
    let mut c = base.clone();
    end_sessions(&mut c, &ak, "2026-11-19T08:00:00Z", json!({}));
    wc(
        o,
        "f2-end-sessions-expired-member",
        &c,
        bad("badSignature", 3),
        "A member's own endSessions issued after its expiry: the member rule needs a current principal (§8.5), so it is badSignature.",
        &["8.5", "9.6"],
    );
    let mut c = base.clone();
    end_sessions(
        &mut c,
        &ak,
        "2026-11-19T08:00:00Z",
        json!({"later": true}),
    );
    wc(
        o,
        "f2-end-sessions-expired-unknown-field",
        &c,
        bad("badSignature", 3),
        "An expired member's endSessions with an unknown field: currency is checked before unknown content, so badSignature, never newerFormat.",
        &["1", "8.5"],
    );
    let mut c = base.clone();
    end_sessions(&mut c, &ak, &ts(120), json!({"later": true}));
    wc(
        o,
        "f2-end-sessions-current-unknown-field",
        &c,
        bad("newerFormat", 3),
        "A current member's own endSessions with an unknown field: the member rule holds, then the unknown field is newerFormat.",
        &["1", "8.5"],
    );

    // A member added by a transition whose activation is not final (one home, no `final`).
    let (mut c, h1k) = with_home();
    let acct = account_id(&c);
    let t = transition(&c, json!({"grant": agent_component(&acct, &ak, &aa)}), sg![a], &ts(R0));
    let r = receipt_of(&acct, &t, &h1k, &ts(R0 + 1));
    activate(&mut c, &t, &[r]);
    end_sessions(&mut c, &ak, &ts(DUE0 + 60), json!({}));
    wc(
        o,
        "f2-end-sessions-provisional-member",
        &c,
        bad("badSignature", 4),
        "The endSessions of a member added by an activation that is not final yet: a provisional member is not a current principal (§8.5).",
        &["8.5", "8.7"],
    );

    // Unknown entry kinds keep the control rule (§8.5 step 3).
    let (mut c, _) = with_home();
    c.add(
        "later",
        &b,
        &ts(120),
        &b,
        Opt::default(),
        json!({"value": 1}),
    );
    wc(
        o,
        "f2-unknown-kind-single-approve",
        &c,
        bad("badSignature", 3),
        "An unknown entry kind signed by one approve-only key: unknown kinds need the control rule, which it does not meet.",
        &["8.4", "8.5"],
    );
    let (mut c, _) = with_home();
    c.add(
        "later",
        &a,
        &ts(120),
        &a,
        Opt::default(),
        json!({"value": 1}),
    );
    wc(
        o,
        "f2-unknown-kind-control-rule",
        &c,
        bad("newerFormat", 3),
        "An unknown entry kind under the control rule: newerFormat, and the reader stops.",
        &["1", "8.5"],
    );

    // Unknown transition components keep the control rule (§8.7 "Unknown components").
    let (mut c, _) = plain();
    let t = transition(&c, json!({"later": {"value": 1}}), sg![a], &ts(60));
    activate(&mut c, &t, &[]);
    wc(
        o,
        "f2-unknown-component-control-rule",
        &c,
        bad("newerFormat", 2),
        "A transition whose only component is unknown, under the control rule: newerFormat at its activate.",
        &["8.5", "8.7"],
    );
    let kr = keyring(
        vec![
            ctrl(&a, AC, Some("Mac"), json!({})),
            ctrl(&k1, &["recover"], Some("Security key"), json!({})),
        ],
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let mut c = Chain::new();
    genesis(
        &mut c,
        &kr,
        sg![a],
        Gen {
            opt: Opt {
                adds: sg![k1],
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let t = transition(&c, json!({"later": {"value": 1}}), sg![k1], &ts(60));
    activate(&mut c, &t, &[]);
    wc(
        o,
        "f2-unknown-component-recovery-rule",
        &c,
        bad("badSignature", 2),
        "A transition whose only component is unknown, signed by the recovery rule alone: unknown components need the control rule, so badSignature.",
        &["8.4", "8.7"],
    );
}

/// A home's appointment item, optionally with an expiry in its granted terms.
fn appointment(acct: &str, label: &str, expires: Option<i64>) -> (Value, Key) {
    let slug = label.to_lowercase().replace(' ', "");
    let (k, a) = (
        derived(&format!("w1a/{slug}/signing")),
        derived(&format!("w1a/{slug}/agreement")),
    );
    let mut item = home_appointment(acct, &k, &a, label);
    if let Some(e) = expires {
        item["terms"]["expires"] = json!(ts(e));
    }
    (item, k)
}

/// An account of `ctrls` (the first is primary; the others prove possession), `rt` recover units,
/// `quorum` as `headQuorum`, and homes appointed at once at 60 s by `appointers` (final then,
/// there being no home before).
fn account(
    ctrls: &[(&Key, &[&str])],
    rt: i64,
    quorum: i64,
    homes: &[(&str, Option<i64>)],
    appointers: Sl,
) -> (Chain, Vec<Key>) {
    let kr = keyring(
        ctrls
            .iter()
            .map(|(k, r)| ctrl(*k, r, None, json!({})))
            .collect(),
        Kr {
            rt,
            policy: Some(policy_with(&[("headQuorum", json!(quorum))])),
            ..Kr::default()
        },
    );
    let adds: Vec<&dyn Signer> = ctrls[1..].iter().map(|(k, _)| *k as &dyn Signer).collect();
    let mut c = Chain::new();
    genesis(
        &mut c,
        &kr,
        &[ctrls[0].0 as &dyn Signer],
        Gen {
            opt: Opt {
                adds: &adds,
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    let acct = account_id(&c);
    let (items, keys): (Vec<Value>, Vec<Key>) = homes
        .iter()
        .map(|(l, e)| appointment(&acct, l, *e))
        .unzip();
    if !items.is_empty() {
        let t = transition(&c, json!({"homes": {"appoint": items}}), appointers, &ts(60));
        activate(&mut c, &t, &[]);
    }
    (c, keys)
}

/// The independent checks' fix rounds (2026-11-16): a home's term never ends its witnessing
/// (§8.5, §8.7), a suspended key's `suspend` (§8.7), a revoked home's later head (§8.6), and the
/// layout raise's remaining paths to finality and conflict.
fn fix_round(o: &mut Out) {
    let (a, b, k1) = (A.clone(), B.clone(), K1.clone());
    const E1: i64 = 2 * 86_400; // a home's expiry: 2026-11-13T08:00:00Z
    let after = E1 + 3_600;

    // The only home's grant has expired. It still witnesses: a transition needs its receipt,
    // which is accepted, and waits the recovery delay.
    let (base, keys) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", Some(E1))], sg![a]);
    let acct = account_id(&base);
    let h1 = keys[0].clone();
    let t = transition(&base, json!({"policy": {"callWindow": 120}}), sg![a], &ts(after));
    let r = receipt_of(&acct, &t, &h1, &ts(after + 1));
    let mut c = base.clone();
    activate(&mut c, &t, std::slice::from_ref(&r));
    wc(
        o,
        "f2-home-expired-still-witnesses",
        &c,
        ok_at(3),
        "The only home's grant has expired; it still witnesses (a home's term bounds what it serves, never its witnessing, §8.5): its receipt is accepted and the activation waits issued + 300 s + recoveryDelay.",
        &["8.5", "8.7", "13.5"],
    );
    let mut c = base.clone();
    append_unsigned(
        &mut c,
        "activate",
        &a.id,
        &ts(after),
        json!({"transition": emb(&t), "receipts": []}),
    );
    wc(
        o,
        "f2-home-expired-receipt-required",
        &c,
        bad("malformed", 3),
        "The same transition activated at once with no receipt, as if the expired home did not count: its receipt is still required, so the activate is malformed. A date never removes the veto window.",
        &["8.5", "8.7"],
    );
    // The expired home will not witness its own removal: the stronger authority (a full set, A
    // and B) revokes it, its receipt still taken, and the activation leaves it out of the
    // witnesses, so it is final at once.
    let t = transition(&base, json!({"homes": {"revoke": [h1.id]}}), sg![a, b], &ts(after));
    let r = receipt_of(&acct, &t, &h1, &ts(after + 1));
    let mut c = base.clone();
    append_unsigned(
        &mut c,
        "activate",
        &a.id,
        &ts(after + 1),
        json!({"transition": emb(&t), "receipts": [emb(&r)]}),
    );
    grant_agent(&mut c, &a, &ts(after + 60), &a);
    wc(
        o,
        "f2-home-expired-revoked-by-full-set",
        &c,
        ok_at(4),
        "The only home's grant has expired and it will not witness its removal: a full set revokes it (its receipt still required), leaving it out of the witnesses, so the revocation is final at once and the history continues.",
        &["8.7"],
    );

    // headQuorum 2 with two homes, one expired: both receipts are still required, both homes
    // witness, and the final carries both heads.
    let (base, keys) = account(
        &[(&a, AC)],
        0,
        2,
        &[("Home one", Some(E1)), ("Home two", None)],
        sg![a],
    );
    let acct = account_id(&base);
    let mut c = base.clone();
    let t = transition(&c, json!({"policy": {"callWindow": 120}}), sg![a], &ts(after));
    let mut rs: Vec<Value> = keys
        .iter()
        .map(|h| receipt_of(&acct, &t, h, &ts(after + 1)))
        .collect();
    rs.sort_by_key(|r| fstr(r, "by"));
    activate(&mut c, &t, &rs);
    let mut hs: Vec<Value> = keys
        .iter()
        .map(|h| head_of(&c, h, after + W + D + 60, 3))
        .collect();
    hs.sort_by_key(|h| fstr(h, "by"));
    let issued = ts(secs(&fstr(&hs[0], "issued")).max(prev_issued(&c)));
    let digest = sha(&body_of(&c.envs[2]));
    append_unsigned(
        &mut c,
        "final",
        &a.id,
        &issued,
        json!({"activation": {"seq": 3, "digest": digest}, "heads": hs.iter().map(emb).collect::<Vec<_>>()}),
    );
    wc(
        o,
        "f2-home-one-of-two-expired",
        &c,
        ok_at(4),
        "headQuorum 2 with two homes, one of whose grants has expired: both still witness, so the transition carries both receipts and its final both heads.",
        &["8.5", "8.7", "13.5"],
    );

    // A receipt from the only home, which then expires before the activation: the home still
    // witnesses, so a layout raise stays provisional and the reader is not stopped.
    let e2 = R0 + 86_400;
    let (base, keys) = account(&[(&a, AC)], 0, 1, &[("Home one", Some(e2))], sg![a]);
    let acct = account_id(&base);
    let mut c = base.clone();
    let t = transition(&c, json!({"layout": 3}), sg![a], &ts(R0));
    let r = receipt_of(&acct, &t, &keys[0], &ts(R0 + 1));
    activate(&mut c, &t, &[r]);
    wc(
        o,
        "f2-home-expired-before-due",
        &c,
        ok_at(3),
        "The only home receipts a layout raise and its grant expires before the due time: it still witnesses the activation, so the raise is provisional and the reader is not stopped.",
        &["8.5", "8.7", "20"],
    );

    // A revoked home's later head decides nothing (§8.6): on X's branch a full set finally
    // revokes the primary home H1 at seq 4, and H1 then signs a head at seq 4 covering X. It
    // does not count, so the recording entry Y stands at seq 3.
    let (base, keys) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let acct = account_id(&base);
    let h1 = keys[0].clone();
    let ty = transition(&base, json!({"policy": {"callWindow": 120}}), sg![a], &ts(R0));
    let ry = receipt_of(&acct, &ty, &h1, &ts(R0 + 1));
    let mut y = base.clone();
    activate(&mut y, &ty, &[ry]);
    let mut x = base.clone();
    grant_agent(&mut x, &a, &ts(R0 + 100), &a);
    let tr = transition(&x, json!({"homes": {"revoke": [h1.id]}}), sg![a, b], &ts(R0 + 200));
    let rr = receipt_of(&acct, &tr, &h1, &ts(R0 + 201));
    append_unsigned(
        &mut x,
        "activate",
        &a.id,
        &ts(R0 + 201),
        json!({"transition": emb(&tr), "receipts": [emb(&rr)]}),
    );
    let head = head_of(&x, &h1, R0 + 300, 4);
    write_case(
        o,
        "f2-head-revoked-at-head-seq",
        &y,
        ok_at(3),
        "The primary home is finally revoked at seq 4 on X's branch and then signs a head at seq 4 covering X: it is not a current home there, so the head counts for nothing and the activate at seq 3 stands.",
        &["8.6", "8.7"],
        vec![("objects/head.json".into(), head)],
        None,
        vec![(
            "x".into(),
            vec![(3, x.envs[2].clone()), (4, x.envs[3].clone())],
        )],
    );

    // A suspends B; B, now suspended, signs a suspend of A: badSignature (§8.7).
    let (mut c, _) = account(&[(&a, AC), (&b, AC)], 0, 1, &[], sg![a]);
    let t1 = transition(&c, json!({"keyring": {"remove": [b.id]}}), sg![a], &ts(60));
    c.add(
        "suspend",
        &a,
        &ts(120),
        &a,
        Opt::default(),
        json!({"key": b.id, "transition": emb(&t1), "receipts": []}),
    );
    let t2 = transition(&c, json!({"keyring": {"remove": [a.id]}}), sg![b], &ts(130));
    c.add(
        "suspend",
        &b,
        &ts(140),
        &b,
        Opt::default(),
        json!({"key": a.id, "transition": emb(&t2), "receipts": []}),
    );
    wc(
        o,
        "f2-suspended-key-suspends",
        &c,
        bad("badSignature", 3),
        "A suspends B; B, while suspended, signs a suspend of A. A suspended key may sign transitions and vetoes but not a suspend (§8.7): badSignature.",
        &["8.5", "8.7"],
    );

    // A raise made final by a later full set's anchor (A and B both sign, all control keys).
    let (base, keys) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let acct = account_id(&base);
    let h1 = keys[0].clone();
    let mut c = base.clone();
    let t = transition(&c, json!({"layout": 3}), sg![a], &ts(R0));
    let r = receipt_of(&acct, &t, &h1, &ts(R0 + 1));
    activate(&mut c, &t, &[r]);
    let at = DUE0 + 60;
    let t2 = transition(&c, json!({"policy": {"callWindow": 120}}), sg![a, b], &ts(at));
    let r2 = receipt_of(&acct, &t2, &h1, &ts(at + 1));
    append_unsigned(
        &mut c,
        "activate",
        &a.id,
        &ts(at + 1),
        json!({"transition": emb(&t2), "receipts": [emb(&r2)]}),
    );
    wc(
        o,
        "f3-raise-final-by-full-set",
        &c,
        bad("newerFormat", 3),
        "A provisional layout raise, then a full set anchored at it: the full set's anchor makes the raise final (§8.7), so the reader stops at the raise.",
        &["8.7", "20"],
    );

    // A raise made final by excusal: the recovery key alone revokes the only home, removal-only
    // and with no witness, so the home is excused and the raise has no remaining witness.
    // B (control) does not sign the raise, so A and K1 are not a full set.
    let (base, keys) = account(
        &[(&a, AC), (&b, AC), (&k1, &["recover"])],
        1,
        1,
        &[("Home one", None)],
        sg![a, k1],
    );
    let acct = account_id(&base);
    let h1 = keys[0].clone();
    let mut c = base.clone();
    let t = transition(&c, json!({"layout": 3}), sg![a, k1], &ts(R0));
    let r = receipt_of(&acct, &t, &h1, &ts(R0 + 1));
    activate(&mut c, &t, &[r]);
    let at = DUE0 + 60;
    let t2 = transition(&c, json!({"homes": {"revoke": [h1.id]}}), sg![k1], &ts(at));
    let r2 = receipt_of(&acct, &t2, &h1, &ts(at + 1));
    activate(&mut c, &t2, &[r2]);
    wc(
        o,
        "f3-raise-final-by-excusal",
        &c,
        bad("newerFormat", 3),
        "A provisional layout raise whose only witness is then revoked by the recovery rule (removal-only, final at once): the home is excused, the raise has no remaining witness and is final, so the reader stops at the raise.",
        &["8.7", "20"],
    );

    // A raise with another component applies or voids as a whole.
    let one = |change: Value| {
        let (mut c, _) = plain();
        let t = transition(&c, change, sg![a], &ts(60));
        activate(&mut c, &t, &[]);
        c
    };
    wc(
        o,
        "f3-raise-with-policy",
        &one(json!({"layout": 3, "policy": {"callWindow": 120}})),
        bad("newerFormat", 2),
        "A layout raise together with a policy change, no home: the transition applies as a whole and is final at once, so the reader stops at it.",
        &["8.7", "20"],
    );
    let a_other = ctrl(&a, &["approve"], Some("Mac"), json!({}));
    wc(
        o,
        "f3-raise-with-void-component",
        &one(json!({"layout": 3, "keyring": {"add": [a_other]}})),
        bad("malformed", 2),
        "A layout raise together with a component that voids the transition (adding a present key with other roles): the whole transition is void, malformed, and nothing stops.",
        &["8.7", "20"],
    );

    // A fork at seq 3 (two grants, no home to decide it), resolved by a `resolve` activation on
    // one branch. The raise rides on the kept branch, then on the discarded one.
    let (base, _) = plain();
    let (x_k, x_a) = (derived("w1a/agent-x/signing"), derived("w1a/agent-x/agreement"));
    let (y_k, y_a) = (derived("w1a/agent-y/signing"), derived("w1a/agent-y/agreement"));
    let mut x = base.clone();
    grant_agent_with(&mut x, &a, &ts(60), &a, &x_k, &x_a, EXPIRES);
    let mut y = base.clone();
    grant_agent_with(&mut y, &a, &ts(61), &a, &y_k, &y_a, EXPIRES);
    let x2 = sha(&body_of(&x.envs[1]));
    let resolve = |c: &Chain, raise: bool| {
        let mut change = json!({"resolve": {"kept": {"seq": 2, "digest": x2}}});
        if raise {
            change["layout"] = json!(3);
        }
        transition(c, change, sg![a], &ts(120))
    };
    let mut kept = x.clone();
    let t = resolve(&kept, true);
    activate(&mut kept, &t, &[]);
    write_case(
        o,
        "f3-raise-on-kept-branch",
        &kept,
        bad("newerFormat", 3),
        "A fork at seq 2 resolved by a resolve activation that also raises the layout: the branch keeps itself, the raise is final at once (no home), and the reader stops at it.",
        &["8.6", "20"],
        vec![],
        None,
        vec![("y".into(), vec![(2, y.envs[1].clone())])],
    );
    let mut kept = x.clone();
    let t = resolve(&kept, false);
    activate(&mut kept, &t, &[]);
    let mut lost = y.clone();
    let t = transition(&lost, json!({"layout": 3}), sg![a], &ts(120));
    activate(&mut lost, &t, &[]);
    write_case(
        o,
        "f3-raise-on-discarded-branch",
        &kept,
        ok_at(3),
        "A fork at seq 2: one branch raises the layout, the other resolves the fork in its own favour. The resolve wins, the raising branch is discarded, and nothing stops.",
        &["8.6", "20"],
        vec![],
        None,
        vec![(
            "y".into(),
            vec![(2, lost.envs[1].clone()), (3, lost.envs[2].clone())],
        )],
    );
}

/// §8.6: a head counts only when its home is current and unexpired at the head's own `issued`
/// (the spec owner's decision of 2026-11-16). The only home H1, also the primary home, expires
/// at `e`; the primary is never re-chosen by expiry.
fn head_expiry(o: &mut Out) {
    let a = A.clone();
    // After the activate's due time, so the home witnesses it and it is not final at once.
    let e = DUE0 + 86_400;
    let (base, keys) = account(&[(&a, AC)], 0, 1, &[("Home one", Some(e))], sg![a]);
    let acct = account_id(&base);
    let h1 = keys[0].clone();
    // A recording entry (an `activate` of a policy transition) against a grant at seq 3.
    let t = transition(&base, json!({"policy": {"callWindow": 120}}), sg![a], &ts(R0));
    let r = receipt_of(&acct, &t, &h1, &ts(R0 + 1));
    let mut act = base.clone();
    activate(&mut act, &t, &[r]);
    let mut granted = base.clone();
    grant_agent(&mut granted, &a, &ts(R0 + 100), &a);
    let late = head_of(&granted, &h1, e + 100, 3);
    // Each winner gets an entry at seq 4, so the verdict's seq shows which branch stood.
    let (z_k, z_a) = (derived("w1a/agent-z/signing"), derived("w1a/agent-z/agreement"));
    let mut act4 = act.clone();
    grant_agent_with(&mut act4, &a, &ts(DUE0 + 60), &a, &z_k, &z_a, EXPIRES);
    let mut granted4 = granted.clone();
    grant_agent_with(&mut granted4, &a, &ts(R0 + 300), &a, &z_k, &z_a, EXPIRES);
    write_case(
        o,
        "f2-head-expired-primary-no-displace",
        &act4,
        ok_at(4),
        "A grant conflicts with an activate at seq 3; the primary home's head covering the grant was issued after that home expired, so it counts for nothing and the activate stands.",
        &["8.6", "13.3"],
        vec![("objects/head.json".into(), late)],
        None,
        vec![("grant".into(), vec![(3, granted.envs[2].clone())])],
    );
    let early = head_of(&granted, &h1, R0 + 200, 3);
    write_case(
        o,
        "f2-head-before-expiry-counts",
        &granted4,
        ok_at(4),
        "The same conflict with the primary home's head issued before the home expired: it counts, and the grant it covers stands against the activate.",
        &["8.6", "13.3"],
        vec![("objects/head.json".into(), early)],
        None,
        vec![("activate".into(), vec![(3, act.envs[2].clone())])],
    );
    // Two grants at seq 3; headQuorum 1; the only head covering one of them was issued after its
    // home expired, so neither is covered by headQuorum current homes: a fork.
    let (y_k, y_a) = (derived("w1a/agent-y/signing"), derived("w1a/agent-y/agreement"));
    let mut other = base.clone();
    grant_agent_with(&mut other, &a, &ts(R0 + 101), &a, &y_k, &y_a, EXPIRES);
    write_case(
        o,
        "f2-head-expired-not-quorum",
        &granted,
        bad("refused:fork", 3),
        "Two grants conflict at seq 3 at headQuorum 1; the only head, covering one of them, was issued after its home expired, so it does not count toward headQuorum and the conflict stays a fork.",
        &["8.6", "13.3"],
        vec![("objects/head.json".into(), late_head(&granted, &h1, e))],
        None,
        vec![("other".into(), vec![(3, other.envs[2].clone())])],
    );
}

fn late_head(chain: &Chain, home: &Key, expiry: i64) -> Value {
    head_of(chain, home, expiry + 100, 3)
}

/// Append an `activate` of `t` at `issued` carrying `receipts` (no due-time arithmetic).
fn activate_at(chain: &mut Chain, t: &Value, receipts: &[Value], issued: i64) {
    append_unsigned(
        chain,
        "activate",
        &fstr(t, "by"),
        &ts(issued),
        json!({"transition": emb(t), "receipts": receipts.iter().map(emb).collect::<Vec<_>>()}),
    );
}

/// A policy transition by `by` activated at once with no receipt: valid only with no home.
fn no_home_step(chain: &mut Chain, by: Key, at: i64) {
    let t = transition(chain, json!({"policy": {"callWindow": 120}}), sg![by], &ts(at));
    activate_at(chain, &t, &[], at);
}

/// §8.7 "Revoking a home": a full set leaves the homes it revokes out of its receipts, as out of
/// its witnesses (the spec owner's decision of 2026-11-16, before the freeze). A home that is
/// gone or refuses can be dropped by the stronger authority; nothing else changes.
fn drop_home(o: &mut Out) {
    let (a, b, k1, k2) = (A.clone(), B.clone(), K1.clone(), K2.clone());
    let at = R0;

    // Full set (b): A and B, every control key in two units, drop the only home, which never
    // answers. No receipt; due at its `issued`; no witness, so final at once.
    let (base, _) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let h1_id = derived("w1a/homeone/signing").id;
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a, b], &ts(at));
    let mut dropped = base.clone();
    activate_at(&mut dropped, &t, &[], at);
    let mut c = dropped.clone();
    no_home_step(&mut c, a.clone(), at + 60);
    wc(
        o,
        "f2-drop-home-full-set-b",
        &c,
        ok_at(4),
        "Every control key (A and B, two units) signs a full set that revokes the only home, which never answers. The home it revokes is left out of its receipts as out of its witnesses: no receipt, due at its issued, final at once. The account then has no home: a transition at seq 4 activates at once with no receipt.",
        &["8.7"],
    );

    // Then a new home is appointed under the no-home rules, and it receipts what follows.
    let mut c = dropped.clone();
    let (item, h2) = appointment(&account_id(&c), "Home two", None);
    let t2 = transition(&c, json!({"homes": {"appoint": [item]}}), sg![a], &ts(at + 60));
    activate_at(&mut c, &t2, &[], at + 60);
    let t3 = transition(&c, json!({"policy": {"callWindow": 120}}), sg![a], &ts(at + 120));
    let r3 = receipt_of(&account_id(&c), &t3, &h2, &ts(at + 121));
    activate(&mut c, &t3, &[r3]);
    wc(
        o,
        "f2-drop-home-then-appoint",
        &c,
        ok_at(5),
        "After a full set drops the only home (seq 3), A appoints a new home with no receipt, as an account with no home does (seq 4); the new home then receipts a transition that waits the recovery delay (seq 5).",
        &["8.7"],
    );

    // Full set (a): both recovery keys (two units, recoverThreshold 2) drop the only home.
    let (base, _) = account(
        &[(&a, AC), (&k1, &["recover"]), (&k2, &["recover"])],
        2,
        1,
        &[("Home one", None)],
        sg![a, k1, k2],
    );
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![k1, k2], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at);
    no_home_step(&mut c, a.clone(), at + 60);
    wc(
        o,
        "f2-drop-home-full-set-a",
        &c,
        ok_at(4),
        "Every recovery key (two units, the recovery rule) signs a full set that revokes the only home, which never answers: no receipt, due at its issued, final at once; the account then has no home.",
        &["8.7"],
    );

    // Full set (a) whose signers also meet the control rule. A holds control and recover, B
    // (control) is lost, K1 holds recover; threshold 1, recoverThreshold 2. A and K1 are every
    // recovery controller in two units: a full set (a), whichever rule it is otherwise judged
    // under, though not a full set (b) (B did not sign).
    let acr: &[&str] = &["approve", "control", "recover"];
    let dual = |extra: bool| {
        let mut ctrls: Vec<(&Key, &[&str])> = vec![(&a, acr), (&b, AC), (&k1, &["recover"])];
        if extra {
            ctrls.push((&k2, &["recover"]));
        }
        account(&ctrls, 2, 1, &[("Home one", None)], sg![a, k1]).0
    };
    let base = dual(false);
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a, k1], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at);
    no_home_step(&mut c, a.clone(), at + 60);
    wc(
        o,
        "f2-drop-home-full-set-a-dual-role",
        &c,
        ok_at(4),
        "A (control and recover) and K1 (recover) are every recovery controller, two units; B (control) is lost and does not sign. A alone also meets the control rule, but the transition is still a full set (a): it drops the silent only home with no receipt, final at once, and the account then has no home.",
        &["8.7"],
    );
    // The same signers when a second recovery key K2 exists and does not sign: not every
    // recovery controller, so no full set, and the home's receipt is required.
    let base = dual(true);
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a, k1], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at + W + D);
    wc(
        o,
        "f2-drop-home-dual-role-not-full",
        &c,
        bad("malformed", 3),
        "As f2-drop-home-full-set-a-dual-role, but a second recovery key K2 exists and does not sign: A and K1 are not every recovery controller, so the transition is no full set and needs the only home's receipt: malformed.",
        &["8.7"],
    );
    // Full set (a)'s signers on a transition the recovery rule may not make (a layout raise): it
    // is judged under the control rule only, is no full set, and needs the home's receipt.
    let base = dual(false);
    let t = transition(&base, json!({"layout": 3}), sg![a, k1], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at);
    wc(
        o,
        "f2-dual-role-full-a-component-not-recovery",
        &c,
        bad("malformed", 3),
        "A and K1, every recovery controller in two units, sign a layout raise, which the recovery rule may not make even as a full set. Being a full set (a) lets no component through that rule's own checks refuse: the raise is judged under the control rule, is no full set (B did not sign) and needs the only home's receipt, so an activate without it is malformed.",
        &["8.7", "20"],
    );

    // headQuorum 2, two homes; a full set revokes Home one. Only the remaining home's receipt is
    // required, and it alone witnesses: its head alone makes the activation final.
    let (base, keys) = account(
        &[(&a, AC), (&b, AC)],
        0,
        2,
        &[("Home one", None), ("Home two", None)],
        sg![a],
    );
    let acct = account_id(&base);
    let (h1, h2) = (keys[0].clone(), keys[1].clone());
    let t = transition(&base, json!({"homes": {"revoke": [h1.id]}}), sg![a, b], &ts(at));
    let r2 = receipt_of(&acct, &t, &h2, &ts(at + 1));
    let mut c = base.clone();
    activate_at(&mut c, &t, std::slice::from_ref(&r2), at + 1);
    let head = head_of(&c, &h2, at + 60, 3);
    final_of(&mut c, 3, &head);
    wc(
        o,
        "f2-drop-one-of-two-homes",
        &c,
        ok_at(4),
        "headQuorum 2 with two homes: a full set revokes Home one. Its receipts are required from min(headQuorum, remaining homes) = 1 remaining home, so Home two's receipt alone suffices, due at its received; Home two alone witnesses, and a final with its head alone makes the activation final.",
        &["8.7"],
    );
    let mut c = base.clone();
    let r1 = receipt_of(&acct, &t, &h1, &ts(at + 1));
    activate_at(&mut c, &t, std::slice::from_ref(&r1), at + 1);
    wc(
        o,
        "f2-drop-one-of-two-homes-revoked-receipt-only",
        &c,
        bad("malformed", 3),
        "The same full set carrying only the receipt of the home it revokes: that is neither headQuorum receipts from the homes current before it (two) nor one from a remaining home, so the activate is malformed.",
        &["8.7"],
    );

    // The same revocation of the only home under the control rule (A alone, not a full set),
    // with no receipt: still refused. It can be vetoed, and the home witnesses its window.
    let (base, _) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at + W + D);
    wc(
        o,
        "f2-drop-home-control-rule-no-receipt",
        &c,
        bad("malformed", 3),
        "A alone (the control rule, not a full set: B did not sign) revokes the only home with no receipt. It can be vetoed, so it still needs the home's receipt: malformed.",
        &["8.7"],
    );

    // Under the recovery rule, not a full set (K1 of K1 and K2, recoverThreshold 1): still refused.
    let (base, _) = account(
        &[(&a, AC), (&k1, &["recover"]), (&k2, &["recover"])],
        1,
        1,
        &[("Home one", None)],
        sg![a, k1],
    );
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![k1], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at + W + D);
    wc(
        o,
        "f2-drop-home-recovery-rule-no-receipt",
        &c,
        bad("malformed", 3),
        "K1 alone (the recovery rule, not a full set: K2 did not sign) revokes the only home with no receipt. It can be vetoed, so it still needs the home's receipt: malformed.",
        &["8.7"],
    );

    // A single control unit is never a full set: its revocation of the home needs the receipt.
    let (base, _) = account(&[(&a, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at);
    wc(
        o,
        "f2-drop-home-one-unit",
        &c,
        bad("malformed", 3),
        "The account's only controller, one unit, revokes the only home with no receipt. One unit is never a full set, so the receipt is required: malformed.",
        &["8.7"],
    );
    // One control key and one recovery key are two units: together they are a full set (b) (every
    // control key, with the recovery key's consent), so they can drop the home.
    let (base, _) = account(
        &[(&a, AC), (&k1, &["recover"])],
        1,
        1,
        &[("Home one", None)],
        sg![a, k1],
    );
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a, k1], &ts(at));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[], at);
    no_home_step(&mut c, a.clone(), at + 60);
    wc(
        o,
        "f2-drop-home-one-control-one-recovery",
        &c,
        ok_at(4),
        "One control key and one recovery key, two units: together they are a full set (b), every control key with the recovery key's consent, so they drop the only home with no receipt; the account then has no home.",
        &["8.7"],
    );

    // A backdated full set with no home remaining. Its `issued` is bounded below by its anchor's
    // `issued` and by the 7-day bound: the activate's `issued` is max(due, previous) and at most
    // 7 days after due, so a full set issued more than 7 days before the entry it follows is
    // malformed.
    let (base, _) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a, b], &ts(120));
    let mut c = base.clone();
    let later = 120 + 8 * 86_400;
    grant_agent(&mut c, &a, &ts(later), &a);
    activate_at(&mut c, &t, &[], later);
    wc(
        o,
        "f2-drop-home-full-set-backdated",
        &c,
        bad("malformed", 4),
        "A full set that drops the only home, anchored at seq 2 and issued 8 days before the entry at seq 3. With no home remaining it is due at its issued; the activate must be issued at max(due, previous) and no more than 7 days after due, so it is malformed. A full set's issued is bounded by its anchor's issued and by the 7-day bound, as in an account with no home.",
        &["8.7"],
    );
    // The same within the bound: issued a day before the entry it follows, it is recorded.
    let mut c = base.clone();
    let later = 120 + 86_400;
    grant_agent(&mut c, &a, &ts(later), &a);
    activate_at(&mut c, &t, &[], later);
    wc(
        o,
        "f2-drop-home-full-set-within-bound",
        &c,
        ok_at(4),
        "The same full set, issued a day before the entry at seq 3: within the 7-day bound, the activate at max(due, previous) is ok and the only home is dropped.",
        &["8.7"],
    );

    // The only home receipts the full set that drops it anyway: still ok (the homes current
    // before it, counted as before), and the account then has no home.
    let (base, keys) = account(&[(&a, AC), (&b, AC)], 0, 1, &[("Home one", None)], sg![a]);
    let t = transition(&base, json!({"homes": {"revoke": [h1_id]}}), sg![a, b], &ts(at));
    let r = receipt_of(&account_id(&base), &t, &keys[0], &ts(at + 5));
    let mut c = base.clone();
    activate_at(&mut c, &t, &[r], at + 5);
    no_home_step(&mut c, a.clone(), at + 60);
    wc(
        o,
        "f2-drop-home-full-set-with-receipt",
        &c,
        ok_at(4),
        "A full set that drops the only home carries that home's receipt anyway: still ok (headQuorum receipts from the homes current before it), due at the receipt's received, final at once; the account then has no home.",
        &["8.7"],
    );
}
