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

/// The independent check's fix round (2026-11-16): homes that expire (§8.5, §8.7), a suspended
/// key's `suspend` (§8.7), and the layout raise's remaining paths to finality and conflict.
fn fix_round(o: &mut Out) {
    let (a, b, k1) = (A.clone(), B.clone(), K1.clone());
    const E1: i64 = 2 * 86_400; // a home's expiry: 2026-11-13T08:00:00Z
    let after = E1 + 3_600;

    // The only home expires; then a transition revokes it, and another appoints a new home.
    // Neither needs a receipt (no current home at its `issued`) and each is final at once.
    let (base, keys) = account(&[(&a, AC)], 0, 1, &[("Home one", Some(E1))], sg![a]);
    let mut c = base.clone();
    let t = transition(&c, json!({"homes": {"revoke": [keys[0].id]}}), sg![a], &ts(after));
    activate(&mut c, &t, &[]);
    wc(
        o,
        "f2-home-expired-then-revoked",
        &c,
        ok_at(3),
        "The account's only home has expired: it is not current (§8.5), so the transition revoking it needs no receipt, is due when issued and has no witness.",
        &["8.5", "8.7", "13.5"],
    );
    let acct = account_id(&base);
    let mut c = base.clone();
    let (h2, _) = appointment(&acct, "Home two", None);
    let t = transition(&c, json!({"homes": {"appoint": [h2]}}), sg![a], &ts(after));
    activate(&mut c, &t, &[]);
    wc(
        o,
        "f2-home-expired-then-replaced",
        &c,
        ok_at(3),
        "The account's only home has expired; a transition appointing a new home needs no receipt and is final at once.",
        &["8.5", "8.7"],
    );

    // Two homes at headQuorum 2; one expires. A later transition needs one receipt (the
    // unexpired home's) and has that home alone as witness; its `final` carries one head.
    let (base, keys) = account(
        &[(&a, AC)],
        0,
        2,
        &[("Home one", Some(E1)), ("Home two", None)],
        sg![a],
    );
    let acct = account_id(&base);
    let h2 = keys[1].clone();
    let mut c = base.clone();
    let t = transition(&c, json!({"policy": {"callWindow": 120}}), sg![a], &ts(after));
    let r = receipt_of(&acct, &t, &h2, &ts(after + 1));
    activate(&mut c, &t, &[r]);
    let head = head_of(&c, &h2, after + W + D + 60, 3);
    final_of(&mut c, 3, &head);
    wc(
        o,
        "f2-home-one-of-two-expired",
        &c,
        ok_at(4),
        "headQuorum 2 with two homes, one expired: the transition needs the receipt of the one current home (at most the current homes), which alone witnesses it, and its final carries that home's head.",
        &["8.5", "8.7", "13.5"],
    );

    // A receipt from the only home, given before it expires; the home expires before the
    // activation, so the activation has no witness and is final at once. The transition raises
    // the layout, so finality shows as the stop.
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
        bad("newerFormat", 3),
        "The only home receipts a layout raise and expires before its due time: the receipt counts (judged at the transition's issued), the home is no witness of the activation (judged at its issued), so the raise is final at once and the reader stops.",
        &["8.5", "8.7", "20"],
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
