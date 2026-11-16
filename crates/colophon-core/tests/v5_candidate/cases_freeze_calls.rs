//! Freeze package, stream W2-C calls: the 0.5 candidate vectors this stream generates.
//! Only that stream edits this file (`docs/design-freeze-package.md`, §0 "Order of work").
//!
//! S, a stopped reader trusts nothing new (§1 "A stop", §12.3 step 4; design §S, finding 4). One
//! account (controllers A: approve, control and B: control; an agent granted at seq 2; a home
//! appointed at seq 3) and one transition raising the layout to 3, in three outcomes:
//! - **final** (seq 4 activates it, seq 5 is its `final` with the home's head, seq 6 revokes the
//!   agent): the reader is stopped and cannot see seq 6, so every call is `unavailable`, even
//!   under the home's fresh head at seq 3 (N−1);
//! - **provisional** (seq 4 activates it, no `final`): the reader is not stopped, the call is
//!   judged as usual;
//! - **vetoed** (seq 4 records B's veto): the reader is not stopped, the call is judged as usual.
//! The same call over seqs 1–3 alone is `ok`.
//!
//! Every key is derived from a fixed label or is a published test key (synthetic, never real
//! data). Helpers are local copies of the shapes `cases_v8.rs` and `cases_freeze_authority.rs`
//! use, so this file depends only on `kit.rs`.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
use super::kit::*;
use serde_json::{json, Value};

const D: i64 = 259_200; // recoveryDelay default, seconds
const W: i64 = 300; // receipt window, seconds
const AC: &[&str] = &["approve", "control"];
const EXPIRES: &str = "2026-11-18T08:00:00Z";
/// The raise's `issued`, its due time, and the clock of every case.
const RAISE: i64 = 120;
const DUE: i64 = RAISE + W + D;
const NOW: i64 = DUE + 120;

fn anchor(chain: &Chain) -> Value {
    json!({"seq": chain.envs.len(), "digest": sha(&body_of(chain.envs.last().unwrap()))})
}

fn transition(chain: &Chain, change: Value, signer: &Key, issued: &str) -> Value {
    let body = json!({"protocol": "colophon/transition/5", "account": account_id(chain),
                      "anchor": anchor(chain), "issued": issued, "by": signer.id,
                      "signers": [signer.id], "change": change});
    seal(&body, signer, Opt::default())
}

fn veto(chain: &Chain, t: &Value, signer: &Key, issued: &str) -> Value {
    let body = json!({"protocol": "colophon/veto/5", "account": account_id(chain),
                      "transition": sha(&body_of(t)), "issued": issued, "by": signer.id,
                      "signers": [signer.id]});
    seal(&body, signer, Opt::default())
}

fn receipt_of(acct: &str, env: &Value, home: &Key, received: &str) -> Value {
    envelope(
        &json!({"protocol": "colophon/receipt/5", "account": acct, "object": sha(&body_of(env)),
                "received": received, "by": home.id}),
        home,
    )
}

fn head(chain: &Chain, home: &Key, seq: usize, at: i64) -> Value {
    envelope(
        &json!({"protocol": "colophon/head/5", "account": account_id(chain),
                "authority": {"seq": seq, "digest": sha(&body_of(&chain.envs[seq - 1]))},
                "issued": ts(at), "by": home.id}),
        home,
    )
}

/// An unsigned recording entry (`activate`, `vetoed`, `final`).
fn append_unsigned(chain: &mut Chain, kind: &str, by: &str, at: &str, fields: Value) {
    let mut body = json!({"protocol": "colophon/authority/5", "seq": chain.envs.len() + 1,
                          "previous": sha(&chain.last()), "issued": at, "by": by, "kind": kind});
    for (k, v) in fields.as_object().unwrap() {
        body[k] = v.clone();
    }
    chain.envs.push(json!({"body": b64(&canonical(&body))}));
}

/// The account before the raise, and its parts.
struct Base {
    chain: Chain,
    a: Key,
    b: Key,
    agent: Key,
    home: Key,
    endpoint: String,
}

/// Seq 1 genesis (A: approve, control; B: control; threshold 1); seq 2 grants the agent; seq 3
/// appoints the home (due when issued: no home before it).
fn base() -> Base {
    let (a, b) = (A.clone(), B.clone());
    let (agent, agent_a) = (derived("w2c/agent/signing"), derived("w2c/agent/agreement"));
    let (home, home_a) = (derived("w2c/home/signing"), derived("w2c/home/agreement"));
    let kr = keyring(
        vec![
            ctrl(&a, AC, Some("Mac"), json!({})),
            ctrl(&b, &["control"], Some("Phone"), json!({})),
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
    grant_agent_with(&mut c, &a, &ts(30), &a, &agent, &agent_a, EXPIRES);
    let endpoint = format!("https://home.example/v1/accounts/{acct}");
    let req = request(
        &acct,
        &home,
        &home_a,
        "server",
        json!({"serves": ["home"]}),
        "Home",
        Some(json!({"endpoints": [endpoint]})),
    );
    let t_home = transition(
        &c,
        json!({"homes": {"appoint": [{"request": req, "terms": {"serves": ["home"]}}]}}),
        &a,
        &ts(60),
    );
    append_unsigned(
        &mut c,
        "activate",
        &a.id,
        &ts(60),
        json!({"transition": emb(&t_home), "receipts": []}),
    );
    Base {
        chain: c,
        a,
        b,
        agent,
        home,
        endpoint,
    }
}

/// The raise and the home's receipt of it.
fn raise(base: &Base) -> (Value, Value) {
    let t = transition(&base.chain, json!({"layout": 3}), &base.a, &ts(RAISE));
    let r = receipt_of(&account_id(&base.chain), &t, &base.home, &ts(RAISE + 1));
    (t, r)
}

/// Seq 4 activates the raise (due after W + D, the home's receipt).
fn activated(base: &Base) -> Chain {
    let (t, r) = raise(base);
    let mut c = base.chain.clone();
    append_unsigned(
        &mut c,
        "activate",
        &base.a.id,
        &ts(DUE),
        json!({"transition": emb(&t), "receipts": [emb(&r)]}),
    );
    c
}

/// Seq 5 makes the raise final (the home's head over seq 4); seq 6 revokes the agent.
fn final_then_revoke(base: &Base) -> Chain {
    let mut c = activated(base);
    let h4 = head(&c, &base.home, 4, DUE + 30);
    let digest = sha(&body_of(&c.envs[3]));
    append_unsigned(
        &mut c,
        "final",
        &base.a.id,
        &ts(DUE + 30),
        json!({"activation": {"seq": 4, "digest": digest}, "heads": [emb(&h4)]}),
    );
    c.add(
        "revoke",
        &base.a,
        &ts(DUE + 60),
        &base.a,
        Opt::default(),
        json!({"member": base.agent.id, "kept": [], "heads": [], "epochs": []}),
    );
    c
}

/// Seq 4 records B's veto of the raise (inside its deadline, the home's receipts of both).
fn vetoed(base: &Base) -> Chain {
    let (t, r) = raise(base);
    let v = veto(&base.chain, &t, &base.b, &ts(600));
    let rv = receipt_of(&account_id(&base.chain), &v, &base.home, &ts(601));
    let mut c = base.chain.clone();
    append_unsigned(
        &mut c,
        "vetoed",
        &base.b.id,
        &ts(601),
        json!({"transition": emb(&t), "transitionReceipts": [emb(&r)], "veto": emb(&v),
               "receipts": [emb(&rv)]}),
    );
    c
}

/// The agent's call with its own key, `asOf` seq 3, at the clock.
fn call(base: &Base, audience: &str, purpose: &str, rid: &str) -> Value {
    let env3 = &base.chain.envs[2];
    envelope(
        &json!({"protocol": "colophon/call/5", "account": account_id(&base.chain),
                "asOf": {"seq": 3, "digest": sha(&body_of(env3))},
                "signer": {"member": base.agent.id}, "key": b64(&base.agent.point),
                "audience": audience, "purpose": purpose, "args": {},
                "requestId": b64url(&sha_raw(format!("w2c/request/{rid}").as_bytes())),
                "created": ts(NOW)}),
        &base.agent,
    )
}

fn write_call_case(
    o: &mut Out,
    name: &str,
    chain: &Chain,
    head: &Value,
    call: &Value,
    verifier: Value,
    expected: &str,
    why: &str,
) {
    let dir = format!("calls/{name}");
    for (i, e) in chain.envs.iter().enumerate() {
        write_raw(
            o,
            &format!("{dir}/records/authority/{:08}.json", i + 1),
            env_bytes(e),
        );
    }
    write(o, &format!("{dir}/objects/head.json"), head);
    write(o, &format!("{dir}/call.json"), call);
    write(
        o,
        &format!("{dir}/case.json"),
        &json!({"description": why, "sections": ["1", "8.7", "12.3", "13.6"],
                "expected": expected, "verifier": verifier}),
    );
}

pub fn part(o: &mut Out) {
    let b = base();
    // The home's head over seq 3 (N−1), 60 s before the clock: fresh in every case.
    let h3 = head(&b.chain, &b.home, 3, NOW - 60);
    let plain = json!({"now": ts(NOW), "audiences": [AUD], "replay": "empty"});
    let read = call(&b, AUD, "task.read", "1");
    write_call_case(
        o,
        "s-stopped-reader-call",
        &final_then_revoke(&b),
        &h3,
        &read,
        plain.clone(),
        "unavailable",
        "Seq 4 raises the layout and seq 5 makes it final (newerFormat: the reader is stopped); seq 6 revokes the member. With a fresh head at seq 3 and asOf seq 3, a stopped reader verifies no call: unavailable, whatever S would be.",
    );
    write_call_case(
        o,
        "s-stopped-home-read",
        &final_then_revoke(&b),
        &h3,
        &call(&b, &b.endpoint, "colophon.history.read", "2"),
        json!({"now": ts(NOW), "audiences": [b.endpoint], "replay": "empty", "role": "home"}),
        "unavailable",
        "As s-stopped-reader-call, at the stopped home: the member reads the history with its own key, and the home verifies no call (503 unavailable, §13.6).",
    );
    write_call_case(
        o,
        "s-before-stop-call",
        &b.chain,
        &h3,
        &read,
        plain.clone(),
        "ok",
        "The same call over seqs 1 to 3 alone, the history before the raise: ok. Only the stop makes s-stopped-reader-call unavailable.",
    );
    write_call_case(
        o,
        "s-provisional-raise-call",
        &activated(&b),
        &h3,
        &read,
        plain.clone(),
        "ok",
        "Seq 4 activates the layout raise but no final makes it final: the reader is not stopped, and the call is judged as usual (ok at S = 3).",
    );
    write_call_case(
        o,
        "s-vetoed-raise-call",
        &vetoed(&b),
        &h3,
        &read,
        plain,
        "ok",
        "Seq 4 records B's veto of the layout raise: the reader is not stopped, and the call is judged as usual (ok at S = 3).",
    );
}
