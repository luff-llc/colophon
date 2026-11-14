//! Identifiers, the 0.4 upgrade, the identity account with its calls and heads (`generate.py`),
//! then the origin, replay, encoding, pairing and malleation cases (`rules.py`).
#![allow(clippy::unwrap_used)]
use crate::kit::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::LazyLock;

pub static P_PIN: LazyLock<Authenticator> = LazyLock::new(|| {
    Authenticator::new(
        "passkey-pinned",
        "id.example",
        json!({"authorityOrigins": ["https://keys.id.example"]}),
    )
});

pub struct Summary {
    pub recanonicalized: usize,
}

fn authority_files(dir: PathBuf) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = sorted_dir(&dir)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    v.sort();
    v
}

/// Paths of `keys/*/records/authority/*.json` (sorted by path components), then the library's.
fn all_authority_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for case in sorted_dir(&v4().join("keys")) {
        let d = case.join("records/authority");
        if case.is_dir() && d.is_dir() {
            out.extend(authority_files(d));
        }
    }
    out.extend(authority_files(v4().join("library/records/authority")));
    out
}

fn load_chain(case: &str) -> Vec<Vec<u8>> {
    authority_files(v4().join("keys").join(case).join("records/authority"))
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect()
}

type Mutate<'a> = Option<&'a dyn Fn(&mut Value)>;
type Extra<'a> = Option<&'a dyn Fn(&Value, &Value, &Key) -> Vec<(String, Vec<u8>)>>;

struct Up<'a> {
    mutate: Mutate<'a>,
    signer_id: Option<String>,
    extra: Extra<'a>,
    expected5: &'a str,
    expected4: &'a str,
}
impl Default for Up<'_> {
    fn default() -> Self {
        Up {
            mutate: None,
            signer_id: None,
            extra: None,
            expected5: "ok",
            expected4: "newerFormat",
        }
    }
}

fn upgrade_case(o: &mut Out, name: &str, base_case: &str, why: &str, u: Up) {
    let chain = load_chain(base_case);
    let envs: Vec<Value> = chain
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    let bodies: Vec<Vec<u8>> = envs.iter().map(body_of).collect();
    let genesis: Value = serde_json::from_slice(&bodies[0]).unwrap();
    let last: Value = serde_json::from_slice(bodies.last().unwrap()).unwrap();
    let keyring = genesis["keyring"].clone();
    let mut keyring5 = keyring.clone();
    keyring5["addThreshold"] = json!(1);
    keyring5["countBy"] = json!("keys");
    keyring5["policy"] = default_policy();
    let controller = &keyring["controllers"][0];
    let cid_ = key_id(&unb64(controller["key"]["signing"].as_str().unwrap()));
    let by = u.signer_id.clone().unwrap_or(cid_.clone());
    let mut body = json!({"protocol": "colophon/authority/4", "seq": last["seq"].as_i64().unwrap() + 1,
                          "previous": sha(bodies.last().unwrap()), "issued": "2026-11-11T09:00:00.000Z", "by": by,
                          "kind": "upgrade", "account": sha(&bodies[0]), "keyring": keyring5});
    if let Some(m) = u.mutate {
        m(&mut body);
    }
    let signer = software(&by).unwrap_or_else(|| derived("outsider"));
    let upgrade = envelope(&body, &signer);
    let mut records: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, c) in chain.iter().enumerate() {
        records.push((format!("records/authority/{:08}.json", i + 1), c.clone()));
    }
    records.push((
        format!("records/authority/{:08}.json", chain.len() + 1),
        env_bytes(&upgrade),
    ));
    if let Some(x) = u.extra {
        records.extend(x(&body, &upgrade, &signer));
    }
    for (rel, data) in records {
        write_raw(o, &format!("upgrade/{name}/{rel}"), data);
    }
    write(
        o,
        &format!("upgrade/{name}/case.json"),
        &json!({"description": why, "base": format!("conformance/0.4/keys/{base_case}"), "sections": ["5.1", "8.5", "16.1"],
                "expected": {"colophon-0.5": u.expected5, "colophon-0.4": u.expected4},
                "accountID": sha(&bodies[0]), "legacyLibraryID": sha(&bodies[0])[..32]}),
    );
}

pub struct P1 {
    pub account: String,
    pub history: Vec<Value>,
    pub head: Value,
    pub head_env: Value,
    pub as_of: Value,
    pub now: &'static str,
    pub agent_sign: Key,
    pub home_sign: Key,
    pub gh_env: Value,
    pub ga_env: Value,
    pub controller: Key,
}

struct CallSpec<'a> {
    links: Vec<Vec<u8>>,
    audience: &'a str,
    purpose: &'a str,
    args: Value,
    key_point: Option<Vec<u8>>,
    rid_seed: &'a str,
    created: &'a str,
    signer: Option<&'a Key>,
}
impl Default for CallSpec<'_> {
    fn default() -> Self {
        CallSpec {
            links: vec![],
            audience: AUD,
            purpose: "task.read",
            args: json!({"task": "T-12"}),
            key_point: None,
            rid_seed: "1",
            created: "2026-11-11T09:01:00Z",
            signer: None,
        }
    }
}

impl P1 {
    fn call(&self, acting: &Key, c: CallSpec) -> Value {
        let mut body = json!({"protocol": "colophon/call/5", "account": self.account, "asOf": self.as_of,
                              "signer": {"member": self.agent_sign.id},
                              "key": b64(c.key_point.as_deref().unwrap_or(&acting.point)),
                              "audience": c.audience, "purpose": c.purpose, "args": c.args,
                              "requestId": b64url(&sha_raw(format!("request/{}", c.rid_seed).as_bytes())),
                              "created": c.created});
        if !c.links.is_empty() {
            body["links"] = json!(c.links.iter().map(|l| b64(l)).collect::<Vec<_>>());
        }
        envelope(&body, c.signer.unwrap_or(acting))
    }
    fn link(
        &self,
        frm: &Key,
        to: &Key,
        terms: &Value,
        session: Option<i64>,
        nb: &str,
        exp: &str,
    ) -> Vec<u8> {
        let mut body = json!({"protocol": "colophon/link/5", "account": self.account, "from": frm.id,
                              "to": {"signing": b64(&to.point)}, "terms": terms, "notBefore": nb, "expires": exp, "created": nb});
        if let Some(s) = session {
            body["session"] = json!(s);
        }
        env_bytes(&envelope(&body, frm))
    }
}

pub fn part1(o: &mut Out) -> (P1, Summary) {
    // Self-check: the canonical encoder reproduces every 0.4 authority body byte for byte.
    let mut recanonicalized = 0;
    for path in all_authority_paths() {
        let env = read_json(&path);
        let body = unb64(env["body"].as_str().unwrap());
        let t: Tracked = serde_json::from_slice(&body).unwrap();
        if t.1 {
            continue; // a published duplicate-name refuse case; not canonical by design
        }
        assert_eq!(
            canonical(&t.0),
            body,
            "canonical mismatch: {}",
            path.display()
        );
        recanonicalized += 1;
    }

    // 1. Identifiers (spec §5.1).
    let mut identifiers = Vec::new();
    let mut genesis_paths: Vec<PathBuf> = Vec::new();
    for case in sorted_dir(&v4().join("keys")) {
        let p = case.join("records/authority/00000001.json");
        if p.is_file() {
            genesis_paths.push(p);
        }
    }
    genesis_paths.push(v4().join("library/records/authority/00000001.json"));
    for path in &genesis_paths {
        let body = unb64(read_json(path)["body"].as_str().unwrap());
        let full = sha(&body);
        identifiers.push(json!({"source": path.strip_prefix(conformance()).unwrap().to_str().unwrap(),
                                "legacyLibraryID": &full[..32], "accountID": full, "text": format!("colophon:{full}")}));
    }
    // The 0.4 library fixture's operations bind `library`; it must equal the legacy prefix.
    let mut ops: Vec<PathBuf> = Vec::new();
    for a in sorted_dir(&v4().join("library/records/ops")) {
        if a.is_dir() {
            for b in sorted_dir(&a) {
                if b.is_dir() {
                    for c in sorted_dir(&b) {
                        if c.extension().is_some_and(|e| e == "json") {
                            ops.push(c);
                        }
                    }
                }
            }
        }
    }
    ops.sort();
    let op_library = body_json(&read_json(&ops[0]))["library"]
        .as_str()
        .unwrap()
        .to_string();
    let lib_full = sha(&body_of(&read_json(
        &v4().join("library/records/authority/00000001.json"),
    )));
    assert_eq!(op_library, lib_full[..32]);
    write(
        o,
        "identifiers.json",
        &json!({
            "description": "0.5 account IDs (spec §5.1) of every published 0.4 genesis. The 0.4 library ID is the first 32 characters. The 0.4 library fixture's operation headers bind `library` = legacyLibraryID, checked by the generator.",
            "cases": identifiers,
            "references": [
                {"reference": {"account": lib_full}, "expected": "ok"},
                {"reference": {"account": &lib_full[..32]}, "expected": "malformed", "why": "a 32-character legacy ID is not a 0.5 account reference"},
                {"reference": {"account": lib_full.to_uppercase()}, "expected": "malformed", "why": "uppercase hex"},
                {"reference": {"account": lib_full, "hints": []}, "expected": "malformed", "why": "hints, when present, is non-empty"},
                {"reference": {"account": lib_full, "hints": ["http://home.example/v1"]}, "expected": "malformed", "why": "hints are https only"},
            ],
        }),
    );

    // 2. Upgrade from 0.4 in place (spec §16.1), on the published seq-two-rekey chain.
    upgrade_case(o, "accept", "seq-two-rekey", "Control-signed upgrade entry after genesis and the seq-2 rekey. A 0.4 reader stops with newerFormat.", Up::default());
    upgrade_case(
        o,
        "wrong-account",
        "seq-two-rekey",
        "`account` is not the digest of the genesis body.",
        Up {
            mutate: Some(&|b| b["account"] = json!("0".repeat(64))),
            expected5: "malformed",
            ..Up::default()
        },
    );
    upgrade_case(
        o,
        "legacy-account",
        "seq-two-rekey",
        "`account` gives only the 32-character legacy ID.",
        Up {
            mutate: Some(&|b| {
                let a = b["account"].as_str().unwrap()[..32].to_string();
                b["account"] = json!(a)
            }),
            expected5: "malformed",
            ..Up::default()
        },
    );
    upgrade_case(o, "keyring-changed", "seq-two-rekey", "The upgrade keyring changes a 0.4 field (a controller label); only addThreshold and policy may be added.",
                 Up { mutate: Some(&|b| b["keyring"]["controllers"][0]["label"] = json!("renamed")), expected5: "malformed", ..Up::default() });
    upgrade_case(
        o,
        "policy-out-of-range",
        "seq-two-rekey",
        "policy.headMaxAge below its range (30-86,400).",
        Up {
            mutate: Some(&|b| b["keyring"]["policy"]["headMaxAge"] = json!(10)),
            expected5: "malformed",
            ..Up::default()
        },
    );
    upgrade_case(
        o,
        "add-threshold-above",
        "seq-two-rekey",
        "addThreshold exceeds threshold (1).",
        Up {
            mutate: Some(&|b| b["keyring"]["addThreshold"] = json!(2)),
            expected5: "malformed",
            ..Up::default()
        },
    );
    upgrade_case(
        o,
        "foreign-signer",
        "seq-two-rekey",
        "Signed by a key that is not a controller of the prior keyring.",
        Up {
            signer_id: Some(derived("outsider").id),
            expected5: "badSignature",
            expected4: "badSignature",
            ..Up::default()
        },
    );
    upgrade_case(o, "at-seq-two", "genesis-only",
                 "Upgrade as seq 2 of a library whose seq 2 must be its rekey (0.4 seq-2 rule stands). A 0.4 reader reports newerFormat because unknown-kind detection precedes transition rules.",
                 Up { expected5: "malformed", ..Up::default() });

    let then_layout = |body: &Value, upgrade: &Value, signer: &Key| -> Vec<(String, Vec<u8>)> {
        let issued = "2026-11-11T09:00:01.000Z";
        let seq = body["seq"].as_i64().unwrap();
        let t = envelope(
            &json!({"protocol": "colophon/transition/5", "account": body["account"],
                    "anchor": {"seq": seq, "digest": sha(&body_of(upgrade))}, "issued": issued, "by": signer.id,
                    "signers": [signer.id], "change": {"layout": 2}}),
            signer,
        );
        let nxt = json!({"protocol": "colophon/authority/5", "seq": seq + 1, "previous": sha(&body_of(upgrade)), "issued": issued,
                         "by": signer.id, "kind": "activate", "transition": b64(&env_bytes(&t)), "receipts": []});
        vec![(
            format!("records/authority/{:08}.json", seq + 1),
            canonical(&json!({"body": b64(&canonical(&nxt))})),
        )]
    };
    let then_v4 = |body: &Value, upgrade: &Value, signer: &Key| -> Vec<(String, Vec<u8>)> {
        let seq = body["seq"].as_i64().unwrap();
        let nxt = json!({"protocol": "colophon/authority/4", "seq": seq + 1, "previous": sha(&body_of(upgrade)),
                         "issued": "2026-11-11T09:00:01.000Z", "by": signer.id, "kind": "layout", "layout": 2});
        vec![(
            format!("records/authority/{:08}.json", seq + 1),
            env_bytes(&envelope(&nxt, signer)),
        )]
    };
    upgrade_case(
        o,
        "then-v5-layout",
        "seq-two-rekey",
        "After the upgrade, a /5 layout transition under the control rule is accepted.",
        Up {
            extra: Some(&then_layout),
            ..Up::default()
        },
    );
    upgrade_case(
        o,
        "then-v4-entry",
        "seq-two-rekey",
        "A /4 entry after the upgrade.",
        Up {
            extra: Some(&then_v4),
            expected5: "malformed",
            ..Up::default()
        },
    );

    // 3. A native 0.5 identity account with an agent and a home (spec §6, §9, §10, §12, §13).
    let g4 = &*G4;
    let controller = software("b609e0fd25ac2aefc193156581e112cb").unwrap();
    let mut keyring5 = g4["keyring"].clone();
    keyring5["addThreshold"] = json!(1);
    keyring5["countBy"] = json!("keys");
    keyring5["policy"] = default_policy();

    let (agent_sign, agent_agree) = (derived("agent/signing"), derived("agent/agreement"));
    let (home_sign, home_agree) = (derived("home/signing"), derived("home/agreement"));
    let session1 = derived("session/1");
    let session2 = derived("session/2");
    let attacker = derived("attacker");

    let genesis = json!({"protocol": "colophon/authority/5", "seq": 1, "previous": null, "issued": "2026-11-11T08:00:00Z",
                         "by": controller.id, "kind": "genesis", "label": "Identity", "namespaces": [], "keyring": keyring5});
    let g_env = envelope(&genesis, &controller);
    let account = sha(&body_of(&g_env));

    let agent_request = json!({"protocol": "colophon/request/5", "account": account,
        "member": {"agreement": b64(&agent_agree.point), "signing": b64(&agent_sign.point)},
        "label": "Agent on test host", "kind": "agent",
        "terms": {"services": [{"audience": AUD, "purposes": ["task.propose", "task.read"]}], "depth": 1},
        "created": "2026-11-11T08:00:00Z"});
    let agent_terms = json!({"services": [{"audience": AUD, "purposes": ["task.propose", "task.read"]}], "depth": 1,
                             "expires": "2026-11-18T08:00:00Z", "conditions": [{"prefix": ["args.task", "T-"]}]});
    let grant_agent = json!({"protocol": "colophon/authority/5", "seq": 2, "previous": sha(&body_of(&g_env)), "issued": "2026-11-11T08:00:01Z",
        "by": controller.id, "kind": "grant", "request": b64(&env_bytes(&envelope(&agent_request, &agent_sign))),
        "terms": agent_terms, "shares": []});
    let ga_env = envelope(&grant_agent, &controller);

    let home = format!("https://home.example/v1/accounts/{account}");
    let home_request = json!({"protocol": "colophon/request/5", "account": account,
        "member": {"agreement": b64(&home_agree.point), "signing": b64(&home_sign.point)},
        "label": "Test home", "kind": "server", "terms": {"serves": ["home"]},
        "created": "2026-11-11T08:00:00Z", "service": {"endpoints": [home]}});
    let home_transition = json!({"protocol": "colophon/transition/5", "account": account,
        "anchor": {"seq": 2, "digest": sha(&body_of(&ga_env))}, "issued": "2026-11-11T08:00:02Z", "by": controller.id,
        "signers": [controller.id],
        "change": {"homes": {"appoint": [{"request": b64(&env_bytes(&envelope(&home_request, &home_sign))),
                                          "terms": {"serves": ["home"]}}]}}});
    let ht_env = envelope(&home_transition, &controller);
    let activate_home = json!({"protocol": "colophon/authority/5", "seq": 3, "previous": sha(&body_of(&ga_env)),
        "issued": "2026-11-11T08:00:02Z", "by": controller.id, "kind": "activate", "transition": b64(&env_bytes(&ht_env)), "receipts": []});
    let gh_env = json!({"body": b64(&canonical(&activate_home))});
    let history = vec![g_env.clone(), ga_env.clone(), gh_env.clone()];
    for (i, e) in history.iter().enumerate() {
        write_raw(
            o,
            &format!("account/records/authority/{:08}.json", i + 1),
            env_bytes(e),
        );
    }

    let head = json!({"protocol": "colophon/head/5", "account": account, "authority": {"seq": 3, "digest": sha(&body_of(&gh_env))},
                      "issued": "2026-11-11T09:00:00Z", "by": home_sign.id});
    let head_env = envelope(&head, &home_sign);
    write(o, "account/head.json", &head_env);

    let now: &'static str = "2026-11-11T09:01:00Z";
    let as_of = json!({"seq": 3, "digest": sha(&body_of(&gh_env))});
    let mut members = serde_json::Map::new();
    members.insert(agent_sign.id.clone(), json!("agent"));
    members.insert(home_sign.id.clone(), json!("home"));
    write(
        o,
        "account/case.json",
        &json!({
            "description": "Identity-only 0.5 account (no namespaces): genesis, an agent grant under the single rule, and the activation of a transition appointing a home (due when issued: no home before it).",
            "sections": ["6.2", "8.2", "8.4", "9.1", "9.2", "13.1"],
            "accountID": account,
            "expected": {"history": "ok", "head": "ok at now; stale after 2026-11-11T09:05:00Z (headMaxAge 300)"},
            "members": members,
        }),
    );

    let p1 = P1 {
        account: account.clone(),
        history: history.clone(),
        head: head.clone(),
        head_env: head_env.clone(),
        as_of,
        now,
        agent_sign: agent_sign.clone(),
        home_sign: home_sign.clone(),
        gh_env: gh_env.clone(),
        ga_env: ga_env.clone(),
        controller: controller.clone(),
    };
    let (nb0, exp0) = ("2026-11-11T09:00:00Z", "2026-11-11T09:10:00Z");
    let narrow = json!({"services": [{"audience": AUD, "purposes": ["task.read"]}], "conditions": [{"prefix": ["args.task", "T-"]}]});
    let wide = json!({"services": [{"audience": AUD, "purposes": ["*"]}], "conditions": [{"prefix": ["args.task", "T-"]}]});
    let l_ok = p1.link(&agent_sign, &session1, &narrow, Some(0), nb0, exp0);
    let cs = |rid: &'static str| CallSpec {
        rid_seed: rid,
        ..CallSpec::default()
    };
    let with_conds = |extra: Value| {
        let mut t = narrow.clone();
        t["conditions"].as_array_mut().unwrap().push(extra);
        t
    };
    let bad_sig = |env: Value, sig: Vec<u8>| {
        let mut e = env;
        e["signature"] = json!(b64(&sig));
        e
    };
    let body13 = body_json(&p1.call(&agent_sign, cs("13")));
    let body14 = body_json(&p1.call(&agent_sign, cs("14")));
    let (mut b13, mut b14) = (body13, body14);
    b13["future"] = json!(1);
    b14["future"] = json!(1);
    let calls: Vec<(&str, Value, &str, &str)> = vec![
        ("member-no-links", p1.call(&agent_sign, CallSpec::default()), "ok", "The member's own key acts."),
        ("one-link", p1.call(&session1, CallSpec { links: vec![l_ok.clone()], rid_seed: "2", ..CallSpec::default() }), "ok",
         "A session key acts through one link with narrower terms (the member's condition is carried, §10.3)."),
        ("copied-link", p1.call(&attacker, CallSpec { links: vec![l_ok.clone()], rid_seed: "3", ..CallSpec::default() }), "badSignature",
         "An attacker signs its own call with a copied link: the acting key is not the link's `to` key (step 6)."),
        ("invalid-call-signature", bad_sig(p1.call(&agent_sign, cs("4")), attacker.sign(b"x")), "badSignature",
         "The call signature doesn't verify under `key` (step 2, before any fetch)."),
        ("wrong-audience", p1.call(&agent_sign, CallSpec { audience: "https://other.example", rid_seed: "5", ..CallSpec::default() }), "refused:audience",
         "Audience is not one of the verifier's (step 3)."),
        ("outside-window", p1.call(&agent_sign, CallSpec { created: "2026-11-11T08:50:00Z", rid_seed: "6", ..CallSpec::default() }), "refused:window",
         "Created 660 s before now: inside step 3's 3,600 s, refused by callWindow 300 at step 4."),
        ("widening-link", p1.call(&session1, CallSpec { links: vec![p1.link(&agent_sign, &session1, &wide, Some(0), nb0, exp0)], purpose: "task.delete", rid_seed: "7", ..CallSpec::default() }),
         "refused:notNarrower", "The link asks for every purpose; the member has two (step 6)."),
        ("ended-session", p1.call(&session1, CallSpec { links: vec![p1.link(&agent_sign, &session1, &narrow, Some(1), nb0, exp0)], rid_seed: "8", ..CallSpec::default() }),
         "refused:ended", "The link names session 1; the member's session number is 0 (step 6)."),
        ("out-of-scope-purpose", p1.call(&agent_sign, CallSpec { purpose: "task.delete", rid_seed: "9", ..CallSpec::default() }), "refused:outOfScope",
         "The member's terms don't grant task.delete (step 7)."),
        ("condition-fails", p1.call(&agent_sign, CallSpec { args: json!({"task": "X-1"}), rid_seed: "10", ..CallSpec::default() }), "refused:outOfScope",
         "The member's condition requires args.task to start with T- (step 7)."),
        ("depth-exceeded", p1.call(&session2, CallSpec { links: vec![l_ok.clone(), p1.link(&session1, &session2, &narrow, None, nb0, exp0)], rid_seed: "11", ..CallSpec::default() }),
         "refused:notNarrower", "Member depth 1 allows one link; the second link's parent depth is 0 (step 6)."),
        ("link-expired", p1.call(&session1, CallSpec { links: vec![p1.link(&agent_sign, &session1, &narrow, Some(0), "2026-11-11T08:00:00Z", "2026-11-11T08:30:00Z")], rid_seed: "12", ..CallSpec::default() }),
         "refused:expired", "The link expired at 08:30 (step 6)."),
        ("link-unknown-operator-not-deciding",
         p1.call(&session1, CallSpec { links: vec![p1.link(&agent_sign, &session1, &with_conds(json!({"any": [{"prefix": ["args.task", "T-"]}, {"future": ["args.task", 1]}]})), Some(0), nb0, exp0)], rid_seed: "15", ..CallSpec::default() }),
         "ok", "A link adds any:[true, unknown]: the any is true, so the unknown operator decides nothing (§10.4, step 8)."),
        ("link-unknown-operator-deciding",
         p1.call(&session1, CallSpec { links: vec![p1.link(&agent_sign, &session1, &with_conds(json!({"any": [{"prefix": ["args.task", "X-"]}, {"future": ["args.task", 1]}]})), Some(0), nb0, exp0)], rid_seed: "16", ..CallSpec::default() }),
         "newerFormat", "A link adds any:[false, unknown]: the result is unknown, so step 8 is newerFormat."),
        ("unknown-field-valid", envelope(&b13, &agent_sign), "newerFormat", "An unknown body field on an otherwise valid, authorized call (step 8)."),
        ("unknown-field-invalid", bad_sig(envelope(&b14, &agent_sign), attacker.sign(b"y")), "badSignature",
         "The same unknown field with an invalid signature: never newerFormat."),
    ];
    for (name, env, expected, why) in &calls {
        write(o, &format!("calls/{name}/call.json"), env);
        write(
            o,
            &format!("calls/{name}/case.json"),
            &json!({
                "description": why, "sections": ["12.3"], "expected": expected,
                "verifier": {"now": now, "audiences": [AUD], "replay": "empty",
                             "history": "conformance/0.5/candidate/account/records", "heads": ["conformance/0.5/candidate/account/head.json"]},
            }),
        );
    }

    // Number ties (spec §2.1).
    let mut ties = Vec::new();
    for (x, even, odd) in [
        (
            -276804372109801.38f64,
            "-276804372109801.38",
            "-276804372109801.37",
        ),
        (
            142129249267021.88,
            "142129249267021.88",
            "142129249267021.87",
        ),
        (
            1059438285926254.2,
            "1059438285926254.2",
            "1059438285926254.3",
        ),
        (
            2124241711641300.2,
            "2124241711641300.2",
            "2124241711641300.3",
        ),
    ] {
        assert!(even.parse::<f64>().unwrap() == x && odd.parse::<f64>().unwrap() == x);
        ties.push(
            json!({"bits": hex(&x.to_bits().to_be_bytes()), "canonical": even, "refused": odd}),
        );
    }
    write(
        o,
        "encoding/number-ties.json",
        &json!({
        "description": "Tie cases: both decimals round-trip; a body spelling the number as `refused` is not canonical (malformed).",
        "sections": ["2.1"], "cases": ties}),
    );

    // Heads (spec §13.3).
    let mut stale_h = head.clone();
    stale_h["issued"] = json!("2026-11-11T08:50:00Z");
    let stale = envelope(&stale_h, &home_sign);
    let mut agent_h = head.clone();
    agent_h["by"] = json!(agent_sign.id);
    let by_agent = envelope(&agent_h, &agent_sign);
    let mut fork_h = head.clone();
    fork_h["authority"] = json!({"seq": 3, "digest": "1".repeat(64)});
    let fork = envelope(&fork_h, &home_sign);
    let heads: Vec<(&str, &Value, &str, &str)> = vec![
        ("valid", &head_env, "ok", "Fresh head by the appointed home."),
        ("stale", &stale, "ok (accepted, not fresh)", "Issued 11 minutes before now with headMaxAge 300: a call verifier needing a fresh head returns unavailable."),
        ("not-a-home", &by_agent, "badSignature", "Signed by a member without serves."),
        ("fork", &fork, "refused:fork", "Names seq 3 with a digest that differs from the held history."),
    ];
    for (name, env, expected, why) in heads {
        write(o, &format!("heads/{name}/head.json"), env);
        write(
            o,
            &format!("heads/{name}/case.json"),
            &json!({"description": why, "sections": ["13.3"], "expected": expected,
            "verifier": {"now": now, "history": "conformance/0.5/candidate/account/records"}}),
        );
    }

    // Public test keys.
    let listed: Vec<(&str, Key)> = vec![
        ("agent/signing", agent_sign.clone()),
        ("agent/agreement", agent_agree.clone()),
        ("home/signing", home_sign.clone()),
        ("home/agreement", home_agree.clone()),
        ("session/1", session1.clone()),
        ("session/2", session2.clone()),
        ("attacker", attacker.clone()),
        ("outsider", derived("outsider")),
    ];
    let mut keys = serde_json::Map::new();
    for (n, k) in &listed {
        keys.insert(
            n.to_string(),
            json!({"id": k.id, "signing": b64(&k.point), "scalar": b64(&k.scalar)}),
        );
    }
    write(
        o,
        "keys.json",
        &json!({
        "warning": "PUBLIC TEST SECRETS. Never use these keys for real data.",
        "derivation": "scalar = SHA-256('colophon-0.5-candidate/' + name) mod n; controller keys are the published 0.4 software keys.",
        "keys": keys}),
    );

    // The call self-check keys.
    CHECK_KEYS
        .set(vec![
            agent_sign.clone(),
            session1.clone(),
            session2.clone(),
            attacker.clone(),
        ])
        .ok();

    part2(o, &p1, &attacker);
    (p1, Summary { recanonicalized })
}

pub static CHECK_KEYS: std::sync::OnceLock<Vec<Key>> = std::sync::OnceLock::new();

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

fn part2(o: &mut Out, p1: &P1, _attacker: &Key) {
    let a: &Key = &A;
    let kr_t1 = keyring(
        vec![ctrl(a, &["approve", "control"], Some("Device"), json!({}))],
        Kr::default(),
    );

    // Authority origins (§4.3) with a synthetic passkey.
    let p_open = Authenticator::new("passkey-open", "id.example", json!({}));
    let p_pin: &Authenticator = &P_PIN;
    let cases: Vec<(&str, &dyn Signer, &str, Value, &str)> = vec![
        (
            "origin-exact-rp",
            &p_open,
            "https://id.example",
            ok_at(1),
            "No pin: the bare rp origin may sign authority.",
        ),
        (
            "origin-subdomain-unpinned",
            &p_open,
            "https://keys.id.example",
            bad("badSignature", 1),
            "No pin: a subdomain may not sign authority.",
        ),
        (
            "origin-subdomain-pinned",
            p_pin,
            "https://keys.id.example",
            ok_at(1),
            "Pinned subdomain signs authority.",
        ),
        (
            "origin-bare-not-pinned",
            p_pin,
            "https://id.example",
            bad("badSignature", 1),
            "Pinned elsewhere: the bare rp may not.",
        ),
    ];
    for (name, auth, origin, expected, why) in cases {
        let kr_p = keyring(
            vec![
                ctrl(a, &["approve", "control"], Some("Device"), json!({})),
                ctrl(
                    auth,
                    &["approve", "control"],
                    Some("Passkey"),
                    json!({"verification": true}),
                ),
            ],
            Kr::default(),
        );
        let mut c = Chain::new();
        genesis(
            &mut c,
            &kr_p,
            &[auth],
            Gen {
                opt: Opt {
                    adds: sg![A],
                    origin: Some(origin),
                    ..Opt::default()
                },
                ..Gen::default()
            },
        );
        wc(o, name, &c, expected, why, &["4.3"]);
    }

    // Calls against the revision-1 account: replay, evaluation point (§12.3, §12.4).
    let replay_ver = json!({"now": p1.now, "audiences": [AUD], "history": "conformance/0.5/candidate/account/records",
        "heads": ["conformance/0.5/candidate/account/head.json"],
        "replay": ["conformance/0.5/candidate/calls/member-no-links/call.json"]});
    write(
        o,
        "rules/replay-identical/call.json",
        &p1.call(&p1.agent_sign, CallSpec::default()),
    );
    write(
        o,
        "rules/replay-identical/case.json",
        &json!({"description": "The same call body again.", "sections": ["12.3", "12.4"],
        "expected": {"call": "refused:replay"}, "verifier": replay_ver}),
    );
    write(
        o,
        "rules/replay-conflict/call.json",
        &p1.call(
            &p1.agent_sign,
            CallSpec {
                args: json!({"task": "T-13"}),
                ..CallSpec::default()
            },
        ),
    );
    write(
        o,
        "rules/replay-conflict/case.json",
        &json!({"description": "Same key and requestId, different body.", "sections": ["12.3", "12.4"],
        "expected": {"call": "refused:conflict"}, "verifier": replay_ver}),
    );

    let mut beyond = Chain::new();
    beyond.envs = p1.history.clone();
    let rev = beyond.add(
        "revoke",
        &p1.controller,
        "2026-11-11T09:00:30Z",
        &p1.controller,
        Opt::default(),
        json!({"member": p1.agent_sign.id, "kept": [], "heads": [], "epochs": []}),
    );
    write(
        o,
        "rules/removal-after-heads/records/authority/00000004.json",
        &rev,
    );
    write(
        o,
        "rules/removal-after-heads/call.json",
        &p1.call(
            &p1.agent_sign,
            CallSpec {
                rid_seed: "r4",
                ..CallSpec::default()
            },
        ),
    );
    write(
        o,
        "rules/removal-after-heads/case.json",
        &json!({
        "description": "The verifier holds a revoke at seq 4 that no head covers yet; removals apply at once.",
        "sections": ["12.3"], "expected": {"call": "refused:revoked"},
        "verifier": {"now": p1.now, "audiences": [AUD], "history": ["conformance/0.5/candidate/account/records",
                                                                   "conformance/0.5/candidate/rules/removal-after-heads/records"],
                     "heads": ["conformance/0.5/candidate/account/head.json"]}}),
    );

    // Heads: equivocation evidence, rollback (§13.3).
    let mut fake_h = p1.head.clone();
    fake_h["authority"] = json!({"seq": 3, "digest": "2".repeat(64)});
    let fake = envelope(&fake_h, &p1.home_sign);
    let mut pair = [p1.head_env.clone(), fake];
    pair.sort_by_key(|e| sha(&body_of(e)));
    write(
        o,
        "rules/equivocation/evidence.json",
        &json!({"protocol": "colophon/equivocation/5", "account": p1.account,
        "heads": pair.iter().map(emb).collect::<Vec<_>>()}),
    );
    write(
        o,
        "rules/equivocation/case.json",
        &json!({"description": "Two heads by one home at seq 3 with different digests.",
        "sections": ["13.3"], "expected": {"evidence": "ok", "home": "not counted"}}),
    );
    let mut old_h = p1.head.clone();
    old_h["authority"] = json!({"seq": 2, "digest": sha(&body_of(&p1.ga_env))});
    old_h["issued"] = json!("2026-11-11T09:00:30Z");
    write(
        o,
        "rules/rollback/head.json",
        &envelope(&old_h, &p1.home_sign),
    );
    write(
        o,
        "rules/rollback/case.json",
        &json!({"description": "A fresh head over seq 2 after the verifier accepted seq 3.",
        "sections": ["13.3"], "expected": {"head": "refused:rollback"},
        "verifier": {"now": p1.now, "highWater": {"seq": 3, "digest": sha(&body_of(&p1.gh_env))}}}),
    );

    // Canonical encodings (§2.1, §2.2).
    let mut c = Chain::new();
    genesis(&mut c, &kr_t1, sg![A], Gen::default());
    let g_obj = body_json(&c.envs[0]);
    let unsorted = reverse_top_level(&g_obj);
    assert_ne!(unsorted, body_of(&c.envs[0]));
    write(
        o,
        "rules/non-canonical-json/records/authority/00000001.json",
        &seal_bytes(&unsorted, a, Opt::default()),
    );
    write(
        o,
        "rules/non-canonical-json/case.json",
        &json!({"description": "Genesis body with keys not in sorted order.",
        "sections": ["2.1"], "expected": bad("malformed", 1)}),
    );
    let mut g_obj2 = body_json(&c.envs[0]);
    let spelled = g_obj2["keyring"]["controllers"][0]["key"]["signing"]
        .as_str()
        .unwrap()
        .to_string();
    // A 65-byte value ends in one padding character; flip a padding bit in the last data character.
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sb: Vec<char> = spelled.chars().collect();
    let last = sb[sb.len() - 2];
    let flipped = alphabet
        .chars()
        .nth(alphabet.find(last).unwrap() ^ 1)
        .unwrap();
    let respelled: String =
        sb[..sb.len() - 2].iter().collect::<String>() + &flipped.to_string() + "=";
    assert_eq!(unb64(&respelled), unb64(&spelled));
    g_obj2["keyring"]["controllers"][0]["key"]["signing"] = json!(respelled);
    write(
        o,
        "rules/non-canonical-base64/records/authority/00000001.json",
        &seal(&g_obj2, a, Opt::default()),
    );
    write(
        o,
        "rules/non-canonical-base64/case.json",
        &json!({"description": "A key spelled with a non-zero padding bit (decodes to the same bytes).",
        "sections": ["2.2"], "expected": bad("malformed", 1)}),
    );
    let mut bad_date = Chain::new();
    bad_date.envs = c.envs.clone();
    grant_agent_with(
        &mut bad_date,
        a,
        &ts(60),
        a,
        &AGENT_K,
        &AGENT_A,
        "2026-02-30T00:00:00Z",
    );
    wc(
        o,
        "invalid-expires-date",
        &bad_date,
        bad("malformed", 2),
        "terms.expires on February 30.",
        &["2.2", "10.1"],
    );

    // Pairing (§7.3).
    let acct_p = format!("{}1", "0".repeat(63));
    let e = derived("pair/E");
    let n_b = sha_raw(b"pair/nB");
    let n_a = sha_raw(b"pair/nA");
    let cat = |parts: &[&[u8]]| parts.concat();
    let commit = sha(&cat(&[
        b"colophon/pair/5",
        acct_p.as_bytes(),
        &e.point,
        &n_b,
    ]));
    let digest = sha_raw(&cat(&[
        b"colophon/pair-code/5",
        acct_p.as_bytes(),
        &e.point,
        &n_a,
        &n_b,
    ]));
    let code = u32::from_be_bytes(digest[..4].try_into().unwrap()) % 1_000_000;
    let e2 = derived("pair/E-substitute");
    write(
        o,
        "pairing/pairing.json",
        &json!({
            "description": "Commit-then-reveal pairing (§7.3). Hex for bytes.",
            "account": acct_p, "E": hex(&e.point), "nB": hex(&n_b), "nA": hex(&n_a),
            "commitment": commit, "code": format!("{code:06}"),
            "refuse": [{"case": "reveal with another key", "E": hex(&e2.point), "nB": hex(&n_b), "expected": "abort: commitment mismatch"},
                       {"case": "reveal with another nB", "E": hex(&e.point), "nB": sha(b"x"), "expected": "abort: commitment mismatch"}],
        }),
    );

    // A malleated envelope: s -> n - s over the same body (§2.2, §8.6).
    let mut m = Chain::new();
    genesis(&mut m, &kr_t1, sg![A], Gen::default());
    let mut env = m.envs[0].clone();
    let sig = unb64(env["signature"].as_str().unwrap());
    let s_val: [u8; 32] = sig[32..].try_into().unwrap();
    let mut flipped_sig = sig[..32].to_vec();
    flipped_sig.extend(sub32(&N, &s_val));
    env["signature"] = json!(b64(&flipped_sig));
    assert!(verify_raw(
        &a.point,
        &body_of(&env),
        &unb64(env["signature"].as_str().unwrap())
    ));
    write(o, "rules/malleated-envelope/original.json", &m.envs[0]);
    write(o, "rules/malleated-envelope/malleated.json", &env);
    write(
        o,
        "rules/malleated-envelope/case.json",
        &json!({"description": "The same body with s replaced by n − s. Both verify; they are one entry.",
        "sections": ["2.2", "8.6", "14"], "expected": {"equal": true, "home": "200, keeps the first"}}),
    );
}
