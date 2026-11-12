//! Draft-1 speaks-for fixtures (NOT Colophon 0.5): opt-in generation and disk-only replay.
//! These vectors contradict the 0.5 candidate and are kept only as history; see
//! `conformance/0.5/legacy-draft-1/README.md`.
//! Regenerate with
//! COLOPHON_WRITE_V5_VECTORS=1 cargo test -p colophon-core --test legacy_draft1_conformance
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::{
    crypto::SoftwareKeys,
    keys::strict_json,
    legacy_draft1::{
        speaks::{
            self, AsOf, CheckInput, Link, Member, Proof, RawEnvelope, RequestBody, Target,
            VerifiedHistory,
        },
        terms::Terms,
        Verdict,
    },
    records,
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

const NOW: &str = "2026-11-10T10:00:00Z";
const ACCOUNT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUDIENCE: &str = "verifier-1";
const KIND: &str = "write:notes:add";

fn key(index: u8) -> SoftwareKeys {
    SoftwareKeys::from_seed([index; 32]).unwrap()
}
fn full_terms(depth: u64) -> Terms {
    Terms::from_value(&json!({
        "scope":[{"namespace":"notes","access":"write","kinds":["add","edit"]}],
        "expires":"2026-12-01T00:00:00Z","depth":depth,"writes":100,
        "conditions":[{"lte":["args.amount",5000]}]
    }))
    .unwrap()
}
fn child_terms(depth: u64, expiry: &str, widen: bool) -> Terms {
    Terms::from_value(&json!({
        "scope":[{"namespace":"notes","access":"write",
            "kinds":if widen {vec!["add","delete"]} else {vec!["add"]}}],
        "expires":expiry,"depth":depth,"writes":50,
        "conditions":[{"lte":["args.amount",5000]}]
    }))
    .unwrap()
}
fn link_expiry(i: usize) -> &'static str {
    match i {
        0 => "2026-11-11T00:00:00Z",
        1 => "2026-11-10T18:00:00Z",
        _ => "2026-11-10T17:00:00Z",
    }
}
fn speaks_case(name: &str) -> Value {
    let count = match name {
        "member-only" | "stale-head" | "revoked-member" | "expired-member" => 0,
        "three-links" | "link-outlives-parent" | "depth-exceeded" => 3,
        _ => 1,
    };
    let depth = if name == "depth-exceeded" { 2 } else { 8 };
    let base = full_terms(depth);
    let mut links = Vec::new();
    for i in 0..count {
        let parent = key(21 + i as u8);
        let next = key(22 + i as u8);
        let expiry = if name == "link-outlives-parent" && i == 1 {
            "2026-11-12T00:00:00Z"
        } else {
            link_expiry(i)
        };
        let link_depth = if name == "depth-exceeded" {
            (depth as usize).saturating_sub(i + 1) as u64
        } else {
            depth - i as u64 - 1
        };
        let l = Link {
            account: ACCOUNT.into(),
            from: parent.public().id(),
            to: Target {
                signing: next.public().signing,
                agreement: Some(next.public().agreement),
            },
            session: (i == 0).then_some(3),
            terms: child_terms(link_depth, expiry, name == "wider-scope" && i == 0),
            not_before: "2026-11-10T09:00:00Z".into(),
            expires: expiry.into(),
            created: "2026-11-10T09:00:00Z".into(),
        };
        let mut body = l.to_value();
        if (name == "unknown-term-signed" || name == "unknown-term-bad-signature") && i == 0 {
            body["terms"]["futureCap"] = json!(123);
        }
        let body = RawEnvelope::begin(&body).unwrap();
        let mut envelope =
            RawEnvelope::finish(body.clone(), parent.sign(&body), &parent.public().signing)
                .unwrap();
        if name == "unknown-term-bad-signature" && i == 0 {
            envelope.signature[0] ^= 1;
        }
        links.push(envelope);
    }
    let proof = Proof::new(
        ACCOUNT.into(),
        key(21).public().id(),
        AsOf {
            seq: 41,
            digest: HEAD.into(),
        },
        links,
    )
    .unwrap();
    let mut proof_value: Value = serde_json::from_slice(&proof.canonical().unwrap()).unwrap();
    if name == "unknown-proof-signed" {
        proof_value["futureProof"] = json!(true);
    }
    let proof_bytes = records::canonical(&proof_value).unwrap();
    let proof = Proof::from_json(&proof_bytes).unwrap();
    let signer = if name == "copied-proof-wrong-key" {
        key(39)
    } else {
        key(21 + count as u8)
    };
    let audience = if name == "wrong-audience" {
        "other-verifier"
    } else {
        AUDIENCE
    };
    let purpose = if name == "out-of-scope" {
        "write:notes:delete"
    } else {
        KIND
    };
    let created = if name == "old-request" {
        "2026-11-10T09:54:59Z"
    } else {
        NOW
    };
    let body_digest = records::digest(b"{\"amount\":25,\"kind\":\"add\"}");
    let request = RequestBody {
        account: ACCOUNT.into(),
        proof: proof.digest().unwrap(),
        audience: audience.into(),
        purpose: purpose.into(),
        body: body_digest.clone(),
        nonce: (0u8..16).collect(),
        created: created.into(),
    };
    let req_body = request.begin_sign().unwrap();
    let req = RawEnvelope::finish(
        req_body.clone(),
        signer.sign(&req_body),
        &signer.public().signing,
    )
    .unwrap();
    let expected = match name {
        "stale-head" => "refused:stale",
        "revoked-member" => "refused:revoked",
        "expired-member" => "refused:expired",
        "wider-scope" | "link-outlives-parent" | "depth-exceeded" => "refused:notNarrower",
        "copied-proof-wrong-key" | "unknown-term-bad-signature" => "badSignature",
        "unknown-term-signed" | "unknown-proof-signed" => "newerFormat",
        "session-ended" => "refused:ended",
        "wrong-audience" | "replayed-nonce" | "out-of-scope" => "refused:outOfScope",
        "old-request" => "refused:expired",
        _ => "ok",
    };
    json!({
        "name":name,"expected":expected,"unguarded":name=="session-unguarded",
        "account":ACCOUNT,"head":HEAD,"headSequence":41,
        "headPresent":name!="stale-head",
        "member":key(21).public().id(),
        "memberSigning":STANDARD.encode(key(21).public().signing),
        "memberTerms":base.to_value(),
        "memberExpires":if name=="expired-member" {"2026-11-10T09:00:00Z"} else {"2026-12-01T00:00:00Z"},
        "memberRevoked":name=="revoked-member",
        "sessionNumber":if name=="session-unguarded" {Value::Null} else {json!(if name=="session-ended" {4} else {3})},
        "actingSigning":STANDARD.encode(signer.public().signing),
        "purpose":purpose,"now":NOW,"args":{"amount":25},
        "proof":proof_value,
        "request":serde_json::from_slice::<Value>(&req.encode().unwrap()).unwrap(),
        "audience":AUDIENCE,"bodyDigest":body_digest,
        "nonceSeen":name=="replayed-nonce"
    })
}
fn speaks_cases() -> Vec<Value> {
    [
        "member-only",
        "three-links",
        "wider-scope",
        "link-outlives-parent",
        "depth-exceeded",
        "copied-proof-wrong-key",
        "unknown-term-signed",
        "unknown-term-bad-signature",
        "session-ended",
        "session-unguarded",
        "wrong-audience",
        "old-request",
        "replayed-nonce",
        "stale-head",
        "revoked-member",
        "expired-member",
        "out-of-scope",
        "unknown-proof-signed",
    ]
    .into_iter()
    .map(speaks_case)
    .collect()
}

fn terms_case(name: &str, probe: &str, spec: Value, expected: &str) -> Value {
    json!({"name":name,"probe":probe,"spec":spec,"expected":expected})
}
fn terms_cases() -> Vec<Value> {
    let a = json!({
        "scope":[{"namespace":"notes","access":"write","kinds":["add","edit"]}],
        "expires":"2027-01-01T00:00:00Z","depth":5,"writes":10,
        "requires":["uv"],"conditions":[{"lte":["args.amount",5000]}],
        "serves":["home","authority"]
    });
    let b = json!({
        "scope":[{"namespace":"notes","access":"propose","kinds":["add"]}],
        "expires":"2026-12-01T00:00:00Z","depth":4,"writes":9,
        "requires":["uv"],"conditions":[{"lte":["args.amount",5000]},{"gte":["args.amount",0]}],
        "serves":["home"]
    });
    let mut cases = Vec::new();
    cases.push(terms_case(
        "narrow-all-rules-pass",
        "narrow",
        json!({"parent":a,"child":b}),
        "ok",
    ));
    for (name, field, bad) in [
        (
            "scope-widens",
            "scope",
            json!([{"namespace":"notes","access":"write","kinds":["delete"]}]),
        ),
        ("expiry-widens", "expires", json!("2028-01-01T00:00:00Z")),
        ("depth-not-less", "depth", json!(5)),
        ("writes-widens", "writes", json!(11)),
        ("requires-dropped", "requires", json!([])),
        ("conditions-dropped", "conditions", json!([])),
        ("serves-widens", "serves", json!(["home", "authority"])),
    ] {
        let mut child = b.clone();
        child[field] = bad;
        // For serves, shrink the parent's services to detect an actual expansion.
        let mut parent = a.clone();
        if name == "serves-widens" {
            parent["serves"] = json!(["home"]);
        }
        cases.push(terms_case(
            name,
            "narrow",
            json!({"parent":parent,"child":child}),
            "refused:notNarrower",
        ));
    }
    for (name, field, good) in [
        ("scope-equal", "scope", a["scope"].clone()),
        ("expiry-equal", "expires", a["expires"].clone()),
        ("depth-smaller", "depth", json!(0)),
        ("writes-equal", "writes", a["writes"].clone()),
        ("requires-retained", "requires", a["requires"].clone()),
        (
            "conditions-more",
            "conditions",
            json!([{"lte":["args.amount",5000]},{"gte":["args.amount",0]},{"prefix":["args.name","A"]}]),
        ),
        ("serves-less", "serves", json!([])),
    ] {
        let mut child = b.clone();
        child[field] = good;
        cases.push(terms_case(
            name,
            "narrow",
            json!({"parent":a,"child":child}),
            "ok",
        ));
    }
    let minimal = |conditions: Vec<Value>| {
        json!({
            "scope":[{"namespace":"notes","access":"write"}],
            "conditions": conditions
        })
    };
    let checks = [
        (
            "eq-pass",
            json!({"eq":["args.amount",5]}),
            json!({"amount":5}),
            true,
        ),
        (
            "eq-fail",
            json!({"eq":["args.amount",5]}),
            json!({"amount":6}),
            false,
        ),
        (
            "in-pass",
            json!({"in":["args.amount",[4,5,6]]}),
            json!({"amount":5}),
            true,
        ),
        (
            "in-fail",
            json!({"in":["args.amount",[4,6]]}),
            json!({"amount":5}),
            false,
        ),
        (
            "prefix-pass",
            json!({"prefix":["args.label","Ac"]}),
            json!({"label":"Acme"}),
            true,
        ),
        (
            "prefix-fail",
            json!({"prefix":["args.label","Ac"]}),
            json!({"label":"Other"}),
            false,
        ),
        (
            "lte-pass",
            json!({"lte":["args.amount",5]}),
            json!({"amount":5}),
            true,
        ),
        (
            "lte-fail",
            json!({"lte":["args.amount",5]}),
            json!({"amount":6}),
            false,
        ),
        (
            "gte-pass",
            json!({"gte":["args.amount",5]}),
            json!({"amount":5}),
            true,
        ),
        (
            "gte-fail",
            json!({"gte":["args.amount",5]}),
            json!({"amount":4}),
            false,
        ),
        (
            "all-pass",
            json!({"all":[{"gte":["args.amount",0]},{"lte":["args.amount",5]}]}),
            json!({"amount":5}),
            true,
        ),
        (
            "all-fail",
            json!({"all":[{"gte":["args.amount",0]},{"lte":["args.amount",5]}]}),
            json!({"amount":6}),
            false,
        ),
        (
            "any-pass",
            json!({"any":[{"eq":["args.amount",1]},{"eq":["args.amount",5]}]}),
            json!({"amount":5}),
            true,
        ),
        (
            "any-fail",
            json!({"any":[{"eq":["args.amount",1]},{"eq":["args.amount",5]}]}),
            json!({"amount":6}),
            false,
        ),
        (
            "not-pass",
            json!({"not":{"eq":["args.amount",4]}}),
            json!({"amount":5}),
            true,
        ),
        (
            "not-fail",
            json!({"not":{"eq":["args.amount",5]}}),
            json!({"amount":5}),
            false,
        ),
    ];
    for (name, condition, args, ok) in checks {
        cases.push(terms_case(
            name,
            "condition",
            json!({"terms":minimal(vec![condition]),"args":args,"uv":false}),
            if ok { "ok" } else { "refused:outOfScope" },
        ));
    }
    cases.push(terms_case(
        "predicate-32-bound",
        "parse",
        minimal((0..32).map(|_| json!({"eq":["args.amount",1]})).collect()),
        "ok",
    ));
    cases.push(terms_case(
        "predicate-33-beyond",
        "parse",
        minimal((0..33).map(|_| json!({"eq":["args.amount",1]})).collect()),
        "malformed",
    ));
    cases.push(terms_case(
        "depth-4-bound",
        "parse",
        minimal(vec![
            json!({"not":{"not":{"not":{"eq":["args.amount",1]}}}}),
        ]),
        "ok",
    ));
    cases.push(terms_case(
        "depth-5-beyond",
        "parse",
        minimal(vec![
            json!({"not":{"not":{"not":{"not":{"eq":["args.amount",1]}}}}}),
        ]),
        "malformed",
    ));
    let mut length = 0;
    for n in 0..=4096 {
        if records::canonical(&vec![json!({"prefix":["args.x","x".repeat(n)]})])
            .unwrap()
            .len()
            == 4096
        {
            length = n;
            break;
        }
    }
    assert!(length > 0);
    cases.push(terms_case(
        "condition-4096-bound",
        "parse",
        minimal(vec![json!({"prefix":["args.x","x".repeat(length)]})]),
        "ok",
    ));
    cases.push(terms_case(
        "condition-4097-beyond",
        "parse",
        minimal(vec![json!({"prefix":["args.x","x".repeat(length+1)]})]),
        "malformed",
    ));
    cases.push(terms_case(
        "unknown-condition",
        "parse",
        minimal(vec![json!({"newOp":["args.x",1]})]),
        "newerFormat",
    ));
    cases.push(terms_case(
        "unknown-term",
        "parse",
        json!({"scope":[{"namespace":"notes","access":"write"}],"futureCap":5}),
        "newerFormat",
    ));
    cases.push(terms_case("requires-uv-pass","condition",json!({"terms":{"scope":[{"namespace":"notes","access":"read"}],"requires":["uv"]},"args":{},"uv":true}),"ok"));
    cases.push(terms_case("requires-uv-fail","condition",json!({"terms":{"scope":[{"namespace":"notes","access":"read"}],"requires":["uv"]},"args":{},"uv":false}),"refused:outOfScope"));
    cases.push(terms_case(
        "purpose-write",
        "purpose",
        json!({"terms":minimal(vec![]),"purpose":"write:notes:add"}),
        "ok",
    ));
    cases.push(terms_case(
        "purpose-unknown",
        "purpose",
        json!({"terms":minimal(vec![]),"purpose":"execute:notes:add"}),
        "refused:outOfScope",
    ));
    cases
}

struct History {
    account: String,
    head: String,
    present: bool,
    member_id: String,
    member: Member,
    session: Option<u64>,
}
impl VerifiedHistory for History {
    fn contains(&self, account: &str, seq: u64, digest: &str) -> bool {
        self.present && self.account == account && seq == 41 && self.head == digest
    }
    fn member(&self, account: &str, id: &str) -> Option<Member> {
        (account == self.account && id == self.member_id).then(|| self.member.clone())
    }
    fn session_number(&self, _account: &str, _id: &str) -> Option<u64> {
        self.session
    }
}
fn replay_speaks(v: &Value) {
    let proof_bytes = records::canonical(&v["proof"]).unwrap();
    let proof = Proof::from_json(&proof_bytes).unwrap();
    let request_bytes = records::canonical(&v["request"]).unwrap();
    let request = RawEnvelope::from_json(&request_bytes).unwrap();
    let signing = STANDARD
        .decode(v["actingSigning"].as_str().unwrap())
        .unwrap();
    let member_signing = STANDARD
        .decode(v["memberSigning"].as_str().unwrap())
        .unwrap();
    let member_terms = Terms::from_value(&v["memberTerms"]).unwrap();
    let h = History {
        account: v["account"].as_str().unwrap().into(),
        head: v["head"].as_str().unwrap().into(),
        present: v["headPresent"].as_bool().unwrap(),
        member_id: v["member"].as_str().unwrap().into(),
        member: Member {
            signing: member_signing,
            terms: member_terms,
            expires: Some(v["memberExpires"].as_str().unwrap().into()),
            revoked: v["memberRevoked"].as_bool().unwrap(),
        },
        session: v["sessionNumber"].as_u64(),
    };
    let got = speaks::check(
        CheckInput {
            proof: &proof,
            acting_signing: &signing,
            purpose: v["purpose"].as_str().unwrap(),
            now: v["now"].as_str().unwrap(),
            arguments: &v["args"],
            request: &request,
            audience: v["audience"].as_str().unwrap(),
            body_digest: v["bodyDigest"].as_str().unwrap(),
            uv: false,
        },
        &h,
        |_| v["nonceSeen"].as_bool().unwrap(),
    );
    assert_eq!(got.code(), v["expected"].as_str().unwrap(), "{}", v["name"]);
    if let Verdict::Ok { unguarded } = got {
        assert_eq!(
            unguarded,
            v["unguarded"].as_bool().unwrap(),
            "{}",
            v["name"]
        );
    }
}
fn replay_terms(v: &Value) {
    let expected = v["expected"].as_str().unwrap();
    let spec = &v["spec"];
    let code = match v["probe"].as_str().unwrap() {
        "parse" => Terms::from_value(spec)
            .map(|_| Verdict::Ok { unguarded: false })
            .unwrap_or_else(|e| e),
        "narrow" => {
            let a = Terms::from_value(&spec["parent"]).unwrap();
            let b = Terms::from_value(&spec["child"]).unwrap();
            if a.narrows(&b) {
                Verdict::Ok { unguarded: false }
            } else {
                Verdict::Refused(colophon_core::legacy_draft1::Refusal::NotNarrower)
            }
        }
        "condition" => {
            let terms = Terms::from_value(&spec["terms"]).unwrap();
            if terms.conditions_hold(&spec["args"], spec["uv"].as_bool().unwrap()) {
                Verdict::Ok { unguarded: false }
            } else {
                Verdict::Refused(colophon_core::legacy_draft1::Refusal::OutOfScope)
            }
        }
        "purpose" => {
            let terms = Terms::from_value(&spec["terms"]).unwrap();
            if terms.allows(spec["purpose"].as_str().unwrap()) {
                Verdict::Ok { unguarded: false }
            } else {
                Verdict::Refused(colophon_core::legacy_draft1::Refusal::OutOfScope)
            }
        }
        _ => panic!("unknown probe"),
    };
    assert_eq!(code.code(), expected, "{}", v["name"]);
}
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5/legacy-draft-1")
}
fn check_group(group: &str, generated: Vec<Value>, replay: fn(&Value)) {
    let dir = root().join(group);
    if std::env::var_os("COLOPHON_WRITE_V5_VECTORS").is_some() {
        fs::create_dir_all(&dir).unwrap();
        for item in &generated {
            let name = item["name"].as_str().unwrap();
            let path = dir.join(format!("{name}.json"));
            let mut bytes = records::canonical(item).unwrap();
            bytes.push(b'\n');
            fs::write(path, bytes).unwrap();
        }
    }
    let mut names = std::collections::BTreeSet::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let parsed = strict_json::parse(&bytes).unwrap();
        let name = parsed["name"].as_str().unwrap().to_string();
        assert!(names.insert(name.clone()), "duplicate case");
        let original = generated.iter().find(|x| x["name"] == name).unwrap();
        assert_eq!(
            &parsed, original,
            "fixture no longer equals deterministic generator: {name}"
        );
        replay(&parsed);
    }
    assert_eq!(
        names.len(),
        generated.len(),
        "incomplete {group} vector directory"
    );
}
#[test]
fn published_legacy_draft1_conformance() {
    check_group("speaks-for", speaks_cases(), replay_speaks);
    check_group("terms", terms_cases(), replay_terms);
}
