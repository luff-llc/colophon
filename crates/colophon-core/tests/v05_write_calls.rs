//! E3: the call-side builders (request, links, calls, heads, receipts) produce objects the 0.5
//! verifiers accept, refuse what they would refuse, reproduce the candidate vectors byte for
//! byte from the published keys, and drive `history::home` admission end to end.
//!
//! Signing happens here with the vectors' public test keys; the builders never see a key. The
//! encoding in this file uses the core's `canonical` only; nothing is shared with the vector
//! generator in `tests/v5_candidate/`.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::{
    calls::{
        AccountView, CallConfig, ControllerStatus, HistoryVerifierOutput, MemberStatus,
        ViewController, ViewMember,
    },
    descriptor::{Controller, Policy},
    encoding::{canonical, digest, parse_date},
    heads::HeadContext,
    history::home::{admit, HomeState, ReceiptToSign, Refusal, ServingInterval},
    history::{verify_history, Objects, Persisted},
    ids::{key_id, AccountId},
    members::MemberKind,
    terms::{Terms, TermsKind},
    write::calls::{
        finish_call, finish_head, finish_link, finish_receipt, finish_request, prepare_call,
        prepare_head, prepare_link, prepare_receipt, prepare_request, CallSignerSpec, CallSpec,
        HeadSpec, LinkSpec, RequestSpec,
    },
    write::{SignatureResult, SigningStep},
    Failure,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::{fs, path::PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn cand() -> PathBuf {
    repo().join("conformance/0.5/candidate")
}
fn read(path: PathBuf) -> Vec<u8> {
    fs::read(path).unwrap()
}
fn json_of(path: PathBuf) -> Value {
    serde_json::from_slice(&read(path)).unwrap()
}
fn unb64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}
fn ms(s: &str) -> i64 {
    parse_date(s).unwrap()
}

struct K {
    sk: SigningKey,
    point: Vec<u8>,
}
impl K {
    fn id(&self) -> String {
        key_id(&self.point)
    }
    fn sign(&self, body: &[u8]) -> SignatureResult {
        SignatureResult {
            signature: raw_sign(&self.sk, body),
            assertion: None,
        }
    }
}
fn raw_sign(sk: &SigningKey, body: &[u8]) -> Vec<u8> {
    let s: Signature = sk.sign(body);
    s.to_bytes().to_vec()
}
fn candidate_key(name: &str) -> K {
    let keys = json_of(cand().join("keys.json"));
    let k = &keys["keys"][name];
    let sk = SigningKey::from_slice(&unb64(k["scalar"].as_str().unwrap())).unwrap();
    let point = unb64(k["signing"].as_str().unwrap());
    assert_eq!(
        sk.verifying_key().to_encoded_point(false).as_bytes(),
        point.as_slice()
    );
    K { sk, point }
}
fn derived_key(name: &str) -> K {
    let scalar = Sha256::digest(format!("colophon-0.5-candidate/{name}").as_bytes());
    let sk = SigningKey::from_slice(&scalar).unwrap();
    let point = sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    K { sk, point }
}
fn envelope(body: &[u8], sig: &[u8]) -> Vec<u8> {
    canonical(&json!({"body": STANDARD.encode(body), "signature": STANDARD.encode(sig)})).unwrap()
}
fn body_of(env_bytes: &[u8]) -> Vec<u8> {
    let v: Value = serde_json::from_slice(env_bytes).unwrap();
    unb64(v["body"].as_str().unwrap())
}
fn sig_of(env_bytes: &[u8]) -> Vec<u8> {
    let v: Value = serde_json::from_slice(env_bytes).unwrap();
    unb64(v["signature"].as_str().unwrap())
}
fn raw_of(sig: &SignatureResult) -> Vec<u8> {
    assert!(sig.assertion.is_none());
    sig.signature.clone()
}
fn trim(b: &[u8]) -> &[u8] {
    b.trim_ascii_end()
}

const AUD: &str = "https://projects.example/scopes/7";
const NOW: &str = "2026-11-11T09:01:00Z";

/// The candidate `account/` fixture: its history, view, policy and homes.
struct Account {
    id: AccountId,
    history: Vec<String>,
    view: AccountView,
    link_max_age_s: u64,
    homes: Vec<(String, Vec<u8>)>,
    principals: BTreeSet<Vec<u8>>,
    members_points: BTreeSet<Vec<u8>>,
    objects: Objects,
}
fn account() -> Account {
    let mut objects = Objects::default();
    for seq in 1..=3 {
        objects.entries.push(read(
            cand().join(format!("account/records/authority/{seq:08}.json")),
        ));
    }
    objects.heads.push(read(cand().join("account/head.json")));
    let now = ms(NOW);
    let verdict = verify_history(&objects, &Persisted::default(), now);
    assert!(verdict.stop.is_none());
    let view = AccountView::from_history_verifier(&verdict, &objects, now).unwrap();
    let st = verdict.state.as_ref().unwrap();
    Account {
        id: st.account().clone(),
        history: st.history().to_vec(),
        view,
        link_max_age_s: st.keyring().policy.link_max_age(),
        homes: st
            .current_homes()
            .into_iter()
            .map(|m| (m.request.member_id(), m.request.signing.clone()))
            .collect(),
        principals: st
            .members()
            .iter()
            .flat_map(|m| [m.request.signing.clone(), m.request.agreement.clone()])
            .chain(
                st.keyring()
                    .controllers
                    .values()
                    .map(|c| c.key().signing().to_vec()),
            )
            .collect(),
        members_points: st
            .members()
            .iter()
            .flat_map(|m| [m.request.signing.clone(), m.request.agreement.clone()])
            .collect(),
        objects,
    }
}
fn cfg<'a>(
    audiences: &'a [String],
    origins: &'a BTreeMap<String, Vec<String>>,
    purposes: &'a [String],
) -> CallConfig<'a> {
    CallConfig {
        now_ms: ms(NOW),
        audiences,
        call_origins: origins,
        controller_purposes: purposes,
        home_endpoints: &[],
    }
}
fn code(r: &Result<Vec<u8>, Failure>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.code(),
    }
}

// ---------------------------------------------------------------------------------------------
// The 14 call cases.

struct LinkDef {
    from: &'static str,
    to: &'static str,
    terms: Value,
    session: Option<u64>,
    nb: &'static str,
    exp: &'static str,
}
struct CallCase {
    name: &'static str,
    acting: &'static str,
    links: Vec<LinkDef>,
    audience: &'static str,
    purpose: &'static str,
    args: Value,
    seed: &'static str,
    created: &'static str,
    /// The vector's signature is not the honest one (it is over other bytes on purpose).
    bad_signature: bool,
}
const NB0: &str = "2026-11-11T09:00:00Z";
const EXP0: &str = "2026-11-11T09:10:00Z";
fn narrow() -> Value {
    json!({"services": [{"audience": AUD, "purposes": ["task.read"]}], "conditions": [{"prefix": ["args.task", "T-"]}]})
}
fn wide() -> Value {
    json!({"services": [{"audience": AUD, "purposes": ["*"]}], "conditions": [{"prefix": ["args.task", "T-"]}]})
}
fn with_conds(extra: Value) -> Value {
    let mut t = narrow();
    t["conditions"].as_array_mut().unwrap().push(extra);
    t
}
fn l(from: &'static str, to: &'static str, terms: Value, session: Option<u64>) -> LinkDef {
    LinkDef {
        from,
        to,
        terms,
        session,
        nb: NB0,
        exp: EXP0,
    }
}
fn case(name: &'static str, seed: &'static str) -> CallCase {
    CallCase {
        name,
        acting: "agent/signing",
        links: vec![],
        audience: AUD,
        purpose: "task.read",
        args: json!({"task": "T-12"}),
        seed,
        created: "2026-11-11T09:01:00Z",
        bad_signature: false,
    }
}
fn call_cases() -> Vec<CallCase> {
    let mut cases = vec![
        case("member-no-links", "1"),
        CallCase {
            acting: "session/1",
            links: vec![l("agent/signing", "session/1", narrow(), Some(0))],
            ..case("one-link", "2")
        },
        CallCase {
            acting: "attacker",
            links: vec![l("agent/signing", "session/1", narrow(), Some(0))],
            ..case("copied-link", "3")
        },
        CallCase {
            bad_signature: true,
            ..case("invalid-call-signature", "4")
        },
        CallCase {
            audience: "https://other.example",
            ..case("wrong-audience", "5")
        },
        CallCase {
            created: "2026-11-11T08:50:00Z",
            ..case("outside-window", "6")
        },
        CallCase {
            acting: "session/1",
            links: vec![l("agent/signing", "session/1", wide(), Some(0))],
            purpose: "task.delete",
            ..case("widening-link", "7")
        },
        CallCase {
            acting: "session/1",
            links: vec![l("agent/signing", "session/1", narrow(), Some(1))],
            ..case("ended-session", "8")
        },
        CallCase {
            purpose: "task.delete",
            ..case("out-of-scope-purpose", "9")
        },
        CallCase {
            args: json!({"task": "X-1"}),
            ..case("condition-fails", "10")
        },
        CallCase {
            acting: "session/2",
            links: vec![
                l("agent/signing", "session/1", narrow(), Some(0)),
                l("session/1", "session/2", narrow(), None),
            ],
            ..case("depth-exceeded", "11")
        },
        CallCase {
            acting: "session/1",
            links: vec![LinkDef {
                nb: "2026-11-11T08:00:00Z",
                exp: "2026-11-11T08:30:00Z",
                ..l("agent/signing", "session/1", narrow(), Some(0))
            }],
            ..case("link-expired", "12")
        },
    ];
    cases.push(CallCase {
        acting: "session/1",
        links: vec![l(
            "agent/signing",
            "session/1",
            with_conds(
                json!({"any": [{"prefix": ["args.task", "T-"]}, {"future": ["args.task", 1]}]}),
            ),
            Some(0),
        )],
        ..case("link-unknown-operator-not-deciding", "15")
    });
    cases.push(CallCase {
        acting: "session/1",
        links: vec![l(
            "agent/signing",
            "session/1",
            with_conds(
                json!({"any": [{"prefix": ["args.task", "X-"]}, {"future": ["args.task", 1]}]}),
            ),
            Some(0),
        )],
        ..case("link-unknown-operator-deciding", "16")
    });
    cases
}

#[test]
fn the_14_call_cases_reproduce_and_the_builders_agree_with_each_verdict() {
    let acct = account();
    let audiences = vec![AUD.to_string()];
    let origins = BTreeMap::new();
    let purposes: Vec<String> = Vec::new();
    let config = cfg(&audiences, &origins, &purposes);
    let agent = candidate_key("agent/signing");
    let as_of_digest = acct.history[2].clone();
    let mut reproduced_bytes = Vec::new();
    let mut body_and_sig_only = Vec::new();
    for c in call_cases() {
        let dir = cand().join("calls").join(c.name);
        let vector = read(dir.join("call.json"));
        let want = json_of(dir.join("case.json"))["expected"]
            .as_str()
            .unwrap()
            .to_string();
        // Links, member outward. A link the verifier refuses at finish is assembled here from
        // its prepared body so the call can still be built and judged.
        let mut link_bytes: Vec<Vec<u8>> = Vec::new();
        let mut link_failure: Option<String> = None;
        let mut parent_key = agent.point.clone();
        for (i, ld) in c.links.iter().enumerate() {
            let from = candidate_key(ld.from);
            assert_eq!(from.point, parent_key, "{}: link {i} from", c.name);
            let to = candidate_key(ld.to);
            let spec = LinkSpec {
                account: &acct.id,
                member: &agent.id(),
                prior: &link_bytes,
                to_signing: &to.point,
                terms: ld.terms.clone(),
                session: ld.session,
                not_before: ld.nb,
                expires: ld.exp,
                created: ld.nb,
            };
            let prepared = prepare_link(&acct.view, &spec).unwrap();
            assert_eq!(prepared.step().signer(), from.id());
            assert_eq!(prepared.step().signing(), from.point.as_slice());
            let sig = from.sign(prepared.step().body());
            let finished = finish_link(&prepared, &sig, &acct.view, ms(NOW));
            let bytes = match finished {
                Ok(b) => b,
                Err(e) => {
                    link_failure.get_or_insert(e.code());
                    envelope(prepared.step().body(), &raw_of(&sig))
                }
            };
            parent_key = to.point.clone();
            link_bytes.push(bytes);
        }
        let acting = candidate_key(c.acting);
        let request_id: [u8; 32] = Sha256::digest(format!("request/{}", c.seed).as_bytes()).into();
        let spec = CallSpec {
            account: &acct.id,
            as_of: (3, &as_of_digest),
            signer: CallSignerSpec::Member(agent.id()),
            key: &acting.point,
            links: &link_bytes,
            audience: c.audience,
            purpose: c.purpose,
            args: c.args.clone(),
            request_id,
            created: c.created,
            webauthn: false,
        };
        let prepared = prepare_call(&spec).unwrap();
        assert_eq!(
            prepared.step().body(),
            body_of(&vector),
            "{}: body differs from the vector",
            c.name
        );
        assert_eq!(prepared.step().challenge(), None);
        let sig = if c.bad_signature {
            SignatureResult {
                signature: sig_of(&vector),
                assertion: None,
            }
        } else {
            let sig = acting.sign(prepared.step().body());
            assert_eq!(
                raw_of(&sig),
                sig_of(&vector),
                "{}: signature differs",
                c.name
            );
            sig
        };
        let result = finish_call(&prepared, &sig, &acct.view, &config);
        assert_eq!(code(&result), want, "{}", c.name);
        if let Some(lf) = &link_failure {
            assert_eq!(
                lf, &want,
                "{}: link refusal differs from the verdict",
                c.name
            );
        }
        match result {
            Ok(bytes) => {
                assert_eq!(bytes, trim(&vector), "{}: envelope bytes", c.name);
                reproduced_bytes.push(c.name);
            }
            Err(_) => {
                // Nothing is returned on refusal; the vector is its body and signature.
                let rebuilt = envelope(prepared.step().body(), &raw_of(&sig));
                assert_eq!(rebuilt, trim(&vector), "{}: assembled envelope", c.name);
                body_and_sig_only.push(c.name);
            }
        }
    }
    assert_eq!(reproduced_bytes.len() + body_and_sig_only.len(), 14);
    assert_eq!(
        reproduced_bytes,
        vec![
            "member-no-links",
            "one-link",
            "link-unknown-operator-not-deciding"
        ]
    );
}

#[test]
fn a_link_chain_of_four_verifies_and_a_fifth_is_refused() {
    let acct = account();
    let agent = candidate_key("agent/signing");
    let home = candidate_key("home/signing");
    let now = ms(NOW);
    // A member with depth 4, over a view built from parts: the history and head are the
    // fixture's, the member is the agent with terms that allow four links.
    let terms = Terms::parse(
        json!({"services": [{"audience": AUD, "purposes": ["task.read"]}], "depth": 4}),
        TermsKind::Member,
    )
    .unwrap();
    let home_terms = Terms::parse(json!({"serves": ["home"]}), TermsKind::Member).unwrap();
    let view = AccountView::from_parts_unverified(HistoryVerifierOutput {
        account: acct.id.clone(),
        history: acct.history.clone(),
        policies: vec![(1, Policy::default_person())],
        controllers: vec![],
        members: vec![
            ViewMember::new(
                agent.point.clone(),
                MemberKind::Agent,
                terms.clone(),
                2,
                vec![],
                vec![],
                None,
                MemberStatus::Active,
            )
            .unwrap(),
            ViewMember::new(
                home.point.clone(),
                MemberKind::Server,
                home_terms,
                3,
                vec![],
                vec![],
                None,
                MemberStatus::Active,
            )
            .unwrap(),
        ],
        heads: acct.objects.heads.clone(),
        vouched_fork: false,
        principal_points: BTreeSet::new(),
    })
    .unwrap();
    let audiences = vec![AUD.to_string()];
    let origins = BTreeMap::new();
    let purposes: Vec<String> = Vec::new();
    let config = cfg(&audiences, &origins, &purposes);
    let keys: Vec<K> = (0..5)
        .map(|i| derived_key(&format!("e3/chain/{i}")))
        .collect();
    let mut parent_signer: &SigningKey = &agent.sk;
    let mut links: Vec<Vec<u8>> = Vec::new();
    let member = agent.id();
    for (i, to) in keys.iter().enumerate() {
        let depth = 3 - i as i64;
        let link_terms = if depth < 0 {
            json!({"services": [{"audience": AUD, "purposes": ["task.read"]}]})
        } else {
            json!({"services": [{"audience": AUD, "purposes": ["task.read"]}], "depth": depth})
        };
        let spec = LinkSpec {
            account: &acct.id,
            member: &member,
            prior: &links,
            to_signing: &to.point,
            terms: link_terms,
            session: (i == 0).then_some(0),
            not_before: NB0,
            expires: EXP0,
            created: NB0,
        };
        if i == 4 {
            // A fifth link is refused at prepare (at most 4).
            assert!(prepare_link(&view, &spec).is_err());
            break;
        }
        let p = prepare_link(&view, &spec).unwrap();
        let sig = SignatureResult {
            signature: raw_sign(parent_signer, p.step().body()),
            assertion: None,
        };
        links.push(finish_link(&p, &sig, &view, now).unwrap());
        parent_signer = &to.sk;
    }
    assert_eq!(links.len(), 4);
    let acting = &keys[3];
    let spec = CallSpec {
        account: &acct.id,
        as_of: (3, &acct.history[2]),
        signer: CallSignerSpec::Member(agent.id()),
        key: &acting.point,
        links: &links,
        audience: AUD,
        purpose: "task.read",
        args: json!({}),
        request_id: [7; 32],
        created: "2026-11-11T09:01:00Z",
        webauthn: false,
    };
    let p = prepare_call(&spec).unwrap();
    let r = finish_call(&p, &acting.sign(p.step().body()), &view, &config);
    assert_eq!(code(&r), "ok");
    // A fifth link is not accepted by prepare.
    let mut five = links.clone();
    five.push(links[0].clone());
    let too_many = CallSpec {
        links: &five,
        ..spec.clone()
    };
    assert!(prepare_call(&too_many).is_err());
    // Links out of order break the `session`-on-the-first-link rule at parse.
    let reversed: Vec<Vec<u8>> = links.iter().rev().cloned().collect();
    let swapped = CallSpec {
        links: &reversed,
        ..spec.clone()
    };
    let p = prepare_call(&swapped).unwrap();
    assert_eq!(
        code(&finish_call(
            &p,
            &acting.sign(p.step().body()),
            &view,
            &config
        )),
        "malformed"
    );
}

#[test]
fn refusals_return_nothing() {
    let acct = account();
    let agent = candidate_key("agent/signing");
    let audiences = vec![AUD.to_string()];
    let origins = BTreeMap::new();
    let purposes: Vec<String> = Vec::new();
    let config = cfg(&audiences, &origins, &purposes);
    let base = CallSpec {
        account: &acct.id,
        as_of: (3, &acct.history[2]),
        signer: CallSignerSpec::Member(agent.id()),
        key: &agent.point,
        links: &[],
        audience: AUD,
        purpose: "task.read",
        args: json!({"task": "T-12"}),
        request_id: [1; 32],
        created: "2026-11-11T09:01:00Z",
        webauthn: false,
    };
    let p = prepare_call(&base).unwrap();
    assert_eq!(
        code(&finish_call(
            &p,
            &agent.sign(p.step().body()),
            &acct.view,
            &config
        )),
        "ok"
    );
    // A call outside its window.
    let late = CallSpec {
        created: "2026-11-11T08:00:00Z",
        ..base.clone()
    };
    let p = prepare_call(&late).unwrap();
    assert_eq!(
        code(&finish_call(
            &p,
            &agent.sign(p.step().body()),
            &acct.view,
            &config
        )),
        "refused:window"
    );
    // A wrong-digest asOf is a fork.
    let wrong = CallSpec {
        as_of: (3, &"1".repeat(64)),
        ..base.clone()
    };
    let p = prepare_call(&wrong).unwrap();
    assert_eq!(
        code(&finish_call(
            &p,
            &agent.sign(p.step().body()),
            &acct.view,
            &config
        )),
        "refused:fork"
    );
    // A signature by another key.
    let p = prepare_call(&base).unwrap();
    let other = candidate_key("attacker");
    assert_eq!(
        code(&finish_call(
            &p,
            &other.sign(p.step().body()),
            &acct.view,
            &config
        )),
        "badSignature"
    );
    // A short signature, and an assertion where none is allowed, never reach the verifier.
    assert!(finish_call(
        &p,
        &SignatureResult {
            signature: vec![0; 63],
            assertion: None,
        },
        &acct.view,
        &config
    )
    .is_err());
    let assertion = SignatureResult {
        signature: vec![0x30, 0x06, 2, 1, 1, 2, 1, 1],
        assertion: Some((vec![0; 37], b"{}".to_vec())),
    };
    assert!(finish_call(&p, &assertion, &acct.view, &config).is_err());
    // prepare refuses shapes that can never verify.
    assert!(prepare_call(&CallSpec {
        args: json!([1]),
        ..base.clone()
    })
    .is_err());
    assert!(prepare_call(&CallSpec {
        signer: CallSignerSpec::Controller(agent.id()),
        links: &[vec![1]],
        ..base.clone()
    })
    .is_err());
    assert!(prepare_call(&CallSpec {
        webauthn: true,
        ..base.clone()
    })
    .is_err());
    // A replayed call is a new reservation at the builder: the service's store is not used.
    let p = prepare_call(&base).unwrap();
    assert!(finish_call(&p, &agent.sign(p.step().body()), &acct.view, &config).is_ok());
}

#[test]
fn a_webauthn_controller_call_carries_its_challenge_and_verifies() {
    let acct = account();
    let controller = derived_key("e3/controller/webauthn");
    let c = Controller::parse(
        json!({"key": {"form": "webauthn", "signing": STANDARD.encode(&controller.point),
                       "rp": "id.example", "credential": "Y3JlZA=="},
               "label": "Passkey", "roles": ["approve", "control"], "verification": true}),
        "controller",
    )
    .unwrap();
    let id = c.id();
    assert_eq!(id, controller.id());
    let home = candidate_key("home/signing");
    let home_terms = Terms::parse(json!({"serves": ["home"]}), TermsKind::Member).unwrap();
    let view = AccountView::from_parts_unverified(HistoryVerifierOutput {
        account: acct.id.clone(),
        history: acct.history.clone(),
        policies: vec![(1, Policy::default_person())],
        controllers: vec![ViewController::new(
            id.clone(),
            vec![(1, Some(c))],
            ControllerStatus::Active,
        )
        .unwrap()],
        members: vec![ViewMember::new(
            home.point.clone(),
            MemberKind::Server,
            home_terms,
            3,
            vec![],
            vec![],
            None,
            MemberStatus::Active,
        )
        .unwrap()],
        heads: acct.objects.heads.clone(),
        vouched_fork: false,
        principal_points: BTreeSet::new(),
    })
    .unwrap();
    let audiences = vec!["https://admin.example".to_string()];
    let origins = BTreeMap::from([(
        "id.example".to_string(),
        vec!["https://id.example".to_string()],
    )]);
    let purposes = vec!["admin.act".to_string()];
    let config = cfg(&audiences, &origins, &purposes);
    let spec = CallSpec {
        account: &acct.id,
        as_of: (3, &acct.history[2]),
        signer: CallSignerSpec::Controller(id),
        key: &controller.point,
        links: &[],
        audience: "https://admin.example",
        purpose: "admin.act",
        args: json!({}),
        request_id: [9; 32],
        created: "2026-11-11T09:01:00Z",
        webauthn: true,
    };
    let p = prepare_call(&spec).unwrap();
    let challenge = p.step().challenge().unwrap().to_string();
    assert_eq!(
        challenge,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(p.step().body()))
    );
    let assert = |origin: &str, flags: u8| {
        let mut auth = Sha256::digest(b"id.example").to_vec();
        auth.extend_from_slice(&[flags, 0, 0, 0, 1]);
        let client =
            canonical(&json!({"type": "webauthn.get", "challenge": challenge, "origin": origin}))
                .unwrap();
        let mut m = auth.clone();
        m.extend_from_slice(&Sha256::digest(&client));
        let s: Signature = controller.sk.sign(&m);
        SignatureResult {
            signature: s.to_der().as_bytes().to_vec(),
            assertion: Some((auth, client)),
        }
    };
    let ok = finish_call(&p, &assert("https://id.example", 0x05), &view, &config).unwrap();
    assert!(String::from_utf8(ok).unwrap().contains("\"assertion\""));
    // Without UV the descriptor's `verification` fails; from another origin it is `origin`.
    assert_eq!(
        code(&finish_call(
            &p,
            &assert("https://id.example", 0x01),
            &view,
            &config
        )),
        "badSignature"
    );
    assert_eq!(
        code(&finish_call(
            &p,
            &assert("https://elsewhere.id.example", 0x05),
            &view,
            &config
        )),
        "refused:origin"
    );
    // A raw signature for a WebAuthn signer is refused before the verifier.
    assert!(finish_call(&p, &controller.sign(p.step().body()), &view, &config).is_err());
}

// ---------------------------------------------------------------------------------------------
// The 4 head cases.

#[test]
fn the_4_head_cases_reproduce_and_refuse() {
    // §13.3 (revision 13 fix round): `prepare_head` takes the guard `HomeState::guard_head`
    // returns, so only heads the home may sign reach a signature. The two vector heads the home
    // may sign are reproduced byte for byte; the other two are refused by the guard (a non-home
    // has no home state, a digest the home has not verified) and still judged by the verifier,
    // through `finish_head`, from the bytes the vectors ship.
    let acct = account();
    let home = candidate_key("home/signing");
    let agent = candidate_key("agent/signing");
    let now = ms(NOW);
    let ctx = || HeadContext {
        account: &acct.id,
        history: &acct.history,
        homes: &acct.homes,
        now_ms: now,
    };
    let mut objects = Objects::default();
    for seq in 1..=3 {
        objects.entries.push(read(
            cand().join(format!("account/records/authority/{seq:08}.json")),
        ));
    }
    let home_state =
        || HomeState::new(home_id(&home).to_string(), &objects, always(), now).unwrap();
    let seq3 = &acct.history[2];
    let mut reproduced = Vec::new();
    for (name, issued) in [
        ("valid", "2026-11-11T09:00:00Z"),
        ("stale", "2026-11-11T08:50:00Z"),
    ] {
        let vector = read(cand().join("heads").join(name).join("head.json"));
        let (_, guard) = home_state().guard_head(3, seq3, issued, NOW).unwrap();
        let prepared = prepare_head(
            &HeadSpec {
                account: &acct.id,
                seq: 3,
                digest: seq3,
                issued,
                by: home_id(&home),
            },
            &guard,
        )
        .unwrap();
        assert_eq!(prepared.step().signer(), home_id(&home));
        assert_eq!(prepared.step().body(), body_of(&vector), "{name}: body");
        let sig = home.sign(prepared.step().body());
        assert_eq!(raw_of(&sig), sig_of(&vector), "{name}: signature");
        let bytes = finish_head(&prepared, &sig, ctx()).unwrap();
        assert_eq!(bytes, trim(&vector), "{name}: envelope");
        reproduced.push(name);
    }
    assert_eq!(reproduced, vec!["valid", "stale"]);
    // A non-home key has no home state; a fork digest and a head for an entry the home has not
    // verified are refused by the guard before anything is prepared.
    assert!(HomeState::new(home_id(&agent).to_string(), &objects, always(), now).is_err());
    assert!(home_state()
        .guard_head(3, &"1".repeat(64), "2026-11-11T09:00:00Z", NOW)
        .is_err());
    assert!(home_state()
        .guard_head(4, &"2".repeat(64), "2026-11-11T09:00:00Z", NOW)
        .is_err());
    // Shape refusals at the guard: seq 0, bad digest, bad date.
    for (seq, dg, at) in [
        (0, seq3.as_str(), "2026-11-11T09:00:00Z"),
        (3, "xyz", "2026-11-11T09:00:00Z"),
        (3, seq3.as_str(), "yesterday"),
    ] {
        assert!(home_state().guard_head(seq, dg, at, NOW).is_err());
    }
    // A guard for one head does not prepare another, or one by another home.
    let (_, guard) = home_state()
        .guard_head(3, seq3, "2026-11-11T09:00:00Z", NOW)
        .unwrap();
    let other = |issued: &'static str, by: &str| {
        prepare_head(
            &HeadSpec {
                account: &acct.id,
                seq: 3,
                digest: seq3,
                issued,
                by,
            },
            &guard,
        )
    };
    assert!(other("2026-11-11T09:00:01Z", home_id(&home)).is_err());
    assert!(other("2026-11-11T09:00:00Z", home_id(&agent)).is_err());
    // A head issued more than 60 s ahead of the clock waits at the verifier (`unavailable`).
    let (_, g) = home_state()
        .guard_head(3, seq3, "2026-11-11T09:02:30Z", NOW)
        .unwrap();
    let future = prepare_head(
        &HeadSpec {
            account: &acct.id,
            seq: 3,
            digest: seq3,
            issued: "2026-11-11T09:02:30Z",
            by: home_id(&home),
        },
        &g,
    )
    .unwrap();
    assert_eq!(
        code(&finish_head(
            &future,
            &home.sign(future.step().body()),
            ctx()
        )),
        "unavailable"
    );
}
fn home_id(k: &K) -> &'static str {
    Box::leak(k.id().into_boxed_str())
}

// ---------------------------------------------------------------------------------------------
// The request body (§9.1).

#[test]
fn the_agent_request_reproduces_and_refusals_return_nothing() {
    let acct = account();
    let agent = candidate_key("agent/signing");
    let agree = candidate_key("agent/agreement");
    let grant: Value = serde_json::from_slice(&body_of(&read(
        cand().join("account/records/authority/00000002.json"),
    )))
    .unwrap();
    let vector = unb64(grant["request"].as_str().unwrap());
    let spec = RequestSpec {
        account: &acct.id,
        signing: &agent.point,
        agreement: &agree.point,
        label: "Agent on test host",
        kind: "agent",
        terms: json!({"services": [{"audience": AUD, "purposes": ["task.propose", "task.read"]}], "depth": 1}),
        created: "2026-11-11T08:00:00Z",
        custody: None,
        operator: None,
        endpoints: None,
    };
    let p = prepare_request(&spec).unwrap();
    assert_eq!(p.step().path(), format!("requests/{}.json", agent.id()));
    assert_eq!(p.step().body(), body_of(&vector));
    let sig = agent.sign(p.step().body());
    assert_eq!(raw_of(&sig), sig_of(&vector));
    assert_eq!(finish_request(&p, &sig).unwrap(), vector);
    // Home request with `serves` and `service`.
    let home = candidate_key("home/signing");
    let hagree = candidate_key("home/agreement");
    let endpoint = format!("https://home.example/v1/accounts/{}", acct.id);
    let hv = unb64(
        serde_json::from_slice::<Value>(&body_of(&read(
            cand().join("account/records/authority/00000003.json"),
        )))
        .unwrap()["transition"]
            .as_str()
            .unwrap(),
    );
    let t: Value = serde_json::from_slice(&body_of(&hv)).unwrap();
    let home_vector = unb64(
        t["change"]["homes"]["appoint"][0]["request"]
            .as_str()
            .unwrap(),
    );
    let hp = prepare_request(&RequestSpec {
        account: &acct.id,
        signing: &home.point,
        agreement: &hagree.point,
        label: "Test home",
        kind: "server",
        terms: json!({"serves": ["home"]}),
        created: "2026-11-11T08:00:00Z",
        custody: None,
        operator: None,
        endpoints: Some(vec![endpoint.clone()]),
    })
    .unwrap();
    assert_eq!(hp.step().body(), body_of(&home_vector));
    assert_eq!(
        finish_request(&hp, &home.sign(hp.step().body())).unwrap(),
        home_vector
    );
    // Refusals.
    assert!(finish_request(&p, &candidate_key("attacker").sign(p.step().body())).is_err());
    let import = prepare_request(&RequestSpec {
        terms: json!({"services": [{"audience": AUD, "purposes": ["x"]}], "import": true}),
        ..spec.clone()
    })
    .unwrap();
    assert!(finish_request(&import, &agent.sign(import.step().body())).is_err());
    let custodial = prepare_request(&RequestSpec {
        custody: Some("custodial"),
        ..spec.clone()
    })
    .unwrap();
    assert!(finish_request(&custodial, &agent.sign(custodial.step().body())).is_err());
    let fine = prepare_request(&RequestSpec {
        custody: Some("custodial"),
        operator: Some("Example hosting"),
        ..spec.clone()
    })
    .unwrap();
    assert!(finish_request(&fine, &agent.sign(fine.step().body())).is_ok());
    let serves_without_service = prepare_request(&RequestSpec {
        terms: json!({"serves": ["home"]}),
        ..spec.clone()
    })
    .unwrap();
    assert!(finish_request(
        &serves_without_service,
        &agent.sign(serves_without_service.step().body())
    )
    .is_err());
    let unknown_kind = prepare_request(&RequestSpec {
        kind: "toaster",
        ..spec.clone()
    })
    .unwrap();
    assert!(finish_request(&unknown_kind, &agent.sign(unknown_kind.step().body())).is_err());
    assert!(prepare_request(&RequestSpec {
        agreement: &agent.point,
        ..spec.clone()
    })
    .map(|q| finish_request(&q, &agent.sign(q.step().body())))
    .unwrap()
    .is_err());
    assert!(prepare_request(&RequestSpec {
        created: "later",
        ..spec.clone()
    })
    .is_err());
    assert!(prepare_request(&RequestSpec {
        signing: &[1, 2, 3],
        ..spec.clone()
    })
    .is_err());
    // A WebAuthn assertion on a request is not allowed (§4.1).
    let assertion = SignatureResult {
        signature: vec![],
        assertion: Some((vec![], vec![])),
    };
    assert!(finish_request(&p, &assertion).is_err());
}

// ---------------------------------------------------------------------------------------------
// Links: narrowing, expiry, session, principals.

#[test]
fn link_refusals_each_return_nothing() {
    let acct = account();
    let agent = candidate_key("agent/signing");
    let s1 = candidate_key("session/1");
    let member = agent.id();
    let mk = |to: &K, terms: Value, session: Option<u64>, nb: &'static str, exp: &'static str| {
        let spec = LinkSpec {
            account: &acct.id,
            member: &member,
            prior: &[],
            to_signing: &to.point,
            terms,
            session,
            not_before: nb,
            expires: exp,
            created: nb,
        };
        prepare_link(&acct.view, &spec)
    };
    let fin = |p: &colophon_core::v05::write::calls::PreparedLink| {
        finish_link(p, &agent.sign(p.step().body()), &acct.view, ms(NOW))
    };
    let ok = mk(&s1, narrow(), Some(0), NB0, EXP0).unwrap();
    assert!(fin(&ok).is_ok());
    // Widens the parent's purposes.
    let widens = mk(&s1, wide(), Some(0), NB0, EXP0).unwrap();
    assert_eq!(code(&fin(&widens)), "refused:notNarrower");
    // Drops the parent's condition.
    let drops = mk(
        &s1,
        json!({"services": [{"audience": AUD, "purposes": ["task.read"]}]}),
        Some(0),
        NB0,
        EXP0,
    )
    .unwrap();
    assert_eq!(code(&fin(&drops)), "refused:notNarrower");
    // Same depth as its parent: not narrower.
    let flat = mk(
        &s1,
        json!({"services": [{"audience": AUD, "purposes": ["task.read"]}], "depth": 1, "conditions": [{"prefix": ["args.task", "T-"]}]}),
        Some(0),
        NB0,
        EXP0,
    )
    .unwrap();
    assert_eq!(code(&fin(&flat)), "refused:notNarrower");
    // Another session number: the member's own is read from the view, not supplied.
    let ended = mk(&s1, narrow(), Some(1), NB0, EXP0).unwrap();
    assert_eq!(code(&fin(&ended)), "refused:ended");
    // Already expired.
    let expired = mk(
        &s1,
        narrow(),
        Some(0),
        "2026-11-11T08:00:00Z",
        "2026-11-11T08:30:00Z",
    )
    .unwrap();
    assert_eq!(code(&fin(&expired)), "refused:expired");
    // Longer than the account's linkMaxAge (86,400 s), which comes from the view.
    assert_eq!(acct.link_max_age_s, 86_400);
    let long = mk(
        &s1,
        narrow(),
        Some(0),
        "2026-11-10T09:00:00Z",
        "2026-11-12T09:00:00Z",
    )
    .unwrap();
    assert_eq!(code(&fin(&long)), "refused:expired");
    // Beyond the member's own expiry (2026-11-18T08:00:00Z).
    let beyond = mk(
        &s1,
        narrow(),
        Some(0),
        "2026-11-18T07:00:00Z",
        "2026-11-18T08:00:01Z",
    )
    .unwrap();
    assert_eq!(code(&fin(&beyond)), "refused:expired");
    // notBefore after expires, a missing session on the first link, link terms with `expires`.
    assert!(mk(&s1, narrow(), Some(0), EXP0, NB0).is_err());
    assert!(mk(&s1, narrow(), None, NB0, EXP0).is_err());
    assert!(mk(
        &s1,
        json!({"expires": "2026-11-11T09:05:00Z"}),
        Some(0),
        NB0,
        EXP0
    )
    .is_err());
    // Integers beyond 2^53 - 1 never reach a body.
    assert!(mk(&s1, narrow(), Some(1 << 53), NB0, EXP0).is_err());
    // Signed by another key: the binding fails.
    let forged = finish_link(
        &ok,
        &candidate_key("attacker").sign(ok.step().body()),
        &acct.view,
        ms(NOW),
    );
    assert_eq!(code(&forged), "badSignature");
    // H1: a signature over any other body never turns the prepared link into output. The
    // prepared body cannot be replaced (no public field), and a foreign body's signature does
    // not verify over the exact bytes finish judges.
    assert_eq!(
        code(&finish_link(
            &ok,
            &agent.sign(widens.step().body()),
            &acct.view,
            ms(NOW)
        )),
        "badSignature"
    );
    assert_eq!(
        code(&finish_link(
            &ok,
            &agent.sign(b"{\"x\":1}"),
            &acct.view,
            ms(NOW)
        )),
        "badSignature"
    );
    // `to.signing` is a principal's point: a controller's key, as the view holds it.
    let controller_point = acct
        .principals
        .iter()
        .find(|p| !acct.members_points.contains(*p))
        .unwrap()
        .clone();
    let to_principal = prepare_link(
        &acct.view,
        &LinkSpec {
            account: &acct.id,
            member: &member,
            prior: &[],
            to_signing: &controller_point,
            terms: narrow(),
            session: Some(0),
            not_before: NB0,
            expires: EXP0,
            created: NB0,
        },
    )
    .unwrap();
    assert_eq!(code(&fin(&to_principal)), "malformed");
    // A link built ahead of its use is accepted (valid within its window, not usable now).
    let ahead = mk(
        &s1,
        narrow(),
        Some(0),
        "2026-11-11T10:00:00Z",
        "2026-11-11T10:05:00Z",
    )
    .unwrap();
    let env = fin(&ahead).unwrap();
    let call = {
        let p = prepare_call(&CallSpec {
            account: &acct.id,
            as_of: (3, &acct.history[2]),
            signer: CallSignerSpec::Member(agent.id()),
            key: &s1.point,
            links: &[env],
            audience: AUD,
            purpose: "task.read",
            args: json!({"task": "T-12"}),
            request_id: [9; 32],
            created: NOW,
            webauthn: false,
        })
        .unwrap();
        let audiences = vec![AUD.to_string()];
        let origins = BTreeMap::new();
        let purposes: Vec<String> = Vec::new();
        let config = cfg(&audiences, &origins, &purposes);
        finish_call(&p, &s1.sign(p.step().body()), &acct.view, &config)
    };
    assert_eq!(code(&call), "refused:expired");
}

#[test]
fn prepare_refuses_integers_beyond_2_53_and_hostile_receipt_bodies() {
    let acct = account();
    let big = 1u64 << 53;
    let home = candidate_key("home/signing");
    // The guard refuses a seq beyond 2^53 - 1 (it is no entry of the home's history).
    let mut objects = Objects::default();
    for seq in 1..=3 {
        objects.entries.push(read(
            cand().join(format!("account/records/authority/{seq:08}.json")),
        ));
    }
    let home_state = HomeState::new(home.id(), &objects, always(), ms(NOW)).unwrap();
    assert!(home_state
        .guard_head(big, &acct.history[0], NOW, NOW)
        .is_err());
    let agent = candidate_key("agent/signing");
    for seq in [big, u64::MAX, 0] {
        assert!(prepare_call(&CallSpec {
            account: &acct.id,
            as_of: (seq, &acct.history[2]),
            signer: CallSignerSpec::Member(agent.id()),
            key: &agent.point,
            links: &[],
            audience: AUD,
            purpose: "task.read",
            args: json!({}),
            request_id: [1; 32],
            created: NOW,
            webauthn: false,
        })
        .is_err());
    }
    // A receipt body naming `by` as a path is refused before it reaches `step().path()`.
    for by in ["../../x", "x", "", "7DD5C27F9DCFDF8B0854A8D04345773E"] {
        let body =
            canonical(&json!({"protocol":"colophon/receipt/5","object":"o","by":by})).unwrap();
        assert!(prepare_receipt(&ReceiptToSign {
            object: "o".into(),
            body
        })
        .is_err());
    }
    for body in [
        b"".to_vec(),
        b"\xff\xfe".to_vec(),
        b"[]".to_vec(),
        vec![b'['; 200_000],
    ] {
        assert!(prepare_receipt(&ReceiptToSign {
            object: "o".into(),
            body
        })
        .is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// Home admission, end to end, with receipts and heads the builders made.

fn fixture(name: &str, path: &str) -> Vec<u8> {
    read(cand().join("rules").join(name).join(path))
}
fn stamp(ms: i64) -> String {
    let base = parse_date("2026-11-11T00:00:00Z").unwrap();
    let t = ms - base;
    let sec = t.div_euclid(1000);
    format!(
        "2026-11-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        11 + sec.div_euclid(86400),
        sec.rem_euclid(86400) / 3600,
        sec.rem_euclid(3600) / 60,
        sec.rem_euclid(60),
        t.rem_euclid(1000)
    )
}
fn issued_of(bytes: &[u8]) -> i64 {
    let b: Value = serde_json::from_slice(&body_of(bytes)).unwrap();
    parse_date(b["issued"].as_str().unwrap()).unwrap()
}
fn find_home_key(id: &str) -> K {
    for name in ["r4/home1/signing", "r4/home2/signing"] {
        let k = derived_key(name);
        if k.id() == id {
            return k;
        }
    }
    panic!("unknown home key {id}")
}
const FIX: &str = "t-remove-after-delay";
fn always() -> Vec<ServingInterval> {
    vec![ServingInterval {
        from_ms: i64::MIN,
        through_ms: None,
    }]
}
fn fixture_objects() -> Objects {
    Objects {
        entries: (1..=2)
            .map(|seq| fixture(FIX, &format!("records/authority/{seq:08}.json")))
            .collect(),
        ..Default::default()
    }
}
fn home_at(second: bool, now: i64) -> (HomeState, K) {
    let objects = fixture_objects();
    let v = verify_history(&objects, &Persisted::default(), now);
    let st = v.state.unwrap();
    let id = st.current_homes()[usize::from(second)].request.member_id();
    (
        HomeState::new(id.clone(), &objects, always(), now).unwrap(),
        find_home_key(&id),
    )
}

#[test]
fn home_admission_end_to_end_with_builder_receipts_and_heads() {
    let transition = fixture(FIX, "objects/transition.json");
    let at = issued_of(&transition);
    let (home1, key1) = home_at(false, at);
    let (home2, key2) = home_at(true, at);

    // A transition submitted at its `issued` is admitted; the signing request becomes a
    // receipt through the builder, signed by the home's key, accepted inside the window.
    let admitted = admit(&home1, &transition, &stamp(at + 10_000));
    assert_eq!(admitted.result, Ok(()));
    assert_eq!(admitted.receipts.len(), 1);
    let prepared = prepare_receipt(&admitted.receipts[0]).unwrap();
    assert_eq!(prepared.step().body(), admitted.receipts[0].body);
    assert_eq!(prepared.step().signer(), key1.id());
    assert_eq!(
        prepared.step().path(),
        format!("{}.receipt.json", key1.id())
    );
    let sig = key1.sign(prepared.step().body());
    // After the 300 s window the home refuses to publish it.
    assert!(finish_receipt(&admitted.state, &prepared, &sig, &stamp(at + 300_001)).is_err());
    // Another key's signature is refused.
    assert!(finish_receipt(
        &admitted.state,
        &prepared,
        &key2.sign(prepared.step().body()),
        &stamp(at + 20_000)
    )
    .is_err());
    // A signature over other bytes (a rebuilt body with another `received`) is refused.
    let mut other = admitted.receipts[0].clone();
    other.body = canonical(
        &json!({"protocol":"colophon/receipt/5","account":acct_text(&other.body),"object":other.object,
                "received":stamp(at + 11_000),"by":key1.id()}),
    )
    .unwrap();
    let other_prepared = prepare_receipt(&other).unwrap();
    assert!(finish_receipt(
        &admitted.state,
        &other_prepared,
        &key1.sign(other_prepared.step().body()),
        &stamp(at + 20_000)
    )
    .is_err());
    let (receipt, home1_next) =
        finish_receipt(&admitted.state, &prepared, &sig, &stamp(at + 20_000)).unwrap();
    assert!(receipt.len() <= 1_024);
    // Published: the home lists the transition and its receipt.
    let page = home1_next.pending_page(0, 64, at + 20_000).unwrap();
    assert_eq!(
        page.objects
            .iter()
            .map(|o| o.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["transition", "receipt"]
    );
    assert_eq!(page.objects[1].envelope, receipt);

    // A late transition (past 300 s) is refused with `late`, no receipt is drafted and the
    // transition is still stored and served so the owner can veto it.
    let late = admit(&home2, &transition, &stamp(at + 300_001));
    assert_eq!(late.result, Err(Refusal::Late));
    assert!(late.receipts.is_empty());
    assert_eq!(
        late.state
            .pending_page(0, 64, at + 300_001)
            .unwrap()
            .objects
            .len(),
        1
    );
    // ... and forwarding the first home's receipt to it is accepted once the object is held.
    let forwarded = admit(&late.state, &receipt, &stamp(at + 300_002));
    // The receipt is within the object's window, so it is kept even though this home was late.
    assert_eq!(forwarded.result, Ok(()));
    let detail = forwarded
        .state
        .pending_object(&issued_digest(&transition), at + 300_002)
        .unwrap()
        .unwrap();
    assert_eq!(detail.receipts, vec![receipt.clone()]);
    // Forwarding again changes nothing (one receipt per home per object).
    let again = admit(&forwarded.state, &receipt, &stamp(at + 300_003));
    assert_eq!(again.result, Ok(()));
    assert_eq!(
        again
            .state
            .pending_page(0, 64, at + 300_003)
            .unwrap()
            .objects
            .len(),
        2
    );

    // A receipt that arrives before its object is held, then promoted when the transition
    // arrives in time.
    let (home3, _) = home_at(true, at);
    let unseen = admit(&home3, &receipt, &stamp(at + 5_000));
    assert_eq!(unseen.result.as_ref().unwrap_err().code(), "unavailable");
    let both = admit(&unseen.state, &transition, &stamp(at + 6_000));
    assert_eq!(both.result, Ok(()));
    assert_eq!(
        both.state
            .pending_object(&issued_digest(&transition), at + 6_000)
            .unwrap()
            .unwrap()
            .receipts,
        vec![receipt.clone()]
    );

    // Heads the builder made: the home admits a valid head and refuses a non-home head and a
    // fork, and keeps its state.
    let objects = fixture_objects();
    let v = verify_history(&objects, &Persisted::default(), at);
    let st = v.state.unwrap();
    let history = st.history().to_vec();
    let homes: Vec<(String, Vec<u8>)> = st
        .current_homes()
        .into_iter()
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    let head_at = stamp(at);
    let head = |seq: u64, dg: &str, by: &K| {
        // The home's own guard first (§13.3): a head for an entry it has not verified never
        // reaches a signature.
        let (_, guard) = home1_next
            .guard_head(seq, dg, &head_at, &stamp(at))
            .unwrap();
        let p = prepare_head(
            &HeadSpec {
                account: st.account(),
                seq,
                digest: dg,
                issued: &head_at,
                by: &by.id(),
            },
            &guard,
        )
        .unwrap();
        let sig = by.sign(p.step().body());
        (p, sig)
    };
    let ctx = HeadContext {
        account: st.account(),
        history: &history,
        homes: &homes,
        now_ms: at,
    };
    let (p, sig) = head(2, &history[1], &key1);
    let head_env = finish_head(&p, &sig, ctx).unwrap();
    let admitted_head = admit(&home1_next, &head_env, &stamp(at + 30_000));
    assert_eq!(admitted_head.result, Ok(()));
    assert!(home1_next
        .guard_head(2, &"3".repeat(64), &head_at, &stamp(at))
        .is_err());
    let (p, _) = head(2, &history[1], &key1);
    let wrong_signer = envelope(
        p.step().body(),
        &raw_of(&candidate_key("attacker").sign(p.step().body())),
    );
    assert_eq!(
        admit(&home1_next, &wrong_signer, &stamp(at + 30_000))
            .result
            .unwrap_err()
            .code(),
        "badSignature"
    );
}
fn issued_digest(envelope_bytes: &[u8]) -> String {
    digest(&body_of(envelope_bytes))
}
fn acct_text(receipt_body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(receipt_body).unwrap();
    v["account"].as_str().unwrap().to_string()
}

#[test]
fn step_bytes_are_exact_and_unsigned() {
    // A step carries no secret: it is bytes and public identifiers.
    let acct = account();
    let agent = candidate_key("agent/signing");
    let p = prepare_call(&CallSpec {
        account: &acct.id,
        as_of: (3, &acct.history[2]),
        signer: CallSignerSpec::Member(agent.id()),
        key: &agent.point,
        links: &[],
        audience: AUD,
        purpose: "task.read",
        args: json!({"b": 1, "a": 2}),
        request_id: [3; 32],
        created: NOW,
        webauthn: false,
    })
    .unwrap();
    let step: &SigningStep = p.step();
    assert!(step.body().starts_with(b"{\"account\":"));
    assert!(String::from_utf8_lossy(step.body()).contains("\"args\":{\"a\":2,\"b\":1}"));
    assert_eq!(step.signer(), agent.id());
}
