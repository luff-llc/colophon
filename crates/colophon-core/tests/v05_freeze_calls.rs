//! Freeze package, stream W2-C: a stopped reader verifies and builds no call (§1 "A stop",
//! §12.3 step 4, §13.6; `docs/design-freeze-package.md` §S, finding 4).
//!
//! The account is the generator's `calls/s-stopped-reader-call`: seq 4 activates a layout raise
//! (the upgrade door, `newerFormat` to a 0.5 reader), seq 5 makes it final, seq 6 revokes the
//! member, and the home's fresh head is at seq 3 (N−1). Before the stop rule, every call below
//! was `ok`: the reader accepted the revoked member under the fresh head at N−1. A raise that is
//! only provisional, or vetoed, does not stop the reader (`s-provisional-raise-call`,
//! `s-vetoed-raise-call`). The tests read only the stop flag, never the layout itself.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::{
    calls::{
        check_home_call_as_signer, home_call_args, home_record_writes, verify_call,
        verify_home_request, verify_home_write, AccountView, CallConfig, HomeRequest, HomeWrite,
    },
    encoding::{canonical, parse_date},
    history::{verify_history, Objects, Persisted, Verdict},
    ids::key_id,
    replay::MemoryReplayStore,
    write::calls::{
        finish_call, finish_home_call, finish_link, prepare_call, prepare_link, CallSignerSpec,
        CallSpec, LinkSpec,
    },
    write::SignatureResult,
    Failure,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

const AUD: &str = "https://projects.example/scopes/7";
const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.5/candidate/calls")
        .join(name)
}

struct Key {
    sk: SigningKey,
    point: Vec<u8>,
}
impl Key {
    /// The generator's `derived(name)`: SHA-256 of the label as the scalar.
    fn derived(name: &str) -> Key {
        let scalar = Sha256::digest(format!("colophon-0.5-candidate/{name}").as_bytes());
        let sk = SigningKey::from_slice(&scalar).unwrap();
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Key { sk, point }
    }
    fn id(&self) -> String {
        key_id(&self.point)
    }
    fn sign(&self, body: &[u8]) -> SignatureResult {
        let s: Signature = self.sk.sign(body);
        SignatureResult {
            signature: s.to_bytes().to_vec(),
            assertion: None,
        }
    }
}

/// A case's verdict and view, its clock and its home endpoint (the stopped home's audience).
struct Case {
    verdict: Verdict,
    view: AccountView,
    now: String,
    now_ms: i64,
    entries: usize,
}
fn load(name: &str) -> Case {
    let dir = case_dir(name);
    let mut entries: Vec<PathBuf> = fs::read_dir(dir.join("records/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    let objects = Objects {
        entries: entries.iter().map(|p| fs::read(p).unwrap()).collect(),
        heads: vec![fs::read(dir.join("objects/head.json")).unwrap()],
        ..Default::default()
    };
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    let now = case["verifier"]["now"].as_str().unwrap().to_string();
    let now_ms = parse_date(&now).unwrap();
    let verdict = verify_history(&objects, &Persisted::default(), now_ms);
    let view = AccountView::from_history_verifier(&verdict, &objects, now_ms).unwrap();
    Case {
        verdict,
        view,
        now,
        now_ms,
        entries: entries.len(),
    }
}
fn stopped() -> Case {
    load("s-stopped-reader-call")
}
fn before() -> Case {
    load("s-before-stop-call")
}
fn endpoint(view: &AccountView) -> String {
    format!(
        "https://home.example/v1/accounts/{}",
        view.account().as_str()
    )
}
fn agent() -> Key {
    Key::derived("w2c/agent/signing")
}

fn cfg<'a>(now_ms: i64, audiences: &'a [String], home: bool) -> CallConfig<'a> {
    static ORIGINS: std::sync::OnceLock<std::collections::BTreeMap<String, Vec<String>>> =
        std::sync::OnceLock::new();
    CallConfig {
        now_ms,
        audiences,
        call_origins: ORIGINS.get_or_init(Default::default),
        controller_purposes: &[],
        home_endpoints: if home { audiences } else { &[] },
    }
}

/// The agent's call with its own key, `asOf` seq 3, built and signed (not judged).
fn signed_call(
    c: &Case,
    audience: &str,
    purpose: &str,
    args: Value,
    rid: u8,
) -> (Vec<u8>, Vec<u8>, SignatureResult) {
    let a = agent();
    let spec = CallSpec {
        account: c.view.account(),
        as_of: (3, &c.view.history()[2]),
        signer: CallSignerSpec::Member(a.id()),
        key: &a.point,
        links: &[],
        audience,
        purpose,
        args,
        request_id: [rid; 32],
        created: &c.now,
        webauthn: false,
    };
    let prepared = prepare_call(&spec).unwrap();
    let body = prepared.step().body().to_vec();
    let sig = a.sign(&body);
    let env = canonical(&json!({"body": STANDARD.encode(&body),
                                "signature": STANDARD.encode(&sig.signature)}))
    .unwrap();
    (env, body, sig)
}

fn is_unavailable<T, F: std::borrow::Borrow<Failure>>(r: Result<T, F>) -> bool {
    matches!(
        r.as_ref().map_err(|f| f.borrow()),
        Err(Failure::Unavailable(_))
    )
}

#[test]
fn the_history_stops_at_the_final_layout_raise_and_holds_the_revoke_after_it() {
    let c = stopped();
    assert_eq!(c.entries, 6, "seq 6, the revoke, is held");
    assert!(c.verdict.is_stopped());
    assert_eq!(c.view.stopped(), c.verdict.stopped);
    // The verified history runs at most through the entry that made the raise final: the revoke
    // after it (seq 6) is never applied.
    assert!(c.view.history().len() < 6, "the revoke after the stop was applied");
    // A stopped reader answers no question of currency.
    assert!(c.view.current_homes(c.now_ms).is_empty());
    let b = before();
    assert_eq!(b.verdict.stopped, None);
    assert_eq!(b.view.current_homes(b.now_ms).len(), 1);
}

#[test]
fn a_stopped_reader_verifies_no_call_under_a_fresh_head_before_the_stop() {
    let c = stopped();
    let aud = [AUD.to_string()];
    let call = fs::read(case_dir("s-stopped-reader-call").join("call.json")).unwrap();
    let mut store = MemoryReplayStore::new();
    let got = verify_call(&call, &c.view, &cfg(c.now_ms, &aud, false), &mut store);
    assert!(is_unavailable(got.as_ref()), "{got:?}");
    // Nothing was reserved: the same call is still unavailable, never refused:replay.
    let again = verify_call(&call, &c.view, &cfg(c.now_ms, &aud, false), &mut store);
    assert!(is_unavailable(again), "replay store was written");
}

#[test]
fn the_same_call_verified_before_the_stop() {
    let b = before();
    let aud = [AUD.to_string()];
    let call = fs::read(case_dir("s-before-stop-call").join("call.json")).unwrap();
    let mut store = MemoryReplayStore::new();
    let vc = verify_call(&call, &b.view, &cfg(b.now_ms, &aud, false), &mut store).unwrap();
    assert_eq!(vc.evaluated_at, 3);
}

#[test]
fn the_stop_does_not_preempt_parse_possession_or_audience() {
    // §12.3 orders the stop at step 4: a call with a bad signature is still badSignature.
    let c = stopped();
    let aud = [AUD.to_string()];
    let (_, body, _) = signed_call(&c, AUD, "task.read", json!({}), 7);
    let forged = canonical(&json!({"body": STANDARD.encode(&body),
                                   "signature": STANDARD.encode(Key::derived("w2c/attacker").sign(&body).signature)}))
    .unwrap();
    let mut store = MemoryReplayStore::new();
    let got = verify_call(&forged, &c.view, &cfg(c.now_ms, &aud, false), &mut store);
    assert_eq!(got.unwrap_err().code(), "badSignature");
    let (env, _, _) = signed_call(&c, "https://other.example", "task.read", json!({}), 8);
    let got = verify_call(&env, &c.view, &cfg(c.now_ms, &aud, false), &mut store);
    assert_eq!(got.unwrap_err().code(), "refused:audience");
}

#[test]
fn the_signer_builds_no_call_or_link_on_a_stopped_history() {
    let c = stopped();
    let b = before();
    let aud = [AUD.to_string()];
    let a = agent();
    // The call: prepared from shape alone, refused at finish with the verifier's own answer.
    let spec = CallSpec {
        account: c.view.account(),
        as_of: (3, &c.view.history()[2]),
        signer: CallSignerSpec::Member(a.id()),
        key: &a.point,
        links: &[],
        audience: AUD,
        purpose: "task.read",
        args: json!({}),
        request_id: [9; 32],
        created: &c.now,
        webauthn: false,
    };
    let prepared = prepare_call(&spec).unwrap();
    let sig = a.sign(prepared.step().body());
    let got = finish_call(&prepared, &sig, &c.view, &cfg(c.now_ms, &aud, false));
    assert!(is_unavailable(got), "a stopped signer built a call");
    // Before the stop the same build succeeds.
    assert!(finish_call(&prepared, &sig, &b.view, &cfg(b.now_ms, &aud, false)).is_ok());

    // The call to a home, judged as its signer.
    let home = [endpoint(&c.view)];
    let args = home_call_args("GET", "/authority", EMPTY_SHA);
    let spec = CallSpec {
        audience: &home[0],
        purpose: "colophon.history.read",
        args,
        request_id: [10; 32],
        ..spec
    };
    let prepared = prepare_call(&spec).unwrap();
    let sig = a.sign(prepared.step().body());
    let req = HomeRequest {
        method: "GET",
        path: "/authority",
        body_sha256: EMPTY_SHA,
        writes: &[],
    };
    let got = finish_home_call(&prepared, &sig, &c.view, &cfg(c.now_ms, &home, true), &req);
    assert!(is_unavailable(got), "a stopped signer built a home call");
    assert!(finish_home_call(&prepared, &sig, &b.view, &cfg(b.now_ms, &home, true), &req).is_ok());

    // A link: not even prepared over a stopped view, and one prepared before is not finished.
    let session = Key::derived("w2c/session");
    let not_before = c.now.clone();
    let link = LinkSpec {
        account: c.view.account(),
        member: &a.id(),
        prior: &[],
        to_signing: &session.point,
        terms: json!({"services": [{"audience": AUD, "purposes": ["task.read"]}]}),
        session: Some(0),
        not_before: &not_before,
        expires: &not_before,
        created: &not_before,
    };
    assert!(is_unavailable(prepare_link(&c.view, &link)));
    let prepared = prepare_link(&b.view, &link).unwrap();
    let sig = a.sign(prepared.step().body());
    assert!(is_unavailable(finish_link(
        &prepared, &sig, &c.view, c.now_ms
    )));
    // Before the stop the verifier judges it (here a member of depth 0 cannot link): never unavailable.
    assert!(!is_unavailable(finish_link(
        &prepared, &sig, &b.view, b.now_ms
    )));
}

#[test]
fn a_stopped_home_verifies_no_request() {
    let c = stopped();
    let b = before();
    let home = [endpoint(&c.view)];
    // A history read with the member's own key.
    let (env, _, _) = signed_call(
        &c,
        &home[0],
        "colophon.history.read",
        home_call_args("GET", "/authority", EMPTY_SHA),
        11,
    );
    let req = HomeRequest {
        method: "GET",
        path: "/authority",
        body_sha256: EMPTY_SHA,
        writes: &[],
    };
    let mut store = MemoryReplayStore::new();
    let got = verify_home_request(&env, &c.view, &cfg(c.now_ms, &home, true), &mut store, &req);
    assert!(is_unavailable(got.as_ref()), "{got:?}");
    assert!(is_unavailable(check_home_call_as_signer(
        &env,
        &c.view,
        &cfg(c.now_ms, &home, true),
        &req
    )));
    let mut fresh = MemoryReplayStore::new();
    assert!(
        verify_home_request(&env, &b.view, &cfg(b.now_ms, &home, true), &mut fresh, &req).is_ok(),
        "the same request is ok before the stop"
    );
    // A write: stored nothing new.
    let path = format!("/records/blobs/{EMPTY_SHA}");
    let writes = home_record_writes(path.strip_prefix("/records/").unwrap())
        .unwrap_or_else(|| vec![HomeWrite::Blob]);
    let (env, _, _) = signed_call(
        &c,
        &home[0],
        "colophon.home.write",
        home_call_args("PUT", &path, EMPTY_SHA),
        12,
    );
    let got = verify_home_write(
        &env,
        &c.view,
        &cfg(c.now_ms, &home, true),
        &mut store,
        &writes,
    );
    assert!(is_unavailable(got.as_ref()), "{got:?}");
    // The vector: a member's own history read at the stopped home.
    let call = fs::read(case_dir("s-stopped-home-read").join("call.json")).unwrap();
    let got = verify_call(&call, &c.view, &cfg(c.now_ms, &home, true), &mut store);
    assert!(is_unavailable(got.as_ref()), "{got:?}");
}

/// A raise that is not final, or is vetoed, stops nothing: the same call is judged as usual.
#[test]
fn a_provisional_or_vetoed_raise_does_not_stop_the_reader() {
    let aud = [AUD.to_string()];
    for name in ["s-provisional-raise-call", "s-vetoed-raise-call"] {
        let c = load(name);
        assert!(!c.verdict.is_stopped(), "{name}: {:?}", c.verdict.stop);
        assert_eq!(c.view.stopped(), None, "{name}");
        let call = fs::read(case_dir(name).join("call.json")).unwrap();
        let mut store = MemoryReplayStore::new();
        let got = verify_call(&call, &c.view, &cfg(c.now_ms, &aud, false), &mut store);
        assert!(got.is_ok(), "{name}: {got:?}");
    }
}
