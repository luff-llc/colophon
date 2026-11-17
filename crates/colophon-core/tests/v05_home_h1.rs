//! H1 fix round (2026-11-15): the home checkpoint is never stale, heads do not accumulate, and a
//! first upload is bound to the provisioned account and accepts an old history.
#![allow(clippy::unwrap_used, dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::{
    encoding::{canonical, digest, parse_date},
    history::home::{
        admit, finish_receipt, HomeState, Refusal, ServingInterval,
    },
    history::{verify_history, Objects, Persisted},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fixture(name: &str, path: &str) -> Vec<u8> {
    fs::read(root().join("conformance/0.5/rules").join(name).join(path)).unwrap()
}
fn body(bytes: &[u8]) -> Value {
    let env: Value = serde_json::from_slice(bytes).unwrap();
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
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
fn time(bytes: &[u8]) -> i64 {
    parse_date(body(bytes)["issued"].as_str().unwrap()).unwrap()
}
fn key_for(id: &str) -> SigningKey {
    let keys: Value =
        serde_json::from_slice(&fs::read(root().join("conformance/0.4/keys/keys.json")).unwrap())
            .unwrap();
    for k in keys["software"].as_array().unwrap() {
        if k["id"] == id {
            return SigningKey::from_slice(
                &STANDARD
                    .decode(k["signingScalar"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        }
    }
    for name in [
        "r4/home1/signing",
        "r4/home2/signing",
        "r5/phone",
        "r4/new-device",
    ] {
        let scalar = Sha256::digest(format!("colophon-0.5-candidate/{name}").as_bytes());
        let k = SigningKey::from_slice(&scalar).unwrap();
        let point = k.verifying_key().to_encoded_point(false);
        if &digest(point.as_bytes())[..32] == id {
            return k;
        }
    }
    panic!("unknown published fixture key {id}")
}
fn signed(value: &Value) -> Vec<u8> {
    let bytes = canonical(value).unwrap();
    let sig: Signature = key_for(value["by"].as_str().unwrap()).sign(&bytes);
    canonical(&json!({"body":STANDARD.encode(&bytes), "signature":STANDARD.encode(sig.to_bytes())}))
        .unwrap()
}
fn setup(name: &str, second: bool, serving: Vec<ServingInterval>, now: i64) -> HomeState {
    let objects = Objects {
        entries: (1..=2)
            .map(|seq| fixture(name, &format!("records/authority/{seq:08}.json")))
            .collect(),
        ..Default::default()
    };
    let v = verify_history(&objects, &Persisted::default(), now);
    let st = v.state.unwrap();
    let id = st.current_homes()[usize::from(second)].request.member_id();
    HomeState::new(id, &objects, serving, now).unwrap()
}
fn always() -> Vec<ServingInterval> {
    vec![ServingInterval {
        from_ms: i64::MIN,
        through_ms: None,
    }]
}
fn restore(state: &HomeState) -> HomeState {
    HomeState::from_bytes(&state.to_bytes().unwrap()).unwrap()
}

fn ids(name: &str, now: i64) -> (String, String, String) {
    let objects = Objects {
        entries: (1..=2)
            .map(|seq| fixture(name, &format!("records/authority/{seq:08}.json")))
            .collect(),
        ..Default::default()
    };
    let st = verify_history(&objects, &Persisted::default(), now).state.unwrap();
    (
        st.account().as_str().to_string(),
        st.current_homes()[0].request.member_id(),
        st.history()[1].clone(),
    )
}

/// The check's M9 test, ported: after a transition is admitted and receipted, the checkpoint's
/// pending objects are exactly what the home stores (before the fix: 0 against 2).
#[test]
fn the_checkpoint_pending_objects_are_never_stale() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let home = setup("t-remove-after-delay", false, always(), at);
    let admitted = admit(&home, &t, &stamp(at));
    assert_eq!(admitted.result, Ok(()));
    let receipt_value: Value = serde_json::from_slice(&admitted.receipts[0].body).unwrap();
    let receipt = signed(&receipt_value);
    let home = finish_receipt(
        &admitted.state,
        &admitted.receipts[0].object,
        &receipt,
        &stamp(at + 1),
    )
    .unwrap();
    let held = home.persisted().unwrap().objects().cloned().unwrap().pending;
    let listed: Vec<Vec<u8>> = home
        .pending_page(0, 64, at + 1)
        .unwrap()
        .objects
        .into_iter()
        .map(|o| o.envelope)
        .collect();
    assert_eq!(listed.len(), 2, "the transition and the home's receipt");
    assert_eq!(held, listed, "the checkpoint holds exactly the stored pending objects");
    // And after a restart.
    let again = restore(&home).persisted().unwrap().objects().cloned().unwrap().pending;
    assert_eq!(again, listed);
}

/// H4: a head over an unchanged history replaces the previous one; the state does not grow with
/// every head. Sizes after 1, 40 and 1,000 heads are printed.
#[test]
fn heads_over_an_unchanged_history_do_not_accumulate() {
    let name = "t-remove-after-delay";
    let t = fixture(name, "objects/transition.json");
    let start = time(&t);
    let (account, home_id, digest) = ids(name, start);
    let mut home = setup(name, false, always(), start);
    let mut sizes = Vec::new();
    for n in 1..=1_000i64 {
        let at = start + n * 150_000;
        let head = signed(&json!({"protocol": "colophon/head/5", "account": account,
            "authority": {"seq": 2, "digest": digest}, "issued": stamp(at), "by": home_id}));
        let a = admit(&home, &head, &stamp(at));
        assert_eq!(a.result, Ok(()), "head {n}");
        home = a.state;
        if [1, 40, 1_000].contains(&n) {
            let heads = home.persisted().unwrap().objects().cloned().unwrap().heads;
            assert_eq!(heads, vec![head.clone()], "only the newest head is kept");
            sizes.push(home.to_bytes().unwrap().len());
        }
    }
    eprintln!("home state bytes after 1, 40 and 1,000 heads: {sizes:?}");
    assert!(sizes[2] <= sizes[0] + 64, "the state does not grow with heads: {sizes:?}");
}

/// H1 and M1 in the core: the first entry must be the provisioned account's genesis (nothing
/// else is held), and an account whose history is a week old can still make its first upload.
#[test]
fn a_first_upload_is_bound_to_its_account_and_accepts_an_old_history() {
    use colophon_core::v05::history::home::{admit_first, FirstUpload};
    let name = "t-remove-after-delay";
    let e1 = fixture(name, "records/authority/00000001.json");
    let e2 = fixture(name, "records/authority/00000002.json");
    let week_later = time(&e2) + 7 * 86_400_000;
    let (account, home_id, _) = ids(name, week_later);
    let other = "ab".repeat(32);
    let refused = admit_first(&home_id, &other, &[], &e1, &stamp(week_later));
    assert_eq!(refused.unwrap_err().code(), "refused:outOfScope");
    let held = match admit_first(&home_id, &account, &[], &e1, &stamp(week_later)).unwrap() {
        FirstUpload::Held(h) => h,
        FirstUpload::Home(_) => panic!("not yet appointed"),
    };
    assert!(matches!(
        admit_first(&home_id, &account, &held, &e2, &stamp(week_later)).unwrap(),
        FirstUpload::Home(_)
    ));
    // An entry that is not seq 1 cannot open a slot either.
    assert_eq!(
        admit_first(&home_id, &account, &[], &e2, &stamp(week_later)).unwrap_err(),
        Refusal::Conflict
    );
}
