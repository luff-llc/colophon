//! The home module (`colophon_home_wasm::handle`) driven directly, no relay and no HTTP: the
//! decisions it returns for a first upload, a transition, a veto, a late object, a forged object,
//! the head guard, recording entries and the call check. The same bytes the relay sees.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::Change;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_home_wasm::handle;
use serde_json::{json, Value};
use support::*;
use support_relay::{appoint_homes, create_with, entries_json, HomeKeys, BASE_A};

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "listening.podcasts";

/// A driver: the module, its state, and the home's key (the host's part).
struct Home {
    keys: HomeKeys,
    state: String,
}
fn call(req: Value) -> Value {
    let out = handle(req.to_string().as_bytes());
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v
}
fn b(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
impl Home {
    fn new(keys: HomeKeys, account: &str) -> Self {
        let state = call(json!({"op": "init", "home": keys.id, "account": account}))["state"]
            .as_str()
            .unwrap()
            .to_string();
        Self { keys, state }
    }
    fn take(&mut self, r: &Value) {
        if let Some(s) = r["state"].as_str() {
            self.state = s.to_string();
        }
    }
    /// Sign what the module asks to be signed, as receipts, and hand the signatures back.
    fn sign_receipts(&mut self, r: &Value, now: i64) -> Vec<Value> {
        let mut out = Vec::new();
        for s in r["sign"].as_array().cloned().unwrap_or_default() {
            let body = STANDARD.decode(s["body"].as_str().unwrap()).unwrap();
            let sig = self.keys.sign(&body).signature;
            let f = call(json!({"op": "finish_receipt", "state": self.state, "object": s["object"],
                                "body": s["body"], "signature": b(&sig), "now": now}));
            self.take(&f);
            out.push(serde_json::from_slice(&STANDARD.decode(f["envelope"].as_str().unwrap()).unwrap()).unwrap());
        }
        out
    }
    fn authority(&mut self, from: u64, entries: &[Value], now: i64) -> Value {
        let body = json!({"from": from, "entries": entries, "receipts": []}).to_string();
        let r = call(json!({"op": "post_authority", "state": self.state, "now": now, "body": b(body.as_bytes())}));
        self.take(&r);
        r
    }
    fn pending(&mut self, objects: &[Value], now: i64) -> Value {
        let body = json!({"objects": objects}).to_string();
        let r = call(json!({"op": "post_pending", "state": self.state, "now": now, "body": b(body.as_bytes())}));
        self.take(&r);
        r
    }
    fn head(&mut self, now: i64) -> Option<Value> {
        let r = call(json!({"op": "head_request", "state": self.state, "now": now}));
        self.take(&r);
        let s = r["sign"].as_object()?;
        let body = STANDARD.decode(s["body"].as_str().unwrap()).unwrap();
        let sig = self.keys.sign(&body).signature;
        let f = call(json!({"op": "finish_head", "state": self.state, "now": now, "seq": s["seq"],
                            "digest": s["digest"], "issued": s["issued"], "signature": b(&sig)}));
        self.take(&f);
        Some(serde_json::from_slice(&STANDARD.decode(f["envelope"].as_str().unwrap()).unwrap()).unwrap())
    }
    fn due(&mut self, now: i64) -> Value {
        let r = call(json!({"op": "record_due", "state": self.state, "now": now}));
        self.take(&r);
        r
    }
    fn kinds(&self) -> Vec<String> {
        let o = call(json!({"op": "objects", "state": self.state}));
        let mut v: Vec<(String, String)> = o["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["path"].as_str().unwrap().starts_with("authority/"))
            .map(|f| {
                let env: Value = serde_json::from_slice(&STANDARD.decode(f["bytes"].as_str().unwrap()).unwrap()).unwrap();
                let body: Value = serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
                (f["path"].as_str().unwrap().to_string(), body["kind"].as_str().unwrap().to_string())
            })
            .collect();
        v.sort();
        v.into_iter().map(|(_, k)| k).collect()
    }
}

struct Setup {
    f: Fixture,
    home: Home,
    ctl: colophon_core::v05::engine::Engine<MemSource>,
    src: MemSource,
}
fn setup(history: &str) -> Setup {
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], history, 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries = entries_json(&f);
    let values: Vec<Value> = entries.iter().map(|(_, e)| e.clone()).collect();
    let r = home.authority(1, &values, T0 + 1_000);
    assert_eq!(r["outcome"], "ok", "{r}");
    assert_eq!(r["appointed"], true);
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    let d = f.d.clone();
    let ctl = controller_engine(&f, &host, &src, &d, NOW);
    f.host = host;
    Setup { f, home, ctl, src }
}
fn transition(s: &mut Setup, window: u64, by: &[String]) -> (String, Value) {
    let action = s
        .ctl
        .account()
        .begin_transition(&Change::policy(json!({"callWindow": window})), by, TransitionRule::Control)
        .unwrap();
    engine_finish(&mut s.ctl, &s.f.host, &s.src, action);
    let digest = s.ctl.account().pending().last().unwrap().digest.clone();
    let env = s
        .ctl
        .account()
        .objects()
        .pending
        .iter()
        .find(|p| pending_path(p).contains(&digest))
        .map(|p| serde_json::from_slice(p).unwrap())
        .unwrap();
    (digest, env)
}

#[test]
fn a_first_upload_appoints_the_home_and_a_head_is_due_then_guarded() {
    let mut s = setup("public");
    let st = call(json!({"op": "status", "state": s.home.state, "now": NOW}));
    assert_eq!(st["appointed"], true);
    assert_eq!(st["seq"], 3);
    // A head is due; signing it twice at the same instant is refused by the guard.
    assert!(s.home.head(NOW).is_some());
    let again = call(json!({"op": "head_request", "state": s.home.state, "now": NOW}));
    assert!(again["sign"].is_null());
    // A head for the same entry is not due again until half of headMaxAge has passed.
    assert!(s.home.head(NOW + 100_000).is_none());
    assert!(s.home.head(NOW + 160_000).is_some());
}

#[test]
fn a_home_admits_a_post_genesis_namespace_and_checks_scoped_writes() {
    use colophon_core::v05::encoding::digest;
    use colophon_core::v05::records::Level;
    use support_relay::{fresh_request_id, home_call};

    const SAVED: &str = "reading.saved";
    const FOUNDRY: &str = "game.foundry";
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS, SAVED], "public", 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<_> = entries_json(&f)
        .into_iter()
        .map(|(_, entry)| entry)
        .collect();
    let admitted = home.authority(1, &entries, T0 + 1_000);
    assert_eq!(admitted["outcome"], "ok", "{admitted}");
    assert_eq!(admitted["appointed"], true);

    let from = f.account.head().0 + 1;
    f.account.advance(NOW).unwrap();
    let add = f
        .account
        .begin_add_namespaces(
            &[FOUNDRY.into()],
            std::slice::from_ref(&f.d),
            f.host.fresh(),
        )
        .unwrap();
    run(&mut f.account, &f.host, add);
    let member = f.host.identity(91);
    let terms = terms_for(&[(FOUNDRY, "write")]);
    admit(&mut f, &member, "AI Foreman", "agent", terms.clone(), terms);
    let suffix: Vec<_> = entries_json(&f)
        .into_iter()
        .filter_map(|(seq, entry)| (seq >= from).then_some(entry))
        .collect();
    let admitted = home.authority(from, &suffix, NOW);
    assert_eq!(admitted["outcome"], "ok", "{}", admitted["result"]);
    assert!(home
        .kinds()
        .ends_with(&["namespace.add".into(), "grant".into()]));
    assert!(home.head(NOW).is_some());

    let src = MemSource::new();
    src.store_account(&f.account);
    let mut engine = member_engine(&f, &f.host, &src, &member, NOW);
    let refused = engine.begin_write(SAVED, "save", json!({}), Level::Write, f.host.fresh());
    assert_eq!(refused.unwrap().err().unwrap().reason, "notGranted");
    let written = engine_write(
        &mut engine,
        &mut f.host,
        &src,
        FOUNDRY,
        "machine.place",
        json!({"machine": "smelter"}),
    );
    let (record_path, bytes) = written
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap();
    let access = |record_path: &str| {
        let path = format!("/records/{record_path}");
        let signed = home_call(
            &f.host,
            engine.account(),
            BASE_A,
            "PUT",
            &path,
            bytes,
            NOW,
            fresh_request_id(),
        );
        call(json!({
            "op": "access", "state": home.state, "now": NOW, "base": BASE_A, "method": "PUT",
            "section": "records", "rest": record_path, "path": path,
            "bodySha256": digest(bytes), "call": b(&signed),
        }))
    };
    let allowed = access(record_path);
    assert_eq!(allowed["allowed"], true, "{allowed}");
    let checked = call(json!({
        "op": "check_record", "state": home.state, "now": NOW,
        "path": record_path, "bytes": b(bytes),
    }));
    assert_eq!(checked["allowed"], true, "{checked}");
    let refused = access(&record_path.replace(FOUNDRY, SAVED));
    assert_eq!(refused["status"], 403, "{refused}");
    assert_eq!(refused["result"], "refused:outOfScope", "{refused}");
}

#[test]
fn a_transition_is_receipted_once_then_due_activated_and_recorded() {
    let mut s = setup("public");
    let d = s.f.d.clone();
    let (digest, env) = transition(&mut s, 600, &[d]);
    let r = s.home.pending(&[env.clone()], NOW + 1_000);
    assert_eq!(r["outcome"], "ok", "{r}");
    let receipts = s.home.sign_receipts(&r, NOW + 1_000);
    assert_eq!(receipts.len(), 1);
    // The same transition again: accepted, no second receipt is asked for.
    let again = s.home.pending(&[env], NOW + 2_000);
    assert_eq!(again["outcome"], "ok");
    assert!(again["sign"].as_array().unwrap().is_empty());
    let feed = call(json!({"op": "pending_page", "state": s.home.state, "now": NOW + 2_000, "after": 0, "limit": 64}));
    let kinds: Vec<&str> = feed["objects"].as_array().unwrap().iter().map(|o| o["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["transition", "receipt"]);
    // Not due yet.
    let r = s.home.due(NOW + 60_000);
    assert!(r["store"].as_array().unwrap().is_empty());
    // Due after the delay: the module builds the `activate`; a head over it lets `final` follow.
    let later = NOW + 3_600_000 + 400_000;
    let r = s.home.due(later);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["note"], Value::Null);
    let k = s.home.kinds();
    assert_eq!(k.last().unwrap(), "activate", "{k:?} {r}");
    assert!(s.home.head(later).is_some());
    let r = s.home.due(later + 1_000);
    assert_eq!(r["result"], "ok");
    assert_eq!(s.home.kinds().last().unwrap(), "final", "the head over the activation lets `final` follow");
    let feed = call(json!({"op": "pending_page", "state": s.home.state, "now": later, "after": 0, "limit": 64}));
    assert!(feed["objects"].as_array().unwrap().is_empty(), "recorded: no longer pending");
    let _ = digest;
}


#[test]
fn a_first_upload_may_arrive_in_pieces_and_is_checked_like_any_entry() {
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let values: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert_eq!(values.len(), 3, "genesis, rekey, the appointing activate");
    let mut home = Home::new(keys, f.account.id().as_str());
    // The genesis alone: it verifies and is kept, but the home is not appointed in it yet.
    let r = home.authority(1, &values[..1], T0 + 1_000);
    assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(false)));
    // Re-sent: acknowledged again.
    assert_eq!(home.authority(1, &values[..1], T0 + 1_000)["outcome"], "ok");
    // A gap is a conflict; entries that skip the first are malformed.
    assert_eq!(home.authority(3, &values[2..], T0 + 1_000)["outcome"], "conflict");
    // Too early: more than 60 s ahead of the home's clock.
    let early = home.authority(2, &values[1..2], T0 - 120_000);
    assert_eq!((early["outcome"].as_str(), early["result"].as_str()), (Some("refused"), Some("refused:early")));
    // An entry written long before the home was appointed is not judged by the home's clock
    // (M1: the clock rule applies from the appointment on): a week later, it is held.
    let old = home.authority(2, &values[1..2], T0 + 7 * 24 * HOUR);
    assert_eq!(old["outcome"], "ok", "{old}");
    // The rest: the home is appointed by the last entry.
    let r = home.authority(3, &values[2..], T0 + 7 * 24 * HOUR);
    assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(true)), "{}", r["result"]);
    // Nothing was stored for the refusals: three files, one per entry.
    let o = call(json!({"op": "objects", "state": home.state}));
    assert_eq!(o["files"].as_array().unwrap().len(), 3);
}

#[test]
fn a_record_is_stored_only_for_a_member_of_the_history_with_a_good_signature_and_path() {
    let s = setup("public");
    let blob = vec![7u8; 100];
    let name = colophon_core::v05::encoding::digest(&blob);
    let ok = call(json!({"op": "check_record", "state": s.home.state, "now": NOW, "path": format!("blobs/{name}"), "bytes": b(&blob)}));
    assert_eq!(ok["allowed"], true);
    let bad = call(json!({"op": "check_record", "state": s.home.state, "now": NOW, "path": format!("blobs/{}", "0".repeat(64)), "bytes": b(&blob)}));
    assert_eq!(bad["allowed"], false);
    // A header from nobody in the history.
    let junk = call(json!({"op": "check_record", "state": s.home.state, "now": NOW,
        "path": format!("ops/{}/{NS}/000000000001-{}.json", "a".repeat(32), "b".repeat(32)), "bytes": b(b"{}")}));
    assert_eq!(junk["allowed"], false);
    // A path outside the store.
    let other = call(json!({"op": "check_record", "state": s.home.state, "now": NOW, "path": "x/y.json", "bytes": b(b"{}")}));
    assert_eq!(other["code"], "malformed");
}

/// H1: a slot provisioned for one account holds nothing of another: a stranger's genesis is
/// refused (`refused:outOfScope`) and the state is unchanged, so the owner's upload goes through.
#[test]
fn a_slot_holds_only_its_own_account_and_a_stranger_cannot_squat_it() {
    let keys = HomeKeys::new(0x77);
    let mut owner = create_with(&[NS], "members", 1);
    appoint_homes(&mut owner, &[(&keys, BASE_A)]);
    let stranger = create_with(&[NS], "public", 1);
    let mut home = Home::new(keys, owner.account.id().as_str());
    let before = home.state.clone();
    let genesis = entries_json(&stranger)[0].1.clone();
    let r = home.authority(1, &[genesis], T0 + 1_000);
    assert_eq!((r["outcome"].as_str(), r["result"].as_str()), (Some("refused"), Some("refused:outOfScope")));
    assert_eq!(home.state, before, "nothing is held");
    assert!(r["store"].as_array().unwrap().is_empty());
    let values: Vec<Value> = entries_json(&owner).into_iter().map(|(_, e)| e).collect();
    let r = home.authority(1, &values, T0 + 1_000);
    assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(true)), "{r}");
}

/// H3: `receipts` in `POST /authority` holds receipt envelopes only; anything else there is
/// malformed and nothing of the request is admitted.
#[test]
fn an_entry_in_the_receipts_array_is_malformed_and_nothing_is_admitted() {
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let values: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    let before = home.state.clone();
    let body = json!({"from": 1, "entries": [values[0]], "receipts": [values[2]]}).to_string();
    let r = call(json!({"op": "post_authority", "state": home.state, "now": T0 + 1_000, "body": b(body.as_bytes())}));
    assert_eq!((r["outcome"].as_str(), r["result"].as_str()), (Some("refused"), Some("malformed")));
    assert_eq!(r["state"], json!(before));
    assert!(r["store"].as_array().unwrap().is_empty());
    home.take(&r);
}

/// H4 over the module: the slot state after 1, 40 and 1,000 heads over an unchanged history.
#[test]
fn the_slot_state_does_not_grow_with_heads() {
    let s = setup("public");
    let mut home = s.home;
    let mut sizes = Vec::new();
    for n in 1..=1_000i64 {
        let at = NOW + n * 150_000;
        assert!(home.head(at).is_some(), "head {n} is due");
        if [1, 40, 1_000].contains(&n) {
            sizes.push(home.state.len());
        }
    }
    eprintln!("slot state bytes after 1, 40 and 1,000 heads: {sizes:?}");
    assert!(sizes[2] <= sizes[0] + 256, "{sizes:?}");
}
