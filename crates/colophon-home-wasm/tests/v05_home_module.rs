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
    fn new(keys: HomeKeys) -> Self {
        let state = call(json!({"op": "init", "home": keys.id}))["state"]
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
    let mut home = Home::new(keys);
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
    let mut home = Home::new(keys);
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
    // Too late: an immediate entry more than 300 s behind the clock.
    let late = home.authority(2, &values[1..2], T0 + 400_000);
    assert_eq!(late["result"], "refused:late");
    // The rest, in time: the home is appointed by the last entry.
    let r = home.authority(2, &values[1..], T0 + 2_000);
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
