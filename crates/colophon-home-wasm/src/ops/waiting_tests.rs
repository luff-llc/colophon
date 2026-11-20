//! `waiting` builds the note `record_due` returns when it records nothing, which is almost every
//! scheduler pass. Its work must not grow with everything the home has ever held: an account's
//! `pending` keeps settled transitions and vetoes for ever, by design. These tests count the work
//! (full-history verifications and `prepare_*` calls) in one `record_due` over a history of many
//! settled transitions and vetoes and a few pending ones, and check the note against the
//! original builder, which tried every held object and verified the history for each.
#![allow(clippy::unwrap_used)]
use super::{handle, held, load, view, waiting, WAITING_WORK};
use crate::support::{
    controller_engine, engine_finish, pending_path, Fixture, Host, MemSource, HOUR, T0,
};
use crate::support_relay::{appoint_homes, create_with, entries_json, HomeKeys, BASE_A};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::Change;
use colophon_core::v05::encoding::bounds;
use colophon_core::v05::history::envelope::AuthEnvelope;
use colophon_core::v05::history::home::HomeState;
use colophon_core::v05::history::Objects;
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::{json, Value};

const NS: &str = "listening.podcasts";

fn call(req: Value) -> Value {
    let out = handle(req.to_string().as_bytes());
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v
}
fn b(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
fn body_of(env: &Value) -> Value {
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}

/// The module, its state, and the home's key (the host's part), as the relay drives them.
struct Home {
    keys: HomeKeys,
    state: String,
}
impl Home {
    fn take(&mut self, r: &Value) {
        if let Some(s) = r["state"].as_str() {
            self.state = s.to_string();
        }
    }
    fn op(&mut self, mut req: Value) -> Value {
        req["state"] = json!(self.state);
        let r = call(req);
        self.take(&r);
        r
    }
    fn sign_receipts(&mut self, r: &Value, now: i64) {
        for s in r["sign"].as_array().cloned().unwrap_or_default() {
            let body = STANDARD.decode(s["body"].as_str().unwrap()).unwrap();
            let sig = self.keys.sign(&body).signature;
            self.op(json!({"op": "finish_receipt", "object": s["object"], "body": s["body"],
                           "signature": b(&sig), "now": now}));
        }
    }
    fn pending(&mut self, object: &Value, now: i64) {
        let body = json!({"objects": [object]}).to_string();
        let r = self.op(json!({"op": "post_pending", "now": now, "body": b(body.as_bytes())}));
        assert_eq!(r["outcome"], "ok", "{r}");
        self.sign_receipts(&r, now);
    }
    fn head(&mut self, now: i64) {
        let r = self.op(json!({"op": "head_request", "now": now}));
        let Some(s) = r["sign"].as_object() else { return };
        let body = STANDARD.decode(s["body"].as_str().unwrap()).unwrap();
        let sig = self.keys.sign(&body).signature;
        self.op(json!({"op": "finish_head", "now": now, "seq": s["seq"], "digest": s["digest"],
                       "issued": s["issued"], "signature": b(&sig)}));
    }
    fn due(&mut self, now: i64) -> Value {
        let r = self.op(json!({"op": "record_due", "now": now}));
        self.sign_receipts(&r, now);
        r
    }
    /// The authority entries the home holds, as `(path, bytes)`.
    fn entries(&self) -> Vec<(String, Vec<u8>)> {
        self.files(&["authority/"])
    }
    /// The files the home holds under these prefixes, as `(path, bytes)`.
    fn files(&self, prefixes: &[&str]) -> Vec<(String, Vec<u8>)> {
        let o = call(json!({"op": "objects", "state": self.state}));
        o["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| prefixes.iter().any(|p| f["path"].as_str().unwrap().starts_with(p)))
            .map(|f| {
                let bytes = STANDARD.decode(f["bytes"].as_str().unwrap()).unwrap();
                (f["path"].as_str().unwrap().to_string(), bytes)
            })
            .collect()
    }
    fn kinds(&self) -> Vec<String> {
        let mut e = self.entries();
        e.sort();
        e.iter()
            .map(|(_, bytes)| {
                let env: Value = serde_json::from_slice(bytes).unwrap();
                body_of(&env)["kind"].as_str().unwrap().to_string()
            })
            .collect()
    }
    /// The held state, as `record_due` sees it.
    fn held(&self) -> (HomeState, Objects) {
        let h = load(&json!({"state": self.state})).unwrap().home.unwrap();
        let o = held(&h).unwrap();
        (h, o)
    }
}

/// An account whose one home is driven through the module, and its owner's controller.
struct World {
    f: Fixture,
    host: Host,
    src: MemSource,
    home: Home,
    /// Authority entries the home should hold.
    want: usize,
}
impl World {
    fn new() -> Self {
        let keys = HomeKeys::new(0x77);
        let mut f = create_with(&[NS], "public", 1);
        appoint_homes(&mut f, &[(&keys, BASE_A)]);
        let state = call(json!({"op": "init", "home": keys.id, "account": f.account.id().as_str()}))
            ["state"]
            .as_str()
            .unwrap()
            .to_string();
        let mut home = Home { keys, state };
        let values: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
        let body = json!({"from": 1, "entries": values, "receipts": []}).to_string();
        let r = home.op(json!({"op": "post_authority", "now": T0 + 1_000, "body": b(body.as_bytes())}));
        assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(true)), "{r}");
        let src = MemSource::new();
        src.store_account(&f.account);
        let host = std::mem::replace(&mut f.host, Host::new());
        Self { f, host, src, home, want: 3 }
    }

    /// Round `k` of the kill loop's schedule (`v05_relay_kill`), at `t`: the owner catches up
    /// with the home and proposes a transition; every third round (k % 3 == 1) vetoes it in time.
    /// With `settle`, the clock moves past its due time until the home has recorded `activate`
    /// and `final` (or `vetoed`). `check` runs at each clock reading where `record_due` runs.
    /// Returns the transition's digest.
    fn round(&mut self, k: i64, t: i64, settle: bool, check: &mut dyn FnMut(&Home, i64)) -> String {
        let (d, p) = (self.f.d.clone(), self.f.p.clone());
        for (path, bytes) in self.home.entries() {
            self.src.put(&path, bytes);
        }
        // After a `vetoed`, a transition its signer's unit signs alone fails escalation (§8.7).
        let signers = if k % 3 == 2 { vec![d.clone(), p.clone()] } else { vec![d.clone()] };
        let mut ctl = controller_engine(&self.f, &self.host, &self.src, &d, t);
        let action = ctl
            .account()
            .begin_transition(&Change::policy(json!({"callWindow": 600 + k})), &signers, TransitionRule::Control)
            .unwrap();
        engine_finish(&mut ctl, &self.host, &self.src, action);
        let digest = ctl.account().pending().last().unwrap().digest.clone();
        let env: Value = ctl
            .account()
            .objects()
            .pending
            .iter()
            .find(|p| pending_path(p).contains(&digest))
            .map(|p| serde_json::from_slice(p).unwrap())
            .unwrap();
        self.home.pending(&env, t + 1_000);
        let vetoed = k % 3 == 1;
        if vetoed {
            // The owner sees the home's receipt of the transition, then vetoes it.
            for (path, bytes) in self.home.files(&["receipts/"]) {
                self.src.put(&path, bytes);
            }
            ctl.advance(t + 2_000).unwrap();
            ctl.refresh(self.src.listing()).unwrap();
            let action = ctl.account().begin_veto(&digest, std::slice::from_ref(&p)).unwrap();
            engine_finish(&mut ctl, &self.host, &self.src, action);
            let veto: Value = ctl
                .account()
                .objects()
                .pending
                .iter()
                .filter(|b| pending_path(b).starts_with("vetoes/"))
                .find(|b| body_of(&serde_json::from_slice::<Value>(b).unwrap())["transition"] == digest.as_str())
                .map(|b| serde_json::from_slice(b).unwrap())
                .expect("the veto");
            self.home.pending(&veto, t + 3_000);
        }
        check(&self.home, t + 60_000);
        self.home.due(t + 60_000);
        if !settle {
            return digest;
        }
        self.want += if vetoed { 1 } else { 2 };
        let mut at = t + HOUR + 400_000;
        for _ in 0..6 {
            if self.home.entries().len() >= self.want {
                break;
            }
            check(&self.home, at);
            self.home.due(at);
            self.home.head(at);
            at += 2_000;
        }
        let kinds = self.home.kinds();
        assert_eq!(kinds.len(), self.want, "round {k}: {kinds:?}");
        let last: &[&str] = if vetoed { &["vetoed"] } else { &["activate", "final"] };
        assert_eq!(&kinds[kinds.len() - last.len()..], last, "round {k}");
        digest
    }
}

/// The original note builder, but for returning its parts: every held transition and veto is
/// tried, and each try verifies the whole history again. Each part is `(transition, text)`: the
/// transition the part is about (none for a `final`), and the text the original joined into
/// `waiting: <part>; <part>…`.
fn waiting_reference(h: &HomeState, objects: &Objects, now_ms: i64) -> Vec<(Option<String>, String)> {
    use colophon_core::v05::write::authority::{prepare_activate, prepare_final, prepare_vetoed};
    let mut why: Vec<(Option<String>, String)> = objects
        .pending
        .iter()
        .filter_map(|p| {
            AuthEnvelope::parse(p, bounds::TRANSITION_ENVELOPE, bounds::TRANSITION_ENVELOPE, false)
                .ok()
        })
        .filter_map(|e| match e.value.get("protocol").and_then(Value::as_str) {
            Some("colophon/transition/5") => prepare_activate(objects, now_ms, &e.digest)
                .err()
                .map(|x| (Some(e.digest.clone()), format!("activate {}: {x}", &e.digest[..8]))),
            Some("colophon/veto/5") => {
                let t = e
                    .value
                    .get("transition")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                prepare_vetoed(objects, now_ms, &t, &e.digest)
                    .err()
                    .map(|x| (Some(t), format!("vetoed {}: {x}", &e.digest[..8])))
            }
            _ => None,
        })
        .collect();
    if let Ok(v) = view(h, now_ms) {
        for a in v.state.activations().iter().filter(|a| !a.final_) {
            if let Err(e) = prepare_final(objects, now_ms, a.seq) {
                why.push((None, format!("final {}: {e}", a.seq)));
            }
        }
    }
    why
}
fn note_of(parts: &[&str]) -> Value {
    if parts.is_empty() {
        Value::Null
    } else {
        json!(format!("waiting: {}", parts.join("; ")))
    }
}

/// The clock reading of round `k` of the kill loop.
fn at(k: i64) -> i64 {
    T0 + HOUR + k * 3 * HOUR
}

fn reset() {
    WAITING_WORK.with(|c| c.set((0, 0)));
}
fn work() -> (usize, usize) {
    WAITING_WORK.with(std::cell::Cell::get)
}

/// One `record_due` that records nothing, over 12 settled transitions (8 activated and final, 4
/// vetoed, so 16 held transitions and vetoes) and 2 pending transitions: `waiting` verifies the
/// history a constant number of times, and tries to build an entry only for what is not settled.
#[test]
fn waiting_work_is_bounded_by_what_is_unsettled_not_by_everything_held() {
    let mut w = World::new();
    let settled = 12;
    for k in 0..settled {
        w.round(k, at(k), true, &mut |_, _| {});
    }
    // Two transitions proposed and receipted, not due yet (rounds with no veto).
    let a = w.round(settled, at(settled), false, &mut |_, _| {});
    let b = w.round(settled + 3, at(settled) + 600_000, false, &mut |_, _| {});
    let (_, objects) = w.home.held();
    let held_objects = objects
        .pending
        .iter()
        .filter(|p| !pending_path(p).starts_with("receipts/"))
        .count();
    assert_eq!(held_objects, 16 + 2, "every transition and veto ever held is kept");
    let now = at(settled) + 720_000;
    reset();
    let before = w.home.entries().len();
    let r = w.home.due(now);
    let (verifications, prepares) = work();
    eprintln!(
        "waiting over {held_objects} held transitions and vetoes, 2 unsettled: \
         {verifications} history verifications, {prepares} prepare_* calls; note: {}",
        r["note"]
    );
    assert_eq!(w.home.entries().len(), before, "nothing was due");
    let note = r["note"].as_str().unwrap();
    assert!(note.contains(&a[..8]) && note.contains(&b[..8]), "{note}");
    // One verification of the held objects and one view of the home's history; one `prepare_*`
    // per unsettled transition (no activation is provisional).
    assert!(verifications <= 2, "{verifications} history verifications in one waiting()");
    assert!(prepares <= 2, "{prepares} prepare_* calls in one waiting()");
}

/// The note is the original builder's note without its parts about settled transitions: at
/// every clock reading where the scheduler runs `record_due` over a history that grows through
/// activations, finals and vetoes (a transition pending, receipted, vetoed, due, activated and
/// provisional), each part about a transition not recorded on the branch, and each `final`, is
/// the original's, in the original order. A part about a recorded transition (its `activate`, or
/// the `vetoed` of a veto of it) is dropped: nothing more can be recorded of it. The original
/// still tried those, and after a `vetoed` each said `badSignature: escalation: too few signer
/// units` on every pass, about transitions recorded long before.
#[test]
fn the_waiting_note_is_the_original_without_parts_about_settled_transitions() {
    use colophon_core::v05::write::authority::VerifiedHead;
    let mut w = World::new();
    let (mut compared, mut notes, mut dropped) = (0usize, 0usize, 0usize);
    let mut example = None;
    let mut check = |home: &Home, now: i64| {
        let (h, objects) = home.held();
        for at in [now, now + 1, now + HOUR] {
            let verified = VerifiedHead::new(&objects, at);
            let recorded = |t: &str| verified.state().is_ok_and(|s| s.is_recorded(t));
            let original = waiting_reference(&h, &objects, at);
            let kept: Vec<&str> = original
                .iter()
                .filter(|(t, _)| t.as_deref().is_none_or(|t| !recorded(t)))
                .map(|(_, text)| text.as_str())
                .collect();
            let new = waiting(&h, &objects, at);
            assert_eq!(new, note_of(&kept), "at {at}");
            compared += 1;
            notes += usize::from(!new.is_null());
            dropped += original.len() - kept.len();
            if example.is_none() && original.len() > kept.len() {
                let all: Vec<&str> = original.iter().map(|(_, text)| text.as_str()).collect();
                example = Some((at, note_of(&all), new));
            }
        }
    };
    for k in 0..7 {
        w.round(k, at(k), true, &mut check);
    }
    // A transition vetoed in time but not yet settled, and one signed by both units.
    w.round(7, at(7), false, &mut check);
    w.round(8, at(7) + 600_000, false, &mut check);
    check(&w.home, at(7) + 720_000);
    eprintln!(
        "the waiting note matched the original's unsettled parts at {compared} readings \
         ({notes} non-null, {dropped} parts about settled transitions dropped)"
    );
    if let Some((at, before, after)) = &example {
        eprintln!("first reading with a dropped part, at {at}:\n  original: {before}\n  now:      {after}");
    }
    assert!(notes > 0, "some readings have something waiting");
    assert!(dropped > 0, "some readings had parts about settled transitions");
}
