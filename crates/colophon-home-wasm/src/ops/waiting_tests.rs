//! `waiting` builds the note `record_due` returns when it records nothing, which is almost every
//! scheduler pass. Its work must not grow with everything the home has ever held: an account's
//! `pending` keeps settled transitions and vetoes for ever, by design. These tests count the work
//! (full-history verifications and `prepare_*` calls) in one `record_due` over a history of many
//! settled transitions and vetoes and a few pending ones, and check the note against the
//! original builder, which tried every held object and verified the history for each.
#![allow(clippy::unwrap_used)]
use super::{genesis_receipt_request, handle, held, load, view, waiting};
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
use colophon_core::v05::history::{work, Objects};
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

/// One `record_due` that records nothing, over 12 settled transitions (8 activated and final, 4
/// vetoed, so 16 held transitions and vetoes) and 2 pending transitions. The core counts, on this
/// thread, every `verify_history` run and every `prepare_*` attempt (feature `work-counters`, on
/// for this crate's tests only), so whatever `waiting` calls is counted: it verifies the history a
/// constant number of times and tries to build an entry only for what is not settled.
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
    let (h, objects) = w.home.held();
    let held_objects = objects
        .pending
        .iter()
        .filter(|p| !pending_path(p).starts_with("receipts/"))
        .count();
    assert_eq!(held_objects, 16 + 2, "every transition and veto ever held is kept");
    let now = at(settled) + 720_000;
    // The whole call, as the relay makes it: nothing is due, so it builds the note.
    let before = w.home.entries().len();
    work::reset();
    let r = w.home.due(now);
    let whole = work::get();
    assert_eq!(w.home.entries().len(), before, "nothing was due");
    let note = r["note"].as_str().unwrap();
    assert!(note.contains(&a[..8]) && note.contains(&b[..8]), "{note}");
    // The note alone, over the same held state and clock.
    work::reset();
    let again = waiting(&h, &objects, now);
    let work::Work { verifications, prepares, .. } = work::get();
    assert_eq!(again, r["note"]);
    eprintln!(
        "waiting over {held_objects} held transitions and vetoes, 2 unsettled: \
         {verifications} history verifications, {prepares} prepare_* calls \
         (the whole record_due: {} and {}); note: {note}",
        whole.verifications, whole.prepares
    );
    // One verification of the held objects and one `view` of the home's history; one `prepare_*`
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
    use colophon_core::v05::write::authority::VerifiedObjects;
    let mut w = World::new();
    let (mut compared, mut notes, mut dropped) = (0usize, 0usize, 0usize);
    let mut example = None;
    let mut check = |home: &Home, now: i64| {
        let (h, objects) = home.held();
        for at in [now, now + 1, now + HOUR] {
            let verified = VerifiedObjects::new(&objects, at);
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

/// `wakeAt` (`record_due`, `head_request`) is sound and on time over the kill loop's schedule:
/// at every reading where the scheduler runs `record_due`, when it records nothing and gives a
/// time, the same state at any reading from then until just before that time records nothing,
/// asks for nothing and leaves the state as it was (so the relay may skip those passes); a head
/// that is not due stays not due until its `wakeAt` and is due then. A transition receipted and
/// not vetoed gives exactly its due time, and is activated at it.
#[test]
fn wake_at_is_never_later_than_what_the_clock_makes_due() {
    use colophon_core::v05::write::authority::VerifiedObjects;
    let mut w = World::new();
    let (mut bounded, mut unbounded, mut exact) = (0usize, 0usize, 0usize);
    let mut check = |home: &Home, now: i64| {
        let r = call(json!({"op": "record_due", "state": home.state, "now": now}));
        let Some(wake) = r["wakeAt"].as_i64() else {
            unbounded += 1;
            return;
        };
        bounded += 1;
        assert!(wake > now, "a wake time after the reading: {wake} at {now}");
        assert!(r.get("state").is_none(), "nothing recorded leaves the state as given, and none is sent back");
        assert_eq!(r["sign"], json!([]));
        let last = wake.min(now + 30 * 24 * HOUR) - 1;
        for t in [now + 1, now + (last - now) / 2, last] {
            let again = call(json!({"op": "record_due", "state": home.state, "now": t}));
            assert!(again.get("state").is_none(), "nothing becomes due at {t}, before {wake}");
            assert_eq!(again["sign"], json!([]), "at {t}");
            assert_eq!(again["result"], "ok", "at {t}");
        }
        // The earliest due time among the held transitions is the wake time when it is the
        // nearest thing waiting, and the transition is activated at it.
        let (_, objects) = home.held();
        let verified = VerifiedObjects::new(&objects, now);
        if verified.next_due_ms() == Some(wake) && wake < now + 30 * 24 * HOUR {
            let at = call(json!({"op": "record_due", "state": home.state, "now": wake}));
            if at.get("state").is_some_and(|s| *s != json!(home.state)) {
                exact += 1;
            }
        }
        // A head not due stays so until its wake time, and is due at it.
        let h = call(json!({"op": "head_request", "state": home.state, "now": now}));
        if let Some(hw) = h["wakeAt"].as_i64() {
            assert_eq!(h["due"], false);
            if hw < now + 30 * 24 * HOUR {
                let before = call(json!({"op": "head_request", "state": home.state, "now": hw - 1}));
                assert_eq!(before["due"], false, "no head due just before {hw}");
                let then = call(json!({"op": "head_request", "state": home.state, "now": hw}));
                assert_eq!(then["due"], true, "a head due at {hw}");
            }
        }
    };
    for k in 0..7 {
        w.round(k, at(k), true, &mut check);
    }
    w.round(7, at(7), false, &mut check);
    w.round(8, at(7) + 600_000, false, &mut check);
    check(&w.home, at(7) + 720_000);
    eprintln!("wakeAt: {bounded} readings bounded, {unbounded} not (asked again next pass), {exact} exactly on a due time");
    assert!(bounded > 0 && exact > 0, "some readings wait for a due time and it comes exactly then");
}

/// The 7-day bound on an `activate` is on its determined `issued` (the later of the last entry's
/// `issued` and the due time), not on the clock: a receipted transition left alone for 8 days
/// after its due time, with nothing appended since, can still be built, so it is not a
/// transition that never comes due: no wake bound, ask again every pass. (This home then refuses
/// its own late `activate` by the home's clock rule, `refused:late`, and gives no wake time
/// either: every pass asks again, as before.)
#[test]
fn a_transition_due_long_ago_with_nothing_appended_since_is_still_due() {
    use colophon_core::v05::write::authority::VerifiedObjects;
    let mut w = World::new();
    let digest = w.round(0, at(0), false, &mut |_, _| {});
    let (_, objects) = w.home.held();
    let early = VerifiedObjects::new(&objects, at(0) + 120_000);
    let due = early.next_due_ms().expect("a receipted transition has a due time");
    assert!(due > at(0) + 120_000 && due < at(0) + 2 * HOUR, "due within the delay: {due}");
    let late = due + 8 * 24 * HOUR;
    let verified = VerifiedObjects::new(&objects, late);
    assert!(verified.state().unwrap().last_issued_ms() <= due, "nothing appended since");
    assert!(verified.prepare_activate(&digest).is_ok(), "still activatable 8 days after its due time");
    assert_eq!(verified.next_due_ms(), None, "due and not recorded: no wake bound");
    let r = w.home.due(late);
    assert_eq!(r["wakeAt"], Value::Null, "{}", r["result"]);
}

/// An account with no predecessor owes no genesis receipt, and finding that out reads the home's
/// verified view once: no replay of the held history from genesis, on every `record_due` and
/// every upload. A no-op `record_due` and `head_request` send no state back.
#[test]
fn a_home_without_a_succession_asks_for_no_genesis_receipt_and_replays_nothing() {
    let mut w = World::new();
    w.round(0, at(0), true, &mut |_, _| {});
    let (h, _) = w.home.held();
    for now in [at(1), at(1) + 7 * 24 * HOUR] {
        work::reset();
        let r = genesis_receipt_request(&h, h.home_id(), now).unwrap();
        assert!(r.is_none());
        assert_eq!(work::get().verifications, 1, "one verification, of the view");
    }
    let now = at(1);
    let quiet = call(json!({"op": "record_due", "state": w.home.state, "now": now}));
    assert_eq!((quiet["result"].as_str(), quiet["store"].clone()), (Some("ok"), json!([])), "{quiet}");
    assert!(quiet.get("state").is_none(), "{quiet}");
    w.home.head(now);
    let fresh = call(json!({"op": "head_request", "state": w.home.state, "now": now + 1}));
    assert_eq!((fresh["due"].clone(), fresh["sign"].clone()), (json!(false), Value::Null), "{fresh}");
    assert!(fresh.get("state").is_none(), "{fresh}");
}
