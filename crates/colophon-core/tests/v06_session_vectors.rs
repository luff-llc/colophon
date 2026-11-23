//! Conformance vectors for 0.6 sessions (`conformance/0.6-sessions/`).
//!
//! Each scenario is a scripted transcript: every step gives a member, its clock and one input
//! (frames in full), and the outputs the reference machine produced; the file ends with each
//! member's view and digest. The test (1) rebuilds every scenario and compares it with the
//! checked-in file and (2) replays each file from its JSON inputs alone, as a binding would.
//! `COLOPHON_REGEN_VECTORS=1` rewrites the files. `offset.json` holds the §S7 integer cases.
#![allow(clippy::unwrap_used)]
use colophon_core::v06::session::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.6-sessions")
}
fn b(s: &str) -> Bytes {
    Bytes(s.as_bytes().to_vec())
}

/// A scripted scenario. Sends go to a pending list; `deliver` routes them in order.
struct Script {
    name: &'static str,
    description: &'static str,
    policy: Policy,
    members: Vec<(String, bool, Option<Claim>)>,
    s: BTreeMap<String, Session>,
    pending: Vec<(String, Frame)>,
    steps: Vec<Value>,
}

impl Script {
    fn new(name: &'static str, description: &'static str, policy: Policy, ids: &[&str]) -> Self {
        let members: Vec<(String, bool, Option<Claim>)> =
            ids.iter().map(|i| ((*i).to_owned(), true, None)).collect();
        let s = members
            .iter()
            .map(|(id, w, p)| (id.clone(), Session::new(id, *w, policy.clone(), p.clone())))
            .collect();
        Script {
            name,
            description,
            policy,
            members,
            s,
            pending: Vec::new(),
            steps: Vec::new(),
        }
    }
    fn ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.0.clone()).collect()
    }
    fn step(&mut self, member: &str, at: u64, input: Input) -> Vec<Output> {
        let outs = self.s.get_mut(member).unwrap().handle(input.clone(), at);
        self.steps.push(json!({"member": member, "at": at, "input": input, "outputs": outs}));
        for o in &outs {
            if let Output::Send { frame } = o {
                let dsts: Vec<String> = match &frame.to {
                    Some(t) => vec![t.clone()],
                    None => self.ids().into_iter().filter(|i| i != member).collect(),
                };
                for d in dsts {
                    self.pending.push((d, frame.clone()));
                }
            }
        }
        outs
    }
    fn cmd(&mut self, member: &str, at: u64, command: Command) -> Vec<Output> {
        self.step(member, at, Input::App { command })
    }
    fn tick(&mut self, member: &str, at: u64) -> Vec<Output> {
        self.step(member, at, Input::Tick)
    }
    /// Deliver pending frames (and those they cause) in order at `at`, except those `drop`
    /// rejects (lost).
    fn deliver_if(&mut self, at: u64, drop: impl Fn(&str, &Frame) -> bool) {
        let mut guard = 0;
        while !self.pending.is_empty() {
            guard += 1;
            assert!(guard < 1000, "{}: frames never quiesce", self.name);
            let (to, f) = self.pending.remove(0);
            if drop(&to, &f) {
                continue;
            }
            self.step(&to, at, Input::Frame { frame: f, writer: true });
        }
    }
    fn deliver(&mut self, at: u64) {
        self.deliver_if(at, |_, _| false);
    }
    fn lose_all(&mut self) {
        self.pending.clear();
    }
    fn join_all(&mut self, at: u64) {
        for id in self.ids() {
            self.cmd(&id, at, Command::Join);
        }
    }
    fn session(&self, id: &str) -> &Session {
        &self.s[id]
    }
    fn to_json(&self) -> Value {
        let finals: Vec<Value> = self
            .members
            .iter()
            .map(|(id, _, _)| {
                let s = &self.s[id];
                json!({"member": id, "view": s.view(), "digest": s.digest()})
            })
            .collect();
        json!({
            "format": "colophon/session-vectors/6",
            "name": self.name,
            "description": self.description,
            "policy": self.policy,
            "fixes": Fixes::default(),
            "members": self.members.iter().map(|(id, w, p)| json!({"id": id, "canWrite": w, "persisted": p})).collect::<Vec<_>>(),
            "steps": self.steps,
            "final": finals,
        })
    }
}

fn started(name: &'static str, description: &'static str, policy: Policy, ids: &[&str]) -> Script {
    let mut s = Script::new(name, description, policy, ids);
    s.join_all(0);
    s.deliver(0);
    s.cmd(ids[0], 10, Command::Take { snapshot: Some(b("s0")) });
    s.deliver(20);
    s
}

fn scenarios() -> Vec<Script> {
    let p = Policy::default;
    let append = || Policy { reducer: Reducer::Append, ..Policy::default() };
    let mut v = Vec::new();

    let mut s = started("take-publish", "a takes with a snapshot, publishes two messages; b follows in order.", append(), &["a", "b"]);
    s.cmd("a", 100, Command::Publish { id: b("id1"), payload: b("+1") });
    s.cmd("a", 110, Command::Publish { id: b("id2"), payload: b("+2") });
    s.deliver(120);
    assert_eq!(s.session("b").state(), &b("s0+1+2"));
    v.push(s);

    let mut s = started("ask-pass", "b asks; a pauses and passes its final snapshot; b holds from exactly that snapshot (§S5, G3).", p(), &["a", "b", "c"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    s.cmd("a", 1_020, Command::Pass { to: "b".into(), snapshot: b("stopped") });
    s.deliver(1_030);
    assert!(s.session("b").is_holder());
    assert_eq!(s.session("c").state(), &b("stopped"));
    v.push(s);

    let mut s = started("ask-decline", "b asks; a declines; b does not take when askTimeoutMs passes (§S5).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    s.cmd("a", 1_020, Command::Decline { to: "b".into() });
    s.deliver(1_030);
    s.tick("b", 3_000);
    s.tick("a", 5_100);
    s.deliver(5_110);
    s.tick("b", 5_200);
    assert!(!s.session("b").is_holder());
    v.push(s);

    let mut s = started("ask-timeout-take", "b asks a holder that is gone; nothing is heard for askTimeoutMs; b takes at term + 1 (§S5, G5).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.lose_all();
    s.tick("b", 2_000);
    s.tick("b", 2_500);
    s.deliver_if(2_510, |to, _| to == "a");
    assert!(s.session("b").is_holder());
    v.push(s);

    let mut s = started("lapse-take", "b wants the role while a beats; when a falls silent for holderTimeoutMs it is lapsed and b takes (§S6, G5).", p(), &["a", "b"]);
    s.cmd("b", 100, Command::Take { snapshot: None });
    s.tick("a", 5_010);
    s.deliver(5_020);
    s.tick("b", 5_100);
    assert!(!s.session("b").is_holder());
    s.tick("b", 20_010);
    assert!(!s.session("b").is_holder());
    s.tick("b", 20_020);
    s.lose_all();
    assert!(s.session("b").is_holder());
    v.push(s);

    let mut s = started("gap-tail-resume", "msg 2 is lost; msg 3 is held early; b's hello names the claim and seq 1; a resends msg 2 and 3 from its tail (§S8).", append(), &["a", "b"]);
    for (i, t) in [(1u8, 100u64), (2, 110), (3, 120)] {
        s.cmd("a", t, Command::Publish { id: Bytes(vec![i]), payload: Bytes(vec![b'0' + i]) });
    }
    let lost = std::cell::Cell::new(false);
    s.deliver_if(130, |_, f| {
        let first = matches!(&f.body, Body::Msg { seq: 2, .. }) && !lost.get();
        lost.set(lost.get() || first);
        first
    });
    assert_eq!(s.session("b").state(), &b("s0123"));
    v.push(s);

    let mut s = started("gap-state-resume", "with tail 1 the missing messages are gone; a answers b's hello with state (§S8).", Policy { tail: 1, ..append() }, &["a", "b"]);
    for (i, t) in [(1u8, 100u64), (2, 110), (3, 120)] {
        s.cmd("a", t, Command::Publish { id: Bytes(vec![i]), payload: Bytes(vec![b'0' + i]) });
    }
    s.deliver_if(130, |_, f| matches!(&f.body, Body::Msg { seq: 1 | 2, .. }) && f.to.is_none());
    assert_eq!(s.session("b").state(), &b("s0123"));
    v.push(s);

    let mut s = started("take-without-state", "b takes; its state frame to c is lost; c accepts the claim from take, says seen.seq = null and gets state (§S8, finding F2).", p(), &["a", "b", "c"]);
    s.lose_all();
    s.cmd("b", 1_000, Command::Take { snapshot: None });
    s.tick("b", 20_000);
    s.deliver_if(20_010, |to, f| to == "c" && matches!(f.body, Body::State { .. }) && f.to.is_none());
    assert!(s.session("c").synced());
    v.push(s);

    let mut s = started("partition-two-holders", "a is cut off; b sees a lapsed and takes; when a's link heals its hello reaches b, which answers with state, and a yields to the greater claim (§S4, §S6, G6).", p(), &["a", "b"]);
    s.step("a", 1_000, Input::LinkDown);
    s.lose_all();
    s.cmd("b", 1_000, Command::Take { snapshot: None });
    s.tick("b", 16_100);
    s.lose_all();
    s.step("a", 10_000, Input::LinkUp);
    s.deliver(10_010);
    assert!(s.session("b").is_holder() && !s.session("a").is_holder());
    v.push(s);

    let mut s = started("out-of-contact-return", "a has no link for 20 s; on link-up it sends hello lapsed:true, sends no holder frame for askTimeoutMs, then retakes at term + 1 (§S6).", p(), &["a", "b"]);
    s.step("a", 1_000, Input::LinkDown);
    s.step("a", 21_000, Input::LinkUp);
    s.deliver(21_010);
    s.tick("a", 22_000);
    s.tick("a", 22_600);
    s.deliver(22_610);
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(2, 0, "a")));
    v.push(s);

    let mut s = started("submit", "b submits; a orders it with origin b; a duplicate submit is dropped; a too-large one is refused (§S8).", Policy { max_payload: 8, ..append() }, &["a", "b"]);
    s.cmd("b", 100, Command::Submit { id: b("x1"), payload: b("+b") });
    s.deliver(110);
    s.step("a", 120, Input::Frame { frame: Frame { from: "b".into(), to: Some("a".into()), retain: false, body: Body::Submit { id: b("x1"), payload: b("+b") } }, writer: true });
    s.step("a", 130, Input::Frame { frame: Frame { from: "b".into(), to: Some("a".into()), retain: false, body: Body::Submit { id: b("x2"), payload: b("0123456789") } }, writer: true });
    s.deliver(140);
    assert_eq!(s.session("b").state(), &b("s0+b"));
    v.push(s);

    let mut s = started("pass-lost-resend", "a's pass to b is lost; b, still under the old claim, resends ask; a resends the same pass (§S5, F9).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    s.cmd("a", 1_020, Command::Pass { to: "b".into(), snapshot: b("stopped") });
    s.lose_all();
    s.step("b", 2_600, Input::Frame { frame: Frame { from: "a".into(), to: None, retain: true, body: Body::Beat { claim: Claim::new(1, 0, "a"), seq: 0 } }, writer: true });
    s.tick("b", 2_600);
    s.deliver(2_610);
    assert!(s.session("b").is_holder());
    v.push(s);

    let mut s = started("restart-holder", "a restarts with its persisted claim and no state: it sends hello lapsed:true, waits askTimeoutMs, then retakes with b's answer (§S6, reference reading).", append(), &["a", "b"]);
    s.cmd("a", 100, Command::Publish { id: b("1"), payload: b("+1") });
    s.deliver(110);
    let persisted = s.session("a").accepted().cloned();
    s.s.insert("a".into(), Session::new("a", true, append(), persisted));
    s.steps.push(json!({"member": "a", "restart": true}));
    s.cmd("a", 200, Command::Join);
    s.deliver(210);
    s.tick("a", 2_000);
    s.deliver(2_010);
    v.push(s);

    let mut s = started("release", "a releases (bye); the cell has no holder; b asks and takes at once (§S4, §S5).", p(), &["a", "b"]);
    s.cmd("a", 100, Command::Release);
    s.deliver(110);
    s.cmd("b", 200, Command::Ask);
    s.deliver(210);
    assert!(s.session("b").is_holder());
    v.push(s);

    let mut s = started("ping-offset", "b pings a; a pongs with its clock; b's offset and error bound follow §S7.", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ping { to: "a".into() });
    let pending = std::mem::take(&mut s.pending);
    for (to, f) in pending {
        s.step(&to, 1_037, Input::Frame { frame: f, writer: true });
    }
    let pending = std::mem::take(&mut s.pending);
    for (to, f) in pending {
        s.step(&to, 1_081, Input::Frame { frame: f, writer: true });
    }
    let o = s.session("b").offset_to("a").unwrap();
    assert_eq!((o.rtt, o.offset, o.error), (81, -4, 41));
    v.push(s);

    v
}

/// §S7 cases: `{now, t, echo, hold}` → `{rtt, offset, error}`, then best-of-8 selection.
fn offset_cases() -> Value {
    let cases: [(u64, u64, u64, u64); 9] = [
        (1_100, 5_050, 1_000, 0),
        (1_100, 5_050, 1_000, 30),
        (1_101, 5_050, 1_000, 0),
        (1_000, 5_050, 1_000, 0),
        (1_000, 5_050, 1_010, 0),
        (1_000, 5_050, 900, 200),
        (10_000_000, 2, 9_999_000, 10),
        (2, 10_000_000, 1, 0),
        (u64::MAX, 0, 0, 0),
    ];
    let one: Vec<Value> = cases
        .iter()
        .map(|&(now, t, echo, hold)| {
            let r = sample(now, t, echo, hold);
            json!({"now": now, "t": t, "echo": echo, "hold": hold, "rtt": r.rtt, "offset": r.offset, "error": r.error})
        })
        .collect();
    // Best of the last 8: rtts 50, 40, 60, 40, 70, 80, 90, 100, 110, 120 → the second 40 until
    // it falls out after two more samples, then the smallest remaining.
    let rtts = [50u64, 40, 60, 40, 70, 80, 90, 100, 110, 120, 130, 140];
    let mut samples = Samples::default();
    let mut seq = Vec::new();
    for (k, rtt) in rtts.iter().enumerate() {
        let now = 10_000 + 1_000 * k as u64;
        let echo = now - rtt;
        let t = 50_000 + 1_000 * k as u64 + k as u64;
        samples.push(sample(now, t, echo, 0));
        let best = samples.best().unwrap();
        seq.push(json!({"now": now, "t": t, "echo": echo, "hold": 0, "best": {"rtt": best.rtt, "offset": best.offset, "error": best.error}}));
    }
    json!({
        "format": "colophon/session-offset-vectors/6",
        "formula": "rtt = max(0, (now - echo) - hold); offset = t - now + floor(rtt / 2); error = ceil(rtt / 2); best = smallest rtt of the last 8, the latest among equals",
        "cases": one,
        "bestOfLast8": seq,
    })
}

fn check_file(name: &str, v: &Value) {
    let path = dir().join(format!("{name}.json"));
    let text = serde_json::to_string_pretty(v).unwrap() + "\n";
    if std::env::var("COLOPHON_REGEN_VECTORS").is_ok() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let old = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {path:?}; run with COLOPHON_REGEN_VECTORS=1"));
    let old: Value = serde_json::from_str(&old).unwrap();
    assert_eq!(&old, v, "{name}.json differs from the reference machine");
}

/// Replay a vector file from its JSON alone.
fn replay(v: &Value) {
    let name = v["name"].as_str().unwrap();
    let policy: Policy = serde_json::from_value(v["policy"].clone()).unwrap();
    let fixes: Fixes = serde_json::from_value(v["fixes"].clone()).unwrap();
    let mut s: BTreeMap<String, Session> = BTreeMap::new();
    let mut initial: BTreeMap<String, (bool, Option<Claim>)> = BTreeMap::new();
    for m in v["members"].as_array().unwrap() {
        let id = m["id"].as_str().unwrap().to_owned();
        let w = m["canWrite"].as_bool().unwrap();
        initial.insert(id.clone(), (w, None));
        s.insert(id.clone(), Session::with_fixes(&id, w, policy.clone(), None, fixes));
    }
    for (k, step) in v["steps"].as_array().unwrap().iter().enumerate() {
        let member = step["member"].as_str().unwrap();
        if step.get("restart").is_some() {
            let p = s[member].accepted().cloned();
            s.insert(member.into(), Session::with_fixes(member, initial[member].0, policy.clone(), p, fixes));
            continue;
        }
        let input: Input = serde_json::from_value(step["input"].clone()).unwrap();
        let at = step["at"].as_u64().unwrap();
        let outs = s.get_mut(member).unwrap().handle(input, at);
        let expected: Vec<Output> = serde_json::from_value(step["outputs"].clone()).unwrap();
        assert_eq!(outs, expected, "{name}: step {k} ({member} at {at})");
    }
    for f in v["final"].as_array().unwrap() {
        let m = f["member"].as_str().unwrap();
        assert_eq!(s[m].digest(), f["digest"].as_str().unwrap(), "{name}: final digest of {m}");
        assert_eq!(serde_json::to_value(s[m].view()).unwrap(), f["view"], "{name}: final view of {m}");
    }
}

#[test]
fn vectors_match_and_replay() {
    let all = scenarios();
    let mut names = Vec::new();
    for sc in &all {
        let v = sc.to_json();
        check_file(sc.name, &v);
        names.push(sc.name);
    }
    check_file("offset", &offset_cases());
    // Replay from the files, as a binding would.
    for n in &names {
        let text = std::fs::read_to_string(dir().join(format!("{n}.json"))).unwrap();
        replay(&serde_json::from_str(&text).unwrap());
    }
    let text = std::fs::read_to_string(dir().join("offset.json")).unwrap();
    let off: Value = serde_json::from_str(&text).unwrap();
    for c in off["cases"].as_array().unwrap() {
        let g = |k: &str| c[k].as_u64().unwrap();
        let r = sample(g("now"), g("t"), g("echo"), g("hold"));
        assert_eq!((r.rtt, r.offset, r.error), (g("rtt"), c["offset"].as_i64().unwrap(), g("error")));
    }
    println!("{} session vectors and offset cases replayed", names.len());
}
