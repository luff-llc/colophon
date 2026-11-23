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
/// An `append` state from payloads.
fn ap(items: &[&str]) -> Bytes {
    Fold::framed(&items.iter().map(|x| b(x)).collect::<Vec<_>>())
}
fn id(label: &str) -> Id {
    Id::from_label(label)
}
fn frame_in(frame: Frame) -> Input {
    Input::Frame { frame, writer: true, key: None, n: None }
}

/// Recipient, frame, and the sender key and `n` when keyed.
type InFlight = (String, Frame, Option<(String, u64)>, Option<String>);

/// A scripted scenario. Sends go to a pending list; `deliver` routes them in order.
struct Script {
    name: &'static str,
    description: &'static str,
    policy: Policy,
    members: Vec<(String, bool, Option<Persisted>)>,
    s: BTreeMap<String, Session>,
    /// In flight: recipient, frame, and the sender key and `n` when keyed.
    pending: Vec<InFlight>,
    steps: Vec<Value>,
    /// Frames from `a` to `b` are lost when `(a, b)` is here.
    cut: Vec<(String, String)>,
    /// Keyed: each member has a session key `k-<id>`, an `n` counter and a `fresh` seed.
    keyed: bool,
    n: BTreeMap<String, u64>,
}

impl Script {
    fn new(name: &'static str, description: &'static str, policy: Policy, ids: &[&str]) -> Self {
        let members: Vec<(String, bool, Option<Persisted>)> =
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
            cut: Vec::new(),
            keyed: false,
            n: BTreeMap::new(),
        }
    }
    fn keyed(mut self) -> Self {
        self.keyed = true;
        for (id, s) in self.s.iter_mut() {
            *s = s.clone().with_fresh_seed(seed_of(id));
        }
        self
    }
    #[allow(dead_code)]
    fn cut(&mut self, a: &str, b: &str) {
        self.cut.push((a.into(), b.into()));
        self.cut.push((b.into(), a.into()));
    }
    fn route(&mut self, from: &str, to: String, frame: Frame, key: Option<(String, u64)>) {
        if !self.cut.iter().any(|(x, y)| x == from && *y == to) {
            let via = (frame.from != from).then(|| from.to_owned());
            self.pending.push((to, frame, key, via));
        }
    }
    fn ids(&self) -> Vec<String> {
        self.members.iter().map(|m| m.0.clone()).collect()
    }
    fn step(&mut self, member: &str, at: u64, input: Input) -> Vec<Output> {
        let outs = self.s.get_mut(member).unwrap().handle(input.clone(), at);
        self.steps.push(json!({"member": member, "at": at, "input": input, "outputs": outs}));
        for o in &outs {
            match o {
                Output::Send { frame } => {
                    let key = self.keyed.then(|| {
                        let n = self.n.entry(member.to_owned()).or_insert(0);
                        *n += 1;
                        (format!("k-{member}"), *n)
                    });
                    // §S9 (revision 10): every frame is carried to every member; `to` is
                    // advice, and a member it does not name ignores the frame.
                    let dsts: Vec<String> = self.ids().into_iter().filter(|i| i != member).collect();
                    for d in dsts {
                        self.route(member, d, frame.clone(), key.clone());
                    }
                }
                Output::Forward { to, frame } => self.route(member, to.clone(), frame.clone(), None),
                _ => {}
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
            let (to, f, key, via) = self.pending.remove(0);
            if drop(&to, &f) {
                continue;
            }
            let (key, n) = match key {
                Some((k, n)) => (Some(k), Some(n)),
                None => (None, None),
            };
            let _ = via;
            self.step(&to, at, Input::Frame { frame: f, writer: true, key, n });
        }
    }
    fn deliver(&mut self, at: u64) {
        self.deliver_if(at, |_, _| false);
    }
    fn lose_all(&mut self) {
        self.pending.clear();
    }
    /// The host supplies the entitled set (every member here) to `member` (§S1).
    fn entitle(&mut self, member: &str, at: u64) {
        let writers = self.ids();
        self.step(member, at, Input::Entitled { writers });
    }
    fn join_all(&mut self, at: u64) {
        for id in self.ids() {
            self.entitle(&id, at);
            self.cmd(&id, at, Command::Join { state: None });
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
            "members": self.members.iter().map(|(id, w, p)| json!({
                "id": id, "canWrite": w, "persisted": p,
                "freshSeed": self.keyed.then(|| hex(&seed_of(id))),
            })).collect::<Vec<_>>(),
            "steps": self.steps,
            "final": finals,
        })
    }
}

fn seed_of(id: &str) -> [u8; 16] {
    Id::from_label(&format!("seed-{id}")).0
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn started(name: &'static str, description: &'static str, policy: Policy, ids: &[&str]) -> Script {
    let st = match policy.fold {
        Fold::Latest => b("s0"),
        Fold::Append => ap(&["s0"]),
    };
    let mut s = Script::new(name, description, policy, ids);
    s.join_all(0);
    s.deliver(0);
    s.cmd(ids[0], 10, Command::Take { state: Some(st) });
    s.deliver(20);
    s
}

fn scenarios() -> Vec<Script> {
    let p = Policy::default;
    let append = || Policy { fold: Fold::Append, ..Policy::default() };
    let mut v = Vec::new();

    let mut s = started("take-publish", "a takes with a snapshot, publishes two messages; b follows in order.", append(), &["a", "b"]);
    s.cmd("a", 100, Command::Publish { id: id("id1"), payload: b("+1") });
    s.cmd("a", 110, Command::Publish { id: id("id2"), payload: b("+2") });
    s.deliver(120);
    assert_eq!(s.session("b").state(), &ap(&["s0", "+1", "+2"]));
    v.push(s);

    let mut s = started("ask-pass", "b asks; a pauses and passes its final §S12 anchor (playing false); b holds from exactly that snapshot (§S5, G3).", p(), &["a", "b", "c"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    let stopped = br#"{"at":1020,"episode":"e1","playing":false,"positionMs":61250,"ratePermille":1250,"show":"s1"}"#;
    s.cmd("a", 1_020, Command::Pass { to: "b".into(), snapshot: Bytes(stopped.to_vec()) });
    s.deliver(1_030);
    assert!(s.session("b").is_holder());
    assert_eq!(s.session("c").state(), &Bytes(stopped.to_vec()));
    v.push(s);

    let mut s = started("pass-not-entitled", "b asks; before a passes, the accepted authority head drops b's write entitlement (an `entitled` input); a's pass to b is rejected and a keeps the role (§S5, revision 10).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    s.step("a", 1_015, Input::Entitled { writers: vec!["a".into()] });
    let outs = s.cmd("a", 1_020, Command::Pass { to: "b".into(), snapshot: b("s1") });
    assert!(outs.iter().any(|o| matches!(o, Output::Event { event: Event::Rejected { reason, .. } } if reason == "not-entitled")));
    s.deliver(1_030);
    assert!(s.session("a").is_holder() && !s.session("b").is_holder());
    v.push(s);

    let mut s = started("entitlement-after-restart", "b asks; the authority head then drops b, and a restarts before its host has the new entitled set. Until the host supplies it nobody is entitled: a's join waits, b's frames are not accepted as a writer's and no pass is made. Then the set (without b) arrives, a joins, retakes after askTimeoutMs, and its pass to b is refused (§S1, revision 12).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    let persisted = s.session("a").persisted();
    s.s.insert("a".into(), Session::new("a", true, p(), persisted));
    s.steps.push(json!({"member": "a", "restart": true}));
    let outs = s.cmd("a", 1_100, Command::Join { state: Some(b("s0")) });
    assert!(outs.is_empty() && !s.session("a").joined());
    let outs = s.cmd("a", 1_110, Command::Pass { to: "b".into(), snapshot: b("s1") });
    assert!(outs.iter().any(|o| matches!(o, Output::Event { event: Event::Rejected { reason, .. } } if reason == "not-joined")));
    s.cmd("b", 1_120, Command::Ask);
    s.deliver(1_130);
    assert!(s.session("a").next_deadline().is_none());
    s.step("a", 1_200, Input::Entitled { writers: vec!["a".into()] });
    assert!(s.session("a").joined());
    s.deliver(1_210);
    s.tick("a", 2_700);
    s.deliver(2_710);
    assert!(s.session("a").is_holder());
    s.cmd("b", 2_800, Command::Ask);
    s.deliver(2_810);
    let outs = s.cmd("a", 2_900, Command::Pass { to: "b".into(), snapshot: b("s1") });
    assert!(outs.iter().any(|o| matches!(o, Output::Event { event: Event::Rejected { reason, .. } } if reason == "not-entitled")));
    s.deliver(2_910);
    assert!(s.session("a").is_holder() && !s.session("b").is_holder());
    v.push(s);

    let mut s = started("revoked-writer-ignored", "a holds; a new authority history removes c. Each host tells its core (an `entitled` input without c) before delivering any later frame (§S1, revision 14). Then c's frames arrive as if c still held a greater claim (take, state, msg, beat at 2.0.c) and c asks: a and b drop them all, keep 1.0.a with a's state, and a takes no ask from c (G8).", p(), &["a", "b", "c"]);
    for m in ["a", "b"] {
        s.step(m, 1_000, Input::Entitled { writers: vec!["a".into(), "b".into()] });
    }
    for (m, at) in [("a", 1_100u64), ("b", 1_100)] {
        for f in revoked_frames() {
            s.step(m, at, Input::Frame { frame: f, writer: true, key: None, n: None });
        }
    }
    s.cmd("c", 1_200, Command::Ask);
    s.deliver(1_210);
    s.tick("a", 5_000);
    s.deliver(5_010);
    for m in ["a", "b"] {
        assert_eq!(s.session(m).accepted(), Some(&Claim::new(1, 0, "a")), "{m}");
        assert_eq!(s.session(m).state(), &b("s0"), "{m}");
    }
    assert!(s.session("a").is_holder() && s.session("a").asks().next().is_none());
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
    s.cmd("b", 100, Command::Take { state: None });
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
        s.cmd("a", t, Command::Publish { id: id(&format!("m{i}")), payload: Bytes(vec![b'0' + i]) });
    }
    let lost = std::cell::Cell::new(false);
    s.deliver_if(130, |_, f| {
        let first = matches!(&f.body, Body::Msg { seq: 2, .. }) && !lost.get();
        lost.set(lost.get() || first);
        first
    });
    assert_eq!(s.session("b").state(), &ap(&["s0", "1", "2", "3"]));
    v.push(s);

    let mut s = started("gap-state-resume", "with tail 1 the missing messages are gone; a answers b's hello with state; the append fold keeps the last `tail` payloads (§S8, §S1).", Policy { tail: 1, ..append() }, &["a", "b"]);
    for (i, t) in [(1u8, 100u64), (2, 110), (3, 120)] {
        s.cmd("a", t, Command::Publish { id: id(&format!("m{i}")), payload: Bytes(vec![b'0' + i]) });
    }
    s.deliver_if(130, |_, f| matches!(&f.body, Body::Msg { seq: 1 | 2, .. }) && f.to.is_none());
    assert_eq!(s.session("b").state(), &ap(&["3"]));
    v.push(s);

    let mut s = started("take-without-state", "b takes; its state frame to c is lost; c accepts the claim from take, says seen.seq = null and gets state (§S8, finding F2).", p(), &["a", "b", "c"]);
    s.lose_all();
    s.cmd("b", 1_000, Command::Take { state: None });
    s.tick("b", 20_000);
    s.deliver_if(20_010, |to, f| to == "c" && matches!(f.body, Body::State { .. }) && f.to.is_none());
    assert!(s.session("c").synced());
    v.push(s);

    let mut s = started("partition-two-holders", "a is cut off; b sees a lapsed and takes; when a's link heals its hello reaches b, which answers with state; a yields to the greater claim and sends `yielded` with what it held, which b reports and acknowledges with `ack` (§S4, §S5 yielding state, §S6, G6, G11).", p(), &["a", "b"]);
    s.step("a", 1_000, Input::LinkDown);
    s.lose_all();
    s.cmd("b", 1_000, Command::Take { state: None });
    s.tick("b", 16_100);
    s.lose_all();
    s.step("a", 10_000, Input::LinkUp);
    s.deliver(10_010);
    assert!(s.session("b").is_holder() && !s.session("a").is_holder());
    assert!(s.steps.iter().any(|st| st["outputs"].to_string().contains("\"displaced\"")));
    assert!(s.steps.iter().any(|st| st["outputs"].to_string().contains("\"kind\":\"ack\"")));
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

    let mut s = started("submit", "b submits; a orders it with origin b; a duplicate submit (same id, within the last `tail`) is dropped; an oversize one is dropped (§S8, §S3).", Policy { max_payload: 32, ..append() }, &["a", "b"]);
    s.cmd("b", 100, Command::Submit { id: id("x1"), payload: b("+b") });
    s.deliver(110);
    s.step("a", 120, frame_in(Frame { from: "b".into(), to: Some("a".into()), retain: false, body: Body::Submit { id: id("x1"), payload: b("+b") } }));
    s.step("a", 130, frame_in(Frame { from: "b".into(), to: Some("a".into()), retain: false, body: Body::Submit { id: id("x2"), payload: Bytes(vec![b'z'; 40]) } }));
    s.deliver(140);
    assert_eq!(s.session("b").state(), &ap(&["s0", "+b"]));
    v.push(s);

    let mut s = started("pass-lost-resend", "a's pass to b is lost; b, still under the old claim, resends ask; a resends the same pass (§S5, F9).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    s.cmd("a", 1_020, Command::Pass { to: "b".into(), snapshot: b("stopped") });
    s.lose_all();
    s.step("b", 2_600, frame_in(Frame { from: "a".into(), to: None, retain: true, body: Body::Beat { claim: Claim::new(1, 0, "a"), seq: 0 } }));
    s.tick("b", 2_600);
    s.deliver(2_610);
    assert!(s.session("b").is_holder());
    v.push(s);

    let mut s = started("restart-holder", "a restarts with its persisted claim; the application supplies the cell's state with join; a sends hello lapsed:true, waits askTimeoutMs, then retakes at term + 1 with that state (§S6, revision 2).", append(), &["a", "b"]);
    s.cmd("a", 100, Command::Publish { id: id("1"), payload: b("+1") });
    s.deliver(110);
    let persisted = s.session("a").persisted();
    s.s.insert("a".into(), Session::new("a", true, append(), persisted));
    s.steps.push(json!({"member": "a", "restart": true}));
    s.entitle("a", 200);
    s.cmd("a", 200, Command::Join { state: Some(ap(&["s0", "+1"])) });
    s.deliver(210);
    s.tick("a", 2_000);
    s.deliver(2_010);
    assert_eq!(s.session("a").accepted(), Some(&Claim::new(2, 0, "a")));
    assert_eq!(s.session("b").state(), &ap(&["s0", "+1"]));
    v.push(s);

    let mut s = started("release", "a releases: it persists the tombstone, then sends bye (leaving false); the cell has no holder; b asks and takes at once; a restarts and does not resurrect its claim (§S4, §S5 release, R2c, R3).", p(), &["a", "b"]);
    s.cmd("a", 100, Command::Release);
    s.deliver(110);
    s.cmd("b", 200, Command::Ask);
    s.lose_all();
    let persisted = s.session("a").persisted();
    assert!(persisted.as_ref().is_some_and(|p| p.released));
    s.s.insert("a".into(), Session::new("a", true, p(), persisted));
    s.steps.push(json!({"member": "a", "restart": true}));
    s.entitle("a", 300);
    s.cmd("a", 300, Command::Join { state: None });
    s.tick("a", 2_000);
    assert!(s.session("b").is_holder() && !s.session("a").is_holder());
    v.push(s);

    let mut s = started("ping-offset", "b pings a; a pongs with its clock; b's offset and error bound follow §S7.", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ping { to: "a".into() });
    let pending = std::mem::take(&mut s.pending);
    for to in pending {
        let f = to.1.clone();
        s.step(&to.0, 1_037, frame_in(f));
    }
    let pending = std::mem::take(&mut s.pending);
    for to in pending {
        let f = to.1.clone();
        s.step(&to.0, 1_081, frame_in(f));
    }
    let o = s.session("b").offset_to("a").unwrap();
    assert_eq!((o.rtt, o.offset, o.error), (81, -4, 41));
    v.push(s);

    // Revision 7.
    let mut s = started("renew-quiet-claim", "c, cut off from a, sees a lapsed and takes 2.0.c; only b hears it, and c then falls silent. a's beat reaches b, which names 2.0.c in its hello; a has heard no holder frame from c for holderTimeoutMs, and its own link has worked that long, so a renews over c to 3.0.a and b follows (§S4 correcting lesser claims, §S5 renewing, revision 7).", p(), &["a", "b", "c"]);
    s.cmd("c", 100, Command::Take { state: Some(b("C")) });
    s.tick("c", 16_000);
    s.deliver_if(16_010, |to, _| to == "a");
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(2, 0, "c")));
    s.tick("a", 20_000);
    s.deliver_if(20_010, |to, f| to == "c" || f.from == "c");
    assert_eq!(s.session("a").accepted(), Some(&Claim::new(3, 0, "a")));
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(3, 0, "a")));
    v.push(s);

    let mut s = Script::new("append-bound", "fold append with maxPayload 64: a 64-byte payload is refused (at most maxPayload − 4 bytes, revision 8); after a 20-byte and a 60-byte payload the state keeps only what fits in 64 bytes once encoded (the 60-byte one with its 4-byte frame); a joiner gets that state (§S1 fold, revisions 7 and 8).", Policy { fold: Fold::Append, max_payload: 64, ..Policy::default() }, &["a", "b"]);
    s.entitle("a", 0);
    s.cmd("a", 0, Command::Join { state: None });
    s.cmd("a", 10, Command::Take { state: None });
    s.cmd("a", 20, Command::Publish { id: id("small"), payload: Bytes(vec![1; 20]) });
    s.cmd("a", 25, Command::Publish { id: id("too-big"), payload: Bytes(vec![3; 64]) });
    s.cmd("a", 30, Command::Publish { id: id("big"), payload: Bytes(vec![2; 60]) });
    assert_eq!(s.session("a").state().len(), 64);
    s.lose_all();
    assert!(s.session("a").state().len() <= 64);
    s.entitle("b", 40);
    s.cmd("b", 40, Command::Join { state: None });
    s.deliver(50);
    assert!(s.session("b").synced());
    assert_eq!(s.session("b").state(), s.session("a").state());
    v.push(s);

    // Revision 4 behaviours.
    let mut s = started("late-pass", "b asks; a's pass (SA) is delayed past b's ask timeout; b takes with SB; the pass arrives: b reports it (late pass, with SA) and renews with SB; a, holding the pass's claim, follows (§S5, R2a, G11).", p(), &["a", "b"]);
    s.cmd("b", 100, Command::Ask);
    s.deliver(110);
    s.cmd("a", 120, Command::Pass { to: "b".into(), snapshot: b("SA") });
    let held: Vec<_> = std::mem::take(&mut s.pending);
    s.cmd("b", 200, Command::Take { state: Some(b("SB")) });
    s.tick("b", 1_700);
    s.deliver_if(1_710, |to, _| to == "a");
    s.pending = held;
    s.deliver(1_800);
    s.tick("b", 7_000);
    s.deliver(7_010);
    assert!(s.steps.iter().any(|st| st["outputs"].to_string().contains("\"latePass\"")));
    assert_eq!(s.session("a").accepted(), Some(&Claim::new(3, 0, "b")));
    v.push(s);

    let mut s = Script::new("freshness", "keyed frames: a's join hello reaches b, which has no window for a's key and answers echoing a's fresh; that answer opens a's window for b's key, and a answers echoing b's fresh, which opens b's window; a frame below a window's floor is then dropped (§S3 freshness, R4).", p(), &["a", "b"]).keyed();
    s.join_all(0);
    s.deliver(0);
    s.cmd("a", 10, Command::Take { state: Some(b("A")) });
    s.deliver(20);
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(1, 0, "a")));
    // A replay of a's take with n = 1 (below the window's floor) changes nothing.
    let replay = Frame { from: "a".into(), to: None, retain: false, body: Body::Take { claim: Claim::new(1, 0, "a") } };
    let outs = s.step("b", 30, Input::Frame { frame: replay, writer: true, key: Some("k-a".into()), n: Some(1) });
    assert!(outs.is_empty());
    v.push(s);

    let mut s = started("reader-claims-ignored", "r may only read (it is in no entitled set): its hello naming itself at 2^53 − 1, its bye releasing a's claim, a yielded and a take reach a and b, flagged by a host as from a writer or not; neither adopts, releases or reports anything, and b can still take one term up later (§S4 rule 1, revision 15).", p(), &["a", "b"]);
    let max = Claim::new(MAX_TERM, 0, "r");
    let reader = |body| Frame { from: "r".into(), to: None, retain: false, body };
    let frames = [
        reader(Body::Hello { fresh: id("r1"), echo: vec![], seen: Some(Seen { claim: max.clone(), seq: Some(0) }), heard: None, lapsed: false }),
        reader(Body::Bye { claim: Some(Claim::new(1, 0, "a")), leaving: false }),
        reader(Body::Bye { claim: Some(max.clone()), leaving: false }),
        reader(Body::Yielded { claim: max.clone(), seq: 0, snapshot: b("evil") }),
        reader(Body::Take { claim: max }),
    ];
    for (k, f) in frames.iter().enumerate() {
        for m in ["a", "b"] {
            s.step(m, 100 + k as u64, Input::Frame { frame: f.clone(), writer: k % 2 == 0, key: None, n: None });
        }
    }
    s.deliver(200);
    assert_eq!(s.session("a").accepted(), Some(&Claim::new(1, 0, "a")));
    assert_eq!(s.session("b").holder(), Some("a"));
    s.cmd("a", 300, Command::Release);
    s.deliver(310);
    s.cmd("b", 400, Command::Take { state: None });
    s.deliver(410);
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(2, 0, "b")));
    v.push(s);

    let mut s = started("demoted-holder-release", "a holds; b's host learns that a may now only read; a's bye releasing exactly 1.0.a, b's accepted claim, held by a, is honoured, so the cell has no holder; a bye from a reader naming a greater claim of its own changes nothing (§S4 rule 1, revision 17).", p(), &["a", "b"]);
    s.step("b", 100, Input::Entitled { writers: vec!["b".into()] });
    let bye = |claim| Input::Frame { frame: Frame { from: "a".into(), to: None, retain: false, body: Body::Bye { claim: Some(claim), leaving: false } }, writer: false, key: None, n: None };
    s.step("b", 110, bye(Claim::new(5, 0, "a")));
    assert_eq!(s.session("b").holder(), Some("a"));
    s.step("b", 120, bye(Claim::new(1, 0, "a")));
    assert_eq!(s.session("b").holder(), None);
    v.push(s);

    // Revision 17: a closed key reopens only through a new challenge.
    let mut s = Script::new("closed-key-reopen", "keyed frames, b alone, five session keys of a (k1–k5): each opens a window by echoing a fresh b issued; the fifth closes k1. A replay of k1's echoing hello (its echoed fresh still inside the 60 s memory) and of a take under k1 do nothing. k1 then answers a new challenge and its take is accepted (§S3 freshness, revision 17). a's own machine is idle: its frames are written by hand.", p(), &["a", "b"]).keyed();
    s.join_all(0);
    let hello = |fresh: &str, echo: Vec<Id>| Body::Hello { fresh: id(fresh), echo, seen: None, heard: None, lapsed: false };
    let fresh_of = |outs: &[Output]| outs.iter().find_map(|o| match o {
        Output::Send { frame: Frame { body: Body::Hello { fresh, .. }, .. } } => Some(*fresh),
        _ => None,
    }).unwrap();
    let keyed_in = |body, key: &str, n| Input::Frame { frame: Frame { from: "a".into(), to: None, retain: false, body }, writer: true, key: Some(key.into()), n: Some(n) };
    let mut k1_answer = None;
    for k in 1..=5u64 {
        let key = format!("k{k}");
        // Keys at least askTimeoutMs apart: answers to new keys share the probe limit.
        let outs = s.step("b", 2_000 * k, keyed_in(hello(&format!("a{k}"), vec![]), &key, 1));
        let challenge = fresh_of(&outs);
        let answer = hello(&format!("a{k}'"), vec![challenge]);
        if k == 1 {
            k1_answer = Some(answer.clone());
        }
        s.step("b", 2_000 * k + 1, keyed_in(answer, &key, 2));
        assert!(s.session("b").window_admits("a", &key, 3));
    }
    assert!(!s.session("b").window_admits("a", "k1", 3), "the fifth key closed k1");
    s.step("b", 11_000, keyed_in(k1_answer.unwrap(), "k1", 2));
    s.step("b", 11_001, keyed_in(Body::Take { claim: Claim::new(1, 0, "a") }, "k1", 3));
    assert!(!s.session("b").window_admits("a", "k1", 3));
    assert_eq!(s.session("b").accepted(), None);
    let outs = s.step("b", 14_000, keyed_in(hello("a1-again", vec![]), "k1", 4));
    let challenge = fresh_of(&outs);
    s.step("b", 14_001, keyed_in(hello("a1-answer", vec![challenge]), "k1", 5));
    assert!(s.session("b").window_admits("a", "k1", 6));
    s.step("b", 14_002, keyed_in(Body::Take { claim: Claim::new(1, 0, "a") }, "k1", 6));
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(1, 0, "a")));
    v.push(s);

    let mut s = started("pass-ack", "a passes to b and the pass is lost; b takes on the ask timeout; a resends the same pass when it hears b (on any frame from b or on its timer, backing off from askTimeoutMs to holderTimeoutMs, revision 17); b reports it as a late pass, renews over it and acknowledges; a stops resending (§S5, revision 15, G11).", p(), &["a", "b"]);
    s.cmd("b", 1_000, Command::Ask);
    s.deliver(1_010);
    s.cmd("a", 1_020, Command::Pass { to: "b".into(), snapshot: b("stopped") });
    s.lose_all();
    s.tick("b", 2_600);
    assert!(s.session("b").is_holder());
    s.deliver(2_610);
    s.tick("b", 7_700);
    s.deliver(7_710);
    assert_eq!(s.session("b").accepted(), Some(&Claim::new(3, 0, "b")));
    assert_eq!(s.session("a").holder(), Some("b"));
    s.tick("b", 12_800);
    s.deliver(12_810);
    v.push(s);

    v
}

/// §S9 bridging on the chain m0–m1–m2–m3: m0 sends a frame; each bridge forwards what it
/// accepts for the first time on its other links; a duplicate and a too-old frame are not
/// forwarded; a `to`-addressed frame is bridged too.
fn bridge_cases() -> Value {
    use colophon_core::v06::bridge::{Bridge, Wire};
    let n = 4;
    let mut bridges: Vec<Bridge> = (0..n).map(|i| Bridge::new(&format!("m{i}"))).collect();
    // Link ids: 2i is i -> i+1, 2i+1 is i+1 -> i; a member names a link by the direction
    // leaving it.
    let mut links = Vec::new();
    for i in 0..n - 1 {
        bridges[i].add_link((2 * i) as u32);
        bridges[i + 1].add_link((2 * i + 1) as u32);
        links.push(json!({"id": 2 * i, "from": format!("m{i}"), "to": format!("m{}", i + 1)}));
        links.push(json!({"id": 2 * i + 1, "from": format!("m{}", i + 1), "to": format!("m{i}")}));
    }
    let peer = |link: u32| -> (usize, u32) {
        let i = (link / 2) as usize;
        if link % 2 == 0 {
            (i + 1, link + 1)
        } else {
            (i, link - 1)
        }
    };
    let wire_json = |w: &Wire| json!({"key": w.key, "n": w.n, "frame": w.frame});
    let mut steps = Vec::new();
    let flood = |bridges: &mut Vec<Bridge>, steps: &mut Vec<Value>, w: Wire, origin: usize| {
        let mut queue: Vec<(u32, Wire)> = bridges[origin].send(w.clone());
        steps.push(json!({"member": format!("m{origin}"), "send": wire_json(&w), "transmit": queue.iter().map(|(l, _)| *l).collect::<Vec<_>>()}));
        while !queue.is_empty() {
            let (l, w) = queue.remove(0);
            let (to, back) = peer(l);
            let r = bridges[to].receive(back, w.clone());
            steps.push(json!({
                "member": format!("m{to}"), "receive": {"link": back, "wire": wire_json(&w)},
                "deliver": r.deliver.is_some(),
                "forward": r.forward.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
            }));
            queue.extend(r.forward);
        }
    };
    let frame = |to: Option<&str>, t: u64| Frame { from: "m0".into(), to: to.map(str::to_owned), retain: false, body: Body::Ping { t } };
    flood(&mut bridges, &mut steps, Wire { key: "k-m0".into(), n: 1, frame: frame(None, 1) }, 0);
    flood(&mut bridges, &mut steps, Wire { key: "k-m0".into(), n: 2, frame: frame(Some("m3"), 2) }, 0);
    // At m2 from m1: a duplicate of n = 1, a new n = 200, then n = 71 (more than 128 below).
    for (nn, t) in [(1u64, 1u64), (200, 3), (71, 4)] {
        let w = Wire { key: "k-m0".into(), n: nn, frame: frame(None, t) };
        let r = bridges[2].receive(3, w.clone());
        steps.push(json!({"member": "m2", "receive": {"link": 3, "wire": wire_json(&w)}, "deliver": r.deliver.is_some(), "forward": r.forward.iter().map(|(l, _)| *l).collect::<Vec<_>>()}));
    }
    json!({
        "format": "colophon/bridge-vectors/6",
        "description": "§S9 bridging on a four-member chain: first-seen forwarding on every other link, nothing back, nothing twice, nothing more than 128 below the window's highest n; to-addressed frames are bridged too.",
        "members": (0..n).map(|i| format!("m{i}")).collect::<Vec<_>>(),
        "links": links,
        "steps": steps,
    })
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
        (MAX_INT, 0, 0, 0),
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
    let mut initial: BTreeMap<String, bool> = BTreeMap::new();
    for m in v["members"].as_array().unwrap() {
        let id = m["id"].as_str().unwrap().to_owned();
        let w = m["canWrite"].as_bool().unwrap();
        initial.insert(id.clone(), w);
        let mut session = Session::with_fixes(&id, w, policy.clone(), None, fixes);
        if let Some(seed) = m["freshSeed"].as_str() {
            let mut b = [0u8; 16];
            for (k, x) in b.iter_mut().enumerate() {
                *x = u8::from_str_radix(&seed[2 * k..2 * k + 2], 16).unwrap();
            }
            session = session.with_fresh_seed(b);
        }
        s.insert(id.clone(), session);
    }
    for (k, step) in v["steps"].as_array().unwrap().iter().enumerate() {
        let member = step["member"].as_str().unwrap();
        if step.get("restart").is_some() {
            let p = s[member].persisted();
            s.insert(member.into(), Session::with_fixes(member, initial[member], policy.clone(), p, fixes));
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
    check_file("bridge", &bridge_cases());
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


/// Frames from c under 2.0.c, as a removed member that still thinks it holds would send.
fn revoked_frames() -> Vec<Frame> {
    let c = Claim::new(2, 0, "c");
    let f = |body| Frame { from: "c".into(), to: None, retain: false, body };
    vec![
        f(Body::Take { claim: c.clone() }),
        f(Body::State { claim: c.clone(), seq: 1, snapshot: b("from c") }),
        f(Body::Msg { claim: c.clone(), seq: 2, origin: "c".into(), id: id("c2"), payload: b("from c 2") }),
        f(Body::Beat { claim: c, seq: 2 }),
    ]
}

/// Outside the model (§S1, revision 14, host ordering): b's host delivers the removed
/// member's frames before telling its core of the new entitled set. b accepts c's greater
/// claim, because as far as its core knew c was still a writer, and the later `entitled`
/// input does not undo an accepted claim. Shown, not a guarantee: G8 depends on the order.
/// a, told in order, ignores c.
#[test]
fn revocation_after_frames_is_outside_the_model() {
    let mut s = started("x", "", Policy::default(), &["a", "b", "c"]);
    s.step("a", 1_000, Input::Entitled { writers: vec!["a".into(), "b".into()] });
    for f in revoked_frames() {
        s.step("a", 1_100, Input::Frame { frame: f.clone(), writer: true, key: None, n: None });
        s.step("b", 1_100, Input::Frame { frame: f, writer: true, key: None, n: None });
    }
    s.lose_all();
    s.step("b", 1_140, Input::Entitled { writers: vec!["a".into(), "b".into()] });
    let b_claim = s.session("b").accepted().cloned();
    let b_state = s.session("b").state().clone();
    s.tick("a", 5_000);
    s.deliver(5_010);
    s.tick("b", 30_000);
    s.deliver(30_010);
    println!(
        "host order violated: b accepted {:?} (state {:?}) from the removed c; a kept 1.0.a; 30 s later b holds {:?}, a holds {:?}",
        b_claim.as_ref().map(show),
        String::from_utf8_lossy(&b_state.0),
        s.session("b").accepted().map(show),
        s.session("a").accepted().map(show)
    );
    assert_eq!(b_claim, Some(Claim::new(2, 0, "c")), "b follows c when its host delivers c's frames first");
    assert_eq!(s.session("a").accepted().map(|c| c.holder.as_str()), Some("a"), "a, told first, ignores c");
}

fn show(c: &Claim) -> String {
    format!("{}.{}.{}", c.term, c.rank, c.holder)
}
