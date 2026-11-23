//! Exhaustive bounded exploration of the 0.6 session machine (§S4–§S8) for 2 and 3 members.
//!
//! The network holds a set of in-flight `(recipient, frame)` pairs. Each step is one of:
//! deliver any in-flight frame, deliver it and keep a copy (duplication, budgeted), drop it,
//! advance every member's clock by one tick, take a member's link down or up (budgeted), or one
//! application command (budgeted): ask, take, pass to a member that asked, decline, publish,
//! submit, release, leave, join, restart from the persisted claim. A frame sent while the
//! sender's link is down is lost; one addressed to a member whose link is down waits.
//! Identical in-flight copies collapse, and at most `cap` frames are in flight (extra sends
//! are lost): both are losses the model allows anyway.
//!
//! On every transition: G1, G2, G3 and G6 (see `v06_session_support`). From every reachable
//! state: G4 by a fair lossless completion (links up, every frame delivered in order, ticks
//! until well past `holderTimeoutMs`) reaching one holder and one ordered state; and G5 by a
//! completion in which the holder is cut off and another writer asks, which must reach a
//! reachable holder within `askTimeoutMs` plus one tick.
//!
//! Bounds: `COLOPHON_EXPLORE=big` explores larger budgets.
#![allow(clippy::unwrap_used)]
mod v06_session_support;
use colophon_core::v06::session::*;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use v06_session_support::*;

const IDS: [&str; 3] = ["a", "b", "c"];
/// One explorer tick in ms: the §S8 gap-hello limit (1 s) is one tick.
const TICK: u64 = 1_000;
/// The longest policy duration (`policy()`): every comparison is `age >= d` or `age < d`
/// with `d` at most this, so ages beyond it are indistinguishable.
const HORIZON: u64 = 3 * TICK;
static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn policy() -> Policy {
    Policy {
        beat_ms: 2 * TICK,
        holder_timeout_ms: 3 * TICK,
        ask_timeout_ms: TICK,
        presence_timeout_ms: 3 * TICK,
        retain_ms: 60 * TICK,
        tail: 2,
        max_payload: 16,
        fold: Fold::Append,
        take: TakeRule::Free,
    }
}

#[derive(Clone, Copy, Debug)]
struct Bounds {
    members: usize,
    time: u64,
    cmds: u8,
    dups: u8,
    links: u8,
    restarts: u8,
    cap: usize,
    max_states: usize,
    /// Steps explored from the initial state (each delivery, drop, tick, link change or
    /// command is one step); every state within this depth is visited.
    depth: u32,
    completions: bool,
    /// Allowed commands: a ask, t take, p pass/decline, u publish, s submit, r release,
    /// l leave/join, x restart.
    kinds: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Cmd {
    Ask,
    Take,
    Pass(usize),
    Decline(usize),
    Publish,
    Submit,
    Release,
    Leave,
    Join,
    Restart,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Action {
    Deliver(usize),
    Dup(usize),
    Drop(usize),
    Tick,
    Link(usize, bool),
    Cmd(usize, Cmd),
}

#[derive(Clone)]
struct World {
    now: u64,
    m: Vec<Session>,
    up: Vec<bool>,
    net: Vec<(usize, Frame)>,
    cmds: u8,
    dups: u8,
    links: u8,
    restarts: u8,
    asks: Vec<Vec<usize>>,
    persisted: Vec<Option<Claim>>,
    ghost: Ghost,
    payload: u8,
    lossless: bool,
    fixes: Fixes,
    kinds: &'static str,
}

fn idx(id: &str) -> usize {
    IDS.iter().position(|x| *x == id).unwrap()
}

impl World {
    fn new(b: &Bounds, fixes: Fixes) -> Self {
        let m = (0..b.members)
            .map(|i| Session::with_fixes(IDS[i], true, policy(), None, fixes))
            .collect();
        let mut w = World {
            now: 0,
            m,
            up: vec![true; b.members],
            net: Vec::new(),
            cmds: b.cmds,
            dups: b.dups,
            links: b.links,
            restarts: b.restarts,
            asks: vec![Vec::new(); b.members],
            persisted: vec![None; b.members],
            ghost: Ghost::default(),
            payload: 0,
            lossless: true,
            fixes,
            kinds: b.kinds,
        };
        // Start: everyone joined, `a` took, all frames delivered.
        for i in 0..b.members {
            w.input(i, Input::App { command: Command::Join { state: None } }, b).unwrap();
        }
        w.input(0, Input::App { command: Command::Take { state: None } }, b).unwrap();
        w.flush(b).unwrap();
        w.lossless = false;
        w
    }

    /// The canonical key: every member hashed with times relative to `now`
    /// ([`Session::hash_at`]), so unbounded time is explored with a finite state space.
    fn key(&self) -> u128 {
        let one = |seed: u8| {
            let mut h = DefaultHasher::new();
            seed.hash(&mut h);
            for m in &self.m {
                m.hash_at(self.now, HORIZON, &mut h);
            }
            self.up.hash(&mut h);
            self.net.hash(&mut h);
            (self.cmds, self.dups, self.links, self.restarts).hash(&mut h);
            self.asks.hash(&mut h);
            self.persisted.hash(&mut h);
            self.ghost.hash(&mut h);
            self.payload.hash(&mut h);
            h.finish()
        };
        (u128::from(one(0)) << 64) | u128::from(one(1))
    }

    fn input(&mut self, i: usize, input: Input, b: &Bounds) -> Result<Vec<Output>, String> {
        let before = self.m[i].clone();
        let delivered = match &input {
            Input::Frame { frame, .. } => Some(frame.clone()),
            _ => None,
        };
        let shown = VERBOSE
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| format!("{input:?}"));
        let outs = self.m[i].handle(input, self.now);
        if let Some(inp) = shown {
            if !outs.is_empty() || !inp.starts_with("Tick") {
                let inp = match &before {
                    _ if inp.starts_with("Frame") => "frame".to_string(),
                    _ => inp,
                };
                println!("      [{} t={}] {inp}", IDS[i], self.now);
                for o in &outs {
                    println!("         {}", show_output(o));
                }
            }
        }
        check_step(&mut self.ghost, IDS[i], &before, &self.m[i], &outs)?;
        if let Some(f) = delivered {
            check_g6(&f, &self.m[i])?;
        }
        for o in &outs {
            match o {
                Output::Send { frame } => {
                    if !self.up[i] {
                        continue;
                    }
                    let dsts: Vec<usize> = match &frame.to {
                        Some(t) => vec![idx(t)],
                        None => (0..self.m.len()).filter(|j| *j != i).collect(),
                    };
                    for d in dsts {
                        let item = (d, frame.clone());
                        let fits = !self.net.contains(&item) && self.net.len() < b.cap;
                        if self.lossless || fits {
                            self.net.push(item);
                        }
                    }
                }
                Output::Persist { claim } => self.persisted[i] = Some(claim.clone()),
                Output::Event { event } => match event {
                    Event::AskReceived { from } => {
                        let f = idx(from);
                        if !self.asks[i].contains(&f) {
                            self.asks[i].push(f);
                            self.asks[i].sort_unstable();
                        }
                    }
                    Event::Yielded { .. } => self.asks[i].clear(),
                    _ => {}
                },
            }
        }
        if !self.lossless {
            self.net.sort();
        }
        Ok(outs)
    }

    fn tick(&mut self, b: &Bounds) -> Result<(), String> {
        self.now += TICK;
        for i in 0..self.m.len() {
            self.input(i, Input::Tick, b)?;
        }
        Ok(())
    }

    /// Deliver everything in order (lossless mode).
    fn flush(&mut self, b: &Bounds) -> Result<(), String> {
        let mut guard = 0;
        while !self.net.is_empty() {
            guard += 1;
            if guard > 10_000 {
                return Err("livelock: frames never quiesce".into());
            }
            let (d, f) = self.net.remove(0);
            if self.up[d] {
                self.input(d, Input::Frame { frame: f, writer: true }, b)?;
            }
        }
        Ok(())
    }

    fn actions(&self) -> Vec<Action> {
        let mut v = Vec::new();
        for (k, (d, _)) in self.net.iter().enumerate() {
            if self.up[*d] {
                v.push(Action::Deliver(k));
                if self.dups > 0 {
                    v.push(Action::Dup(k));
                }
            }
            v.push(Action::Drop(k));
        }
        v.push(Action::Tick);
        if self.links > 0 {
            for i in 0..self.m.len() {
                v.push(Action::Link(i, !self.up[i]));
            }
        } else {
            for i in 0..self.m.len() {
                if !self.up[i] {
                    v.push(Action::Link(i, true));
                }
            }
        }
        if self.cmds > 0 {
            for i in 0..self.m.len() {
                let s = &self.m[i];
                if !s.joined() {
                    if self.kinds.contains('l') {
                        v.push(Action::Cmd(i, Cmd::Join));
                    }
                    continue;
                }
                if s.is_holder() {
                    for a in &self.asks[i] {
                        if self.kinds.contains('p') {
                            v.push(Action::Cmd(i, Cmd::Pass(*a)));
                            v.push(Action::Cmd(i, Cmd::Decline(*a)));
                        }
                    }
                    if self.kinds.contains('u') {
                        v.push(Action::Cmd(i, Cmd::Publish));
                    }
                    if self.kinds.contains('r') {
                        v.push(Action::Cmd(i, Cmd::Release));
                    }
                } else {
                    if self.kinds.contains('a') {
                        v.push(Action::Cmd(i, Cmd::Ask));
                    }
                    if self.kinds.contains('t') {
                        v.push(Action::Cmd(i, Cmd::Take));
                    }
                    if self.kinds.contains('s') {
                        v.push(Action::Cmd(i, Cmd::Submit));
                    }
                }
                if self.kinds.contains('l') {
                    v.push(Action::Cmd(i, Cmd::Leave));
                }
                if self.restarts > 0 && self.kinds.contains('x') {
                    v.push(Action::Cmd(i, Cmd::Restart));
                }
            }
        }
        v
    }

    fn apply(&mut self, a: &Action, b: &Bounds) -> Result<(), String> {
        match a {
            Action::Deliver(k) => {
                let (d, f) = self.net.remove(*k);
                self.input(d, Input::Frame { frame: f, writer: true }, b)?;
            }
            Action::Dup(k) => {
                self.dups -= 1;
                let (d, f) = self.net[*k].clone();
                self.input(d, Input::Frame { frame: f, writer: true }, b)?;
            }
            Action::Drop(k) => {
                self.net.remove(*k);
            }
            Action::Tick => self.tick(b)?,
            Action::Link(i, up) => {
                if self.links > 0 {
                    self.links -= 1;
                }
                self.up[*i] = *up;
                let input = if *up { Input::LinkUp } else { Input::LinkDown };
                self.input(*i, input, b)?;
            }
            Action::Cmd(i, c) => {
                self.cmds -= 1;
                let i = *i;
                let command = match c {
                    Cmd::Ask => Command::Ask,
                    Cmd::Take => Command::Take { state: None },
                    Cmd::Pass(to) => {
                        self.asks[i].retain(|x| x != to);
                        Command::Pass {
                            to: IDS[*to].into(),
                            snapshot: self.m[i].state().clone(),
                        }
                    }
                    Cmd::Decline(to) => {
                        self.asks[i].retain(|x| x != to);
                        Command::Decline { to: IDS[*to].into() }
                    }
                    Cmd::Publish | Cmd::Submit => {
                        self.payload += 1;
                        let p = Bytes(vec![b'0' + self.payload]);
                        let id = Bytes(vec![IDS[i].as_bytes()[0], self.payload]);
                        if *c == Cmd::Publish {
                            Command::Publish { id, payload: p }
                        } else {
                            Command::Submit { id, payload: p }
                        }
                    }
                    Cmd::Release => Command::Release,
                    Cmd::Leave => Command::Leave,
                    Cmd::Join => Command::Join { state: None },
                    Cmd::Restart => {
                        self.restarts -= 1;
                        let before = self.m[i].clone();
                        self.m[i] = Session::with_fixes(
                            IDS[i],
                            true,
                            policy(),
                            self.persisted[i].clone(),
                            self.fixes,
                        );
                        if before.accepted() > self.m[i].accepted() {
                            return Err(format!("G1: {} lost its claim on restart", IDS[i]));
                        }
                        self.asks[i].clear();
                        if !self.up[i] {
                            self.input(i, Input::LinkDown, b)?;
                        }
                        Command::Join { state: None }
                    }
                };
                self.input(i, Input::App { command }, b)?;
            }
        }
        Ok(())
    }

    /// G4: fair lossless completion converges.
    fn complete(&self, b: &Bounds) -> Result<(), String> {
        let mut w = self.clone();
        w.lossless = true;
        for i in 0..w.m.len() {
            if !w.up[i] {
                w.up[i] = true;
                w.input(i, Input::LinkUp, b)?;
            }
        }
        let p = policy();
        let horizon = (3 * p.holder_timeout_ms + 2 * p.ask_timeout_ms + 2 * p.beat_ms) / TICK;
        for _ in 0..horizon {
            w.flush(b)?;
            // Quiet, converged and no timer pending: only beats follow.
            if !w.m.iter().any(Session::pending) && check_converged(&w.m).is_ok() {
                let lapsing = w.m.iter().any(|m| {
                    m.joined() && m.holder().is_some_and(|h| !w.m[idx(h)].sends_as_holder())
                });
                if !lapsing {
                    return Ok(());
                }
            }
            w.tick(b)?;
        }
        w.flush(b)?;
        check_converged(&w.m).map_err(|e| format!("{e} (after lossless completion)"))
    }

    /// G5: with the holder cut off, another joined writer that asks holds or sees a reachable
    /// holder within askTimeoutMs plus one tick.
    fn complete_g5(&self, b: &Bounds) -> Result<(), String> {
        let Some(h) = self.m.iter().position(|s| s.is_holder()) else {
            return Ok(());
        };
        let Some(wi) = (0..self.m.len()).find(|j| *j != h && self.m[*j].joined()) else {
            return Ok(());
        };
        let mut w = self.clone();
        w.lossless = true;
        w.up[h] = false;
        w.input(h, Input::LinkDown, b)?;
        w.net.retain(|(d, f)| *d != h && f.from != IDS[h]);
        for i in 0..w.m.len() {
            if i != h && !w.up[i] {
                w.up[i] = true;
                w.input(i, Input::LinkUp, b)?;
            }
        }
        w.flush(b)?;
        w.input(wi, Input::App { command: Command::Ask }, b)?;
        let deadline = policy().ask_timeout_ms / TICK + 1;
        for _ in 0..deadline {
            w.flush(b)?;
            w.tick(b)?;
        }
        w.flush(b)?;
        let s = &w.m[wi];
        let ok = match s.holder() {
            Some(x) if idx(x) != h => w.m[idx(x)].sends_as_holder(),
            _ => false,
        };
        if !ok {
            return Err(format!(
                "G5: {} asked with holder {} cut off and after {deadline} ticks sees holder {:?}",
                IDS[wi],
                IDS[h],
                s.holder()
            ));
        }
        Ok(())
    }
}

struct Report {
    states: usize,
    transitions: usize,
    violation: Option<(String, Vec<Action>)>,
    truncated: bool,
}

fn explore(b: Bounds, fixes: Fixes) -> Report {
    let init = World::new(&b, fixes);
    let mut parent: HashMap<u128, (u128, Action)> = HashMap::new();
    let mut seen: HashSet<u128> = HashSet::new();
    let root = init.key();
    seen.insert(root);
    let mut queue: VecDeque<(World, u32)> = VecDeque::from([(init.clone(), 0)]);
    let mut levels: Vec<usize> = vec![1];
    let mut transitions = 0;
    let mut max_term = (0u64, 0u128);
    let mut max_now = 0;
    let trace_to = |parent: &HashMap<u128, (u128, Action)>, mut k: u128| {
        let mut path = Vec::new();
        while let Some((p, a)) = parent.get(&k) {
            path.push(a.clone());
            k = *p;
        }
        path.reverse();
        path
    };
    if b.completions {
        if let Err(e) = init.complete(&b).and_then(|_| init.complete_g5(&b)) {
            return Report {
                states: 1,
                transitions: 0,
                violation: Some((e, Vec::new())),
                truncated: false,
            };
        }
    }
    while let Some((w, depth)) = queue.pop_front() {
        if depth >= b.depth {
            continue;
        }
        let wk = w.key();
        for a in w.actions() {
            transitions += 1;
            let mut n = w.clone();
            let r = n.apply(&a, &b);
            let nk = n.key();
            if let Err(e) = r {
                let mut path = trace_to(&parent, wk);
                path.push(a);
                return Report {
                    states: seen.len(),
                    transitions,
                    violation: Some((e, path)),
                    truncated: false,
                };
            }
            if !seen.insert(nk) {
                continue;
            }
            parent.insert(nk, (wk, a.clone()));
            if b.completions {
                if let Err(e) = n.complete(&b).and_then(|_| n.complete_g5(&b)) {
                    return Report {
                        states: seen.len(),
                        transitions,
                        violation: Some((e, trace_to(&parent, nk))),
                        truncated: false,
                    };
                }
            }
            let term = n.m.iter().filter_map(|m| m.accepted().map(|c| c.term)).max().unwrap_or(0);
            if term > max_term.0 {
                max_term = (term, nk);
            }
            max_now = max_now.max(n.now);
            if levels.len() <= depth as usize + 1 {
                levels.push(0);
            }
            levels[depth as usize + 1] += 1;
            if n.now <= b.time {
                queue.push_back((n, depth + 1));
            }
            if seen.len() >= b.max_states {
                println!("max term {} max now {max_now}; new states per depth: {levels:?}", max_term.0);
                if std::env::var("COLOPHON_EXPLORE_VERBOSE").is_ok() {
                    println!("{}", print_trace(b, fixes, &trace_to(&parent, max_term.1)));
                }
                return Report {
                    states: seen.len(),
                    transitions,
                    violation: None,
                    truncated: true,
                };
            }
        }
    }
    println!("new states per depth: {levels:?}; max term {}", max_term.0);
    Report {
        states: seen.len(),
        transitions,
        violation: None,
        truncated: false,
    }
}

/// Replay a trace and print every step's outputs.
fn print_trace(b: Bounds, fixes: Fixes, path: &[Action]) -> String {
    let mut w = World::new(&b, fixes);
    let mut s = String::new();
    s.push_str(&format!(
        "initial: {}\n",
        w.m.iter()
            .map(|m| format!("{}={:?}", m.me(), m.accepted().map(show_claim)))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    for a in path {
        let label = match a {
            Action::Deliver(k) | Action::Dup(k) | Action::Drop(k) => {
                let (d, f) = &w.net[*k];
                format!("{a:?} [{}->{} {}]", f.from, IDS[*d], show_body(&f.body))
            }
            _ => format!("{a:?}"),
        };
        s.push_str(&format!("t={} {label}\n", w.now));
        let before: Vec<Session> = w.m.clone();
        let r = w.apply(a, &b);
        for (i, m) in w.m.iter().enumerate() {
            if *m != before[i] {
                s.push_str(&format!(
                    "    {} accepted={:?} holder={} seq={} state={:?} synced={}\n",
                    IDS[i],
                    m.accepted().map(show_claim),
                    m.is_holder(),
                    m.seq(),
                    String::from_utf8_lossy(&m.state().0),
                    m.synced()
                ));
            }
        }
        if let Err(e) = r {
            s.push_str(&format!("    VIOLATION {e}\n"));
        }
    }
    if std::env::var("COLOPHON_EXPLORE_VERBOSE").is_ok() {
        println!("{s}--- completions of the final state ---");
        VERBOSE.store(true, std::sync::atomic::Ordering::Relaxed);
        println!("G4 completion: {:?}", w.complete(&b));
        println!("G5 completion: {:?}", w.complete_g5(&b));
        VERBOSE.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    s
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Default bounds finish in seconds; `COLOPHON_EXPLORE=big` widens them, and
/// `COLOPHON_EXPLORE_{CMDS,DUPS,LINKS,CAP,STATES}` override single bounds. Time is unbounded
/// (states are keyed with relative times); `time` only caps the clock as a safety net.
fn bounds(members: usize, kinds: &'static str, small: (u8, u8, u8, usize), depth: u32) -> Bounds {
    let big = std::env::var("COLOPHON_EXPLORE").is_ok_and(|v| v == "big");
    let (cmds, dups, links, cap) = if big {
        (small.0 + 1, small.1.max(1), small.2 + 1, small.3 + 1)
    } else {
        small
    };
    let depth = if big { depth + 4 } else { depth };
    Bounds {
        members,
        time: 200 * TICK,
        cmds: env_u64("COLOPHON_EXPLORE_CMDS", u64::from(cmds)) as u8,
        dups: env_u64("COLOPHON_EXPLORE_DUPS", u64::from(dups)) as u8,
        links: env_u64("COLOPHON_EXPLORE_LINKS", u64::from(links)) as u8,
        restarts: 1,
        cap: env_u64("COLOPHON_EXPLORE_CAP", cap as u64) as usize,
        max_states: env_u64("COLOPHON_EXPLORE_STATES", if big { 100_000_000 } else { 3_000_000 })
            as usize,
        depth: env_u64("COLOPHON_EXPLORE_DEPTH", u64::from(depth)) as u32,
        completions: std::env::var("COLOPHON_EXPLORE_NO_COMPLETIONS").is_err(),
        kinds,
    }
}

fn run(b: Bounds, fixes: Fixes) -> Report {
    let t = std::time::Instant::now();
    let r = explore(b, fixes);
    println!(
        "explore members={} fixes={fixes:?} bounds={b:?}: {} states, {} transitions, {:?}, truncated={}",
        b.members,
        r.states,
        r.transitions,
        t.elapsed(),
        r.truncated
    );
    if let Some((e, path)) = &r.violation {
        println!("violation: {e}\n{}", print_trace(b, fixes, path));
    }
    r
}

/// `small` is `(commands, duplications, link changes, in-flight cap)`.
/// `COLOPHON_EXPLORE_WITHOUT=F5,F6` explores with those fixes off (for findings work).
fn fixes_under_test() -> Fixes {
    let mut f = Fixes::ALL;
    let off = std::env::var("COLOPHON_EXPLORE_WITHOUT").unwrap_or_default();
    for name in off.split(',') {
        match name.trim() {
            "F1" => f.rank1_from_holder = false,
            "F2" => f.seen_unsynced = false,
            "F5" => f.bye_resend = false,
            "F6" => f.answer_lesser = false,
            "F7" => f.renew_wider = false,
            "F8" => f.liveness_holder_frames = false,
            "F9" => f.ask_resend = false,
            "F10" => f.renew_needs_contact = false,
            _ => {}
        }
    }
    f
}

fn check(members: usize, kinds: &'static str, small: (u8, u8, u8, usize), depth: u32) {
    let r = run(bounds(members, kinds, small, depth), fixes_under_test());
    assert!(r.violation.is_none(), "{:?}", r.violation.map(|v| v.0));
    assert!(!r.truncated, "state bound reached before exhausting the space");
}

/// Ask, take, pass, decline and publish between two members.
#[test]
fn two_members_handoff() {
    check(2, "atpu", (3, 1, 2, 3), 8);
}

/// Release, leave, join, restart, submit and publish between two members.
#[test]
fn two_members_membership() {
    check(2, "rlxsu", (3, 0, 1, 3), 8);
}

/// Ask, take and pass among three members.
#[test]
fn three_members_handoff() {
    check(3, "atp", (2, 0, 1, 3), 8);
}

/// Release, leave, join and restart among three members.
#[test]
fn three_members_membership() {
    check(3, "rlxu", (2, 0, 1, 2), 8);
}

type Profile = (usize, &'static str, (u8, u8, u8, usize));
const PROFILES: [Profile; 4] = [
    (2, "atpu", (3, 1, 2, 3)),
    (2, "rlxsu", (3, 0, 1, 3)),
    (3, "atp", (2, 0, 1, 3)),
    (3, "rlxu", (2, 0, 1, 2)),
];

/// The draft as written fails, and so does the reference reading without F1 or without F2:
/// the explorer finds a counterexample (printed with `--nocapture`; see the findings
/// document). The other fixes are exercised by the simulator's `fix_ablation`.
#[test]
fn draft_counterexamples() {
    let all = Fixes::ALL;
    let cases: [(&str, Fixes); 3] = [
        ("literal draft", Fixes::LITERAL),
        ("without F1 rank1_from_holder", Fixes { rank1_from_holder: false, ..all }),
        ("without F2 seen_unsynced", Fixes { seen_unsynced: false, ..all }),
    ];
    for (name, fixes) in cases {
        let found = PROFILES.iter().any(|&(members, kinds, small)| {
            println!("== {name}, {members} members, {kinds}");
            run(bounds(members, kinds, small, 8), fixes).violation.is_some()
        });
        assert!(found, "no counterexample for the {name}");
    }
}

/// F12 (adopted in revision 2, §S5): two holders partitioned from each other both pass to the
/// same asker. With `pass_conflict_renew` off, members end on the same claim with different
/// states (G3/G4); with it on, the new holder renews and one state prevails.
fn two_passes_to_one(fixes: Fixes, lose_a_pass_to_x: bool) -> Vec<Session> {
    let ids = ["a", "b", "x"];
    let mut m: Vec<Session> = ids
        .iter()
        .map(|i| Session::with_fixes(i, true, Policy::default(), None, fixes))
        .collect();
    let mut net: Vec<(usize, Frame)> = Vec::new();
    // Route one member's outputs into the network, dropping what `cut` rejects.
    let route = |net: &mut Vec<(usize, Frame)>, from: usize, outs: Vec<Output>, cut: &dyn Fn(usize, usize) -> bool| {
        for o in outs {
            if let Output::Send { frame } = o {
                let dsts: Vec<usize> = match &frame.to {
                    Some(t) => vec![ids.iter().position(|x| x == t).unwrap()],
                    None => (0..3).filter(|j| *j != from).collect(),
                };
                for d in dsts {
                    if !cut(from, d) {
                        net.push((d, frame.clone()));
                    }
                }
            }
        }
    };
    let flush = |m: &mut Vec<Session>, net: &mut Vec<(usize, Frame)>, t: u64, cut: &dyn Fn(usize, usize) -> bool| {
        while !net.is_empty() {
            let (d, f) = net.remove(0);
            let outs = m[d].handle(Input::Frame { frame: f, writer: true }, t);
            route(net, d, outs, cut);
        }
    };
    // a and b cannot reach each other.
    let ab = |x: usize, y: usize| (x == 0 && y == 1) || (x == 1 && y == 0);
    for (i, s) in m.iter_mut().enumerate() {
        let outs = s.handle(Input::App { command: Command::Join { state: None } }, 0);
        route(&mut net, i, outs, &ab);
    }
    flush(&mut m, &mut net, 0, &ab);
    // a takes 1.0.a; only x hears it.
    let outs = m[0].handle(Input::App { command: Command::Take { state: Some(Bytes(b"A".to_vec())) } }, 10);
    route(&mut net, 0, outs, &ab);
    flush(&mut m, &mut net, 10, &ab);
    // x asks a; the ask reaches a.
    let outs = m[2].handle(Input::App { command: Command::Ask }, 20);
    route(&mut net, 2, outs, &ab);
    flush(&mut m, &mut net, 20, &ab);
    // b takes 1.0.b (greater); x accepts it and re-asks b.
    let outs = m[1].handle(Input::App { command: Command::Take { state: Some(Bytes(b"B".to_vec())) } }, 30);
    route(&mut net, 1, outs, &ab);
    flush(&mut m, &mut net, 30, &ab);
    assert_eq!(m[2].accepted(), Some(&Claim::new(1, 0, "b")));
    // Both holders pass to x: b's pass first, then a's (a still holds 1.0.a, and passes too).
    let outs = m[1].handle(Input::App { command: Command::Pass { to: "x".into(), snapshot: Bytes(b"B".to_vec()) } }, 40);
    route(&mut net, 1, outs, &ab);
    let outs = m[0].handle(Input::App { command: Command::Pass { to: "x".into(), snapshot: Bytes(b"A".to_vec()) } }, 40);
    let cut_ax = |x: usize, y: usize| ab(x, y) || (lose_a_pass_to_x && x == 0 && y == 2);
    route(&mut net, 0, outs, &cut_ax);
    flush(&mut m, &mut net, 50, &ab);
    // Heal and let beats and answers settle.
    let none = |_: usize, _: usize| false;
    for t in [6_000u64, 12_000, 18_000] {
        for (i, s) in m.iter_mut().enumerate() {
            let outs = s.handle(Input::Tick, t);
            route(&mut net, i, outs, &none);
        }
        flush(&mut m, &mut net, t + 10, &none);
    }
    m
}

#[test]
fn f12_two_passes_to_one_asker() {
    let off = two_passes_to_one(Fixes { pass_conflict_renew: false, ..Fixes::ALL }, false);
    let diverged = check_converged(&off).is_err();
    println!("F12 off: {:?}", off.iter().map(|s| (s.me().to_owned(), s.accepted().map(show_claim), String::from_utf8_lossy(&s.state().0).into_owned())).collect::<Vec<_>>());
    assert!(diverged, "without F12 the two passes should leave different states under one claim");
    let on = two_passes_to_one(Fixes::ALL, false);
    println!("F12 on: {:?}", on.iter().map(|s| (s.me().to_owned(), s.accepted().map(show_claim), String::from_utf8_lossy(&s.state().0).into_owned())).collect::<Vec<_>>());
    check_converged(&on).unwrap();
    // F21: if a's pass to x is lost, x never meets the second pass and nothing tells a that
    // its state under 2.1.x differs: revision 2's F12 rule alone does not cover it. The
    // passer's one-time echo of its pass (F21) does.
    let lost = two_passes_to_one(Fixes { pass_echo: false, ..Fixes::ALL }, true);
    println!("F12 on, F21 off, a's pass to x lost: {:?}", lost.iter().map(|s| (s.me().to_owned(), s.accepted().map(show_claim), String::from_utf8_lossy(&s.state().0).into_owned())).collect::<Vec<_>>());
    assert!(check_converged(&lost).is_err(), "F21 scenario should diverge without the echo");
    let echoed = two_passes_to_one(Fixes::ALL, true);
    println!("F12 and F21 on, a's pass to x lost: {:?}", echoed.iter().map(|s| (s.me().to_owned(), s.accepted().map(show_claim), String::from_utf8_lossy(&s.state().0).into_owned())).collect::<Vec<_>>());
    check_converged(&echoed).unwrap();
}
