//! Exhaustive bounded exploration of the 0.6 session machine (revision 4) for 2 and 3 members.
//!
//! **Network.** Reachability is per directed edge (`reach[i][j]`), fixed for a profile: the
//! full mesh, or the chain a↔b↔c with a↮c held indefinitely. In-flight `(recipient, frame)`
//! pairs form a set (identical copies collapse; at most `cap` in flight, extra sends lost).
//!
//! **Steps.** Deliver any in-flight frame, deliver and keep a copy (duplication, budgeted),
//! drop it, advance every clock one tick, take a member's own link down or up (budgeted), an
//! application command (budgeted: ask, take, pass to a member that asked, decline, publish,
//! submit, release, leave, join, restart from what was persisted), or, in the crash profile,
//! any single-member step cut short after each prefix of its outputs followed by a restart
//! from what was persisted (G12).
//!
//! **Checked on every transition.** G1, G2, G3 (including "no holder frame under a claim it
//! passed away"), G6, G11 for late passes, and G12 (after a crash, the restarted member's
//! claim is not below any claim it revealed, and it does not act under a released claim).
//!
//! **Checked from every reachable state, by completions that keep the topology.** Three fair
//! lossless schedules (FIFO, LIFO, rotating), each running well past `holderTimeoutMs`: G4 per
//! component of the topology, G10 (no claim changes in the second half), G11 (every displaced
//! holder's state reported to the member that took over, when the two can talk). G5 strictly:
//! with the holder cut off and nobody else pending, the asking writer itself holds within
//! `askTimeoutMs` plus a tick.
//!
//! Bounds: `COLOPHON_EXPLORE=big` explores deeper; `COLOPHON_EXPLORE_{CMDS,DUPS,LINKS,CAP,
//! STATES,DEPTH}` override single bounds; `COLOPHON_EXPLORE_WITHOUT=F5,R1,…` turns fixes off.
#![allow(clippy::unwrap_used)]
mod v06_session_support;
use colophon_core::v06::session::*;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use v06_session_support::*;

const IDS: [&str; 3] = ["a", "b", "c"];
thread_local! {
    /// Deliveries within one lossless flush before it is called a livelock.
    static GUARD: usize = env_u64("COLOPHON_EXPLORE_GUARD", 10_000) as usize;
}
static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// One explorer tick in ms: the §S8 gap-hello limit (1 s) is one tick.
const TICK: u64 = 1_000;
/// The longest policy duration (`policy()`): every comparison is `age >= d` or `age < d`
/// with `d` at most this, so ages beyond it are indistinguishable.
const HORIZON: u64 = 3 * TICK;

fn policy() -> Policy {
    Policy {
        beat_ms: 2 * TICK,
        holder_timeout_ms: 3 * TICK,
        ask_timeout_ms: TICK,
        presence_timeout_ms: 3 * TICK,
        retain_ms: 60 * TICK,
        tail: 2,
        max_payload: 64,
        fold: Fold::Append,
        take: TakeRule::Free,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topo {
    Mesh,
    /// a↔b↔c, a↮c, without bridging (revisions 3–6).
    Chain,
    /// a↔b↔c, a↮c, with §S9 bridging at b (revision 7): one group, so every frame b
    /// accepts also reaches the far end. Modelled as the transitive closure; the delivery
    /// order is still arbitrary.
    BridgedChain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// Everyone joined, `a` took, all frames delivered.
    Taken,
    /// F12/F21: `a` holds 1.0.a and `b` holds 1.0.b, unheard by each other; `c` asked `a`,
    /// then accepted 1.0.b and asked `b`. Both holders have `c`'s ask pending.
    TwoHolders,
    /// R1: on the chain, `a` took 1.0.a and `c` took 1.0.c; `b` hears both.
    ChainTwoHolders,
}

#[derive(Clone, Copy, Debug)]
struct Bounds {
    members: usize,
    time: u64,
    cmds: u8,
    dups: u8,
    links: u8,
    restarts: u8,
    crashes: u8,
    cuts: u8,
    cap: usize,
    max_states: usize,
    depth: u32,
    completions: bool,
    /// Allowed commands: a ask, t take, p pass/decline, u publish, s submit, r release,
    /// l leave/join, x restart.
    kinds: &'static str,
    start: Start,
    topo: Topo,
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
    /// Split member `i` from its group (true) or merge it back (false); its own link
    /// stays up (groups split and merge, §S0).
    Cut(usize, bool),
    /// The step, cut after this many of its outputs, then a restart (G12).
    Crash(Box<Action>, usize),
}

#[derive(Clone, Copy, Debug)]
enum Schedule {
    Fifo,
    Lifo,
    Rotate,
}

#[derive(Clone)]
struct World {
    now: u64,
    m: Vec<Session>,
    up: Vec<bool>,
    reach: Vec<Vec<bool>>,
    /// In flight: recipient, frame, and the forwarder when it is forwarded evidence.
    net: Vec<(usize, Frame, Option<usize>)>,
    /// `heard_direct[i][j]`: member i has received a frame directly from j since it
    /// (re)started, so it has a freshness window for j's key (§S3 evidence without a window).
    heard_direct: Vec<Vec<bool>>,
    cmds: u8,
    dups: u8,
    links: u8,
    restarts: u8,
    crashes: u8,
    cuts: u8,
    cut: Vec<bool>,
    topo: Topo,
    asks: Vec<Vec<usize>>,
    persisted: Vec<Option<Persisted>>,
    ghost: Ghost,
    payload: u8,
    lossless: bool,
    fixes: Fixes,
    kinds: &'static str,
    /// Claim changes (Persist outputs) seen, for G10.
    persists: u64,
    rotate: usize,
    /// The in-flight cap (copied from the bounds).
    cap: usize,
    /// Members that emitted `BecameHolder` (G5 bookkeeping).
    became: Vec<bool>,
    /// Forwarded evidence frames delivered to each member (G5 bound).
    evidence_seen: Vec<u64>,
}

fn idx(id: &str) -> usize {
    IDS.iter().position(|x| *x == id).unwrap()
}
fn reach_for(topo: Topo, n: usize) -> Vec<Vec<bool>> {
    (0..n)
        .map(|i| {
            (0..n)
                .map(|j| i != j && !(topo == Topo::Chain && ((i == 0 && j == 2) || (i == 2 && j == 0))))
                .collect()
        })
        .collect()
}
fn id_of(i: usize, k: u8) -> Id {
    Id::from_label(&format!("{}-{k}", IDS[i]))
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
            reach: reach_for(b.topo, b.members),
            net: Vec::new(),
            heard_direct: vec![vec![false; b.members]; b.members],
            cmds: b.cmds,
            dups: b.dups,
            links: b.links,
            restarts: b.restarts,
            crashes: b.crashes,
            cuts: b.cuts,
            cut: vec![false; b.members],
            topo: b.topo,
            asks: vec![Vec::new(); b.members],
            persisted: vec![None; b.members],
            ghost: Ghost::default(),
            payload: 0,
            lossless: true,
            fixes,
            kinds: b.kinds,
            persists: 0,
            rotate: 0,
            cap: b.cap,
            became: vec![false; b.members],
            evidence_seen: vec![0; b.members],
        };
        for i in 0..b.members {
            w.input(i, Input::App { command: Command::Join { state: None } }, b, None).unwrap();
        }
        w.flush(b, Schedule::Fifo).unwrap();
        let st = |x: &[u8]| Some(Fold::framed(&[Bytes(x.to_vec())]));
        match b.start {
            Start::Taken => {
                w.input(0, Input::App { command: Command::Take { state: None } }, b, None).unwrap();
                w.flush(b, Schedule::Fifo).unwrap();
            }
            Start::TwoHolders => {
                // Until b takes, b hears nobody (not even evidence relayed by c); a and b never
                // hear each other during the start.
                for k in 0..3 {
                    w.reach[k][1] = false;
                    w.reach[1][k] = false;
                }
                w.input(0, Input::App { command: Command::Take { state: st(b"A") } }, b, None).unwrap();
                w.flush(b, Schedule::Fifo).unwrap();
                w.input(2, Input::App { command: Command::Ask }, b, None).unwrap();
                w.flush(b, Schedule::Fifo).unwrap();
                // b now reaches c and back, but c's evidence of b must not reach a yet.
                w.reach[1][2] = true;
                w.reach[2][1] = true;
                w.reach[2][0] = false;
                w.input(1, Input::App { command: Command::Take { state: st(b"B") } }, b, None).unwrap();
                w.flush(b, Schedule::Fifo).unwrap();
                w.reach = reach_for(b.topo, b.members);
                assert_eq!(w.m[2].accepted(), Some(&Claim::new(1, 0, "b")));
                assert_eq!((w.asks[0].clone(), w.asks[1].clone()), (vec![2], vec![2]));
            }
            Start::ChainTwoHolders => {
                assert!(matches!(b.topo, Topo::Chain | Topo::BridgedChain));
                w.input(0, Input::App { command: Command::Take { state: st(b"A") } }, b, None).unwrap();
                w.input(2, Input::App { command: Command::Take { state: st(b"C") } }, b, None).unwrap();
                w.flush(b, Schedule::Fifo).unwrap();
                assert_eq!(w.m[2].accepted(), Some(&Claim::new(1, 0, "c")));
            }
        }
        w.lossless = false;
        w.persists = 0;
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
            self.heard_direct.hash(&mut h);
            (self.cmds, self.dups, self.links, self.restarts, self.crashes, self.cuts).hash(&mut h);
            self.cut.hash(&mut h);
            self.asks.hash(&mut h);
            self.persisted.hash(&mut h);
            self.ghost.hash(&mut h);
            self.payload.hash(&mut h);
            h.finish()
        };
        (u128::from(one(0)) << 64) | u128::from(one(1))
    }

    fn route(&mut self, src: usize, dst: usize, frame: Frame, b: &Bounds, via: Option<usize>) {
        if !self.up[src] || !self.reach[src][dst] {
            return;
        }
        let item = (dst, frame, via);
        let fits = !self.net.contains(&item) && self.net.len() < b.cap;
        if self.lossless || fits {
            self.net.push(item);
        }
    }

    /// Run one input on member `i`. With `crash = Some(k)` only the first `k` outputs take
    /// effect, then the member restarts from what it persisted (G12). Returns the number of
    /// outputs, or `None` when `k` is not below it (no such crash point).
    fn input(&mut self, i: usize, input: Input, b: &Bounds, crash: Option<usize>) -> Result<Option<usize>, String> {
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
            if !outs.is_empty() {
                let inp = if inp.starts_with("Frame") { "frame".to_owned() } else { inp };
                println!("      [{} t={}] {inp}", IDS[i], self.now);
                for o in &outs {
                    println!("         {}", show_output(o));
                }
            }
        }
        let total = outs.len();
        let keep = match crash {
            Some(k) if k >= total => {
                return Ok(None);
            }
            Some(k) => k,
            None => total,
        };
        let outs = &outs[..keep];
        check_step_input(&mut self.ghost, IDS[i], &before, &self.m[i], outs, delivered.as_ref())?;
        if let (Some(f), None) = (&delivered, crash) {
            check_g6(f, &self.m[i])?;
        }
        for o in outs {
            match o {
                Output::Send { frame } => {
                    let dsts: Vec<usize> = match &frame.to {
                        Some(t) => vec![idx(t)],
                        None => (0..self.m.len()).filter(|j| *j != i).collect(),
                    };
                    for d in dsts {
                        self.route(i, d, frame.clone(), b, None);
                    }
                }
                Output::Forward { to, frame } => self.route(i, idx(to), frame.clone(), b, Some(i)),
                Output::Persist { claim, released } => {
                    self.persists += 1;
                    self.persisted[i] = Some(Persisted {
                        claim: claim.clone(),
                        released: *released,
                    });
                }
                Output::Event { event } => match event {
                    Event::AskReceived { from } => {
                        let f = idx(from);
                        if !self.asks[i].contains(&f) {
                            self.asks[i].push(f);
                            self.asks[i].sort_unstable();
                        }
                    }
                    Event::Yielded { .. } => self.asks[i].clear(),
                    Event::BecameHolder { .. } => self.became[i] = true,
                    _ => {}
                },
            }
        }
        if !self.lossless {
            self.net.sort();
        }
        if crash.is_some() {
            self.restart(i, b)?;
        }
        Ok(Some(total))
    }

    fn restart(&mut self, i: usize, b: &Bounds) -> Result<(), String> {
        self.m[i] = Session::with_fixes(IDS[i], true, policy(), self.persisted[i].clone(), self.fixes);
        self.heard_direct[i] = vec![false; self.m.len()];
        self.ghost.check_restart(&self.m[i])?;
        // A member that restarts lost what it held: it cannot report it (G11 is about
        // members that keep running).
        self.ghost.owed.retain(|(_, d, _)| d != IDS[i]);
        self.asks[i].clear();
        if !self.up[i] {
            self.input(i, Input::LinkDown, b, None)?;
        }
        self.input(i, Input::App { command: Command::Join { state: None } }, b, None)?;
        Ok(())
    }

    fn tick(&mut self, b: &Bounds) -> Result<(), String> {
        self.now += TICK;
        for i in 0..self.m.len() {
            self.input(i, Input::Tick, b, None)?;
        }
        Ok(())
    }

    /// The input for delivering `frame` to `d`; forwarded evidence is windowed only if `d`
    /// has heard the origin directly since it started.
    fn deliver_input(&mut self, d: usize, frame: Frame, via: Option<usize>) -> Input {
        let origin = idx(&frame.from);
        let forwarded = via.map(|v| Forwarded {
            via: IDS[v].to_owned(),
            windowed: self.heard_direct[d][origin],
        });
        if via.is_none() {
            self.heard_direct[d][origin] = true;
        } else {
            self.evidence_seen[d] += 1;
        }
        Input::Frame {
            frame,
            writer: true,
            key: None,
            n: None,
            forwarded,
        }
    }

    /// Deliver everything (lossless mode) in the given fair order.
    fn flush(&mut self, b: &Bounds, s: Schedule) -> Result<(), String> {
        let mut guard = 0;
        let mut last: VecDeque<String> = VecDeque::new();
        while !self.net.is_empty() {
            guard += 1;
            if guard > GUARD.with(|g| *g) {
                return Err(format!(
                    "livelock: frames never quiesce; last deliveries: {}",
                    last.iter().cloned().collect::<Vec<_>>().join(" | ")
                ));
            }

            let k = match s {
                Schedule::Fifo => 0,
                Schedule::Lifo => self.net.len() - 1,
                Schedule::Rotate => {
                    self.rotate += 1;
                    self.rotate % self.net.len()
                }
            };
            let (d, f, v) = self.net.remove(k);
            if guard + 20 > GUARD.with(|g| *g) {
                last.push_back(format!("{}->{}{} {}", f.from, IDS[d], v.map_or(String::new(), |v| format!(" via {}", IDS[v])), show_body(&f.body)));
            }
            if self.up[d] {
                let input = self.deliver_input(d, f, v);
                self.input(d, input, b, None)?;
            }
        }
        Ok(())
    }

    /// The bounds `input` needs for routing during a trial step (only `cap` matters).
    fn bounds_for_trial(&self) -> Bounds {
        let mut b = bounds(self.m.len(), "", (0, 0, 0, self.cap), 0);
        b.topo = self.topo;
        b
    }

    fn single_member(&self, a: &Action) -> bool {
        match a {
            Action::Deliver(_) | Action::Dup(_) | Action::Link(..) => true,
            Action::Cmd(_, c) => *c != Cmd::Restart,
            _ => false,
        }
    }

    fn actions(&self) -> Vec<Action> {
        let mut v = Vec::new();
        for (k, (d, _, _)) in self.net.iter().enumerate() {
            if self.up[*d] {
                v.push(Action::Deliver(k));
                if self.dups > 0 {
                    v.push(Action::Dup(k));
                }
            }
            v.push(Action::Drop(k));
        }
        v.push(Action::Tick);
        for i in 0..self.m.len() {
            if self.links > 0 || !self.up[i] {
                v.push(Action::Link(i, !self.up[i]));
            }
        }
        if self.cmds > 0 {
            for i in 0..self.m.len() {
                let s = &self.m[i];
                let k = self.kinds;
                if !s.joined() {
                    if k.contains('l') {
                        v.push(Action::Cmd(i, Cmd::Join));
                    }
                    continue;
                }
                if s.is_holder() {
                    if k.contains('p') {
                        for a in &self.asks[i] {
                            v.push(Action::Cmd(i, Cmd::Pass(*a)));
                            v.push(Action::Cmd(i, Cmd::Decline(*a)));
                        }
                    }
                    if k.contains('u') {
                        v.push(Action::Cmd(i, Cmd::Publish));
                    }
                    if k.contains('r') {
                        v.push(Action::Cmd(i, Cmd::Release));
                    }
                } else {
                    if k.contains('a') {
                        v.push(Action::Cmd(i, Cmd::Ask));
                    }
                    if k.contains('t') {
                        v.push(Action::Cmd(i, Cmd::Take));
                    }
                    if k.contains('s') {
                        v.push(Action::Cmd(i, Cmd::Submit));
                    }
                }
                if k.contains('l') {
                    v.push(Action::Cmd(i, Cmd::Leave));
                }
                if self.restarts > 0 && k.contains('x') {
                    v.push(Action::Cmd(i, Cmd::Restart));
                }
            }
        }
        for i in 0..self.m.len() {
            if self.cuts > 0 || self.cut[i] {
                v.push(Action::Cut(i, !self.cut[i]));
            }
        }
        if self.crashes > 0 {
            // G12: every prefix of the step's outputs.
            let base: Vec<Action> = v.iter().filter(|a| self.single_member(a)).cloned().collect();
            for a in base {
                let mut t = self.clone();
                let total = t
                    .prepare(&a)
                    .and_then(|(i, input)| t.input(i, input, &self.bounds_for_trial(), None).ok().flatten())
                    .unwrap_or(0);
                for k in 0..total {
                    v.push(Action::Crash(Box::new(a.clone()), k));
                }
            }
        }
        v
    }

    /// The member and input of a single-member action (consuming budgets).
    fn prepare(&mut self, a: &Action) -> Option<(usize, Input)> {
        Some(match a {
            Action::Deliver(k) => {
                let (d, f, v) = self.net.remove(*k);
                (d, self.deliver_input(d, f, v))
            }
            Action::Dup(k) => {
                self.dups -= 1;
                let (d, f, v) = self.net[*k].clone();
                (d, self.deliver_input(d, f, v))
            }
            Action::Link(i, up) => {
                if self.links > 0 {
                    self.links -= 1;
                }
                self.up[*i] = *up;
                (*i, if *up { Input::LinkUp } else { Input::LinkDown })
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
                        let id = id_of(i, self.payload);
                        if *c == Cmd::Publish {
                            Command::Publish { id, payload: p }
                        } else {
                            Command::Submit { id, payload: p }
                        }
                    }
                    Cmd::Release => Command::Release,
                    Cmd::Leave => Command::Leave,
                    Cmd::Join => Command::Join { state: None },
                    Cmd::Restart => return None,
                };
                (i, Input::App { command })
            }
            _ => return None,
        })
    }

    /// Apply an action; `Ok(false)` means it does not exist (a crash point past the end).
    fn apply(&mut self, a: &Action, b: &Bounds) -> Result<bool, String> {
        match a {
            Action::Drop(k) => {
                self.net.remove(*k);
            }
            Action::Tick => self.tick(b)?,
            Action::Cut(i, c) => {
                if *c {
                    self.cuts -= 1;
                }
                self.cut[*i] = *c;
                self.reach = reach_for(self.topo, self.m.len());
                for j in 0..self.m.len() {
                    if self.cut[j] {
                        for k in 0..self.m.len() {
                            self.reach[j][k] = false;
                            self.reach[k][j] = false;
                        }
                    }
                }
            }
            Action::Cmd(i, Cmd::Restart) => {
                self.cmds -= 1;
                self.restarts -= 1;
                self.restart(*i, b)?;
            }
            Action::Crash(inner, k) => {
                self.crashes -= 1;
                let Some((i, input)) = self.prepare(inner) else {
                    return Ok(false);
                };
                if self.input(i, input, b, Some(*k))?.is_none() {
                    return Ok(false);
                }
            }
            other => {
                let Some((i, input)) = self.prepare(other) else {
                    return Ok(false);
                };
                self.input(i, input, b, None)?;
            }
        }
        Ok(true)
    }

    fn component(&self) -> Vec<usize> {
        let n = self.m.len();
        let mut comp: Vec<usize> = (0..n).collect();
        for _ in 0..n {
            for i in 0..n {
                for j in 0..n {
                    if i != j && self.reach[i][j] && self.reach[j][i] && comp[j] < comp[i] {
                        comp[i] = comp[j];
                    }
                }
            }
        }
        comp
    }

    /// G4, G10, G11 under one fair lossless schedule that keeps the topology.
    fn complete_with(&self, b: &Bounds, s: Schedule) -> Result<(), String> {
        let mut w = self.clone();
        w.lossless = true;
        for i in 0..w.m.len() {
            if !w.up[i] {
                w.up[i] = true;
                w.input(i, Input::LinkUp, b, None)?;
            }
        }
        let p = policy();
        let warm = (3 * p.holder_timeout_ms + 2 * p.ask_timeout_ms + 2 * p.beat_ms) / TICK;
        let observe = (3 * p.holder_timeout_ms + p.beat_ms) / TICK;
        let mesh = matches!(b.topo, Topo::Mesh | Topo::BridgedChain) && !w.cut.iter().any(|c| *c);
        for t in 0..warm + observe {
            if t == warm {
                w.persists = 0;
            }
            w.flush(b, s)?;
            if mesh
                && t < warm
                && w.ghost.owed.is_empty()
                && !w.m.iter().any(Session::pending)
                && check_converged_topo(&w.m, &w.reach).is_ok()
            {
                let lapsing = w.m.iter().any(|m| {
                    m.joined() && m.holder().is_some_and(|h| !w.m[idx(h)].sends_as_holder())
                });
                if !lapsing {
                    // Quiet, converged, no timer pending: only beats follow (G10 holds).
                    w.persists = 0;
                    break;
                }
            }
            w.tick(b)?;
        }
        w.flush(b, s)?;
        let tag = format!("(after lossless completion, {s:?})");
        if w.persists > 0 {
            return Err(format!(
                "G10: claims still change after {warm} quiet ticks: {} persists in the last {observe} {tag}",
                w.persists
            ));
        }
        check_converged_topo(&w.m, &w.reach).map_err(|e| format!("{e} {tag}"))?;
        if w.fixes.state_reports {
            // G11 (revision 5), strictly: a displaced member that kept running and can
            // exchange frames with the component's holder has had its state reported.
            let comp = w.component();
            for (_, displaced, claim) in &w.ghost.owed {
                let d = idx(displaced);
                let holder = (0..w.m.len()).find(|&h| comp[h] == comp[d] && w.m[h].sends_as_holder());
                if let Some(h) = holder {
                    if w.m[d].joined() && w.reach[d][h] && w.reach[h][d] {
                        return Err(format!(
                            "G11: {displaced}'s state under {} never reported to a holder ({} holds) {tag}",
                            show_claim(claim),
                            IDS[h]
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn complete(&self, b: &Bounds) -> Result<(), String> {
        for s in [Schedule::Fifo, Schedule::Lifo, Schedule::Rotate] {
            self.complete_with(b, s)?;
        }
        Ok(())
    }

    /// G5 strictly: with the holder cut off and nobody else pending, a joined writer that
    /// asks is itself holder within askTimeoutMs plus one tick.
    fn complete_g5(&self, b: &Bounds) -> Result<(), String> {
        self.complete_g5_inner(b)
    }
    fn complete_g5_inner(&self, b: &Bounds) -> Result<(), String> {
        let Some(h) = self.m.iter().position(|s| s.is_holder()) else {
            return Ok(());
        };
        let mut w = self.clone();
        w.lossless = true;
        for j in 0..w.m.len() {
            w.reach[h][j] = false;
            w.reach[j][h] = false;
        }
        w.net.retain(|(d, f, v)| *d != h && (f.from != IDS[h] || v.is_some_and(|v| v != h)));
        for i in 0..w.m.len() {
            if i != h && !w.up[i] {
                w.up[i] = true;
                w.input(i, Input::LinkUp, b, None)?;
            }
        }
        w.flush(b, Schedule::Fifo)?;
        let Some(wi) = (0..w.m.len()).find(|j| *j != h && w.m[*j].joined()) else {
            return Ok(());
        };
        let others_busy = (0..w.m.len())
            .any(|j| j != h && j != wi && (w.m[j].pending() || w.m[j].is_holder()))
            || w.m[wi].is_holder();
        if others_busy {
            return Ok(());
        }
        w.became = vec![false; w.m.len()];
        w.input(wi, Input::App { command: Command::Ask }, b, None)?;
        // G5 (revision 5): askTimeoutMs plus a tick; with forwarded evidence of the cut-off
        // holder, holderTimeoutMs + askTimeoutMs from the last such evidence (plus ticks).
        let p = policy();
        let quick = p.ask_timeout_ms / TICK + 1;
        let slow = (p.holder_timeout_ms + p.ask_timeout_ms) / TICK + 2;
        let mut deadline = quick;
        let mut t = 0;
        while t < deadline {
            let before = w.evidence_seen.clone();
            w.flush(b, Schedule::Fifo)?;
            if w.evidence_seen[wi] > before[wi] {
                deadline = deadline.max(t + slow).min(quick + 3 * slow);
            }
            w.tick(b)?;
            t += 1;
        }
        w.flush(b, Schedule::Fifo)?;
        if !w.m[wi].sends_as_holder() {
            return Err(format!(
                "G5: {} asked with holder {} cut off and after {deadline} ticks is not holder (sees {:?})",
                IDS[wi],
                IDS[h],
                w.m[wi].holder()
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
    seen.insert(init.key());
    let mut queue: VecDeque<(World, u32)> = VecDeque::from([(init.clone(), 0)]);
    let mut levels: Vec<usize> = vec![1];
    let mut transitions = 0;
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
            match r {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) => {
                    let mut path = trace_to(&parent, wk);
                    path.push(a);
                    return Report {
                        states: seen.len(),
                        transitions,
                        violation: Some((e, path)),
                        truncated: false,
                    };
                }
            }
            let nk = n.key();
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
            if levels.len() <= depth as usize + 1 {
                levels.push(0);
            }
            levels[depth as usize + 1] += 1;
            if n.now <= b.time {
                queue.push_back((n, depth + 1));
            }
            if seen.len() >= b.max_states {
                println!("new states per depth: {levels:?} (truncated)");
                return Report {
                    states: seen.len(),
                    transitions,
                    violation: None,
                    truncated: true,
                };
            }
        }
    }
    println!("new states per depth: {levels:?}");
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
                let (d, f, _) = &w.net[*k];
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
    s
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

type Small = (u8, u8, u8, usize);

/// Default bounds finish in seconds; `COLOPHON_EXPLORE=big` widens them.
fn bounds(members: usize, kinds: &'static str, small: Small, depth: u32) -> Bounds {
    let big = std::env::var("COLOPHON_EXPLORE").is_ok_and(|v| v == "big");
    let (cmds, dups, links, cap) = if big {
        (small.0 + 1, small.1.max(1), small.2 + 1, small.3 + 1)
    } else {
        small
    };
    let depth = if big { depth + 3 } else { depth };
    Bounds {
        members,
        time: 200 * TICK,
        cmds: env_u64("COLOPHON_EXPLORE_CMDS", u64::from(cmds)) as u8,
        dups: env_u64("COLOPHON_EXPLORE_DUPS", u64::from(dups)) as u8,
        links: env_u64("COLOPHON_EXPLORE_LINKS", u64::from(links)) as u8,
        restarts: 1,
        crashes: 0,
        cuts: 0,
        cap: env_u64("COLOPHON_EXPLORE_CAP", cap as u64) as usize,
        max_states: env_u64("COLOPHON_EXPLORE_STATES", if big { 100_000_000 } else { 3_000_000 })
            as usize,
        depth: env_u64("COLOPHON_EXPLORE_DEPTH", u64::from(depth)) as u32,
        completions: std::env::var("COLOPHON_EXPLORE_NO_COMPLETIONS").is_err(),
        kinds,
        start: Start::Taken,
        topo: Topo::Mesh,
    }
}

fn run(b: Bounds, fixes: Fixes) -> Report {
    let t = std::time::Instant::now();
    let r = explore(b, fixes);
    println!(
        "explore members={} topo={:?} start={:?} kinds={:?} crashes={}: {} states, {} transitions, {:?}, truncated={}",
        b.members,
        b.topo,
        b.start,
        b.kinds,
        b.crashes,
        r.states,
        r.transitions,
        t.elapsed(),
        r.truncated
    );
    if let Some((e, path)) = &r.violation {
        println!("violation: {e}\n{}", print_trace(b, fixes, path));
        if std::env::var("COLOPHON_EXPLORE_VERBOSE").is_ok() {
            let mut w = World::new(&b, fixes);
            for a in path {
                let _ = w.apply(a, &b);
            }
            VERBOSE.store(true, std::sync::atomic::Ordering::Relaxed);
            println!("--- completion ---");
            println!("{:?}", w.complete(&b));
            println!("--- G5 completion ---");
            println!("{:?}", w.complete_g5(&b));
            VERBOSE.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }
    r
}

/// `COLOPHON_EXPLORE_WITHOUT=F5,R1` explores with those fixes off (for findings work).
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
            "R1" => f.evidence = false,
            "R2" => f.state_reports = false,
            "R2c" => f.persist_release = false,
            "R5" => f.submit_retry = false,
            "R1c" => f.evidence_push = false,
            "R2d" => f.yielded_ack = false,
            "R1d" => f.evidence_keeps_want = false,
            "R1f" => f.evidence_refresh = false,
            _ => {}
        }
    }
    f
}

fn check_bounds(b: Bounds) {
    let r = run(b, fixes_under_test());
    assert!(r.violation.is_none(), "{:?}", r.violation.map(|v| v.0));
    assert!(!r.truncated, "state bound reached before exhausting the space");
}
fn check(members: usize, kinds: &'static str, small: Small, depth: u32) {
    check_bounds(bounds(members, kinds, small, depth));
}

/// Ask, take, pass, decline and publish between two members.
#[test]
fn two_members_handoff() {
    check(2, "atpu", (3, 1, 2, 3), 7);
}

/// Release, leave, join, restart, submit and publish between two members.
#[test]
fn two_members_membership() {
    check(2, "rlxsu", (3, 0, 1, 3), 7);
}

/// Ask, take and pass among three members.
#[test]
fn three_members_handoff() {
    check(3, "atp", (2, 0, 1, 3), 7);
}

/// Release, leave, join and restart among three members.
#[test]
fn three_members_membership() {
    check(3, "rlxu", (2, 0, 1, 2), 7);
}

/// H1: the chain a↔b↔c with a↮c held indefinitely, starting from two holders (a 1.0.a,
/// c 1.0.c), with no application command: G10, G4 per component, G11.
fn chain_two_holders(fixes: Fixes, topo: Topo) -> Report {
    let mut b = bounds(3, "", (0, 0, 0, 3), 8);
    b.topo = topo;
    b.start = Start::ChainTwoHolders;
    run(b, fixes)
}

/// Revision 7: with bridging the chain is one group and settles.
#[test]
fn bridged_chain_two_holders_settle() {
    let r = chain_two_holders(fixes_under_test(), Topo::BridgedChain);
    assert!(r.violation.is_none(), "{:?}", r.violation.map(|v| v.0));
    assert!(!r.truncated);
}

/// Revision 6 (one-hop evidence) on the unbridged three-member chain, kept as a regression.
#[test]
fn chain_two_holders_settle_rev6() {
    let r = chain_two_holders(Fixes::REV6, Topo::Chain);
    assert!(r.violation.is_none(), "{:?}", r.violation.map(|v| v.0));
    assert!(!r.truncated);
}

/// H1: revision 3's hearsay renewing livelocks on the unbridged chain.
#[test]
fn chain_two_holders_rev3_livelocks() {
    let r = chain_two_holders(Fixes::REV3, Topo::Chain);
    let v = r.violation.expect("revision 3 should livelock on the chain");
    assert!(v.0.starts_with("G10"), "{}", v.0);
}

fn chain_handoff_bounds(topo: Topo) -> Bounds {
    let mut b = bounds(3, "atp", (2, 0, 0, 3), 7);
    b.topo = topo;
    b
}

/// Finding R1f: revision 5 as written livelocks on the unbridged chain (G10).
#[test]
fn chain_two_holders_rev5_livelocks() {
    let r = chain_two_holders(Fixes::REV5, Topo::Chain);
    let v = r.violation.expect("revision 5 should livelock on the chain");
    assert!(v.0.starts_with("G10"), "{}", v.0);
}

/// The bridged chain with ask, take and pass (revision 7), and the unbridged one under
/// revision 6.
#[test]
fn chain_handoff() {
    check_bounds(chain_handoff_bounds(Topo::BridgedChain));
    let r = run(chain_handoff_bounds(Topo::Chain), Fixes::REV6);
    assert!(r.violation.is_none(), "{:?}", r.violation.map(|v| v.0));
}

/// Groups split and merge (§S0): a member is cut from the others while its own link stays
/// up, then merged back, with ask, take and pass.
#[test]
fn groups_split_merge() {
    let mut b = bounds(3, "atp", (2, 0, 0, 3), 7);
    b.cuts = 2;
    check_bounds(b);
}

/// Revision 4 as written fails where revision 5 changed it: without evidence for silent
/// members (R1c) a member behind a non-holder on the chain never learns the holder (G4);
/// without the `ack` (R2d/R2f) two losses lose a displaced holder's state (G11); without
/// R1d an asker displaced by forwarded evidence of a cut-off holder never takes (G5).
#[test]
fn rev4_counterexamples() {
    let r = run(chain_handoff_bounds(Topo::Chain), Fixes { evidence_push: false, ..Fixes::REV6 });
    let v = r.violation.expect("R1c off should break G4 on the chain");
    assert!(v.0.starts_with("G4"), "{}", v.0);
    let r = run(bounds(2, "atpu", (3, 1, 2, 3), 7), Fixes { yielded_ack: false, ..Fixes::ALL });
    // (the `ack` is unchanged in revision 7)
    let v = r.violation.expect("R2d off should break G11");
    assert!(v.0.starts_with("G11"), "{}", v.0);
    let r = run(bounds(3, "atp", (2, 0, 1, 3), 7), Fixes { evidence_keeps_want: false, ..Fixes::REV6 });
    let v = r.violation.expect("R1d off should break G5");
    assert!(v.0.starts_with("G5"), "{}", v.0);
}

/// H4/G12: every single-member step cut after each prefix of its outputs, then a restart.
#[test]
fn crash_prefixes() {
    let mut b = bounds(2, "atpur", (2, 0, 0, 3), 6);
    b.crashes = 1;
    check_bounds(b);
    let mut b = bounds(3, "atp", (2, 0, 0, 3), 5);
    b.crashes = 1;
    check_bounds(b);
}

/// F12/F21 (revision 3, §S4 `via`) explored from the two-holder start.
#[test]
fn two_passes_to_one_asker_explored() {
    let mut b = bounds(3, "p", (2, 0, 1, 3), 7);
    b.start = Start::TwoHolders;
    check_bounds(b);
}

const PROFILES: [(usize, &str, Small); 4] = [
    (2, "atpu", (3, 1, 2, 3)),
    (2, "rlxsu", (3, 0, 1, 3)),
    (3, "atp", (2, 0, 1, 3)),
    (3, "rlxu", (2, 0, 1, 2)),
];

/// The revision 1 draft fails, and so does the reference reading without F1 or without F2.
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
            run(bounds(members, kinds, small, 7), fixes).violation.is_some()
        });
        assert!(found, "no counterexample for the {name}");
    }
}

// ---------------------------------------------------------------------------------------------
// Scripted traces (H5): a small router with per-edge reachability and explicit losses.

struct Router {
    ids: Vec<&'static str>,
    m: Vec<Session>,
    reach: Vec<Vec<bool>>,
    net: Vec<(usize, Frame, Option<usize>)>,
    events: Vec<(usize, Event)>,
    persisted: Vec<Option<Persisted>>,
    fixes: Fixes,
    policy: Policy,
}

impl Router {
    fn new(ids: &[&'static str], fixes: Fixes, policy: Policy) -> Self {
        let n = ids.len();
        Router {
            ids: ids.to_vec(),
            m: ids.iter().map(|i| Session::with_fixes(i, true, policy.clone(), None, fixes)).collect(),
            reach: (0..n).map(|i| (0..n).map(|j| i != j).collect()).collect(),
            net: Vec::new(),
            events: Vec::new(),
            persisted: vec![None; n],
            fixes,
            policy,
        }
    }
    fn i(&self, id: &str) -> usize {
        self.ids.iter().position(|x| *x == id).unwrap()
    }
    fn step(&mut self, i: usize, input: Input, now: u64) {
        let outs = self.m[i].handle(input, now);
        for o in outs {
            match o {
                Output::Send { frame } => {
                    let dsts: Vec<usize> = match &frame.to {
                        Some(t) => vec![self.i(t)],
                        None => (0..self.m.len()).filter(|j| *j != i).collect(),
                    };
                    for d in dsts {
                        if self.reach[i][d] {
                            self.net.push((d, frame.clone(), None));
                        }
                    }
                }
                Output::Forward { to, frame } => {
                    let d = self.i(&to);
                    if self.reach[i][d] {
                        self.net.push((d, frame, Some(i)));
                    }
                }
                Output::Persist { claim, released } => self.persisted[i] = Some(Persisted { claim, released }),
                Output::Event { event } => self.events.push((i, event)),
            }
        }
    }
    fn cmd(&mut self, id: &str, command: Command, now: u64) {
        let i = self.i(id);
        self.step(i, Input::App { command }, now);
    }
    /// Deliver pending frames in order, holding back (keeping in flight) those `hold` picks.
    fn deliver_except(&mut self, now: u64, hold: &dyn Fn(&str, &Frame) -> bool) {
        let mut held = Vec::new();
        let mut guard = 0;
        while !self.net.is_empty() {
            guard += 1;
            assert!(guard < 10_000, "frames never quiesce");
            let (d, f, v) = self.net.remove(0);
            if hold(self.ids[d], &f) {
                held.push((d, f, v));
                continue;
            }
            // Scripted evidence is delivered with a window (the stale-evidence test builds its
            // own windowless input).
            let forwarded = v.map(|v| Forwarded { via: self.ids[v].to_owned(), windowed: true });
            self.step(d, Input::Frame { frame: f, writer: true, key: None, n: None, forwarded }, now);
        }
        self.net = held;
    }
    fn deliver(&mut self, now: u64) {
        self.deliver_except(now, &|_, _| false);
    }
    fn tick_all(&mut self, now: u64) {
        for i in 0..self.m.len() {
            self.step(i, Input::Tick, now);
        }
    }
    fn restart(&mut self, id: &str, now: u64) {
        let i = self.i(id);
        self.m[i] = Session::with_fixes(id, true, self.policy.clone(), self.persisted[i].clone(), self.fixes);
        self.step(i, Input::App { command: Command::Join { state: None } }, now);
    }
    /// Whether member `i`'s application was told `snapshot`.
    fn reported(&self, i: usize, snapshot: &Bytes) -> bool {
        self.events.iter().any(|(at, e)| *at == i && match e {
            Event::LatePass { snapshot: s, .. } | Event::Displaced { snapshot: s, .. } => s == snapshot,
            Event::BecameHolder { snapshot: s, .. } | Event::Snapshot { snapshot: s, .. } => s == snapshot,
            _ => false,
        })
    }
}

fn b(x: &str) -> Bytes {
    Bytes(x.as_bytes().to_vec())
}

/// H5(1): a takes; b asks; a's pass (with SA) is delayed past b's ask timeout; b takes with
/// SB; the pass arrives. Revision 3 renews over it silently (SA never reaches any
/// application); revision 4 reports it (`LatePass`).
fn take_races_delayed_pass(fixes: Fixes) -> (bool, Router) {
    let mut r = Router::new(&["a", "b"], fixes, Policy::default());
    for id in ["a", "b"] {
        r.cmd(id, Command::Join { state: None }, 0);
    }
    r.deliver(0);
    r.cmd("a", Command::Take { state: Some(b("S0")) }, 10);
    r.deliver(20);
    r.cmd("b", Command::Ask, 100);
    r.deliver(110);
    r.cmd("a", Command::Pass { to: "b".into(), snapshot: b("SA") }, 120);
    // The pass is delayed; b times out and takes with its own projection.
    r.deliver_except(130, &|_, f| matches!(f.body, Body::Pass { .. }));
    r.cmd("b", Command::Take { state: Some(b("SB")) }, 200);
    r.tick_all(1_700);
    r.deliver_except(1_710, &|_, f| matches!(f.body, Body::Pass { .. }));
    assert!(r.m[1].is_holder());
    r.deliver(1_800);
    for t in [7_000u64, 13_000, 19_000] {
        r.tick_all(t);
        r.deliver(t + 10);
    }
    (r.reported(1, &b("SA")), r)
}

#[test]
fn h5_take_races_delayed_pass() {
    let (old, _) = take_races_delayed_pass(Fixes::REV3);
    assert!(!old, "revision 3 should drop SA silently");
    let (new, r) = take_races_delayed_pass(Fixes::ALL);
    assert!(new, "revision 4 must report SA");
    assert!(r.events.iter().any(|(i, e)| *i == 1 && matches!(e, Event::LatePass { .. })));
    check_converged(&r.m).unwrap();
}

/// H5(2): `ff` takes term 1 and releases; `00` takes term 2 and publishes N; `ff` restarts
/// with its persisted data while `00`'s frames to it are delayed past askTimeoutMs.
/// Revision 3 resurrects 1.0.ff, retakes 2.0.ff and overwrites N; revision 4's tombstone
/// keeps `ff` from acting as holder.
fn released_restart_overwrites(fixes: Fixes) -> Router {
    let policy = Policy::default();
    let mut r = Router::new(&["00", "ff"], fixes, policy);
    for id in ["00", "ff"] {
        r.cmd(id, Command::Join { state: None }, 0);
    }
    r.deliver(0);
    r.cmd("ff", Command::Take { state: Some(b("OLD")) }, 10);
    r.deliver(20);
    r.cmd("ff", Command::Release, 30);
    r.deliver(40);
    r.cmd("00", Command::Ask, 50);
    // 00's take and later frames to ff are delayed.
    r.deliver_except(60, &|to, _| to == "ff");
    r.cmd("00", Command::Publish { id: Id::from_label("n"), payload: b("N") }, 70);
    r.deliver_except(80, &|to, _| to == "ff");
    r.restart("ff", 1_000);
    r.deliver_except(1_010, &|to, _| to == "ff");
    r.tick_all(2_600);
    r.deliver_except(2_610, &|to, _| to == "ff");
    // Now everything flows.
    r.deliver(3_000);
    for t in [8_000u64, 14_000, 20_000] {
        r.tick_all(t);
        r.deliver(t + 10);
    }
    r
}

#[test]
fn h5_released_restart_does_not_overwrite() {
    let old = released_restart_overwrites(Fixes::REV3);
    let old_state = old.m[0].state().clone();
    assert_ne!(old_state, b("N"), "revision 3 should overwrite N");
    let new = released_restart_overwrites(Fixes::ALL);
    assert_eq!(new.m[0].state(), &b("N"));
    assert!(new.m[0].is_holder());
    check_converged(&new.m).unwrap();
}

/// H5(3): b submits X to the holder a, but a passes to c before the submit arrives (a drops
/// it). Revision 3 never orders X and tells nobody; revision 4 resends on the holder change
/// and c orders it (possibly more than once, which §S8 allows).
fn submit_across_holder_change(fixes: Fixes) -> Router {
    let policy = Policy { fold: Fold::Append, ..Policy::default() };
    let mut r = Router::new(&["a", "b", "c"], fixes, policy);
    for id in ["a", "b", "c"] {
        r.cmd(id, Command::Join { state: None }, 0);
    }
    r.deliver(0);
    r.cmd("a", Command::Take { state: None }, 10);
    r.deliver(20);
    r.cmd("c", Command::Ask, 30);
    r.deliver(40);
    r.cmd("b", Command::Submit { id: Id::from_label("x"), payload: b("X") }, 50);
    // The submit is held while a passes to c.
    r.deliver_except(55, &|_, f| matches!(f.body, Body::Submit { .. }));
    r.cmd("a", Command::Pass { to: "c".into(), snapshot: r.m[0].state().clone() }, 60);
    r.deliver(70);
    for t in [1_600u64, 3_200, 6_000, 12_000] {
        r.tick_all(t);
        r.deliver(t + 10);
    }
    r
}

#[test]
fn h5_submit_across_holder_change() {
    let ordered = |r: &Router| {
        r.events
            .iter()
            .filter(|(i, e)| *i == 2 && matches!(e, Event::Message { id, .. } if *id == Id::from_label("x")))
            .count()
    };
    let old = submit_across_holder_change(Fixes::REV3);
    let failed = |r: &Router| r.events.iter().any(|(_, e)| matches!(e, Event::SubmitFailed { .. }));
    assert_eq!(ordered(&old), 0, "revision 3 drops the submit");
    assert!(!failed(&old), "and reports nothing");
    let new = submit_across_holder_change(Fixes::ALL);
    assert!(ordered(&new) >= 1, "revision 4 orders it at least once");
    assert!(!failed(&new));
    check_converged(&new.m).unwrap();
}

/// F12/F21 scripted with the default policy: (1) every frame delivered, (2) `a`'s pass to `x`
/// lost, (3) 300 seeds of 30 % random loss from the passes on, then eventual delivery.
fn two_passes_to_one(fixes: Fixes, lose_a_pass_to_x: bool, loss_seed: Option<u64>) -> Vec<Session> {
    let mut r = Router::new(&["a", "b", "x"], fixes, Policy::default());
    // a and b never hear each other; b hears nobody until it takes.
    r.reach[0][1] = false;
    r.reach[1][0] = false;
    r.reach[1][2] = false;
    r.reach[2][1] = false;
    for id in ["a", "b", "x"] {
        r.cmd(id, Command::Join { state: None }, 0);
    }
    r.deliver(0);
    r.cmd("a", Command::Take { state: Some(b("A")) }, 10);
    r.deliver(10);
    r.cmd("x", Command::Ask, 20);
    r.deliver(20);
    r.reach[1][2] = true;
    r.reach[2][1] = true;
    r.cmd("b", Command::Take { state: Some(b("B")) }, 30);
    r.deliver(30);
    assert_eq!(r.m[2].accepted(), Some(&Claim::new(1, 0, "b")));
    r.cmd("b", Command::Pass { to: "x".into(), snapshot: b("B") }, 40);
    r.cmd("a", Command::Pass { to: "x".into(), snapshot: b("A") }, 40);
    let mut rng = loss_seed.unwrap_or(0).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut lose = |r: &mut Router, k: u64| {
        if lose_a_pass_to_x && k == 0 {
            r.net.retain(|(d, f, _)| !(*d == 2 && f.from == "a" && matches!(f.body, Body::Pass { .. })));
        }
        if loss_seed.is_some() && k < 12 {
            r.net.retain(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng % 10 >= 3
            });
        }
    };
    lose(&mut r, 0);
    r.deliver(50);
    r.reach[0][1] = true;
    r.reach[1][0] = true;
    for k in 1..=20u64 {
        let t = k * 6_000;
        r.tick_all(t);
        lose(&mut r, k);
        r.deliver(t + 10);
    }
    r.m
}

fn show(m: &[Session]) -> String {
    format!("{:?}", m.iter().map(|s| (s.me().to_owned(), s.accepted().map(show_claim), String::from_utf8_lossy(&s.state().0).into_owned())).collect::<Vec<_>>())
}

#[test]
fn f12_f21_two_passes_to_one_asker() {
    let both = two_passes_to_one(Fixes::ALL, false, None);
    println!("both passes delivered: {}", show(&both));
    check_converged(&both).unwrap();
    let lost = two_passes_to_one(Fixes::ALL, true, None);
    println!("a's pass to x lost: {}", show(&lost));
    check_converged(&lost).unwrap();
    for seed in 0..300 {
        let m = two_passes_to_one(Fixes::ALL, seed % 2 == 0, Some(seed));
        if let Err(e) = check_converged(&m) {
            panic!("loss seed {seed}: {e}: {}", show(&m));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Revision 7 checks from the second review.

fn frame_to(from: &str, to: &str, body: Body) -> Input {
    Input::Frame {
        frame: Frame { from: from.into(), to: Some(to.into()), retain: false, body },
        writer: true,
        key: None,
        n: None,
        forwarded: None,
    }
}

/// a held 1.0.a and yielded to b's take, so it owes b a `yielded`. A third writer c cannot
/// clear that with an `ack`, nor inject a `yielded` at b: revision 7 checks the sender.
fn third_writer(fixes: Fixes) -> (bool, bool) {
    let mut r = Router::new(&["a", "b", "c"], fixes, Policy::default());
    for id in ["a", "b", "c"] {
        r.cmd(id, Command::Join { state: None }, 0);
    }
    r.deliver(0);
    r.cmd("a", Command::Take { state: Some(b("A")) }, 10);
    r.deliver(20);
    // a's yielded to b is lost.
    r.reach[0][1] = false;
    r.cmd("b", Command::Take { state: None }, 30);
    r.tick_all(16_000);
    r.deliver(16_010);
    r.reach[0][1] = true;
    assert_eq!(r.m[0].accepted(), Some(&Claim::new(2, 0, "b")));
    // c forges an ack to a.
    r.step(0, frame_to("c", "a", Body::Ack { yielded: Claim::new(1, 0, "a") }), 16_100);
    // b's next beat: a resends (and b reports) only if the forged ack was ignored.
    r.tick_all(22_000);
    r.deliver(22_010);
    let resent = r.events.iter().any(|(i, e)| *i == 1 && matches!(e, Event::Displaced { from, .. } if from == "a"));
    // c injects a yielded naming a's old claim at b.
    let n_before = r.events.len();
    r.step(1, frame_to("c", "b", Body::Yielded { claim: Claim::new(1, 0, "a"), seq: 0, snapshot: b("FAKE") }), 22_100);
    let injected = r.events[n_before..]
        .iter()
        .any(|(_, e)| matches!(e, Event::Displaced { snapshot, .. } if *snapshot == b("FAKE")));
    (resent, injected)
}

#[test]
fn third_writer_cannot_clear_or_inject_reports() {
    let (resent, injected) = third_writer(Fixes::ALL);
    assert!(resent, "revision 7: a forged ack must not clear the pending report");
    assert!(!injected, "revision 7: a yielded from a non-holder of its claim is ignored");
    let (_, injected_old) = third_writer(Fixes::REV6);
    assert!(injected_old, "revision 6 accepted the injected yielded");
}

/// The `append` fold never makes a snapshot larger than maxPayload (revision 7), and a
/// payload is at most maxPayload − 4 bytes (revision 8), so a joiner gets `state`.
fn append_bound(fixes: Fixes, big: usize) -> (usize, bool, bool) {
    let policy = Policy { fold: Fold::Append, max_payload: 64, ..Policy::default() };
    let mut r = Router::new(&["a", "b"], fixes, policy);
    r.cmd("a", Command::Join { state: None }, 0);
    r.cmd("a", Command::Take { state: None }, 10);
    r.cmd("a", Command::Publish { id: Id::from_label("small"), payload: Bytes(vec![1; 20]) }, 20);
    r.cmd("a", Command::Publish { id: Id::from_label("big"), payload: Bytes(vec![2; big]) }, 30);
    let rejected = r.events.iter().any(|(_, e)| matches!(e, Event::Rejected { command, .. } if command == "publish"));
    r.net.clear();
    let size = r.m[0].state().len();
    r.cmd("b", Command::Join { state: None }, 40);
    r.deliver(50);
    (size, r.m[1].synced(), rejected)
}

#[test]
fn append_state_fits_a_frame() {
    let (size, synced, rejected) = append_bound(Fixes::ALL, 64);
    assert!(rejected, "a 64-byte append payload exceeds maxPayload - 4");
    assert!(size <= 64 && synced);
    let (size, synced, rejected) = append_bound(Fixes::ALL, 60);
    assert!(!rejected && size == 64 && synced, "60 bytes + 4 fit exactly: {size}");
    let (old, old_synced, _) = append_bound(Fixes::REV6, 64);
    assert!(old > 64 && !old_synced, "revision 6: {old} bytes, joiner synced {old_synced}");
}

/// Freshness windows: at most 4 keys per member; all dropped when the member is no longer
/// accepted.
#[test]
fn freshness_windows_are_bounded() {
    let mut s = Session::new("a", true, Policy::default(), None).with_fresh_seed([7; 16]);
    let outs = s.handle(Input::App { command: Command::Join { state: None } }, 0);
    let mine = outs
        .iter()
        .find_map(|o| match o {
            Output::Send { frame: Frame { body: Body::Hello { fresh, .. }, .. } } => Some(*fresh),
            _ => None,
        })
        .unwrap();
    for k in 0..6u8 {
        let hello = Body::Hello {
            fresh: Id([k; 16]),
            echo: vec![mine],
            seen: None,
            heard: None,
            lapsed: false,
        };
        s.handle(
            Input::Frame {
                frame: Frame { from: "x".into(), to: None, retain: false, body: hello },
                writer: true,
                key: Some(format!("kx{k}")),
                n: Some(1),
                forwarded: None,
            },
            10 + u64::from(k),
        );
    }
    assert_eq!(s.windows_for("x"), MAX_KEYS_PER_MEMBER);
    s.forget_member("x");
    assert_eq!(s.windows_for("x"), 0);
}
