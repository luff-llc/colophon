//! The session machine over modelled carriers, in virtual time (revision 10).
//!
//! **Carriers.** The home carrier is a hub: a frame uploaded by a member is delivered to every
//! other subscribed member (revision 10: every frame is a broadcast; `to` is advice), with
//! loss and per-frame delay. Direct links connect pairs of members; every member runs the
//! §S9 bridge (`colophon_core::v06::bridge`), with the home as one of its links, so frames
//! cross between the home and direct links. Groups are modelled by a group label per
//! member: nothing crosses between groups until they merge.
//!
//! **Freshness is real.** Every member has a `fresh` seed, and each frame reaches the
//! machine with its sender key and `n`, so the §S3 exchange decides what a member acts on.
//!
//! **Time.** Each frame gets its own delay from the delay policy; member ticks run every
//! 250 ms between deliveries, so deliveries span beat, ask and holder timeouts.
//!
//! Checked on every input: G1, G2, G3, G6 (for frames the member accepts) and G11 bookkeeping (`v06_session_support`). At
//! the end of a timely phase: G4 (one holder, one claim, one state), G10 (no claim change
//! in the final window) and G11 (every displaced state reported).
#![allow(clippy::unwrap_used)]
mod v06_session_support;
use colophon_core::v06::bridge::{Bridge, LinkId, Wire};
use colophon_core::v06::session::*;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use v06_session_support::*;

/// The link id each member's bridge uses for the home.
const HOME: LinkId = 10_000;
const TICK: u64 = 250;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HomeMode {
    /// Revision 10: every frame to every subscribed member.
    Broadcast,
    /// Revision 9: an addressed frame only to the member named by `to`.
    ToOnly,
}

#[derive(Clone, Copy, Debug)]
enum Delay {
    /// Uniform in [0, max] ms.
    Uniform(u64),
    /// Holder frames (`state`, `beat`, `msg`, `take`, `pass`) delayed by `late`; every other
    /// frame within `prompt`: the review's adversary.
    HolderLate { late: u64, prompt: u64 },
    /// Holder frames held back and released together at the next multiple of `period` ms
    /// (each delayed by at most `period`, arriving `period` apart); every other frame within
    /// `prompt`. Beyond holderTimeoutMs this is the review's renew-forever adversary.
    HolderBatch { period: u64, prompt: u64 },
    /// The review's adaptive adversary: a holder frame sent to a member that is itself acting
    /// as holder is withheld until its claim is obsolete (some member accepts a greater one)
    /// or `cap` ms have passed, whichever is first; holder frames to followers and every
    /// other frame within `prompt`. `cap` is the maximum delay D.
    Obsolete { cap: u64, prompt: u64 },
    /// Exactly this many ms per hop.
    Fixed(u64),
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn holder_frame(w: &Wire) -> bool {
    matches!(
        w.frame.body,
        Body::State { .. } | Body::Beat { .. } | Body::Msg { .. } | Body::Take { .. } | Body::Pass { .. }
    )
}

type Event = (u64, u64, usize, LinkId, Wire);

/// How member timers fire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ticks {
    /// Every member ticks every 250 ms. Each tick that does anything must have been due by
    /// `next_deadline` (checked).
    Every,
    /// Each member ticks only at its `next_deadline`, plus a dispatch delay of up to `max`
    /// ms (§S11 G5: a host delivers a timer expiry within 250 ms).
    Deadline { max: u64 },
}

/// §S0 (revision 12), condition 3: these kinds must be accepted within the interval.
fn control_frame(b: &Body) -> bool {
    matches!(
        b,
        Body::Hello { .. } | Body::State { .. } | Body::Take { .. } | Body::Pass { .. } | Body::Yielded { .. } | Body::Ack { .. } | Body::Bye { .. }
    )
}
/// Condition 2 counts holder frames (§S6), `take` included.
fn counts_as_holder(b: &Body) -> bool {
    b.is_holder_frame() || matches!(b, Body::Take { .. })
}

/// Allowance after the oracle's T before the final window may be judged.
const SETTLE: u64 = 30_000;

struct Net {
    ids: Vec<String>,
    s: Vec<Session>,
    b: Vec<Bridge>,
    home: BTreeSet<usize>,
    home_mode: HomeMode,
    links: BTreeMap<LinkId, (usize, usize)>,
    link_of: BTreeMap<(usize, usize), LinkId>,
    group: Vec<u32>,
    q: BinaryHeap<Reverse<Event>>,
    now: u64,
    seq: u64,
    rng: Rng,
    delay: Delay,
    loss: u64,
    n: Vec<u64>,
    ghost: Ghost,
    persists: u64,
    keyed: bool,
    violation: Option<String>,
    /// Revision 6 evidence outputs, forwarded as legacy inputs (regression only).
    sent: BTreeMap<Frame, (String, u64)>,
    legacy: BTreeMap<u64, usize>,
    /// Holder frames withheld by `Delay::Obsolete`: (sent at, seq, to, back link, frame).
    withheld: Vec<Event>,
    /// Adversarial consecutive loss: of the holder frames from one member to another, lose
    /// `burst` in a row, deliver the next, and so on.
    burst: u64,
    burst_count: BTreeMap<(usize, usize), u64>,
    ticks: Ticks,
    tick_at: Vec<Option<u64>>,
    // The trace the timely oracle reads.
    log_sent: Vec<(u64, usize, Frame)>,
    log_accepted: Vec<(u64, usize, Frame)>,
    log_holding: Vec<(u64, usize, bool)>,
    log_membership: Vec<u64>,
    /// (time, member) of every `becameHolder`.
    became: Vec<(u64, usize)>,
}

impl Net {
    fn new(n: usize, home: &[usize], edges: &[(usize, usize)], fixes: Fixes, keyed: bool, seed: u64) -> Self {
        let ids: Vec<String> = (0..n).map(|i| format!("{:02x}", (i + 1) * 0x11)).collect();
        let s = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let x = Session::with_fixes(id, true, Policy::default(), None, fixes).with_entitled(ids.clone());
                if keyed {
                    x.with_fresh_seed([i as u8 + 1; 16])
                } else {
                    x
                }
            })
            .collect();
        let mut net = Net {
            b: ids.iter().map(|id| Bridge::new(id)).collect(),
            ids,
            s,
            home: home.iter().copied().collect(),
            home_mode: HomeMode::Broadcast,
            links: BTreeMap::new(),
            link_of: BTreeMap::new(),
            group: vec![0; n],
            q: BinaryHeap::new(),
            now: 0,
            seq: 0,
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            delay: Delay::Uniform(100),
            loss: 0,
            n: vec![0; n],
            ghost: Ghost::default(),
            persists: 0,
            keyed,
            violation: None,
            sent: BTreeMap::new(),
            legacy: BTreeMap::new(),
            withheld: Vec::new(),
            burst: 0,
            burst_count: BTreeMap::new(),
            ticks: Ticks::Every,
            tick_at: vec![None; n],
            log_sent: Vec::new(),
            log_accepted: Vec::new(),
            log_holding: Vec::new(),
            log_membership: vec![0],
            became: Vec::new(),
        };
        for &i in home {
            net.b[i].add_link(HOME);
        }
        let mut id = 0;
        for &(a, c) in edges {
            for (x, y) in [(a, c), (c, a)] {
                net.links.insert(id, (x, y));
                net.link_of.insert((x, y), id);
                net.b[x].add_link(id);
                id += 1;
            }
        }
        net
    }

    fn delay_for(&mut self, w: &Wire) -> u64 {
        match self.delay {
            Delay::Uniform(max) => self.rng.below(max + 1),
            Delay::Fixed(d) => d,
            Delay::HolderLate { late, prompt } => {
                if holder_frame(w) {
                    late
                } else {
                    self.rng.below(prompt + 1)
                }
            }
            Delay::Obsolete { prompt, .. } => {
                if holder_frame(w) {
                    0
                } else {
                    self.rng.below(prompt + 1)
                }
            }
            Delay::HolderBatch { period, prompt } => {
                if holder_frame(w) {
                    (self.now / period + 1) * period - self.now
                } else {
                    self.rng.below(prompt + 1)
                }
            }
        }
    }

    fn enqueue(&mut self, from: usize, to: usize, back: LinkId, w: Wire, legacy_via: Option<usize>) {
        if self.group[from] != self.group[to] || self.rng.below(1000) < self.loss {
            return;
        }
        if self.burst > 0 && counts_as_holder(&w.frame.body) {
            let c = self.burst_count.entry((from, to)).or_insert(0);
            *c += 1;
            if *c % (self.burst + 1) != 0 {
                return;
            }
        }
        let d = self.delay_for(&w);
        self.seq += 1;
        if let Some(v) = legacy_via {
            self.legacy.insert(self.seq, v);
        }
        if matches!(self.delay, Delay::Obsolete { .. }) && holder_frame(&w) && self.s[to].is_holder() {
            self.withheld.push((self.now, self.seq, to, back, w));
            return;
        }
        self.q.push(Reverse((self.now + d, self.seq, to, back, w)));
    }

    /// Transmit `w` from member `u` on link `l` (the home or a direct link).
    fn transmit(&mut self, u: usize, l: LinkId, w: Wire, legacy_via: Option<usize>) {
        if l == HOME {
            let targets: Vec<usize> = match (self.home_mode, w.frame.to.as_deref()) {
                (HomeMode::ToOnly, Some(t)) => self.home.iter().copied().filter(|j| self.ids[*j] == t).collect(),
                _ => self.home.iter().copied().filter(|j| *j != u).collect(),
            };
            for j in targets {
                if j != u {
                    self.enqueue(u, j, HOME, w.clone(), legacy_via);
                }
            }
        } else {
            let (_, v) = self.links[&l];
            let back = self.link_of[&(v, u)];
            self.enqueue(u, v, back, w, legacy_via);
        }
    }

    fn input(&mut self, i: usize, input: Input) {
        let before = self.s[i].clone();
        let delivered = match &input {
            Input::Frame { frame, .. } | Input::LegacyEvidence { frame, .. } => Some(frame.clone()),
            _ => None,
        };
        let wkey = match &input {
            Input::Frame { key: Some(k), n: Some(n), .. } => Some((k.clone(), *n)),
            _ => None,
        };
        let is_tick = matches!(input, Input::Tick);
        let outs = self.s[i].handle(input, self.now);
        let id = self.ids[i].clone();
        if is_tick && !outs.is_empty() && before.next_deadline().is_none_or(|d| d > self.now) {
            self.violation.get_or_insert(format!(
                "t={} next_deadline {:?} missed a timer of {id}: {outs:?}",
                self.now,
                before.next_deadline()
            ));
        }
        // G6 applies to a frame the member accepts: addressed to it or to no one, and through
        // §S3 (a hello may open its own window; any other frame needs one open already).
        let accepted = delivered.as_ref().is_some_and(|f| {
            f.to.as_ref().is_none_or(|t| *t == id)
                && wkey.as_ref().is_none_or(|(k, n)| {
                    let by = if matches!(f.body, Body::Hello { .. }) { &self.s[i] } else { &before };
                    by.window_admits(&f.from, k, *n)
                })
        });
        if let Some(f) = &delivered {
            // A hello is acted on (its `fresh` answered) once it names this member or no one.
            let taken = accepted || (matches!(f.body, Body::Hello { .. }) && f.to.as_ref().is_none_or(|t| *t == id));
            if taken {
                self.log_accepted.push((self.now, i, f.clone()));
            }
        }
        if before.sends_as_holder() != self.s[i].sends_as_holder() {
            self.log_holding.push((self.now, i, self.s[i].sends_as_holder()));
        }
        if let Ticks::Deadline { max } = self.ticks {
            let due = self.s[i].next_deadline().map(|d| d.max(self.now));
            self.tick_at[i] = due.map(|d| d + self.rng.below(max + 1));
        }
        if let Err(e) = check_step_input(&mut self.ghost, &id, &before, &self.s[i], &outs, delivered.as_ref())
            .and_then(|_| match &delivered {
                Some(f) if accepted => check_g6(f, &self.s[i]),
                _ => Ok(()),
            })
        {
            self.violation.get_or_insert(format!("t={} {e}", self.now));
        }
        for o in outs {
            match o {
                Output::Send { frame } => {
                    self.log_sent.push((self.now, i, frame.clone()));
                    self.n[i] += 1;
                    let w = Wire { key: format!("k-{id}"), n: self.n[i], frame };
                    self.sent.insert(w.frame.clone(), (w.key.clone(), w.n));
                    for (l, w) in self.b[i].send(w) {
                        self.transmit(i, l, w, None);
                    }
                }
                Output::Forward { to, frame } => {
                    // Revision 6 evidence (regression presets only): to a direct peer or over
                    // the home, as the origin's frame.
                    let t = self.ids.iter().position(|x| *x == to).unwrap();
                    if let Some((key, n)) = self.sent.get(&frame).cloned() {
                        let w = Wire { key, n, frame };
                        if let Some(l) = self.link_of.get(&(i, t)).copied() {
                            self.transmit(i, l, w, Some(i));
                        } else if self.home.contains(&i) && self.home.contains(&t) {
                            self.enqueue(i, t, HOME, w, Some(i));
                        }
                    }
                }
                Output::Persist { .. } => self.persists += 1,
                Output::Event { event: colophon_core::v06::session::Event::BecameHolder { .. } } => {
                    self.became.push((self.now, i));
                }
                Output::Event { .. } => {}
            }
        }
    }

    fn deliver(&mut self, seq: u64, to: usize, back: LinkId, w: Wire) {
        let legacy = self.legacy.remove(&seq);
        let r = self.b[to].receive_at(back, w, true, Some(self.now));
        for (l, fw) in r.forward {
            self.transmit(to, l, fw, None);
        }
        if let Some(w) = r.deliver {
            let input = match legacy {
                Some(v) => Input::LegacyEvidence { frame: w.frame, writer: true, via: self.ids[v].clone(), windowed: true },
                None if self.keyed => Input::Frame { frame: w.frame, writer: true, key: Some(w.key), n: Some(w.n) },
                None => Input::Frame { frame: w.frame, writer: true, key: None, n: None },
            };
            self.input(to, input);
        }
    }

    /// Advance to `until`, delivering frames and ticking every member every 250 ms.
    /// Release withheld holder frames whose claim is obsolete or whose delay reached the cap
    /// (all of them once the adversary has stopped).
    fn release_withheld(&mut self) {
        if self.withheld.is_empty() {
            return;
        }
        let cap = match self.delay {
            Delay::Obsolete { cap, .. } => Some(cap),
            _ => None,
        };
        let best = self.s.iter().filter_map(|x| x.accepted().cloned()).max();
        let now = self.now;
        let (go, keep): (Vec<Event>, Vec<Event>) = std::mem::take(&mut self.withheld).into_iter().partition(|(at, _, _, _, w)| {
            cap.is_none_or(|c| now >= at + c) || w.frame.body.claim().zip(best.as_ref()).is_some_and(|(c, b)| c < b)
        });
        self.withheld = keep;
        for (_, seq, to, back, w) in go {
            self.q.push(Reverse((now, seq, to, back, w)));
        }
    }

    fn run(&mut self, until: u64) {
        while self.now < until {
            self.release_withheld();
            let (next_tick, who) = match self.ticks {
                Ticks::Every => ((self.now / TICK + 1) * TICK, None),
                Ticks::Deadline { .. } => {
                    let best = (0..self.s.len()).filter_map(|i| self.tick_at[i].map(|t| (t.max(self.now), i))).min();
                    match best {
                        Some((t, i)) => (t, Some(i)),
                        None => (until, None),
                    }
                }
            };
            let next_tick = if who.is_some() { next_tick.min(until.max(self.now)) } else { next_tick };
            match self.q.peek() {
                Some(Reverse((t, ..))) if *t < next_tick => {
                    let Reverse((t, seq, to, back, w)) = self.q.pop().unwrap();
                    self.now = self.now.max(t);
                    self.deliver(seq, to, back, w);
                }
                _ => {
                    self.now = next_tick;
                    match (self.ticks, who) {
                        (Ticks::Every, _) => {
                            for i in 0..self.s.len() {
                                self.input(i, Input::Tick);
                            }
                        }
                        (Ticks::Deadline { .. }, Some(i)) if self.tick_at[i].is_some_and(|t| t <= self.now) => {
                            self.tick_at[i] = None;
                            self.input(i, Input::Tick);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn set_ticks(&mut self, ticks: Ticks) {
        self.ticks = ticks;
        for i in 0..self.s.len() {
            self.tick_at[i] = self.s[i].next_deadline().map(|d| d.max(self.now));
        }
    }
    fn join_all(&mut self) {
        for i in 0..self.s.len() {
            self.input(i, Input::App { command: Command::Join { state: None } });
        }
    }
    /// Groups become one: every member's carriers reconnect (link-up hellos).
    fn merge(&mut self) {
        for g in self.group.iter_mut() {
            *g = 0;
        }
        self.log_membership.push(self.now);
        for i in 0..self.s.len() {
            self.input(i, Input::LinkDown);
            self.input(i, Input::LinkUp);
        }
    }

    /// The timely oracle (§S0, revision 12) over this run's trace up to `end`: the earliest
    /// T from which (1) membership does not change, (2) in every interval of
    /// L = holderTimeoutMs − beatMs every member accepts a holder frame from each member
    /// acting as holder throughout it, and (3) every `hello`, `state`, `take`, `pass`,
    /// `yielded`, `ack` and `bye` sent at or after T is accepted by each member it concerns
    /// within L of its first send (resends of the same frame count). `None`: no such T up to
    /// `end`. Intervals that would reach past `end` are not judged.
    fn timely_from(&self, end: u64) -> Option<u64> {
        self.timely_report(end).0
    }
    /// As `timely_from`, with the constraint that set T.
    fn timely_report(&self, end: u64) -> (Option<u64>, String) {
        let p = Policy::default();
        let mut why = String::from("membership");
        let l = p.holder_timeout_ms - p.beat_ms;
        let n = self.s.len();
        let mut t = self.log_membership.iter().copied().max().unwrap_or(0);
        // (2) Holding intervals per member.
        let mut spans: Vec<(usize, u64, u64)> = Vec::new();
        let mut open: Vec<Option<u64>> = vec![None; n];
        for &(at, i, on) in &self.log_holding {
            match (on, open[i]) {
                (true, None) => open[i] = Some(at),
                (false, Some(a)) => {
                    spans.push((i, a, at));
                    open[i] = None;
                }
                _ => {}
            }
        }
        for (i, a) in open.iter().enumerate() {
            if let Some(a) = a {
                spans.push((i, *a, end));
            }
        }
        for &(h, a, b) in &spans {
            for m in (0..n).filter(|m| *m != h) {
                let mut points = vec![a];
                points.extend(
                    self.log_accepted
                        .iter()
                        .filter(|(at, to, f)| *to == m && f.from == self.ids[h] && *at >= a && *at <= b && counts_as_holder(&f.body))
                        .map(|(at, ..)| *at),
                );
                points.push(b);
                for w in points.windows(2) {
                    if w[1] - w[0] > l && w[1] - l > t {
                        t = w[1] - l;
                        why = format!("condition 2: {} accepted no holder frame from {} between {} and {} ms", self.ids[m], self.ids[h], w[0], w[1]);
                    }
                }
            }
        }
        // (3) Control frames, by first send. `yielded`, `pass` and `bye` are resent by rule
        // until answered, so a resend is the same frame; every other send stands alone.
        let mut first: BTreeMap<(usize, Option<String>, String, usize), u64> = BTreeMap::new();
        for (k, (at, i, f)) in self.log_sent.iter().enumerate() {
            if control_frame(&f.body) {
                let resent = matches!(f.body, Body::Yielded { .. } | Body::Pass { .. } | Body::Bye { .. });
                let key = (*i, f.to.clone(), format!("{:?}", f.body), if resent { 0 } else { k });
                first.entry(key).or_insert(*at);
            }
        }
        for ((i, to, body, _), s0) in &first {
            if s0 + l > end {
                continue;
            }
            let concerned: Vec<usize> = match to {
                Some(x) => self.ids.iter().position(|y| y == x).into_iter().collect(),
                None => (0..n).filter(|m| m != i).collect(),
            };
            for m in concerned {
                let got = self.log_accepted.iter().find(|(at, to2, f)| {
                    *to2 == m && *at >= *s0 && f.from == self.ids[*i] && f.to == *to && format!("{:?}", f.body) == *body
                });
                if got.is_none_or(|(at, ..)| at - s0 > l) && s0 + 1 > t {
                    t = s0 + 1;
                    why = format!(
                        "condition 3: {} from {} at {s0} ms not accepted by {} within {l} ms ({:?})",
                        body.split(' ').next().unwrap_or(""),
                        self.ids[*i],
                        self.ids[m],
                        got.map(|(at, ..)| *at)
                    );
                }
            }
        }
        ((t <= end).then_some(t), why)
    }

    /// The premise, then the conclusion. Runs `window` more ms, then asks the oracle. If the
    /// group was timely from some T early enough (T + SETTLE ≤ the window's start):
    /// G4 (one group), G10 over the window and G11 must hold, `Ok(Some(T))`. Otherwise
    /// `Ok(None)`: convergence is not promised and only safety is checked.
    fn check_timely_end(&mut self, window: u64) -> Result<Option<u64>, String> {
        if let Some(v) = &self.violation {
            return Err(format!("safety: {v}"));
        }
        let start = self.now;
        let end = self.now + window;
        self.persists = 0;
        self.run(end);
        if let Some(v) = &self.violation {
            return Err(format!("safety: {v}"));
        }
        let from = self.timely_from(end).filter(|t| t + SETTLE <= start);
        let Some(from) = from else {
            return Ok(None);
        };
        self.check_conclusion(window).map_err(|e| format!("timely from {from} ms, yet {e}"))?;
        Ok(Some(from))
    }
    /// As `check_timely_end`, requiring the premise.
    fn expect_timely(&mut self, window: u64) -> Result<u64, String> {
        self.check_timely_end(window)?
            .ok_or_else(|| format!("the oracle finds the run not timely: {:?}", self.timely_report(self.now)))
    }
    /// The conclusion only, over the last `window` ms (no premise checked).
    fn check_conclusion(&self, window: u64) -> Result<(), String> {
        if self.persists > 0 {
            return Err(format!("G10: {} claim changes in the last {window} ms", self.persists));
        }
        check_converged(&self.s)?;
        if let Some((t, d, c)) = self.ghost.owed.iter().next() {
            return Err(format!("G11: {d}'s state under {} never reported (taker {t})", show_claim(c)));
        }
        Ok(())
    }
}

/// Members `0..n` in `groups` (each group's first member takes before the merge), all on one
/// home; merge at 20 s, then `delay` for the rest.
fn merged_home(n: usize, groups: &[Vec<usize>], delay: Delay, loss: u64, seed: u64) -> Net {
    let home: Vec<usize> = (0..n).collect();
    let mut net = Net::new(n, &home, &[], Fixes::ALL, true, seed);
    for (g, members) in groups.iter().enumerate() {
        for m in members {
            net.group[*m] = g as u32 + 1;
        }
    }
    net.join_all();
    for members in groups {
        let h = members[0];
        let st = Some(Bytes(format!("S{h}").into_bytes()));
        net.input(h, Input::App { command: Command::Take { state: st } });
    }
    net.run(20_000);
    net.delay = delay;
    net.loss = loss;
    net.merge();
    net
}

fn groups_of(n: usize, k: usize) -> Vec<Vec<usize>> {
    (0..k).map(|g| (0..n).filter(|i| i % k == g).collect()).collect()
}

/// (b, c-i) The home carrier, 2–5 members, groups that each hold merging, then delivery
/// within D ≤ beatMs: random loss (0 or 10 %) or adversarial consecutive loss of holder frames
/// (1 or 2 in a row between every pair). The oracle decides whether each run is timely; every
/// timely run must converge (G4, G10, G11), every run must be safe, and the loss-free runs
/// must all be timely.
#[test]
fn home_timely_converges() {
    let seeds = std::env::var("COLOPHON_CARRIER_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(20u64);
    let mut tally: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for n in 2..=5usize {
        for k in 1..=n.min(3) {
            for d in [0u64, 1_000, 2_500, 5_000] {
                for (name, loss, burst) in [("none", 0u64, 0u64), ("10 %", 100, 0), ("burst 1", 0, 1), ("burst 2", 0, 2)] {
                    for seed in 1..=seeds {
                        let mut net = merged_home(n, &groups_of(n, k), Delay::Uniform(d), loss, seed);
                        net.burst = burst;
                        net.run(120_000);
                        let v = net.check_timely_end(60_000).unwrap_or_else(|e| {
                            panic!("n={n} groups={k} D={d} loss={name} seed={seed}: {e}")
                        });
                        if loss == 0 && burst == 0 {
                            assert!(v.is_some(), "n={n} groups={k} D={d} seed={seed}: a loss-free run is not timely");
                        }
                        let e = tally.entry(name.to_string()).or_default();
                        e.0 += 1;
                        e.1 += u64::from(v.is_some());
                    }
                }
            }
        }
    }
    for (name, (runs, timely)) in &tally {
        println!("home, loss {name}: {runs} runs, {timely} timely (all of those converge), all safe");
    }
}

/// The review's trace, deterministic: two or three members on one home, the first holding,
/// the others wanting the role (taking when the holder lapses), holder frames between every pair lost
/// `burst` in a row (the next delivered), delay up to `jitter` ms. Returns the oracle's
/// verdict, the number of claim changes in the last 100 s and whether it converged.
fn lost_beats(n: usize, burst: u64, jitter: u64, seed: u64) -> (Option<u64>, u64, bool) {
    let home: Vec<usize> = (0..n).collect();
    let mut net = Net::new(n, &home, &[], Fixes::ALL, true, seed);
    net.delay = Delay::Uniform(jitter);
    net.join_all();
    net.run(1_000);
    net.input(0, Input::App { command: Command::Take { state: Some(Bytes(b"A".to_vec())) } });
    net.run(5_000);
    net.burst = burst;
    net.log_membership.push(net.now);
    for _ in 0..60 {
        // An application that always wants the role once the holder lapses (`take` with a
        // live holder waits for the lapse, §S5), and asks for it again whenever not holding.
        want_all(&mut net);
        let t = net.now + 5_000;
        net.run(t);
    }
    assert!(net.violation.is_none(), "burst {burst}: {:?}", net.violation);
    net.persists = 0;
    for _ in 0..20 {
        want_all(&mut net);
        let t = net.now + 5_000;
        net.run(t);
    }
    assert!(net.violation.is_none(), "burst {burst}: {:?}", net.violation);
    let end = net.now;
    let timely = net.timely_from(end).filter(|t| t + SETTLE <= end - 100_000);
    let converged = net.persists == 0 && check_converged(&net.s).is_ok();
    (timely, net.persists, converged)
}

fn want_all(net: &mut Net) {
    for i in 0..net.s.len() {
        if !net.s[i].is_holder() && !net.s[i].pending() {
            net.input(i, Input::App { command: Command::Take { state: None } });
        }
    }
}

/// (1) Consecutive lost beats at the timeout boundary. One lost beat in a row: accepted
/// holder frames every 10 s = holderTimeoutMs − beatMs, so without jitter the oracle finds
/// the run timely, and it converges (with jitter some gaps exceed 10 s and the oracle
/// rejects those runs, which still converge). Two in a row: accepted frames 15 s apart, which condition 2 of §S0
/// rejects (the oracle says not timely), and with any jitter the listener lapses the holder
/// at the boundary and takes: the review's cycle. Three: not timely, the cycle every time.
/// Safety holds in all of them.
#[test]
fn consecutive_lost_beats() {
    for n in [2usize, 3] {
        for burst in [1u64, 2, 3] {
            for jitter in [0u64, 1_000] {
                let mut timely_runs = 0;
                let mut cycling = 0;
                let mut settled = 0;
                for seed in 1..=10 {
                    let (timely, changes, converged) = lost_beats(n, burst, jitter, seed);
                    settled += u64::from(converged);
                    if let Some(t) = timely {
                        timely_runs += 1;
                        assert!(converged, "n={n} burst={burst} jitter={jitter} seed={seed}: timely from {t} ms but {changes} claim changes");
                    }
                    cycling += u64::from(changes > 0);
                }
                println!("{n} members, {burst} holder frames lost in a row, jitter {jitter} ms: {timely_runs}/10 timely, {cycling}/10 still changing claims, {settled}/10 converged");
                match (burst, jitter) {
                    (1, 0) => assert_eq!(timely_runs, 10, "one lost beat in a row, no jitter, is within §S0"),
                    // With jitter the 10 s gaps vary around L: the oracle decides per run.
                    (1, _) => {}
                    _ => assert_eq!(timely_runs, 0, "{burst} lost in a row is outside condition 2"),
                }
                if burst == 3 && n == 2 {
                    assert!(cycling > 0, "three lost in a row should show the cycle");
                }
            }
        }
    }
}

/// The lapse boundary (§S6: lapsed when no holder frame was accepted for holderTimeoutMs,
/// i.e. `now − last ≥ holderTimeoutMs`). A frame accepted exactly at the deadline, before the
/// timer input at that instant, keeps the holder live; the timer input first lapses it (G9:
/// the order of the member's own inputs decides). One ms earlier it is not lapsed.
#[test]
fn lapse_boundary() {
    let ids = ["a", "b"];
    let mk = |id: &str| Session::new(id, true, Policy::default(), None).with_entitled(ids);
    let (mut a, mut b) = (mk("a"), mk("b"));
    let lapsed = |o: &[Output]| o.iter().any(|o| matches!(o, Output::Event { event: colophon_core::v06::session::Event::HolderLapsed { .. } }));
    let deliver = |to: &mut Session, outs: Vec<Output>, at: u64| -> Vec<Output> {
        outs.into_iter()
            .filter_map(|o| match o {
                Output::Send { frame } => Some(frame),
                _ => None,
            })
            .flat_map(|frame| to.handle(Input::Frame { frame, writer: true, key: None, n: None }, at))
            .collect()
    };
    a.handle(Input::App { command: Command::Join { state: None } }, 0);
    b.handle(Input::App { command: Command::Join { state: None } }, 0);
    let outs = a.handle(Input::App { command: Command::Take { state: None } }, 0);
    deliver(&mut b, outs, 1_000);
    assert_eq!(b.holder(), Some("a"));
    let h = Policy::default().holder_timeout_ms;
    // One ms before: not lapsed.
    let mut b1 = b.clone();
    assert!(!lapsed(&b1.handle(Input::Tick, 1_000 + h - 1)));
    assert_eq!(b1.next_deadline(), Some(1_000 + h));
    // At the deadline, timer first: lapsed.
    let mut b2 = b.clone();
    assert!(lapsed(&b2.handle(Input::Tick, 1_000 + h)));
    // At the deadline, the holder's beat first: live.
    let mut b3 = b.clone();
    let beat = a.handle(Input::Tick, 1_000 + h - 2);
    deliver(&mut b3, beat, 1_000 + h);
    assert!(!lapsed(&b3.handle(Input::Tick, 1_000 + h)));
    assert_eq!(b3.next_deadline(), Some(1_000 + 2 * h));
}

/// G5 (revision 12): a writer becomes holder within askTimeoutMs of asking, or
/// holderTimeoutMs of the holder's last accepted frame, plus at most 250 ms of timer
/// dispatch. Members tick only at `next_deadline` plus a random dispatch delay of up to
/// 250 ms (and, separately, every 250 ms); the bound is asserted exactly.
#[test]
fn g5_exact_bounds() {
    let p = Policy::default();
    for ticks in [Ticks::Deadline { max: 250 }, Ticks::Deadline { max: 0 }, Ticks::Every] {
        let mut worst = (0u64, 0u64);
        for seed in 1..=40 {
            // Ask trigger: the holder (0) is cut off, then 1 asks.
            let mut net = Net::new(3, &[0, 1, 2], &[], Fixes::ALL, true, seed);
            net.set_ticks(ticks);
            net.delay = Delay::Uniform(50);
            net.join_all();
            net.run(1_000);
            net.input(0, Input::App { command: Command::Take { state: None } });
            net.run(20_000);
            net.group[0] = 9;
            net.run(20_500);
            let asked = net.now;
            net.became.clear();
            net.input(1, Input::App { command: Command::Ask });
            net.run(asked + p.ask_timeout_ms + 1_000);
            let took = net.became.iter().find(|(_, i)| *i == 1).map(|(t, _)| *t);
            let took = took.unwrap_or_else(|| panic!("{ticks:?} seed {seed}: 1 never took after asking"));
            assert!(took - asked <= p.ask_timeout_ms + 250, "{ticks:?} seed {seed}: took {} ms after asking", took - asked);
            worst.0 = worst.0.max(took - asked);
            assert!(net.violation.is_none(), "{:?}", net.violation);

            // Lapse trigger: 2 wants the role while 1 holds (`take` waits for the lapse), then
            // 1 is cut off.
            net.input(2, Input::App { command: Command::Take { state: None } });
            net.run(net.now + 3_000);
            net.group[1] = 8;
            let cut = net.now;
            net.became.clear();
            net.run(cut + p.holder_timeout_ms + 2_000);
            let last = net
                .log_accepted
                .iter()
                .filter(|(_, to, f)| *to == 2 && f.from == net.ids[1] && counts_as_holder(&f.body))
                .map(|(t, ..)| *t)
                .max()
                .unwrap();
            let took = net.became.iter().find(|(_, i)| *i == 2).map(|(t, _)| *t);
            let took = took.unwrap_or_else(|| panic!("{ticks:?} seed {seed}: 2 never took after the lapse"));
            assert!(took - last <= p.holder_timeout_ms + 250, "{ticks:?} seed {seed}: took {} ms after the last frame", took - last);
            worst.1 = worst.1.max(took - last);
            assert!(net.violation.is_none(), "{:?}", net.violation);
        }
        println!("G5 with {ticks:?}: worst {} ms after asking (bound {}), {} ms after the last holder frame (bound {})", worst.0, p.ask_timeout_ms + 250, worst.1, p.holder_timeout_ms + 250);
    }
}

/// Deadline-driven timers run the home profile as well as a 250 ms poll does.
#[test]
fn deadline_ticks_converge() {
    for n in [2usize, 3, 5] {
        for seed in 1..=10 {
            let mut net = merged_home(n, &groups_of(n, 2.min(n)), Delay::Uniform(1_000), 0, seed);
            net.set_ticks(Ticks::Deadline { max: 250 });
            net.run(120_000);
            net.expect_timely(60_000).unwrap_or_else(|e| panic!("n={n} seed={seed}: {e}"));
        }
    }
}

/// The review's merge: {A, X} and {Y, B}, A and B holding, on one home, then `delay`.
fn review_merge(delay: Delay, seed: u64) -> Net {
    let mut net = merged_home(4, &[vec![0, 1], vec![3, 2]], delay, 0, seed);
    net.run(200_000);
    net
}

/// Whether the review's merge converges under `delay` (G4 and G10 over 60 s, 10 seeds);
/// safety is asserted throughout, and once delivery becomes timely again the group converges
/// and every displaced state is reported.
fn converges_under(delay: Delay) -> bool {
    let mut all_ok = true;
    for seed in 1..=10 {
        let mut net = review_merge(delay, seed);
        assert!(net.violation.is_none(), "safety broken under {delay:?}: {:?}", net.violation);
        net.persists = 0;
        net.run(net.now + 60_000);
        assert!(net.violation.is_none(), "safety broken under {delay:?}: {:?}", net.violation);
        if net.persists > 0 || check_converged(&net.s).is_err() {
            all_ok = false;
        }
        net.delay = Delay::Uniform(100);
        net.run(net.now + 60_000);
        net.expect_timely(60_000).unwrap_or_else(|e| panic!("{delay:?} seed={seed} after timely: {e}"));
    }
    all_ok
}

/// (c) Adversarial delay on the review's merge. A constant delay on holder frames (any size)
/// keeps them `beatMs` apart and converges. Holding holder frames back and releasing them
/// together every `period` ms (prompt hellos meanwhile) converges while `period` stays below
/// holderTimeoutMs, and renews forever beyond it: the review's trace, outside the timely
/// condition of §S0. Safety holds in every run; timely delivery afterwards converges.
#[test]
fn adversarial_delay_sweep() {
    for late in [5_000u64, 15_000, 30_000, 60_000] {
        let ok = converges_under(Delay::HolderLate { late, prompt: 50 });
        println!("holder frames a constant {late} ms late: converges {ok}");
        assert!(ok, "a constant delay should not stop convergence");
    }
    for period in [5_000u64, 15_000, 30_000] {
        let ok = converges_under(Delay::HolderBatch { period, prompt: 50 });
        println!("holder frames released together every {period} ms: converges {ok}");
    }
    let mut largest_ok = 0u64;
    let mut first_bad = None;
    let caps = [2_500u64, 5_000, 10_000, 15_000, 15_500, 16_000, 16_500, 17_000, 17_500, 20_000, 30_000];
    for cap in caps {
        let ok = converges_under(Delay::Obsolete { cap, prompt: 50 });
        println!("holder frames withheld until obsolete, at most {cap} ms: converges {ok}");
        if ok && first_bad.is_none() {
            largest_ok = cap;
        } else if !ok && first_bad.is_none() {
            first_bad = Some(cap);
        }
    }
    println!("largest maximum delay D that converged: {largest_ok} ms; first failing: {first_bad:?}");
    let beat = Policy::default().beat_ms;
    assert!(largest_ok >= beat, "convergence failed for D within beatMs: a finding against revision 10");
    let bad = first_bad.expect("the renew-forever trace should reproduce beyond holderTimeoutMs");
    assert!(bad > Policy::default().holder_timeout_ms, "renewal beyond holderTimeoutMs only");
}

/// (c-i) Uniform random delay up to D after the merge, D from 0 to beatMs.
#[test]
fn uniform_delay_within_beat_converges() {
    for d in [500u64, 2_500, 5_000] {
        for seed in 1..=20 {
            let mut net = merged_home(4, &[vec![0, 1], vec![3, 2]], Delay::Uniform(d), 0, seed);
            net.run(120_000);
            net.expect_timely(60_000).unwrap_or_else(|e| panic!("D={d} seed={seed}: {e}"));
        }
    }
}

/// (d) The review's hybrid topology: A and C on a home, B linked to C directly and not on the
/// home, C bridging. Under "home forwards an addressed frame only to `to`", A's echo to B never
/// reaches C to be bridged, so B never opens a window for A and never follows A. Under
/// revision 10's broadcast rule it does.
fn hybrid(mode: HomeMode, seed: u64) -> (bool, bool) {
    // 0 = A, 1 = B, 2 = C.
    let mut net = Net::new(3, &[0, 2], &[(1, 2)], Fixes::ALL, true, seed);
    net.home_mode = mode;
    net.delay = Delay::Uniform(200);
    net.join_all();
    net.run(1_000);
    net.input(0, Input::App { command: Command::Take { state: Some(Bytes(b"A".to_vec())) } });
    net.run(120_000);
    let a = net.ids[0].clone();
    (net.s[1].windows_for(&a) > 0, net.s[1].accepted().is_some_and(|c| c.holder == a))
}

#[test]
fn hybrid_topology_needs_broadcast() {
    for seed in 1..=10 {
        let (win, follows) = hybrid(HomeMode::ToOnly, seed);
        assert!(!win && !follows, "seed {seed}: to-only routing should strand B");
        let (win, follows) = hybrid(HomeMode::Broadcast, seed);
        assert!(win && follows, "seed {seed}: broadcast routing should reach B");
    }
}

/// (e) Three and four groups, each with its own holder, merge under timely delivery: one
/// holder remains and every displaced state is reported.
#[test]
fn multi_group_merges() {
    for (n, k) in [(3usize, 3usize), (4, 4), (5, 3), (6, 4)] {
        for seed in 1..=20 {
            let mut net = merged_home(n, &groups_of(n, k), Delay::Uniform(1_000), 0, seed);
            net.run(90_000);
            net.expect_timely(60_000).unwrap_or_else(|e| panic!("{k} groups of {n} seed {seed}: {e}"));
        }
    }
}

/// (f) Freshness over a slow path: round trips of 10 s and 50 s open the window, 70 s does
/// not (an echo is honoured only of a `fresh` sent within 60 s); nothing unsafe meanwhile.
#[test]
fn freshness_slow_path() {
    for (rtt, opens) in [(10_000u64, true), (50_000, true), (70_000, false)] {
        let mut net = Net::new(2, &[0, 1], &[], Fixes::ALL, true, 1);
        net.delay = Delay::Fixed(rtt / 2);
        net.join_all();
        net.input(0, Input::App { command: Command::Take { state: None } });
        net.run(400_000);
        assert!(net.violation.is_none(), "rtt {rtt}: {:?}", net.violation);
        let a = net.ids[0].clone();
        let b = net.ids[1].clone();
        let open = net.s[1].windows_for(&a) > 0 && net.s[0].windows_for(&b) > 0;
        assert_eq!(open, opens, "round trip {rtt} ms: windows open {open}");
        println!("freshness round trip {rtt} ms: windows open {open}");
    }
    // Five members: every hello carries a new `fresh`, and a member answers or probes each
    // peer, so it may send more than 32 hellos within one slow round trip.
    for rtt in [10_000u64, 30_000, 50_000] {
        let mut net = Net::new(5, &[0, 1, 2, 3, 4], &[], Fixes::ALL, true, 1);
        net.delay = Delay::Fixed(rtt / 2);
        net.join_all();
        net.input(0, Input::App { command: Command::Take { state: None } });
        net.run(400_000);
        assert!(net.violation.is_none(), "rtt {rtt}: {:?}", net.violation);
        let pairs = (0..5)
            .flat_map(|i| (0..5).map(move |j| (i, j)))
            .filter(|(i, j)| i != j && net.s[*i].windows_for(&net.ids[*j]) > 0)
            .count();
        let r = check_converged(&net.s);
        println!("five members, round trip {rtt} ms: {pairs}/20 windows open, converged {r:?}");
        assert_eq!(pairs, 20, "round trip {rtt} ms with five members");
    }
}

/// Chains of direct links with bridging, holders at both ends (revision 7's check, now with
/// real freshness and per-frame delays across timeouts).
/// `Ok(Some(T))` when the oracle finds the run timely (and it converged), `Ok(None)` when it
/// does not, though the run converged anyway.
fn ends_hold(n: usize, edges: &[(usize, usize)], delay: Delay, lossy: bool) -> Result<Option<u64>, String> {
    let mut net = Net::new(n, &[], edges, Fixes::ALL, true, 7);
    for i in 0..n {
        net.group[i] = if i < n / 2 { 1 } else { 2 };
    }
    net.join_all();
    net.input(0, Input::App { command: Command::Take { state: Some(Bytes(b"A".to_vec())) } });
    net.input(n - 1, Input::App { command: Command::Take { state: Some(Bytes(b"Z".to_vec())) } });
    net.run(20_000);
    net.delay = delay;
    if lossy {
        net.loss = 300;
    }
    net.merge();
    net.run(150_000);
    net.loss = 0;
    net.run(200_000);
    let v = net.check_timely_end(80_000)?;
    // Beyond the premise: the conclusion held in every run so far; keep it as a regression.
    net.check_conclusion(80_000).map_err(|e| format!("not timely, and {e}"))?;
    Ok(v)
}

/// The second review's trace kept as a regression: four-member chain, revision 6 (one-hop
/// evidence) without bridging fails G10; revision 10 with bridging settles on chains of 3, 4
/// and 5, a ring and a star, through real freshness, with 30 % loss for a while, then delays of
/// 100 ms per hop (timely by the oracle) or up to 5 s per hop (the oracle decides; they converge).
#[test]
fn chains_with_bridging() {
    // Revision 6 has no bridging in its model: switch every bridge off.
    let edges: Vec<(usize, usize)> = (0..3).map(|i| (i, i + 1)).collect();
    let mut net = Net::new(4, &[], &edges, Fixes::REV6, false, 7);
    for (i, b) in net.b.iter_mut().enumerate() {
        *b = Bridge::without_bridging(&net.ids[i]);
        for &(a, c) in &edges {
            if a == i {
                b.add_link(net.link_of[&(a, c)]);
            }
            if c == i {
                b.add_link(net.link_of[&(c, a)]);
            }
        }
    }
    for i in 0..4 {
        net.group[i] = if i < 2 { 1 } else { 2 };
    }
    net.join_all();
    net.input(0, Input::App { command: Command::Take { state: None } });
    net.input(3, Input::App { command: Command::Take { state: None } });
    net.run(20_000);
    net.delay = Delay::Uniform(100);
    net.merge();
    net.run(120_000);
    // No premise here: the unbridged chain is not one group (the oracle rejects it), and the
    // test shows the conclusion failing.
    net.persists = 0;
    let t = net.now + 80_000;
    net.run(t);
    assert!(net.timely_from(net.now).is_none_or(|x| x + SETTLE > net.now - 80_000), "the oracle should reject an unbridged chain");
    let r = net.check_conclusion(80_000);
    println!("revision 6, unbridged chain of 4: {r:?}");
    assert!(r.is_err_and(|e| e.starts_with("G10")), "revision 6 should renew forever on the chain");
    let chain = |n: usize| (0..n - 1).map(|i| (i, i + 1)).collect::<Vec<_>>();
    let ring = |n: usize| (0..n).map(|i| (i, (i + 1) % n)).collect::<Vec<_>>();
    let star = |n: usize| (1..n).map(|i| (0, i)).collect::<Vec<_>>();
    let cases = [("chain3", 3, chain(3)), ("chain4", 4, chain(4)), ("chain5", 5, chain(5)), ("ring5", 5, ring(5)), ("star5", 5, star(5))];
    for (name, n, edges) in cases {
        for lossy in [false, true] {
            // 100 ms per hop: timely over every path here.
            let v = ends_hold(n, &edges, Delay::Uniform(100), lossy).unwrap_or_else(|e| panic!("{name} lossy={lossy}: {e}"));
            assert!(v.is_some(), "{name} lossy={lossy}: 100 ms per hop should be timely");
            // Up to 5 s per hop: across two or more hops a beat may arrive more than
            // holderTimeoutMs − beatMs after the last, so the oracle decides.
            let v = ends_hold(n, &edges, Delay::Uniform(5_000), lossy).unwrap_or_else(|e| panic!("{name} 5 s lossy={lossy}: {e}"));
            println!("{name}, up to 5 s per hop, lossy {lossy}: timely {}", v.is_some());
        }
    }
}

/// (c-ii) The review's renew-forever trace, shown: holder frames withheld from the rival
/// holder for up to 60 s (beyond holderTimeoutMs), followers and hellos prompt. Terms grow
/// for as long as the adversary runs; safety holds throughout (checked on every input).
#[test]
fn renew_forever_trace() {
    let mut net = merged_home(4, &[vec![0, 1], vec![3, 2]], Delay::Obsolete { cap: 60_000, prompt: 50 }, 0, 1);
    let mut terms = Vec::new();
    for _ in 0..12 {
        let t = net.now + 15_000;
        net.run(t);
        let cl: Vec<String> = net
            .s
            .iter()
            .map(|x| format!("{}{}", x.accepted().map(show_claim).unwrap_or_default(), if x.is_holder() { "*" } else { "" }))
            .collect();
        println!("t={:>6} {}", net.now, cl.join(" "));
        terms.push(net.s.iter().filter_map(|x| x.accepted().map(|c| c.term)).max().unwrap_or(0));
    }
    assert!(net.violation.is_none(), "{:?}", net.violation);
    let first = terms[1];
    let last = terms[terms.len() - 1];
    assert!(last >= first + 3, "terms should keep growing under the adversary: {terms:?}");
}
