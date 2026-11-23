//! Seeded deterministic simulation of 0.6 sessions (§S4–§S9, §S12) in virtual time.
//!
//! Each member has its own clock (offset and drift in ppm from virtual time). Each directed
//! link uses the best working carrier: a slow "home" carrier and, in some seeds, a fast
//! "direct" one, each with its own latency, jitter, loss and duplication; jitter reorders.
//! Some seeds apply the §S3 (revision 2) per-key `n` window: duplicates and frames more than
//! 128 below the highest are dropped, reordering inside the window is delivered.
//! Partitions isolate members (their link goes down) and heal; members restart from their
//! persisted claim.
//!
//! Checked continuously: G1, G2, G3, G6 (`v06_session_support`). At the end every partition
//! heals and the network becomes lossless: G4 (one holder, one ordered state). The §S12
//! playback handoff is the workload: the holder publishes anchors; members ping the holder;
//! a pass must start the new holder exactly at the passer's stopped position; a take must
//! start within `ratePermille × (offset error bound + drift × age of the samples) + 3 ms` of where the
//! unreachable holder actually is; a returning lapsed holder yields and pauses.
//!
//! `COLOPHON_SIM_SEEDS=n` runs n random seeds (default 300); `COLOPHON_SIM_SEED=s` runs one.
#![allow(clippy::unwrap_used)]
mod v06_session_support;
use colophon_core::v06::session::*;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};
use v06_session_support::*;

// ---------------------------------------------------------------------------------------------
// PRNG.

#[derive(Clone)]
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    fn range(&mut self, a: u64, b: u64) -> u64 {
        a + self.below(b - a + 1)
    }
    fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }
}

// ---------------------------------------------------------------------------------------------
// The §S12 anchor (revision 2): `positionMs`, integer `ratePermille`, `playing`, `at`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anchor {
    pos: i64,
    rate: i64,
    playing: bool,
    at: i64,
}
impl Anchor {
    fn encode(&self) -> Bytes {
        let v = serde_json::json!({
            "episode": "e1", "show": "s1", "positionMs": self.pos,
            "ratePermille": self.rate, "playing": self.playing, "at": self.at,
        });
        Bytes(serde_json::to_vec(&v).unwrap())
    }
    fn decode(b: &Bytes) -> Option<Anchor> {
        let v: serde_json::Value = serde_json::from_slice(&b.0).ok()?;
        Some(Anchor {
            pos: v["positionMs"].as_i64()?,
            rate: v["ratePermille"].as_i64()?,
            playing: v["playing"].as_bool()?,
            at: v["at"].as_i64()?,
        })
    }
    /// `positionMs + floor(ratePermille × (now + offset − at) / 1000)` while playing.
    fn project(&self, clock: i64) -> i64 {
        if self.playing {
            self.pos + (self.rate * (clock - self.at)).div_euclid(1000)
        } else {
            self.pos
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The world.

#[derive(Clone, Copy, Debug)]
struct Carrier {
    base: u64,
    jitter: u64,
    loss: u64,
    dup: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::large_enum_variant)]
enum Ev {
    /// `src` is the member that sent it (the forwarder for evidence); `n` 0 marks a
    /// forwarded frame, whose original `n` this model does not track (window bypassed).
    Deliver { to: usize, n: u64, frame: Frame, src: usize },
    Tick(usize),
}

struct Member {
    id: String,
    s: Session,
    off: i64,
    drift: i64,
    /// A clock stall (§S0): from global `start` for `len` ms this member's clock stands still.
    stall: Option<(u64, u64)>,
    up: bool,
    persisted: Option<Persisted>,
    /// §S3 (revision 2): per sender key, the highest `n` and the accepted ones within 128.
    high: BTreeMap<usize, (u64, std::collections::BTreeSet<u64>)>,
    /// The anchor this member plays from when holder, if playing.
    playing: Option<Anchor>,
    /// The last anchor received and the member that anchored it.
    known: Option<(Anchor, String)>,
    /// Global times of the last 8 pongs from each peer.
    pongs: BTreeMap<String, VecDeque<u64>>,
    log: Vec<(u64, Input)>,
}

struct Sim {
    rng: Rng,
    g: u64,
    seq: u64,
    queue: BinaryHeap<Reverse<(u64, u64, Ev)>>,
    m: Vec<Member>,
    carriers: Vec<Carrier>,
    n_filter: bool,
    lossless: bool,
    n: Vec<u64>,
    ghost: Ghost,
    policy: Policy,
    trace: Vec<String>,
    pass_positions: BTreeMap<Claim, i64>,
    stats: Stats,
    record: bool,
    take_failure: Option<String>,
    /// The `n` each frame content was last sent with (forwarded frames keep it).
    last_n: std::collections::HashMap<Frame, u64>,
    pass_rate: u64,
    fixes: Fixes,
    /// Settling: the application stops re-anchoring so the end state can be compared.
    quiet: bool,
}

#[derive(Default, Debug, Clone)]
struct Stats {
    passes: u64,
    takes_checked: u64,
    max_take_error: i64,
    max_take_bound: i64,
    yields: u64,
    delivered: u64,
    /// Messages applied from the early-hold buffer (they arrived before a missing one).
    early_applied: u64,
    /// Evidence frames forwarded (§S4, revision 4).
    forwarded: u64,
    /// Displaced-state and late-pass reports (G11).
    reports: u64,
    /// Forwarded frames delivered.
    forwarded_delivered: u64,
    /// Frames a read-only member injected (revision 15).
    injected: u64,
}

const RATE: i64 = 1250;
const IDS: [&str; 5] = ["0a", "1b", "2c", "3d", "4e"];

impl Sim {
    fn new(seed: u64, members: usize, carriers: Vec<Carrier>, n_filter: bool) -> Self {
        let mut rng = Rng::new(seed);
        let policy = Policy::default();
        let m = (0..members)
            .map(|i| Member {
                id: IDS[i].to_owned(),
                s: Session::new(IDS[i], true, policy.clone(), None).with_entitled(IDS),
                off: rng.range(1_000_000, 1_000_000_000) as i64,
                drift: rng.range(0, 1000) as i64 - 500,
                stall: None,
                up: true,
                persisted: None,
                high: BTreeMap::new(),
                playing: None,
                known: None,
                pongs: BTreeMap::new(),
                log: Vec::new(),
            })
            .collect();
        Sim {
            rng,
            g: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            m,
            carriers,
            n_filter,
            lossless: false,
            n: vec![0; members],
            ghost: Ghost::default(),
            policy,
            trace: Vec::new(),
            pass_positions: BTreeMap::new(),
            stats: Stats::default(),
            record: false,
            take_failure: None,
            last_n: std::collections::HashMap::new(),
            pass_rate: 700,
            fixes: Fixes::ALL,
            quiet: false,
        }
    }

    fn clock(&self, i: usize) -> u64 {
        let g = match self.m[i].stall {
            Some((start, len)) if self.g >= start => {
                if self.g < start + len {
                    start
                } else {
                    self.g - len
                }
            }
            _ => self.g,
        } as i64;
        (self.m[i].off + g + g * self.m[i].drift / 1_000_000) as u64
    }
    fn push(&mut self, at: u64, ev: Ev) {
        self.seq += 1;
        self.queue.push(Reverse((at, self.seq, ev)));
    }
    fn note(&mut self, s: String) {
        if self.trace.len() > 200_000 {
            self.trace.remove(0);
        }
        self.trace.push(format!("g={} {s}", self.g));
    }

    fn input(&mut self, i: usize, input: Input) -> Result<(), String> {
        let now = self.clock(i);
        if self.record {
            self.m[i].log.push((now, input.clone()));
        }
        let before = self.m[i].s.clone();
        let delivered = match &input {
            Input::Frame { frame, .. } => Some(frame.clone()),
            _ => None,
        };
        let label = match &input {
            Input::Frame { frame, .. } => format!("recv {}<-{} {}", self.m[i].id, frame.from, show_body(&frame.body)),
            other => format!("{} {other:?}", self.m[i].id),
        };
        let outs = self.m[i].s.handle(input, now);
        if let Some(Body::Msg { seq, .. }) = delivered.as_ref().map(|f| &f.body) {
            let drained = outs
                .iter()
                .filter(|o| matches!(o, Output::Event { event: Event::Message { seq: q, .. } } if q != seq))
                .count();
            self.stats.early_applied += drained as u64;
        }
        if !outs.is_empty() || delivered.is_none() {
            self.note(label);
            for o in &outs {
                self.note(format!("    {}", show_output(o)));
            }
        }
        check_step_input(&mut self.ghost, &self.m[i].id.clone(), &before, &self.m[i].s, &outs, delivered.as_ref())?;
        // Revision 15 §S4 rule 1: no claim of the reader is ever accepted.
        if self.fixes.writer_claims && self.m[i].s.accepted().is_some_and(|c| c.holder == READER || c.via.as_deref() == Some(READER)) {
            return Err(format!("§S4: {} accepted the reader's claim {:?}", self.m[i].id, self.m[i].s.accepted()));
        }
        if let Some(f) = delivered.filter(|f| f.from != READER) {
            check_g6(&f, &self.m[i].s)?;
        }
        let mut follow = Vec::new();
        for o in outs {
            match o {
                Output::Send { frame } => self.send(i, frame),
                Output::Forward { to, frame } => {
                    self.stats.forwarded += 1;
                    self.forward(i, &to, frame)
                }
                Output::Persist { claim, released } => {
                    self.m[i].persisted = Some(Persisted { claim, released })
                }
                Output::Event { event } => follow.push(event),
            }
        }
        for e in follow {
            self.app_event(i, e)?;
        }
        Ok(())
    }

    fn send(&mut self, i: usize, frame: Frame) {
        if !self.m[i].up {
            return;
        }
        self.n[i] += 1;
        let n = self.n[i];
        self.last_n.insert(frame.clone(), n);
        let dsts: Vec<usize> = match &frame.to {
            Some(t) => self.m.iter().position(|m| m.id == *t).into_iter().collect(),
            None => (0..self.m.len()).filter(|j| *j != i).collect(),
        };
        self.carry(i, n, frame, dsts);
    }
    fn forward(&mut self, i: usize, to: &str, frame: Frame) {
        if !self.m[i].up {
            return;
        }
        let dsts: Vec<usize> = self.m.iter().position(|m| m.id == to).into_iter().collect();
        // A forwarded frame keeps its origin's `n`.
        let n = self.last_n.get(&frame).copied().unwrap_or(0);
        self.carry(i, n, frame, dsts);
    }
    fn carry(&mut self, i: usize, n: u64, frame: Frame, dsts: Vec<usize>) {
        for j in dsts {
            let Some(c) = self.carriers.iter().min_by_key(|c| c.base).copied() else {
                continue;
            };
            if !self.lossless && self.rng.chance(c.loss) {
                continue;
            }
            let delay = c.base + self.rng.below(c.jitter + 1);
            self.push(self.g + delay, Ev::Deliver { to: j, n, frame: frame.clone(), src: i });
            if !self.lossless && self.rng.chance(c.dup) {
                let d2 = delay + self.rng.below(c.jitter + 50);
                self.push(self.g + d2, Ev::Deliver { to: j, n, frame: frame.clone(), src: i });
            }
        }
    }

    fn deliver(&mut self, to: usize, n: u64, frame: Frame, src: usize) -> Result<(), String> {
        let from = self.m.iter().position(|m| m.id == frame.from).unwrap();
        if !self.m[to].up || !self.m[src].up {
            return Ok(());
        }
        let forwarded = src != from;
        let mut windowed = true;
        if forwarded {
            // §S3 evidence without a window: the receiver's 128-wide window for the origin's
            // key decides. A copy it already accepted is dropped; without a window (never
            // heard the origin since starting) or below it, only the claim is used.
            let (high, seen) = self.m[to].high.entry(from).or_default();
            if seen.contains(&n) {
                return Ok(());
            }
            windowed = *high > 0 && n + 128 >= *high && n > 0;
            self.stats.forwarded_delivered += 1;
        } else if self.n_filter {
            let (high, seen) = self.m[to].high.entry(from).or_default();
            if seen.contains(&n) || n + 128 < *high {
                return Ok(());
            }
            *high = (*high).max(n);
            seen.insert(n);
            let floor = high.saturating_sub(128);
            seen.retain(|x| *x >= floor);
        }
        self.stats.delivered += 1;
        if matches!(frame.body, Body::Pong { .. }) {
            let q = self.m[to].pongs.entry(frame.from.clone()).or_default();
            q.push_back(self.g);
            while q.len() > 8 {
                q.pop_front();
            }
        }
        let input = if forwarded {
            Input::LegacyEvidence { frame, writer: true, via: self.m[src].id.clone(), windowed }
        } else {
            Input::Frame { frame, writer: true, key: None, n: None }
        };
        self.input(to, input)
    }

    // ---- the application (§S12) ----

    fn position_of(&self, i: usize) -> Option<i64> {
        self.m[i].playing.map(|a| a.project(self.clock(i) as i64))
    }

    fn publish(&mut self, i: usize, a: Anchor) -> Result<(), String> {
        self.m[i].playing = a.playing.then_some(a);
        self.m[i].known = Some((a, self.m[i].id.clone()));
        let id = Id::from_label(&format!("{}-{}", self.m[i].id, self.seq));
        self.seq += 1;
        self.input(i, Input::App { command: Command::Publish { id, payload: a.encode() } })
    }

    fn app_event(&mut self, i: usize, e: Event) -> Result<(), String> {
        match e {
            Event::BecameHolder { claim, snapshot, via } => {
                let now = self.clock(i) as i64;
                match via {
                    Via::Pass => {
                        let a = Anchor::decode(&snapshot).ok_or("pass snapshot is not an anchor")?;
                        let expected = self.pass_positions.get(&claim).copied();
                        if a.playing || expected != Some(a.pos) {
                            return Err(format!(
                                "S12: pass to {} starts at {} (playing {}) but the passer stopped at {expected:?}",
                                self.m[i].id, a.pos, a.playing
                            ));
                        }
                        self.stats.passes += 1;
                        self.publish(i, Anchor { pos: a.pos, rate: RATE, playing: true, at: now })?;
                    }
                    Via::Take => {
                        let start = match self.m[i].known.clone() {
                            Some((a, from)) => {
                                let off = if from == self.m[i].id {
                                    Some(Sample { rtt: 0, offset: 0, error: 0 })
                                } else {
                                    self.m[i].s.offset_to(&from)
                                };
                                match off {
                                    Some(o) => {
                                        let proj = a.project(now + o.offset);
                                        self.check_take(i, &from, a, proj, o);
                                        proj
                                    }
                                    None => a.pos,
                                }
                            }
                            None => 0,
                        };
                        self.publish(i, Anchor { pos: start, rate: RATE, playing: true, at: now })?;
                    }
                    Via::Renew => {}
                }
            }
            Event::Yielded { .. } => {
                // §S12: a device that yields MUST pause.
                self.m[i].playing = None;
                self.stats.yields += 1;
            }
            Event::Message { payload, claim, .. } => {
                if let Some(a) = Anchor::decode(&payload) {
                    self.m[i].known = Some((a, claim.holder.clone()));
                }
            }
            Event::Snapshot { snapshot, claim, .. } => {
                if let Some(a) = Anchor::decode(&snapshot) {
                    self.m[i].known = Some((a, claim.holder.clone()));
                }
            }
            Event::AskReceived { from } => {
                if self.rng.chance(self.pass_rate) {
                    // Pause first, then pass the stopped position.
                    let now = self.clock(i) as i64;
                    let pos = self.position_of(i).unwrap_or(0);
                    self.m[i].playing = None;
                    let stopped = Anchor { pos, rate: RATE, playing: false, at: now };
                    if let Some(c) = self.m[i].s.accepted().cloned() {
                        self.pass_positions.insert(Claim::passed(c.term + 1, &from, &self.m[i].id.clone()), pos);
                    }
                    self.input(i, Input::App { command: Command::Pass { to: from, snapshot: stopped.encode() } })?;
                } else {
                    self.input(i, Input::App { command: Command::Decline { to: from } })?;
                }
            }
            Event::OffsetChanged { .. } => {}
            Event::Displaced { .. } | Event::LatePass { .. } => self.stats.reports += 1,
            _ => {}
        }
        Ok(())
    }

    /// Take accuracy: `proj` against where `from` actually is now, if it still plays.
    fn check_take(&mut self, i: usize, from: &str, a: Anchor, proj: i64, o: Sample) {
        let Some(h) = self.m.iter().position(|m| m.id == from) else {
            return;
        };
        let Some(truth) = self.position_of(h) else {
            return;
        };
        // Only anchors still current at the old holder are comparable.
        if self.m[h].playing != Some(a) {
            return;
        }
        let oldest = self.m[i].pongs.get(from).and_then(|q| q.front().copied()).unwrap_or(0);
        let age = self.g.saturating_sub(oldest) as i64;
        if self.m[i].stall.is_some() || self.m[h].stall.is_some() {
            // A stalled clock makes no promise about positions (§S0), only about safety.
            return;
        }
        let drift = (self.m[i].drift - self.m[h].drift).abs();
        let bound_clock = o.error as i64 + drift * age / 1_000_000 + 3;
        let bound = RATE * bound_clock / 1000 + 2;
        let err = (proj - truth).abs();
        self.stats.takes_checked += 1;
        self.stats.max_take_error = self.stats.max_take_error.max(err);
        self.stats.max_take_bound = self.stats.max_take_bound.max(bound);
        if err > bound {
            self.note(format!(
                "TAKE ERROR {} projected {proj} but {from} is at {truth}: err {err} > bound {bound}",
                self.m[i].id
            ));
            self.take_failure = Some(format!(
                "S12 take: {} started at {proj}, {from} is at {truth}, error {err} ms > bound {bound} ms (offset error {} ms, drift {drift} ppm over {age} ms)",
                self.m[i].id, o.error
            ));
        }
    }
}


// ---------------------------------------------------------------------------------------------
// Driving.

const TICK_MS: u64 = 100;

#[derive(Clone, Debug)]
enum Act {
    Ask(usize),
    Take(usize),
    Isolate(usize),
    Heal(usize),
    Restart(usize),
    Seek(usize),
    /// Five seeks in the same millisecond: a burst that jitter reorders.
    Burst(usize),
    Release(usize),
    Leave(usize),
    Join(usize),
    /// A member that may only read (revision 15) sends this member a frame of a random kind,
    /// with claims naming itself, at any term up to 2^53 − 1.
    Inject(usize),
}

/// The read-only member of every run: in no entitled set.
const READER: &str = "9r";

impl Sim {
    /// A frame body of any kind that a reader might send, with claims naming itself (or, for
    /// a pass, naming a writer as passed to by the reader).
    fn reader_body(&mut self) -> Body {
        let term = match self.rng.below(3) {
            0 => MAX_TERM,
            1 => self.rng.range(1, 10),
            _ => self.rng.range(1, MAX_TERM),
        };
        let c = Claim::new(term, 0, READER);
        let to = IDS[self.rng.below(self.m.len() as u64) as usize];
        let passed = Claim::passed(term.min(MAX_TERM - 1) + 1, to, READER);
        let id = Id::from_label(&format!("r{}", self.rng.next()));
        let b = Bytes(b"reader".to_vec());
        match self.rng.below(16) {
            0 => Body::Hello { fresh: id, echo: vec![], seen: Some(Seen { claim: c, seq: Some(1) }), heard: None, lapsed: self.rng.chance(500) },
            1 => Body::State { claim: c, seq: 1, snapshot: b },
            2 => Body::Beat { claim: c, seq: 1 },
            3 => Body::Msg { claim: c, seq: 1, origin: READER.into(), id, payload: b },
            4 => Body::Submit { id, payload: b },
            5 => Body::Refuse { id, reason: "no".into() },
            6 => Body::Presence { payload: b },
            7 => Body::Ask { claim: c },
            8 => Body::Pass { claim: c, next: passed, seq: 1, snapshot: b },
            9 => Body::Decline { claim: c },
            10 => Body::Take { claim: c },
            11 => Body::Ping { t: 1 },
            12 => Body::Pong { t: 1, echo: 1, hold: 0 },
            13 => Body::Yielded { claim: c, seq: 1, snapshot: b },
            14 => Body::Ack { yielded: Some(c), passed: None },
            _ => Body::Bye { claim: Some(c), leaving: self.rng.chance(500) },
        }
    }

    fn holder_index(&self) -> Option<usize> {
        self.m.iter().position(|m| m.s.sends_as_holder())
    }

    fn act(&mut self, a: Act) -> Result<(), String> {
        self.note(format!("ACT {a:?}"));
        match a {
            Act::Ask(i) => self.input(i, Input::App { command: Command::Ask })?,
            Act::Take(i) => self.input(i, Input::App { command: Command::Take { state: None } })?,
            Act::Isolate(i) => {
                if self.m[i].up {
                    self.m[i].up = false;
                    self.input(i, Input::LinkDown)?;
                }
            }
            Act::Heal(i) => {
                if !self.m[i].up {
                    self.m[i].up = true;
                    self.input(i, Input::LinkUp)?;
                }
            }
            Act::Restart(i) => {
                let p = self.m[i].persisted.clone();
                let before = self.m[i].s.accepted().cloned();
                self.m[i].s =
                    Session::with_fixes(&self.m[i].id.clone(), true, self.policy.clone(), p, self.fixes).with_entitled(IDS);
                if before.as_ref() > self.m[i].s.accepted() {
                    return Err("G1: claim lost across restart".into());
                }
                self.m[i].playing = None;
                self.m[i].high.clear();
                self.m[i].pongs.clear();
                // A member that restarts lost what it held (G11 excludes crashes).
                let me = self.m[i].id.clone();
                self.ghost.restarted(&me);
                if !self.m[i].up {
                    self.input(i, Input::LinkDown)?;
                }
                // §S12: the device kept its last anchor and supplies it.
                let state = self.m[i].known.as_ref().map(|(a, _)| a.encode());
                self.input(i, Input::App { command: Command::Join { state } })?;
            }
            Act::Seek(i) => {
                if self.m[i].s.is_holder() {
                    let now = self.clock(i) as i64;
                    let pos = self.rng.range(0, 3_600_000) as i64;
                    self.publish(i, Anchor { pos, rate: RATE, playing: true, at: now })?;
                }
            }
            Act::Burst(i) => {
                for _ in 0..5 {
                    self.act(Act::Seek(i))?;
                }
            }
            Act::Release(i) => {
                if self.m[i].s.is_holder() {
                    self.m[i].playing = None;
                    self.input(i, Input::App { command: Command::Release })?;
                }
            }
            Act::Leave(i) => {
                if self.m[i].s.joined() {
                    self.m[i].playing = None;
                    self.input(i, Input::App { command: Command::Leave })?;
                }
            }
            Act::Join(i) => {
                if !self.m[i].s.joined() {
                    self.input(i, Input::App { command: Command::Join { state: None } })?;
                }
            }
            Act::Inject(i) => {
                // Before revision 15 a reader's `hello.seen` was adopted: not injected there.
                if !self.fixes.writer_claims {
                    return Ok(());
                }
                for _ in 0..self.rng.range(1, 6) {
                    let body = self.reader_body();
                    // The host may even (wrongly) flag it as a writer: the entitled set still
                    // says no.
                    let writer = self.rng.chance(500);
                    let frame = Frame { from: READER.into(), to: None, retain: false, body };
                    self.stats.injected += 1;
                    self.input(i, Input::Frame { frame, writer, key: None, n: None })?;
                }
            }
        }
        Ok(())
    }

    /// Run until global time `until`, with `script` actions at their times.
    fn run(&mut self, until: u64, mut script: Vec<(u64, Act)>) -> Result<(), String> {
        script.sort_by_key(|(t, _)| *t);
        let mut script: VecDeque<(u64, Act)> = script.into();
        loop {
            let next_ev = self.queue.peek().map(|Reverse((t, _, _))| *t);
            let next_act = script.front().map(|(t, _)| *t);
            let next = match (next_ev, next_act) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) => a,
                (None, Some(b)) => b,
                (None, None) => break,
            };
            if next > until {
                break;
            }
            self.g = next;
            if next_act == Some(next) && next_ev.is_none_or(|e| e >= next) {
                let (_, a) = script.pop_front().unwrap();
                self.act(a)?;
                continue;
            }
            let Reverse((_, _, ev)) = self.queue.pop().unwrap();
            match ev {
                Ev::Deliver { to, n, frame, src } => self.deliver(to, n, frame, src)?,
                Ev::Tick(i) => {
                    self.push(self.g + TICK_MS, Ev::Tick(i));
                    if !self.m[i].s.joined() {
                        continue;
                    }
                    self.input(i, Input::Tick)?;
                    // App duties: holder re-anchors at least every 60 s; others ping the holder
                    // every second.
                    if self.m[i].s.sends_as_holder() {
                        if let Some(a) = self.m[i].playing.filter(|_| !self.quiet) {
                            let now = self.clock(i) as i64;
                            if now - a.at >= 60_000 {
                                let pos = a.project(now);
                                self.publish(i, Anchor { pos, rate: RATE, playing: true, at: now })?;
                            }
                        }
                    } else if self.g % 1000 < TICK_MS {
                        if let Some(h) = self.m[i].s.holder().map(str::to_owned) {
                            self.input(i, Input::App { command: Command::Ping { to: h } })?;
                        }
                    }
                }
            }
            if let Some(f) = self.take_failure.take() {
                return Err(f);
            }
        }
        self.g = until;
        Ok(())
    }

    fn start(&mut self) -> Result<(), String> {
        for i in 0..self.m.len() {
            let jitter = self.rng.below(TICK_MS);
            self.push(jitter, Ev::Tick(i));
            self.input(i, Input::App { command: Command::Join { state: None } })?;
        }
        // Member 0 starts playing.
        self.input(0, Input::App { command: Command::Take { state: None } })?;
        Ok(())
    }

    /// Heal everything, stop loss, let it settle: G4.
    fn settle(&mut self) -> Result<(), String> {
        let t = self.g;
        let heal: Vec<(u64, Act)> = (0..self.m.len()).map(|i| (t, Act::Heal(i))).collect();
        self.lossless = true;
        self.quiet = true;
        // Frames already in flight may still be lost; then two holder timeouts and beats.
        self.run(t + 3 * self.policy.holder_timeout_ms + 2 * self.policy.beat_ms, heal)?;
        check_converged(&self.m.iter().map(|m| m.s.clone()).collect::<Vec<_>>())?;
        // G11: every displaced holder's state reached the member that took over.
        if self.fixes.state_reports {
            for (taker, displaced, claim) in &self.ghost.owed {
                let joined = |id: &str| self.m.iter().any(|m| m.id == id && m.s.joined());
                let _ = taker;
                if joined(displaced) && self.m.iter().any(|m| m.s.sends_as_holder()) {
                    return Err(format!(
                        "G11: {displaced}'s state under {} never reported to {taker}",
                        show_claim(claim)
                    ));
                }
            }
        }
        // G11 (revision 15): every pass reached the application of the member it named.
        if self.fixes.pass_ack {
            for (asker, passer, next) in &self.ghost.owed_passes {
                let joined = |id: &str| self.m.iter().any(|m| m.id == id && m.s.joined());
                if joined(asker) && joined(passer) {
                    return Err(format!(
                        "G11: {passer}'s pass {} never reached {asker}'s application",
                        show_claim(next)
                    ));
                }
            }
        }
        Ok(())
    }
}

fn random_carrier(rng: &mut Rng, fast: bool) -> Carrier {
    if fast {
        Carrier { base: rng.range(2, 20), jitter: rng.range(0, 20), loss: rng.range(0, 50), dup: rng.range(0, 30) }
    } else {
        Carrier { base: rng.range(30, 150), jitter: rng.range(0, 200), loss: rng.range(0, 200), dup: rng.range(0, 50) }
    }
}

/// One random seed: members, carriers, partitions, restarts, asks and takes.
fn random_run(seed: u64) -> Result<Stats, (String, Vec<String>)> {
    random_run_with(seed, Fixes::ALL)
}

fn random_run_with(seed: u64, fixes: Fixes) -> Result<Stats, (String, Vec<String>)> {
    let mut rng = Rng::new(seed ^ 0x5eed);
    let members = rng.range(2, 5) as usize;
    let mut carriers = vec![random_carrier(&mut rng, false)];
    if rng.chance(500) {
        carriers.push(random_carrier(&mut rng, true));
    }
    let n_filter = rng.chance(500);
    let mut sim = Sim::new(seed, members, carriers, n_filter);
    // §S0: some seeds stall one member's clock for up to 30 s.
    if rng.chance(200) {
        let i = rng.below(members as u64) as usize;
        sim.m[i].stall = Some((rng.range(5_000, 200_000), rng.range(1_000, 30_000)));
    }
    sim.fixes = fixes;
    for (k, m) in sim.m.iter_mut().enumerate() {
        m.s = Session::with_fixes(IDS[k], true, Policy::default(), None, fixes).with_entitled(IDS);
    }
    let duration = 240_000;
    let mut script = Vec::new();
    for _ in 0..rng.range(4, 14) {
        let t = rng.range(2_000, duration - 20_000);
        let i = rng.below(members as u64) as usize;
        let a = match rng.below(100) {
            0..=29 => Act::Ask(i),
            30..=39 => Act::Take(i),
            40..=59 => {
                let d = rng.range(1_000, 40_000);
                script.push((t + d, Act::Heal(i)));
                Act::Isolate(i)
            }
            60..=69 => Act::Restart(i),
            70..=74 => Act::Seek(i),
            75..=77 => Act::Inject(i),
            78..=84 => Act::Burst(i),
            85..=91 => Act::Release(i),
            _ => {
                script.push((t + rng.range(500, 20_000), Act::Join(i)));
                Act::Leave(i)
            }
        };
        script.push((t, a));
    }
    let r = sim.start().and_then(|_| sim.run(duration, script)).and_then(|_| sim.settle());
    match r {
        Ok(()) => Ok(sim.stats),
        Err(e) => Err((e, sim.trace.clone())),
    }
}

/// The trace lines worth reading: actions, claim changes, roles.
fn key_lines(trace: &[String]) -> String {
    let keys = ["ACT", "persist", "BecameHolder", "Yielded", "HolderChanged", "Lapsed", "send", "Declined", "Rejected"];
    trace
        .iter()
        .filter(|l| keys.iter().any(|k| l.contains(k)) && !l.contains(" beat ") && !l.contains("ping") && !l.contains("pong"))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

fn seeds() -> Vec<u64> {
    if let Some(s) = std::env::var("COLOPHON_SIM_SEED").ok().and_then(|v| v.parse().ok()) {
        return vec![s];
    }
    let n = std::env::var("COLOPHON_SIM_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
    (1..=n).collect()
}

#[test]
fn random_seeds_hold_the_guarantees() {
    let mut total = Stats::default();
    let mut n = 0;
    for seed in seeds() {
        match random_run(seed) {
            Ok(s) => {
                total.passes += s.passes;
                total.takes_checked += s.takes_checked;
                total.yields += s.yields;
                total.delivered += s.delivered;
                total.early_applied += s.early_applied;
                total.forwarded += s.forwarded;
                total.reports += s.reports;
                total.forwarded_delivered += s.forwarded_delivered;
                total.injected += s.injected;
                total.max_take_error = total.max_take_error.max(s.max_take_error);
                total.max_take_bound = total.max_take_bound.max(s.max_take_bound);
                n += 1;
            }
            Err((e, trace)) => {
                panic!("seed {seed}: {e}\nrerun: COLOPHON_SIM_SEED={seed}\n{}", key_lines(&trace));
            }
        }
    }
    println!(
        "sim: {n} seeds passed; {total:?}"
    );
    // With the revision 2 window, reordered bursts are delivered and early hold applies them.
    assert!(n < 50 || total.early_applied > 0, "early hold never applied a message");
    assert!(n < 50 || total.injected > 0, "the reader never injected a frame");
}

/// §S12 scripted, over seeds for clocks and links: an ask is passed and the new holder starts
/// exactly at the stopped position; with that holder cut off, another member asks and holds
/// within `askTimeoutMs` plus 250 ms of timer dispatch (G5, revision 12), starting within the take bound of where the
/// cut-off holder really is; the cut-off holder returns lapsed, yields and pauses; then with
/// the holder cut off for good, a member that wants the role holds within `holderTimeoutMs`
/// of the holder's last frame (G5, both triggers).
fn playback_run(seed: u64, fixes: Fixes) -> Result<Stats, (String, Vec<String>)> {
    let mut rng = Rng::new(seed ^ 0xab);
    let carriers = vec![random_carrier(&mut rng, false)];
    let mut sim = Sim::new(seed, 3, carriers, rng.chance(500));
    sim.pass_rate = 1000;
    sim.fixes = fixes;
    for (k, m) in sim.m.iter_mut().enumerate() {
        m.s = Session::with_fixes(IDS[k], true, Policy::default(), None, fixes).with_entitled(IDS);
    }
    let r = (|| -> Result<(), String> {
        sim.start()?;
        sim.run(30_000, vec![])?;
        sim.run(60_000, vec![(30_000, Act::Ask(1))])?;
        if sim.holder_index() != Some(1) {
            return Err(format!("1b asked and is not holder (holder {:?})", sim.holder_index()));
        }
        sim.run(100_000, vec![(90_000, Act::Isolate(1))])?;
        // G5 (revision 12): askTimeoutMs on the asker's own clock (±500 ppm of virtual time)
        // plus at most 250 ms of timer dispatch (this simulator ticks every 100 ms, up to
        // 100 ms late).
        let on_clock = |ms: u64| ms + (ms * 500).div_ceil(1_000_000);
        let deadline = 100_000 + on_clock(sim.policy.ask_timeout_ms) + 250;
        sim.run(deadline, vec![(100_000, Act::Ask(2))])?;
        if !sim.m[2].s.sends_as_holder() {
            return Err("G5: 2c asked with the holder cut off and does not hold in time".into());
        }
        // One beat after the gate the two holders have exchanged frames even if some were
        // lost: allow askTimeoutMs plus two beats.
        let settle = 130_000 + sim.policy.ask_timeout_ms + 2 * sim.policy.beat_ms + 1_000;
        sim.run(settle, vec![(130_000, Act::Heal(1))])?;
        if sim.m[1].s.is_holder() || sim.m[1].playing.is_some() {
            return Err("S6: the returning lapsed holder did not yield and pause".into());
        }
        if sim.holder_index() != Some(2) {
            return Err("S6: 2c lost the role to the returning lapsed holder".into());
        }
        // Holder lapse trigger.
        sim.run(settle + 2_000, vec![(settle + 1_000, Act::Take(0))])?;
        let cut = settle + 2_000;
        // The holder's last frame reaches 0a no later than the cut (frames in flight to or
        // from an isolated member are dropped).
        let deadline = cut + on_clock(sim.policy.holder_timeout_ms) + 250;
        sim.run(deadline, vec![(cut, Act::Isolate(2))])?;
        if !sim.m[0].s.sends_as_holder() {
            return Err("G5: 0a wants the role with the holder lapsed and does not hold in time".into());
        }
        sim.settle()
    })();
    match r {
        Ok(()) => Ok(sim.stats),
        Err(e) => Err((e, sim.trace.clone())),
    }
}

#[test]
fn playback_handoff() {
    let mut worst = (0i64, 0i64);
    let mut passes = 0;
    let mut n = 0;
    for seed in seeds() {
        match playback_run(seed, Fixes::ALL) {
            Ok(st) => {
                n += 1;
                passes += st.passes;
                worst.0 = worst.0.max(st.max_take_error);
                worst.1 = worst.1.max(st.max_take_bound);
            }
            Err((e, trace)) => panic!("seed {seed}: {e}\nrerun: COLOPHON_SIM_SEED={seed}\n{}", key_lines(&trace)),
        }
    }
    println!("playback: {n} seeds, {passes} exact passes; take error max {} ms (bound max {} ms)", worst.0, worst.1);
}

/// G9: the state depends only on the frames delivered and their order. (1) Replaying each
/// member's recorded inputs into a fresh machine gives the same outputs and digest. (2) The
/// same lossless workload over a slow home carrier and over a fast direct carrier ends in the
/// same ordered state.
#[test]
fn carrier_independence() {
    for seed in seeds().into_iter().take(50) {
        let mut sim = Sim::new(seed, 3, vec![Carrier { base: 80, jitter: 120, loss: 100, dup: 20 }], false);
        sim.record = true;
        let script = vec![(20_000, Act::Ask(1)), (50_000, Act::Seek(1)), (70_000, Act::Isolate(0)), (75_000, Act::Heal(0))];
        sim.start().and_then(|_| sim.run(100_000, script)).unwrap();
        for m in &sim.m {
            let mut fresh = Session::new(&m.id, true, Policy::default(), None).with_entitled(IDS);
            for (t, input) in &m.log {
                fresh.handle(input.clone(), *t);
            }
            assert_eq!(fresh, m.s, "seed {seed}: replay of {} differs", m.id);
            assert_eq!(fresh.digest(), m.s.digest());
        }
    }
    for seed in seeds().into_iter().take(50) {
        let mut ends = Vec::new();
        for c in [Carrier { base: 120, jitter: 150, loss: 0, dup: 0 }, Carrier { base: 3, jitter: 5, loss: 0, dup: 0 }] {
            let mut sim = Sim::new(seed, 3, vec![c], true);
            sim.lossless = true;
            let mut script = Vec::new();
            for k in 0..10u64 {
                script.push((5_000 + k * 3_000, Act::Seek(0)));
            }
            sim.start().and_then(|_| sim.run(60_000, script)).and_then(|_| sim.settle()).unwrap();
            let views: Vec<(Option<Claim>, u64)> = sim.m.iter().map(|m| (m.s.accepted().cloned(), m.s.seq())).collect();
            ends.push(views);
        }
        assert_eq!(ends[0], ends[1], "seed {seed}: carriers led to different ordered state");
    }
}

/// Evidence for the findings: with each fix off, the first random seed (of
/// `COLOPHON_SIM_SEEDS`, default 300) that breaks a guarantee, and how many break. Report only;
/// run with `--ignored`.
#[test]
#[ignore]
fn fix_ablation() {
    let all = Fixes::ALL;
    let cases: [(&str, Fixes); 16] = [
        ("no fix removed (revision 10)", all),
        ("revision 1 draft (LITERAL)", Fixes::LITERAL),
        ("revision 3 draft (REV3)", Fixes::REV3),
        ("revision 4 (REV4)", Fixes::REV4),
        ("revision 5 (REV5)", Fixes::REV5),
        ("revision 6 (REV6)", Fixes::REV6),
        ("F1 rank1_from_holder", Fixes { rank1_from_holder: false, ..all }),
        ("F2 seen_unsynced", Fixes { seen_unsynced: false, ..all }),
        ("F9 ask_resend", Fixes { ask_resend: false, ..all }),
        ("F10 renew_needs_contact", Fixes { renew_needs_contact: false, ..all }),
        ("R2 state_reports", Fixes { state_reports: false, ..all }),
        ("R2c persist_release", Fixes { persist_release: false, ..all }),
        ("R5 submit_retry", Fixes { submit_retry: false, ..all }),
        ("R2d/R2f yielded_ack", Fixes { yielded_ack: false, ..all }),
        ("rev7 hello_correction", Fixes { hello_correction: false, ..all }),
        ("rev7 sender_checks", Fixes { sender_checks: false, ..all }),
    ];


    for (name, fixes) in cases {
        for (kind, run) in [("random", random_run_with as fn(u64, Fixes) -> _), ("playback", playback_run)] {
            let mut fails = 0;
            let mut first: Option<(u64, String)> = None;
            let seeds = seeds();
            for &seed in &seeds {
                if let Err((e, _)) = run(seed, fixes) {
                    fails += 1;
                    if first.is_none() {
                        first = Some((seed, e));
                    }
                }
            }
            println!("ablation [{name}] {kind}: {fails}/{} seeds fail; first {first:?}", seeds.len());
        }
    }
}
