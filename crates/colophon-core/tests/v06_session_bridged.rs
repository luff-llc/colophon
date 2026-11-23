//! The session machine on top of the §S9 bridge, over topologies that are not complete:
//! chains of 3, 4 and 5 members, a ring and a star, with live holders at both ends (each
//! end took before any link came up). Links are lossless; every frame is delivered under
//! one of three fair schedules (oldest first, newest first, rotating over links), and time
//! runs for many `holderTimeoutMs`.
//!
//! Checked at the end: G4 (one claim, one holder, one ordered state in the group) and G10
//! (no claim changed in the last 80 s). The second design review's trace — a four-member
//! chain under revision 6 with one-hop evidence and no bridging — is reproduced and fails;
//! revision 7 with bridging passes.
#![allow(clippy::unwrap_used)]
mod v06_session_support;
use colophon_core::v06::bridge::{Bridge, LinkId, Wire};
use colophon_core::v06::session::*;
use std::collections::{BTreeMap, VecDeque};
use v06_session_support::*;

#[derive(Clone, Copy, Debug)]
enum Schedule {
    Oldest,
    Newest,
    Rotate,
}

struct World {
    ids: Vec<String>,
    s: Vec<Session>,
    b: Vec<Bridge>,
    /// link -> (from, to)
    links: BTreeMap<LinkId, (usize, usize)>,
    link_of: BTreeMap<(usize, usize), LinkId>,
    /// per link, FIFO of (sent order, wire)
    queues: BTreeMap<LinkId, VecDeque<(u64, Wire)>>,
    order: u64,
    rotate: usize,
    n: Vec<u64>,
    /// The (key, n) each frame content was sent with, for forwarded evidence (revision 6).
    sent: BTreeMap<Frame, (String, u64)>,
    now: u64,
    persists: u64,
    connected: bool,
}

impl World {
    fn new(n: usize, edges: &[(usize, usize)], fixes: Fixes, bridging: bool) -> Self {
        let ids: Vec<String> = (0..n).map(|i| format!("{:02x}", i * 0x11)).collect();
        let mut w = World {
            s: ids.iter().map(|i| Session::with_fixes(i, true, Policy::default(), None, fixes)).collect(),
            b: ids
                .iter()
                .map(|i| if bridging { Bridge::new(i) } else { Bridge::without_bridging(i) })
                .collect(),
            ids,
            links: BTreeMap::new(),
            link_of: BTreeMap::new(),
            queues: BTreeMap::new(),
            order: 0,
            rotate: 0,
            n: vec![0; n],
            sent: BTreeMap::new(),
            now: 0,
            persists: 0,
            connected: false,
        };
        let mut id = 0;
        for &(a, c) in edges {
            for (x, y) in [(a, c), (c, a)] {
                w.links.insert(id, (x, y));
                w.link_of.insert((x, y), id);
                w.b[x].add_link(id);
                w.queues.insert(id, VecDeque::new());
                id += 1;
            }
        }
        w
    }
    fn idx(&self, id: &str) -> usize {
        self.ids.iter().position(|x| x == id).unwrap()
    }
    fn input(&mut self, i: usize, input: Input) {
        let outs = self.s[i].handle(input, self.now);
        for o in outs {
            match o {
                Output::Send { frame } => {
                    self.n[i] += 1;
                    let wire = Wire { key: format!("k-{}", self.ids[i]), n: self.n[i], frame };
                    self.sent.insert(wire.frame.clone(), (wire.key.clone(), wire.n));
                    if self.connected {
                        for (l, w) in self.b[i].send(wire) {
                            self.push(l, w);
                        }
                    }
                }
                Output::Forward { to, frame } => {
                    // Revision 6 evidence: the origin's frame, unchanged, to a direct peer.
                    let t = self.idx(&to);
                    if let (Some(l), Some((key, n))) = (self.link_of.get(&(i, t)).copied(), self.sent.get(&frame).cloned()) {
                        if self.connected {
                            self.push(l, Wire { key, n, frame });
                        }
                    }
                }
                Output::Persist { .. } => self.persists += 1,
                Output::Event { .. } => {}
            }
        }
    }
    fn push(&mut self, l: LinkId, w: Wire) {
        self.order += 1;
        self.queues.get_mut(&l).unwrap().push_back((self.order, w));
    }
    fn deliver_one(&mut self, s: Schedule) -> bool {
        let pick = match s {
            Schedule::Oldest => self
                .queues
                .iter()
                .filter_map(|(l, q)| q.front().map(|(o, _)| (*o, *l)))
                .min()
                .map(|(_, l)| (l, false)),
            Schedule::Newest => self
                .queues
                .iter()
                .filter_map(|(l, q)| q.back().map(|(o, _)| (*o, *l)))
                .max()
                .map(|(_, l)| (l, true)),
            Schedule::Rotate => {
                let ls: Vec<LinkId> = self.queues.iter().filter(|(_, q)| !q.is_empty()).map(|(l, _)| *l).collect();
                if ls.is_empty() {
                    None
                } else {
                    self.rotate += 1;
                    Some((ls[self.rotate % ls.len()], false))
                }
            }
        };
        let Some((l, back)) = pick else {
            return false;
        };
        let q = self.queues.get_mut(&l).unwrap();
        let (_, wire) = if back { q.pop_back().unwrap() } else { q.pop_front().unwrap() };
        let (from, to) = self.links[&l];
        let back_link = self.link_of[&(to, from)];
        let r = self.b[to].receive(back_link, wire);
        for (fl, fw) in r.forward {
            self.push(fl, fw);
        }
        if let Some(w) = r.deliver {
            let forwarded = (w.frame.from != self.ids[from]).then(|| Forwarded {
                via: self.ids[from].clone(),
                windowed: true,
            });
            self.input(to, Input::Frame { frame: w.frame, writer: true, key: None, n: None, forwarded });
        }
        true
    }
    fn run(&mut self, s: Schedule, until: u64, tick: u64) -> Result<(), String> {
        while self.now < until {
            let mut guard = 0;
            while self.deliver_one(s) {
                guard += 1;
                if guard > 200_000 {
                    return Err(format!("frames never quiesce at {}", self.now));
                }
            }
            self.now += tick;
            for i in 0..self.s.len() {
                self.input(i, Input::Tick);
            }
        }
        Ok(())
    }
}

/// Holders at both ends, then the links come up; run 200 s. Returns G4/G10 verdicts.
fn ends_hold(n: usize, edges: &[(usize, usize)], fixes: Fixes, bridging: bool, s: Schedule) -> Result<(), String> {
    let mut w = World::new(n, edges, fixes, bridging);
    for i in 0..n {
        w.input(i, Input::App { command: Command::Join { state: None } });
    }
    w.input(0, Input::App { command: Command::Take { state: Some(Bytes(b"A".to_vec())) } });
    w.input(n - 1, Input::App { command: Command::Take { state: Some(Bytes(b"Z".to_vec())) } });
    w.now = 1_000;
    w.connected = true;
    for i in 0..n {
        w.input(i, Input::LinkDown);
        w.input(i, Input::LinkUp);
    }
    w.run(s, 120_000, 500)?;
    w.persists = 0;
    w.run(s, 200_000, 500)?;
    if w.persists > 0 {
        return Err(format!("G10: {} claim changes in the last 80 s", w.persists));
    }
    check_converged(&w.s)
}

fn chain(n: usize) -> Vec<(usize, usize)> {
    (0..n - 1).map(|i| (i, i + 1)).collect()
}

const SCHEDULES: [Schedule; 3] = [Schedule::Oldest, Schedule::Newest, Schedule::Rotate];

/// The second review's trace: four-member chain, holders at both ends, revision 6 (evidence
/// over one hop) and no bridging. It fails G10 or G4 under some fair schedule.
#[test]
fn review2_chain4_fails_under_rev6_without_bridging() {
    let mut failures = Vec::new();
    for s in SCHEDULES {
        if let Err(e) = ends_hold(4, &chain(4), Fixes::REV6, false, s) {
            println!("REV6 chain4 {s:?}: {e}");
            failures.push(e);
        }
    }
    assert!(!failures.is_empty(), "revision 6 without bridging should fail on the four-member chain");
}

/// Revision 7 with bridging: every topology and schedule settles on one holder and one state.
#[test]
fn bridged_topologies_settle_under_rev7() {
    let ring = |n: usize| (0..n).map(|i| (i, (i + 1) % n)).collect::<Vec<_>>();
    let star = |n: usize| (1..n).map(|i| (0, i)).collect::<Vec<_>>();
    type Case = (&'static str, usize, Vec<(usize, usize)>);
    let cases: Vec<Case> = vec![
        ("chain3", 3, chain(3)),
        ("chain4", 4, chain(4)),
        ("chain5", 5, chain(5)),
        ("ring5", 5, ring(5)),
        ("star5", 5, star(5)),
    ];
    for (name, n, edges) in cases {
        for s in SCHEDULES {
            ends_hold(n, &edges, Fixes::ALL, true, s).unwrap_or_else(|e| panic!("{name} {s:?}: {e}"));
        }
        println!("rev7 bridged {name}: all three schedules settle");
    }
}

/// Revision 7's rules need the group model: without bridging the four-member chain is not
/// one group, and the rules make no promise there (shown, not asserted either way).
#[test]
fn rev7_without_bridging_is_outside_the_model() {
    for s in SCHEDULES {
        let r = ends_hold(4, &chain(4), Fixes::ALL, false, s);
        println!("rev7 unbridged chain4 {s:?}: {r:?}");
    }
}
