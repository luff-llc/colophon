//! The §S9 bridge on its own: arbitrary connected graphs of 2–6 members (chains of 4, 5 and
//! 6, rings, stars, a graph with a cut vertex, complete graphs), links that lose, duplicate
//! and reorder, and an origin whose session layer retransmits fairly (a new frame, new `n`,
//! until every member has the content).
//!
//! Checked: every frame (key, n) reaches each member's session layer at most once per bridge
//! incarnation; every content reaches every member; a bridge forwards a given frame at most
//! once per link per incarnation, so the transmissions of one frame are bounded by the number
//! of directed edges (times one plus the restarts); forwarding terminates.
//!
//! `COLOPHON_BRIDGE_SEEDS=n` (default 200 per topology).
#![allow(clippy::unwrap_used)]
use colophon_core::v06::bridge::{Bridge, LinkId, Wire};
use colophon_core::v06::session::{Body, Frame};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::cmp::Reverse;

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
    fn chance(&mut self, pm: u64) -> bool {
        self.below(1000) < pm
    }
}

/// Undirected edges.
type Topology = (&'static str, usize, Vec<(usize, usize)>);

fn topologies() -> Vec<Topology> {
    let chain = |n: usize| (0..n - 1).map(|i| (i, i + 1)).collect::<Vec<_>>();
    let ring = |n: usize| (0..n).map(|i| (i, (i + 1) % n)).collect::<Vec<_>>();
    let star = |n: usize| (1..n).map(|i| (0, i)).collect::<Vec<_>>();
    let complete = |n: usize| {
        let mut v = Vec::new();
        for i in 0..n {
            for j in i + 1..n {
                v.push((i, j));
            }
        }
        v
    };
    vec![
        ("pair", 2, chain(2)),
        ("chain3", 3, chain(3)),
        ("chain4", 4, chain(4)),
        ("chain5", 5, chain(5)),
        ("chain6", 6, chain(6)),
        ("ring5", 5, ring(5)),
        ("ring6", 6, ring(6)),
        ("star5", 5, star(5)),
        // Two triangles joined at member 2 (a cut vertex).
        ("cut-vertex", 5, vec![(0, 1), (1, 2), (0, 2), (2, 3), (3, 4), (2, 4)]),
        ("complete4", 4, complete(4)),
    ]
}

struct Net {
    bridges: Vec<Bridge>,
    /// link id -> (from, to)
    links: BTreeMap<LinkId, (usize, usize)>,
    /// link id for (from, to)
    link_of: BTreeMap<(usize, usize), LinkId>,
    queue: BinaryHeap<Reverse<(u64, u64, LinkId, Wire)>>,
    seq: u64,
    now: u64,
    rng: Rng,
    loss: u64,
    dup: u64,
    /// deliveries[(member, incarnation, key, n)] = count
    deliveries: BTreeMap<(usize, u32, String, u64), u32>,
    /// content -> members that have it
    have: BTreeMap<u64, BTreeSet<usize>>,
    /// forwards[(member, incarnation, key, n, link)] = count
    forwards: BTreeMap<(usize, u32, String, u64, LinkId), u32>,
    /// transmissions per (key, n)
    tx: BTreeMap<(String, u64), u64>,
    incarnation: Vec<u32>,
}

fn content_of(w: &Wire) -> u64 {
    match &w.frame.body {
        Body::Ping { t } => *t,
        _ => 0,
    }
}

impl Net {
    fn new(n: usize, edges: &[(usize, usize)], seed: u64) -> Self {
        let mut net = Net {
            bridges: (0..n).map(|i| Bridge::new(&format!("m{i}"))).collect(),
            links: BTreeMap::new(),
            link_of: BTreeMap::new(),
            queue: BinaryHeap::new(),
            seq: 0,
            now: 0,
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            loss: 0,
            dup: 0,
            deliveries: BTreeMap::new(),
            have: BTreeMap::new(),
            forwards: BTreeMap::new(),
            tx: BTreeMap::new(),
            incarnation: vec![0; n],
        };
        net.loss = net.rng.below(300);
        net.dup = net.rng.below(200);
        let mut id = 0;
        for &(a, b) in edges {
            for (x, y) in [(a, b), (b, a)] {
                net.links.insert(id, (x, y));
                net.link_of.insert((x, y), id);
                net.bridges[x].add_link(id);
                id += 1;
            }
        }
        net
    }
    fn transmit(&mut self, link: LinkId, wire: Wire) {
        *self.tx.entry((wire.key.clone(), wire.n)).or_default() += 1;
        if self.rng.chance(self.loss) {
            return;
        }
        let copies = if self.rng.chance(self.dup) { 2 } else { 1 };
        for _ in 0..copies {
            let delay = 1 + self.rng.below(50);
            self.seq += 1;
            self.queue.push(Reverse((self.now + delay, self.seq, link, wire.clone())));
        }
    }
    fn originate(&mut self, from: usize, content: u64, n: u64) {
        let wire = Wire {
            key: format!("k{from}-{}", self.incarnation[from]),
            n,
            frame: Frame {
                from: format!("m{from}"),
                to: None,
                retain: false,
                body: Body::Ping { t: content },
            },
        };
        self.have.entry(content).or_default().insert(from);
        for (l, w) in self.bridges[from].send(wire) {
            self.transmit(l, w);
        }
    }
    fn step(&mut self) -> bool {
        let Some(Reverse((t, _, link, wire))) = self.queue.pop() else {
            return false;
        };
        self.now = t;
        let (_, to) = self.links[&link];
        // The receiving side's link back to the sender is the "came from" link.
        let (from, _) = self.links[&link];
        let back = self.link_of[&(to, from)];
        let r = self.bridges[to].receive(back, wire);
        if let Some(w) = r.deliver {
            let inc = self.incarnation[to];
            *self.deliveries.entry((to, inc, w.key.clone(), w.n)).or_default() += 1;
            self.have.entry(content_of(&w)).or_default().insert(to);
        }
        for (l, w) in r.forward {
            let inc = self.incarnation[to];
            *self.forwards.entry((to, inc, w.key.clone(), w.n, l)).or_default() += 1;
            self.transmit(l, w);
        }
        true
    }
    fn restart(&mut self, m: usize) {
        self.bridges[m].restart();
        self.incarnation[m] += 1;
    }
}

fn run(name: &str, n: usize, edges: &[(usize, usize)], seed: u64) -> Result<(), String> {
    let mut net = Net::new(n, edges, seed);
    let directed = 2 * edges.len() as u64;
    let contents = 3 + net.rng.below(4);
    let restart_at = net.rng.chance(300).then(|| (net.rng.below(n as u64) as usize, 1 + net.rng.below(3)));
    let mut restarts = 0u64;
    let mut next_n = vec![1u64; n];
    for c in 1..=contents {
        let origin = net.rng.below(n as u64) as usize;
        // Fair retransmission by the session layer: a new frame (new n) each round until
        // every member has the content.
        let mut rounds = 0;
        loop {
            rounds += 1;
            if rounds > 500 {
                return Err(format!("{name} seed {seed}: content {c} never reached everyone"));
            }
            let k = next_n[origin];
            next_n[origin] += 1;
            net.originate(origin, c, k);
            if restart_at.is_some_and(|(_, at)| at == c) && rounds == 1 {
                let m = restart_at.unwrap().0;
                net.restart(m);
                restarts += 1;
            }
            let mut guard = 0;
            while net.step() {
                guard += 1;
                if guard > 1_000_000 {
                    return Err(format!("{name} seed {seed}: forwarding never terminates"));
                }
            }
            if net.have.get(&c).is_some_and(|s| s.len() == n) {
                break;
            }
        }
    }
    for ((m, inc, key, nn), count) in &net.deliveries {
        if *count > 1 {
            return Err(format!("{name} seed {seed}: m{m} (incarnation {inc}) got {key}#{nn} {count} times"));
        }
    }
    for ((m, inc, key, nn, l), count) in &net.forwards {
        if *count > 1 {
            return Err(format!("{name} seed {seed}: m{m} (incarnation {inc}) forwarded {key}#{nn} on link {l} {count} times"));
        }
    }
    for ((key, nn), count) in &net.tx {
        let bound = directed * (1 + restarts);
        if *count > bound {
            return Err(format!("{name} seed {seed}: {key}#{nn} transmitted {count} times > {bound}"));
        }
    }
    Ok(())
}

fn seeds() -> u64 {
    std::env::var("COLOPHON_BRIDGE_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(200)
}

#[test]
fn bridged_delivery_on_connected_graphs() {
    for (name, n, edges) in topologies() {
        let mut max_tx = 0;
        for seed in 1..=seeds() {
            run(name, n, &edges, seed).unwrap_or_else(|e| panic!("{e}"));
            max_tx = max_tx.max(2 * edges.len());
        }
        println!("bridge {name}: {} seeds pass (directed edges {max_tx})", seeds());
    }
}

/// Without loss the very first frame of each content reaches everyone, exactly once, with
/// at most one transmission per directed edge.
#[test]
fn lossless_flood_is_exact() {
    for (name, n, edges) in topologies() {
        let mut net = Net::new(n, &edges, 7);
        net.loss = 0;
        net.dup = 0;
        net.originate(0, 1, 1);
        while net.step() {}
        assert_eq!(net.have[&1].len(), n, "{name}");
        let tx = net.tx[&("k0-0".to_owned(), 1)];
        assert!(tx <= 2 * edges.len() as u64, "{name}: {tx} transmissions");
    }
}

/// A frame lost beyond the first hop is not repaired by the origin resending the same `n`:
/// the bridges that have it treat the resend as a duplicate and do not forward it again.
/// Repair needs a new frame from the session layer (finding B1).
#[test]
fn same_n_resend_does_not_cross_a_bridge() {
    let mut net = Net::new(3, &[(0, 1), (1, 2)], 9);
    net.loss = 0;
    net.dup = 0;
    // Deliver 0 -> 1 but lose 1 -> 2 by removing member 2's link back for the first flood.
    net.originate(0, 1, 1);
    let first = net.queue.pop().unwrap();
    let Reverse((_, _, link, wire)) = first;
    let (_, to) = net.links[&link];
    let back = net.link_of[&(to, 0)];
    let r = net.bridges[to].receive(back, wire.clone());
    assert!(r.deliver.is_some() && r.forward.len() == 1);
    // The forward to 2 is lost. The origin resends n = 1.
    let r = net.bridges[to].receive(back, wire);
    assert!(r.deliver.is_none() && r.forward.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Revision 8: forwarding without the bridge's own freshness exchange, the handshake across
// bridges, replays and the key cap.

use colophon_core::v06::session::{Command, Input, Output, Policy, Session};

fn wire(from: &str, key: &str, n: u64, t: u64) -> Wire {
    Wire { key: key.into(), n, frame: Frame { from: from.into(), to: None, retain: false, body: Body::Ping { t } } }
}

/// (a) A bridge forwards a verified frame from an origin it has no freshness window with;
/// its own session layer drops the frame (no window), the far member gets it.
#[test]
fn forwards_without_own_window() {
    let mut b = Bridge::new("mb");
    b.add_link(0);
    b.add_link(1);
    let beat = Wire {
        key: "k-ma".into(),
        n: 5,
        frame: Frame {
            from: "ma".into(),
            to: None,
            retain: false,
            body: Body::Beat { claim: colophon_core::v06::session::Claim::new(1, 0, "ma"), seq: 0 },
        },
    };
    let r = b.receive(0, beat.clone());
    assert_eq!(r.forward.iter().map(|(l, _)| *l).collect::<Vec<_>>(), vec![1]);
    let mut s = Session::new("mb", true, Policy::default(), None).with_fresh_seed([3; 16]);
    s.handle(Input::App { command: Command::Join { state: None } }, 0);
    let w = r.deliver.unwrap();
    let outs = s.handle(Input::Frame { frame: w.frame, writer: true, key: Some(w.key), n: Some(w.n), forwarded: None }, 10);
    // It does not act on the frame; it only probes the origin with a hello (finding B5).
    let only_probe = outs.iter().all(|o| matches!(o, Output::Send { frame } if matches!(frame.body, Body::Hello { .. }) && frame.to.as_deref() == Some("ma")));
    assert!(only_probe && s.accepted().is_none() && s.windows_for("ma") == 0);
    // An unverified frame is neither forwarded nor delivered.
    let r = b.receive_checked(0, wire("ma", "k-ma", 6, 1), false);
    assert!(r.forward.is_empty() && r.deliver.is_none());
}

/// (c) A carrier replaying old frames: within the window nothing is forwarded again, below
/// it nothing at all; after the bridge restarts each replayed frame is forwarded at most once.
#[test]
fn replays_are_bounded() {
    let mut b = Bridge::new("mb");
    b.add_link(0);
    b.add_link(1);
    for n in 1..=300 {
        assert_eq!(b.receive(0, wire("ma", "k-ma", n, n)).forward.len(), 1);
    }
    let again: usize = (1..=300).map(|n| b.receive(0, wire("ma", "k-ma", n, n)).forward.len()).sum();
    assert_eq!(again, 0, "no re-flood within or below the window");
    b.restart();
    let first: usize = (1..=300).map(|n| b.receive(0, wire("ma", "k-ma", n, n)).forward.len()).sum();
    let second: usize = (1..=300).map(|n| b.receive(0, wire("ma", "k-ma", n, n)).forward.len()).sum();
    assert!(first <= 300, "at most once per frame after a restart: {first}");
    assert_eq!(second, 0);
    // Replayed in descending order after a restart, only frames within 128 of the first
    // replayed one are forwarded.
    b.restart();
    let desc: usize = (1..=300).rev().map(|n| b.receive(0, wire("ma", "k-ma", n, n)).forward.len()).sum();
    assert_eq!(desc, 129);
}

/// (d) The session's 4-keys-per-member cap does not touch the bridge's forwarding memory:
/// a member that cycles through 10 keys cannot make a bridge forward an old key's frame
/// again. Bound: each (key, n) is forwarded at most once per bridge incarnation; the memory
/// is one 128-wide window per accepted key until the key is forgotten.
#[test]
fn key_cycling_cannot_force_refloods() {
    let mut b = Bridge::new("mb");
    b.add_link(0);
    b.add_link(1);
    for k in 0..10 {
        for n in 1..=5 {
            b.receive(0, wire("ma", &format!("k{k}"), n, n));
        }
    }
    let replays: usize = (0..10)
        .flat_map(|k| (1..=5).map(move |n| (k, n)))
        .map(|(k, n)| b.receive(0, wire("ma", &format!("k{k}"), n, n)).forward.len())
        .sum();
    assert_eq!(replays, 0);
    assert_eq!(b.forwarding_keys(), 10);
    b.forget_key("k0");
    assert_eq!(b.forwarding_keys(), 9);
}

#[allow(clippy::needless_range_loop)]
/// (b) The fresh/echo handshake end to end across 1, 2 and 3 bridges (chains of 3, 4 and 5)
/// under 20 % loss per hop: every member opens a window for the key of every member that sent frames
/// other than hellos, and the group agrees on the holder.
fn handshake_chain(n: usize, seed: u64, fixes: colophon_core::v06::session::Fixes) -> Result<(), String> {
    let ids: Vec<String> = (0..n).map(|i| format!("{:02x}", i * 0x11)).collect();
    let mut s: Vec<Session> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| Session::with_fixes(id, true, Policy::default(), None, fixes).with_fresh_seed([i as u8 + 1; 16]))
        .collect();
    let mut b: Vec<Bridge> = ids.iter().map(|id| Bridge::new(id)).collect();
    // link 2i: i -> i+1, 2i+1: i+1 -> i
    for i in 0..n - 1 {
        b[i].add_link((2 * i) as u32);
        b[i + 1].add_link((2 * i + 1) as u32);
    }
    let dest = |l: u32| -> (usize, u32) {
        let i = (l / 2) as usize;
        if l % 2 == 0 { (i + 1, l + 1) } else { (i, l - 1) }
    };
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut counters = vec![0u64; n];
    let mut queue: Vec<(u32, Wire)> = Vec::new();
    let mut now = 0u64;
    let mut spoke = vec![false; n];
    let route = |i: usize, outs: Vec<Output>, b: &mut Vec<Bridge>, counters: &mut Vec<u64>, queue: &mut Vec<(u32, Wire)>, ids: &Vec<String>, spoke: &mut Vec<bool>| {
        for o in outs {
            if let Output::Send { frame } = o {
                if !matches!(frame.body, Body::Hello { .. }) {
                    spoke[i] = true;
                }
                counters[i] += 1;
                let w = Wire { key: format!("k-{}", ids[i]), n: counters[i], frame };
                queue.extend(b[i].send(w));
            }
        }
    };
    for i in 0..n {
        let outs = s[i].handle(Input::App { command: Command::Join { state: None } }, now);
        route(i, outs, &mut b, &mut counters, &mut queue, &ids, &mut spoke);
    }
    let outs = s[0].handle(Input::App { command: Command::Take { state: None } }, now);
    route(0, outs, &mut b, &mut counters, &mut queue, &ids, &mut spoke);
    // Each probe round trip crosses up to 2 × 4 lossy hops, so give it ten minutes.
    while now < 600_000 {
        let mut guard = 0;
        while !queue.is_empty() {
            guard += 1;
            if guard > 100_000 {
                return Err("frames never quiesce".into());
            }
            let (l, w) = queue.remove(0);
            if rng.chance(200) {
                continue;
            }
            let (to, back) = dest(l);
            let r = b[to].receive(back, w);
            queue.extend(r.forward);
            if let Some(w) = r.deliver {
                let dbg = std::env::var("COLOPHON_BRIDGE_DEBUG").is_ok() && matches!(w.frame.body, Body::Hello { .. });
                let desc = format!("{} <- {} {:?} n={}", ids[to], w.frame.from, w.frame.body, w.n);
                let outs = s[to].handle(
                    Input::Frame { frame: w.frame, writer: true, key: Some(w.key), n: Some(w.n), forwarded: None },
                    now,
                );
                if dbg {
                    println!("t={now} {desc} -> {} outs, windows {:?}", outs.len(), (0..n).map(|j| s[to].windows_for(&ids[j])).collect::<Vec<_>>());
                }
                route(to, outs, &mut b, &mut counters, &mut queue, &ids, &mut spoke);
            }
        }
        now += 500;
        for i in 0..n {
            let outs = s[i].handle(Input::Tick, now);
            route(i, outs, &mut b, &mut counters, &mut queue, &ids, &mut spoke);
        }
    }
    for i in 0..n {
        for j in 0..n {
            // Every member that sent anything but hellos is heard by everyone.
            if i != j && spoke[j] && s[i].windows_for(&ids[j]) == 0 {
                return Err(format!("{} never opened a window for {}'s key", ids[i], ids[j]));
            }
        }
    }
    let claims: Vec<_> = s.iter().map(|x| x.accepted().cloned()).collect();
    if claims.iter().any(|c| *c != claims[0]) || claims[0].is_none() {
        return Err(format!("no agreement: {claims:?}"));
    }
    Ok(())
}

#[test]
fn handshake_across_bridges_under_loss() {
    for n in [3, 4, 5] {
        let mut fails = Vec::new();
        for seed in 1..=100 {
            if let Err(e) = handshake_chain(n, seed, colophon_core::v06::session::Fixes::ALL) {
                fails.push((seed, e));
            }
        }
        println!("handshake chain{n} ({} bridges): {}/100 seeds fail; first {:?}", n - 2, fails.len(), fails.first());
        assert!(fails.is_empty(), "chain{n}: {:?}", fails.first());
    }
}

/// Finding B5: revision 8 as written (no probe) stalls the handshake under loss: a member
/// whose own hellos were lost drops the holder's frames for want of a window and never
/// speaks again.
#[test]
fn handshake_stalls_without_probe() {
    let fails = (1..=50)
        .filter(|seed| handshake_chain(3, *seed, colophon_core::v06::session::Fixes::REV7).is_err())
        .count();
    println!("handshake chain3 without probe: {fails}/50 seeds fail");
    assert!(fails > 0);
}
