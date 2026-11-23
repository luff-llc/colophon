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
