//! The session façade (`v06::session::endpoint`) end to end with real sealing: the §S3
//! freshness exchange (loss, the 60 s bound, the retry and the unknown-key hello), entitlement
//! and revocation mid-session, delegation expiry and renewal, and the §S12 playback handoff
//! over a lossy, duplicating, reordering home carrier.
#![allow(clippy::unwrap_used)]
mod v06_codec_support;

use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::SealError;
use colophon_core::v06::session::endpoint::{Effect, Endpoint, Step};
use colophon_core::v06::session::keys::SessionAccount;
use colophon_core::v06::session::wire::DropReason;
use colophon_core::v06::session::*;
use std::collections::BTreeMap;
use v06_codec_support::*;

/// A frame in flight: when it arrives, to whom, its bytes, and its sender and kind.
#[derive(Clone)]
struct Flight {
    at: u64,
    seq: u64,
    to: usize,
    from: usize,
    kind: &'static str,
    bytes: Vec<u8>,
}

/// Decides one delivery: `None` drops it, `Some(delay)` delivers after `delay` ms.
type Filter = Box<dyn FnMut(&Flight, u64) -> Option<u64>>;

/// The home carrier: every frame a member sends goes to every other member, with loss,
/// duplication and random delay (so reordering) chosen by a seeded generator, or by a filter.
struct Net {
    eps: Vec<Endpoint>,
    flights: Vec<Flight>,
    seq: u64,
    now: u64,
    rng: Rng,
    loss: u64,
    dup: u64,
    max_delay: u64,
    /// Members that are gone: they neither receive nor tick.
    silent: Vec<bool>,
    events: Vec<Vec<(u64, Event)>>,
    drops: Vec<Vec<DropReason>>,
    sent: Vec<(u64, usize, &'static str, Option<String>)>,
    /// Decides each delivery: `None` drops it, `Some(delay)` delivers after `delay` ms.
    filter: Option<Filter>,
}
impl Net {
    fn new(eps: Vec<Endpoint>, seed: u64, loss: u64, dup: u64, max_delay: u64) -> Self {
        let n = eps.len();
        Self {
            eps,
            flights: Vec::new(),
            seq: 0,
            now: 0,
            rng: Rng(seed | 1),
            loss,
            dup,
            max_delay,
            silent: vec![false; n],
            events: vec![Vec::new(); n],
            drops: vec![Vec::new(); n],
            sent: Vec::new(),
            filter: None,
        }
    }
    fn post(&mut self, from: usize, step: Step) {
        if let Some(d) = step.dropped {
            self.drops[from].push(d.reason);
        }
        for e in step.effects {
            match e {
                Effect::Send { bytes, to, kind } => {
                    self.sent.push((self.now, from, kind, to));
                    for j in 0..self.eps.len() {
                        if j == from {
                            continue;
                        }
                        let copies = if self.rng.chance(self.dup) { 2 } else { 1 };
                        for _ in 0..copies {
                            self.seq += 1;
                            let mut f = Flight {
                                at: 0,
                                seq: self.seq,
                                to: j,
                                from,
                                kind,
                                bytes: bytes.clone(),
                            };
                            let delay = match self.filter.as_mut() {
                                Some(filter) => filter(&f, self.now),
                                None => (!self.rng.chance(self.loss))
                                    .then(|| self.rng.below(self.max_delay + 1)),
                            };
                            if let Some(d) = delay {
                                f.at = self.now + d;
                                self.flights.push(f);
                            }
                        }
                    }
                }
                Effect::Event(ev) => self.events[from].push((self.now, ev)),
                Effect::Persist { .. } => {}
                Effect::Unsent { kind, error } => panic!("unsent {kind}: {error}"),
            }
        }
    }
    fn command(&mut self, i: usize, c: Command) {
        let s = self.eps[i].command(c, clock(self.now), &epochs());
        self.post(i, s);
    }
    /// Advance to `until` in 10 ms steps, delivering due frames and running due timers.
    fn run_until(&mut self, until: u64) {
        while self.now < until {
            self.now += 10;
            self.flights.sort_by_key(|f| (f.at, f.seq));
            let due: Vec<Flight> = {
                let (d, rest): (Vec<_>, Vec<_>) =
                    self.flights.drain(..).partition(|f| f.at <= self.now);
                self.flights = rest;
                d
            };
            for f in due {
                if self.silent[f.to] {
                    continue;
                }
                let s = self.eps[f.to].receive(&f.bytes, clock(self.now), &epochs());
                assert!(self.eps[f.to].keys_consistent(), "codec and machine key sets differ");
                self.post(f.to, s);
            }
            for i in 0..self.eps.len() {
                if self.silent[i] {
                    continue;
                }
                if self.eps[i].next_deadline().is_some_and(|d| d <= self.now) {
                    let s = self.eps[i].tick(clock(self.now), &epochs());
                    self.post(i, s);
                }
            }
        }
    }
    fn hellos(&self) -> usize {
        self.sent.iter().filter(|s| s.2 == "hello").count()
    }
    fn window_open(&self, i: usize, j: usize) -> bool {
        let peer = &self.eps[j];
        self.eps[i]
            .machine()
            .window_admits(peer.me(), peer.key_id(), u64::MAX)
    }
}

fn two(seed_a: u8, seed_b: u8) -> (World, Endpoint, Endpoint) {
    let w = world();
    let view = w.view();
    let a = endpoint(&w.a, &view, seed_a, Policy::default());
    let b = endpoint(&w.b, &view, seed_b, Policy::default());
    (w, a, b)
}

#[test]
fn the_freshness_exchange_opens_both_windows_in_four_hellos() {
    let (_, a, b) = two(61, 62);
    let mut net = Net::new(vec![a, b], 1, 0, 0, 0);
    net.command(0, Command::Join { state: None });
    net.run_until(1_000);
    let before = net.hellos();
    net.command(1, Command::Join { state: None });
    net.run_until(5_000);
    assert!(net.window_open(0, 1) && net.window_open(1, 0));
    assert_eq!(net.hellos() - before, 4, "{:?}", net.sent);
    // Quiet afterwards: no endless answering.
    let settled = net.hellos();
    net.run_until(30_000);
    assert_eq!(net.hellos(), settled);
}

#[test]
fn a_lost_answer_is_retried_when_frames_are_dropped_for_want_of_a_window() {
    let (_, a, b) = two(63, 64);
    let mut net = Net::new(vec![a, b], 1, 0, 0, 0);
    // Lose a's first answer to b.
    let mut lost = false;
    net.filter = Some(Box::new(move |f, _| {
        if f.from == 0 && f.kind == "hello" && !lost && f.to == 1 {
            // The first hello from a after b joined is the answer.
            lost = true;
            return None;
        }
        Some(20)
    }));
    net.command(1, Command::Join { state: None });
    net.run_until(500);
    net.command(0, Command::Join { state: None });
    net.run_until(1_000);
    // a's join hello was lost; nobody holds, so nothing else is sent.
    assert!(!net.window_open(1, 0));
    // a takes: its `state` reaches b without a window, b probes, the exchange completes.
    net.command(0, Command::Take { state: Some(bytes("s0")) });
    net.run_until(12_000);
    assert!(net.window_open(0, 1) && net.window_open(1, 0));
    assert_eq!(net.eps[1].machine().holder(), Some(net.eps[0].me()));
    let probes = net.sent.iter().filter(|s| s.1 == 1 && s.2 == "hello").count();
    assert!(probes >= 2, "b probed after the lost answer");
}

#[test]
fn an_echo_older_than_sixty_seconds_is_not_honoured() {
    let (_, a, b) = two(65, 66);
    let mut net = Net::new(vec![a, b], 1, 0, 0, 0);
    net.command(0, Command::Join { state: None });
    net.run_until(1_000);
    // a's answer to b's join hello takes 61 s to arrive.
    let mut first = true;
    net.filter = Some(Box::new(move |f, _| {
        if f.from == 0 && f.kind == "hello" && first {
            first = false;
            return Some(61_000);
        }
        Some(20)
    }));
    net.command(1, Command::Join { state: None });
    net.run_until(61_500);
    assert!(!net.window_open(1, 0), "nothing reached b yet");
    net.run_until(62_030);
    // The late answer arrived at 62.02 s and did not open b's window: b's fresh was 61 s old.
    assert!(!net.window_open(1, 0));
    net.run_until(62_100);
    let late = net.sent.iter().filter(|s| s.0 >= 62_000 && s.2 == "hello").count();
    assert!(late >= 2, "a new exchange started: {:?}", net.sent);
    // …but the new hellos it provoked are timely, and both windows open.
    net.run_until(64_000);
    assert!(net.window_open(0, 1) && net.window_open(1, 0));
}

#[test]
fn a_frame_from_an_unknown_key_draws_one_hello_per_ask_timeout() {
    let w = world();
    let view = w.view();
    let mut a = endpoint(&w.a, &view, 67, Policy::default());
    let mut c = endpoint(&w.c, &view, 68, Policy::default());
    let ep = epochs();
    c.command(Command::Join { state: None }, clock(0), &ep);
    a.command(Command::Join { state: None }, clock(0), &ep);
    let s = a.command(Command::Take { state: Some(bytes("x")) }, clock(10), &ep);
    let state = s.frames().last().unwrap().to_vec();
    let stripped = edit(&state, |m| {
        m.remove("delegation");
    });
    let r = c.receive(&stripped, clock(20), &ep);
    assert_eq!(r.dropped.as_ref().map(|d| d.reason.clone()), Some(DropReason::NoKey));
    let hellos: Vec<_> = r
        .effects
        .iter()
        .filter(|e| matches!(e, Effect::Send { kind: "hello", to: Some(t), .. } if *t == w.a.id))
        .collect();
    assert_eq!(hellos.len(), 1);
    let again = c.receive(&stripped, clock(1_000), &ep);
    assert!(again.frames().next().is_none(), "rate limited");
    let later = c.receive(&stripped, clock(1_600), &ep);
    assert_eq!(later.frames().count(), 1, "one more after askTimeoutMs");
}

#[test]
fn a_read_only_member_cannot_take_even_if_its_own_view_says_write() {
    let w = world();
    let honest = w.view();
    // r's own (wrong) view claims write access; b's says read.
    let lying = SessionAccount::new(ACCOUNT)
        .with_member(&w.r.point, 0, None, &[(NS, Access::Write)])
        .with_member(&w.b.point, 0, None, &[(NS, Access::Write)]);
    let r = endpoint(&w.r, &lying, 69, Policy::default());
    let b = endpoint(&w.b, &honest, 70, Policy::default());
    let mut net = Net::new(vec![r, b], 1, 0, 0, 20);
    net.command(1, Command::Join { state: None });
    net.command(0, Command::Join { state: None });
    net.run_until(2_000);
    assert!(net.window_open(1, 0), "r may join: it reads the namespace");
    net.command(0, Command::Take { state: Some(bytes("mine")) });
    net.run_until(20_000);
    assert!(net.eps[0].machine().is_holder());
    assert_eq!(net.eps[1].machine().holder(), None, "b never accepts r as holder");
    assert!(net.drops[1].is_empty(), "the frames open; the machine ignores them");
}

fn holder_and_follower() -> (World, Net) {
    let (w, a, b) = two(71, 72);
    let mut net = Net::new(vec![a, b], 5, 0, 0, 20);
    net.command(0, Command::Join { state: None });
    net.command(1, Command::Join { state: None });
    net.run_until(1_000);
    net.command(0, Command::Take { state: Some(bytes("s0")) });
    net.run_until(3_000);
    assert_eq!(net.eps[1].machine().holder(), Some(w.a.id.as_str()));
    (w, net)
}

#[test]
fn revocation_mid_session_drops_the_member_everywhere() {
    let (w, mut net) = holder_and_follower();
    let without_a = SessionAccount::new(ACCOUNT).with_member(&w.b.point, 0, None, &[(NS, Access::Write)]);
    let s = net.eps[1].set_account(without_a, clock(net.now), &epochs());
    net.post(1, s);
    assert_eq!(net.eps[1].receiver().keys_for(&w.a.id), 0);
    assert_eq!(net.eps[1].machine().windows_for(&w.a.id), 0);
    let before = net.drops[1].len();
    net.command(0, Command::Publish { id: id("p1"), payload: bytes("after") });
    net.run_until(net.now + 6_000);
    assert!(net.drops[1].len() > before);
    assert!(net.drops[1][before..].iter().all(|d| matches!(d, DropReason::Delegation(_))));
    assert!(!net.events[1].iter().any(|(_, e)| matches!(e, Event::Message { .. })));
}

#[test]
fn a_new_session_number_mid_session_drops_the_old_key() {
    let (w, mut net) = holder_and_follower();
    let bumped = SessionAccount::new(ACCOUNT)
        .with_member(&w.a.point, 1, None, &[(NS, Access::Write)])
        .with_member(&w.b.point, 0, None, &[(NS, Access::Write)]);
    let s = net.eps[1].set_account(bumped, clock(net.now), &epochs());
    net.post(1, s);
    // Revision 17: nothing is kept for the old key, and its window is closed.
    assert_eq!(net.eps[1].receiver().keys_for(&w.a.id), 0);
    assert_eq!(net.eps[1].machine().windows_for(&w.a.id), 0);
    let before = net.drops[1].len();
    net.run_until(net.now + 6_000);
    assert!(net.drops[1].len() > before, "a's beats are dropped");
    assert!(net.drops[1][before..].iter().all(|d| matches!(d, DropReason::Delegation(_))));
    // a's own endpoint, told of its new session number, retires its key.
    let s = net.eps[0].set_account(bumped_view(&w), clock(net.now), &epochs());
    assert!(s.effects.iter().all(|e| !matches!(e, Effect::Send { .. })));
    assert_eq!(net.eps[0].begin_delegation(t0(), t0() + 1_000), Err(colophon_core::v06::session::keys::KeyError::Retired));
}

fn bumped_view(w: &World) -> SessionAccount {
    SessionAccount::new(ACCOUNT)
        .with_member(&w.a.point, 1, None, &[(NS, Access::Write)])
        .with_member(&w.b.point, 0, None, &[(NS, Access::Write)])
}

#[test]
fn an_expired_delegation_stops_sending_until_renewed() {
    let w = world();
    let view = w.view();
    let a = endpoint_window(&w.a, &view, 73, Policy::default(), t0(), t0() + 20_000);
    let b = endpoint(&w.b, &view, 74, Policy::default());
    let mut net = Net::new(vec![a, b], 5, 0, 0, 20);
    net.command(0, Command::Join { state: None });
    net.command(1, Command::Join { state: None });
    net.run_until(1_000);
    net.command(0, Command::Take { state: Some(bytes("s0")) });
    net.run_until(70_000);
    // At 80 s past t0 the 20 s window plus 60 s slack is over: the next beat cannot be sealed.
    let s = net.eps[0].tick(clock(85_000), &epochs());
    let unsent = s
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Unsent { error: SealError::DelegationWindow, .. }));
    assert!(unsent || s.frames().next().is_none());
    let s = net.eps[0].command(Command::Publish { id: id("late"), payload: bytes("x") }, clock(85_000), &epochs());
    assert!(s.effects.iter().any(|e| matches!(e, Effect::Unsent { error: SealError::DelegationWindow, .. })));
    // The host renews the delegation for the same key; b replaces it and keeps the window.
    let body = net.eps[0].begin_delegation(t0() + 80_000, t0() + 86_400_000).unwrap();
    let sig = host_sign(&w.a, &body);
    net.eps[0].finish_delegation(&body, &sig, clock(85_000)).unwrap();
    net.now = 85_000;
    net.command(0, Command::Publish { id: id("renewed"), payload: bytes("y") });
    net.run_until(87_000);
    assert!(net.events[1].iter().any(|(_, e)| matches!(e, Event::Message { id: i, .. } if *i == id("renewed"))));
}

// ---------------------------------------------------------------------------------------
// §S12: the now-playing handoff.

fn anchor(position: u64, playing: bool, at: u64) -> Bytes {
    bytes(&format!(
        r#"{{"at":{at},"episode":"ep-1","playing":{playing},"positionMs":{position},"ratePermille":1000,"show":"show-1"}}"#
    ))
}

fn became(net: &Net, i: usize, via: Via, since: u64) -> Option<(u64, Claim, Bytes)> {
    net.events[i].iter().rev().find_map(|(t, e)| match e {
        Event::BecameHolder { claim, snapshot, via: v } if *v == via && *t >= since => {
            Some((*t, claim.clone(), snapshot.clone()))
        }
        _ => None,
    })
}

fn handoff(seed: u64, loss: u64) -> Route {
    let (w, a, b) = two(81, 82);
    let mut net = Net::new(vec![a, b], seed, loss, 10, 300);
    net.command(0, Command::Join { state: None });
    net.command(1, Command::Join { state: None });
    net.run_until(2_000);
    // a plays.
    net.command(0, Command::Take { state: Some(anchor(0, true, 2_000)) });
    for k in 1..=4u64 {
        net.run_until(2_000 + k * 3_000);
        net.command(0, Command::Publish { id: id(&format!("a{k}")), payload: anchor(k * 3_000, true, net.now) });
    }
    net.run_until(30_000);
    assert_eq!(net.eps[1].machine().holder(), Some(w.a.id.as_str()), "seed {seed}");
    // b asks; a's application pauses and passes with its exact stopped position.
    net.command(1, Command::Ask);
    let stopped = anchor(12_345, false, 0);
    let deadline = net.now + 60_000;
    let mut passed = false;
    let mut corrected = false;
    let late_pass = |net: &Net| {
        net.events[1].iter().find_map(|(_, e)| match e {
            Event::LatePass { snapshot, .. } => Some(snapshot.clone()),
            _ => None,
        })
    };
    while net.now < deadline && became(&net, 1, Via::Pass, 0).is_none() && !corrected {
        net.run_until(net.now + 100);
        let asked = net.events[0].iter().any(|(_, e)| matches!(e, Event::AskReceived { from } if *from == w.b.id));
        if asked && !passed && net.eps[0].machine().is_holder() {
            passed = true;
            net.command(0, Command::Pass { to: w.b.id.clone(), snapshot: stopped.clone() });
        }
        // If the pass arrived after b took on the ask timeout (§S5), b's application is told
        // and publishes the passed position as a correction.
        if let Some(snap) = late_pass(&net) {
            if net.eps[1].machine().is_holder() {
                assert_eq!(snap, stopped, "seed {seed}: the late pass carries the stopped position");
                net.command(1, Command::Publish { id: id("correction"), payload: snap });
                corrected = true;
            }
        }
    }
    // How b came to hold: by the pass (the expected path), by a pass that arrived after b
    // took on the ask timeout (reported, then corrected), or, when loss kept the group from
    // being timely (§S0) and a lapsed to b, by a take, with a's state reported as displaced.
    let route = if let Some((_, claim, snapshot)) = became(&net, 1, Via::Pass, 0) {
        assert_eq!(snapshot, stopped, "the new holder starts from exactly the stopped position");
        assert_eq!(claim.rank, 1);
        assert_eq!(claim.via.as_deref(), Some(w.a.id.as_str()));
        Route::Pass
    } else if corrected {
        Route::LatePass
    } else {
        net.run_until(net.now + 20_000);
        assert!(net.eps[1].machine().is_holder(), "seed {seed}: b never held");
        let displaced = net.events[1]
            .iter()
            .any(|(_, e)| matches!(e, Event::Displaced { from, .. } if *from == w.a.id));
        // Revision 15: a pass is resent until acknowledged, so a pass a sent always reaches
        // b's application; without one, b took over a's claim and a's state was reported.
        assert!(!passed, "seed {seed}: a's pass never reached b's application");
        assert!(displaced, "seed {seed}: b took over a live holder without a report");
        Route::Take
    };
    assert!(!net.eps[0].machine().is_holder());
    // Convergence is promised once the group is timely (§S0); at 30 % loss it may take a few
    // beats: wait for it, up to two minutes.
    let until = net.now + 120_000;
    net.run_until(net.now + 20_000);
    while net.now < until && net.eps[0].machine().state() != net.eps[1].machine().state() {
        net.run_until(net.now + 1_000);
    }
    assert_eq!(net.eps[0].machine().holder(), Some(w.b.id.as_str()), "seed {seed}");
    let settled = net.eps[1].machine().state().clone();
    assert_eq!(
        net.eps[0].machine().state(),
        &settled,
        "seed {seed} loss {loss}: a follows b's state ({route:?}; a {:?} synced {} seq {}, b {:?} seq {})",
        net.eps[0].machine().accepted(),
        net.eps[0].machine().synced(),
        net.eps[0].machine().seq(),
        net.eps[1].machine().accepted(),
        net.eps[1].machine().seq()
    );
    if matches!(route, Route::Pass | Route::LatePass) {
        assert_eq!(settled, stopped, "seed {seed}");
    }
    // b goes silent; a asks and takes once the ask times out.
    net.silent[1] = true;
    let asked_at = net.now;
    net.command(0, Command::Ask);
    let deadline = net.now + 60_000;
    while net.now < deadline && became(&net, 0, Via::Take, asked_at).is_none() {
        net.run_until(net.now + 100);
    }
    let (t, _, snapshot) = became(&net, 0, Via::Take, asked_at).unwrap_or_else(|| panic!("seed {seed}: no take"));
    assert!(t - asked_at <= 15_000 + 1_000, "seed {seed}: took after {} ms", t - asked_at);
    assert_eq!(snapshot, settled, "a takes with the last state it held");
    assert!(net.eps[0].machine().is_holder());
    // Honest members never drop a frame for a cryptographic or shape reason.
    for d in net.drops.iter().flatten() {
        assert!(
            matches!(d, DropReason::Replay | DropReason::NoKey),
            "seed {seed}: unexpected drop {d}"
        );
    }
    route
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Pass,
    LatePass,
    Take,
}

#[test]
fn playback_handoff_over_a_lossy_duplicating_reordering_carrier() {
    for loss in [15, 30] {
        let mut routes = Vec::new();
        for seed in 1..=40u64 {
            routes.push(handoff(seed * 7_919, loss));
        }
        let count = |r: Route| routes.iter().filter(|x| **x == r).count();
        eprintln!(
            "loss {loss}%: {} passes, {} late passes, {} takes, 0 lost",
            count(Route::Pass),
            count(Route::LatePass),
            count(Route::Take)
        );
        assert!(count(Route::Pass) * 3 >= routes.len(), "the pass path is common: {routes:?}");
    }
}

#[test]
fn the_same_inputs_give_the_same_bytes() {
    let run = || {
        let (_, a, b) = two(91, 92);
        let mut net = Net::new(vec![a, b], 42, 10, 10, 200);
        net.command(0, Command::Join { state: None });
        net.command(1, Command::Join { state: None });
        net.run_until(1_000);
        net.command(0, Command::Take { state: Some(bytes("s")) });
        net.run_until(10_000);
        let mut out: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for f in &net.flights {
            out.insert(f.seq, f.bytes.clone());
        }
        (net.sent.clone(), out, net.eps[1].machine().digest())
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------------------
// Revision 15: key lifecycle, probes, local authority, policy.

/// Deliver `frames` to `b` and its answers back to `a`, until quiet; returns every frame `a`
/// sent to `b` (including the first batch).
fn exchange(a: &mut Endpoint, b: &mut Endpoint, frames: Vec<Vec<u8>>, t: u64) -> Vec<Vec<u8>> {
    let ep = epochs();
    let mut sent = Vec::new();
    let mut wire = frames;
    for _ in 0..6 {
        let mut back = Vec::new();
        for f in wire.drain(..) {
            sent.push(f.clone());
            back.extend(b.receive(&f, clock(t), &ep).frames().map(<[u8]>::to_vec).collect::<Vec<_>>());
            assert!(b.keys_consistent());
        }
        for f in back {
            wire.extend(a.receive(&f, clock(t), &ep).frames().map(<[u8]>::to_vec).collect::<Vec<_>>());
        }
    }
    sent
}
fn frames_of(s: Step) -> Vec<Vec<u8>> {
    s.frames().map(<[u8]>::to_vec).collect()
}

/// The eviction-replay attack against revision 17: five keys of `a` open in turn, so the
/// fifth closes the first. The home then replays the first key's delegation, its old
/// echoing `hello` (whose echoed `fresh` is still inside b's 60 s memory) and its old action
/// frames. None reopens the key or acts on b. When the key's owner speaks again, a new
/// challenge reopens it.
#[test]
fn a_closed_key_reopens_only_through_a_new_challenge() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 120, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    let mut keys: Vec<Endpoint> = (0..5).map(|i| endpoint(&w.a, &view, 121 + i, Policy::default())).collect();
    let mut first = Vec::new();
    let mut t = 10;
    for (i, a) in keys.iter_mut().enumerate() {
        let mut f = frames_of(a.command(Command::Join { state: None }, clock(t), &ep));
        if i == 0 {
            f.extend(frames_of(a.command(Command::Take { state: Some(bytes("old")) }, clock(t), &ep)));
        }
        let sent = exchange(a, &mut b, f, t);
        if i == 0 {
            first = sent;
            assert!(b.machine().window_admits(&w.a.id, a.key_id(), u64::MAX));
        }
        // Restarts at least askTimeoutMs apart: answers to new keys share the probe limit.
        t += 2_000;
    }
    let k1 = keys[0].key_id().to_owned();
    assert!(!b.machine().knows_key(&w.a.id, &k1), "the fifth key closed the first");
    assert!(!b.receiver().knows(&w.a.id, &k1), "and nothing is kept for it");
    assert_eq!(b.machine().windows_for(&w.a.id), 4);
    // The replays: every one of them, at a time when the old echoed fresh is still recent.
    let claim = b.machine().accepted().cloned();
    let old_echo = first.iter().filter(|f| String::from_utf8_lossy(f).contains("delegation")).count();
    assert!(old_echo > 0);
    for f in &first {
        let s = b.receive(f, clock(t), &ep);
        assert!(!s.events().any(|e| matches!(e, Event::Message { .. } | Event::Snapshot { .. } | Event::BecameHolder { .. } | Event::HolderChanged { .. })));
        assert!(!b.machine().window_admits(&w.a.id, &k1, u64::MAX), "a replay reopened the key");
        assert_eq!(b.machine().accepted().cloned(), claim);
    }
    assert!(b.machine().candidates_for(&w.a.id) <= 4);
    assert!(b.receiver().keys_for(&w.a.id) <= 8);
    // The owner returns. Its own window for b is still open, so it does not answer the
    // challenge in b's reply to its hello (§S3 R4a); its next frame other than a hello is
    // dropped, and b's probe is a new challenge whose answer reopens the key.
    t += 2_000;
    let mut f = frames_of(keys[0].link_down(clock(t), &ep));
    f.extend(frames_of(keys[0].link_up(clock(t), &ep)));
    exchange(&mut keys[0], &mut b, f, t);
    assert!(!b.machine().window_admits(&w.a.id, &k1, u64::MAX));
    t += 2_000;
    let p1 = frames_of(keys[0].command(Command::Publish { id: id("p1"), payload: bytes("p1") }, clock(t), &ep));
    exchange(&mut keys[0], &mut b, p1, t);
    assert!(b.machine().window_admits(&w.a.id, &k1, u64::MAX), "the owner reopened it");
    let p2 = frames_of(keys[0].command(Command::Publish { id: id("new"), payload: bytes("new") }, clock(t), &ep));
    exchange(&mut keys[0], &mut b, p2, t + 1_500);
    assert_eq!(b.machine().state(), &bytes("new"), "the reopened key is acted on");
}

/// A home replaying frames of a hundred old keys of `a` cannot affect a's current key, and
/// b's state stays bounded.
#[test]
fn a_hundred_old_keys_cannot_touch_the_current_key() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 150, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    let mut current = endpoint(&w.a, &view, 151, Policy::default());
    let mut f = frames_of(current.command(Command::Join { state: None }, clock(10), &ep));
    f.extend(frames_of(current.command(Command::Take { state: Some(bytes("s")) }, clock(10), &ep)));
    exchange(&mut current, &mut b, f, 10);
    let k = current.key_id().to_owned();
    assert!(b.machine().window_admits(&w.a.id, &k, u64::MAX));
    for i in 0..100u64 {
        let mut old = Endpoint::new(cell(), &w.a.id, Policy::default(), None, view.clone(), &mut [10 + i as u8; 32], [i as u8; 16], clock(0)).unwrap();
        let body = old.begin_delegation(t0(), t0() + 86_400_000).unwrap();
        old.finish_delegation(&body, &host_sign(&w.a, &body), clock(0)).unwrap();
        let mut f = frames_of(old.command(Command::Join { state: None }, clock(20), &ep));
        f.extend(frames_of(old.command(Command::Presence { payload: bytes("old") }, clock(20), &ep)));
        for x in f {
            b.receive(&x, clock(20 + i), &ep);
        }
        assert!(b.machine().candidates_for(&w.a.id) <= 4);
        assert!(b.machine().windows_for(&w.a.id) <= 4);
        assert!(b.receiver().keys_for(&w.a.id) <= 8);
    }
    assert!(b.machine().window_admits(&w.a.id, &k, u64::MAX), "the current key is untouched");
    let s = current.command(Command::Publish { id: id("p"), payload: bytes("after") }, clock(200), &ep);
    for x in frames_of(s) {
        b.receive(&x, clock(200), &ep);
    }
    assert_eq!(b.machine().state(), &bytes("after"));
    assert!(b.machine().closed_marks() <= 1);
}

#[test]
fn unknown_key_hellos_are_limited_per_member_and_in_all() {
    let w = world();
    let mut view = w.view();
    let extra: Vec<Member> = (30..40).map(member).collect();
    for m in &extra {
        view = view.with_member(&m.point, 0, None, &[(NS, Access::Write)]);
    }
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 130, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    // One stripped frame from each of ten entitled members and ten fake ones, at once.
    let mut hellos = 0;
    for (i, m) in extra.iter().enumerate() {
        let mut tx = sender(m, &view, 140 + i as u8, cell());
        let f = tx.seal(&Frame { from: m.id.clone(), to: None, retain: false, body: Body::Ping { t: 1 } }, &ep, t0()).unwrap();
        let stripped = edit(&f, |o| { o.remove("delegation"); });
        hellos += b.receive(&stripped, clock(10), &ep).frames().count();
        let fake = edit(&stripped, |o| { o.insert("from".into(), serde_json::json!(member(90 + i as u8).id)); });
        assert_eq!(b.receive(&fake, clock(10), &ep).frames().count(), 0, "no hello to a fake member");
    }
    assert_eq!(hellos, 4, "four a second in all");
    // A second later the budget is back, but each member still waits askTimeoutMs.
    let mut later = 0;
    for (i, m) in extra.iter().enumerate() {
        let mut tx = sender(m, &view, 160 + i as u8, cell());
        let f = tx.seal(&Frame { from: m.id.clone(), to: None, retain: false, body: Body::Ping { t: 1 } }, &ep, t0()).unwrap();
        let stripped = edit(&f, |o| { o.remove("delegation"); });
        later += b.receive(&stripped, clock(1_100), &ep).frames().count();
    }
    assert_eq!(later, 4);
}

#[test]
fn local_authority_follows_the_account() {
    let (w, mut net) = holder_and_follower();
    let ep = epochs();
    // a is reduced to read: it releases at once and seals no writer frame.
    let read = SessionAccount::new(ACCOUNT)
        .with_member(&w.a.point, 0, None, &[(NS, Access::Read)])
        .with_member(&w.b.point, 0, None, &[(NS, Access::Write)]);
    let s = net.eps[0].set_account(read.clone(), clock(net.now), &ep);
    assert!(s.effects.iter().any(|e| matches!(e, Effect::Send { kind: "bye", .. })));
    assert!(s.effects.iter().any(|e| matches!(e, Effect::Persist { released: true, .. })));
    net.post(0, s);
    assert!(!net.eps[0].machine().is_holder());
    let s = net.eps[0].command(Command::Take { state: None }, clock(net.now), &ep);
    assert!(s.frames().next().is_none(), "a reader cannot take");
    let s = net.eps[1].set_account(read.clone(), clock(net.now), &ep);
    net.post(1, s);
    // Revision 17: b, told that a only reads, still honours a's `bye` releasing exactly the
    // claim b accepted, held by a: the cell has no holder at once, and b can take.
    net.run_until(net.now + 1_000);
    assert_eq!(net.eps[1].machine().holder(), None);
    net.command(1, Command::Take { state: None });
    net.run_until(net.now + 1_000);
    assert!(net.eps[1].machine().is_holder());
    // Promoted again, it may take.
    let s = net.eps[0].set_account(w.view(), clock(net.now), &ep);
    net.post(0, s);
    let s = net.eps[1].set_account(w.view(), clock(net.now), &ep);
    net.post(1, s);
    net.command(1, Command::Release);
    net.run_until(net.now + 1_000);
    net.command(0, Command::Take { state: None });
    net.run_until(net.now + 3_000);
    assert!(net.eps[0].machine().is_holder());
    assert_eq!(net.eps[1].machine().holder(), Some(w.a.id.as_str()));
    // Without the namespace it leaves and seals nothing at all.
    let none = SessionAccount::new(ACCOUNT).with_member(&w.b.point, 0, None, &[(NS, Access::Write)]);
    let s = net.eps[0].set_account(none, clock(net.now), &ep);
    assert!(!net.eps[0].entitled());
    assert!(!net.eps[0].machine().joined());
    assert!(s.effects.iter().all(|e| !matches!(e, Effect::Send { .. })));
    assert!(s.effects.iter().any(|e| matches!(e, Effect::Unsent { error: SealError::NotEntitled, .. })));
}

#[test]
fn policies_are_checked_at_construction() {
    use colophon_core::v06::session::endpoint::{validate_policy, EndpointError};
    let largest = validate_policy(&Policy::default(), &cell()).unwrap();
    assert!(largest <= 16_384, "{largest}");
    let w = world();
    let bad = [
        Policy { max_payload: 8_193, ..Policy::default() },
        Policy { max_payload: 0, ..Policy::default() },
        Policy { fold: Fold::Append, max_payload: 4, ..Policy::default() },
        Policy { beat_ms: 0, ..Policy::default() },
        Policy { holder_timeout_ms: 5_000, ..Policy::default() },
        Policy { tail: 0, ..Policy::default() },
    ];
    for p in bad {
        let e = Endpoint::new(cell(), &w.a.id, p.clone(), None, w.view(), &mut [1; 32], [1; 16], clock(0));
        assert!(matches!(e, Err(EndpointError::Policy(_))), "{p:?}");
    }
}

/// With four open keys and four candidates of `a`, a ninth authentic candidate
/// `hello` must not cost an open key its replay window. The machine drops a candidate; the
/// codec follows it exactly; a replay of an open key's old frame is still a replay.
#[test]
fn a_ninth_key_never_evicts_an_open_keys_replay_window() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 170, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    let mut keys: Vec<Endpoint> = (0..9).map(|i| endpoint(&w.a, &view, 171 + i, Policy::default())).collect();
    let mut presence = None;
    for (i, a) in keys.iter_mut().enumerate().take(4) {
        let t = 10 + 2_000 * i as u64;
        let f = frames_of(a.command(Command::Join { state: None }, clock(t), &ep));
        exchange(a, &mut b, f, t);
        if i == 0 {
            let p = frames_of(a.command(Command::Presence { payload: bytes("here") }, clock(t), &ep));
            for x in &p {
                let s = b.receive(x, clock(t), &ep);
                assert!(s.events().any(|e| matches!(e, Event::PresenceChanged { .. })));
            }
            presence = p.into_iter().next();
        }
    }
    assert_eq!(b.machine().windows_for(&w.a.id), 4);
    // Four candidates: hellos whose answers never reach them (the probe limit spaces them).
    for (i, a) in keys.iter_mut().enumerate().skip(4) {
        let t = 10_000 + 2_000 * i as u64;
        for x in frames_of(a.command(Command::Join { state: None }, clock(t), &ep)) {
            b.receive(&x, clock(t), &ep);
            assert!(b.keys_consistent());
        }
    }
    assert_eq!(b.machine().candidates_for(&w.a.id), 4);
    assert_eq!(b.receiver().keys_for(&w.a.id), 8);
    // (The ninth key arrived last: the previous codec dropped the oldest cached key, an open
    // one, while the machine dropped a candidate.)
    let replay = presence.unwrap();
    let s = b.receive(&replay, clock(30_000), &ep);
    assert_eq!(s.dropped.map(|d| d.reason), Some(DropReason::Replay), "the open key kept its window");
    assert!(b.keys_consistent());
    assert_eq!(b.machine().windows_for(&w.a.id), 4);
}

/// Old candidate hellos are answered only under the probe limit.
#[test]
fn candidate_hellos_are_answered_under_the_probe_limit() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 190, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    let mut answers = 0;
    for i in 0..20u8 {
        let mut old = endpoint(&w.a, &view, 191 + i, Policy::default());
        for x in frames_of(old.command(Command::Join { state: None }, clock(10), &ep)) {
            answers += b.receive(&x, clock(10), &ep).frames().count();
        }
    }
    assert_eq!(answers, 1, "once per askTimeoutMs for one member");
}

/// A home replaying old candidate hellos of `a` every second, so
/// that each takes a's probe slot, cannot keep b from answering a's genuine new key: the
/// suppressed answer is deferred and sent when the slot reopens, and the new key's window
/// opens within askTimeoutMs plus a tick even though its owner then only answers.
#[test]
fn replayed_candidate_hellos_cannot_starve_a_new_key() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 200, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    let old: Vec<Vec<u8>> = (0..12u8)
        .flat_map(|i| {
            let mut o = endpoint(&w.a, &view, 201 + i, Policy::default());
            frames_of(o.command(Command::Join { state: None }, clock(0), &ep))
        })
        .collect();
    let mut k = endpoint(&w.a, &view, 230, Policy::default());
    let key = k.key_id().to_owned();
    let start = 3_050;
    let mut opened_at = None;
    let mut to_k: Vec<Vec<u8>> = Vec::new();
    let mut t = 1_000;
    while t <= 12_000 && opened_at.is_none() {
        let mut from_b = Vec::new();
        if t % 1_000 == 0 {
            let replay = &old[(t / 1_000) as usize % old.len()];
            from_b.extend(frames_of(b.receive(replay, clock(t), &ep)));
        }
        if t == start {
            for f in frames_of(k.command(Command::Join { state: None }, clock(t), &ep)) {
                from_b.extend(frames_of(b.receive(&f, clock(t), &ep)));
            }
        }
        if b.next_deadline().is_some_and(|d| d <= t) {
            from_b.extend(frames_of(b.tick(clock(t), &ep)));
        }
        to_k.extend(from_b);
        // k only answers what reaches it (b's frames to a); it sends nothing else.
        if t >= start {
            for f in to_k.drain(..) {
                for back in frames_of(k.receive(&f, clock(t), &ep)) {
                    b.receive(&back, clock(t), &ep);
                    assert!(b.keys_consistent());
                }
            }
        } else {
            to_k.clear();
        }
        if b.machine().window_admits(&w.a.id, &key, u64::MAX) {
            opened_at = Some(t);
        }
        t += 50;
    }
    let opened = opened_at.expect("the new key's window never opened");
    assert!(opened - start <= 1_500 + 100, "opened after {} ms", opened - start);
}
