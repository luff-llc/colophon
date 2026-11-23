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
    // The key is retired (a tombstone until it expires), and its window closed.
    assert_eq!(net.eps[1].receiver().keys_for(&w.a.id), 1);
    assert!(!net.eps[1].receiver().knows(&w.a.id, net.eps[0].key_id()));
    assert_eq!(net.eps[1].machine().windows_for(&w.a.id), 0);
    let before = net.drops[1].len();
    net.run_until(net.now + 6_000);
    assert!(net.drops[1].len() > before, "a's beats are dropped");
    assert!(net.drops[1][before..].iter().all(|d| *d == DropReason::Retired));
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

/// The reviewer's attack end to end: a restarts five times quickly, so b closes a's first
/// key; the home replays that key's delegation, its `hello` and its old frames. b drops them
/// at the floor; when the first key really speaks again, the machine makes it pass a new
/// freshness exchange before acting on anything but a `hello`.
#[test]
fn an_evicted_key_cannot_be_replayed_back_to_life() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut b = endpoint(&w.b, &view, 120, Policy::default());
    b.command(Command::Join { state: None }, clock(0), &ep);
    let mut a_keys: Vec<Endpoint> = (0..5).map(|i| endpoint(&w.a, &view, 121 + i, Policy::default())).collect();
    let mut first_frames: Vec<Vec<u8>> = Vec::new();
    let mut t = 10;
    let (first_four, fifth) = a_keys.split_at_mut(4);
    for (i, a) in first_four.iter_mut().enumerate() {
        // Each "restart" joins, exchanges hellos with b, and (the first) takes.
        let mut wire: Vec<Vec<u8>> = a.command(Command::Join { state: None }, clock(t), &ep).frames().map(<[u8]>::to_vec).collect();
        if i == 0 {
            wire.extend(a.command(Command::Take { state: Some(bytes("old")) }, clock(t), &ep).frames().map(<[u8]>::to_vec));
        }
        for _ in 0..4 {
            let mut back = Vec::new();
            for f in wire.drain(..) {
                if i == 0 {
                    first_frames.push(f.clone());
                }
                back.extend(b.receive(&f, clock(t), &ep).frames().map(<[u8]>::to_vec).collect::<Vec<_>>());
            }
            for f in back {
                wire.extend(a.receive(&f, clock(t), &ep).frames().map(<[u8]>::to_vec).collect::<Vec<_>>());
            }
        }
        t += 10;
    }
    let k1 = a_keys_id(first_four);
    assert!(b.machine().window_admits(&w.a.id, &k1, u64::MAX), "four open windows");
    // The fifth key sends one frame, without any exchange: the codec opens it and closes the
    // first, and must close the first key's freshness window in the machine too.
    let ping = fifth[0].command(Command::Join { state: None }, clock(t), &ep);
    for f in ping.frames() {
        b.receive(f, clock(t), &ep);
    }
    t += 10;
    assert!(!b.receiver().knows(&w.a.id, &k1), "the fifth key closed the first");
    assert!(!b.machine().window_admits(&w.a.id, &k1, u64::MAX), "and its freshness window");
    let before = (b.machine().clone(), b.receiver().clone());
    for f in &first_frames {
        let s = b.receive(f, clock(t), &ep);
        assert_eq!(s.dropped.map(|d| d.reason), Some(DropReason::Floor));
    }
    assert_eq!((b.machine().clone(), b.receiver().clone()), before, "replays changed nothing");
    // The first key speaks again (after askTimeoutMs, so b may probe it): its key reopens,
    // but its frames wait for a new exchange.
    t += 2_000;
    let s = a_keys[0].command(Command::Publish { id: id("new"), payload: bytes("new") }, clock(t), &ep);
    let msg = s.frames().next().unwrap().to_vec();
    let r = b.receive(&msg, clock(t), &ep);
    assert!(r.dropped.is_none());
    assert!(b.receiver().knows(&w.a.id, &k1));
    assert!(!b.machine().window_admits(&w.a.id, &k1, u64::MAX), "no window without a new exchange");
    assert!(r.frames().count() == 1, "b probes a with a hello");
    assert!(!r.events().any(|e| matches!(e, Event::Message { .. })));
}

fn a_keys_id(keys: &[Endpoint]) -> String {
    keys[0].key_id().to_owned()
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
    // b, told that a only reads, ignores the claim in a's `bye` (§S4 rule 1); a is silent,
    // so it lapses, and b can take.
    net.run_until(net.now + 20_000);
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
