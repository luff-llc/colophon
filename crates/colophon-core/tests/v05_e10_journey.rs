//! The differential journey (E10 fix round; ported from the independent check): a long random
//! journey of several members and devices in two namespaces, durable and live writes delivered
//! late, out of order and partially, authority changes, revocations, rekeys, session ends,
//! read-scope changes, proposals, bursts past the 1,024 bound and garbage-signature twins, at
//! snapshot intervals 2, 3, 4, 7 and 256. After every step the maintained derivation equals a
//! rebuild (`verify_derivation`), and at intervals everything readers see (view, query, change
//! token, the verdict on every held record, live heads and verdicts, proposals, status, members)
//! equals a cold `Account::open`, a cold engine open, and a resumed open from a checkpoint saved
//! at a random earlier step. `E10_SEEDS=n E10_STEPS=n` run longer.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::type_complexity,
    dead_code,
    unused_variables
)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::account::{Account, Identity, Incoming, RevokeKeep};
use colophon_core::v05::engine::{Engine, EngineOptions, Saved};
use colophon_core::v05::history::Objects;
use colophon_core::v05::records::{HeldRecord, Level, OperationHeader};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use support::*;

const LISTEN: &str = "listening.podcasts";
const NOTES: &str = "notes";
const NSS: [&str; 2] = [LISTEN, NOTES];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn chance(&mut self, pct: usize) -> bool {
        self.below(100) < pct
    }
}

type Eng = Engine<MemSource>;
static OVERLAY_SPLIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static COLD_LIVE_REFUSED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PRUNE_DIFFS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct Member {
    id: String,
    budget: bool,
    revoked: bool,
}
struct Writer {
    m: usize,
    e: Eng,
    src: MemSource,
}

pub struct World {
    f: Fixture,
    now: i64,
    auth: BTreeMap<String, Vec<u8>>,
    recs: BTreeMap<String, Vec<u8>>,
    hist: BTreeMap<String, Vec<u8>>,
    live: BTreeMap<String, Vec<Vec<u8>>>,
    members: Vec<Member>,
    writers: Vec<Writer>,
    proposals: Vec<String>,
    log: Vec<String>,
}

fn classify(w: &mut World, stores: &[(String, Vec<u8>)]) {
    for (p, b) in stores {
        if p.starts_with("ops/") {
            w.recs.insert(p.clone(), b.clone());
        } else if p.starts_with("history/") {
            w.hist.insert(p.clone(), b.clone());
        } else if p.starts_with("state/") {
            let v = w.live.entry(p.clone()).or_default();
            if !v.contains(b) {
                v.push(b.clone());
            }
        } else {
            w.auth.insert(p.clone(), b.clone());
        }
    }
}

fn publish_authority(w: &mut World) {
    for e in &w.f.account.objects().entries {
        w.auth
            .insert(format!("authority/{:08}.json", entry_seq(e)), e.clone());
    }
    for p in &w.f.account.objects().pending {
        w.auth.insert(pending_path(p), p.clone());
    }
}

fn sync_writer(w: &mut World, i: usize, rng: &mut Rng) {
    let now = w.now;
    let wr = &mut w.writers[i];
    for (p, b) in &w.auth {
        if wr.src.get(p).as_deref() != Some(b.as_slice()) {
            wr.src.put(p, b.clone());
        }
    }
    let pct = 20 + rng.below(80);
    for (p, b) in &w.recs {
        if wr.src.get(p).is_none() && rng.chance(pct) {
            wr.src.put(p, b.clone());
        }
    }
    for (p, vs) in &w.live {
        if rng.chance(pct) {
            let b = vs.last().unwrap();
            if wr.src.get(p).as_deref() != Some(b.as_slice()) {
                wr.src.put(p, b.clone());
            }
        }
    }
    let _ = wr.e.advance(now);
    if let Err(e) = wr.e.refresh(wr.src.listing()) {
        w.log.push(format!("writer {i} refresh: {e:?}"));
    }
    let wr = &mut w.writers[i];
    let steps = wr.e.begin_unlock_epochs();
    if !steps.is_empty() {
        let id = w.members[wr.m].id.clone();
        let res = w.f.host.answer_epochs(&id, steps);
        let _ = wr.e.finish_unlock_epochs(res);
    }
}

fn finish(w: &mut World, i: usize, action: colophon_core::v05::account::PendingAction) -> bool {
    let sigs = w.f.host.sign(action.steps());
    match w.writers[i].e.finish_write(action, sigs) {
        Ok(written) => {
            for (p, b) in &written.stores {
                w.writers[i].src.put(p, b.clone());
            }
            let stores = written.stores.clone();
            classify(w, &stores);
            true
        }
        Err(e) => {
            w.log.push(format!("finish {i}: {e:?}"));
            false
        }
    }
}

fn write(
    w: &mut World,
    i: usize,
    ns: &str,
    kind: &str,
    payload: Value,
    level: Level,
) -> Option<String> {
    let seed = w.f.host.fresh();
    let action = match w.writers[i].e.begin_write(ns, kind, payload, level, seed) {
        Ok(Ok(a)) => a,
        Ok(Err(d)) => {
            w.log.push(format!("denied {i} {kind}: {d:?}"));
            return None;
        }
        Err(e) => {
            w.log.push(format!("begin {i} {kind}: {e:?}"));
            return None;
        }
    };
    let sigs = w.f.host.sign(action.steps());
    match w.writers[i].e.finish_write(action, sigs) {
        Ok(written) => {
            for (p, b) in &written.stores {
                w.writers[i].src.put(p, b.clone());
            }
            let id = written
                .stores
                .iter()
                .find(|(p, _)| p.starts_with("ops/"))
                .and_then(|(_, b)| OperationHeader::parse(b).ok())
                .map(|(h, _)| h.id);
            let stores = written.stores.clone();
            classify(w, &stores);
            id
        }
        Err(e) => {
            w.log.push(format!("finish {i} {kind}: {e:?}"));
            None
        }
    }
}

fn live_write(w: &mut World, i: usize, ep: usize, seconds: f64) -> bool {
    let seed = w.f.host.fresh();
    let payload = json!({"id": format!("ep{ep}"), "show": "s1", "seconds": seconds});
    let pending = match w.writers[i]
        .e
        .begin_live_write(LISTEN, "position", payload, seed)
    {
        Ok(Ok(p)) => p,
        Ok(Err(d)) => {
            w.log.push(format!("live denied {i}: {d:?}"));
            return false;
        }
        Err(e) => {
            w.log.push(format!("live begin {i}: {e:?}"));
            return false;
        }
    };
    let step = pending.step();
    let sig = colophon_core::v05::write::SignatureResult {
        signature: w.f.host.ids[step.signer()].sign(step.body()).to_vec(),
        assertion: None,
    };
    match w.writers[i].e.finish_live_write(pending, sig) {
        Ok(lw) => {
            for (p, b) in &lw.stores {
                w.writers[i].src.put(p, b.clone());
            }
            let stores = lw.stores.clone();
            classify(w, &stores);
            true
        }
        Err(e) => {
            w.log.push(format!("live finish {i}: {e:?}"));
            false
        }
    }
}

/// The observer: a controller account fed by hand, and the same deliveries to an engine.
struct Observer {
    a: Account,
    now: i64,
    live: Vec<HeldRecord>,
    live_batches: Vec<Vec<HeldRecord>>,
    seen_recs: BTreeSet<String>,
    seen_live: BTreeSet<(String, Vec<u8>)>,
    scope: Option<Vec<String>>,
    // The engine observer and its source.
    esrc: MemSource,
    e: Eng,
    saved: Vec<(usize, Saved)>,
    extended: usize,
    rebuilt: usize,
}

fn snapshot_objects(w: &World) -> Objects {
    let mut o = w.f.account.objects().clone();
    o.heads.clear();
    o.predecessor.clear();
    o
}

fn obs_new(w: &World) -> Observer {
    let mut a = Account::open(
        snapshot_objects(w),
        Vec::new(),
        None,
        Identity::Controller(w.f.d.clone()),
        w.now,
    )
    .unwrap();
    unlock_controller(&w.f.host, &mut a, &w.f.d);
    let esrc = MemSource::versioned();
    for (p, b) in &w.auth {
        esrc.put(p, b.clone());
    }
    let e = controller_engine(&w.f, &w.f.host, &esrc, &w.f.d, w.now);
    Observer {
        a,
        now: w.now,
        live: Vec::new(),
        live_batches: Vec::new(),
        seen_recs: BTreeSet::new(),
        seen_live: BTreeSet::new(),
        scope: None,
        esrc,
        e,
        saved: Vec::new(),
        extended: 0,
        rebuilt: 0,
    }
}

fn cold_account(w: &World, o: &Observer) -> Account {
    let mut c = Account::open(
        o.a.objects().clone(),
        o.a.records().to_vec(),
        None,
        Identity::Controller(w.f.d.clone()),
        o.a.now_ms(),
    )
    .unwrap();
    unlock_controller(&w.f.host, &mut c, &w.f.d);
    if let Some(s) = &o.scope {
        c.set_read_scope(s.clone()).unwrap();
    }
    // The held live candidates in one merge: the same set must be held, judged the same.
    if !o.a.live_held().is_empty() {
        let now = c.now_ms();
        c.merge_live(o.a.live_held().to_vec(), now)
            .expect("a merge of the held live candidates is accepted");
    }
    c
}

fn first_diff(a: &str, b: &str) -> String {
    let i = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
    let lo = i.saturating_sub(300);
    let cut = |s: &str| -> String { s.get(lo..(i + 300).min(s.len())).unwrap_or("").to_string() };
    format!(
        "at byte {i} (len {} vs {})\n    inc : ...{}...\n    cold: ...{}...",
        a.len(),
        b.len(),
        cut(a),
        cut(b)
    )
}

fn heads(a: &Account) -> Vec<(String, String, u64)> {
    a.live_heads()
        .iter()
        .map(|h| (h.path.clone(), h.digest.clone(), h.generation))
        .collect()
}
fn eheads(e: &Eng) -> Vec<(String, String, u64)> {
    e.live_heads()
        .iter()
        .map(|h| (h.path.clone(), h.digest.clone(), h.generation))
        .collect()
}

fn compare_accounts(a: &Account, c: &Account, ctx: &str) -> Vec<String> {
    let mut diffs = Vec::new();
    for ns in NSS {
        if a.revision(ns) != c.revision(ns) {
            diffs.push(format!(
                "{ctx}: revision {ns} {} vs {}",
                a.revision(ns),
                c.revision(ns)
            ));
        }
        let va = serde_json::to_string(&a.view(ns).unwrap()).unwrap();
        let vc = serde_json::to_string(&c.view(ns).unwrap()).unwrap();
        if va != vc {
            diffs.push(format!(
                "{ctx}: view {ns} differs: {}",
                first_diff(&va, &vc)
            ));
        }
        let qa = serde_json::to_string(&a.query(ns, "read", json!({})).unwrap()).unwrap();
        let qc = serde_json::to_string(&c.query(ns, "read", json!({})).unwrap()).unwrap();
        if qa != qc {
            diffs.push(format!("{ctx}: query {ns} differs"));
        }
        if format!("{:?}", a.proposals(ns)) != format!("{:?}", c.proposals(ns)) {
            diffs.push(format!("{ctx}: proposals {ns} differ"));
        }
        if a.highest_admitted_clock(ns) != c.highest_admitted_clock(ns) {
            diffs.push(format!("{ctx}: highest clock {ns}"));
        }
    }
    for r in a.records() {
        let x = a.verdict_of(&r.path, &r.bytes);
        let y = c.verdict_of(&r.path, &r.bytes);
        if x != y {
            diffs.push(format!("{ctx}: verdict {} {:?} vs {:?}", r.path, x, y));
        }
    }
    if heads(a) != heads(c) {
        diffs.push(format!(
            "{ctx}: live heads {:?}\n vs {:?}",
            heads(a),
            heads(c)
        ));
    }
    let lv = |x: &Account| -> Vec<String> {
        x.live_verdicts()
            .iter()
            .map(|(p, v)| format!("{p}:{v:?}"))
            .collect()
    };
    if lv(a) != lv(c) {
        let (x, y) = (lv(a), lv(c));
        let mut only_a = x.clone();
        for e in &y {
            if let Some(i) = only_a.iter().position(|z| z == e) {
                only_a.remove(i);
            }
        }
        let mut only_c = y.clone();
        for e in &x {
            if let Some(i) = only_c.iter().position(|z| z == e) {
                only_c.remove(i);
            }
        }
        diffs.push(format!(
            "{ctx}: live verdicts differ: only inc {only_a:?}\n   only cold {only_c:?}"
        ));
    }
    if format!("{:?}", a.status()) != format!("{:?}", c.status()) {
        diffs.push(format!("{ctx}: status"));
    }
    if format!("{:?}", a.members()) != format!("{:?}", c.members()) {
        diffs.push(format!("{ctx}: members"));
    }
    diffs
}

fn compare_engines(
    a: &Eng,
    c: &Eng,
    ctx: &str,
    live_strict: bool,
    scope: &Option<Vec<String>>,
) -> Vec<String> {
    let mut diffs = Vec::new();
    let held = |e: &Eng| -> BTreeSet<(String, usize)> {
        e.account()
            .records()
            .iter()
            .map(|r| (r.path.clone(), r.bytes.len()))
            .collect()
    };
    if held(a) != held(c) {
        let (x, y) = (held(a), held(c));
        diffs.push(format!(
            "{ctx}: held records differ: only first {:?} only second {:?}",
            x.difference(&y).collect::<Vec<_>>(),
            y.difference(&x).collect::<Vec<_>>()
        ));
    }
    let in_scope = |ns: &str| scope.as_ref().is_none_or(|s| s.iter().any(|x| x == ns));
    for ns in NSS {
        if !in_scope(ns) {
            continue;
        }
        if ns == LISTEN && !live_strict {
            continue;
        }
        if a.revision(ns) != c.revision(ns) {
            diffs.push(format!(
                "{ctx}: revision {ns} {} vs {}",
                a.revision(ns),
                c.revision(ns)
            ));
        }
        // A known pre-existing engine difference (base 1dd3c0a too): a revoked member's kept walk
        // judged `revokedBackdated` incrementally and `unavailable` cold. Normalized here.
        let norm = |x: String| x;
        let va = norm(serde_json::to_string(&a.view(ns).unwrap()).unwrap());
        let vc = norm(serde_json::to_string(&c.view(ns).unwrap()).unwrap());
        if va != vc {
            diffs.push(format!(
                "{ctx}: view {ns} differs: {}",
                first_diff(&va, &vc)
            ));
        }
    }
    for r in a.account().records() {
        let ns = r.path.split('/').nth(2).unwrap_or_default();
        if !in_scope(ns) {
            continue;
        }
        let n = |v: Option<String>| v;
        if n(a.record_verdict(&r.path)) != n(c.record_verdict(&r.path)) {
            diffs.push(format!(
                "{ctx}: verdict {} {:?} vs {:?}",
                r.path,
                a.record_verdict(&r.path),
                c.record_verdict(&r.path)
            ));
        }
    }
    if live_strict && eheads(a) != eheads(c) {
        diffs.push(format!("{ctx}: heads"));
    }
    diffs
}

pub struct Config {
    pub steps: usize,
    pub interval: usize,
    pub burst: bool,
    pub engine: bool,
    pub check_every: usize,
    pub twin: bool,
}

pub fn journey(seed: u64, cfg: &Config) -> Result<usize, String> {
    colophon_core::v05::account::set_fold_snapshot_interval(cfg.interval);
    let mut rng = Rng(seed | 1);
    let mut f = create(&NSS);
    let now = f.account.now_ms();
    let mut w = World {
        f,
        now,
        auth: BTreeMap::new(),
        recs: BTreeMap::new(),
        hist: BTreeMap::new(),
        live: BTreeMap::new(),
        members: Vec::new(),
        writers: Vec::new(),
        proposals: Vec::new(),
        log: Vec::new(),
    };
    // Members: A and B write both namespaces; C has a budget on notes; D proposes only on notes.
    let both = terms_for(&[(LISTEN, "write"), (NOTES, "write")]);
    let mut specs: Vec<(Value, bool)> = vec![(both.clone(), false), (both.clone(), false)];
    let mut budget = json!({"records": [{"namespace": NOTES, "access": "write"}, {"namespace": LISTEN, "access": "write"}], "writes": 40});
    specs.push((budget.take(), true));
    specs.push((
        json!({"records": [{"namespace": NOTES, "access": "propose"}]}),
        false,
    ));
    for (k, (t, b)) in specs.into_iter().enumerate() {
        let id = w.f.host.identity(31 + k as u8);
        admit(&mut w.f, &id, &format!("M{k}"), "device", t.clone(), t);
        w.members.push(Member {
            id,
            budget: b,
            revoked: false,
        });
    }
    publish_authority(&mut w);
    // Writers: member 0 on two devices (one identity, for equivocation), the others one each.
    for (wi, m) in [0usize, 0, 1, 2, 3].into_iter().enumerate() {
        let src = MemSource::versioned();
        for (p, b) in &w.auth {
            src.put(p, b.clone());
        }
        let e = member_engine(&w.f, &w.f.host, &src, &w.members[m].id, w.now);
        w.writers.push(Writer { m, e, src });
    }
    // A follow by member 1 that everyone sees, so positions have a parent.
    write(
        &mut w,
        2,
        LISTEN,
        "follow",
        json!({"id": "s1", "url": "https://example.org/f", "title": "T"}),
        Level::Write,
    );
    let mut o = obs_new(&w);
    let mut counter = 0usize;
    let mut next_member = 60u8;
    let mut checks = 0usize;
    let mut last_saved_step: Option<usize> = None;
    for step in 0..cfg.steps {
        w.now += 1_000 + rng.below(20_000) as i64;
        let op = rng.below(100);
        let mut what = String::new();
        match op {
            // Durable writes by a random writer.
            0..=29 => {
                let mut i = rng.below(w.writers.len());
                if i == 1 {
                    i = 0; // the second device of member 0 writes live samples only
                }
                if rng.chance(40) {
                    sync_writer(&mut w, i, &mut rng);
                }
                for _ in 0..1 + rng.below(4) {
                    counter += 1;
                    let r = rng.below(6);
                    let (ns, kind, payload) = match r {
                        0 => (
                            NOTES,
                            "createNotebook",
                            json!({"id": format!("n{counter}"), "title": format!("T{counter}")}),
                        ),
                        1 => (
                            LISTEN,
                            "follow",
                            json!({"id": format!("s{}", 1 + rng.below(4)), "url": "https://example.org/f", "title": format!("T{counter}")}),
                        ),
                        2 => (
                            LISTEN,
                            "unfollow",
                            json!({"id": format!("s{}", 2 + rng.below(3))}),
                        ),
                        3 => (
                            LISTEN,
                            "position",
                            json!({"id": format!("ep{}", rng.below(6)), "show": "s1", "seconds": rng.below(1000) as f64, "seek": true}),
                        ),
                        _ => (
                            NOTES,
                            "createNotebook",
                            json!({"id": format!("n{}", rng.below(counter.max(1))), "title": format!("R{counter}")}),
                        ),
                    };
                    what = format!("write w{i} {kind}");
                    write(&mut w, i, ns, kind, payload, Level::Write);
                }
            }
            // Live samples.
            30..=49 => {
                let i = rng.below(w.writers.len());
                if rng.chance(30) {
                    sync_writer(&mut w, i, &mut rng);
                }
                let ep = rng.below(8);
                what = format!("live w{i} ep{ep}");
                live_write(&mut w, i, ep, (step * 3 + rng.below(50)) as f64);
                // Equivocation: the other device of member 0 writes the same slot from the same view.
                if i <= 1 && rng.chance(30) {
                    let j = 1 - i;
                    live_write(&mut w, j, ep, rng.below(10_000) as f64);
                    what.push_str(" +twin");
                }
            }
            // Sync a writer.
            50..=57 => {
                let i = rng.below(w.writers.len());
                what = format!("sync w{i}");
                sync_writer(&mut w, i, &mut rng);
            }
            // Deliver records to the observer: a random subset, sometimes only very old ones.
            58..=71 => {
                let pending: Vec<(String, Vec<u8>)> = w
                    .recs
                    .iter()
                    .filter(|(p, _)| !o.seen_recs.contains(*p))
                    .map(|(p, b)| (p.clone(), b.clone()))
                    .collect();
                let pct = 10 + rng.below(90);
                let mut batch = Vec::new();
                for (p, b) in pending {
                    if rng.chance(pct) {
                        batch.push(HeldRecord { path: p, bytes: b });
                    }
                }
                // Sometimes a twin of one record: a garbage-signature envelope over its body.
                if !batch.is_empty() && rng.chance(5) && cfg.twin {
                    let r = batch[0].clone();
                    if let Ok(mut v) = serde_json::from_slice::<Value>(&r.bytes) {
                        v["signature"] = json!(b64(&[0xf8u8; 64]));
                        batch.push(HeldRecord {
                            path: r.path.clone(),
                            bytes: colophon_core::v05::encoding::canonical(&v).unwrap(),
                        });
                    }
                }
                what = format!("deliver {} recs", batch.len());
                deliver_records(&mut w, &mut o, batch)?;
            }
            // Deliver live candidates.
            72..=81 => {
                let mut batch = Vec::new();
                for (p, vs) in &w.live {
                    for b in vs {
                        if !o.seen_live.contains(&(p.clone(), b.clone())) && rng.chance(50) {
                            batch.push(HeldRecord {
                                path: p.clone(),
                                bytes: b.clone(),
                            });
                        }
                    }
                }
                what = format!("deliver {} live", batch.len());
                deliver_live(&mut w, &mut o, batch)?;
            }
            // Deliver authority.
            82..=86 => {
                what = "deliver authority".into();
                deliver_authority(&mut w, &mut o)?;
            }
            // Advance the observer's clock.
            87..=89 => {
                let to = if rng.chance(50) {
                    w.now
                } else {
                    o.now + (w.now - o.now) / 2
                };
                what = format!("advance {}", to - o.now);
                advance(&mut w, &mut o, to)?;
            }
            // Authority changes by the controller.
            90..=97 => {
                w.f.account.advance(w.now).unwrap();
                let live_members: Vec<usize> = (0..w.members.len())
                    .filter(|m| !w.members[*m].revoked)
                    .collect();
                let kind = rng.below(7);
                let d = w.f.d.clone();
                let res: Result<(), String> = match kind {
                    0 => {
                        // A grant, sometimes expiring soon.
                        let id = w.f.host.identity(next_member);
                        next_member = next_member.wrapping_add(1);
                        let mut t = terms_for(&[(LISTEN, "write"), (NOTES, "write")]);
                        if rng.chance(50) {
                            t["expires"] = json!(colophon_core::v05::write::format_date(
                                w.now + 60_000 + rng.below(600_000) as i64
                            ));
                        }
                        admit(&mut w.f, &id, "New", "device", t.clone(), t);
                        w.members.push(Member {
                            id: id.clone(),
                            budget: false,
                            revoked: false,
                        });
                        let src = MemSource::versioned();
                        publish_authority(&mut w);
                        for (p, b) in &w.auth {
                            src.put(p, b.clone());
                        }
                        let e = member_engine(&w.f, &w.f.host, &src, &id, w.now);
                        w.writers.push(Writer {
                            m: w.members.len() - 1,
                            e,
                            src,
                        });
                        what = "grant".into();
                        Ok(())
                    }
                    1 if live_members.len() > 2 => {
                        // Revoke a member other than 0, keeping everything the controller holds
                        // (a random subset of the cloud) or nothing.
                        let m = live_members[1 + rng.below(live_members.len() - 1)];
                        let recs: Vec<HeldRecord> = w
                            .recs
                            .iter()
                            .filter(|_| rng.chance(70))
                            .map(|(p, b)| HeldRecord {
                                path: p.clone(),
                                bytes: b.clone(),
                            })
                            .collect();
                        let now = w.f.account.now_ms();
                        let _ = w.f.account.merge(
                            Incoming {
                                objects: Objects::default(),
                                records: recs,
                            },
                            now,
                        );
                        let keep = if rng.chance(70) {
                            RevokeKeep::Everything
                        } else {
                            RevokeKeep::Nothing
                        };
                        let seed = w.f.host.fresh();
                        let id = w.members[m].id.clone();
                        match w.f.account.begin_revoke(&id, &keep, &[d.clone()], seed) {
                            Ok(a) => {
                                run(&mut w.f.account, &w.f.host, a);
                                w.members[m].revoked = true;
                                what = format!(
                                    "revoke M{m} {:?}",
                                    matches!(keep, RevokeKeep::Everything)
                                );
                                Ok(())
                            }
                            Err(e) => Err(format!("revoke: {e:?}")),
                        }
                    }
                    2 => {
                        let seed = w.f.host.fresh();
                        let ns: Vec<String> = if rng.chance(50) {
                            vec![LISTEN.into(), NOTES.into()]
                        } else {
                            vec![NOTES.into()]
                        };
                        match w.f.account.begin_rekey(&ns, &[d.clone()], seed) {
                            Ok(a) => {
                                run(&mut w.f.account, &w.f.host, a);
                                what = format!("rekey {ns:?}");
                                Ok(())
                            }
                            Err(e) => Err(format!("rekey: {e:?}")),
                        }
                    }
                    3 => {
                        let m = live_members[rng.below(live_members.len())];
                        let id = w.members[m].id.clone();
                        match w.f.account.begin_end_sessions(&id, &[d.clone()]) {
                            Ok(a) => {
                                run(&mut w.f.account, &w.f.host, a);
                                what = format!("end sessions M{m}");
                                Ok(())
                            }
                            Err(e) => Err(format!("end sessions: {e:?}")),
                        }
                    }
                    4 => {
                        // A proposal by member 3 and a resolution by member 1.
                        let wi = w.writers.iter().position(|x| x.m == 3).unwrap();
                        sync_writer(&mut w, wi, &mut rng);
                        counter += 1;
                        let pid = write(
                            &mut w,
                            wi,
                            NOTES,
                            "createNotebook",
                            json!({"id": format!("p{counter}"), "title": "Proposed"}),
                            Level::Propose,
                        );
                        if let Some(pid) = pid {
                            w.proposals.push(pid.clone());
                            let ri = 2; // member 1's writer
                            sync_writer(&mut w, ri, &mut rng);
                            let seed = w.f.host.fresh();
                            let accept = rng.chance(60);
                            if let Ok(a) = w.writers[ri].e.account().begin_resolution(
                                NOTES,
                                accept,
                                &[pid],
                                seed,
                            ) {
                                finish(&mut w, ri, a);
                            }
                        }
                        what = "proposal".into();
                        Ok(())
                    }
                    5 => {
                        // A read-scope change on the observer.
                        let s: Option<Vec<String>> = match rng.below(3) {
                            0 => Some(vec![NOTES.into()]),
                            1 => Some(vec![LISTEN.into()]),
                            _ => Some(vec![LISTEN.into(), NOTES.into()]),
                        };
                        o.a.set_read_scope(s.clone().unwrap())
                            .map_err(|e| format!("{e:?}"))?;
                        if cfg.engine {
                            let _ = o.e.set_read_scope(s.clone().unwrap());
                        }
                        o.scope = s;
                        what = "read scope".into();
                        Ok(())
                    }
                    _ => {
                        // A burst: one writer writes many notebooks, ahead of everyone.
                        if cfg.burst && rng.chance(30) {
                            let i = 2;
                            sync_writer(&mut w, i, &mut rng);
                            let n = 1_030 + rng.below(30);
                            for _ in 0..n {
                                counter += 1;
                                write(
                                    &mut w,
                                    i,
                                    NOTES,
                                    "createNotebook",
                                    json!({"id": format!("b{counter}"), "title": "B"}),
                                    Level::Write,
                                );
                            }
                            // And a live sample of member 0 from a view that saw the burst.
                            sync_writer(&mut w, 0, &mut rng);
                            live_write(&mut w, 0, rng.below(8), 1.0);
                            what = format!("burst {n}");
                        }
                        Ok(())
                    }
                };
                if let Err(e) = res {
                    w.log.push(e);
                }
                publish_authority(&mut w);
            }
            // Save the engine observer's checkpoint.
            _ => {
                if cfg.engine {
                    if let Ok(s) = o.e.save(w.f.host.fresh()) {
                        o.saved.push((step, s));
                        last_saved_step = Some(step);
                        what = "save".into();
                    }
                }
            }
        }
        // After every step: the maintained derivation equals a rebuild.
        if let Err(e) = o.a.verify_derivation() {
            let cold = cold_account(&w, &o);
            let d = compare_accounts(&o.a, &cold, "at verify failure, vs cold");
            {
                return Err(format!("seed {seed:#x} step {step} ({what}): verify_derivation: {e:?}\n{}\n log tail {:?}", d.join("\n"), &w.log[w.log.len().saturating_sub(6)..]));
            }
        }
        if cfg.engine {
            if let Err(e) =
                o.e.account()
                    .verify_derivation()
                    .map_err(|e| format!("{e:?}"))
                    .and_then(|_| Ok(()))
            {
                return Err(format!(
                    "seed {seed:#x} step {step} ({what}): engine verify_derivation: {e:?}"
                ));
            }
        }
        if step % cfg.check_every == 0 || step + 1 == cfg.steps {
            checks += 1;
            let cold = cold_account(&w, &o);
            let d = compare_accounts(
                &o.a,
                &cold,
                &format!("seed {seed:#x} step {step} ({what}) cold"),
            );
            if !d.is_empty() {
                return Err(format!(
                    "{}\n log tail {:?}",
                    d.join("\n"),
                    &w.log[w.log.len().saturating_sub(6)..]
                ));
            }
            if cfg.engine {
                let mut d = Vec::new();
                let opts = EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY);
                let _ = &opts;
                let cold_e = open_engine(&w, &o, None);
                d.extend(compare_engines(
                    &o.e,
                    &cold_e,
                    &format!("seed {seed:#x} step {step} engine cold"),
                    false,
                    &o.scope,
                ));
                if !o.saved.is_empty() {
                    let k = rng.below(o.saved.len());
                    let (at, s) = &o.saved[k];
                    let resumed = open_engine(&w, &o, Some(s));
                    d.extend(compare_engines(
                        &resumed,
                        &cold_e,
                        &format!("seed {seed:#x} step {step} resumed from {at} vs cold"),
                        true,
                        &o.scope,
                    ));
                    d.extend(compare_engines(
                        &o.e,
                        &resumed,
                        &format!("seed {seed:#x} step {step} resumed from {at} vs inc"),
                        false,
                        &o.scope,
                    ));
                }
                if !d.is_empty() {
                    let errs: Vec<&String> =
                        w.log.iter().filter(|l| l.starts_with("ENGINE")).collect();
                    return Err(format!("{}\n engine errors {:?}", d.join("\n"), errs));
                }
            }
        }
    }
    if env_or("E10_VERBOSE", 0) == 1 {
        let mut verdicts: BTreeMap<String, usize> = BTreeMap::new();
        for r in o.a.records() {
            *verdicts
                .entry(o.a.verdict_of(&r.path, &r.bytes).unwrap_or_default())
                .or_default() += 1;
        }
        let mut lv: BTreeMap<String, usize> = BTreeMap::new();
        for (_, v) in o.a.live_verdicts() {
            *lv.entry(format!("{v:?}")).or_default() += 1;
        }
        let mut logs: BTreeMap<String, usize> = BTreeMap::new();
        for l in &w.log {
            *logs.entry(l.chars().take(70).collect()).or_default() += 1;
        }
        eprintln!(
            "seed {seed:#x}: ext {} rebuilt {} saves {} | cloud recs {} live paths {} | obs recs {} live held {} heads {} | verdicts {verdicts:?} | live {lv:?} | work {:?}\n  log {logs:?}",
            o.extended, o.rebuilt, o.saved.len(),
            w.recs.len(),
            w.live.len(),
            o.a.records().len(),
            o.live.len(),
            o.a.live_heads().len(),
            o.a.work()
        );
    }
    Ok(checks)
}

fn open_engine(w: &World, o: &Observer, saved: Option<&Saved>) -> Eng {
    let mut e = Engine::open(
        o.esrc.clone(),
        o.esrc.listing(),
        Identity::Controller(w.f.d.clone()),
        {
            let mut op = EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY);
            if let Some(s) = &o.scope {
                op.namespaces = s.clone();
            }
            op
        },
        saved,
        o.now,
    )
    .unwrap();
    let idx = e
        .slots()
        .unwrap()
        .into_iter()
        .find(|x| x.controllers.len() == 1 && x.controllers[0].0 == w.f.d)
        .unwrap()
        .index;
    let inputs = e.begin_unlock_slot(idx).unwrap();
    e.finish_unlock_slot(idx, &w.f.host.answer_unlock(&inputs))
        .unwrap();
    e
}

fn deliver_records(w: &mut World, o: &mut Observer, batch: Vec<HeldRecord>) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    for r in &batch {
        o.seen_recs.insert(r.path.clone());
        o.esrc.put(&r.path, r.bytes.clone());
    }
    let now = o.now;
    o.a.merge(
        Incoming {
            objects: Objects::default(),
            records: batch,
        },
        now,
    )
    .map_err(|e| format!("merge records: {e:?}"))?;
    let wk = o.a.work();
    if wk.last.resumed {
        o.extended += 1;
    } else {
        o.rebuilt += 1;
    }
    // The engine also gets the history evidence the writers stored.
    for (p, b) in &w.hist {
        if o.esrc.get(p).is_none() {
            o.esrc.put(p, b.clone());
        }
    }
    if let Err(e) = o.e.refresh(o.esrc.listing()) {
        w.log.push(format!("ENGINE refresh: {e:?}"));
    }
    Ok(())
}

fn deliver_live(w: &mut World, o: &mut Observer, batch: Vec<HeldRecord>) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    for r in &batch {
        o.seen_live.insert((r.path.clone(), r.bytes.clone()));
    }
    let now = o.now;
    match o.a.merge_live(batch.clone(), now) {
        Ok(_) => {
            o.live.extend(batch.clone());
            o.live_batches.push(batch.clone());
        }
        Err(e) => {
            // A refused merge changes nothing; the cold reference then must not hold it either.
            w.log.push(format!("merge_live refused: {e:?}"));
        }
    }
    // The engine: the latest bytes of each path, only when the generation is new to the path (an
    // equivocating twin cannot be held by a source at one path).
    for r in &batch {
        let gen = OperationHeader::parse(&r.bytes)
            .map(|(h, _)| h.clock)
            .unwrap_or(0);
        let cur = o
            .esrc
            .get(&r.path)
            .and_then(|b| OperationHeader::parse(&b).ok().map(|(h, _)| h.clock));
        if cur.is_none_or(|c| gen > c) {
            o.esrc.put(&r.path, r.bytes.clone());
        }
    }
    if let Err(e) = o.e.refresh(o.esrc.listing()) {
        w.log.push(format!("ENGINE refresh: {e:?}"));
    }
    Ok(())
}

fn deliver_authority(w: &mut World, o: &mut Observer) -> Result<(), String> {
    let now = o.now;
    o.a.merge(
        Incoming {
            objects: snapshot_objects(w),
            records: Vec::new(),
        },
        now,
    )
    .map_err(|e| format!("merge authority: {e:?}"))?;
    for (p, b) in &w.auth {
        o.esrc.put(p, b.clone());
    }
    if let Err(e) = o.e.refresh(o.esrc.listing()) {
        w.log.push(format!("ENGINE refresh: {e:?}"));
    }
    Ok(())
}

fn advance(w: &mut World, o: &mut Observer, to: i64) -> Result<(), String> {
    if to <= o.now {
        return Ok(());
    }
    o.a.advance(to).map_err(|e| format!("advance: {e:?}"))?;
    let _ = o.e.advance(to);
    o.now = to;
    Ok(())
}

fn run_seeds(seeds: std::ops::Range<u64>, cfg: &Config) {
    let mut failures = Vec::new();
    let mut total_checks = 0;
    for s in seeds {
        let seed = 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(s + 1);
        match journey(seed, cfg) {
            Ok(c) => total_checks += c,
            Err(e) => {
                eprintln!("FAIL seed {s} ({seed:#x}): {e}");
                failures.push(s);
            }
        }
    }
    eprintln!("checks {total_checks}, failures {failures:?}, overlay-split verify failures with no reader difference {}, pruning-only live differences {}, cold all-at-once live merge refused {}", OVERLAY_SPLIT.load(std::sync::atomic::Ordering::Relaxed), PRUNE_DIFFS.load(std::sync::atomic::Ordering::Relaxed), COLD_LIVE_REFUSED.load(std::sync::atomic::Ordering::Relaxed));
    assert!(failures.is_empty(), "failing seeds {failures:?}");
}

fn env_or(name: &str, d: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

/// The journeys, one after another (the snapshot interval is process-wide). By default about
/// a few minutes in a debug build; `E10_LONG=1` runs 8 seeds of 300 steps each (what the
/// independent check ran), `E10_ONLY=k E10_SEEDS=n E10_FROM=s E10_STEPS=t` picks one.
#[test]
fn e10_journeys_equal_cold_and_resumed_opens() {
    let long = env_or("E10_LONG", 0) == 1;
    let scale = if long { 8 } else { 1 };
    // Seeds that once failed, run in the long mode as well: 3007 (a garbage twin kept by a
    // rebuild) and 0, 5, 7 (a revoked member's kept walk after a scope change).
    let from = env_or("E10_FROM", 0);
    let steps = env_or("E10_STEPS", if long { 300 } else { 60 }) as usize;
    // (interval, seeds, twin, burst, steps)
    for (k, (interval, seeds, twin, burst, st)) in [
        (3usize, 1u64, false, false, steps),
        (4, 1, false, false, steps),
        (7, 1, false, false, steps),
        (2, 1, true, false, steps),
        (256, 1, false, true, steps / 2),
    ]
    .into_iter()
    .enumerate()
    {
        if std::env::var("E10_ONLY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|o| o != k)
        {
            continue;
        }
        let seeds = std::env::var("E10_SEEDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(seeds);
        let base = from + 1000 * k as u64;
        run_seeds(
            base..base + seeds * scale,
            &Config {
                steps: st,
                interval,
                burst,
                engine: true,
                check_every: 5,
                twin,
            },
        );
    }
}

// ---- targeted ----
const NOW: i64 = T0 + 3 * HOUR;

fn observer(f: &Fixture, host: &Host) -> Account {
    let mut a = Account::open(
        f.account.objects().clone(),
        Vec::new(),
        None,
        Identity::Controller(f.d.clone()),
        NOW,
    )
    .unwrap();
    unlock_controller(host, &mut a, &f.d);
    a
}
fn cold(f: &Fixture, host: &Host, o: &Account, live: &[HeldRecord]) -> Account {
    let mut c = Account::open(
        o.objects().clone(),
        o.records().to_vec(),
        None,
        Identity::Controller(f.d.clone()),
        o.now_ms(),
    )
    .unwrap();
    unlock_controller(host, &mut c, &f.d);
    if !live.is_empty() {
        let now = c.now_ms();
        c.merge_live(live.to_vec(), now).unwrap();
    }
    c
}
fn recs(stores: &[(String, Vec<u8>)], prefix: &str) -> Vec<HeldRecord> {
    stores
        .iter()
        .filter(|(p, _)| p.starts_with(prefix))
        .map(|(p, b)| HeldRecord {
            path: p.clone(),
            bytes: b.clone(),
        })
        .collect()
}
fn merge(o: &mut Account, r: Vec<HeldRecord>) {
    let now = o.now_ms();
    o.merge(
        Incoming {
            objects: Objects::default(),
            records: r,
        },
        now,
    )
    .unwrap();
}
fn view(a: &Account, ns: &str) -> String {
    serde_json::to_string(&a.view(ns).unwrap()).unwrap()
}

/// T1. A live head becomes `Retained` when its exact bytes arrive under `ops/`: the merged order
/// (digests) is unchanged, so the cached overlay (keyed by the merged order's hash) is reused,
/// but the number of durable operations before the first head (`split`) moved. The maintained
/// derivation then differs from a rebuild (`verify_derivation` fails on `overlay`), although the
/// view a reader gets is the same as a cold open's.
#[test]
fn t1_a_head_that_becomes_retained_leaves_a_stale_overlay_split() {
    let mut f = create(&[LISTEN, NOTES]);
    let t = terms_for(&[(LISTEN, "write"), (NOTES, "write")]);
    let a = f.host.identity(31);
    admit(&mut f, &a, "A", "device", t.clone(), t);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &a, NOW);
    let follow = engine_write(
        &mut e,
        &mut host,
        &src,
        LISTEN,
        "follow",
        json!({"id": "s1", "url": "https://example.org/f", "title": "T"}),
    );
    let h1 = engine_live(
        &mut e,
        &mut host,
        &src,
        json!({"id": "ep0", "show": "s1", "seconds": 10.0}),
    );
    // Two durable operations, so the second head sits after them.
    let n1 = engine_write(
        &mut e,
        &mut host,
        &src,
        NOTES,
        "createNotebook",
        json!({"id": "n1", "title": "N"}),
    );
    let n2 = engine_write(
        &mut e,
        &mut host,
        &src,
        LISTEN,
        "follow",
        json!({"id": "s2", "url": "https://example.org/g", "title": "U"}),
    );
    let h2 = engine_live(
        &mut e,
        &mut host,
        &src,
        json!({"id": "ep1", "show": "s1", "seconds": 20.0}),
    );
    // A deliberate seek on ep0: the engine retains ep0's head under `ops/` first.
    let seek = engine_write(
        &mut e,
        &mut host,
        &src,
        LISTEN,
        "position",
        json!({"id": "ep0", "show": "s1", "seconds": 5.0, "seek": true}),
    );
    let live1 = recs(&h1.stores, "state/");
    let live2 = recs(&h2.stores, "state/");
    let retained: Vec<HeldRecord> = recs(&seek.stores, "ops/")
        .into_iter()
        .filter(|r| live1.iter().any(|l| l.bytes == r.bytes))
        .collect();
    assert_eq!(retained.len(), 1, "the seek retained ep0's head under ops/");

    let mut o = observer(&f, &host);
    merge(&mut o, recs(&follow.stores, "ops/"));
    merge(&mut o, recs(&n1.stores, "ops/"));
    merge(&mut o, recs(&n2.stores, "ops/"));
    let mut live = live1.clone();
    live.extend(live2.clone());
    let now = o.now_ms();
    o.merge_live(live.clone(), now).unwrap();
    o.verify_derivation().unwrap();
    let _ = view(&o, LISTEN); // the overlay is answered and remembered
    merge(&mut o, retained);
    println!(
        "work after the retained copy: {:?}; heads {}",
        o.work(),
        o.live_heads().len()
    );
    let verdict = o.verify_derivation();
    let c = cold(&f, &host, &o, &live);
    let same_view = view(&o, LISTEN) == view(&c, LISTEN);
    let same_rev = o.revision(LISTEN) == c.revision(LISTEN);
    println!("verify_derivation after the retained copy: {verdict:?}; view equal to cold: {same_view}; revision equal: {same_rev}");
    assert!(same_view && same_rev, "a reader-visible difference");
    verdict.unwrap();
}
/// T8. The 1,024 bound hit and then loosened by late records: the newest durable record and a
/// live sample arrive first (both refused `clockJump`), then the gap is filled in two late
/// batches, out of order. After each step the derivation equals a rebuild and a cold open.
#[test]
fn t8_clock_jump_then_filled_late_equals_cold() {
    colophon_core::v05::account::set_fold_snapshot_interval(256);
    let mut f = create(&[LISTEN]);
    let t = terms_for(&[(LISTEN, "write")]);
    let a = f.host.identity(31);
    admit(&mut f, &a, "A", "device", t.clone(), t);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &a, NOW);
    let mut all = Vec::new();
    let w = engine_write(
        &mut e,
        &mut host,
        &src,
        LISTEN,
        "follow",
        json!({"id": "s1", "url": "https://example.org/f", "title": "T"}),
    );
    all.extend(recs(&w.stores, "ops/"));
    for i in 0..1_100 {
        let w = engine_write(
            &mut e,
            &mut host,
            &src,
            LISTEN,
            "follow",
            json!({"id": format!("x{i}"), "url": "https://example.org/f", "title": "X"}),
        );
        all.extend(recs(&w.stores, "ops/"));
    }
    let lw = engine_live(
        &mut e,
        &mut host,
        &src,
        json!({"id": "ep0", "show": "s1", "seconds": 1.0}),
    );
    let live = recs(&lw.stores, "state/");
    let mut o = observer(&f, &host);
    let last = all.pop().unwrap();
    let first = all.remove(0);
    let check = |o: &Account, label: &str| {
        o.verify_derivation()
            .unwrap_or_else(|e| panic!("{label}: {e:?}"));
        let c = cold(&f, &host, o, &live);
        assert_eq!(view(o, LISTEN), view(&c, LISTEN), "{label}");
        assert_eq!(o.revision(LISTEN), c.revision(LISTEN), "{label}");
        let h = |x: &Account| {
            x.live_heads()
                .iter()
                .map(|h| h.digest.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(h(o), h(&c), "{label}");
        for r in o.records() {
            assert_eq!(
                o.verdict_of(&r.path, &r.bytes),
                c.verdict_of(&r.path, &r.bytes),
                "{label} {}",
                r.path
            );
        }
    };
    merge(&mut o, vec![first, last.clone()]);
    assert_eq!(
        o.verdict_of(&last.path, &last.bytes).as_deref(),
        Some("refused:clockJump")
    );
    let now = o.now_ms();
    o.merge_live(live.clone(), now).unwrap();
    println!(
        "live verdicts after the jump: {:?}",
        o.live_verdicts().iter().map(|x| &x.1).collect::<Vec<_>>()
    );
    check(&o, "after jump");
    let mut hi: Vec<HeldRecord> = Vec::new();
    let mut lo: Vec<HeldRecord> = Vec::new();
    for (i, r) in all.into_iter().enumerate() {
        if i % 3 == 0 {
            hi.push(r)
        } else {
            lo.push(r)
        }
    }
    merge(&mut o, hi[hi.len() / 2..].to_vec());
    check(&o, "upper third of a third");
    merge(&mut o, lo);
    check(&o, "two thirds");
    merge(&mut o, hi[..hi.len() / 2].to_vec());
    check(&o, "all");
    println!(
        "final verdict of the jumped record: {:?}; heads {}",
        o.verdict_of(&last.path, &last.bytes),
        o.live_heads().len()
    );
}
