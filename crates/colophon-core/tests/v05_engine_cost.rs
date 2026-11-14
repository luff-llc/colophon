//! What the engine costs, opt in: `cargo test -p colophon-core --release --test v05_engine_cost
//! -- --ignored --nocapture`. For N = 1,000 and 10,000 held records it prints cold open,
//! resumed open, one write, a refresh adding 100 records, a first sync from a home and a live
//! write, each as signature checks, decryptions, fold applications and wall time. Nothing here
//! asserts a time; the assertions are the counts that must not depend on N.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::engine::{Engine, EngineStats};
use serde_json::json;
use std::time::Instant;
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";

fn row(label: &str, before: &EngineStats, after: &EngineStats, t: Instant) {
    println!(
        "  {label:<34} {:>9.1} ms  sig {:>6}  dec {:>6}  fold {:>6}  walked {:>6}",
        t.elapsed().as_secs_f64() * 1e3,
        after.signatures_verified - before.signatures_verified,
        after.payloads_decrypted - before.payloads_decrypted,
        after.folds_applied_last,
        after.walked_last,
    );
}

fn run(n: usize) {
    println!("N = {n}");
    let (mut s, ids) = setup(NS, &[("Writer", 31, "write")]);
    let writer = ids[0].clone();
    let src = device_source(&s);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let mut e = member_engine(&s.f, &host, &src, &writer, NOW);
    let t = Instant::now();
    for i in 0..n {
        engine_write(&mut e, &mut host, &src, NS, "createNotebook", json!({"id": format!("n{i}"), "title": format!("Notebook {i}")}));
    }
    println!("  (building {n} records by {n} writes took {:.1} s)", t.elapsed().as_secs_f64());
    let saved = e.save([1; 32]).unwrap();
    let mem = saved.parts.values().map(Vec::len).sum::<usize>() + saved.checkpoint.len();

    // Cold open.
    let t = Instant::now();
    let cold = member_engine(&s.f, &host, &src, &writer, NOW);
    row("cold open + unlock + load", &EngineStats::default(), &cold.stats(), t);
    // Resumed open, nothing new.
    let t = Instant::now();
    let mut r = Engine::open(
        src.clone(),
        src.listing(),
        colophon_core::v05::account::Identity::Member(writer.clone()),
        colophon_core::v05::engine::EngineOptions::new(s.f.account.id().as_str(), DEVICE_KEY),
        Some(&saved),
        NOW,
    )
    .unwrap();
    let steps = r.begin_unlock_epochs();
    r.finish_unlock_epochs(host.answer_epochs(&writer, steps)).unwrap();
    row("resumed open (nothing new)", &EngineStats::default(), &r.stats(), t);
    assert_eq!(r.stats().signatures_verified, 0);
    assert_eq!(r.stats().folds_applied_last, 0);
    // One write.
    let before = r.stats();
    let t = Instant::now();
    engine_write(&mut r, &mut host, &src, NS, "createNotebook", json!({"id": "one", "title": "One"}));
    row("one write (prepare + finish)", &before, &r.stats(), t);
    assert!(r.stats().signatures_verified - before.signatures_verified <= 2);
    // A refresh adding 100 records (written by another session of the same writer's chain).
    let mut other = member_engine(&s.f, &host, &src, &writer, NOW);
    let other_src = src.clone();
    for i in 0..100 {
        engine_write(&mut other, &mut host, &other_src, NS, "createNotebook", json!({"id": format!("m{i}"), "title": "M"}));
    }
    let before = r.stats();
    let t = Instant::now();
    r.refresh(src.listing()).unwrap();
    row("refresh adding 100 records", &before, &r.stats(), t);
    assert_eq!(r.stats().signatures_verified - before.signatures_verified, 100);

    // First sync from a home that holds everything.
    let mut files = 0;
    for p in src.listing() {
        if p.starts_with("ops/") {
            s.sim.files.insert(p.clone(), src.get(&p).unwrap());
            s.sim.log.push(p);
            files += 1;
        }
    }
    let fresh_src = device_source(&s);
    let mut fresh = member_engine(&s.f, &host, &fresh_src, &writer, NOW);
    let home = s.home.clone();
    let before = fresh.stats();
    let t = Instant::now();
    let faults = sync_pass(&mut fresh, &fresh_src, &home, &mut s.sim, &host, NOW + 1_000);
    row(&format!("first sync of {files} records"), &before, &fresh.stats(), t);
    assert!(faults.iter().all(|f| matches!(f, colophon_core::v05::engine::exchange::Fault::More { .. })), "{faults:?}");

    println!("  sealed checkpoint: {} KiB for {n} records", mem / 1024);
}

fn live(slots: usize) {
    let (mut s, ids) = setup("listening.podcasts", &[("Phone", 31, "write")]);
    let id = ids[0].clone();
    let src = device_source(&s);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let mut e = member_engine(&s.f, &host, &src, &id, NOW);
    engine_write(&mut e, &mut host, &src, "listening.podcasts", "follow", json!({"id": "show", "url": "https://example.org/f", "title": "T"}));
    let t = Instant::now();
    for i in 0..slots {
        engine_live(&mut e, &mut host, &src, json!({"id": format!("ep{i}"), "show": "show", "seconds": 1.0}));
    }
    println!("L = {slots} live slots (built in {:.1} s)", t.elapsed().as_secs_f64());
    let before = e.stats();
    let t = Instant::now();
    engine_live(&mut e, &mut host, &src, json!({"id": "ep0", "show": "show", "seconds": 2.0}));
    row("one live write", &before, &e.stats(), t);
}

#[test]
#[ignore]
fn cost_of_open_resume_write_refresh_sync_for_1000_records() {
    run(1_000);
}
#[test]
#[ignore]
fn cost_of_open_resume_write_refresh_sync_for_10000_records() {
    run(10_000);
}
#[test]
#[ignore]
fn cost_of_a_live_write_with_1000_and_2000_slots() {
    live(1_000);
    live(2_000);
}
