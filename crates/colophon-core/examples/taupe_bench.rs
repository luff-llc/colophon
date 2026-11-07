//! Taupe-shaped playback-progress benchmark: immutable ops vs replaceable live state.
#![allow(clippy::unwrap_used)]
#[path = "../tests/support/mod.rs"]
mod support;
use colophon_core::{crypto::SoftwareKeys, library::Library};
use serde_json::json;
use std::time::Instant;
use support::*;

fn unlock(lib: &mut Library, owner: &SoftwareKeys) {
    let results = lib
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    lib.finish_unlock_many(results).unwrap();
}

fn position(lib: &mut Library, owner: &SoftwareKeys, seconds: u64, seek: bool) {
    let mut entropy = [0u8; 32];
    entropy[..8].copy_from_slice(&seconds.to_le_bytes());
    entropy[8] = if seek { 1 } else { 0 };
    let pending = success(
        lib.begin_write(
            "listening.podcasts",
            "position",
            json!({"id":"ep","seconds":seconds as f64,"seek":seek}),
            NOW,
            entropy,
        )
        .unwrap(),
    );
    apply(lib, pending, owner);
}

fn cold_open(records: colophon_core::model::Records, owner: &SoftwareKeys) -> f64 {
    let started = Instant::now();
    let mut lib = Library::open(records, owner.public()).unwrap();
    unlock(&mut lib, owner);
    started.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed.xml"}),
        1,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "episode",
        json!({"id":"ep","show":"show","title":"Episode"}),
        2,
    );
    let baseline = lib.records().len();
    let started = Instant::now();
    for i in 0..n {
        position(&mut lib, &owner, i, true);
    }
    let immutable_ms = started.elapsed().as_secs_f64() * 1000.0;
    let immutable_ops = lib
        .records()
        .keys()
        .filter(|p| p.starts_with("ops/"))
        .count();
    let immutable_records = lib.records().len();
    let immutable_open = cold_open(lib.records().clone(), &owner);

    let (mut live, owner, _) = create();
    write(
        &mut live,
        &owner,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed.xml"}),
        1,
    );
    write(
        &mut live,
        &owner,
        "listening.podcasts",
        "episode",
        json!({"id":"ep","show":"show","title":"Episode"}),
        2,
    );
    let started = Instant::now();
    for i in 0..n {
        position(&mut live, &owner, i, false);
    }
    let live_ms = started.elapsed().as_secs_f64() * 1000.0;
    let live_ops = live
        .records()
        .keys()
        .filter(|p| p.starts_with("ops/"))
        .count();
    let live_state = live
        .records()
        .keys()
        .filter(|p| p.starts_with("state/"))
        .count();
    let live_history = live
        .records()
        .keys()
        .filter(|p| p.starts_with("history/"))
        .count();
    let live_records = live.records().len();
    let live_open = cold_open(live.records().clone(), &owner);

    let immutable_open_paths = lib
        .records()
        .keys()
        .filter(|p| p.starts_with("ops/") || p.starts_with("state/"))
        .count();
    let live_open_paths = live
        .records()
        .keys()
        .filter(|p| p.starts_with("ops/") || p.starts_with("state/"))
        .count();
    println!("taupe-shaped {n} playback samples (baseline records {baseline})");
    println!("immutable seek:true ops={immutable_ops} opening-paths={immutable_open_paths} records={immutable_records} write={immutable_ms:.3} ms cold-open={immutable_open:.3} ms");
    println!("live state: ops={live_ops} state={live_state} history={live_history} opening-paths={live_open_paths} records={live_records} write={live_ms:.3} ms cold-open={live_open:.3} ms");
    println!(
        "opening-path ratio (immutable/live): {:.1}",
        immutable_open_paths as f64 / live_open_paths.max(1) as f64
    );
}
