//! Live heads are an overlay on the durable fold (E10): after every step of a random journey
//! (durable writes and live samples by two devices, records arriving late so that heads sit
//! before durable operations, many slots) each account's maintained derivation equals a
//! rebuild (`Account::verify_derivation`, which also compares the overlay with one plain fold of
//! the merged order), and a cold reopen from the same source reads the same view, query and
//! change token.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use serde_json::json;
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const LISTEN: &str = "listening.podcasts";

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % n
    }
}

fn journey(seed: u64, steps: usize) {
    // Snapshots every few operations, so late records rewind to one.
    colophon_core::v05::account::set_fold_snapshot_interval(3);
    let mut rng = Rng(seed);
    let mut f = create(&[LISTEN]);
    let t = terms_for(&[(LISTEN, "write")]);
    let a = f.host.identity(31);
    let b = f.host.identity(32);
    admit(&mut f, &a, "A", "device", t.clone(), t.clone());
    admit(&mut f, &b, "B", "device", t.clone(), t);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = [
        member_engine(&f, &host, &src, &a, NOW),
        member_engine(&f, &host, &src, &b, NOW),
    ];
    let mut shows = 0usize;
    for step in 0..steps {
        let who = rng.below(2);
        match rng.below(6) {
            0 | 1 => {
                shows += 1;
                engine_write(
                    &mut e[who],
                    &mut host,
                    &src,
                    LISTEN,
                    "follow",
                    json!({"id": format!("s{shows}"), "url": "https://example.org/f", "title": "T"}),
                );
            }
            2..=4 => {
                if shows == 0 {
                    continue;
                }
                let ep = rng.below(12);
                engine_live(
                    &mut e[who],
                    &mut host,
                    &src,
                    json!({"id": format!("ep{ep}"), "show": "s1", "seconds": step as f64}),
                );
            }
            _ => {
                e[who].refresh(src.listing()).unwrap();
            }
        }
        for x in &e {
            x.account().verify_derivation().unwrap();
        }
        if step % 7 == 0 {
            // A cold reopen of one device from the same source and what it has been given.
            let mut cold = member_engine(&f, &host, &src, &a, NOW);
            cold.refresh(src.listing()).unwrap();
            e[0].refresh(src.listing()).unwrap();
            cold.account().verify_derivation().unwrap();
            assert_eq!(cold.revision(LISTEN), e[0].revision(LISTEN), "seed {seed}");
            assert_eq!(
                serde_json::to_string(&cold.view(LISTEN).unwrap()).unwrap(),
                serde_json::to_string(&e[0].view(LISTEN).unwrap()).unwrap(),
                "seed {seed} step {step}"
            );
            assert_eq!(
                serde_json::to_string(&cold.query(LISTEN, "read", json!({})).unwrap()).unwrap(),
                serde_json::to_string(&e[0].query(LISTEN, "read", json!({})).unwrap()).unwrap(),
            );
        }
    }
}

#[test]
fn live_overlay_equals_a_rebuild_after_every_step() {
    for seed in 1..=6u64 {
        journey(seed, 30);
    }
}

const NOTES: &str = "notes";

fn notebook(e: &mut Eng, host: &mut Host, src: &MemSource, n: &str) {
    engine_write(
        e,
        host,
        src,
        NOTES,
        "createNotebook",
        json!({"id": n, "title": n}),
    );
}
type Eng = colophon_core::v05::engine::Engine<MemSource>;

/// A record that sorts before the last of its namespace (a second device with a lower clock) is
/// judged and folded at its place: the walk visits it alone and the fold is taken back to a
/// snapshot, not to nothing; and the result is what a rebuild gives.
#[test]
fn a_late_record_costs_what_it_affects() {
    colophon_core::v05::account::set_fold_snapshot_interval(8);
    let mut f = create(&[NOTES]);
    let t = terms_for(&[(NOTES, "write")]);
    let a = f.host.identity(31);
    let b = f.host.identity(32);
    admit(&mut f, &a, "A", "device", t.clone(), t.clone());
    admit(&mut f, &b, "B", "device", t.clone(), t);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut ea = member_engine(&f, &host, &src, &a, NOW);
    let mut eb = member_engine(&f, &host, &src, &b, NOW);
    for i in 0..60 {
        notebook(&mut ea, &mut host, &src, &format!("a{i}"));
    }
    eb.refresh(src.listing()).unwrap();
    for i in 60..64 {
        notebook(&mut ea, &mut host, &src, &format!("a{i}"));
    }
    // B writes at the clock after what it saw: before A's last four.
    notebook(&mut eb, &mut host, &src, "late");
    let before = ea.stats();
    ea.refresh(src.listing()).unwrap();
    let after = ea.stats();
    ea.account().verify_derivation().unwrap();
    assert_eq!(after.walked_last, 1, "only the late record is walked");
    assert!(
        after.folds_applied_last <= 8 + 6,
        "the fold is taken back to a snapshot, not to nothing: {}",
        after.folds_applied_last
    );
    assert!(after.signatures_verified - before.signatures_verified <= 1);
    let cold = member_engine(&f, &host, &src, &a, NOW);
    let mut cold = cold;
    cold.refresh(src.listing()).unwrap();
    assert_eq!(cold.revision(NOTES), ea.revision(NOTES));
    assert_eq!(
        serde_json::to_string(&cold.view(NOTES).unwrap()).unwrap(),
        serde_json::to_string(&ea.view(NOTES).unwrap()).unwrap()
    );
}

/// Late records at random places among several authors: after every step the maintained
/// derivation equals a rebuild.
#[test]
fn random_late_records_equal_a_rebuild() {
    colophon_core::v05::account::set_fold_snapshot_interval(4);
    for seed in 1..=8u64 {
        let mut rng = Rng(seed * 7919);
        let mut f = create(&[NOTES]);
        let t = terms_for(&[(NOTES, "write")]);
        let ids: Vec<String> = (0..3).map(|i| f.host.identity(40 + i)).collect();
        for (i, id) in ids.iter().enumerate() {
            admit(&mut f, id, &format!("D{i}"), "device", t.clone(), t.clone());
        }
        let src = MemSource::new();
        src.store_account(&f.account);
        let mut host = std::mem::replace(&mut f.host, Host::new());
        let mut e: Vec<Eng> = ids
            .iter()
            .map(|id| member_engine(&f, &host, &src, id, NOW))
            .collect();
        let mut n = 0;
        for _ in 0..40 {
            let who = rng.below(3);
            if rng.below(3) == 0 {
                e[who].refresh(src.listing()).unwrap();
            } else {
                n += 1;
                notebook(&mut e[who], &mut host, &src, &format!("n{n}"));
            }
            for x in &e {
                x.account().verify_derivation().unwrap();
            }
        }
        for x in &mut e {
            x.refresh(src.listing()).unwrap();
            x.account().verify_derivation().unwrap();
        }
        let revs: Vec<u64> = e.iter().map(|x| x.revision(NOTES)).collect();
        assert!(
            revs.windows(2).all(|w| w[0] == w[1]),
            "seed {seed}: {revs:?}"
        );
    }
}
