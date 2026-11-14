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
