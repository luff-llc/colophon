//! A cached or incremental derivation always equals the full one: after every step of long
//! random journeys (grants, revocations, rekeys, proposals and their resolutions, writes by
//! several members, records arriving in shuffled batches, some held back and delivered late)
//! the account's maintained derivation is compared with a rebuild from nothing over the same
//! inputs (`Account::verify_derivation`: the judgement, the write index, the live heads and
//! every namespace fold).
#![allow(clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::account::{Incoming, RevokeKeep};
use colophon_core::v05::history::Objects;
use colophon_core::v05::records::{HeldRecord, Level, OperationHeader};
use serde_json::json;
use support::*;

const NS: &str = "notes";
const NS2: &str = "scratch";

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
}

fn deliver(f: &mut Fixture, records: Vec<HeldRecord>) {
    let now = f.account.now_ms();
    f.account
        .merge(
            Incoming {
                objects: Objects::default(),
                records,
            },
            now,
        )
        .unwrap();
}

fn journey(seed: u64, steps: usize) {
    let mut rng = Rng(seed);
    let mut f = create(&[NS, NS2]);
    let mut members: Vec<String> = Vec::new();
    let mut revoked: Vec<String> = Vec::new();
    // Records written and not yet delivered to the controller's account (they arrive late).
    let mut mailbox: Vec<HeldRecord> = Vec::new();
    let mut next_member = 31u8;
    let mut counter = 0usize;
    let mut extended = 0usize;
    for step in 0..steps {
        let live: Vec<String> = members
            .iter()
            .filter(|m| !revoked.contains(m))
            .cloned()
            .collect();
        let op = if live.is_empty() { 0 } else { rng.below(10) };
        match op {
            // A grant.
            0 | 1 if next_member < 120 => {
                let id = f.host.identity(next_member);
                next_member += 1;
                let both = terms_for(&[(NS, "write"), (NS2, "write")]);
                admit(&mut f, &id, "Device", "device", both.clone(), both);
                members.push(id);
            }
            // Writes by one member, delivered in shuffled batches, some held back.
            2..=6 => {
                // What a member wrote earlier has reached the controller before it writes again
                // (a member's session holds its own chain).
                deliver(&mut f, std::mem::take(&mut mailbox));
                let who = live[rng.below(live.len())].clone();
                let mut s = member_session(&f, &who);
                let mut made = Vec::new();
                for _ in 0..1 + rng.below(3) {
                    counter += 1;
                    let seed = f.host.fresh();
                    let ns = if rng.below(3) == 0 { NS2 } else { NS };
                    let action = s
                        .begin_write(
                            ns,
                            "createNotebook",
                            json!({"id": format!("n{counter}"), "title": format!("T{counter}")}),
                            Level::Write,
                            seed,
                        )
                        .unwrap()
                        .unwrap();
                    let done = run(&mut s, &f.host, action);
                    s.verify_derivation().unwrap();
                    // The write extended the derivation: it walked the one new record.
                    let w = s.work();
                    assert!(w.last.resumed && w.last.walked == 1, "{w:?}");
                    extended += 1;
                    made.extend(done.records);
                }
                mailbox.extend(shuffled(&made, rng.next()));
                // Deliver a random prefix of the mailbox.
                let n = rng.below(mailbox.len() + 1);
                let batch: Vec<HeldRecord> = mailbox.drain(..n).collect();
                deliver(&mut f, batch);
            }
            // A proposal by one member and its acceptance by another.
            7 if live.len() >= 2 => {
                deliver(&mut f, std::mem::take(&mut mailbox));
                let (a, b) = (live[0].clone(), live[live.len() - 1].clone());
                let mut sa = member_session(&f, &a);
                counter += 1;
                let seed = f.host.fresh();
                let action = sa
                    .begin_propose(
                        NS,
                        "createNotebook",
                        json!({"id": format!("p{counter}"), "title": "Proposed"}),
                        seed,
                    )
                    .unwrap()
                    .unwrap();
                let done = run(&mut sa, &f.host, action);
                let proposal = OperationHeader::parse(&done.records[0].bytes).unwrap().0.id;
                deliver(&mut f, done.records);
                let mut sb = member_session(&f, &b);
                let seed = f.host.fresh();
                let action = sb
                    .begin_resolution(NS, rng.below(2) == 0, &[proposal], seed)
                    .unwrap();
                let done = run(&mut sb, &f.host, action);
                sb.verify_derivation().unwrap();
                deliver(&mut f, done.records);
            }
            // A rekey.
            8 => {
                deliver(&mut f, std::mem::take(&mut mailbox));
                let seed = f.host.fresh();
                let action = f
                    .account
                    .begin_rekey(&[NS.to_string(), NS2.to_string()], &[f.d.clone()], seed)
                    .unwrap();
                run(&mut f.account, &f.host, action);
            }
            // A revocation keeping everything.
            9 if live.len() >= 2 => {
                deliver(&mut f, std::mem::take(&mut mailbox));
                let who = live[rng.below(live.len())].clone();
                let seed = f.host.fresh();
                let action = f
                    .account
                    .begin_revoke(&who, &RevokeKeep::Everything, &[f.d.clone()], seed)
                    .unwrap();
                run(&mut f.account, &f.host, action);
                revoked.push(who);
            }
            _ => {}
        }
        f.account
            .verify_derivation()
            .unwrap_or_else(|e| panic!("seed {seed:#x} step {step} op {op}: {e:?}"));
    }
    deliver(&mut f, std::mem::take(&mut mailbox));
    f.account.verify_derivation().unwrap();
    assert!(extended > 0, "the journey wrote at least once");
}

#[test]
fn the_maintained_derivation_equals_a_rebuild_after_every_step_of_random_journeys() {
    for seed in [
        0x9e37_79b9_7f4a_7c15u64,
        0x2545_f491_4f6c_dd1d,
        0xdead_beef_cafe_f00d,
    ] {
        journey(seed, 30);
    }
}
