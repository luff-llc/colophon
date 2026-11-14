//! The 0.5 account engine (`v05::engine`): open cold and resumed, refresh and `apply_paths`,
//! incremental judgement, checkpoints and the attacks each property needs.
#![allow(clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::model::Outcome;
use colophon_core::v05::account::{Account, Finished, Identity};
use colophon_core::v05::engine::{Engine, EngineOptions, OpenMode, Saved};
use colophon_core::v05::history::Objects;
use colophon_core::v05::records::{
    judge_records, HeldRecord, Level, Outcome as Admission, RecordAuthority,
};
use serde_json::{json, Value};
use support::*;

const DEVICE_KEY: [u8; 32] = [0x77; 32];

/// An account with one app member that has written `n` notes.
struct World {
    f: Fixture,
    src: MemSource,
    member: String,
    /// The member's own session, which wrote the notes.
    writer: Account,
    written: Vec<Finished>,
}

fn write_one(w: &mut World, id: &str, title: &str) {
    let mut host = std::mem::replace(&mut w.f.host, Host::new());
    let done = write_note(&mut w.writer, &mut host, id, title);
    w.f.host = host;
    w.src.publish(&done);
    w.written.push(done);
}
fn write_note(m: &mut Account, host: &mut Host, id: &str, title: &str) -> Finished {
    let seed = host.fresh();
    let action = m
        .begin_write(
            "notes",
            "createNotebook",
            json!({"id": id, "title": title}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    run(m, host, action)
}

fn world(n: usize) -> World {
    world_v(n, 0)
}
/// `v` makes every key different: another account.
fn world_v(n: usize, v: u8) -> World {
    let mut f = create_v(&["notes"], v);
    let member = f.host.identity(31);
    admit(
        &mut f,
        &member,
        "Phone",
        "device",
        terms("write"),
        terms("write"),
    );
    let src = MemSource::new();
    src.store_account(&f.account);
    let writer = member_session(&f, &member);
    let mut w = World {
        f,
        src,
        member,
        writer,
        written: Vec::new(),
    };
    for i in 0..n {
        write_one(&mut w, &format!("nb{i:03}"), &format!("Notebook {i}"));
    }
    w
}

fn open(
    w: &World,
    src: &MemSource,
    listing: Vec<String>,
    saved: Option<&Saved>,
) -> Engine<MemSource> {
    open_as(w, src, listing, saved, &w.member)
}
fn open_as(
    w: &World,
    src: &MemSource,
    listing: Vec<String>,
    saved: Option<&Saved>,
    member: &str,
) -> Engine<MemSource> {
    let mut e = Engine::open(
        src.clone(),
        listing,
        Identity::Member(member.to_string()),
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY),
        saved,
        w.f.account.now_ms(),
    )
    .unwrap();
    unlock(w, &mut e, member);
    e
}
fn unlock(w: &World, e: &mut Engine<MemSource>, member: &str) {
    let steps = e.begin_unlock_epochs();
    assert!(!steps.is_empty());
    let results = w.f.host.answer_epochs(member, steps);
    e.finish_unlock_epochs(results).unwrap();
}

fn view(e: &Engine<MemSource>) -> Value {
    match e.view("notes").unwrap() {
        Outcome::Success { value, .. } => serde_json::to_value(value).unwrap(),
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}
fn ids(v: &Value) -> Vec<String> {
    v["admitted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_cold_open_reads_authority_first_and_no_record_until_unlocked() {
    let w = world(5);
    let mut e = Engine::open(
        w.src.clone(),
        w.src.listing(),
        Identity::Member(w.member.clone()),
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY),
        None,
        w.f.account.now_ms(),
    )
    .unwrap();
    assert_eq!(*e.open_mode(), OpenMode::Cold);
    assert_eq!(
        e.stats().unread_paths,
        5,
        "the five records wait for the unlock"
    );
    assert_eq!(e.stats().signatures_verified, 0);
    // Nothing is readable before the records are loaded: no empty success.
    assert!(e.view("notes").is_err());
    assert_eq!(e.access("notes").unwrap().unwrap().reason, "notReadable");
    unlock(&w, &mut e, &w.member);
    assert_eq!(ids(&view(&e)).len(), 5);
    assert_eq!(e.stats().unread_paths, 0);
    assert_eq!(
        e.stats().signatures_verified,
        5,
        "each record's signature once"
    );
    assert_eq!(e.stats().payloads_decrypted, 5);
    assert!(e.access("notes").unwrap().is_none());
    assert_eq!(e.status().code, "ok");
}

#[test]
fn a_source_of_another_account_is_refused() {
    let w = world(1);
    let other = create_v(&["notes"], 1);
    let src = MemSource::new();
    src.store_account(&other.account);
    let r = Engine::open(
        src.clone(),
        src.listing(),
        Identity::Member(w.member.clone()),
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY),
        None,
        w.f.account.now_ms(),
    );
    assert!(r.is_err(), "the genesis is not the expected account's");
    // Not even its records are read.
    assert_eq!(
        src.reads() as usize,
        src.listing()
            .iter()
            .filter(|p| p.starts_with("authority/") || p.starts_with("transitions/"))
            .count()
    );
}

#[test]
fn refresh_judges_and_folds_only_what_is_new() {
    let mut w = world(40);
    let listing40 = w.src.listing();
    let mut e = open(&w, &w.src, listing40, None);
    assert_eq!(e.stats().signatures_verified, 40);
    for i in 40..50 {
        write_one(&mut w, &format!("nb{i:03}"), &format!("Notebook {i}"));
    }
    let before = e.stats();
    let changes = e.refresh(w.src.listing()).unwrap();
    assert!(changes.namespaces.contains_key("notes"));
    let after = e.stats();
    assert_eq!(
        after.signatures_verified - before.signatures_verified,
        10,
        "{after:?}"
    );
    assert_eq!(after.payloads_decrypted - before.payloads_decrypted, 10);
    assert_eq!(after.walked_last, 10, "the walk resumed after the 40 held");
    assert_eq!(
        after.folds_applied_last, 10,
        "the fold was extended, not redone"
    );
    // The result is a full open's.
    let fresh = open(&w, &w.src, w.src.listing(), None);
    assert_eq!(view(&e), view(&fresh));
    assert_eq!(e.revision("notes"), fresh.revision("notes"));
    // Nothing new: nothing read, nothing judged.
    let reads = w.src.reads();
    let c = e.refresh(w.src.listing()).unwrap();
    assert!(c.is_empty(), "{c:?}");
    assert_eq!(w.src.reads(), reads);
}

#[test]
fn records_that_sort_earlier_arrive_late_and_the_state_is_the_same() {
    let w = world(30);
    let all = w.src.listing();
    // The records of clocks 11..30 first, then 1..10.
    let ops: Vec<String> = all
        .iter()
        .filter(|p| p.starts_with("ops/"))
        .cloned()
        .collect();
    let (early, late): (Vec<_>, Vec<_>) = ops.iter().cloned().partition(|p| {
        let clock: u64 = p.rsplit('/').next().unwrap()[..12].parse().unwrap();
        clock <= 10
    });
    let auth: Vec<String> = all
        .iter()
        .filter(|p| !p.starts_with("ops/"))
        .cloned()
        .collect();
    let src = MemSource::new();
    for p in auth.iter().chain(&late) {
        src.put(p, w.src.get(p).unwrap());
    }
    let mut e = open(&w, &src, src.listing(), None);
    assert_eq!(ids(&view(&e)).len(), 20);
    for p in &early {
        src.put(p, w.src.get(p).unwrap());
    }
    let before = e.stats();
    e.refresh(src.listing()).unwrap();
    let after = e.stats();
    assert_eq!(
        after.signatures_verified - before.signatures_verified,
        10,
        "only the new signatures"
    );
    let fresh = open(&w, &w.src, w.src.listing(), None);
    assert_eq!(view(&e), view(&fresh));
    assert_eq!(e.revision("notes"), fresh.revision("notes"));
}

#[test]
fn a_resumed_open_and_a_cold_open_give_one_state_and_the_resume_verifies_nothing_old() {
    let mut w = world(30);
    let mut e = open(&w, &w.src, w.src.listing(), None);
    let saved = e.save([9; 32]).unwrap();
    for i in 30..35 {
        write_one(&mut w, &format!("nb{i:03}"), &format!("Notebook {i}"));
    }
    let resumed = open(&w, &w.src, w.src.listing(), Some(&saved));
    assert_eq!(*resumed.open_mode(), OpenMode::Resumed);
    let cold = open(&w, &w.src, w.src.listing(), None);
    assert_eq!(*cold.open_mode(), OpenMode::Cold);
    assert_eq!(view(&resumed), view(&cold));
    assert_eq!(resumed.revision("notes"), cold.revision("notes"));
    assert_eq!(resumed.status(), cold.status());
    assert_eq!(cold.stats().signatures_verified, 35);
    assert_eq!(
        resumed.stats().signatures_verified,
        5,
        "only the five new signatures: the 30 covered ones come from the sealed memo"
    );
    assert_eq!(resumed.stats().payloads_decrypted, 5);
}

#[test]
fn a_checkpoint_that_does_not_verify_is_ignored_and_the_open_is_cold() {
    let w = world(12);
    let mut e = open(&w, &w.src, w.src.listing(), None);
    let saved = e.save([3; 32]).unwrap();
    let cold = open(&w, &w.src, w.src.listing(), None);
    let want = view(&cold);
    // A flipped byte, a truncation, garbage, another key.
    let mut flipped = saved.clone();
    let n = flipped.checkpoint.len() - 5;
    flipped.checkpoint[n] ^= 1;
    let truncated = Saved {
        checkpoint: saved.checkpoint[..saved.checkpoint.len() / 2].to_vec(),
        ..saved.clone()
    };
    let garbage = Saved {
        checkpoint: vec![0xff; 200],
        ..saved.clone()
    };
    for bad in [&flipped, &truncated, &garbage] {
        let e = open(&w, &w.src, w.src.listing(), Some(bad));
        assert!(
            matches!(e.open_mode(), OpenMode::Invalidated(_)),
            "{:?}",
            e.open_mode()
        );
        assert_eq!(view(&e), want);
        assert_eq!(
            e.stats().signatures_verified,
            12,
            "everything verified again"
        );
    }
    // Sealed under another device key.
    let mut other_key = Engine::open(
        w.src.clone(),
        w.src.listing(),
        Identity::Member(w.member.clone()),
        EngineOptions::new(w.f.account.id().as_str(), [1; 32]),
        None,
        w.f.account.now_ms(),
    )
    .unwrap();
    unlock(&w, &mut other_key, &w.member);
    let theirs = other_key.save([4; 32]).unwrap();
    let e2 = open(&w, &w.src, w.src.listing(), Some(&theirs));
    assert!(matches!(e2.open_mode(), OpenMode::Invalidated(_)));
    assert_eq!(e2.stats().signatures_verified, 12);
}

#[test]
fn a_checkpoint_of_another_account_or_identity_is_ignored() {
    let w = world(6);
    let mut e = open(&w, &w.src, w.src.listing(), None);
    let saved = e.save([5; 32]).unwrap();
    // Another identity of the same account, holding the same device key.
    let mut w2 = world(6);
    let other_member = w2.f.host.identity(44);
    admit(
        &mut w2.f,
        &other_member,
        "Tablet",
        "device",
        terms("write"),
        terms("write"),
    );
    w2.src.store_account(&w2.f.account);
    // Same account bytes cannot be reused across worlds, so test identity on this world.
    let mut w = w;
    let m2 = w.f.host.identity(45);
    admit(
        &mut w.f,
        &m2,
        "Tablet",
        "device",
        terms("write"),
        terms("write"),
    );
    w.src.store_account(&w.f.account);
    let e2 = open_as(&w, &w.src, w.src.listing(), Some(&saved), &m2);
    assert!(
        matches!(e2.open_mode(), OpenMode::Invalidated(_)),
        "{:?}",
        e2.open_mode()
    );
    // A checkpoint of another account.
    let mut o = world_v(2, 1);
    let mut eo = open(&o, &o.src, o.src.listing(), None);
    let theirs = eo.save([6; 32]).unwrap();
    o.f.host.counter = 0;
    let e3 = open(&w, &w.src, w.src.listing(), Some(&theirs));
    assert!(matches!(e3.open_mode(), OpenMode::Invalidated(_)));
    let _ = e;
}

#[test]
fn a_changed_provider_version_makes_that_record_be_verified_again() {
    let mut w = world(0);
    w.src.store_account(&w.f.account);
    let src = MemSource::versioned();
    for p in w.src.listing() {
        src.put(&p, w.src.get(&p).unwrap());
    }
    w.src = src.clone();
    for i in 0..8 {
        write_one(&mut w, &format!("nb{i}"), &format!("N{i}"));
    }
    let mut e = open(&w, &src, src.listing(), None);
    let saved = e.save([8; 32]).unwrap();
    // The provider reports a new version of one record (the bytes are the same).
    let victim = src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    src.put(&victim, src.get(&victim).unwrap());
    let e2 = open(&w, &src, src.listing(), Some(&saved));
    assert_eq!(*e2.open_mode(), OpenMode::Resumed);
    assert_eq!(
        e2.stats().signatures_verified,
        1,
        "the token changed: checked again, even though the bytes are the same"
    );
    assert_eq!(e2.stats().payloads_decrypted, 1);
}

#[test]
fn different_bytes_at_an_immutable_path_fail_closed() {
    let w = world(4);
    let mut e = open(&w, &w.src, w.src.listing(), None);
    let victim = w
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    let mut bytes = w.src.get(&victim).unwrap();
    bytes.push(b' ');
    let src2 = w.src.clone();
    src2.put(&victim, bytes);
    let err = e.apply_paths(vec![victim.clone()]).unwrap_err();
    assert_eq!(err.code(), "refused:fork");
    // Sticky: the engine answers nothing more until the host opens a fresh one.
    assert!(e.view("notes").is_err());
    assert!(e.refresh(src2.listing()).is_err());
}

#[test]
fn the_integrity_audit_reports_a_changed_or_missing_path() {
    let w = world(6);
    let mut e = open(&w, &w.src, w.src.listing(), None);
    let held = e.stats().held_paths;
    let mut seen = 0;
    loop {
        let p = e.verify_batch(4).unwrap();
        seen += p.checked;
        if p.remaining == 0 {
            break;
        }
    }
    assert_eq!(seen, held, "every held path checked once per pass");
    let victim = w
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    w.src.remove(&victim);
    let mut failed = None;
    for _ in 0..10 {
        if let Err(f) = e.verify_batch(100) {
            failed = Some(f);
            break;
        }
    }
    assert!(
        failed.is_some(),
        "a vanished covered path is an integrity error"
    );
    assert!(e.view("notes").is_err(), "sticky");
}

#[test]
fn a_covered_path_the_listing_no_longer_names_is_unavailable_not_gone() {
    let w = world(5);
    let mut e = open(&w, &w.src, w.src.listing(), None);
    let victim = w
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    let listing: Vec<String> = w
        .src
        .listing()
        .into_iter()
        .filter(|p| *p != victim)
        .collect();
    e.refresh(listing).unwrap();
    assert_eq!(e.missing_covered(), vec![victim.clone()]);
    // What was verified is still shown: absence is not deletion (0.3 §8.4).
    assert_eq!(ids(&view(&e)).len(), 5);
}

#[test]
fn history_pages_and_operation_at() {
    let w = world(7);
    let e = open(&w, &w.src, w.src.listing(), None);
    let mut seen = Vec::new();
    let mut off = 0;
    loop {
        match e.history("notes", off, 3).unwrap() {
            Outcome::Success { value, .. } => {
                seen.extend(value.items.iter().map(|o| o.id.clone()));
                match value.next_offset {
                    Some(n) => off = n,
                    None => break,
                }
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(seen.len(), 7);
    assert!(e.history("notes", 0, 0).is_err());
    assert!(e.history("notes", 0, 201).is_err());
    let path = w.written[3].records[0].path.clone();
    match e.operation_at("notes", &path).unwrap() {
        Outcome::Success { value, .. } => assert_eq!(value.payload["title"], "Notebook 3"),
        other => panic!("{other:?}"),
    }
    assert!(e.operation_at("other", &path).is_err());
}

// ---------------------------------------------------------------------------------------------
// Properties.

/// An independent reading of the same records: the full judgement `judge_records`, over the
/// set, with keys opened by the member's own ECDH.
fn reference(w: &World, records: &[HeldRecord]) -> Vec<(String, String)> {
    let auth = RecordAuthority::from_objects(w.f.account.objects(), w.f.account.now_ms()).unwrap();
    let mut keys = colophon_core::v05::records::EpochKeys::new();
    let probe = Account::open(
        w.f.account.objects().clone(),
        Vec::new(),
        None,
        Identity::Member(w.member.clone()),
        w.f.account.now_ms(),
    )
    .unwrap();
    for step in probe.begin_unlock_epochs() {
        let shared = w.f.host.ids[&w.member].agree(&step.peer).unwrap();
        keys.insert(
            auth.open_epoch(&step.namespace, step.epoch, &step.recipient, &shared)
                .unwrap(),
        )
        .unwrap();
    }
    let j = judge_records(&auth, &keys, records);
    let mut out: Vec<(String, String)> = j
        .records
        .iter()
        .map(|r| (r.path.clone(), r.outcome.code()))
        .collect();
    out.sort();
    out
}

#[test]
fn incremental_equals_full_across_shuffled_arrival_orders() {
    let w = world(36);
    let records: Vec<HeldRecord> = w
        .src
        .listing()
        .into_iter()
        .filter(|p| p.starts_with("ops/"))
        .map(|p| HeldRecord {
            bytes: w.src.get(&p).unwrap(),
            path: p,
        })
        .collect();
    let want = reference(&w, &records);
    assert!(want.iter().all(|(_, c)| c == "admitted"));
    let base = open(&w, &w.src, w.src.listing(), None);
    let want_view = view(&base);
    for seed in 1..=12u64 {
        // The authority first, then the records in a shuffled order and in uneven batches.
        let src = MemSource::new();
        for p in w.src.listing().iter().filter(|p| !p.starts_with("ops/")) {
            src.put(p, w.src.get(p).unwrap());
        }
        let mut e = open(&w, &src, src.listing(), None);
        let order = shuffled(&records, seed * 7919);
        let mut i = 0;
        let mut step = 1 + (seed as usize % 7);
        while i < order.len() {
            let end = (i + step).min(order.len());
            for r in &order[i..end] {
                src.put(&r.path, r.bytes.clone());
            }
            e.refresh(src.listing()).unwrap();
            // After every batch the state is the reference's over what is held so far.
            let held: Vec<HeldRecord> = order[..end].to_vec();
            let got: Vec<(String, String)> = {
                let v = view(&e);
                let mut g: Vec<(String, String)> = Vec::new();
                for o in v["admitted"].as_array().unwrap() {
                    g.push((o["id"].as_str().unwrap().to_string(), "admitted".into()));
                }
                g.sort();
                g
            };
            let mut ref_ids: Vec<(String, String)> = reference(&w, &held)
                .into_iter()
                .filter(|(_, c)| c == "admitted")
                .map(|(p, c)| {
                    (
                        p.rsplit('-')
                            .next()
                            .unwrap()
                            .trim_end_matches(".json")
                            .to_string(),
                        c,
                    )
                })
                .collect();
            ref_ids.sort();
            assert_eq!(got, ref_ids, "seed {seed} after {end}");
            i = end;
            step += 3;
        }
        assert_eq!(view(&e), want_view, "seed {seed}");
        assert_eq!(e.revision("notes"), base.revision("notes"), "seed {seed}");
        // The signatures were verified once each, whatever the order.
        assert_eq!(e.stats().signatures_verified, 36, "seed {seed}");
    }
}

#[test]
fn garbage_planted_before_the_real_record_changes_nothing_and_is_replaced() {
    let w = world(6);
    let base = open(&w, &w.src, w.src.listing(), None);
    let want = view(&base);
    let victim = w
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    let real = w.src.get(&victim).unwrap();
    // The same body under a signature from nobody.
    let mut v: Value = serde_json::from_slice(&real).unwrap();
    v["signature"] = json!(b64(&[7u8; 64]));
    let twin = serde_json::to_vec(&v).unwrap();
    let src = MemSource::new();
    for p in w.src.listing() {
        src.put(&p, w.src.get(&p).unwrap());
    }
    src.put(&victim, twin);
    let mut e = open(&w, &src, src.listing(), None);
    // Five records fold; the sixth is no record at all, and nothing else is disturbed.
    assert_eq!(ids(&view(&e)).len(), 5);
    assert_eq!(e.account().record_verdict(&victim).unwrap(), "badSignature");
    // The real one arrives at the path: bytes that verified nothing are replaced, the engine
    // does not fail closed over them, and the state is the full one.
    src.put(&victim, real);
    e.apply_paths(vec![victim.clone()]).unwrap();
    assert_eq!(view(&e), want);
    assert_eq!(e.account().record_verdict(&victim).unwrap(), "admitted");
    assert!(e.view("notes").is_ok(), "not poisoned");
}

#[test]
fn a_resume_from_any_point_of_a_shuffled_arrival_equals_a_cold_open() {
    let w = world(24);
    let records: Vec<(String, Vec<u8>)> = w
        .src
        .listing()
        .into_iter()
        .filter(|p| p.starts_with("ops/"))
        .map(|p| (w.src.get(&p).unwrap(), p))
        .map(|(b, p)| (p, b))
        .collect();
    let cold = open(&w, &w.src, w.src.listing(), None);
    let want = view(&cold);
    for seed in [3u64, 11, 29] {
        let src = MemSource::new();
        for p in w.src.listing().iter().filter(|p| !p.starts_with("ops/")) {
            src.put(p, w.src.get(p).unwrap());
        }
        let mut e = open(&w, &src, src.listing(), None);
        let order = shuffled(&records, seed);
        let mut i = 0;
        while i < order.len() {
            let end = (i + 5).min(order.len());
            for (p, b) in &order[i..end] {
                src.put(p, b.clone());
            }
            e.refresh(src.listing()).unwrap();
            // Restart from the sealed state, as a device would, and compare with a cold open
            // of exactly what the source holds now.
            let saved = e.save([seed as u8; 32]).unwrap();
            let resumed = open(&w, &src, src.listing(), Some(&saved));
            let cold_now = open(&w, &src, src.listing(), None);
            assert_eq!(*resumed.open_mode(), OpenMode::Resumed);
            assert_eq!(view(&resumed), view(&cold_now), "seed {seed} at {end}");
            assert_eq!(resumed.revision("notes"), cold_now.revision("notes"));
            assert_eq!(resumed.status(), cold_now.status());
            assert_eq!(
                resumed.stats().signatures_verified, 0,
                "everything the checkpoint covers is read, nothing re-verified (seed {seed} at {end})"
            );
            e = resumed;
            i = end;
        }
        assert_eq!(view(&e), want, "seed {seed}");
    }
}

#[test]
fn the_engine_exposes_no_secret() {
    let w = world(2);
    let e = open(&w, &w.src, w.src.listing(), None);
    let d = format!("{e:?}");
    assert!(!d.contains("[119"), "{d}");
    let o = format!(
        "{:?}",
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY)
    );
    assert!(
        !o.contains("119") && !o.contains("0x77") && !o.contains("[119"),
        "{o}"
    );
    let mut e = e;
    let saved = e.save([1; 32]).unwrap();
    // The checkpoint is sealed: no plaintext title is readable in it.
    let text = String::from_utf8_lossy(&saved.checkpoint);
    assert!(
        !text.contains("Notebook"),
        "the sealed checkpoint holds no plaintext"
    );
    assert!(!String::from_utf8_lossy(&saved.verifier).contains("Notebook"));
}

#[test]
fn the_bounds_hold_for_a_hostile_listing_and_hostile_bytes() {
    let w = world(2);
    // Garbage paths are ignored, never read.
    let mut listing = w.src.listing();
    for i in 0..50 {
        listing.push(format!("junk/{i}"));
        listing.push(format!("ops/../{i}"));
    }
    let e = open(&w, &w.src, listing, None);
    assert_eq!(e.stats().ignored_paths, 100);
    // An oversized listing is refused before anything is read.
    let huge: Vec<String> = (0..600_000).map(|i| format!("ops/{i}")).collect();
    let r = Engine::open(
        w.src.clone(),
        huge,
        Identity::Member(w.member.clone()),
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY),
        None,
        w.f.account.now_ms(),
    );
    assert!(r.is_err());
    // Garbage where a record should be: held as nothing, the others unaffected.
    let src = MemSource::new();
    for p in w.src.listing() {
        src.put(&p, w.src.get(&p).unwrap());
    }
    let victim = src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    src.put(&victim, vec![0xff; 64]);
    let e = open(&w, &src, src.listing(), None);
    assert_eq!(ids(&view(&e)).len(), 1);
    let _ = Objects::default();
    let _ = Admission::Admitted;
}

#[test]
fn the_path_grammar_accepts_the_store_and_nothing_else() {
    use colophon_core::v05::engine::paths::{classify, Kind};
    let a = "ab".repeat(16);
    let d = "cd".repeat(32);
    let ok = [
        "authority/00000001.json".to_string(),
        "predecessor/authority/00000007.json".to_string(),
        format!("transitions/{d}.json"),
        format!("vetoes/{d}.json"),
        format!("heads/{a}.json"),
        format!("receipts/{d}/{a}.receipt.json"),
        format!("ops/{a}/notes/000000000007-{a}.json"),
        format!("state/{a}/listening.podcasts/{d}.json"),
        format!("history/{a}/notes/000000000007-{a}.json"),
        format!("blobs/{d}"),
    ];
    for p in &ok {
        assert!(classify(p).is_some(), "{p}");
    }
    assert!(matches!(classify(&ok[0]), Some(Kind::Authority(1))));
    let bad = [
        "authority/1.json".to_string(),
        "authority/00000000.json".to_string(),
        "authority/../00000001.json".to_string(),
        "/authority/00000001.json".to_string(),
        format!("ops/{a}/notes/7-{a}.json"),
        format!("ops/{a}/Notes/000000000007-{a}.json"),
        format!("ops/{a}/notes/000000000007-{a}.json/"),
        format!("ops/{a}/notes/.hidden/000000000007-{a}.json"),
        format!("blobs/{}", "CD".repeat(32)),
        format!("blobs/{d}x"),
        "ops\\x".to_string(),
        "x".repeat(600),
        String::new(),
        "state/a/b/c.json".to_string(),
    ];
    for p in &bad {
        assert!(classify(p).is_none(), "{p}");
    }
}

#[test]
fn one_write_does_a_constant_number_of_signature_checks_whatever_is_held() {
    for n in [10usize, 60] {
        let mut w = world(n);
        let mut e = open(&w, &w.src, w.src.listing(), None);
        let before = e.stats();
        let mut host = std::mem::replace(&mut w.f.host, Host::new());
        host.counter = 5_000;
        let src = w.src.clone();
        engine_write(&mut e, &mut host, &src, "notes", "createNotebook", json!({"id": "extra", "title": "Extra"}));
        let after = e.stats();
        assert!(
            after.signatures_verified - before.signatures_verified <= 2,
            "held {n}: {} signature checks for one write",
            after.signatures_verified - before.signatures_verified
        );
        assert!(after.payloads_decrypted - before.payloads_decrypted <= 2);
        // And what it wrote is what a cold judgement of everything says.
        w.f.host = host;
        let cold = open(&w, &src, src.listing(), None);
        assert_eq!(view(&e), view(&cold));
        assert_eq!(cold.stats().signatures_verified as usize, n + 1);
    }
}

#[test]
fn a_write_over_budget_or_clock_is_refused_at_prepare_as_the_full_judgement_refuses_it() {
    let mut f = create(&["notes"]);
    let id = f.host.identity(31);
    let capped = json!({"records": [{"namespace": "notes", "access": "write"}], "writes": 2});
    admit(&mut f, &id, "Capped", "device", terms("write"), capped);
    let src = MemSource::new();
    src.store_account(&f.account);
    let host_keys = std::mem::replace(&mut f.host, Host::new());
    let mut host = host_keys;
    let mut e = member_engine(&f, &host, &src, &id, f.account.now_ms());
    for i in 0..2 {
        engine_write(&mut e, &mut host, &src, "notes", "createNotebook", json!({"id": format!("n{i}"), "title": "T"}));
    }
    let seed = host.fresh();
    let third = e.begin_write("notes", "createNotebook", json!({"id": "n2", "title": "T"}), Level::Write, seed);
    let reason = match third {
        Err(f) => f.code(),
        Ok(Err(d)) => d.reason,
        Ok(Ok(_)) => panic!("a third write under a budget of two was prepared"),
    };
    assert!(reason.contains("budgetSpent"), "{reason}");
    // The cold open of the same records admits exactly the two.
    let cold = member_engine(&f, &host, &src, &id, f.account.now_ms());
    match cold.view("notes").unwrap() {
        Outcome::Success { value, .. } => assert_eq!(value.admitted.len(), 2),
        o => panic!("{o:?}"),
    }
}
