//! Builds the home slot the idle benchmark copies (`scripts/bench-home-idle.sh`): an ordinary
//! account's history as the REAL relay holds it after a few days of use, then left alone.
//!
//! The account is created with the relay as its home; three devices are approved; one writes
//! records, a required and an optional blob; another reads them; one device is revoked; a policy
//! change is proposed, waits out its delay, activates and becomes final; a second change is
//! proposed and vetoed. The relay's slot directory, its key and the clock are written to
//! `$COLOPHON_IDLE_FIXTURE` (`home/`, `meta.json`). Test keys only: they protect nothing.
//!
//! `COLOPHON_IDLE_FIXTURE=<dir> cargo test -p colophon-home-wasm --test v05_relay_idle_fixture
//! -- --ignored`. Without the variable the test builds the history and writes nothing.
#![allow(clippy::unwrap_used, dead_code)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use colophon_core::v05::account::{Change, RevokeKeep};
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::json;
use std::path::Path;
use support::*;
use support_relay::*;

const NOW: i64 = T0 + 3 * HOUR;
const SAVED: &str = "reading.saved";

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[test]
#[ignore = "builds the idle benchmark's slot; run with COLOPHON_IDLE_FIXTURE=<dir>"]
fn build_idle_fixture() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x77);
    let mut f = create_public(&[SAVED]);
    let home = appoint_home_keys(&mut f, &keys, BASE_A);
    let mut ids = Vec::new();
    for (label, seed) in [("Phone", 41u8), ("Tablet", 42), ("Old", 43)] {
        let id = f.host.identity(seed);
        let terms = terms_for(&[(SAVED, "write")]);
        admit(&mut f, &id, label, "device", terms.clone(), terms);
        ids.push(id);
    }
    let authority = MemSource::new();
    authority.store_account(&f.account);
    let scratch = Scratch::new("idle-fixture");
    let mut relay = Relay::start(&keys, f.account.id().as_str(), BASE_A, scratch.path(), f.account.now_ms(), &[]);
    first_upload(&relay, &f, f.account.now_ms() + 1_000);
    let source = || {
        let src = MemSource::new();
        for p in authority.listing() {
            src.put(&p, authority.get(&p).unwrap());
        }
        src
    };
    let mut wire = RealRelay::new(&relay);
    let (phone_src, tablet_src, old_src, ctl_src) = (source(), source(), source(), source());
    let mut phone = member_engine(&f, &f.host, &phone_src, &ids[0], NOW);
    let mut tablet = member_engine(&f, &f.host, &tablet_src, &ids[1], NOW);
    let mut old = member_engine(&f, &f.host, &old_src, &ids[2], NOW);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut at = NOW;
    let pass = |e: &mut colophon_core::v05::engine::Engine<MemSource>, src: &MemSource, wire: &mut RealRelay, host: &Host, at: i64| {
        relay.set_clock(at);
        let faults = relay_pass(e, src, &home, wire, host, at);
        assert!(faults.is_empty(), "{faults:?}");
    };

    // Records and blobs from the phone; a record from the device later revoked; the tablet reads.
    for n in 0..8 {
        engine_write(&mut phone, &mut host, &phone_src, SAVED, "capture",
            json!({"id": format!("item-{n}"), "title": format!("A long read {n}"), "url": format!("https://example.org/{n}")}));
    }
    engine_blob(&mut phone, &mut host, &phone_src, SAVED, "text/plain", &b"original ".repeat(12_000), "source", true);
    engine_blob(&mut phone, &mut host, &phone_src, SAVED, "image/png", &[0x89u8; 70_000], "image:item-0", false);
    pass(&mut phone, &phone_src, &mut wire, &host, at);
    at += 1_000;
    engine_write(&mut old, &mut host, &old_src, SAVED, "capture", json!({"id": "from-old", "title": "Written by a device later revoked"}));
    pass(&mut old, &old_src, &mut wire, &host, at);
    at += 1_000;
    pass(&mut tablet, &tablet_src, &mut wire, &host, at);

    // The account revokes the old device.
    at += 1_000;
    let mut ctl = controller_engine(&f, &host, &ctl_src, &f.d.clone(), at);
    pass(&mut ctl, &ctl_src, &mut wire, &host, at);
    let action = ctl.account().begin_revoke(&ids[2], &RevokeKeep::Everything, &[f.d.clone()], host.fresh()).unwrap();
    engine_finish(&mut ctl, &host, &ctl_src, action);
    at += 1_000;
    pass(&mut ctl, &ctl_src, &mut wire, &host, at);

    // A policy change signed by one unit: it waits out the recovery delay, activates and is final.
    let before = kinds(&relay).len();
    let action = ctl.account().begin_transition(&Change::policy(json!({"callWindow": 600})), &[f.d.clone()], TransitionRule::Control).unwrap();
    engine_finish(&mut ctl, &host, &ctl_src, action);
    at += 1_000;
    pass(&mut ctl, &ctl_src, &mut wire, &host, at);
    at += 3_600_000 + 400_000;
    relay.set_clock(at);
    ticks_until("the activate and its final", 6, &[&relay], || kinds(&relay).len() >= before + 2);
    assert_eq!(kinds(&relay)[before..before + 2], ["activate", "final"]);

    // A second change, vetoed from the other unit (the passkey).
    at += 1_000;
    pass(&mut ctl, &ctl_src, &mut wire, &host, at);
    let had: Vec<String> = ctl.account().pending().iter().map(|t| t.digest.clone()).collect();
    let action = ctl.account().begin_transition(&Change::policy(json!({"callWindow": 900})), &[f.d.clone()], TransitionRule::Control).unwrap();
    engine_finish(&mut ctl, &host, &ctl_src, action);
    let digest = ctl.account().pending().iter().map(|t| t.digest.clone()).find(|d| !had.contains(d)).unwrap();
    at += 1_000;
    pass(&mut ctl, &ctl_src, &mut wire, &host, at);
    let action = ctl.account().begin_veto(&digest, &[f.p.clone()]).unwrap();
    engine_finish(&mut ctl, &host, &ctl_src, action);
    at += 1_000;
    pass(&mut ctl, &ctl_src, &mut wire, &host, at);
    let vetoed = kinds(&relay).len();
    ticks_until("the vetoed", 6, &[&relay], || kinds(&relay).len() > vetoed);
    assert_eq!(kinds(&relay).last().unwrap(), "vetoed");
    // The devices catch up, and the home settles (its head over everything).
    for (e, src) in [(&mut phone, &phone_src), (&mut tablet, &tablet_src)] {
        at += 1_000;
        pass(e, src, &mut wire, &host, at);
    }
    at += 1_000;
    relay.set_clock(at);
    for _ in 0..3 {
        relay.tick();
    }
    assert_eq!(relay.get("/head").0, 200);
    let entries = kinds(&relay).len();
    drop(wire);
    relay.stop();
    let Some(out) = std::env::var_os("COLOPHON_IDLE_FIXTURE") else {
        eprintln!("built a history of {entries} entries; COLOPHON_IDLE_FIXTURE is not set, nothing written");
        return;
    };
    let out = Path::new(&out);
    let _ = std::fs::remove_dir_all(out.join("home"));
    copy_dir(&scratch.path().join("data/home"), &out.join("home"));
    let meta = json!({
        "account": f.account.id().as_str(),
        "base": BASE_A,
        "homeKey": serde_json::from_str::<serde_json::Value>(&keys.jwk()).unwrap(),
        "now": at,
        "entries": entries,
    });
    std::fs::write(out.join("meta.json"), serde_json::to_string_pretty(&meta).unwrap() + "\n").unwrap();
    eprintln!("wrote the idle fixture ({entries} entries) to {}", out.display());
}
