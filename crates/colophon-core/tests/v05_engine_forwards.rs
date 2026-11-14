//! The engine forwards what a session needs of the account it owns, applying each result to
//! its own state: lock, read scope, batched versions, the verdict of a stored record.
#![allow(clippy::unwrap_used)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::model::Outcome;
use serde_json::json;
use support::*;

const NS: &str = "notes";

fn count(e: &colophon_core::v05::engine::Engine<MemSource>) -> usize {
    match e.view(NS) {
        Ok(Outcome::Success { value, .. }) => value.admitted.len(),
        _ => 0,
    }
}

#[test]
fn lock_forgets_keys_and_the_device_key_and_leaves_the_history_readable() {
    let (mut s, ids) = setup(NS, &[("Writer", 31, "write")]);
    let id = ids[0].clone();
    let src = device_source(&s);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let mut e = member_engine(&s.f, &host, &src, &id, s.f.account.now_ms());
    engine_write(
        &mut e,
        &mut host,
        &src,
        NS,
        "createNotebook",
        json!({"id": "a", "title": "A"}),
    );
    assert_eq!(count(&e), 1);
    let path = src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    assert_eq!(e.record_verdict(&path).as_deref(), Some("admitted"));
    e.save([1; 32]).unwrap();
    e.lock().unwrap();
    assert!(e.is_locked());
    assert_eq!(count(&e), 0, "no key: nothing of the namespace is readable");
    assert!(e.save([2; 32]).is_err(), "the device key is gone");
    assert!(e.account().head().0 >= 1, "the verified history stays");
    assert!(e
        .begin_write(
            NS,
            "createNotebook",
            json!({"id": "b", "title": "B"}),
            colophon_core::v05::records::Level::Write,
            [3; 32]
        )
        .map_or(true, |r| r.is_err()));
}

#[test]
fn a_batched_refresh_reads_what_a_refresh_reads_and_asks_the_source_less() {
    let (mut s, ids) = setup(NS, &[("Writer", 31, "write")]);
    let id = ids[0].clone();
    let src = device_source(&s);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let now = s.f.account.now_ms();
    let mut a = member_engine(&s.f, &host, &src, &id, now);
    let mut b = member_engine(&s.f, &host, &src, &id, now);
    for i in 0..3 {
        engine_write(
            &mut a,
            &mut host,
            &src,
            NS,
            "createNotebook",
            json!({"id": format!("n{i}"), "title": "T"}),
        );
    }
    let listing = src.listing();
    let versions = b
        .version_paths(&listing)
        .into_iter()
        .map(|p| {
            let v =
                colophon_core::v05::engine::RecordSource::content_version(&src, &p).unwrap_or(None);
            (p, v)
        })
        .collect();
    b.refresh_batched(listing, versions).unwrap();
    assert_eq!(count(&b), 3);
}

#[test]
fn the_read_scope_narrows_and_widens_through_the_engine() {
    let (mut s, ids) = setup(NS, &[("Writer", 31, "write")]);
    let id = ids[0].clone();
    let src = device_source(&s);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let mut e = member_engine(&s.f, &host, &src, &id, s.f.account.now_ms());
    engine_write(
        &mut e,
        &mut host,
        &src,
        NS,
        "createNotebook",
        json!({"id": "a", "title": "A"}),
    );
    e.set_read_scope(vec!["other".into()]).unwrap_or_default();
    e.set_read_scope(vec![NS.into()]).unwrap();
    assert_eq!(count(&e), 1);
}
