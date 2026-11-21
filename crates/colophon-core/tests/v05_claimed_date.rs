//! A claimed date on a write (`Engine::begin_write_claimed`): an app importing old data keeps
//! each item's original date in the operation's signed `created` (§11.2, §11.3). Only
//! `created` changes: the clock, the cited authority, the epoch, the author chain and the nonce
//! are the ones the same write without a claimed date would carry. A claimed date later than
//! the engine's clock is refused, and so is a write by a member whose grant has expired by the
//! real time, whatever date it claims.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use colophon_core::model::Outcome;
use colophon_core::v05::engine::Engine;
use colophon_core::v05::records::Level;
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const LISTEN: &str = "listening.podcasts";
/// 2019-03-04T05:06:07.890Z: years before the account existed.
const CLAIMED: i64 = 1_551_675_967_890;

fn q(e: &Engine<MemSource>, name: &str, args: Value) -> Value {
    match e.query(LISTEN, name, args).unwrap() {
        Outcome::Success { value, .. } => value["value"].clone(),
        Outcome::Failure { reason, detail, .. } => panic!("{reason}: {detail}"),
    }
}

/// The header body a prepared write asks the author to sign.
fn header(action: &colophon_core::v05::account::PendingAction) -> Value {
    serde_json::from_slice(action.steps()[0].body()).unwrap()
}

/// The stored header of the `ops/` record a write produced.
fn stored_header(stores: &[(String, Vec<u8>)]) -> Value {
    let (_, bytes) = stores.iter().find(|(p, _)| p.starts_with("ops/")).unwrap();
    let envelope: Value = serde_json::from_slice(bytes).unwrap();
    let body = STANDARD.decode(envelope["body"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn note() -> Value {
    json!({"id": "n1", "episode": "e1", "show": "show", "text": "An old thought"})
}

#[test]
fn a_claimed_date_is_the_operations_created_and_nothing_else_changes() {
    let (mut s, ids) = setup(LISTEN, &[("Phone", 41, "write"), ("Laptop", 42, "write")]);
    let (phone_id, laptop_id) = (ids[0].clone(), ids[1].clone());
    let src = device_source(&s);
    let mut phone = member_engine(&s.f, &s.f.host, &src, &phone_id, NOW);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    // An earlier write, so the next one has a clock above 1 and a `previous`.
    engine_write(
        &mut phone,
        &mut host,
        &src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/feed", "title": "The Show"}),
    );

    // The same write from the same state and seed, with and without a claimed date.
    let seed = host.fresh();
    let plain = phone
        .begin_write(LISTEN, "addNote", note(), Level::Write, seed)
        .unwrap()
        .unwrap();
    let claimed = phone
        .begin_write_claimed(LISTEN, "addNote", note(), Level::Write, Some(CLAIMED), seed)
        .unwrap()
        .unwrap();
    let (a, b) = (header(&plain), header(&claimed));
    assert_eq!(a["created"], json!(format_date(NOW)), "without: the clock");
    assert_eq!(
        b["created"],
        json!("2019-03-04T05:06:07.890Z"),
        "with: the claim"
    );
    for field in [
        "protocol",
        "account",
        "namespace",
        "author",
        "epoch",
        "clock",
        "authority",
        "level",
        "previous",
        "nonce",
    ] {
        assert_eq!(a[field], b[field], "{field} is unchanged");
    }
    assert!(b["previous"].is_string() && b["clock"].as_u64() > Some(1));

    // Finish the claimed write: it is admitted and stored with the claimed date.
    let sigs = host.sign(claimed.steps());
    let w = phone.finish_write(claimed, sigs).unwrap();
    src.publish_stores(&w.stores);
    assert_eq!(
        stored_header(&w.stores)["created"],
        json!("2019-03-04T05:06:07.890Z")
    );
    // A later write without a claim takes the next clock and the real time: the claim moved
    // nothing for what follows.
    let head = q(&phone, "note", json!({"id": "n1"}))["note"]["revision"].clone();
    let after = engine_write(
        &mut phone,
        &mut host,
        &src,
        LISTEN,
        "editNote",
        json!({"id": "n1", "text": "An old thought, edited", "expect": head}),
    );
    let h = stored_header(&after.stores);
    assert_eq!(h["created"], json!(format_date(NOW)));
    assert_eq!(h["clock"].as_u64(), b["clock"].as_u64().map(|c| c + 1));

    // A second device opens the same records and reads the note's claimed creation date, with
    // the later edit applied.
    let laptop = member_engine(&s.f, &host, &src, &laptop_id, NOW + 1_000);
    let row = q(&laptop, "note", json!({"id": "n1"}));
    assert_eq!(row["note"]["created"], json!("2019-03-04T05:06:07.890Z"));
    assert!(row.to_string().contains("An old thought, edited"), "{row}");
    let list = q(&laptop, "notes", json!({"episode": "e1"}));
    let first = &list["rows"][0];
    assert_eq!(first["id"], json!("n1"), "{list}");
    assert_eq!(first["created"], json!("2019-03-04T05:06:07.890Z"));
}

#[test]
fn a_claimed_date_later_than_now_is_refused_and_now_itself_is_not() {
    let (mut s, ids) = setup(LISTEN, &[("Phone", 43, "write")]);
    let src = device_source(&s);
    let phone = member_engine(&s.f, &s.f.host, &src, &ids[0], NOW);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let seed = host.fresh();
    assert!(phone
        .begin_write_claimed(LISTEN, "addNote", note(), Level::Write, Some(NOW + 1), seed)
        .is_err());
    assert!(phone
        .begin_write_claimed(
            LISTEN,
            "addNote",
            note(),
            Level::Write,
            Some(NOW + HOUR),
            seed
        )
        .is_err());
    // Before year 1: not a §2.2 date.
    assert!(phone
        .begin_write_claimed(
            LISTEN,
            "addNote",
            note(),
            Level::Write,
            Some(-62_135_596_800_001),
            seed
        )
        .is_err());
    // Extremes never reach the date arithmetic.
    for ms in [i64::MIN, i64::MIN + 1, -62_135_596_800_001] {
        assert!(phone
            .begin_write_claimed(LISTEN, "addNote", note(), Level::Write, Some(ms), seed)
            .is_err());
    }
    let year_one = phone
        .begin_write_claimed(
            LISTEN,
            "addNote",
            note(),
            Level::Write,
            Some(-62_135_596_800_000),
            seed,
        )
        .unwrap()
        .unwrap();
    assert_eq!(header(&year_one)["created"], json!("0001-01-01T00:00:00Z"));
    let at_now = phone
        .begin_write_claimed(LISTEN, "addNote", note(), Level::Write, Some(NOW), seed)
        .unwrap()
        .unwrap();
    assert_eq!(header(&at_now)["created"], json!(format_date(NOW)));
}

#[test]
fn an_expired_member_cannot_write_by_claiming_an_earlier_date() {
    let mut f = create(&[LISTEN]);
    let id = f.host.identity(44);
    let mut granted = terms_for(&[(LISTEN, "write")]);
    let expires = f.account.now_ms() + 4 * HOUR;
    granted["expires"] = json!(format_date(expires));
    admit(
        &mut f,
        &id,
        "Phone",
        "device",
        terms_for(&[(LISTEN, "write")]),
        granted,
    );
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    // Before the expiry, a claimed date writes.
    let early = member_engine(&f, &host, &src, &id, expires - HOUR);
    let seed = host.fresh();
    early
        .begin_write_claimed(LISTEN, "addNote", note(), Level::Write, Some(CLAIMED), seed)
        .unwrap()
        .unwrap();
    // After it, the plain write is refused and so is the same write claiming a date before it.
    let late = member_engine(&f, &host, &src, &id, expires + HOUR);
    let seed = host.fresh();
    let plain = late.begin_write(LISTEN, "addNote", note(), Level::Write, seed);
    assert!(!matches!(plain, Ok(Ok(_))), "the plain write is refused");
    let claimed =
        late.begin_write_claimed(LISTEN, "addNote", note(), Level::Write, Some(CLAIMED), seed);
    assert!(
        !matches!(claimed, Ok(Ok(_))),
        "a claim before the expiry does not reopen it"
    );
}
