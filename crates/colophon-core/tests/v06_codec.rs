//! The 0.6 session codec (§S2, §S3): delegations, sealing, the receiver checks, replay
//! windows and the plaintext encoding. Every rejected frame must fail closed and leave the
//! receiver exactly as it was.
#![allow(clippy::unwrap_used)]
mod v06_codec_support;

use colophon_core::v06::bridge;
use colophon_core::v06::session::codec::{
    frame_key, nonce, Attach, CellId, EpochTable, Receiver, ReplayWindow, SealError, Sender,
    CACHED_PER_MEMBER,
};
use colophon_core::v06::session::keys::{
    Delegation, KeyError, SessionAccount, SessionKey, MAX_WINDOW_MS,
};
use colophon_core::v06::session::wire::{decode_body, encode_body, DropReason, MAX_FRAME_BYTES};
use colophon_core::v06::session::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use v06_codec_support::*;

const MAXP: u64 = 8_192;

fn every_kind(w: &World) -> Vec<Body> {
    let c = claim(3, &w.a);
    let passed = Claim::passed(4, &w.b.id, &w.a.id);
    vec![
        Body::Hello {
            fresh: id("f1"),
            echo: vec![id("e1"), id("e2")],
            seen: Some(Seen {
                claim: passed.clone(),
                seq: None,
            }),
            heard: None,
            lapsed: false,
        },
        Body::Hello {
            fresh: id("f2"),
            echo: vec![],
            seen: None,
            heard: None,
            lapsed: true,
        },
        Body::State {
            claim: c.clone(),
            seq: 7,
            snapshot: bytes("{\"episode\":\"e\"}"),
        },
        Body::Beat {
            claim: c.clone(),
            seq: 7,
        },
        Body::Msg {
            claim: c.clone(),
            seq: 8,
            origin: w.b.id.clone(),
            id: id("m"),
            payload: bytes("p"),
        },
        Body::Submit {
            id: id("s"),
            payload: Bytes(vec![0, 1, 2, 255]),
        },
        Body::Refuse {
            id: id("s"),
            reason: "busy".into(),
        },
        Body::Presence {
            payload: bytes("{\"label\":\"Kitchen iPad\",\"playing\":false}"),
        },
        Body::Ask { claim: c.clone() },
        Body::Pass {
            claim: c.clone(),
            next: passed.clone(),
            seq: 9,
            snapshot: bytes("final"),
        },
        Body::Decline { claim: c.clone() },
        Body::Take {
            claim: claim(5, &w.a),
        },
        Body::Ping { t: 12_345 },
        Body::Pong {
            t: 99,
            echo: 12_345,
            hold: 3,
        },
        Body::Yielded {
            claim: passed.clone(),
            seq: 2,
            snapshot: Bytes::default(),
        },
        Body::Ack { yielded: None, passed: Some(passed) },
        Body::Bye {
            claim: Some(c),
            leaving: false,
        },
        Body::Bye {
            claim: None,
            leaving: true,
        },
    ]
}

fn frame(from: &Member, body: Body) -> Frame {
    Frame {
        from: from.id.clone(),
        to: None,
        retain: false,
        body,
    }
}

#[test]
fn every_kind_round_trips_through_seal_and_open() {
    let w = world();
    let view = w.view();
    let mut tx = sender(&w.a, &view, 11, cell());
    let mut rx = Receiver::new(cell(), &w.b.id);
    let ep = epochs();
    let bodies = every_kind(&w);
    let kinds: BTreeSet<&str> = bodies.iter().map(Body::kind).collect();
    assert_eq!(kinds.len(), 16, "every kind is covered");
    for (i, body) in bodies.into_iter().enumerate() {
        // Plaintext alone.
        let p = encode_body(&body).unwrap();
        assert_eq!(decode_body(&p, MAXP).unwrap(), body);
        // Sealed, with `to` and `retain` on some.
        let mut f = frame(&w.a, body.clone());
        if i % 3 == 0 {
            f.to = Some(w.b.id.clone());
        }
        f.retain = i % 2 == 0;
        let wire = tx.seal(&f, &ep, t0()).unwrap();
        assert!(wire.len() <= MAX_FRAME_BYTES);
        let o = rx.open(&wire, &view, t0(), &ep, MAXP).unwrap();
        assert_eq!(o.frame, f);
        assert!(o.writer);
        assert_eq!(o.key, tx.key().id());
        assert_eq!(o.n, i as u64 + 1);
    }
    // A bye without a claim omits the field rather than writing null.
    let p = encode_body(&Body::Bye {
        claim: None,
        leaving: true,
    })
    .unwrap();
    assert_eq!(p, br#"{"kind":"bye","leaving":true}"#);
}

/// One sealed beat from a, and a receiver b that has or has not already accepted a's key.
fn setup(warm: bool) -> (World, SessionAccount, Sender, Receiver, Vec<u8>) {
    let w = world();
    let view = w.view();
    let mut tx = sender(&w.a, &view, 11, cell());
    let mut rx = Receiver::new(cell(), &w.b.id);
    let ep = epochs();
    if warm {
        let first = tx
            .seal(&frame(&w.a, Body::Ping { t: 1 }), &ep, t0())
            .unwrap();
        rx.open(&first, &view, t0(), &ep, MAXP).unwrap();
    }
    let mut f = frame(&w.a, Body::Beat { claim: claim(2, &w.a), seq: 4 });
    f.to = Some(w.b.id.clone());
    f.retain = true;
    let wire = tx.seal(&f, &ep, t0()).unwrap();
    (w, view, tx, rx, wire)
}

fn assert_dropped(rx: &mut Receiver, view: &SessionAccount, bytes: &[u8], why: &str) -> DropReason {
    let before = rx.clone();
    let d = rx.open(bytes, view, t0(), &epochs(), MAXP).unwrap_err();
    assert_eq!(*rx, before, "{why}: a dropped frame changed receiver state");
    d.reason
}

#[test]
fn tampering_any_field_fails_closed_and_changes_nothing() {
    for warm in [false, true] {
        let (w, view, _, mut rx, wire) = setup(warm);
        let other = member(9).id;
        type Edit = Box<dyn Fn(&mut serde_json::Map<String, Value>)>;
        let edits: Vec<(&str, Edit)> = vec![
            ("protocol", Box::new(|m| { m.insert("protocol".into(), json!("colophon/session/7")); })),
            ("account", Box::new(|m| { m.insert("account".into(), json!(OTHER_ACCOUNT)); })),
            ("namespace", Box::new(|m| { m.insert("namespace".into(), json!("notes")); })),
            ("cell", Box::new(|m| { m.insert("cell".into(), json!("up-next")); })),
            ("from", { let b = w.b.id.clone(); Box::new(move |m| { m.insert("from".into(), json!(b)); }) }),
            ("key", { let o = other.clone(); Box::new(move |m| { m.insert("key".into(), json!(o)); }) }),
            ("to changed", { let o = other.clone(); Box::new(move |m| { m.insert("to".into(), json!(o)); }) }),
            ("to removed", Box::new(|m| { m.remove("to"); })),
            ("n", Box::new(|m| { m.insert("n".into(), json!(3)); })),
            ("epoch", Box::new(|m| { m.insert("epoch".into(), json!(2)); })),
            ("retain removed", Box::new(|m| { m.remove("retain"); })),
            ("retain false", Box::new(|m| { m.insert("retain".into(), json!(false)); })),
            ("ciphertext", Box::new(|m| flip_b64(m.get_mut("ciphertext").unwrap(), 5))),
            ("ciphertext tag", Box::new(|m| { let len = m["ciphertext"].as_str().unwrap().len(); flip_b64(m.get_mut("ciphertext").unwrap(), len); })),
            ("signature", Box::new(|m| flip_b64(m.get_mut("signature").unwrap(), 40))),
            ("delegation body", Box::new(|m| flip_b64(m.get_mut("delegation").unwrap().get_mut("body").unwrap(), 30))),
            ("delegation signature", Box::new(|m| flip_b64(m.get_mut("delegation").unwrap().get_mut("signature").unwrap(), 3))),
            ("delegation not an object", Box::new(|m| { m.insert("delegation".into(), json!("x")); })),
            ("unknown field", Box::new(|m| { m.insert("extra".into(), json!(1)); })),
            ("missing signature", Box::new(|m| { m.remove("signature"); })),
        ];
        for (name, f) in edits {
            let bad = edit(&wire, f);
            assert_dropped(&mut rx, &view, &bad, name);
        }
        // Without its delegation the frame still opens for a receiver that knows the key (it
        // is not signed), and is dropped with a hello request by one that does not.
        let stripped = edit(&wire, |m| { m.remove("delegation"); });
        if warm {
            rx.open(&stripped, &view, t0(), &epochs(), MAXP).unwrap();
        } else {
            let before = rx.clone();
            let d = rx.open(&stripped, &view, t0(), &epochs(), MAXP).unwrap_err();
            assert_eq!(d.reason, DropReason::NoKey);
            assert_eq!(d.hello_to.as_deref(), Some(w.a.id.as_str()));
            assert_eq!(rx, before);
        }
        // The unmodified frame still opens after all of that.
        if !warm {
            rx.open(&wire, &view, t0(), &epochs(), MAXP).unwrap();
        }
    }
}

#[test]
fn wrong_account_namespace_cell_or_epoch_is_dropped() {
    let (w, view, mut tx, _, wire) = setup(false);
    let cases: Vec<(CellId, SessionAccount, EpochTable, DropReason)> = vec![
        (CellId::new(OTHER_ACCOUNT, NS, CELL), SessionAccount::new(OTHER_ACCOUNT), epochs(), DropReason::Account),
        (CellId::new(ACCOUNT, "notes", CELL), view.clone(), epochs(), DropReason::Namespace),
        (CellId::new(ACCOUNT, NS, "up-next"), view.clone(), epochs(), DropReason::Cell),
        (cell(), view.clone(), EpochTable::new().with(NS, 2, EPOCH_KEY), DropReason::NoEpoch(1)),
        (cell(), view.clone(), EpochTable::new().with(NS, 1, [0x43; 32]), DropReason::Open),
        // The epoch key of another namespace does not open it either.
        (cell(), view.clone(), EpochTable::new().with("notes", 1, EPOCH_KEY), DropReason::NoEpoch(1)),
    ];
    for (c, v, ep, want) in cases {
        let mut rx = Receiver::new(c, &w.b.id);
        let before = rx.clone();
        let d = rx.open(&wire, &v, t0(), &ep, MAXP).unwrap_err();
        assert_eq!(d.reason, want);
        assert_eq!(rx, before);
    }
    // A frame sealed for another cell, replayed into this one.
    let mut other_cell = sender(&w.a, &view, 12, CellId::new(ACCOUNT, NS, "up-next"));
    let f = other_cell.seal(&frame(&w.a, Body::Ping { t: 1 }), &epochs(), t0()).unwrap();
    let mut rx = Receiver::new(cell(), &w.b.id);
    assert_eq!(assert_dropped(&mut rx, &view, &f, "other cell"), DropReason::Cell);
    // ... and with its cell rewritten: the signature no longer verifies.
    let rewritten = edit(&f, |m| { m.insert("cell".into(), json!(CELL)); });
    assert_eq!(assert_dropped(&mut rx, &view, &rewritten, "cell rewritten"), DropReason::Signature);
    // A frame sealed under another account's view, its account rewritten.
    let other_view = SessionAccount::new(OTHER_ACCOUNT).with_member(&w.a.point, 0, None, &[(NS, colophon_core::v05::terms::Access::Write)]);
    let mut acct = sender(&w.a, &other_view, 13, CellId::new(OTHER_ACCOUNT, NS, CELL));
    let f = acct.seal(&frame(&w.a, Body::Ping { t: 1 }), &epochs(), t0()).unwrap();
    assert_eq!(assert_dropped(&mut rx, &view, &f, "other account"), DropReason::Account);
    let rewritten = edit(&f, |m| { m.insert("account".into(), json!(ACCOUNT)); });
    let r = assert_dropped(&mut rx, &view, &rewritten, "account rewritten");
    assert!(matches!(r, DropReason::Delegation(_)), "{r}");
    let _ = tx.seal(&frame(&w.a, Body::Ping { t: 2 }), &epochs(), t0()).unwrap();
}

#[test]
fn replays_are_dropped_across_frames_cells_accounts_and_keys() {
    let (w, view, mut tx, mut rx, wire) = setup(false);
    rx.open(&wire, &view, t0(), &epochs(), MAXP).unwrap();
    assert_eq!(assert_dropped(&mut rx, &view, &wire, "replay"), DropReason::Replay);
    // A second session key of the same member: a frame of key 1 relabelled as key 2 (with
    // key 2's delegation) fails the signature.
    let mut tx2 = sender(&w.a, &view, 21, cell());
    let k2 = tx2.seal(&frame(&w.a, Body::Ping { t: 1 }), &epochs(), t0()).unwrap();
    rx.open(&k2, &view, t0(), &epochs(), MAXP).unwrap();
    let d2 = json(&k2)["delegation"].clone();
    let k2id = tx2.key().id().to_owned();
    let relabelled = edit(&wire, |m| {
        m.insert("key".into(), json!(k2id));
        m.insert("delegation".into(), d2);
    });
    assert_eq!(assert_dropped(&mut rx, &view, &relabelled, "key relabelled"), DropReason::Signature);
    // The delegation of key 2 attached to a frame of key 1 does not name (from, key).
    let d2 = json(&k2)["delegation"].clone();
    let mixed = edit(&wire, |m| { m.insert("delegation".into(), d2); });
    assert!(matches!(assert_dropped(&mut rx, &view, &mixed, "foreign delegation"), DropReason::Delegation(_)));
    // Windows are per key: n = 1 of key 2 was accepted, and key 1 continues independently.
    let next = tx.seal(&frame(&w.a, Body::Ping { t: 3 }), &epochs(), t0()).unwrap();
    rx.open(&next, &view, t0(), &epochs(), MAXP).unwrap();
}

#[test]
fn the_window_allows_reordering_inside_128_and_nothing_older() {
    let w = world();
    let view = w.view();
    let mut tx = sender(&w.a, &view, 11, cell());
    let ep = epochs();
    let sealed: Vec<Vec<u8>> = (0..300)
        .map(|i| tx.seal(&frame(&w.a, Body::Ping { t: i }), &ep, t0()).unwrap())
        .collect();
    let mut rx = Receiver::new(cell(), &w.b.id);
    rx.open(&sealed[199], &view, t0(), &ep, MAXP).unwrap(); // n = 200
    rx.open(&sealed[71], &view, t0(), &ep, MAXP).unwrap(); // n = 72: exactly 128 below
    assert_eq!(assert_dropped(&mut rx, &view, &sealed[70], "n = 71"), DropReason::TooOld);
    rx.open(&sealed[150], &view, t0(), &ep, MAXP).unwrap();
    assert_eq!(assert_dropped(&mut rx, &view, &sealed[150], "dup"), DropReason::Replay);
    rx.open(&sealed[299], &view, t0(), &ep, MAXP).unwrap(); // n = 300
    assert_eq!(assert_dropped(&mut rx, &view, &sealed[150], "now too old"), DropReason::TooOld);
    rx.open(&sealed[250], &view, t0(), &ep, MAXP).unwrap();
}

/// The receiver's window has exactly the bridge's forwarding window semantics.
#[test]
fn replay_window_matches_the_bridge_window() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..200 {
        let mut a = ReplayWindow::default();
        let mut b = bridge::Window::default();
        let mut high = 1u64;
        for _ in 0..400 {
            let n = match rng.below(4) {
                0 => high + rng.below(300),
                1 => high.saturating_sub(rng.below(140)).max(1),
                2 => high.saturating_sub(127 + rng.below(4)).max(1),
                _ => 1 + rng.below(high + 2),
            };
            let ours = a.check(n);
            let theirs = b.admit(n);
            let same = matches!(
                (&ours, theirs),
                (Ok(()), bridge::Seen::New)
                    | (Err(DropReason::Replay), bridge::Seen::Duplicate)
                    | (Err(DropReason::TooOld), bridge::Seen::TooOld)
            );
            assert!(same, "n={n} high={high}: {ours:?} vs {theirs:?}");
            if ours.is_ok() {
                a.admit(n);
                high = high.max(n);
            }
        }
    }
}

#[test]
fn nonces_never_repeat_and_a_restart_is_a_new_key() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut rng = Rng(7);
    let mut pairs = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for restart in 0..20u8 {
        let mut tx = sender(&w.a, &view, 100 + restart, cell());
        assert!(ids.insert(tx.key().id().to_owned()), "a restart reused a key");
        assert_eq!(tx.key().last_n(), 0);
        let bodies = every_kind(&w);
        for i in 0..150 {
            let body = bodies[rng.below(bodies.len() as u64) as usize].clone();
            let mut f = frame(&w.a, body);
            f.to = (i % 4 == 0).then(|| w.b.id.clone());
            let bytes = tx.seal(&f, &ep, t0()).unwrap();
            let v = json(&bytes);
            let n = v["n"].as_u64().unwrap();
            let key = v["key"].as_str().unwrap().to_owned();
            assert_eq!(n, i + 1, "n is the key's counter");
            let fk = frame_key(&EPOCH_KEY, &cell(), &key);
            assert!(pairs.insert((key, n)), "(key, n) sealed twice");
            assert!(nonces.insert((*fk, nonce(n))), "(frame key, nonce) used twice");
        }
    }
    // Failed seals never hand out an n twice either.
    let mut tx = sender(&w.a, &view, 99, cell());
    let big = frame(&w.a, Body::Submit { id: id("x"), payload: Bytes(vec![7; 13_000]) });
    assert_eq!(tx.seal(&big, &ep, t0()), Err(SealError::Oversize));
    let after = tx.seal(&frame(&w.a, Body::Ping { t: 1 }), &ep, t0()).unwrap();
    assert_eq!(json(&after)["n"], json!(2));
}

#[test]
fn delegations_are_bounded_and_checked_against_the_account() {
    let w = world();
    let view = w.view();
    let key = SessionKey::generate(&mut [31; 32]).unwrap();
    // Window longer than a day: refused when building, and when parsing a signed one.
    assert_eq!(
        key.delegation_body(ACCOUNT, &w.a.id, 0, NS, t0(), t0() + MAX_WINDOW_MS + 1000),
        Err(KeyError::Window)
    );
    let ok = key.delegation_body(ACCOUNT, &w.a.id, 0, NS, t0(), t0() + MAX_WINDOW_MS).unwrap();
    let long = String::from_utf8(ok.clone()).unwrap().replace("2026-11-23T10:00:00Z", "2026-11-23T10:00:01Z").into_bytes();
    assert!(Delegation::assemble(&long, &host_sign(&w.a, &long)).is_err());
    let d = Delegation::assemble(&ok, &host_sign(&w.a, &ok)).unwrap();
    d.verify(&view, NS, t0()).unwrap();
    // The clock: within the window widened by 60 s, inclusive.
    d.verify(&view, NS, t0() - 60_000).unwrap();
    assert!(d.verify(&view, NS, t0() - 60_001).is_err());
    d.verify(&view, NS, t0() + MAX_WINDOW_MS + 60_000).unwrap();
    assert!(d.verify(&view, NS, t0() + MAX_WINDOW_MS + 60_001).is_err());
    // Another namespace, a signature by another member, a member absent from the view, a
    // stale session number, and a member without the namespace.
    assert!(d.verify(&view, "notes", t0()).is_err());
    assert!(Delegation::assemble(&ok, &host_sign(&w.b, &ok)).unwrap().verify(&view, NS, t0()).is_err());
    let without_a = SessionAccount::new(ACCOUNT).with_member(&w.b.point, 0, None, &[(NS, colophon_core::v05::terms::Access::Write)]);
    assert!(d.verify(&without_a, NS, t0()).is_err());
    let bumped = SessionAccount::new(ACCOUNT).with_member(&w.a.point, 1, None, &[(NS, colophon_core::v05::terms::Access::Write)]);
    assert!(d.verify(&bumped, NS, t0()).is_err());
    let expired = SessionAccount::new(ACCOUNT).with_member(&w.a.point, 0, Some(t0() - 1), &[(NS, colophon_core::v05::terms::Access::Write)]);
    assert!(d.verify(&expired, NS, t0()).is_err());
    let xd = key.delegation_body(ACCOUNT, &w.x.id, 0, NS, t0(), t0() + 1000).unwrap();
    assert!(Delegation::assemble(&xd, &host_sign(&w.x, &xd)).unwrap().verify(&view, NS, t0()).is_err());
    // Unknown and missing fields in the body.
    let mut v = json(&ok);
    v.as_object_mut().unwrap().insert("extra".into(), json!(1));
    let extra = enc(&v);
    assert!(Delegation::assemble(&extra, &host_sign(&w.a, &extra)).is_err());
    let mut v = json(&ok);
    v.as_object_mut().unwrap().remove("session");
    let missing = enc(&v);
    assert!(Delegation::assemble(&missing, &host_sign(&w.a, &missing)).is_err());
}

#[test]
fn a_member_without_the_namespace_can_neither_forge_nor_open() {
    let (w, view, _, _, wire) = setup(false);
    // x forges a frame for the namespace with its own delegation: dropped at the delegation.
    let key = SessionKey::generate(&mut [41; 32]).unwrap();
    let mut forged = Sender::new(cell(), &w.x.id, key);
    let body = forged.delegation_body(0, t0(), t0() + 1000).unwrap();
    // The sender refuses to install a delegation the account does not support.
    assert!(forged.install(&body, &host_sign(&w.x, &body), &view, t0()).is_err());
    // x holds no epoch key for the namespace, so it cannot open a's frames.
    let mut rx = Receiver::new(cell(), &w.x.id);
    let d = rx.open(&wire, &view, t0(), &EpochTable::new().with("notes", 1, [9; 32]), MAXP).unwrap_err();
    assert_eq!(d.reason, DropReason::NoEpoch(1));
    // A frame x assembled by hand under a delegation it signed itself is dropped too.
    let env = Delegation::assemble(&body, &host_sign(&w.x, &body)).unwrap();
    let frame_x = edit(&wire, |m| {
        m.insert("from".into(), json!(w.x.id));
        m.insert("key".into(), json!(env.key_id()));
        m.insert("delegation".into(), json(&env.envelope));
    });
    let mut rx = Receiver::new(cell(), &w.b.id);
    assert!(matches!(assert_dropped(&mut rx, &view, &frame_x, "forged"), DropReason::Delegation(_)));
}

#[test]
fn a_read_only_member_is_never_a_writer() {
    let w = world();
    let view = w.view();
    let mut tx = sender(&w.r, &view, 51, cell());
    let mut rx = Receiver::new(cell(), &w.b.id);
    let f = tx.seal(&frame(&w.r, Body::Take { claim: claim(1, &w.r) }), &epochs(), t0()).unwrap();
    let o = rx.open(&f, &view, t0(), &epochs(), MAXP).unwrap();
    assert!(!o.writer, "a read entry never yields writer = true");
    // In the endpoint test the machine then ignores the take; here the flag is the contract.
}

#[test]
fn revocation_or_a_new_session_number_drops_keys() {
    let (w, view, mut tx, mut rx, wire) = setup(false);
    rx.open(&wire, &view, t0(), &epochs(), MAXP).unwrap();
    assert_eq!(rx.keys_for(&w.a.id), 1);
    let bumped = SessionAccount::new(ACCOUNT)
        .with_member(&w.a.point, 1, None, &[(NS, colophon_core::v05::terms::Access::Write)])
        .with_member(&w.b.point, 0, None, &[(NS, colophon_core::v05::terms::Access::Write)]);
    let gone = rx.set_account(&bumped, t0());
    assert!(gone.members.is_empty());
    assert_eq!(gone.keys, vec![(w.a.id.clone(), tx.key().id().to_owned())]);
    // Revision 17: nothing is kept for the old key; its frames fail their delegation.
    assert_eq!(rx.keys_for(&w.a.id), 0);
    let next = tx.seal(&frame(&w.a, Body::Ping { t: 9 }), &epochs(), t0()).unwrap();
    assert!(matches!(assert_dropped(&mut rx, &bumped, &next, "after bump"), DropReason::Delegation(_)));
    let revoked = SessionAccount::new(ACCOUNT).with_member(&w.b.point, 0, None, &[(NS, colophon_core::v05::terms::Access::Write)]);
    assert!(matches!(assert_dropped(&mut rx, &revoked, &next, "after revoke"), DropReason::Delegation(_)));
}

#[test]
fn delegation_expiry_mid_session() {
    let (w, view, mut tx, mut rx, wire) = setup(false);
    rx.open(&wire, &view, t0(), &epochs(), MAXP).unwrap();
    let late = t0() + 86_400_000 + 60_000;
    let f = tx.seal(&frame(&w.a, Body::Ping { t: 1 }), &epochs(), late).unwrap();
    rx.open(&f, &view, late, &epochs(), MAXP).unwrap();
    let f = tx.seal(&frame(&w.a, Body::Ping { t: 2 }), &epochs(), late).unwrap();
    let before = rx.clone();
    let d = rx.open(&f, &view, late + 1, &epochs(), MAXP).unwrap_err();
    assert_eq!(d.reason, DropReason::KeyWindow);
    assert_eq!(d.hello_to.as_deref(), Some(w.a.id.as_str()));
    assert_eq!(rx, before);
    // The sender stops sealing once its own delegation is outside the window.
    assert_eq!(
        tx.seal(&frame(&w.a, Body::Ping { t: 3 }), &epochs(), late + 1),
        Err(SealError::DelegationWindow)
    );
}

#[test]
fn oversize_frames_and_payloads_are_dropped() {
    let (w, view, mut tx, mut rx, _) = setup(false);
    let mut big = vec![b' '; MAX_FRAME_BYTES + 1];
    big[0] = b'{';
    assert_eq!(assert_dropped(&mut rx, &view, &big, "oversize"), DropReason::Oversize);
    // A payload over the receiver's maxPayload.
    let f = tx
        .seal(&frame(&w.a, Body::Presence { payload: Bytes(vec![1; 200]) }), &epochs(), t0())
        .unwrap();
    let before = rx.clone();
    let d = rx.open(&f, &view, t0(), &epochs(), 100).unwrap_err();
    assert_eq!(d.reason, DropReason::Range);
    assert_eq!(rx, before);
    // The largest snapshot a default cell allows, in a pass, still fits with room to spare;
    // a hello always carries the delegation.
    let pass = Body::Pass {
        claim: claim(MAX_TERM - 1, &w.a),
        next: Claim::passed(MAX_TERM, &w.b.id, &w.a.id),
        seq: MAX_INT,
        snapshot: Bytes(vec![0xff; 8_192]),
    };
    let mut f = frame(&w.a, pass);
    f.to = Some(w.b.id.clone());
    f.retain = true;
    let sealed = tx.seal(&f, &epochs(), t0()).unwrap();
    eprintln!("largest pass: {} bytes, delegation attached: {}", sealed.len(), json(&sealed).get("delegation").is_some());
    assert!(sealed.len() <= MAX_FRAME_BYTES);
    rx.open(&sealed, &view, t0(), &epochs(), MAXP).unwrap();
}

#[test]
fn malformed_outer_frames_are_dropped() {
    let (_, view, _, mut rx, wire) = setup(false);
    let text = String::from_utf8(wire.clone()).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("not json", b"not json".to_vec()),
        ("array", b"[]".to_vec()),
        ("whitespace", text.replacen(",", ", ", 1).into_bytes()),
        ("duplicate", text.replacen("{", "{\"n\":1,", 1).into_bytes()),
        ("n zero", edit(&wire, |m| { m.insert("n".into(), json!(0)); })),
        ("n float", text.replacen("\"n\":1", "\"n\":1.0", 1).into_bytes()),
        ("n too big", edit(&wire, |m| { m.insert("n".into(), json!(1u64 << 53)); })),
        ("epoch zero", edit(&wire, |m| { m.insert("epoch".into(), json!(0)); })),
        ("bad cell", edit(&wire, |m| { m.insert("cell".into(), json!("Now Playing")); })),
        ("bad from", edit(&wire, |m| { m.insert("from".into(), json!("a")); })),
        ("padded base64 broken", edit(&wire, |m| { let s = m["signature"].as_str().unwrap().trim_end_matches('=').to_owned(); m.insert("signature".into(), json!(s)); })),
        ("short signature", edit(&wire, |m| { m.insert("signature".into(), json!("AAAA")); })),
        ("short ciphertext", edit(&wire, |m| { m.insert("ciphertext".into(), json!("AAAA")); })),
    ];
    for (name, bytes) in cases {
        let r = assert_dropped(&mut rx, &view, &bytes, name);
        assert!(matches!(r, DropReason::Malformed(_)), "{name}: {r}");
    }
}

#[test]
fn malformed_plaintexts_are_dropped_after_opening() {
    let w = world();
    let view = w.view();
    let mut tx = sender(&w.a, &view, 11, cell());
    let mut rx = Receiver::new(cell(), &w.b.id);
    let a = w.a.id.clone();
    let good_hello = encode_body(&Body::Hello { fresh: id("f"), echo: vec![], seen: None, heard: None, lapsed: false }).unwrap();
    let f22 = String::from_utf8(good_hello.clone()).unwrap();
    let fresh = json(&good_hello)["fresh"].as_str().unwrap().to_owned();
    let cases: Vec<(&str, String, &str)> = vec![
        ("unknown kind", r#"{"kind":"wave"}"#.into(), "unknownKind"),
        ("no kind", r#"{"t":1}"#.into(), "plaintext"),
        ("unknown field", r#"{"kind":"ping","t":1,"x":2}"#.into(), "plaintext"),
        ("missing field", r#"{"kind":"pong","echo":1,"t":1}"#.into(), "plaintext"),
        ("heard is not a revision 14 field", f22.replacen("\"kind\"", "\"heard\":\"live\",\"kind\"", 1), "plaintext"),
        ("bye claim null", r#"{"claim":null,"kind":"bye","leaving":false}"#.into(), "plaintext"),
        ("non-canonical", r#"{"t":1,"kind":"ping"}"#.into(), "plaintext"),
        ("integer too big", r#"{"kind":"ping","t":9007199254740992}"#.into(), "range"),
        ("float", r#"{"kind":"ping","t":1.0}"#.into(), "range"),
        ("negative", r#"{"kind":"ping","t":-1}"#.into(), "range"),
        ("short fresh", f22.replace(&fresh, "AAAA"), "plaintext"),
        ("padded fresh", f22.replace(&fresh, &format!("{fresh}==")), "plaintext"),
        ("payload not canonical base64", r#"{"kind":"presence","payload":"AB=="}"#.into(), "plaintext"),
        ("holder not a member ID", r#"{"claim":{"holder":"a","rank":0,"term":1},"kind":"ask"}"#.into(), "plaintext"),
        ("claim unknown field", format!(r#"{{"claim":{{"holder":"{a}","rank":0,"term":1,"x":1}},"kind":"ask"}}"#), "plaintext"),
        ("rank 1 without via", format!(r#"{{"claim":{{"holder":"{a}","rank":1,"term":1}},"kind":"ask"}}"#), "range"),
        ("term zero", format!(r#"{{"claim":{{"holder":"{a}","rank":0,"term":0}},"kind":"ask"}}"#), "range"),
        ("nine echoes", { let e = vec![format!("\"{fresh}\""); 9].join(","); format!(r#"{{"echo":[{e}],"fresh":"{fresh}","kind":"hello","lapsed":false,"seen":null}}"#) }, "range"),
        ("duplicate member", r#"{"kind":"ping","t":1,"t":2}"#.into(), "plaintext"),
    ];
    for (name, plaintext, code) in cases {
        let bytes = tx
            .seal_plaintext(None, false, plaintext.as_bytes(), Attach::Always, &epochs(), t0())
            .unwrap();
        let r = assert_dropped(&mut rx, &view, &bytes, name);
        assert_eq!(r.code(), code, "{name}: {r}");
    }
    // A well-formed one after all of those still opens: nothing was remembered.
    let ok = tx.seal_plaintext(None, false, br#"{"kind":"ping","t":1}"#, Attach::Always, &epochs(), t0()).unwrap();
    rx.open(&ok, &view, t0(), &epochs(), MAXP).unwrap();
}

// ---------------------------------------------------------------------------------------
// Revision 15: key lifecycle, replay floors, probes, reasons, `ack`.

/// A sender for `m` with a delegation for `[nb, ex]`.
fn sender_window(m: &Member, view: &SessionAccount, random: u8, nb: i64, ex: i64) -> Sender {
    let key = SessionKey::generate(&mut [random; 32]).unwrap();
    let mut s = Sender::new(cell(), &m.id, key);
    let body = s.delegation_body(0, nb, ex).unwrap();
    s.install(&body, &host_sign(m, &body), view, t0()).unwrap();
    s
}

/// Revision 17: the receiver never evicts on its own; the caller (the
/// machine, through the endpoint) decides, and `retain` applies exactly that.
#[test]
fn the_receiver_never_evicts_on_its_own() {
    let w = world();
    let view = w.view();
    let ep = epochs();
    let mut rx = Receiver::new(cell(), &w.b.id);
    for i in 0..20u8 {
        let mut s = sender_window(&w.a, &view, 20 + i, t0(), t0() + 86_400_000);
        let f = s.seal(&frame(&w.a, Body::Ping { t: 1 }), &ep, t0()).unwrap();
        rx.open(&f, &view, t0(), &ep, MAXP).unwrap();
        assert_eq!(rx.len(), i as usize + 1, "nothing else was dropped");
    }
    rx.retain(|_, _| false);
    assert!(rx.is_empty());
    assert_eq!(CACHED_PER_MEMBER, 8);
}

#[test]
fn renewing_a_delegation_keeps_the_window_and_rewrapped_replays_fail() {
    let (w, view, mut tx, mut rx, wire) = setup(false);
    rx.open(&wire, &view, t0(), &epochs(), MAXP).unwrap();
    let body = tx.delegation_body(0, t0() + 1_000, t0() + 86_400_000).unwrap();
    tx.install(&body, &host_sign(&w.a, &body), &view, t0() + 1_000).unwrap();
    let renewed = json(&tx.seal(&frame(&w.a, Body::Ping { t: 1 }), &epochs(), t0() + 1_000).unwrap())["delegation"].clone();
    // The old frame re-wrapped with the renewed delegation is still a replay.
    let rewrapped = edit(&wire, |m| { m.insert("delegation".into(), renewed.clone()); });
    assert_eq!(assert_dropped(&mut rx, &view, &rewrapped, "rewrapped"), DropReason::Replay);
    let next = tx.seal(&frame(&w.a, Body::Ping { t: 2 }), &epochs(), t0() + 1_000).unwrap();
    let before = rx.window(&w.a.id, tx.key().id()).unwrap();
    rx.open(&next, &view, t0() + 1_000, &epochs(), MAXP).unwrap();
    assert!(rx.window(&w.a.id, tx.key().id()).unwrap().high() > before.high());
    // The sender refuses to delegate a key under another session number.
    assert_eq!(tx.delegation_body(1, t0(), t0() + 1_000), Err(KeyError::Retired));
}

#[test]
fn only_an_entitled_sender_draws_a_hello() {
    let (w, view, _, mut rx, wire) = setup(false);
    let stripped = edit(&wire, |m| { m.remove("delegation"); });
    let d = rx.open(&stripped, &view, t0(), &epochs(), MAXP).unwrap_err();
    assert_eq!(d.hello_to.as_deref(), Some(w.a.id.as_str()));
    // The same frame claiming a fake member ID, or a member without the namespace.
    for fake in [member(77).id, w.x.id.clone()] {
        let f = edit(&stripped, |m| { m.insert("from".into(), json!(fake)); });
        let d = rx.open(&f, &view, t0(), &epochs(), MAXP).unwrap_err();
        assert_eq!(d.reason, DropReason::NoKey);
        assert_eq!(d.hello_to, None, "no hello for {fake}");
    }
    // A reader is entitled to the namespace: it may be probed.
    let f = edit(&stripped, |m| { m.insert("from".into(), json!(w.r.id)); });
    assert_eq!(rx.open(&f, &view, t0(), &epochs(), MAXP).unwrap_err().hello_to.as_deref(), Some(w.r.id.as_str()));
}

#[test]
fn refuse_reasons_and_acks_are_bounded() {
    let w = world();
    let c = claim(1, &w.a);
    let ok = |b: &Body| decode_body(&encode_body(b).unwrap(), MAXP);
    assert!(ok(&Body::Refuse { id: id("s"), reason: "x".repeat(64) }).is_ok());
    assert!(ok(&Body::Refuse { id: id("s"), reason: String::new() }).is_ok());
    for reason in ["x".repeat(65), "Busy".into(), "too large".into(), "é".into()] {
        assert_eq!(ok(&Body::Refuse { id: id("s"), reason }).unwrap_err(), DropReason::Range);
    }
    assert_eq!(ok(&Body::Ack { yielded: None, passed: None }).unwrap_err(), DropReason::Range);
    assert_eq!(ok(&Body::Ack { yielded: Some(c.clone()), passed: Some(c.clone()) }).unwrap_err(), DropReason::Range);
    assert!(ok(&Body::Ack { yielded: Some(c), passed: None }).is_ok());
}
