//! Live state (0.3 §5.1), blobs (0.3 §7.2) and imports (§9.3, §10.1) through the engine: the
//! mechanics, and the attack each security property needs, asserted by reason.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs
)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use colophon_core::blobs::BlobRead;
use colophon_core::model::Outcome;
use colophon_core::v05::account::{Identity, RevokeKeep};
use colophon_core::v05::engine::{Engine, EngineOptions};
use colophon_core::v05::live::LiveVerdict;
use colophon_core::v05::records::HeldRecord;
use serde_json::{json, Value};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const LISTEN: &str = "listening.podcasts";
const NOTES: &str = "notes";

struct Shared {
    f: Fixture,
    host: Host,
    src: MemSource,
}
fn shared(namespaces: &[&str]) -> Shared {
    let mut f = create(namespaces);
    let host = std::mem::replace(&mut f.host, Host::new());
    f.host = Host::new();
    let src = MemSource::new();
    src.store_account(&f.account);
    Shared { f, host, src }
}
impl Shared {
    fn admit(&mut self, seed: u8, terms: Value) -> String {
        self.admit_with(seed, terms.clone(), terms)
    }
    fn admit_with(&mut self, seed: u8, asked: Value, granted: Value) -> String {
        // `admit` needs the fixture's own host: move ours in and out.
        std::mem::swap(&mut self.f.host, &mut self.host);
        let id = self.f.host.identity(seed);
        admit(&mut self.f, &id, "Device", "device", asked, granted);
        std::mem::swap(&mut self.f.host, &mut self.host);
        self.src.store_account(&self.f.account);
        id
    }
    fn engine(&self, member: &str) -> Engine<MemSource> {
        member_engine(&self.f, &self.host, &self.src, member, NOW)
    }
    fn live(
        &mut self,
        e: &mut Engine<MemSource>,
        payload: Value,
    ) -> colophon_core::v05::engine::live::LiveWritten {
        engine_live(e, &mut self.host, &self.src, payload)
    }
}
fn position(id: &str, seconds: f64) -> Value {
    json!({"id": id, "show": "show", "seconds": seconds})
}
fn heads(e: &Engine<MemSource>) -> Vec<(String, u64)> {
    e.account()
        .live_heads()
        .iter()
        .map(|h| (h.author.clone(), h.generation))
        .collect()
}

#[test]
fn a_higher_generation_replaces_a_lower_one_replays_do_not() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let mut e = s.engine(&id);
    let first = s.live(&mut e, position("e1", 10.0));
    let g1 = e.account().live_heads()[0].generation;
    let second = s.live(&mut e, position("e1", 20.0));
    let g2 = e.account().live_heads()[0].generation;
    assert!(g2 > g1);
    assert_eq!(
        e.account().live_heads().len(),
        1,
        "one slot per episode per author"
    );
    // The slot's old bytes arrive again (a stale copy on the relay): not a head, and not an error.
    let old = first.stores.last().unwrap().clone();
    assert_eq!(old.0, second.stores.last().unwrap().0, "the same path");
    e.apply_live(vec![HeldRecord {
        path: old.0.clone(),
        bytes: old.1.clone(),
    }])
    .unwrap();
    assert_eq!(
        e.account().live_heads()[0].generation,
        g2,
        "a lower generation never replaces"
    );
    let verdicts = e.live_verdicts();
    assert!(verdicts.iter().any(|(_, v)| *v == LiveVerdict::Superseded));
    // The fold carries the head, not the evidence.
    let ep = match e.query(LISTEN, "episode", json!({"id": "e1"})).unwrap() {
        Outcome::Success { value, .. } => value["value"].clone(),
        o => panic!("{o:?}"),
    };
    assert_eq!(ep["row"]["seconds"], 20.0);
}

#[test]
fn only_a_passive_position_may_be_live_and_a_caveated_writer_may_not() {
    let mut s = shared(&[LISTEN]);
    let plain = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let capped = s.admit(
        32,
        json!({"records": [{"namespace": LISTEN, "access": "write"}], "writes": 100}),
    );
    let kinded = s.admit(
        33,
        json!({"records": [{"namespace": LISTEN, "access": "write", "kinds": ["position", "follow"]}]}),
    );
    let seed = s.host.fresh();
    let e = s.engine(&plain);
    // A deliberate seek, a queue edit and a follow are not replaceable.
    for (kind, payload) in [
        (
            "position",
            json!({"id": "e1", "show": "show", "seconds": 5.0, "seek": true}),
        ),
        ("queue", json!({"episodes": ["e1"]})),
        (
            "follow",
            json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
        ),
    ] {
        let r = e.begin_live_write(LISTEN, kind, payload, seed);
        assert!(r.is_err(), "{kind} must stay on the immutable path");
    }
    // A caveated writer (a budget, a kind restriction) is refused, and by that reason.
    for who in [&capped, &kinded] {
        let e = s.engine(who);
        let seed = s.host.fresh();
        let d = e
            .begin_live_write(LISTEN, "position", position("e1", 1.0), seed)
            .unwrap()
            .unwrap_err();
        assert_eq!(d.reason, "caveatedLive", "{who}");
    }
}

#[test]
fn a_revoked_writers_live_slot_supplies_no_current_state_but_its_kept_records_stay() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let ctl_id = s.f.d.clone();
    let mut e = s.engine(&id);
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
    );
    s.live(&mut e, position("e1", 42.0));
    // Another device reads it.
    let mut r = {
        let id2 = s.admit(34, terms_for(&[(LISTEN, "read")]));
        s.engine(&id2)
    };
    r.refresh(s.src.listing()).unwrap();
    assert_eq!(r.account().live_heads().len(), 1);
    // The account revokes the writer, keeping its records.
    let mut ctl = controller_engine(&s.f, &s.host, &s.src, &ctl_id, NOW);
    let seed = s.host.fresh();
    let action = ctl
        .account()
        .begin_revoke(&id, &RevokeKeep::Everything, &[ctl_id.clone()], seed)
        .unwrap();
    engine_finish(&mut ctl, &s.host, &s.src, action);
    r.refresh(s.src.listing()).unwrap();
    let verdicts = r.live_verdicts().to_vec();
    assert!(
        verdicts
            .iter()
            .any(|(_, v)| *v == LiveVerdict::Refused("revoked")),
        "{verdicts:?}"
    );
    assert!(
        r.account().live_heads().is_empty(),
        "a revoked writer's slot supplies no current state"
    );
}

#[test]
fn two_bodies_at_one_generation_are_equivocation_and_neither_is_current() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    // A member key with two writing processes: two engines, one key.
    let mut a = s.engine(&id);
    let mut b = s.engine(&id);
    let mut r = s.engine(&id);
    let mut r2 = s.engine(&id);
    let wa = s.live(&mut a, position("e1", 10.0));
    let wb = engine_live(&mut b, &mut s.host, &MemSource::new(), position("e1", 99.0));
    assert_eq!(
        wa.stores.last().unwrap().0,
        wb.stores.last().unwrap().0,
        "one slot path"
    );
    assert_ne!(wa.stores.last().unwrap().1, wb.stores.last().unwrap().1);
    r.apply_live(vec![
        HeldRecord {
            path: wa.stores.last().unwrap().0.clone(),
            bytes: wa.stores.last().unwrap().1.clone(),
        },
        HeldRecord {
            path: wb.stores.last().unwrap().0.clone(),
            bytes: wb.stores.last().unwrap().1.clone(),
        },
    ])
    .unwrap();
    assert!(
        r.account().live_heads().is_empty(),
        "no head at an equivocated generation"
    );
    assert_eq!(
        r.live_verdicts()
            .iter()
            .filter(|(_, v)| *v == LiveVerdict::Equivocation)
            .count(),
        2
    );
    // The order they arrive in does not matter.
    r2.apply_live(vec![
        HeldRecord {
            path: wb.stores.last().unwrap().0.clone(),
            bytes: wb.stores.last().unwrap().1.clone(),
        },
        HeldRecord {
            path: wa.stores.last().unwrap().0.clone(),
            bytes: wa.stores.last().unwrap().1.clone(),
        },
    ])
    .unwrap();
    assert_eq!(heads(&r), heads(&r2));
    // A later generation by the same key resolves it.
    let mut a = s.engine(&id);
    a.apply_live(vec![
        HeldRecord {
            path: wa.stores.last().unwrap().0.clone(),
            bytes: wa.stores.last().unwrap().1.clone(),
        },
        HeldRecord {
            path: wb.stores.last().unwrap().0.clone(),
            bytes: wb.stores.last().unwrap().1.clone(),
        },
    ])
    .unwrap();
    s.live(&mut a, position("e1", 11.0));
    assert_eq!(a.account().live_heads().len(), 1);
}

#[test]
fn a_rolled_back_slot_is_recognised_after_a_restart_by_its_witness() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let mut w = s.engine(&id);
    let first = s.live(&mut w, position("e1", 10.0));
    let mut r = s.engine(&id);
    r.refresh(s.src.listing()).unwrap();
    let second = s.live(&mut w, position("e1", 20.0));
    r.refresh(s.src.listing()).unwrap();
    assert_eq!(
        r.account().live_heads()[0].generation,
        second_generation(&second)
    );
    let saved = r.save([1; 32]).unwrap();
    // The relay (or whoever holds the folder) puts the first value back.
    let (path, old) = first.stores.last().unwrap().clone();
    s.src.put(&path, old);
    let mut r2 = Engine::open(
        s.src.clone(),
        s.src.listing(),
        Identity::Member(id.clone()),
        EngineOptions::new(s.f.account.id().as_str(), DEVICE_KEY),
        Some(&saved),
        NOW,
    )
    .unwrap();
    let steps = r2.begin_unlock_epochs();
    r2.finish_unlock_epochs(s.host.answer_epochs(&id, steps))
        .unwrap();
    assert_eq!(
        r2.stale_live().len(),
        1,
        "the older slot is below its witness"
    );
    assert!(
        r2.account().live_heads().is_empty(),
        "the rolled-back value is not shown as current"
    );
    // A cold open has no witness and cannot tell (0.3 §7.1): it shows the old value.
    let cold = s.engine(&id);
    assert_eq!(cold.account().live_heads().len(), 1);
}
fn second_generation(w: &colophon_core::v05::engine::live::LiveWritten) -> u64 {
    let (_, bytes) = w.stores.last().unwrap();
    colophon_core::v05::records::OperationHeader::parse(bytes)
        .unwrap()
        .0
        .clock
}

#[test]
fn a_sample_that_cites_its_predecessor_retains_it_under_ops_and_a_passive_one_does_not() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let mut e = s.engine(&id);
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
    );
    let first = s.live(&mut e, position("e1", 10.0));
    let second = s.live(&mut e, position("e1", 20.0));
    assert!(
        second.stores.iter().all(|(p, _)| !p.starts_with("ops/")),
        "a passive sample replaces"
    );
    let prior_id = e.account().live_heads()[0].id.clone();
    let third = s.live(
        &mut e,
        json!({"id": "e1", "show": "show", "seconds": 30.0, "expect": prior_id}),
    );
    let (ops, bytes) = &third.stores[0];
    assert!(
        ops.starts_with("ops/"),
        "the exact predecessor first: {:?}",
        third.stores.iter().map(|x| &x.0).collect::<Vec<_>>()
    );
    assert_eq!(
        bytes,
        &second.stores.last().unwrap().1,
        "the exact signed bytes, not a rebuild"
    );
    assert_eq!(
        third.replaces.as_ref().unwrap().0,
        third.stores.last().unwrap().0
    );
    let _ = first;
    // The retained copy does not fork the author's chain: a durable write still works.
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "queue",
        json!({"episodes": ["e1"]}),
    );
}

#[test]
fn the_1024_bound_makes_a_passive_sample_wait_for_an_immutable_anchor() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let mut e = s.engine(&id);
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
    );
    let mut n = 0u32;
    loop {
        let seed = s.host.fresh();
        match e.begin_live_write(LISTEN, "position", position("e1", f64::from(n)), seed) {
            Ok(Ok(p)) => {
                let step = p.step();
                let sig = colophon_core::v05::write::SignatureResult {
                    signature: s.host.ids[step.signer()].sign(step.body()).to_vec(),
                    assertion: None,
                };
                e.finish_live_write(p, sig).unwrap();
                n += 1;
            }
            Ok(Err(d)) => panic!("{d:?}"),
            Err(f) => {
                assert!(
                    f.to_string().contains("1,024") || format!("{f:?}").contains("1,024"),
                    "{f:?}"
                );
                break;
            }
        }
        assert!(n <= 1_100, "the bound must stop the samples");
    }
    assert!(
        (1_000..=1_030).contains(&n),
        "samples before the anchor: {n}"
    );
    // The anchor: the same sample as an immutable operation, after which live samples go on.
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "position",
        position("e1", 9_999.0),
    );
    s.live(&mut e, position("e1", 10_000.0));
}

// ---------------------------------------------------------------------------------------------
// Blobs.

fn upload(
    s: &mut Shared,
    e: &mut Engine<MemSource>,
    ns: &str,
    bytes: &[u8],
    required: bool,
) -> colophon_core::blobs::BlobDescriptor {
    engine_blob(
        e,
        &mut s.host,
        &s.src,
        ns,
        "application/octet-stream",
        bytes,
        "r",
        required,
    )
}

#[test]
fn a_chunk_opens_only_under_its_own_account_namespace_epoch_and_bytes() {
    let mut s = shared(&[LISTEN, NOTES]);
    let id = s.admit(31, terms_for(&[(NOTES, "write"), (LISTEN, "write")]));
    let mut e = s.engine(&id);
    let bytes: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    let d = upload(&mut s, &mut e, NOTES, &bytes, true);
    let other = upload(&mut s, &mut e, NOTES, b"another blob", false);
    let m = match e.blob_manifest(NOTES, &d.digest).unwrap() {
        Outcome::Success { value, .. } => value,
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    };
    assert_eq!(m.chunks.len(), 3);
    match e.read_blob(NOTES, &d.digest).unwrap() {
        BlobRead::Available(b) => assert_eq!(b, bytes),
        o => panic!("{o:?}"),
    }
    let ct0 = s.src.get(&m.chunks[0].path).unwrap();
    let ct1 = s.src.get(&m.chunks[1].path).unwrap();
    // The right chunk at the wrong index, a flipped bit, and a chunk of another blob.
    assert!(
        e.open_blob_chunk(NOTES, &d.digest, 1, &ct0).is_err(),
        "bound to its index"
    );
    let mut flipped = ct1.clone();
    flipped[3] ^= 1;
    assert!(
        e.open_blob_chunk(NOTES, &d.digest, 1, &flipped).is_err(),
        "the content address"
    );
    let m2 = match e.blob_manifest(NOTES, &other.digest).unwrap() {
        Outcome::Success { value, .. } => value,
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    };
    let foreign = s.src.get(&m2.chunks[0].path).unwrap();
    assert!(e.open_blob_chunk(NOTES, &d.digest, 0, &foreign).is_err());
    // The same digest asked in another namespace is not there: no manifest, no key.
    assert!(matches!(
        e.blob_manifest(LISTEN, &d.digest).unwrap(),
        Outcome::Failure { .. }
    ));
    // Replaced chunk bytes at the right path: invalid, never an empty success.
    s.src.put(&m.chunks[1].path, flipped);
    assert!(matches!(
        e.blob_chunk(NOTES, &d.digest, 1).unwrap(),
        BlobRead::Invalid(_)
    ));
    assert!(matches!(
        e.read_blob(NOTES, &d.digest).unwrap(),
        BlobRead::Invalid(_)
    ));
}

#[test]
fn a_missing_chunk_is_missing_not_empty_and_availability_says_how_much() {
    let mut s = shared(&[NOTES]);
    let id = s.admit(31, terms_for(&[(NOTES, "write")]));
    let mut e = s.engine(&id);
    let bytes = vec![7u8; 140_000];
    let d = upload(&mut s, &mut e, NOTES, &bytes, true);
    let m = match e.blob_manifest(NOTES, &d.digest).unwrap() {
        Outcome::Success { value, .. } => value,
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    };
    assert_eq!(
        e.required_blob_fetches(NOTES).unwrap(),
        Vec::<String>::new()
    );
    s.src.remove(&m.chunks[2].path);
    assert!(matches!(
        e.blob_chunk(NOTES, &d.digest, 2).unwrap(),
        BlobRead::Missing
    ));
    assert!(matches!(
        e.read_blob(NOTES, &d.digest).unwrap(),
        BlobRead::Missing
    ));
    assert_eq!(
        e.blob_availability(NOTES, &d.digest).unwrap(),
        colophon_core::v05::engine::blobs::BlobAvailability::Partial {
            present: 2,
            total: 3
        }
    );
    assert_eq!(
        e.required_blob_fetches(NOTES).unwrap(),
        vec![m.chunks[2].path.clone()],
        "a required blob's missing chunk is to be fetched"
    );
    // An optional blob with a missing chunk is not on the fetch list.
    let opt = upload(&mut s, &mut e, NOTES, &vec![9u8; 70_000], false);
    let mo = match e.blob_manifest(NOTES, &opt.digest).unwrap() {
        Outcome::Success { value, .. } => value,
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    };
    s.src.remove(&mo.chunks[0].path);
    assert_eq!(e.required_blob_fetches(NOTES).unwrap().len(), 1);
}

#[test]
fn a_revoked_member_reads_no_blob_and_an_unknown_one_is_unavailable() {
    let mut s = shared(&[NOTES]);
    let id = s.admit(31, terms_for(&[(NOTES, "write")]));
    let reader = s.admit(35, terms_for(&[(NOTES, "read")]));
    let ctl_id = s.f.d.clone();
    let mut e = s.engine(&id);
    let d = upload(&mut s, &mut e, NOTES, b"private blob", true);
    let mut r = s.engine(&reader);
    r.refresh(s.src.listing()).unwrap();
    assert!(matches!(
        r.read_blob(NOTES, &d.digest).unwrap(),
        BlobRead::Available(_)
    ));
    assert!(matches!(
        r.read_blob(NOTES, &"0".repeat(64)).unwrap(),
        BlobRead::Missing
    ));
    let mut ctl = controller_engine(&s.f, &s.host, &s.src, &ctl_id, NOW);
    let seed = s.host.fresh();
    let action = ctl
        .account()
        .begin_revoke(&reader, &RevokeKeep::Nothing, &[ctl_id.clone()], seed)
        .unwrap();
    engine_finish(&mut ctl, &s.host, &s.src, action);
    r.refresh(s.src.listing()).unwrap();
    assert!(
        matches!(
            r.read_blob(NOTES, &d.digest).unwrap(),
            BlobRead::Inaccessible(_)
        ),
        "revoked: inaccessible, not empty"
    );
    // A read-only member cannot start an upload.
    let ro = s.admit(36, terms_for(&[(NOTES, "read")]));
    let e = s.engine(&ro);
    assert!(matches!(
        e.begin_blob(NOTES, "text/plain".into(), [3; 32]).unwrap(),
        Outcome::Failure { .. }
    ));
}

// ---------------------------------------------------------------------------------------------
// Imports.

#[test]
fn an_import_batch_needs_the_import_term_in_the_engine_and_in_the_fold() {
    // `begin_approve` cannot grant `import` (§9.3: "a home or import grant is a transition"),
    // and the account has no builder for a transition's `grant` component with its shares, so
    // the positive path (a member whose terms carry `import`) cannot be driven from here: see
    // the report. What can be shown: the engine refuses the batch of a member without the term,
    // and a batch such a member writes anyway (through the plain write path) has no effect.
    let mut s = shared(&[NOTES]);
    let plain = s.admit(32, terms_for(&[(NOTES, "write")]));
    let batch = colophon_core::imports::ImportBatch {
        key: "unit-1".into(),
        evidence: json!({"source": "synthetic"}),
        children: vec![colophon_core::imports::ImportChild {
            key: "c1".into(),
            kind: "createNotebook".into(),
            payload: json!({"id": "imported", "title": "Imported"}),
            baseline: false,
        }],
        alternatives: vec![],
        identities: Default::default(),
        blobs: vec![],
    };
    let mut e = s.engine(&plain);
    let err = e.begin_import(NOTES, &batch, [4; 32]).unwrap_err();
    assert_eq!(err.code(), "refused:notGranted", "no import term");
    // Around the engine's gate: the batch is an ordinary record, admitted, and the fold does
    // not apply it for a writer without the import role.
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        NOTES,
        "colophon.importBatch",
        serde_json::to_value(&batch).unwrap(),
    );
    let r = s.engine(&plain);
    let nb = match r.query(NOTES, "notebooks", json!({})).unwrap() {
        Outcome::Success { value, .. } => value.to_string(),
        o => panic!("{o:?}"),
    };
    assert!(!nb.contains("imported"), "no import role, no effect: {nb}");
}

#[test]
fn a_forged_live_signature_and_a_live_record_at_the_wrong_path_supply_nothing() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let other = s.admit(32, terms_for(&[(LISTEN, "write")]));
    let mut r = s.engine(&id);
    let mut e = s.engine(&id);
    let w = s.live(&mut e, position("e1", 10.0));
    let (path, bytes) = w.stores.last().unwrap().clone();
    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
    let mut sig = STANDARD.decode(v["signature"].as_str().unwrap()).unwrap();
    sig[7] ^= 1;
    v["signature"] = json!(b64(&sig));
    let forged = colophon_core::v05::encoding::canonical(&v).unwrap();
    let slot_name = path.rsplit('/').next().unwrap().to_string();
    let elsewhere = path.replace(&slot_name, &format!("{}.json", "ab".repeat(32)));
    let as_other = path.replace(&id, &other);
    r.apply_live(vec![HeldRecord {
        path: path.clone(),
        bytes: forged,
    }])
    .unwrap();
    assert!(
        r.account().live_heads().is_empty(),
        "a forged signature is no live record"
    );
    for bad in [elsewhere, as_other] {
        r.apply_live(vec![HeldRecord {
            path: bad,
            bytes: bytes.clone(),
        }])
        .unwrap();
        assert!(
            r.account().live_heads().is_empty(),
            "a slot, a path and a stamp must agree"
        );
    }
    assert!(
        r.live_verdicts()
            .iter()
            .all(|(_, v)| matches!(v, LiveVerdict::Invalid(_) | LiveVerdict::Refused(_))),
        "{:?}",
        r.live_verdicts()
    );
    // The real one is a head.
    r.apply_live(vec![HeldRecord { path, bytes }]).unwrap();
    assert_eq!(r.account().live_heads().len(), 1);
}

#[test]
fn a_write_budget_that_spans_unread_namespaces_refuses_local_writes_on_a_partial_replica() {
    let mut s = shared(&[LISTEN, NOTES]);
    let capped = s.admit(
        31,
        json!({"records": [{"namespace": LISTEN, "access": "write"}, {"namespace": NOTES, "access": "write"}], "writes": 50}),
    );
    let mut partial_opts = EngineOptions::new(s.f.account.id().as_str(), DEVICE_KEY);
    partial_opts.namespaces = vec![LISTEN.to_string()];
    let mut e = Engine::open(
        s.src.clone(),
        s.src.listing(),
        Identity::Member(capped.clone()),
        partial_opts,
        None,
        NOW,
    )
    .unwrap();
    let steps = e.begin_unlock_epochs();
    e.finish_unlock_epochs(s.host.answer_epochs(&capped, steps))
        .unwrap();
    assert_eq!(e.budget_scope_unavailable(), vec![capped.clone()]);
    let seed = s.host.fresh();
    let d = e
        .begin_write(
            LISTEN,
            "follow",
            json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
            colophon_core::v05::records::Level::Write,
            seed,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(d.reason, "budgetScopeUnavailable");
    // The complete scope may write.
    let mut full = s.engine(&capped);
    assert!(full.budget_scope_unavailable().is_empty());
    engine_write(
        &mut full,
        &mut s.host,
        &s.src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
    );
}

#[test]
fn an_immutable_action_on_an_episode_retains_the_live_head_it_relies_on() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let mut e = s.engine(&id);
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/f", "title": "T"}),
    );
    let live = s.live(&mut e, position("e1", 10.0));
    let (slot_path, slot_bytes) = live.stores.last().unwrap().clone();
    // A deliberate seek on the same episode is immutable and relies on the head: it is
    // retained exactly, first.
    let w = engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "position",
        json!({"id": "e1", "show": "show", "seconds": 50.0, "seek": true}),
    );
    let (ops, bytes) = &w.stores[0];
    assert!(
        ops.starts_with("ops/"),
        "{:?}",
        w.stores.iter().map(|x| &x.0).collect::<Vec<_>>()
    );
    assert_eq!(bytes, &slot_bytes, "the exact signed bytes of the head");
    assert_ne!(ops, &slot_path);
    let mut r = s.engine(&id);
    r.refresh(s.src.listing()).unwrap();
    assert_eq!(r.account().record_verdict(ops).as_deref(), Some("admitted"));
    // An action on another episode retains nothing.
    let w2 = engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "position",
        json!({"id": "e2", "show": "show", "seconds": 5.0, "seek": true}),
    );
    assert_eq!(w2.stores.len(), 1);
}

fn home_receipt(f: &Fixture, home: &str, object: &str, at: i64) -> Vec<u8> {
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/receipt/5", "account": f.account.id().as_str(), "object": object,
        "received": colophon_core::v05::write::format_date(at), "by": home,
    }))
    .unwrap();
    colophon_core::v05::encoding::canonical(
        &json!({"body": b64(&body), "signature": b64(&f.host.ids[home].sign(&body))}),
    )
    .unwrap()
}
fn home_head(f: &Fixture, home: &str, at: i64) -> Vec<u8> {
    let (seq, dg) = f.account.head();
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/head/5", "account": f.account.id().as_str(),
        "authority": {"seq": seq, "digest": dg}, "by": home,
        "issued": colophon_core::v05::write::format_date(at),
    }))
    .unwrap();
    colophon_core::v05::encoding::canonical(
        &json!({"body": b64(&body), "signature": b64(&f.host.ids[home].sign(&body))}),
    )
    .unwrap()
}

/// §9.3 end to end: an import grant is a transition (`Change::grant`), receipted by the home,
/// activated when due, made final by a home's head, its shares sealed by a shares-only renew; the
/// member then publishes a `colophon.importBatch` that folds once.
#[test]
fn an_import_grant_is_made_through_the_account_and_its_batch_folds() {
    use colophon_core::v05::account::{Change, Incoming};
    use colophon_core::v05::history::Objects;
    use colophon_core::v05::write::authority::TransitionRule;
    let mut f = create(&[NOTES]);
    let home = appoint_home(&mut f);
    let importer = f.host.identity(40);
    let now = f.account.now_ms();
    let asked = terms_for(&[(NOTES, "write")]);
    let granted = json!({"records": [{"namespace": NOTES, "access": "write"}], "import": true,
        "expires": colophon_core::v05::write::format_date(now + 30 * 24 * HOUR)});
    let req = request_for(&f, &f.host, &importer, "Importer", "device", asked, now);
    let change = Change::grant(&req.raw, granted);
    let action = f
        .account
        .begin_transition(
            &change,
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    let digest = pending_path(&done.pending[0]);
    let digest = digest
        .trim_start_matches("transitions/")
        .trim_end_matches(".json")
        .to_string();
    let merge_pending = |a: &mut colophon_core::v05::account::Account, o: Objects| {
        let n = a.now_ms();
        a.merge(
            Incoming {
                objects: o,
                records: vec![],
            },
            n,
        )
        .unwrap();
    };
    let r = home_receipt(&f, &home, &digest, now + 10 * SEC);
    merge_pending(
        &mut f.account,
        Objects {
            pending: vec![r],
            ..Default::default()
        },
    );
    f.account.advance(now + 2 * HOUR).unwrap();
    let rec = f.account.record_due().unwrap();
    assert_eq!(rec.len(), 1, "the activation is recorded when due");
    // Provisional until a home's head covers the activation; then final.
    let head = home_head(&f, &home, now + 2 * HOUR);
    merge_pending(
        &mut f.account,
        Objects {
            heads: vec![head],
            ..Default::default()
        },
    );
    let _ = f.account.record_due().unwrap();
    assert!(f.account.members().iter().any(|m| m.member.id == importer));
    // Its shares: a transition's grant carries none; the shares-only renew seals them.
    assert!(!f.account.owed_shares().is_empty());
    let seed = f.host.fresh();
    let a = f
        .account
        .begin_renew_shares(&importer, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, a);
    assert!(f.account.owed_shares().is_empty());
    // The importer's engine publishes a batch.
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &importer, now + 3 * HOUR);
    let batch = colophon_core::imports::ImportBatch {
        key: "unit-1".into(),
        evidence: json!({"source": "synthetic"}),
        children: vec![colophon_core::imports::ImportChild {
            key: "c1".into(),
            kind: "createNotebook".into(),
            payload: json!({"id": "imported", "title": "Imported"}),
            baseline: false,
        }],
        alternatives: vec![],
        identities: Default::default(),
        blobs: vec![],
    };
    let seed = host.fresh();
    let action = e.begin_import(NOTES, &batch, seed).unwrap().unwrap();
    engine_finish(&mut e, &host, &src, action);
    let nb = match e.query(NOTES, "notebooks", json!({})).unwrap() {
        Outcome::Success { value, .. } => value.to_string(),
        o => panic!("{o:?}"),
    };
    assert!(
        nb.contains("imported"),
        "the batch folds for a member whose terms carry import: {nb}"
    );
}
