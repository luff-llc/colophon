//! The second independent check of the engine (2026-11-14), ported as permanent tests with the
//! assertions turned round: each states the correct behaviour and failed before the E9 fix.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code,
    unused_imports
)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use colophon_core::model::Outcome;
use colophon_core::v05::account::{Account, Identity, Incoming};
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::engine::exchange::{Fault, Method, Request, Response, Step};
use colophon_core::v05::engine::{Engine, EngineOptions, OpenMode};
use colophon_core::v05::history::Objects;
use colophon_core::v05::records::{HeldRecord, Level};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::*;

const NOTES: &str = "notes";

fn sha_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn body_of(env: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(env).unwrap();
    let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&body).unwrap()
}
fn body_digest(env: &[u8]) -> String {
    let v: Value = serde_json::from_slice(env).unwrap();
    let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
    digest(&body)
}
/// An envelope over `body` with a signature of 64 zero bytes (no key needed).
fn unsigned(body: &Value) -> Vec<u8> {
    let b = canonical(body).unwrap();
    canonical(&json!({"body": STANDARD.encode(&b), "signature": STANDARD.encode([0u8; 64])}))
        .unwrap()
}
fn op_path(b: &Value) -> String {
    format!(
        "ops/{}/{}/{:012}-{}.json",
        b["author"].as_str().unwrap(),
        b["namespace"].as_str().unwrap(),
        b["clock"].as_u64().unwrap(),
        b["id"].as_str().unwrap()
    )
}

// ---------------------------------------------------------------------------------------------
// A notes world: one member that has written `n` notes through an `Account`.

struct Notes {
    f: Fixture,
    src: MemSource,
    member: String,
    writer: Account,
}
fn notes(n: usize) -> Notes {
    let mut f = create(&[NOTES]);
    let member = f.host.identity(31);
    admit(
        &mut f,
        &member,
        "Phone",
        "device",
        terms("write"),
        terms("write"),
    );
    let src = MemSource::versioned();
    src.store_account(&f.account);
    let writer = member_session(&f, &member);
    let mut w = Notes {
        f,
        src,
        member,
        writer,
    };
    for i in 0..n {
        write_note(&mut w, i);
    }
    w
}
fn write_note(w: &mut Notes, i: usize) -> HeldRecord {
    let seed = w.f.host.fresh();
    let action = w
        .writer
        .begin_write(
            NOTES,
            "createNotebook",
            json!({"id": format!("nb{i:05}"), "title": format!("Notebook {i}")}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let done = run(&mut w.writer, &w.f.host, action);
    w.src.publish(&done);
    done.records[0].clone()
}
fn open_notes(
    w: &Notes,
    src: &MemSource,
    saved: Option<&colophon_core::v05::engine::Saved>,
) -> colophon_core::v05::Result<Engine<MemSource>> {
    let mut e = Engine::open(
        src.clone(),
        src.listing(),
        Identity::Member(w.member.clone()),
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY),
        saved,
        w.f.account.now_ms(),
    )?;
    let steps = e.begin_unlock_epochs();
    let results = w.f.host.answer_epochs(&w.member, steps);
    e.finish_unlock_epochs(results)?;
    Ok(e)
}
fn admitted_ids(e: &Engine<MemSource>, ns: &str) -> Vec<String> {
    match e.view(ns).unwrap() {
        Outcome::Success { value, .. } => {
            let v = serde_json::to_value(value).unwrap();
            v["admitted"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["id"].as_str().unwrap().to_string())
                .collect()
        }
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}

/// A keyless header naming `previous` under an author the verified history does not know.
fn planted_naming(w: &mut Notes, like: &HeldRecord, previous: &str) -> HeldRecord {
    let stranger = w.f.host.identity(99);
    let mut b = body_of(&like.bytes);
    b["author"] = json!(stranger);
    b["previous"] = json!(previous);
    HeldRecord {
        path: op_path(&b),
        bytes: unsigned(&b),
    }
}

// ---------------------------------------------------------------------------------------------
// S-H1: the write index takes `previous` from every judged header, of any author, including a
// keyless header by an author the history does not know. One planted file removes the
// member's chain tip: its next write starts a second root (a fork of its own chain by the
// §11.2 rule), and a device of the same member that does not hold the planted file is then
// refused every further write (`refused:fork`).

#[test]
fn a_planted_header_does_not_steer_the_writers_chain_tip() {
    let mut w = notes(3);
    let tip = w.writer.records().last().unwrap().clone();
    let tip_digest = body_digest(&tip.bytes);
    // Control: the next write would name the tip.
    // Plant one keyless header (unknown author) whose `previous` is the tip.
    let planted = planted_naming(&mut w, &tip, &tip_digest);
    let now = w.writer.now_ms();
    w.writer
        .merge(
            Incoming {
                objects: Objects::default(),
                records: vec![planted.clone()],
            },
            now,
        )
        .unwrap();
    // The writer writes once more. The full rule (chain_heads over verified headers of this
    // author) names `tip_digest` as `previous`.
    let next = write_note(&mut w, 3);
    let prev = body_of(&next.bytes)["previous"].clone();
    assert_eq!(
        prev,
        json!(tip_digest),
        "a keyless header by an unknown author must not move the writer's chain tip"
    );
    // A second device of the same member, holding every real record but not the planted one.
    let mut other = member_session(&w.f, &w.member);
    let real: Vec<HeldRecord> = w
        .writer
        .records()
        .iter()
        .filter(|r| r.path != planted.path)
        .cloned()
        .collect();
    other
        .merge(
            Incoming {
                objects: Objects::default(),
                records: real,
            },
            now,
        )
        .unwrap();
    let seed = w.f.host.fresh();
    let r = other.begin_write(
        NOTES,
        "createNotebook",
        json!({"id": "nb99999", "title": "x"}),
        Level::Write,
        seed,
    );
    assert!(
        matches!(r, Ok(Ok(_))),
        "the second device is not refused: {:?}",
        r.map(|x| x.map(|_| ()))
    );
}

/// Control for S-H1: without the planted file the next write names the tip.
#[test]
fn control_next_write_names_the_tip() {
    let mut w = notes(3);
    let tip = w.writer.records().last().unwrap().clone();
    let tip_digest = body_digest(&tip.bytes);
    let next = write_note(&mut w, 3);
    assert_eq!(body_of(&next.bytes)["previous"], json!(tip_digest));
}

// ---------------------------------------------------------------------------------------------
// Exchange helpers.

const FAKE_AUTHOR: &str = "ffffffffffffffffffffffffffffffff";

/// A home that adds listed entries to the first change page and answers their GETs as told.
struct Hostile {
    sim: SimHome,
    extra: Vec<(String, String)>,
    /// What to answer for a GET of an extra path: status and body.
    answer: (u16, Vec<u8>),
    pub gets: Vec<String>,
}
impl Wire for Hostile {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        let path = req
            .url
            .strip_prefix("https://home.example")
            .unwrap()
            .to_string();
        if req.method == Method::Get {
            self.gets.push(path.clone());
            for (p, _) in &self.extra {
                if path == format!("/records/{p}") {
                    return Response {
                        status: self.answer.0,
                        headers: vec![],
                        body: self.answer.1.clone(),
                    };
                }
            }
        }
        let mut r = self.sim.call(host, req, now_ms);
        if req.method == Method::Get && path.starts_with("/changes") && !path.contains("after=") {
            let mut v: Value = serde_json::from_slice(&r.body).unwrap();
            for (p, sha) in &self.extra {
                v["entries"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"path": p, "size": 10, "sha256": sha}));
            }
            r.body = serde_json::to_vec(&v).unwrap();
        }
        r
    }
}

fn note_payload(i: usize) -> Value {
    json!({"id": format!("nb{i:05}"), "title": format!("Notebook {i}")})
}

/// An account with a home; device A wrote `n` notes and synced them to the home.
fn synced_notes(n: usize) -> (Setup, String, i64) {
    let (mut s, ids) = setup(NOTES, &[("Phone", 31, "write")]);
    let member = ids[0].clone();
    let now = s.f.account.now_ms() + 60 * SEC;
    let src_a = device_source(&s);
    let mut a = member_engine(&s.f, &s.f.host, &src_a, &member, now);
    for i in 0..n {
        engine_write(
            &mut a,
            &mut s.f.host,
            &src_a,
            NOTES,
            "createNotebook",
            note_payload(i),
        );
    }
    let faults = sync_pass(&mut a, &src_a, &s.home, &mut s.sim, &s.f.host, now);
    assert!(
        faults.iter().all(|f| !matches!(f, Fault::Conflict { .. })),
        "{faults:?}"
    );
    (s, member, now)
}

// ---------------------------------------------------------------------------------------------
// S-H2: pulled records are judged only when the last queued pull is answered with a record.
// If the pull that sorts last fails (a 404, a digest mismatch, junk), the batch is never
// flushed: the pass ends with every real record fetched, hash-checked and dropped. The default
// batch is 16,384, so a home that lists one bad path that sorts last (or an honest home that
// lost one file) keeps an honest device from ever taking new records.

#[test]
fn one_failing_last_pull_costs_only_itself() {
    let (s, member, now) = synced_notes(3);
    let mut wire = Hostile {
        sim: s.sim.clone(),
        extra: vec![(
            format!("ops/{FAKE_AUTHOR}/{NOTES}/000000000999-{FAKE_AUTHOR}.json"),
            sha_hex(b"gone"),
        )],
        answer: (404, b"{}".to_vec()),
        gets: Vec::new(),
    };
    let src_b = device_source(&s);
    let mut b = member_engine(&s.f, &s.f.host, &src_b, &member, now);
    let mut reported = false;
    for pass in 0..3 {
        let faults = sync_pass(&mut b, &src_b, &s.home, &mut wire, &s.f.host, now + pass);
        reported |= faults
            .iter()
            .any(|f| matches!(f, Fault::Status { status: 404, .. }));
    }
    assert!(reported, "the bad answer is reported");
    let real_gets = wire
        .gets
        .iter()
        .filter(|g| g.starts_with("/records/ops/") && !g.contains(FAKE_AUTHOR))
        .count();
    assert_eq!(
        real_gets, 3,
        "each real record was fetched once: it was taken the first pass"
    );
    assert_eq!(
        admitted_ids(&b, NOTES).len(),
        3,
        "the real records were taken"
    );
    assert_eq!(
        src_b
            .listing()
            .iter()
            .filter(|p| p.starts_with("ops/"))
            .count(),
        3
    );
}

/// Control for S-H2: the same home without the extra entry delivers the three records.
#[test]
fn control_honest_home_delivers_the_records() {
    let (mut s, member, now) = synced_notes(3);
    let src_b = device_source(&s);
    let mut b = member_engine(&s.f, &s.f.host, &src_b, &member, now);
    sync_pass(&mut b, &src_b, &s.home, &mut s.sim, &s.f.host, now);
    assert_eq!(admitted_ids(&b, NOTES).len(), 3);
}

// ---------------------------------------------------------------------------------------------
// The blob AAD after an in-place upgrade: a chunk the 0.4 code wrote for a library opens with
// the 0.5 engine's key and AAD (the first 32 characters of the account ID) for the same
// account after the upgrade, through the engine's ordinary read path.

#[path = "support/mod.rs"]
mod v04;

#[test]
fn a_0_4_blob_opens_with_the_0_5_engine_after_an_in_place_upgrade() {
    use colophon_core::blobs::BlobRead;
    use colophon_core::v05::account::EpochSecret;
    use colophon_core::v05::vault::EcdhOutput;
    use colophon_core::v05::write::upgrade::{prepare_upgrade, UpgradeParams};
    use colophon_core::v05::write::SignatureResult;
    // 0.4: a library, a two-chunk blob written by the 0.4 code, its manifest published by a
    // 0.4 operation.
    let (mut lib, owner, controller) = v04::create();
    let mut writer = match lib
        .begin_blob("notes", "text/plain".into(), v04::NOW, [60; 32])
        .unwrap()
    {
        Outcome::Success { value, .. } => value,
        _ => panic!(),
    };
    let first = vec![b'a'; colophon_core::blobs::CHUNK_BYTES];
    let second = b"the last chunk of a 0.4 blob".to_vec();
    let (p1, c1) = writer.push(&first).unwrap();
    let (p2, c2) = writer.push(&second).unwrap();
    let manifest = writer.finish().unwrap();
    let content = manifest.descriptor.digest.clone();
    v04::write(
        &mut lib,
        &owner,
        "notes",
        "colophon.blobPublish",
        json!({"manifest": manifest, "reference": "attachment", "required": true}),
        61,
    );
    // The 0.4 code itself opens it.
    assert_eq!(
        v04::success(
            lib.open_blob_chunk("notes", &content, 1, &c2, v04::NOW)
                .unwrap()
        ),
        second
    );
    let legacy_id = lib.id().to_string();
    // The in-place upgrade (§16.1), signed by the 0.4 controller.
    const T_NOW04: i64 = 1_793_793_600_000; // 2026-11-04T12:00:00Z
    let records = lib.records().clone();
    let params = UpgradeParams {
        policy: json!({"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
           "linkMaxAge": 86400, "memberRule": "single", "recoveryDelay": 259200,
           "rate": {"account": {"bytes": 16777216, "entries": 256},
                    "signer": {"bytes": 4194304, "entries": 64}}}),
        add_threshold: 1,
        count_by: "keys".into(),
        issued_ms: T_NOW04 + HOUR,
        signers: vec![controller.public().id()],
    };
    let pending = prepare_upgrade(&records, &params, T_NOW04 + 2 * HOUR).unwrap();
    let sigs: Vec<SignatureResult> = pending
        .steps()
        .iter()
        .map(|s| SignatureResult {
            signature: controller.sign(s.body()),
            assertion: None,
        })
        .collect();
    let upgraded: Vec<(String, Vec<u8>)> = pending
        .finish(sigs)
        .unwrap()
        .entries
        .into_iter()
        .map(|(seq, b)| (format!("authority/{seq:08}.json"), b))
        .collect();
    // The device's folder after the upgrade: the 0.4 files, the upgrade entry, the chunks.
    let src = MemSource::new();
    for (p, b) in records.iter().chain(upgraded.iter().map(|(p, b)| (p, b))) {
        src.put(p, b.clone());
    }
    src.put(&p1, c1.clone());
    src.put(&p2, c2.clone());
    let entries: Vec<Vec<u8>> = records
        .iter()
        .chain(upgraded.iter().map(|(p, b)| (p, b)))
        .filter(|(p, _)| p.starts_with("authority/"))
        .map(|(_, b)| b.clone())
        .collect();
    let me = owner.public().id();
    let probe = Account::open(
        Objects {
            entries,
            ..Default::default()
        },
        vec![],
        None,
        Identity::Member(me.clone()),
        T_NOW04 + 2 * HOUR,
    )
    .unwrap();
    let account = probe.id().as_str().to_string();
    assert_eq!(
        &account[..32],
        legacy_id,
        "the account ID extends the library ID"
    );
    // 0.5: the engine for the same member, unlocked by its own shares.
    let mut e = Engine::open(
        src.clone(),
        src.listing(),
        Identity::Member(me.clone()),
        EngineOptions::new(&account, DEVICE_KEY),
        None,
        T_NOW04 + 2 * HOUR,
    )
    .unwrap();
    let steps = e.begin_unlock_epochs();
    assert!(!steps.is_empty());
    let answers: Vec<EpochSecret> = steps
        .into_iter()
        .map(|s| EpochSecret {
            shared: EcdhOutput::from_host(&owner.agree(&s.peer).unwrap()).unwrap(),
            step: s,
        })
        .collect();
    e.finish_unlock_epochs(answers).unwrap();
    match e.read_blob("notes", &content).unwrap() {
        BlobRead::Available(b) => assert_eq!(b, [first.as_slice(), &second].concat()),
        other => panic!("the 0.4 blob does not open after the upgrade: {other:?}"),
    }
    // And each chunk through the explicit chunk API.
    match e.open_blob_chunk("notes", &content, 0, &c1).unwrap() {
        Outcome::Success { value, .. } => assert_eq!(value, first),
        o => panic!("{o:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Resumed open (E6 H5, re-attacked).

/// Changed bytes at a covered immutable path across a restart: the open no longer says
/// `Resumed` and names the path, but it does not fail closed. The verified record leaves the
/// view, queries and writes work, and only the background audit poisons the engine once it
/// reaches the path.
#[test]
fn resume_with_changed_covered_bytes_raises_a_source_fault_and_marks_the_path() {
    let w = notes(4);
    let mut e = open_notes(&w, &w.src, None).unwrap();
    assert_eq!(admitted_ids(&e, NOTES).len(), 4);
    let saved = e.save([3; 32]).unwrap();
    let victim = w
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    w.src.put(&victim, b"{}".to_vec());
    let mut r = open_notes(&w, &w.src, Some(&saved)).unwrap();
    assert!(
        matches!(r.open_mode(), OpenMode::Invalidated(_)),
        "{:?}",
        r.open_mode()
    );
    assert_eq!(r.rejudged(), &[victim.clone()]);
    // The host must be shown a fault, naming the path, and the path is marked to be pulled
    // again from a home.
    assert_eq!(r.source_faults().len(), 1);
    assert_eq!(r.source_faults()[0].path, victim);
    assert!(!r.source_faults()[0].what.is_empty());
    assert_eq!(
        admitted_ids(&r, NOTES).len(),
        3,
        "the changed bytes are no record"
    );
    assert!(r.missing_covered().is_empty());
    // The audit catches it when it gets there.
    let mut caught = false;
    for _ in 0..10 {
        if r.verify_batch(1).is_err() {
            caught = true;
            break;
        }
    }
    assert!(caught, "the audit poisons once it reaches the path");
}

/// A namespace part rolled back to an older save, with the checkpoint and verifier current:
/// the older fold is a prefix and is extended; the view equals a cold open.
#[test]
fn rolled_back_namespace_part_equals_a_cold_open() {
    let mut w = notes(3);
    let mut e = open_notes(&w, &w.src, None).unwrap();
    let old = e.save([1; 32]).unwrap();
    write_note(&mut w, 3);
    write_note(&mut w, 4);
    let mut e2 = open_notes(&w, &w.src, None).unwrap();
    let cold = admitted_ids(&e2, NOTES);
    let cold_rev = e2.revision(NOTES);
    let mut newer = e2.save([2; 32]).unwrap();
    newer.parts = old.parts.clone();
    let r = open_notes(&w, &w.src, Some(&newer)).unwrap();
    assert_eq!(admitted_ids(&r, NOTES), cold);
    assert_eq!(r.revision(NOTES), cold_rev);
    // And the newer part with the older checkpoint and verifier, against a folder that holds
    // fewer records than the part folded: the part is not used.
    let src_old = MemSource::versioned();
    src_old.store_account(&w.f.account);
    for rec in w.writer.records().iter().take(3) {
        src_old.put(&rec.path, rec.bytes.clone());
    }
    let mut mixed = old.clone();
    mixed.parts = e2.save([4; 32]).unwrap().parts;
    let m = open_notes(&w, &src_old, Some(&mixed)).unwrap();
    let c = open_notes(&w, &src_old, None).unwrap();
    assert_eq!(admitted_ids(&m, NOTES), admitted_ids(&c, NOTES));
    assert_eq!(admitted_ids(&m, NOTES).len(), 3);
}

/// A part sealed for one namespace cannot be presented as another's, and a part from another
/// identity of the same account is refused by the seal.
#[test]
fn parts_cannot_be_swapped_between_namespaces_or_identities() {
    let w = notes(3);
    let mut e = open_notes(&w, &w.src, None).unwrap();
    let mut s = e.save([1; 32]).unwrap();
    let part = s.parts.remove(NOTES).unwrap();
    s.parts.insert("reading.saved".into(), part);
    let r = open_notes(&w, &w.src, Some(&s)).unwrap();
    assert!(matches!(r.open_mode(), OpenMode::Invalidated(_)));
    assert_eq!(admitted_ids(&r, NOTES).len(), 3);
}

// ---------------------------------------------------------------------------------------------
// S-H3: the pending feed has no page bound per pass. Strictly increasing seqs do not bound it:
// a home that answers every page with one object (any bytes) under the next seq and
// `more: true` keeps one pass going for ever (the change feed has 64 pages; this feed none).

struct EndlessPending {
    sim: SimHome,
    pages: u64,
}
impl Wire for EndlessPending {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        let path = req
            .url
            .strip_prefix("https://home.example")
            .unwrap()
            .to_string();
        if req.method == Method::Get && path.starts_with("/pending?") {
            self.pages += 1;
            let after: u64 = path
                .split('&')
                .find_map(|kv| {
                    kv.strip_prefix("/pending?after=")
                        .or(kv.strip_prefix("after="))
                })
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&json!({
                    "objects": [{"seq": after + 1, "digest": "00".repeat(32), "kind": "receipt",
                                 "envelope": {"body": "e30=", "signature": STANDARD.encode([0u8; 64])}}],
                    "more": true
                }))
                .unwrap(),
            };
        }
        self.sim.call(host, req, now_ms)
    }
}

#[test]
fn pending_feed_has_a_page_bound_per_pass() {
    let (s, member, now) = synced_notes(1);
    let mut wire = EndlessPending {
        sim: s.sim.clone(),
        pages: 0,
    };
    let src = device_source(&s);
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    e.advance(now).unwrap();
    e.refresh(src.listing()).unwrap();
    let held_before = e.account().objects().pending.len();
    let mut done = false;
    for _ in 0..3_000 {
        match e.exchange_next(&s.home).unwrap() {
            Step::Done => {
                done = true;
                break;
            }
            Step::Request(r) => {
                let a = wire.call(&s.f.host, &r, now);
                let rep = e.exchange_answer(&s.home, r.ticket, a).unwrap();
                for (p, b) in rep.store {
                    src.put(&p, b);
                }
            }
            Step::NeedCall(n) => e.exchange_provide_call(&s.home, n.ticket, b"call").unwrap(),
            Step::Waiting => unreachable!(),
        }
    }
    assert!(done, "the pass ends");
    assert!(
        wire.pages <= u64::from(colophon_core::v05::engine::exchange::MAX_PENDING_PAGES),
        "{} pages",
        wire.pages
    );
    assert!(
        wire.pages >= 100,
        "the bound is a page count, not a refusal to read"
    );
    assert_eq!(
        e.account().objects().pending.len(),
        held_before,
        "junk pages are dropped before the account is asked to hold them (no merge each)"
    );
}

// ---------------------------------------------------------------------------------------------
// S-M (caveatedLive): §11.8 says an uncaveated writer's terms have no `kinds`; the code decides
// per namespace. A member whose terms carry `kinds` on another namespace writes live state, and
// the verifier admits its live-stamped records.

#[test]
fn kinds_on_another_namespace_is_not_caveated_for_live_state() {
    const LISTEN: &str = "listening.podcasts";
    let mut f = create(&[LISTEN, NOTES]);
    let m = f.host.identity(41);
    let t = json!({"records": [
        {"namespace": LISTEN, "access": "write"},
        {"namespace": NOTES, "access": "write", "kinds": ["createNotebook"]}]});
    admit(&mut f, &m, "Phone", "device", t.clone(), t);
    let src = MemSource::new();
    src.store_account(&f.account);
    let now = f.account.now_ms();
    let mut e = member_engine(&f, &f.host, &src, &m, now);
    let seed = f.host.fresh();
    let r = e
        .begin_live_write(
            LISTEN,
            "position",
            json!({"id": "e1", "show": "show", "seconds": 3.0}),
            seed,
        )
        .unwrap();
    assert!(
        r.is_ok(),
        "a writer with `kinds` in its terms writes live state"
    );
    let pending = r.unwrap();
    let step = pending.step();
    let sig = colophon_core::v05::write::SignatureResult {
        signature: f.host.ids[step.signer()].sign(step.body()).to_vec(),
        assertion: None,
    };
    let w = e.finish_live_write(pending, sig).unwrap();
    assert!(!w.stores.is_empty());
    assert!(e.account().live_heads().iter().any(|h| h.author == m));
}

// ---------------------------------------------------------------------------------------------
// S-M (Change::grant): a transition's `grant` is checked at activation by `member_from` only,
// which never applies §9.3's import rules (a device or app; write in every records entry;
// `expires` later than `issued`) nor §9.2's "every granted namespace is declared". An import
// grant to an agent, read-only, with no expiry, is built, receipted, activated and final.

fn home_receipt(f: &Fixture, home: &str, object: &str, at: i64) -> Vec<u8> {
    let body = canonical(&json!({
        "protocol": "colophon/receipt/5", "account": f.account.id().as_str(), "object": object,
        "received": colophon_core::v05::write::format_date(at), "by": home,
    }))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&f.host.ids[home].sign(&body))}))
        .unwrap()
}
fn home_head(f: &Fixture, home: &str, at: i64) -> Vec<u8> {
    let (seq, dg) = f.account.head();
    let body = canonical(&json!({
        "protocol": "colophon/head/5", "account": f.account.id().as_str(),
        "authority": {"seq": seq, "digest": dg}, "by": home,
        "issued": colophon_core::v05::write::format_date(at),
    }))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&f.host.ids[home].sign(&body))}))
        .unwrap()
}

#[test]
fn an_import_grant_by_transition_follows_the_import_rules() {
    use colophon_core::v05::account::Change;
    use colophon_core::v05::write::authority::TransitionRule;
    let mut f = create(&[NOTES]);
    let _home = appoint_home(&mut f);
    let agent = f.host.identity(42);
    let now = f.account.now_ms();
    let asked = terms_for(&[(NOTES, "read")]);
    // An agent; read only; no expiry; `import`.
    let granted = json!({"records": [{"namespace": NOTES, "access": "read"}], "import": true});
    let req = request_for(&f, &f.host, &agent, "Agent", "agent", asked, now);
    let change = Change::grant(&req.raw, granted);
    // The builder applies the rules an immediate grant follows (§9.3): an import grant goes to
    // a device or app, with write in every records entry and an expiry later than `issued`.
    let r = f.account.begin_transition(
        &change,
        &[f.d.clone(), f.k.clone()],
        TransitionRule::Control,
    );
    assert!(
        r.is_err(),
        "an import grant to an agent, read-only, without expiry is refused"
    );
    // A device with write access and `import`, still without an expiry, is refused too.
    let device = f.host.identity(43);
    let req = request_for(
        &f,
        &f.host,
        &device,
        "Importer",
        "device",
        terms_for(&[(NOTES, "write")]),
        now,
    );
    let t = json!({"records": [{"namespace": NOTES, "access": "write"}], "import": true});
    assert!(
        f.account
            .begin_transition(
                &Change::grant(&req.raw, t),
                &[f.d.clone(), f.k.clone()],
                TransitionRule::Control
            )
            .is_err(),
        "an import grant without an expiry is refused"
    );
}

// ---------------------------------------------------------------------------------------------
// Hostile answers: random statuses and bodies on every request of 40 passes. No panic, no
// error from the engine's own API, no pass longer than the bound, and the verified head and
// view are unchanged.

#[test]
fn random_answers_never_panic_or_move_verified_state() {
    let (s, member, now) = synced_notes(2);
    let src = device_source(&s);
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    let head = e.account().head();
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let bodies: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"null".to_vec(),
        b"{".to_vec(),
        serde_json::to_vec(&json!({"entries": "x", "more": true})).unwrap(),
        serde_json::to_vec(&json!({"entries": [{"path": "ops/x", "sha256": 7}], "cursor": [], "more": true})).unwrap(),
        serde_json::to_vec(&json!({"objects": [{"seq": u64::MAX, "envelope": {"body": "!!"}}], "more": true})).unwrap(),
        serde_json::to_vec(&json!({"entries": [{"body": "e30=", "signature": ""}], "receipts": [1, 2], "more": true})).unwrap(),
        "[".repeat(10_000).into_bytes(),
        serde_json::to_vec(&json!({"head": {"body": "e30=", "signature": "AA=="}, "receipts": [{}]})).unwrap(),
        vec![0xff; 70_000],
    ];
    for pass in 0..40 {
        e.advance(now + pass).unwrap();
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 20_000, "a pass did not end");
            match e.exchange_next(&s.home).unwrap() {
                Step::Done => break,
                Step::Request(r) => {
                    let statuses = [200u16, 200, 200, 404, 401, 409, 410, 412, 421, 422, 500];
                    let status = statuses[(next() % statuses.len() as u64) as usize];
                    let body = bodies[(next() % bodies.len() as u64) as usize].clone();
                    let rep = e
                        .exchange_answer(
                            &s.home,
                            r.ticket,
                            Response {
                                status,
                                headers: vec![],
                                body,
                            },
                        )
                        .unwrap();
                    for (p, b) in rep.store {
                        src.put(&p, b);
                    }
                }
                Step::NeedCall(n) => e.exchange_provide_call(&s.home, n.ticket, b"c").unwrap(),
                Step::Waiting => unreachable!(),
            }
        }
    }
    assert_eq!(e.account().head(), head);
    assert_eq!(
        admitted_ids(&e, NOTES).len(),
        0,
        "nothing hostile was admitted"
    );
}

// ---------------------------------------------------------------------------------------------
// M2: when the remembered remote set is full, change-feed entries are not skipped while the
// cursor moves past them: the pass says so (`More`, feed `remote`) and the cursor stays.

/// A home whose change feed lists `total` distinct blob chunks, 1,000 an entry page, under a
/// cursor that is the index of the next entry.
struct FloodHome {
    sim: SimHome,
    total: usize,
    after_seen: Vec<String>,
}
impl Wire for FloodHome {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        let path = req
            .url
            .strip_prefix("https://home.example")
            .unwrap()
            .to_string();
        if req.method == Method::Get && path.starts_with("/changes") {
            let after: usize = path
                .split('&')
                .find_map(|kv| kv.strip_prefix("after="))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            self.after_seen.push(after.to_string());
            let end = (after + 1_000).min(self.total);
            let entries: Vec<Value> = (after..end)
                .map(|i| {
                    json!({"path": format!("blobs/{}", sha_hex(format!("chunk {i}").as_bytes())),
                           "size": 10, "sha256": sha_hex(format!("chunk {i}").as_bytes())})
                })
                .collect();
            return Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(
                    &json!({"entries": entries, "cursor": end.to_string(), "more": end < self.total}),
                )
                .unwrap(),
            };
        }
        self.sim.call(host, req, now_ms)
    }
}

#[test]
fn a_full_remote_set_is_reported_and_the_cursor_does_not_pass_what_could_not_be_kept() {
    let (s, member, now) = synced_notes(1);
    let total = colophon_core::v05::engine::MAX_LISTING + 5_000;
    let mut wire = FloodHome {
        sim: s.sim.clone(),
        total,
        after_seen: Vec::new(),
    };
    let src = device_source(&s);
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    let mut overflow_at = None;
    for pass in 0..14 {
        let faults = sync_pass(&mut e, &src, &s.home, &mut wire, &s.f.host, now + pass);
        if faults
            .iter()
            .any(|f| matches!(f, Fault::More { feed, .. } if feed == "remote"))
        {
            overflow_at = Some(pass);
            break;
        }
    }
    assert!(
        overflow_at.is_some(),
        "the full set is reported, not skipped silently"
    );
    // Another pass reads the page that overflowed again: the cursor did not move past it.
    let seen = wire.after_seen.len();
    let overflowed = wire.after_seen.last().cloned().unwrap();
    let faults = sync_pass(&mut e, &src, &s.home, &mut wire, &s.f.host, now + 99);
    assert!(faults
        .iter()
        .any(|f| matches!(f, Fault::More { feed, .. } if feed == "remote")));
    assert_eq!(
        wire.after_seen[seen], overflowed,
        "the next pass reads the page that overflowed again"
    );
}

// ---------------------------------------------------------------------------------------------
// H1, as a property: the fast write's chain tip equals the full rule (`chain_heads` over the
// verified headers) whatever keyless noise is held, over several random histories.

#[test]
fn the_write_index_tip_equals_the_full_chain_rule_over_planted_noise() {
    use colophon_core::v05::records::{chain_heads, verified_headers, RecordAuthority};
    let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..6 {
        let mut w = notes(2 + (next() % 4) as usize);
        // Noise: headers by unknown authors naming real digests and random ones, in several
        // namespaces, and a header by the member itself with a zero signature.
        for k in 0..(3 + next() % 8) {
            let like =
                w.writer.records()[(next() % w.writer.records().len() as u64) as usize].clone();
            let named = if next() % 2 == 0 {
                body_digest(&like.bytes)
            } else {
                sha_hex(format!("noise {round} {k}").as_bytes())
            };
            let mut p = planted_naming(&mut w, &like, &named);
            if next() % 3 == 0 {
                let mut b = body_of(&p.bytes);
                b["author"] = json!(w.member);
                p = HeldRecord {
                    path: op_path(&b),
                    bytes: unsigned(&b),
                };
            }
            let now = w.writer.now_ms();
            w.writer
                .merge(
                    Incoming {
                        objects: Objects::default(),
                        records: vec![p],
                    },
                    now,
                )
                .unwrap();
        }
        let auth = RecordAuthority::from_objects(w.writer.objects(), w.writer.now_ms()).unwrap();
        let headers = verified_headers(&auth, w.writer.records());
        let expected = chain_heads(&headers, &w.member, NOTES);
        assert_eq!(expected.len(), 1);
        let next_rec = write_note(&mut w, 100 + round);
        assert_eq!(
            body_of(&next_rec.bytes)["previous"],
            json!(expected[0]),
            "round {round}"
        );
    }
}
