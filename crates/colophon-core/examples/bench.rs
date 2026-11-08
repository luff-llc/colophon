//! Deterministic, fully signed engine benchmark; no benchmark framework or new dependencies.
#![allow(clippy::unwrap_used)]
#[path = "../tests/support/mod.rs"]
mod support;
use colophon_core::{
    crypto::SoftwareKeys,
    domain::{DomainModule, ListeningPodcasts},
    library::{operation_path, Library},
    model::{MemberKind, Operation, OperationHeader, OperationMeta, Records},
    records::{canonical, SignedRecord},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Instant,
};
use support::*;

#[allow(clippy::too_many_arguments)]
fn operation(
    lib: &Library,
    signer: &SoftwareKeys,
    key: &[u8],
    ns: &str,
    kind: &str,
    payload: serde_json::Value,
    clock: u64,
) -> Records {
    let mut nonce = vec![0; 12];
    nonce[4..].copy_from_slice(&clock.to_be_bytes());
    let mut op = Operation {
        id: String::new(),
        kind: kind.into(),
        v: 1,
        clock,
        authority: lib.authority().latest,
        created: NOW.into(),
        payload,
    };
    op.id = colophon_core::records::id(&canonical(&json!({"purpose":colophon_core::protocol::OPERATION_ID,"namespace":ns,"author":signer.public().id(),"epoch":1,"nonce":nonce,"operation":op})).unwrap());
    let meta = OperationMeta {
        protocol: colophon_core::protocol::OPERATION.into(),
        library: lib.id().into(),
        namespace: ns.into(),
        author: signer.public().id(),
        epoch: 1,
        id: op.id.clone(),
        clock,
        authority: op.authority,
        created: NOW.into(),
    };
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes256Gcm, KeyInit, Nonce,
    };
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &canonical(&op).unwrap(),
                aad: &canonical(&meta).unwrap(),
            },
        )
        .unwrap();
    let path = operation_path(&meta);
    let body = canonical(&OperationHeader {
        meta,
        nonce,
        ciphertext,
        live: None,
    })
    .unwrap();
    let signature = signer.sign(&body);
    // Benchmark fixture only: the normal engine verifies this on ingest.
    Records::from([(path, SignedRecord { body, signature }.encode().unwrap())])
}
fn generate(count: usize) -> Records {
    assert!(count >= 100);
    let owner = keys(1);
    let pending = Library::begin_create(
        colophon_core::library::CreateOptions {
            owner: keys(201).public(),
            member: owner.public(),
            vault_seed: [202; 32],
            import_expires: None,
            recovery: None,
            imported_from: None,
            label: "Four-domain benchmark".into(),
            owner_label: "Owner".into(),
            namespaces: colophon_core::domain::NAMESPACES
                .iter()
                .map(|ns| (*ns).into())
                .collect(),
        },
        NOW,
        [10; 32],
    )
    .unwrap();
    let mut root = opened(finish(pending, &owner), &owner);
    let members = [keys(2), keys(3), keys(4)];
    for (i, member) in members.iter().enumerate() {
        enroll(
            &mut root,
            &owner,
            member,
            &format!("Member {i}"),
            MemberKind::Device,
            grant(&colophon_core::domain::NAMESPACES, None),
            40 + i as u8,
        );
    }
    let material: BTreeMap<_, _> = root
        .authority()
        .namespaces
        .iter()
        .map(|ns| {
            let seal = &root.authority().epochs[ns][&1].1.seals[&owner.public().id()];
            let key = seal
                .finish_open(
                    &owner.public().agreement,
                    &owner.agree(&seal.enc).unwrap(),
                    &root.authority().key_info(ns, 1, &owner.public().id()),
                )
                .unwrap();
            (ns.clone(), key)
        })
        .collect();
    let mut records = Records::new();
    for i in 0..count {
        let (ns, kind, payload) = if i == 0 {
            (
                "notes",
                "createNotebook",
                json!({"id":"journal","title":"Journal"}),
            )
        } else if i == 1 {
            (
                "notes",
                "addNote",
                json!({"id":"daily","notebook":"journal","text":"First entry"}),
            )
        } else if i == 2 {
            (
                "reading.books",
                "addBook",
                json!({"id":"book","title":"Benchmark book","creator":"Writer"}),
            )
        } else if i % 100 == 0 {
            (
                "reading.books",
                "position",
                json!({"id":"book","fraction": (i % 1000) as f64 / 1000.0}),
            )
        } else if i % 50 == 0 {
            (
                "notes",
                "editNote",
                json!({"id":"daily","notebook":"journal","text":format!("Entry {i}")}),
            )
        } else if i % 20 == 0 {
            (
                "reading.saved",
                "capture",
                json!({"id":format!("link{i}"),"url":format!("https://example.org/{i}"),"title":format!("Article {i}")}),
            )
        } else if i % 10 == 0 {
            (
                "listening.podcasts",
                "episode",
                json!({"id":format!("ep{}",i%1000),"title":format!("Episode {i}"),"show":"show"}),
            )
        } else {
            (
                "listening.podcasts",
                "position",
                json!({"id":format!("ep{}",i%1000),"seconds":i}),
            )
        };
        let signer = if i % 4 == 0 {
            &owner
        } else {
            &members[i % 4 - 1]
        };
        records.extend(operation(
            &root,
            signer,
            &material[ns],
            ns,
            kind,
            payload,
            i as u64 + 1,
        ));
        if (i + 1) % 10_000 == 0 {
            eprintln!("Generated {} / {count}", i + 1);
        }
    }
    root.merge(records).unwrap();
    let revoke = success(
        root.begin_revoke(&members[2].public().id(), NOW, [99; 32])
            .unwrap(),
    );
    apply(&mut root, revoke, &owner);
    root.records().clone()
}
fn save(path: &Path, records: &Records) {
    let mut file = File::create(path).unwrap();
    file.write_all(&(records.len() as u64).to_le_bytes())
        .unwrap();
    for (path, bytes) in records {
        file.write_all(&(path.len() as u64).to_le_bytes()).unwrap();
        file.write_all(path.as_bytes()).unwrap();
        file.write_all(&(bytes.len() as u64).to_le_bytes()).unwrap();
        file.write_all(bytes).unwrap();
    }
}
fn load(path: &Path) -> Records {
    fn length(file: &mut File) -> usize {
        let mut bytes = [0; 8];
        file.read_exact(&mut bytes).unwrap();
        u64::from_le_bytes(bytes) as usize
    }
    let mut file = File::open(path).unwrap();
    let mut records = Records::new();
    for _ in 0..length(&mut file) {
        let mut path = vec![0; length(&mut file)];
        file.read_exact(&mut path).unwrap();
        let mut bytes = vec![0; length(&mut file)];
        file.read_exact(&mut bytes).unwrap();
        records.insert(String::from_utf8(path).unwrap(), bytes);
    }
    records
}
fn unlock_all(lib: &mut Library, owner: &SoftwareKeys) {
    let results = lib
        .begin_unlock()
        .into_iter()
        .map(|step| {
            let shared = owner.agree(&step.peer).unwrap();
            (step.namespace, step.epoch, shared)
        })
        .collect();
    lib.finish_unlock_many(results).unwrap();
}
fn report(label: &str, started: Instant) {
    println!(
        "{label}: {:.3} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(100_000);
    let fixture = args.get(2).map(Path::new);
    let records = if let Some(path) = fixture.filter(|p| p.exists()) {
        load(path)
    } else {
        let started = Instant::now();
        let records = generate(count);
        report("fixture generation (excluded)", started);
        if let Some(path) = fixture {
            save(path, &records);
        }
        records
    };
    assert_eq!(
        records.keys().filter(|p| p.starts_with("ops/")).count(),
        count
    );
    println!(
        "operations: {count}; record bytes: {}",
        records.values().map(Vec::len).sum::<usize>()
    );
    let owner = keys(1);
    let input = records.clone();
    let started = Instant::now();
    let mut root = Library::open(input, owner.public()).unwrap();
    report("full rebuild / verify and header admission", started);
    let decrypt = Instant::now();
    unlock_all(&mut root, &owner);
    report("full rebuild / unlock, decrypt, reduce", decrypt);
    report("full rebuild total", started);
    let started = Instant::now();
    let checkpoints: BTreeMap<_, _> = root
        .authority()
        .namespaces
        .iter()
        .map(|ns| (ns.clone(), root.checkpoint(ns).unwrap()))
        .collect();
    report("serialize checkpoints", started);
    println!(
        "checkpoint bytes: {}",
        checkpoints.values().map(Vec::len).sum::<usize>()
    );
    // Isolate domain replay cost from signature verification, admission, and decrypt/ID validation.
    let view = success(root.view("listening.podcasts", NOW).unwrap());
    let started = Instant::now();
    let projected = ListeningPodcasts.fold(&view.admitted);
    report("podcast reducer replay", started);
    assert_eq!(projected, view.state);
    drop(projected);
    drop(view);
    let started = Instant::now();
    for (ns, bytes) in &checkpoints {
        assert!(root.restore_checkpoint(ns, bytes).unwrap());
    }
    report(
        "warm checkpoint restore (already verified and decrypted)",
        started,
    );
    if args.iter().any(|arg| arg == "--profile") {
        for ns in ["reading.saved", "reading.books", "notes"] {
            let view = success(root.view(ns, NOW).unwrap());
            let started = Instant::now();
            let state = colophon_core::domain::module(ns)
                .unwrap()
                .fold(&view.admitted);
            report(&format!("{ns} reducer replay"), started);
            assert_eq!(state, view.state);
        }
        profile(&root, &owner);
    }
    let before = root.applied_operations("listening.podcasts");
    let started = Instant::now();
    let pending = success(
        root.begin_write(
            "listening.podcasts",
            "position",
            json!({"id":"ep1","seconds":count+1}),
            NOW,
            [111; 32],
        )
        .unwrap(),
    );
    let signatures = pending.steps.iter().map(|s| owner.sign(&s.body)).collect();
    root.finish_with_changes(pending, signatures).unwrap();
    report("single local write incl sign and merge", started);
    println!(
        "local write reducer applications: {}",
        root.applied_operations("listening.podcasts") - before
    );
    let started = Instant::now();
    let pending = success(
        root.begin_write(
            "notes",
            "editNote",
            json!({"id":"daily","notebook":"journal","text":"Quiet namespace write"}),
            NOW,
            [113; 32],
        )
        .unwrap(),
    );
    let signatures = pending.steps.iter().map(|s| owner.sign(&s.body)).collect();
    root.finish_with_changes(pending, signatures).unwrap();
    report("single local write to quieter namespace", started);
    let started = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(
            root.query("listening.podcasts", "getEpisode", json!({"id":"ep1"}), NOW)
                .unwrap(),
        );
    }
    report("1000 single episode queries", started);
    let inserted = adversarial(
        &root,
        &owner,
        &owner,
        "listening.podcasts",
        op(
            "position",
            2,
            5,
            json!({"id":"ep1","seconds":0,"seek":true}),
        ),
        1,
        112,
    );
    let started = Instant::now();
    root.merge(inserted).unwrap();
    report("out-of-order insert near start", started);
    drop(root);
    let input = records.clone();
    let started = Instant::now();
    let mut cold = Library::open_with_checkpoints(input, owner.public(), checkpoints).unwrap();
    report(
        "cold checkpoint open / verify and header admission",
        started,
    );
    let unlock_started = Instant::now();
    unlock_all(&mut cold, &owner);
    report("cold checkpoint open / unlock and restore", unlock_started);
    report("cold checkpoint open total", started);
    println!(
        "cold reducer applications: {}",
        cold.authority()
            .namespaces
            .iter()
            .map(|ns| cold.applied_operations(ns))
            .sum::<u64>()
    );
}

fn profile(lib: &Library, owner: &SoftwareKeys) {
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes256Gcm, KeyInit, Nonce,
    };
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let sample: Vec<_> = lib
        .records()
        .iter()
        .filter(|(p, _)| p.starts_with("ops/"))
        .take(2000)
        .map(|(_, raw)| {
            let record: SignedRecord = serde_json::from_slice(raw).unwrap();
            let header: OperationHeader = serde_json::from_slice(&record.body).unwrap();
            (raw, record, header)
        })
        .collect();
    let started = Instant::now();
    for (raw, _, _) in &sample {
        let record: SignedRecord = serde_json::from_slice(raw).unwrap();
        std::hint::black_box(serde_json::from_slice::<OperationHeader>(&record.body).unwrap());
    }
    report(
        "profile 2000 / envelope + header JSON/base64 parse",
        started,
    );
    let verifiers: BTreeMap<_, _> = lib
        .authority()
        .members
        .iter()
        .map(|(id, m)| {
            (
                id,
                VerifyingKey::from_sec1_bytes(&m.public.signing).unwrap(),
            )
        })
        .collect();
    let started = Instant::now();
    for (_, record, header) in &sample {
        verifiers[&header.meta.author]
            .verify(
                &record.body,
                &Signature::from_slice(&record.signature).unwrap(),
            )
            .unwrap();
    }
    report("profile 2000 / P-256 signature verification only", started);
    let ciphers: BTreeMap<_, _> = lib
        .authority()
        .namespaces
        .iter()
        .map(|ns| {
            let seal = &lib.authority().epochs[ns][&1].1.seals[&owner.public().id()];
            let key = seal
                .finish_open(
                    &owner.public().agreement,
                    &owner.agree(&seal.enc).unwrap(),
                    &lib.authority().key_info(ns, 1, &owner.public().id()),
                )
                .unwrap();
            (ns, Aes256Gcm::new_from_slice(&key).unwrap())
        })
        .collect();
    let aad: Vec<_> = sample
        .iter()
        .map(|(_, _, h)| canonical(&h.meta).unwrap())
        .collect();
    let started = Instant::now();
    let plaintexts: Vec<_> = sample
        .iter()
        .zip(&aad)
        .map(|((_, _, header), aad)| {
            ciphers[&header.meta.namespace]
                .decrypt(
                    Nonce::from_slice(&header.nonce),
                    Payload {
                        msg: &header.ciphertext,
                        aad,
                    },
                )
                .unwrap()
        })
        .collect();
    report("profile 2000 / AES-GCM decrypt only", started);
    let started = Instant::now();
    for plain in &plaintexts {
        std::hint::black_box(serde_json::from_slice::<Operation>(plain).unwrap());
    }
    report("profile 2000 / plaintext JSON parse only", started);
}
