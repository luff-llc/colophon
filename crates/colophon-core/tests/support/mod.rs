#![allow(clippy::unwrap_used, dead_code)]
use colophon_core::{
    crypto::{PublicIdentity, SoftwareKeys},
    library::{CreateOptions, Library, PendingBatch},
    model::*,
    records::{canonical, SignedRecord},
};
use serde_json::Value;
pub const NOW: &str = "2026-11-04T12:00:00.000Z";
pub const LATER: &str = "2026-11-04T12:01:00.000Z";
pub fn keys(n: u8) -> SoftwareKeys {
    SoftwareKeys::from_seed([n; 32]).unwrap()
}
pub fn success<T: std::fmt::Debug>(outcome: Outcome<T>) -> T {
    match outcome {
        Outcome::Success { value, .. } => value,
        other => panic!("Expected success: {other:?}"),
    }
}
pub fn finish(pending: PendingBatch, key: &SoftwareKeys) -> Records {
    let sign = |p: &PendingBatch| {
        p.steps
            .iter()
            .map(|s| {
                if s.signing == keys(201).public().signing {
                    keys(201).sign(&s.body)
                } else {
                    key.sign(&s.body)
                }
            })
            .collect()
    };
    let sigs = sign(&pending);
    if pending
        .steps
        .iter()
        .any(|s| s.path == "authority/00000001.json")
    {
        let next = pending.advance_create(sigs).unwrap();
        let sigs = sign(&next);
        next.finish(sigs).unwrap()
    } else {
        pending.finish(sigs).unwrap()
    }
}
pub fn apply(lib: &mut Library, pending: PendingBatch, keys: &SoftwareKeys) {
    lib.merge(finish(pending, keys)).unwrap();
    unlock(lib, keys);
}
pub fn unlock(lib: &mut Library, keys: &SoftwareKeys) {
    for step in lib.begin_unlock() {
        lib.finish_unlock(
            &step.namespace,
            step.epoch,
            &keys.agree(&step.peer).unwrap(),
        )
        .unwrap();
    }
}
pub fn opened(records: Records, keys: &SoftwareKeys) -> Library {
    let mut lib = Library::open(records, keys.public()).unwrap();
    unlock(&mut lib, keys);
    if matches!(keys.public().id().as_str(),id if id==self::keys(1).public().id() || id==self::keys(5).public().id())
    {
        lib.select_controller(&self::keys(201).public().id())
            .unwrap();
        let secret = match &lib.begin_unlock_slot(0).unwrap()[0] {
            colophon_core::slots::OpeningInput::Ecdh { enc, .. } => {
                self::keys(201).agree(enc).unwrap()
            }
            _ => panic!("expected sealed owner slot"),
        };
        lib.finish_unlock_slot(0, &[colophon_core::slots::OpeningSecret::Ecdh(&secret)])
            .unwrap();
    }
    lib
}
pub fn create() -> (Library, SoftwareKeys, SoftwareKeys) {
    create_importing(false)
}
pub fn create_importing(importing: bool) -> (Library, SoftwareKeys, SoftwareKeys) {
    let owner = keys(1);
    let controller = keys(201);
    let pending = Library::begin_create(
        CreateOptions {
            owner: keys(201).public(),
            member: owner.public(),
            vault_seed: [202; 32],
            import_expires: importing.then(|| "2027-01-01T00:00:00Z".into()),
            label: "Conformance Library".into(),
            owner_label: "Owner".into(),
            namespaces: vec![
                "reading.saved".into(),
                "listening.podcasts".into(),
                "notes".into(),
            ],
        },
        NOW,
        [10; 32],
    )
    .unwrap();
    (opened(finish(pending, &owner), &owner), owner, controller)
}
pub fn request(
    lib: &Library,
    member: &SoftwareKeys,
    label: &str,
    kind: MemberKind,
    namespaces: Vec<String>,
) -> Vec<u8> {
    let p = Library::begin_request(Request {
        protocol: colophon_core::protocol::REQUEST.into(),
        library_id: lib.id().into(),
        member: member.public(),
        label: label.into(),
        kind,
        namespaces,
        access: vec![Access::Read, Access::Write],
        created: NOW.into(),
    })
    .unwrap();
    finish(p, member).into_values().next().unwrap()
}
pub fn enroll(
    lib: &mut Library,
    owner: &SoftwareKeys,
    member: &SoftwareKeys,
    label: &str,
    kind: MemberKind,
    grant: Grant,
    seed: u8,
) {
    let request = request(lib, member, label, kind, lib.authority().namespaces.clone());
    lib.merge(Records::from([(
        format!("requests/{}.json", member.public().id()),
        request.clone(),
    )]))
    .unwrap();
    let pending = success(
        lib.begin_approve(request, Some(grant), NOW, [seed; 32])
            .unwrap(),
    );
    apply(lib, pending, owner);
}
pub fn grant(namespaces: &[&str], budget: Option<u64>) -> Grant {
    Grant {
        namespaces: namespaces.iter().map(|n| (*n).into()).collect(),
        access: vec![Access::Read, Access::Write],
        expires: None,
        write_budget: budget,
        import: None,
    }
}
pub fn write(
    lib: &mut Library,
    keys: &SoftwareKeys,
    ns: &str,
    kind: &str,
    payload: Value,
    seed: u8,
) {
    let pending = success(lib.begin_write(ns, kind, payload, NOW, [seed; 32]).unwrap());
    apply(lib, pending, keys);
}
/// An adversarial wire writer deliberately bypassing the honest host's admission guard.
/// Encryption material is supplied by the fixture owner, never a public SDK backdoor.
pub fn adversarial(
    lib: &Library,
    material_owner: &SoftwareKeys,
    signer: &SoftwareKeys,
    ns: &str,
    operation: Operation,
    epoch: u64,
    seed: u8,
) -> Records {
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes256Gcm, KeyInit, Nonce,
    };
    let state = lib.authority();
    let sealed = &state.epochs[ns][&epoch].1.seals[&material_owner.public().id()];
    let key = sealed
        .finish_open(
            &material_owner.public().agreement,
            &material_owner.agree(&sealed.enc).unwrap(),
            &state.key_info(ns, epoch, &material_owner.public().id()),
        )
        .unwrap();
    let mut op = operation;
    op.id.clear();
    let nonce = vec![seed; 12];
    op.id = colophon_core::records::id(&canonical(&serde_json::json!({"purpose":colophon_core::protocol::OPERATION_ID,"namespace":ns,"author":signer.public().id(),"epoch":epoch,"nonce":nonce,"operation":op})).unwrap());
    let meta = OperationMeta {
        protocol: colophon_core::protocol::OPERATION.into(),
        library: lib.id().into(),
        namespace: ns.into(),
        author: signer.public().id(),
        epoch,
        id: op.id.clone(),
        clock: op.clock,
        authority: op.authority,
        created: op.created.clone(),
    };
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &canonical(&op).unwrap(),
                aad: &canonical(&meta).unwrap(),
            },
        )
        .unwrap();
    let path = colophon_core::library::operation_path(&meta);
    let body = canonical(&OperationHeader {
        meta,
        nonce,
        ciphertext,
        live: None,
    })
    .unwrap();
    let signature = signer.sign(&body);
    let record = SignedRecord::finish_sign(body, signature, &signer.public().signing).unwrap();
    Records::from([(path, record.encode().unwrap())])
}
pub fn op(kind: &str, clock: u64, authority: u64, payload: Value) -> Operation {
    Operation {
        id: String::new(),
        kind: kind.into(),
        v: 1,
        clock,
        authority,
        created: NOW.into(),
        payload,
    }
}
pub fn public_identity(seed: u8) -> PublicIdentity {
    keys(seed).public()
}

pub mod books;

/// Signed passive sample at a chosen clock, independent of the honest writer's anchor policy.
pub fn live_at(lib: &Library, owner: &SoftwareKeys, clock: u64, seconds: u64, seed: u8) -> Records {
    let raw = adversarial(
        lib,
        owner,
        owner,
        "listening.podcasts",
        Operation {
            id: String::new(),
            kind: "position".into(),
            v: 1,
            clock,
            authority: lib.authority().latest,
            created: NOW.into(),
            payload: serde_json::json!({"id":"ep","seconds":seconds}),
        },
        lib.authority()
            .epoch_at("listening.podcasts", lib.authority().latest)
            .unwrap(),
        seed,
    )
    .into_values()
    .next()
    .unwrap();
    let record: SignedRecord = serde_json::from_slice(&raw).unwrap();
    let mut header: OperationHeader = serde_json::from_slice(&record.body).unwrap();
    let slot = colophon_core::protocol::live_slot_name("ep");
    header.live = Some(LiveStamp {
        library_id: lib.id().into(),
        slot: slot.clone(),
        generation: clock,
        operation_id: header.meta.id.clone(),
    });
    let body = canonical(&header).unwrap();
    [(
        colophon_core::protocol::live_state_path(&owner.public().id(), "listening.podcasts", &slot),
        SignedRecord {
            signature: owner.sign(&body),
            body,
        }
        .encode()
        .unwrap(),
    )]
    .into()
}
