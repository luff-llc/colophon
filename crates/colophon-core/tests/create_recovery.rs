//! Creating a library with a recovery-kit controller in genesis, and opening its vault with the kit.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod support;

use colophon_core::{
    authority::Role,
    crypto::SoftwareKeys,
    library::{CreateOptions, Library, PendingBatch, RecoveryController},
    slots::{OpeningInput, OpeningSecret},
};
use support::{keys, NOW};

fn sign(pending: &PendingBatch, member: &SoftwareKeys, controller: &SoftwareKeys) -> Vec<Vec<u8>> {
    pending
        .steps
        .iter()
        .map(|s| {
            if s.signing == controller.public().signing {
                controller.sign(&s.body)
            } else {
                member.sign(&s.body)
            }
        })
        .collect()
}

#[test]
fn genesis_carries_the_kit_as_a_recover_controller_that_opens_the_vault() {
    let member = keys(1);
    let owner = keys(201);
    let kit = SoftwareKeys::recovery([77; 32]).unwrap();
    let pending = Library::begin_create(
        CreateOptions {
            owner: owner.public(),
            member: member.public(),
            vault_seed: [202; 32],
            import_expires: None,
            recovery: Some(RecoveryController {
                identity: kit.public(),
                label: "Recovery Kit".into(),
            }),
            imported_from: Some("0123456789abcdef0123456789abcdef".into()),
            label: "Kit Library".into(),
            owner_label: "Owner".into(),
            namespaces: vec!["notes".into()],
        },
        NOW,
        [10; 32],
    )
    .unwrap();
    let first = sign(&pending, &member, &owner);
    let next = pending.advance_create(first).unwrap();
    let second = sign(&next, &member, &owner);
    let records = next.finish(second).unwrap();
    let mut library = Library::open(records, kit.public()).unwrap();

    let keyring = library.authority().keyring.clone();
    assert_eq!(keyring.controllers.len(), 2);
    assert_eq!(keyring.threshold, 1);
    assert_eq!(keyring.recover_threshold, 1);
    let kit_id = colophon_core::records::id(&kit.public().signing);
    let kit_controller = keyring.controller(&kit_id).expect("kit controller");
    assert_eq!(kit_controller.roles, vec![Role::Recover]);

    let index = keyring
        .slots
        .iter()
        .position(|slot| slot.controllers() == [kit_id.clone()])
        .expect("kit slot");
    let enc = match library.begin_unlock_slot(index).unwrap().as_slice() {
        [OpeningInput::Ecdh { enc, .. }] => enc.to_vec(),
        other => panic!("unexpected opening inputs: {}", other.len()),
    };
    let shared = kit.agree(&enc).unwrap();
    library
        .finish_unlock_slot(index, &[OpeningSecret::Ecdh(&shared)])
        .unwrap();
}

#[test]
fn a_kit_sharing_the_owner_key_is_refused() {
    let member = keys(1);
    let owner = keys(201);
    let refused = Library::begin_create(
        CreateOptions {
            owner: owner.public(),
            member: member.public(),
            vault_seed: [202; 32],
            import_expires: None,
            recovery: Some(RecoveryController {
                identity: owner.public(),
                label: "Same key".into(),
            }),
            imported_from: None,
            label: "Bad".into(),
            owner_label: "Owner".into(),
            namespaces: vec!["notes".into()],
        },
        NOW,
        [10; 32],
    );
    assert!(refused.is_err());
}
