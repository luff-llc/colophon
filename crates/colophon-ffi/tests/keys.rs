//! W5 transport journey. Fixed software credentials are public test keys only.
#![allow(clippy::unwrap_used)]
use colophon_core::{
    authority::{Controller, Keyring, Role},
    crypto::SoftwareKeys as SoftwareIdentity,
    keys::{testing::SyntheticAuthenticator, KeyDescriptor},
};
use colophon_ffi::*;
use serde_json::{json, Value};
use std::sync::Arc;
const NOW: &str = "2026-11-08T12:00:00Z";
fn bytes(value: &impl serde::Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn public(key: &SoftwareIdentity) -> PublicKeys {
    let p = key.public();
    PublicKeys {
        signing: p.signing,
        agreement: p.agreement,
    }
}
fn raw(key: &SoftwareIdentity, label: &str, roles: Vec<Role>) -> Controller {
    let p = key.public();
    Controller {
        key: KeyDescriptor::Raw {
            signing: p.signing,
            agreement: Some(p.agreement),
        },
        label: label.into(),
        roles,
        verification: None,
    }
}
fn sign(
    action: &HostAction,
    keys: &[&SoftwareIdentity],
    auth: &SyntheticAuthenticator,
) -> (Vec<SignatureResult>, Value) {
    let mut fixture = Vec::new();
    let results = action.signing_steps().into_iter().map(|step| {
        let result = if step.form == KeyForm::Webauthn {
            let assertion = auth.assertion(&step.body, "id.luff.works", "https://id.luff.works", 5, true).unwrap();
            let a = WebauthnResult { signature: assertion.signature, authenticator_data: assertion.assertion.authenticator_data, client_data: assertion.assertion.client_data, prf: None };
            SignatureResult { signature: a.signature.clone(), assertion: Some(a) }
        } else {
            let key = keys.iter().find(|k| k.public().signing == step.signing_key).unwrap();
            SignatureResult { signature: key.sign(&step.body), assertion: None }
        };
        fixture.push(json!({"body":step.body,"signature":result.signature,"assertion":result.assertion.as_ref().map(|a| json!({"signature":a.signature,"authenticatorData":a.authenticator_data,"clientData":a.client_data}))}));
        result
    }).collect();
    (results, json!(fixture))
}
fn commit(
    lib: &NativeLibrary,
    action: Arc<HostAction>,
    keys: &[&SoftwareIdentity],
    auth: &SyntheticAuthenticator,
    fixture: &mut Vec<Value>,
    name: &str,
) {
    let (results, signed) = sign(&action, keys, auth);
    lib.finish_authority(action, results).unwrap();
    fixture.push(json!({"name":name,"signing":signed}));
}
fn unlock(lib: &NativeLibrary, key: &SoftwareIdentity) -> Vec<Vec<u8>> {
    let option = lib.begin_unlock_slots().unwrap().into_iter().find(|o| o.inputs.iter().all(|input| matches!(input, SlotInput::Ecdh { controller, .. } if controller == &key.public().id()))).unwrap();
    let secrets: Vec<Vec<u8>> = option
        .inputs
        .iter()
        .map(|input| match input {
            SlotInput::Ecdh { enc, .. } => key.agree(enc).unwrap(),
            _ => panic!("not ECDH"),
        })
        .collect();
    lib.finish_unlock_slot(
        option,
        secrets
            .iter()
            .map(|secret| SlotSecret::Ecdh {
                secret: secret.clone(),
            })
            .collect(),
    )
    .unwrap();
    secrets
}
fn prf_slot(
    lib: &NativeLibrary,
    key: &KeyDescriptor,
    auth: &SyntheticAuthenticator,
    new_seed: Option<Vec<u8>>,
    entropy: u8,
    fixture: &mut Vec<Value>,
) -> Vec<u8> {
    let action = lib.begin_prf_slot(bytes(key), vec![entropy; 32]).unwrap();
    // The authenticator signs the fresh challenge, not registration clientData.
    let client = bytes(
        &json!({"type":"webauthn.get","challenge":action.challenge(),"origin":"https://id.luff.works"}),
    );
    let template = auth
        .assertion(
            b"unused",
            "id.luff.works",
            "https://id.luff.works",
            5,
            false,
        )
        .unwrap();
    let signed = auth
        .sign_bytes(template.assertion.authenticator_data, client, false)
        .unwrap();
    let result = WebauthnResult {
        signature: signed.signature,
        authenticator_data: signed.assertion.authenticator_data,
        client_data: signed.assertion.client_data,
        prf: Some(vec![71; 32]),
    };
    fixture.push(json!({"name":"prf","challenge":action.challenge(),"salt":action.salt(),"signature":result.signature,"authenticatorData":result.authenticator_data,"clientData":result.client_data,"output":result.prf}));
    lib.finish_prf_slot(
        action,
        result,
        "Passkey".into(),
        new_seed,
        vec![entropy + 1; 32],
    )
    .unwrap()
}
#[test]
fn keys_full_flow() {
    let owner = SoftwareIdentity::from_seed([11; 32]).unwrap();
    let member = SoftwareIdentity::from_seed([12; 32]).unwrap();
    let recovery = SoftwareIdentity::from_seed([13; 32]).unwrap();
    let added = SoftwareIdentity::from_seed([14; 32]).unwrap();
    let auth = SyntheticAuthenticator::new().unwrap();
    let mut fixture = Vec::new();
    let first = begin_create(
        public(&member),
        public(&owner),
        vec![21; 32],
        "Keys".into(),
        "Device".into(),
        vec!["notes".into()],
        NOW.into(),
        vec![22; 32],
    )
    .unwrap();
    let (results, signed) = sign(&first, &[&owner, &member], &auth);
    fixture.push(json!({"name":"create","signing":signed}));
    let final_action = first
        .advance_create(results.into_iter().map(|s| s.signature).collect())
        .unwrap();
    let (results, signed) = sign(&final_action, &[&owner], &auth);
    fixture.push(json!({"name":"createFinal","signing":signed}));
    let records = final_action.finish_authority(results).unwrap();
    let lib = NativeLibrary::open(records, public(&member)).unwrap();
    let owner_secret = unlock(&lib, &owner);
    lib.select_controller(owner.public().id()).unwrap();
    let key = auth.descriptor("id.luff.works", None).unwrap();
    let passkey = Controller {
        key: key.clone(),
        label: "Passkey".into(),
        roles: vec![Role::Approve, Role::Control],
        verification: Some(true),
    };
    let slot = prf_slot(&lib, &key, &auth, None, 31, &mut fixture);
    commit(
        &lib,
        lib.begin_add_passkey(bytes(&passkey), slot, vec![owner.public().id()], NOW.into())
            .unwrap(),
        &[&owner],
        &auth,
        &mut fixture,
        "addPasskey",
    );
    let reopened = NativeLibrary::open(lib.records().unwrap(), public(&member)).unwrap();
    let option = reopened
        .begin_unlock_slots()
        .unwrap()
        .into_iter()
        .find(|o| matches!(o.inputs.as_slice(), [SlotInput::Prf { .. }]))
        .unwrap();
    assert!(reopened
        .finish_unlock_slot(
            option.clone(),
            vec![SlotSecret::Prf {
                output: vec![0; 32]
            }]
        )
        .is_err());
    reopened
        .finish_unlock_slot(
            option,
            vec![SlotSecret::Prf {
                output: vec![71; 32],
            }],
        )
        .unwrap();
    // Add the recovery kit and enable its threshold in one control-rule change.
    let recovery_controller = raw(&recovery, "Recovery", vec![Role::Recover]);
    let recovery_slot = lib
        .build_sealed_slot(
            bytes(&recovery_controller),
            "Recovery".into(),
            None,
            vec![33; 32],
        )
        .unwrap();
    let mut keyring: Keyring = serde_json::from_slice(&lib.keyring().unwrap()).unwrap();
    keyring.controllers.push(recovery_controller.clone());
    keyring.controllers.sort_by_key(Controller::id);
    keyring.recover_threshold = 1;
    keyring
        .slots
        .push(serde_json::from_slice(&recovery_slot).unwrap());
    commit(
        &lib,
        lib.begin_keyring(
            bytes(&keyring),
            None,
            vec![owner.public().id()],
            NOW.into(),
            vec![34; 32],
        )
        .unwrap(),
        &[&owner],
        &auth,
        &mut fixture,
        "enableRecovery",
    );
    // Remove the device, rotate the vault and preserve both remaining routes.
    let rotated_prf = prf_slot(&lib, &key, &auth, Some(vec![41; 32]), 35, &mut fixture);
    let rotated_recovery = lib
        .build_sealed_slot(
            bytes(&recovery_controller),
            "Recovery".into(),
            Some(vec![41; 32]),
            vec![37; 32],
        )
        .unwrap();
    commit(
        &lib,
        lib.begin_remove_controller(
            owner.public().id(),
            vec![41; 32],
            vec![rotated_prf, rotated_recovery],
            vec![owner.public().id()],
            NOW.into(),
            vec![38; 32],
        )
        .unwrap(),
        &[&owner],
        &auth,
        &mut fixture,
        "removeDevice",
    );
    let recovering = NativeLibrary::open(lib.records().unwrap(), public(&member)).unwrap();
    let recovery_secret = unlock(&recovering, &recovery);
    let added_controller = raw(&added, "Replacement", vec![Role::Approve, Role::Control]);
    let added_slot = recovering
        .build_sealed_slot(
            bytes(&added_controller),
            "Replacement".into(),
            None,
            vec![39; 32],
        )
        .unwrap();
    commit(
        &recovering,
        recovering
            .begin_recovery_add(
                bytes(&added_controller),
                Some(added_slot),
                vec![recovery.public().id()],
                NOW.into(),
            )
            .unwrap(),
        &[&recovery],
        &auth,
        &mut fixture,
        "recoveryAdd",
    );
    let current: Keyring = serde_json::from_slice(&recovering.keyring().unwrap()).unwrap();
    assert!(current.controller(&owner.public().id()).is_none());
    assert!(current.controller(&added.public().id()).is_some());
    assert_eq!(
        recovering.records().unwrap().len(),
        lib.records().unwrap().len() + 1
    );
    // A passkey assertion exercises the same high-S path through UniFFI finishing.
    let action = recovering
        .prepare_authority(
            bytes(&json!({"kind":"layout","layout":2})),
            key.id(),
            vec![key.id()],
            NOW.into(),
        )
        .unwrap();
    commit(
        &recovering,
        action,
        &[],
        &auth,
        &mut fixture,
        "passkeyLayout",
    );
    let final_open = NativeLibrary::open(recovering.records().unwrap(), public(&member)).unwrap();
    let added_secret = unlock(&final_open, &added);
    let template = auth
        .assertion(
            b"registration",
            "id.luff.works",
            "https://id.luff.works",
            0x41,
            false,
        )
        .unwrap();
    let p = key.signing();
    let cose = [
        vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32],
        p[1..33].to_vec(),
        vec![0x22, 0x58, 32],
        p[33..].to_vec(),
    ]
    .concat();
    let auth_data = [
        template.assertion.authenticator_data,
        vec![0; 16],
        vec![0, 1, 1],
        cose,
    ]
    .concat();
    let registration = [
        vec![0xa3, 0x63],
        b"fmt".to_vec(),
        vec![0x64],
        b"none".to_vec(),
        vec![0x67],
        b"attStmt".to_vec(),
        vec![0xa0, 0x68],
        b"authData".to_vec(),
        vec![0x58, auth_data.len() as u8],
        auth_data,
    ]
    .concat();
    assert_eq!(
        KeyDescriptor::from_json(
            &parse_registration(registration.clone(), "id.luff.works".into()).unwrap()
        )
        .unwrap(),
        key
    );
    let document = json!({"registration":registration,"openings":{"owner":owner_secret,"recovery":recovery_secret,"added":added_secret},"now":NOW,"member":json!(member.public()),"owner":json!(owner.public()),"recovery":recovery_controller,"added":added_controller,"passkey":passkey,"stages":fixture,"records":recovering.records().unwrap()});
    if let Ok(path) = std::env::var("W5_FIXTURE_OUTPUT") {
        std::fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
    }
}

#[test]
fn keys_missing_prf_and_stale_opening() {
    let owner = SoftwareIdentity::from_seed([11; 32]).unwrap();
    let member = SoftwareIdentity::from_seed([12; 32]).unwrap();
    let auth = SyntheticAuthenticator::new().unwrap();
    let action = begin_create(
        public(&member),
        public(&owner),
        vec![21; 32],
        "Keys".into(),
        "Device".into(),
        vec!["notes".into()],
        NOW.into(),
        vec![22; 32],
    )
    .unwrap();
    let (signed, _) = sign(&action, &[&owner, &member], &auth);
    let action = action
        .advance_create(signed.into_iter().map(|s| s.signature).collect())
        .unwrap();
    let (signed, _) = sign(&action, &[&owner], &auth);
    let lib =
        NativeLibrary::open(action.finish_authority(signed).unwrap(), public(&member)).unwrap();
    let stale = lib.begin_unlock_slots().unwrap().remove(0);
    unlock(&lib, &owner);
    assert!(matches!(
        lib.finish_unlock_slot(
            stale,
            vec![SlotSecret::Ecdh {
                secret: vec![0; 32]
            }]
        ),
        Err(BindingError::StaleAction)
    ));
    let action = lib
        .begin_prf_slot(
            bytes(&auth.descriptor("id.luff.works", None).unwrap()),
            vec![31; 32],
        )
        .unwrap();
    assert!(lib
        .finish_prf_slot(
            action,
            WebauthnResult {
                signature: vec![],
                authenticator_data: vec![],
                client_data: vec![],
                prf: None
            },
            "Passkey".into(),
            None,
            vec![32; 32]
        )
        .is_err());
    let before = lib.records().unwrap();
    let action = lib
        .begin_prf_slot(
            bytes(&auth.descriptor("id.luff.works", None).unwrap()),
            vec![33; 32],
        )
        .unwrap();
    let template = auth
        .assertion(
            b"unused",
            "id.luff.works",
            "https://id.luff.works",
            5,
            false,
        )
        .unwrap();
    let registration = auth.sign_bytes(template.assertion.authenticator_data, bytes(&json!({"type":"webauthn.create","challenge":action.challenge(),"origin":"https://id.luff.works"})), false).unwrap();
    let error = lib
        .finish_prf_slot(
            action,
            WebauthnResult {
                signature: registration.signature,
                authenticator_data: registration.assertion.authenticator_data,
                client_data: registration.assertion.client_data,
                prf: Some(vec![71; 32]),
            },
            "Passkey".into(),
            None,
            vec![34; 32],
        )
        .unwrap_err();
    assert!(
        matches!(error, BindingError::InvalidData { detail } if detail.starts_with("badSignature"))
    );
    assert_eq!(lib.records().unwrap(), before);
}

#[test]
fn keys_controller_import_grant_and_revoke() {
    let owner = SoftwareIdentity::from_seed([81; 32]).unwrap();
    let member = SoftwareIdentity::from_seed([82; 32]).unwrap();
    let copying = SoftwareIdentity::from_seed([83; 32]).unwrap();
    let auth = SyntheticAuthenticator::new().unwrap();
    let first = begin_create(
        public(&member),
        public(&owner),
        vec![84; 32],
        "Imports".into(),
        "Owner".into(),
        vec!["notes".into()],
        NOW.into(),
        vec![85; 32],
    )
    .unwrap();
    let (signed, _) = sign(&first, &[&owner, &member], &auth);
    let final_action = first
        .advance_create(signed.into_iter().map(|s| s.signature).collect())
        .unwrap();
    let (signed, _) = sign(&final_action, &[&owner], &auth);
    let lib = NativeLibrary::open(
        final_action.finish_authority(signed).unwrap(),
        public(&member),
    )
    .unwrap();
    unlock(&lib, &owner);
    lib.select_controller(owner.public().id()).unwrap();
    let request = begin_request(
        lib.id().unwrap(),
        public(&copying),
        "Copying device".into(),
        MemberKind::Device,
        vec!["notes".into()],
        vec![Access::Read, Access::Write],
        NOW.into(),
    )
    .unwrap();
    let (signed, _) = sign(&request, &[&copying], &auth);
    let request = request
        .finish_authority(signed)
        .unwrap()
        .into_values()
        .next()
        .unwrap();
    let grant = json!({"namespaces":["notes"],"access":["read","write"],"expires":"2026-11-09T12:00:00Z","import":true});
    let action = lib
        .begin_import_grant(
            request,
            bytes(&grant),
            vec![owner.public().id()],
            NOW.into(),
            vec![86; 32],
        )
        .unwrap();
    let (signed, _) = sign(&action, &[&owner], &auth);
    lib.finish_authority(action, signed).unwrap();
    let copying_id = copying.public().id();
    let granted = lib
        .members()
        .unwrap()
        .into_iter()
        .find(|m| m.id == copying_id)
        .unwrap();
    assert_eq!(granted.grant.unwrap().import, Some(true));
    let action = match lib
        .begin_revoke(copying_id.clone(), NOW.into(), vec![87; 32])
        .unwrap()
    {
        PreparedAction::Ready { action } => action,
        _ => panic!("denied controller revoke"),
    };
    let (signed, _) = sign(&action, &[&owner], &auth);
    lib.finish_authority(action, signed).unwrap();
    assert!(lib
        .members()
        .unwrap()
        .into_iter()
        .find(|m| m.id == copying_id)
        .unwrap()
        .revoked_at
        .is_some());
}

#[test]
fn keys_combined_route_reopens_before_publication() {
    let owner = SoftwareIdentity::from_seed([91; 32]).unwrap();
    let member = SoftwareIdentity::from_seed([92; 32]).unwrap();
    let auth = SyntheticAuthenticator::new().unwrap();
    let first = begin_create(
        public(&member),
        public(&owner),
        vec![93; 32],
        "Combined".into(),
        "Owner".into(),
        vec!["notes".into()],
        NOW.into(),
        vec![94; 32],
    )
    .unwrap();
    let (signed, _) = sign(&first, &[&owner, &member], &auth);
    let final_action = first
        .advance_create(signed.into_iter().map(|s| s.signature).collect())
        .unwrap();
    let (signed, _) = sign(&final_action, &[&owner], &auth);
    let lib = NativeLibrary::open(
        final_action.finish_authority(signed).unwrap(),
        public(&member),
    )
    .unwrap();
    unlock(&lib, &owner);
    let descriptor = auth.descriptor("id.luff.works", None).unwrap();
    let passkey = Controller {
        key: descriptor.clone(),
        label: "Passkey".into(),
        roles: vec![Role::Approve, Role::Control],
        verification: Some(true),
    };
    let ceremony = lib
        .begin_prf_slot(bytes(&descriptor), vec![95; 32])
        .unwrap();
    let template = auth
        .assertion(
            b"unused",
            "id.luff.works",
            "https://id.luff.works",
            5,
            false,
        )
        .unwrap();
    let signed=auth.sign_bytes(template.assertion.authenticator_data,bytes(&json!({"type":"webauthn.get","challenge":ceremony.challenge(),"origin":"https://id.luff.works"})),false).unwrap();
    let result = WebauthnResult {
        signature: signed.signature,
        authenticator_data: signed.assertion.authenticator_data,
        client_data: signed.assertion.client_data,
        prf: Some(vec![96; 32]),
    };
    let combined = lib
        .begin_combined_slot(
            vec![
                CombinedSlotPart::Sealed {
                    controller: bytes(&raw(&owner, "Owner", vec![Role::Approve, Role::Control])),
                },
                CombinedSlotPart::Prf {
                    controller: bytes(&passkey),
                    action: ceremony,
                    result,
                },
            ],
            "Owner and passkey".into(),
            None,
            vec![97; 32],
        )
        .unwrap();
    let secrets = combined
        .inputs()
        .into_iter()
        .map(|input| match input {
            SlotInput::Ecdh { enc, .. } => SlotSecret::Ecdh {
                secret: owner.agree(&enc).unwrap(),
            },
            SlotInput::Prf { .. } => SlotSecret::Prf {
                output: vec![96; 32],
            },
        })
        .collect();
    let slot = lib.finish_combined_slot(combined, secrets).unwrap();
    let add = lib
        .begin_add_controller(
            bytes(&passkey),
            Some(slot),
            vec![owner.public().id()],
            NOW.into(),
        )
        .unwrap();
    let (signed, _) = sign(&add, &[&owner], &auth);
    lib.finish_authority(add, signed).unwrap();
    let candidates = lib
        .eligible_signers(bytes(&json!({"kind":"layout","layout":2})))
        .unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(webauthn_prf_input(vec![0; 32]).unwrap().len(), 32);
    assert!(webauthn_prf_input(vec![0; 31]).is_err());
}
