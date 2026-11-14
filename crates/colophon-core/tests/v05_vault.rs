//! Colophon 0.5 vault, slots, pairing, seed transfer and kits (work package E2).
//!
//! Independent of `tests/v5_candidate/`: nothing here shares encoding code with the vector
//! generator. Bytes are checked against the published 0.4 and 0.5 candidate vectors and
//! against the 0.4 implementation (`vault`, `hpke`, `crypto`), which the 0.5 labels keep.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::crypto::{Entropy, SoftwareKeys};
use colophon_core::hpke::SealedKey;
use colophon_core::v05::descriptor::Controller;
use colophon_core::v05::history::keyring::Keyring;
use colophon_core::v05::history::{verify_history, Objects, Persisted, State};
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::pairing::{
    code, commitment, seal_seed_for_transfer, ConfirmedPairing, ExistingWaiting, FailureLimiter,
    Joiner, LimitReached, PairingAbort, Permit, QrJoiner, ScannedQr, TransferKey,
};
use colophon_core::v05::signature::verify_raw;
use colophon_core::v05::slots::{
    answer_with_identity, part_info, plan_rotation, slot_info, validate_self_slot, validate_slots,
    validate_vault_entry_slots, webauthn_prf_input, OpeningInput, OpeningSecret, Part,
    PrfAssertion, PrfInput, PrfResult, Slot, SlotBuild, SlotPlan, SlotTarget,
};
use colophon_core::v05::vault::{
    kit_identity, EcdhOutput, PrfOutput, SoftwareIdentity, VaultPublic, VaultSeed, VaultSession,
};
use colophon_core::v05::{Failure, Reason};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------------------------
// Helpers.

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
fn unb64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}
fn genesis_body(dir: &str) -> Value {
    let env: Value =
        serde_json::from_slice(&std::fs::read(repo().join(dir).join("00000001.json")).unwrap())
            .unwrap();
    serde_json::from_slice(&unb64(env["body"].as_str().unwrap())).unwrap()
}
fn seed(n: u8) -> VaultSeed {
    VaultSeed::from_host_random([n; 32])
}
fn vault_of(n: u8) -> VaultPublic {
    seed(n).public().unwrap()
}
fn soft(n: u8) -> SoftwareIdentity {
    SoftwareIdentity::from_seed(&[n; 32]).unwrap()
}
fn raw_controller(id: &SoftwareIdentity, roles: &[&str], label: &str) -> Controller {
    let p = id.public();
    Controller::parse(
        json!({"key": {"form": "raw", "signing": b64(&p.signing), "agreement": b64(&p.agreement)},
               "label": label, "roles": roles}),
        "controller",
    )
    .unwrap()
}
fn map_of(list: &[&Controller]) -> BTreeMap<String, Controller> {
    list.iter().map(|c| (c.id(), (*c).clone())).collect()
}

const RP: &str = "id.luff.works";
/// A test authenticator with a published scalar (never use for real data).
struct Authenticator {
    key: SigningKey,
}
impl Authenticator {
    fn new(n: u8) -> Self {
        Self {
            key: SigningKey::from_slice(&[n; 32]).unwrap(),
        }
    }
    fn controller(&self, roles: &[&str], verification: bool) -> Controller {
        let mut c = json!({"key": {"form": "webauthn", "rp": RP, "credential": b64(&[1]),
                  "signing": b64(self.key.verifying_key().to_encoded_point(false).as_bytes())},
               "label": "Passkey", "roles": roles});
        if verification {
            c["verification"] = json!(true);
        }
        Controller::parse(c, "controller").unwrap()
    }
    fn assert_with(
        &self,
        challenge: &str,
        origin: &str,
        flags: u8,
        kind: &str,
        rp: &str,
    ) -> PrfAssertion {
        let client_data =
            serde_json::to_vec(&json!({"type": kind, "challenge": challenge, "origin": origin}))
                .unwrap();
        let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&[0, 0, 0, 1]);
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let sig: Signature = self.key.sign(&message);
        PrfAssertion {
            authenticator_data: auth,
            client_data,
            signature: sig.to_der().as_bytes().to_vec(),
        }
    }
    /// A valid assertion over exactly `challenge`.
    fn assert(&self, challenge: &[u8; 32]) -> PrfAssertion {
        self.assert_with(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "https://id.luff.works",
            0x05,
            "webauthn.get",
            RP,
        )
    }
}
fn prf(n: u8) -> PrfOutput {
    PrfOutput::from_host(&[n; 32]).unwrap()
}
fn locked<T: std::fmt::Debug>(r: Result<T, Failure>) {
    assert_eq!(r.unwrap_err(), Failure::Refused(Reason::VaultLocked));
}
fn failed<T: std::fmt::Debug>(r: Result<T, Failure>) -> Failure {
    r.unwrap_err()
}
fn default_account() -> AccountId {
    AccountId::parse(&"ab".repeat(32)).unwrap()
}
/// Open a slot completely: kit/device software identities answer ECDH, `prf_n` answers PRF.
fn open(
    slot: &Slot,
    vault: &VaultPublic,
    controllers: &BTreeMap<String, Controller>,
    identities: &[&SoftwareIdentity],
    prf_n: u8,
) -> Result<VaultSeed, Failure> {
    open_as(
        &default_account(),
        slot,
        vault,
        controllers,
        identities,
        prf_n,
    )
}
/// [`open`], recording the seed as opened under `account`.
fn open_as(
    account: &AccountId,
    slot: &Slot,
    vault: &VaultPublic,
    controllers: &BTreeMap<String, Controller>,
    identities: &[&SoftwareIdentity],
    prf_n: u8,
) -> Result<VaultSeed, Failure> {
    let secrets: Vec<OpeningSecret> = slot
        .begin_open(controllers)?
        .iter()
        .map(|input| match input {
            OpeningInput::Ecdh { .. } => identities
                .iter()
                .find_map(|i| answer_with_identity(i, input).ok())
                .unwrap_or_else(|| OpeningSecret::Ecdh(EcdhOutput::from_host(&[9; 32]).unwrap())),
            OpeningInput::Prf { .. } => OpeningSecret::Prf(prf(prf_n)),
        })
        .collect();
    slot.finish_open(account, vault, controllers, &secrets)
}

// ---------------------------------------------------------------------------------------------
// §7.1 Vault.

#[test]
fn vault_identity_is_derived_under_the_vault_label() {
    for n in [70u8, 71, 202, 1] {
        let ours = vault_of(n);
        // The 0.4 implementation keeps the label on purpose (§7.1).
        let theirs = colophon_core::vault::derive([n; 32]).unwrap().public();
        assert_eq!(ours.signing, theirs.signing);
        assert_eq!(ours.agreement, theirs.agreement);
        assert_eq!(ours.id(), theirs.id());
        ours.validate().unwrap();
    }
    assert_ne!(vault_of(70), vault_of(71));
    // Not the software identity of the seed itself, nor the 0.3 recovery derivation.
    assert_ne!(vault_of(70).signing, soft(70).public().signing);
    assert_ne!(
        vault_of(70).signing,
        SoftwareKeys::recovery([70; 32]).unwrap().public().signing
    );
}

#[test]
fn the_candidate_account_vault_is_reproduced_from_its_seed() {
    // `account` (and every upgrade vector) reuse the 0.4 genesis: vault seed [70; 32].
    let body = genesis_body("conformance/0.5/candidate/account/records/authority");
    let v = &body["keyring"]["vault"];
    let public = vault_of(70);
    assert_eq!(b64(&public.signing), v["signing"].as_str().unwrap());
    assert_eq!(b64(&public.agreement), v["agreement"].as_str().unwrap());
}

#[test]
fn software_identity_expansion_matches_the_published_software_keys() {
    for n in [11u8, 12, 13, 14, 15, 201, 0, 255] {
        let ours = soft(n).public();
        let theirs = SoftwareKeys::from_seed([n; 32]).unwrap().public();
        assert_eq!(ours.signing, theirs.signing);
        assert_eq!(ours.agreement, theirs.agreement);
    }
    // raw signature: 64 bytes that verify under the signing point.
    let id = soft(11);
    let sig = id.sign(b"body");
    verify_raw(&id.public().signing, b"body", &sig).unwrap();
    assert!(verify_raw(&id.public().signing, b"other", &sig).is_err());
}

#[test]
fn the_seed_check_is_vault_locked_and_leaves_the_session_alone() {
    let vault = vault_of(70);
    for bad in [vec![], vec![70; 31], vec![70; 33], vec![71; 32]] {
        locked(VaultSeed::check(&bad, &vault, &default_account()));
    }
    // Both public keys must match, not only one.
    let other = vault_of(71);
    for expected in [
        VaultPublic {
            signing: other.signing.clone(),
            agreement: vault.agreement.clone(),
        },
        VaultPublic {
            signing: vault.signing.clone(),
            agreement: other.agreement.clone(),
        },
    ] {
        locked(VaultSeed::check(&[70; 32], &expected, &default_account()));
    }
    let mut session = VaultSession::new();
    assert!(!session.is_unlocked());
    session
        .install(VaultSeed::check(&[70; 32], &vault, &default_account()))
        .unwrap();
    assert_eq!(session.seed().unwrap().public().unwrap(), vault);
    // A failed open does not replace or clear the unlocked seed.
    assert_eq!(
        session.install(VaultSeed::check(&[71; 32], &vault, &default_account())),
        Err(Failure::Refused(Reason::VaultLocked))
    );
    assert_eq!(session.seed().unwrap().public().unwrap(), vault);
    session.lock();
    assert!(!session.is_unlocked());
    assert_eq!(
        Failure::Refused(Reason::VaultLocked).code(),
        "refused:vaultLocked"
    );
}

#[test]
fn secrets_are_redacted_and_cannot_be_read() {
    let s = seed(70);
    assert_eq!(format!("{s:?}"), "VaultSeed(..)");
    assert_eq!(format!("{:?}", prf(7)), "PrfOutput(..)");
    assert_eq!(
        format!("{:?}", EcdhOutput::from_host(&[1; 32]).unwrap()),
        "EcdhOutput(..)"
    );
    // The host's bytes must be exactly 32.
    locked(PrfOutput::from_host(&[7; 31]));
    locked(EcdhOutput::from_host(&[7; 33]));
    assert!(!format!("{:?}", soft(11)).contains("scalar"));
}

// ---------------------------------------------------------------------------------------------
// §7.5 Software identities and kits.

#[test]
fn a_kit_has_the_one_0_4_derivation() {
    let kit = kit_identity(&[33; 32]).unwrap();
    // One derivation: the 0.3 and 0.4 recovery pre-step, so a 0.4 kit keeps its keys.
    let keys: Value = serde_json::from_slice(
        &std::fs::read(repo().join("conformance/0.4/keys/keys.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        b64(&kit.public().signing),
        keys["kit"]["public"]["signing"].as_str().unwrap()
    );
    assert_eq!(
        b64(&kit.public().agreement),
        keys["kit"]["public"]["agreement"].as_str().unwrap()
    );
    let recovery = SoftwareKeys::recovery([33; 32]).unwrap().public();
    assert_eq!(kit.public().signing, recovery.signing);
    assert_eq!(kit.public().agreement, recovery.agreement);
    // Not the plain software identity of the same bytes.
    assert_ne!(kit.public(), soft(33).public());
    // No 0.5 candidate vector uses a kit key under either derivation, so nothing there
    // constrains the choice.
    let bodies = collect_candidate_text();
    for k in [kit.public(), soft(33).public()] {
        for point in [&k.signing, &k.agreement] {
            assert!(
                !bodies.contains(&b64(point)),
                "a candidate vector contains a kit key"
            );
        }
    }
    // A kit is a `raw` controller with `agreement`, usually `recover` only.
    let controller = raw_controller(&kit, &["recover"], "Recovery kit");
    assert_eq!(
        controller.key().agreement(),
        Some(&kit.public().agreement[..])
    );
    assert_eq!(controller.id(), kit.id());
    assert_eq!(kit.descriptor().unwrap().id(), kit.id());
}

// ---------------------------------------------------------------------------------------------
// §7.2 Slots: build, open, vectors.

#[test]
fn the_candidate_genesis_sealed_slot_is_reproduced_and_opens() {
    // The 0.4 genesis the 0.5 vectors reuse: seed [70;32], controller seed 11, entropy [9;32].
    let body = genesis_body("conformance/0.5/candidate/account/records/authority");
    let published = &body["keyring"]["slots"][0];
    let device = soft(11);
    let controller = raw_controller(&device, &["approve", "control", "recover"], "raw 11");
    assert_eq!(
        controller.id(),
        published["controllers"][0].as_str().unwrap()
    );
    let controllers = map_of(&[&controller]);
    let vault = vault_of(70);
    let plan = SlotPlan {
        controllers: vec![controller.id()],
        label: "raw 11".into(),
    };
    let build = SlotBuild::begin(&plan, &gen(70, &controllers), [9; 32]).unwrap();
    assert!(build.prf_requests().is_empty());
    let slot = build.finish(&seed(70), &[]).unwrap();
    assert_eq!(&slot.to_value().unwrap(), published);
    assert_eq!(slot, Slot::from_value(published).unwrap());
    slot.validate(&controllers).unwrap();
    // It opens with the device's ECDH, and a wrong ECDH is vaultLocked.
    let opened = open(&slot, &vault, &controllers, &[&device], 0).unwrap();
    assert_eq!(opened.public().unwrap(), vault);
    locked(open(&slot, &vault, &controllers, &[], 0));
}

fn published_04_slots() -> (Vec<Value>, BTreeMap<String, Controller>) {
    let body = genesis_body("conformance/0.4/keys/prf-slot-open/records/authority");
    let controllers: Vec<Controller> = body["keyring"]["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Controller::parse(c.clone(), "controller").unwrap())
        .collect();
    let slots = body["keyring"]["slots"].as_array().unwrap().clone();
    (
        slots,
        controllers.into_iter().map(|c| (c.id(), c)).collect(),
    )
}

#[test]
fn the_0_4_prf_and_combined_slots_open_and_are_reproduced_under_0_5() {
    let (slots, controllers) = published_04_slots();
    let vault = vault_of(70);
    let device = soft(11);
    let passkey = Authenticator::new(1);
    // Opening the published slots: sealed (11), prf (output [7;32]), combined (sealed + prf).
    for (i, expected_kind) in ["sealed", "prf", "combined"].into_iter().enumerate() {
        let slot = Slot::from_value(&slots[i]).unwrap();
        assert_eq!(slot.kind(), expected_kind);
        slot.validate(&controllers).unwrap();
        let seed = open(&slot, &vault, &controllers, &[&device], 7).unwrap();
        assert_eq!(seed.public().unwrap(), vault);
        if slot.kind() != "sealed" {
            locked(open(&slot, &vault, &controllers, &[&device], 8));
        }
    }
    // Reproducing the `prf` slot: salt [6;32], PRF output [7;32], entropy [8;32].
    let pk = passkey.controller(&["approve", "control", "recover"], false);
    let pk_id = controllers
        .values()
        .find(|c| c.key().webauthn().is_some())
        .unwrap()
        .id();
    assert_eq!(pk.id(), pk_id);
    let plan = SlotPlan {
        controllers: vec![pk_id.clone()],
        label: "Passkey".into(),
    };
    let input = PrfInput {
        salt: [6; 32],
        challenge: [0x5a; 32],
    };
    let build = SlotBuild::begin_with(&plan, &gen(70, &controllers), &[input], [8; 32]).unwrap();
    let requests = build.prf_requests().to_vec();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].salt, [6; 32]);
    assert_eq!(requests[0].rp, RP);
    let result = PrfResult {
        assertion: passkey.assert(&requests[0].challenge),
        output: prf(7),
    };
    let slot = build.finish(&seed(70), &[result]).unwrap();
    assert_eq!(slot.to_value().unwrap(), slots[1]);
    // Reproducing the `combined` slot: sealed part to the device, PRF part; entropy [90;32].
    let device_id = controllers
        .values()
        .find(|c| c.key().webauthn().is_none())
        .unwrap()
        .id();
    let plan = SlotPlan {
        controllers: vec![device_id, pk_id],
        label: "Kit and passkey".into(),
    };
    let build = SlotBuild::begin_with(&plan, &gen(70, &controllers), &[input], [90; 32]).unwrap();
    let result = PrfResult {
        assertion: passkey.assert(&build.prf_requests()[0].challenge),
        output: prf(7),
    };
    let slot = build.finish(&seed(70), &[result]).unwrap();
    assert_eq!(slot.to_value().unwrap(), slots[2]);
}

#[test]
fn the_info_strings_are_the_slot_labels() {
    let v = "0123456789abcdef0123456789abcdef";
    let a = "11111111111111111111111111111111".to_string();
    let b = "22222222222222222222222222222222".to_string();
    assert_eq!(
        slot_info(v, "sealed", std::slice::from_ref(&a)),
        format!("colophon/vault-slot/4\n{v}\nsealed\n{a}").into_bytes()
    );
    assert_eq!(
        slot_info(v, "combined", &[b.clone(), a.clone()]),
        format!("colophon/vault-slot/4\n{v}\ncombined\n{b},{a}").into_bytes()
    );
    assert_eq!(
        part_info(v, 10, "prf", &b),
        format!("colophon/vault-part/4\n{v}\n10\nprf\n{b}").into_bytes()
    );
    // The 0.4 library builds the same bytes.
    assert_eq!(
        slot_info(v, "prf", std::slice::from_ref(&a)),
        colophon_core::slots::slot_info(v, "prf", std::slice::from_ref(&a))
    );
    assert_eq!(
        part_info(v, 3, "sealed", &a),
        colophon_core::slots::part_info(v, 3, "sealed", &a)
    );
    // PRF input transformation of a CTAP host.
    assert_eq!(
        webauthn_prf_input(&[4; 32]),
        colophon_core::slots::webauthn_prf_input(&[4; 32])
    );
}

fn collect_candidate_text() -> String {
    fn walk(dir: &std::path::Path, out: &mut String) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if let Ok(t) = std::fs::read_to_string(&p) {
                out.push_str(&t);
                // Bodies are base64 inside the envelopes: decode them too.
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if let Some(b) = v["body"].as_str().and_then(|b| STANDARD.decode(b).ok()) {
                        out.push_str(&String::from_utf8_lossy(&b));
                    }
                }
            }
        }
    }
    let mut out = String::new();
    walk(&repo().join("conformance/0.5/candidate"), &mut out);
    out
}

/// The slot target for a genesis of the new seed `n`.
fn gen(n: u8, controllers: &BTreeMap<String, Controller>) -> SlotTarget {
    SlotTarget::genesis(&seed(n), controllers).unwrap()
}

/// The verifier's state of the candidate `account` vector: vault seed [70;32] and one raw
/// controller (key seed 11).
fn account_state() -> State {
    let dir = repo().join("conformance/0.5/candidate/account/records/authority");
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let objects = Objects {
        entries: files.iter().map(|p| std::fs::read(p).unwrap()).collect(),
        ..Default::default()
    };
    let now = colophon_core::v05::encoding::parse_date("2026-11-11T09:01:00Z").unwrap();
    let verdict = verify_history(&objects, &Persisted::default(), now);
    assert_eq!(verdict.code(), "ok");
    verdict.state.unwrap()
}

/// A passkey, a device key and a kit, for the build and refusal tests.
struct Fixture {
    passkey: Authenticator,
    device: SoftwareIdentity,
    kit: SoftwareIdentity,
    controllers: BTreeMap<String, Controller>,
    ids: [String; 3],
    vault: VaultPublic,
}
fn fixture() -> Fixture {
    let passkey = Authenticator::new(1);
    let device = soft(11);
    let kit = kit_identity(&[33; 32]).unwrap();
    let p = passkey.controller(&["approve", "control"], false);
    let d = raw_controller(&device, &["approve", "control"], "Mac");
    let k = raw_controller(&kit, &["recover"], "Kit");
    let ids = [p.id(), d.id(), k.id()];
    Fixture {
        controllers: map_of(&[&p, &d, &k]),
        passkey,
        device,
        kit,
        ids,
        vault: vault_of(70),
    }
}
fn build(f: &Fixture, ids: &[&str], salt_seed: u8) -> Result<Slot, Failure> {
    let plan = SlotPlan {
        controllers: ids.iter().map(|s| s.to_string()).collect(),
        label: "slot".into(),
    };
    let b = SlotBuild::begin(&plan, &gen(70, &f.controllers), [salt_seed; 32])?;
    let results: Vec<PrfResult> = b
        .prf_requests()
        .iter()
        .map(|r| PrfResult {
            assertion: f.passkey.assert(&r.challenge),
            output: prf(7),
        })
        .collect();
    b.finish(&seed(70), &results)
}

#[test]
fn every_slot_kind_is_built_verified_and_opened() {
    let f = fixture();
    let [p, d, k] = &f.ids;
    let ids = [p.as_str(), d.as_str(), k.as_str()];
    for combo in [
        vec![ids[0]],
        vec![ids[1]],
        vec![ids[2]],
        vec![ids[1], ids[0]],
        vec![ids[0], ids[2]],
        vec![ids[2], ids[1], ids[0]],
        vec![ids[1], ids[2]],
    ] {
        let slot = build(&f, &combo, 5).unwrap();
        let expect = match combo.len() {
            1 if combo[0] == ids[0] => "prf",
            1 => "sealed",
            _ => "combined",
        };
        assert_eq!(slot.kind(), expect, "{combo:?}");
        assert_eq!(slot.controllers(), combo);
        slot.validate(&f.controllers).unwrap();
        // Round trip through JSON.
        assert_eq!(Slot::from_value(&slot.to_value().unwrap()).unwrap(), slot);
        // Opens with the right secrets: the device and the kit answer ECDH; the passkey PRF.
        let opened = open(&slot, &f.vault, &f.controllers, &[&f.device, &f.kit], 7).unwrap();
        assert_eq!(opened.public().unwrap(), f.vault);
        // A different PRF output, or a missing ECDH answer, is vaultLocked.
        if combo.contains(&ids[0]) {
            locked(open(
                &slot,
                &f.vault,
                &f.controllers,
                &[&f.device, &f.kit],
                6,
            ));
        }
        if combo.iter().any(|c| *c != ids[0]) {
            locked(open(&slot, &f.vault, &f.controllers, &[], 7));
        }
    }
    // Part secrets are independent and fresh: two builds with other entropy differ.
    assert_ne!(
        build(&f, &[&f.ids[1], &f.ids[0]], 5).unwrap(),
        build(&f, &[&f.ids[1], &f.ids[0]], 6).unwrap()
    );
}

#[test]
fn a_combined_slot_needs_every_part_in_order() {
    let f = fixture();
    let slot = build(&f, &[&f.ids[1], &f.ids[2], &f.ids[0]], 5).unwrap();
    let inputs = slot.begin_open(&f.controllers).unwrap();
    assert_eq!(inputs.len(), 3);
    assert!(matches!(&inputs[0], OpeningInput::Ecdh { controller, .. } if *controller == f.ids[1]));
    assert!(matches!(&inputs[2], OpeningInput::Prf { controller, .. } if *controller == f.ids[0]));
    // Wrong order of the right secrets, wrong count and wrong types are vaultLocked.
    let right = |n: usize| -> OpeningSecret {
        match &inputs[n] {
            OpeningInput::Ecdh { controller, .. } => {
                let who = if *controller == f.ids[1] {
                    &f.device
                } else {
                    &f.kit
                };
                answer_with_identity(who, &inputs[n]).unwrap()
            }
            OpeningInput::Prf { .. } => OpeningSecret::Prf(prf(7)),
        }
    };
    slot.finish_open(
        &default_account(),
        &f.vault,
        &f.controllers,
        &[right(0), right(1), right(2)],
    )
    .unwrap();
    locked(slot.finish_open(
        &default_account(),
        &f.vault,
        &f.controllers,
        &[right(1), right(0), right(2)],
    ));
    locked(slot.finish_open(
        &default_account(),
        &f.vault,
        &f.controllers,
        &[right(0), right(1)],
    ));
    locked(slot.finish_open(
        &default_account(),
        &f.vault,
        &f.controllers,
        &[
            right(0),
            right(1),
            OpeningSecret::Ecdh(EcdhOutput::from_host(&[7; 32]).unwrap()),
        ],
    ));
    // The kit cannot answer the device's route.
    assert_eq!(
        answer_with_identity(&f.kit, &inputs[0]).unwrap_err(),
        Failure::Refused(Reason::VaultLocked)
    );
    // Nor a PRF input.
    assert!(answer_with_identity(&f.device, &inputs[2]).is_err());
}

#[test]
fn a_slot_opening_to_another_seed_or_vault_is_vault_locked() {
    let f = fixture();
    // A slot for vault 70 does not open the keyring of vault 71 (the info differs) ...
    let slot = build(&f, &[&f.ids[1]], 5).unwrap();
    locked(open(&slot, &vault_of(71), &f.controllers, &[&f.device], 0));
    // ... and a slot sealed with a seed that is not the keyring's vault never builds.
    let plan = SlotPlan {
        controllers: vec![f.ids[1].clone()],
        label: "x".into(),
    };
    let b = SlotBuild::begin(&plan, &gen(70, &f.controllers), [5; 32]).unwrap();
    locked(b.finish(&seed(71), &[]));
    // ... and a target for another seed's vault never takes this seed.
    let b = SlotBuild::begin(&plan, &gen(71, &f.controllers), [5; 32]).unwrap();
    locked(b.finish(&seed(70), &[]));
}

// ---------------------------------------------------------------------------------------------
// §7.2 refusals: structure.

fn controller_value(c: &Slot) -> Value {
    c.to_value().unwrap()
}

#[test]
fn structural_violations_are_malformed() {
    let f = fixture();
    let sealed = controller_value(&build(&f, &[&f.ids[1]], 5).unwrap());
    let prf_slot = controller_value(&build(&f, &[&f.ids[0]], 5).unwrap());
    let combined = controller_value(&build(&f, &[&f.ids[1], &f.ids[0]], 5).unwrap());
    let set = |mut v: Value, f: &dyn Fn(&mut Value)| {
        f(&mut v);
        v
    };
    let cases: Vec<(&str, Value)> = vec![
        (
            "empty label",
            set(sealed.clone(), &|v| v["label"] = json!("")),
        ),
        (
            "long label",
            set(sealed.clone(), &|v| v["label"] = json!("x".repeat(201))),
        ),
        (
            "extra field",
            set(sealed.clone(), &|v| v["extra"] = json!(1)),
        ),
        (
            "unknown kind",
            set(sealed.clone(), &|v| v["kind"] = json!("hybrid")),
        ),
        (
            "no controllers",
            set(sealed.clone(), &|v| v["controllers"] = json!([])),
        ),
        (
            "sealed names two",
            set(sealed.clone(), &|v| {
                v["controllers"] = json!([f.ids[1], f.ids[2]])
            }),
        ),
        (
            "enc size",
            set(sealed.clone(), &|v| {
                v["sealed"]["enc"] = json!(b64(&[4; 64]))
            }),
        ),
        (
            "enc not a point",
            set(sealed.clone(), &|v| {
                v["sealed"]["enc"] = json!(b64(&[4; 65]))
            }),
        ),
        (
            "ciphertext size",
            set(sealed.clone(), &|v| {
                v["sealed"]["ciphertext"] = json!(b64(&[1; 47]))
            }),
        ),
        (
            "salt size",
            set(prf_slot.clone(), &|v| v["salt"] = json!(b64(&[1; 31]))),
        ),
        (
            "box size",
            set(prf_slot.clone(), &|v| v["box"] = json!(b64(&[1; 59]))),
        ),
        (
            "box long",
            set(prf_slot.clone(), &|v| v["box"] = json!(b64(&[1; 61]))),
        ),
        (
            "non-canonical base64",
            set(prf_slot.clone(), &|v| {
                let s = v["salt"].as_str().unwrap().replace('=', "");
                v["salt"] = json!(s);
            }),
        ),
        (
            "combined duplicate controllers",
            set(combined.clone(), &|v| {
                v["controllers"] = json!([f.ids[1], f.ids[1]]);
            }),
        ),
        (
            "combined one part",
            set(combined.clone(), &|v| {
                v["controllers"] = json!([f.ids[1]]);
                v["parts"] = json!([v["parts"][0].clone()]);
            }),
        ),
        (
            "combined empty",
            set(combined.clone(), &|v| {
                v["controllers"] = json!([]);
                v["parts"] = json!([]);
            }),
        ),
        (
            "combined parts differ",
            set(combined.clone(), &|v| {
                v["parts"] = json!([v["parts"][0].clone()])
            }),
        ),
        (
            "part salt size",
            set(combined.clone(), &|v| {
                v["parts"][1]["salt"] = json!(b64(&[1; 31]))
            }),
        ),
        (
            "part ciphertext size",
            set(combined.clone(), &|v| {
                v["parts"][0]["sealed"]["ciphertext"] = json!(b64(&[1; 47]));
            }),
        ),
        (
            "part unknown field",
            set(combined.clone(), &|v| v["parts"][0]["x"] = json!(1)),
        ),
        (
            "combined box size",
            set(combined.clone(), &|v| v["box"] = json!(b64(&[1; 61]))),
        ),
        (
            "controller id not a key id",
            set(sealed.clone(), &|v| v["controllers"] = json!(["ABC"])),
        ),
    ];
    for (name, value) in cases {
        let r = Slot::from_value(&value).and_then(|s| s.validate(&f.controllers));
        let failure = failed(r);
        assert_eq!(failure.code(), "malformed", "{name}: {failure}");
    }
    // Controllers: a slot naming a non-controller, a sign controller, or the wrong form.
    let sign = Controller::parse(
        json!({"key": {"form": "raw", "signing": b64(&soft(14).public().signing)},
               "label": "agent", "roles": ["sign"], "audiences": ["https://a.example"]}),
        "c",
    )
    .unwrap();
    let no_agreement = Controller::parse(
        json!({"key": {"form": "raw", "signing": b64(&soft(15).public().signing)},
               "label": "no agreement", "roles": ["approve"]}),
        "c",
    )
    .unwrap();
    let mut controllers = f.controllers.clone();
    controllers.insert(sign.id(), sign.clone());
    controllers.insert(no_agreement.id(), no_agreement.clone());
    let sealed_slot = Slot::from_value(&sealed).unwrap();
    let rename = |id: &str, v: &Value| set(v.clone(), &|x| x["controllers"] = json!([id]));
    for (name, value) in [
        ("not a controller", rename(&"3".repeat(32), &sealed)),
        ("sign controller", rename(&sign.id(), &sealed)),
        ("raw without agreement", rename(&no_agreement.id(), &sealed)),
        ("sealed names a webauthn key", rename(&f.ids[0], &sealed)),
        ("prf names a raw key", rename(&f.ids[1], &prf_slot)),
    ] {
        let s = Slot::from_value(&value).unwrap();
        assert_eq!(
            failed(s.validate(&controllers)).code(),
            "malformed",
            "{name}"
        );
    }
    assert_eq!(
        failed(sealed_slot.begin_open(&BTreeMap::new())).code(),
        "malformed"
    );
    // A combined slot whose part kind does not fit its controller.
    let swapped = set(combined.clone(), &|v| {
        v["controllers"] = json!([f.ids[0], f.ids[1]]);
    });
    let s = Slot::from_value(&swapped).unwrap();
    assert_eq!(failed(s.validate(&f.controllers)).code(), "malformed");
    // validate_slots: bounds on the count.
    assert_eq!(
        failed(validate_slots(&f.controllers, &[], 1)).code(),
        "malformed"
    );
    validate_slots(&f.controllers, &[], 0).unwrap();
    let many = vec![sealed.clone(); 257];
    assert_eq!(
        failed(validate_slots(&f.controllers, &many, 0)).code(),
        "malformed"
    );
    assert!(matches!(
        Slot::from_value(&sealed).unwrap(),
        Slot::Sealed { .. }
    ));
    assert!(matches!(
        Slot::from_value(&combined).unwrap(),
        Slot::Combined { ref parts, .. } if matches!(parts[1], Part::Prf { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// §7.2 refusals: building a PRF route.

#[test]
fn a_new_prf_route_needs_a_verified_assertion_over_the_core_challenge() {
    let f = fixture();
    let plan = SlotPlan {
        controllers: vec![f.ids[0].clone()],
        label: "Passkey".into(),
    };
    let begin = || SlotBuild::begin(&plan, &gen(70, &f.controllers), [5; 32]).unwrap();
    let req = begin().prf_requests()[0].clone();
    assert_eq!(req.controller, f.ids[0]);
    assert_eq!(req.rp, RP);
    assert_eq!(req.credential, vec![1]);
    // The salt and challenge come from the entropy seed: stable per seed, fresh per seed.
    assert_eq!(begin().prf_requests()[0], req);
    let other = SlotBuild::begin(&plan, &gen(70, &f.controllers), [6; 32]).unwrap();
    assert_ne!(other.prf_requests()[0].salt, req.salt);
    assert_ne!(other.prf_requests()[0].challenge, req.challenge);
    assert_ne!(req.salt, req.challenge);
    let url = |c: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(c);
    let good_origin = "https://id.luff.works";
    let ok = |a: PrfAssertion| {
        begin().finish(
            &seed(70),
            &[PrfResult {
                assertion: a,
                output: prf(7),
            }],
        )
    };
    ok(f.passkey.assert(&req.challenge)).unwrap();
    // Subdomains of the rp are allowed under the general rule.
    ok(f.passkey.assert_with(
        &url(&req.challenge),
        "https://a.id.luff.works",
        5,
        "webauthn.get",
        RP,
    ))
    .unwrap();
    // A body digest, or any other challenge: badSignature.
    let digest = Sha256::digest(b"some body");
    for challenge in [
        url(&digest),
        url(&[0; 32]),
        url(&req.challenge[..31]),
        "x".into(),
    ] {
        let a = f
            .passkey
            .assert_with(&challenge, good_origin, 5, "webauthn.get", RP);
        assert_eq!(failed(ok(a)).code(), "badSignature", "{challenge}");
    }
    // Registration type, wrong rp hash, no user presence, foreign origin: badSignature.
    let c = url(&req.challenge);
    for (name, a) in [
        (
            "create",
            f.passkey
                .assert_with(&c, good_origin, 5, "webauthn.create", RP),
        ),
        (
            "rp hash",
            f.passkey
                .assert_with(&c, good_origin, 5, "webauthn.get", "evil.example"),
        ),
        (
            "no UP",
            f.passkey
                .assert_with(&c, good_origin, 0x04, "webauthn.get", RP),
        ),
        (
            "origin",
            f.passkey
                .assert_with(&c, "https://evil.example", 5, "webauthn.get", RP),
        ),
        (
            "origin suffix",
            f.passkey
                .assert_with(&c, "https://xid.luff.works", 5, "webauthn.get", RP),
        ),
        (
            "origin http",
            f.passkey
                .assert_with(&c, "http://id.luff.works", 5, "webauthn.get", RP),
        ),
    ] {
        assert_eq!(failed(ok(a)).code(), "badSignature", "{name}");
    }
    // A foreign authenticator's signature, and a damaged one.
    let foreign = Authenticator::new(2).assert(&req.challenge);
    assert_eq!(failed(ok(foreign)).code(), "badSignature");
    let mut damaged = f.passkey.assert(&req.challenge);
    *damaged.signature.last_mut().unwrap() ^= 1;
    assert_eq!(failed(ok(damaged)).code(), "badSignature");
    let mut short = f.passkey.assert(&req.challenge);
    short.authenticator_data.truncate(36);
    assert_eq!(failed(ok(short)).code(), "badSignature");
    // crossOrigin true is refused; clientData over 8,192 bytes is malformed.
    let mut cross = f.passkey.assert(&req.challenge);
    cross.client_data = serde_json::to_vec(
        &json!({"type":"webauthn.get","challenge":c,"origin":good_origin,"crossOrigin":true}),
    )
    .unwrap();
    assert_eq!(failed(ok(cross)).code(), "badSignature");
    let mut big = f.passkey.assert(&req.challenge);
    big.client_data = vec![b' '; 8_193];
    assert_eq!(failed(ok(big)).code(), "malformed");
    // Missing assertions: no results, or a PRF output of the wrong length.
    assert_eq!(failed(begin().finish(&seed(70), &[])).code(), "malformed");
    locked(PrfOutput::from_host(&[]));
}

#[test]
fn uv_is_required_when_the_controller_has_verification() {
    let passkey = Authenticator::new(1);
    let strict = passkey.controller(&["approve", "control"], true);
    let controllers = map_of(&[&strict]);
    let plan = SlotPlan {
        controllers: vec![strict.id()],
        label: "Passkey".into(),
    };
    let run = |flags: u8| {
        let b = SlotBuild::begin(&plan, &gen(70, &controllers), [5; 32]).unwrap();
        let c =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b.prf_requests()[0].challenge);
        let a = passkey.assert_with(&c, "https://id.luff.works", flags, "webauthn.get", RP);
        b.finish(
            &seed(70),
            &[PrfResult {
                assertion: a,
                output: prf(7),
            }],
        )
    };
    run(0x05).unwrap();
    assert_eq!(failed(run(0x01)).code(), "badSignature");
}

#[test]
fn the_builder_refuses_what_a_slot_cannot_name() {
    let f = fixture();
    let sign = Controller::parse(
        json!({"key": {"form": "raw", "signing": b64(&soft(14).public().signing),
                       "agreement": b64(&soft(14).public().agreement)},
               "label": "agent", "roles": ["sign"], "audiences": ["https://a.example"]}),
        "c",
    )
    .unwrap();
    let mut controllers = f.controllers.clone();
    controllers.insert(sign.id(), sign.clone());
    for ids in [
        vec![sign.id()],
        vec!["4".repeat(32)],
        vec![],
        vec![f.ids[1].clone(), f.ids[1].clone()],
    ] {
        let plan = SlotPlan {
            controllers: ids,
            label: "x".into(),
        };
        assert_eq!(
            failed(SlotBuild::begin(&plan, &gen(70, &controllers), [1; 32])).code(),
            "malformed"
        );
    }
    let plan = SlotPlan {
        controllers: vec![f.ids[1].clone()],
        label: String::new(),
    };
    assert_eq!(
        failed(SlotBuild::begin(&plan, &gen(70, &controllers), [1; 32])).code(),
        "malformed"
    );
    // The wrong number of PRF inputs for `begin_with`.
    let plan = SlotPlan {
        controllers: vec![f.ids[1].clone()],
        label: "x".into(),
    };
    let one = PrfInput {
        salt: [1; 32],
        challenge: [2; 32],
    };
    assert!(SlotBuild::begin_with(&plan, &gen(70, &controllers), &[one], [1; 32]).is_err());
}

// ---------------------------------------------------------------------------------------------
// §8.3 Rotation.

fn policy() -> Value {
    json!({"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
           "linkMaxAge": 86400, "memberRule": "single", "recoveryDelay": 259200,
           "rate": {"account": {"bytes": 16777216, "entries": 256},
                    "signer": {"bytes": 4194304, "entries": 64}}})
}
fn ring(controllers: &[&Controller], slots: &[&Slot], vault: &VaultPublic) -> Keyring {
    let mut list: Vec<(String, Value)> = controllers
        .iter()
        .map(|c| {
            let key = if let Some(a) = c.key().agreement() {
                json!({"form": "raw", "signing": b64(c.key().signing()), "agreement": b64(a)})
            } else {
                json!({"form": "webauthn", "rp": RP, "credential": b64(&[1]),
                       "signing": b64(c.key().signing())})
            };
            let roles: Vec<String> = c
                .roles()
                .iter()
                .map(|r| format!("{r:?}").to_lowercase())
                .collect();
            (
                c.id(),
                json!({"key": key, "label": c.label(), "roles": roles}),
            )
        })
        .collect();
    list.sort_by(|a, b| a.0.cmp(&b.0));
    Keyring::parse(
        json!({"controllers": list.into_iter().map(|x| x.1).collect::<Vec<_>>(),
               "threshold": 1, "recoverThreshold": 1, "addThreshold": 1, "countBy": "keys",
               "policy": policy(), "vault": vault.to_value(),
               "slots": slots.iter().map(|s| s.to_value().unwrap()).collect::<Vec<_>>()}),
        0,
    )
    .unwrap()
}
fn sealed_for(c: &Controller, vault_seed: u8, entropy: u8) -> Slot {
    let controllers = map_of(&[c]);
    let plan = SlotPlan {
        controllers: vec![c.id()],
        label: format!("slot {}", &c.id()[..4]),
    };
    SlotBuild::begin(&plan, &gen(vault_seed, &controllers), [entropy; 32])
        .unwrap()
        .finish(&seed(vault_seed), &[])
        .unwrap()
}
struct Rot {
    a: Controller,
    b: Controller,
    c: Controller,
    sa: Slot,
    sb: Slot,
    sc: Slot,
    vault: VaultPublic,
}
fn rot() -> Rot {
    let all = ["approve", "control", "recover"];
    let a = raw_controller(&soft(11), &all, "A");
    let b = raw_controller(&soft(12), &all, "B");
    let c = raw_controller(&soft(13), &all, "C");
    Rot {
        sa: sealed_for(&a, 70, 1),
        sb: sealed_for(&b, 70, 2),
        sc: sealed_for(&c, 70, 3),
        vault: vault_of(70),
        a,
        b,
        c,
    }
}

#[test]
fn removing_a_never_slotted_controller_needs_no_vault_change() {
    let r = rot();
    let before = ring(&[&r.a, &r.b, &r.c], &[&r.sa, &r.sb], &r.vault);
    let after = ring(&[&r.a, &r.b], &[&r.sa, &r.sb], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(!plan.retiring && !plan.vault_changed);
    assert!(plan.lost.is_empty() && plan.dropped.is_empty() && plan.rebuild.is_empty());
    assert!(plan.without_slot.is_empty() && plan.vault_signers.is_empty());
}

#[test]
fn removing_a_slotted_controller_retires_the_vault_and_names_the_rebuild() {
    let r = rot();
    let before = ring(&[&r.a, &r.b, &r.c], &[&r.sa, &r.sb, &r.sc], &r.vault);
    // Removal drops the slot naming C; the vault is unchanged and retiring.
    let after = ring(&[&r.a, &r.b], &[&r.sa, &r.sb], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.retiring && !plan.vault_changed);
    assert_eq!(plan.lost, vec![r.c.id()]);
    assert_eq!(plan.dropped, vec![r.sc.clone()]);
    let mut want = vec![r.a.id(), r.b.id()];
    want.sort();
    assert_eq!(plan.vault_signers, want);
    // The `vault` entry must rebuild every remaining slotted controller's slot.
    let plans: Vec<&Vec<String>> = plan.rebuild.iter().map(|p| &p.controllers).collect();
    assert_eq!(plans, vec![&vec![r.a.id()], &vec![r.b.id()]]);
    assert!(plan.without_slot.is_empty());
    // The result may leave no slot at all (§8.3): everything removed but one unslotted key.
    let d = raw_controller(&soft(14), &["approve", "control", "recover"], "D");
    let before = ring(&[&r.a, &d], &[&r.sa], &r.vault);
    let after = ring(&[&d], &[], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.retiring);
    assert!(plan.vault_signers.is_empty());
}

#[test]
fn demotion_and_agreement_change_drop_slots_too() {
    let r = rot();
    let before = ring(&[&r.a, &r.b], &[&r.sa, &r.sb], &r.vault);
    // Demote B (loses `recover`): its slot is dropped.
    let b2 = raw_controller(&soft(12), &["approve", "control"], "B");
    let after = ring(&[&r.a, &b2], &[&r.sa], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.retiring);
    assert_eq!(plan.lost, vec![r.b.id()]);
    // The slot kept anyway is refused: "every slot naming that controller is dropped".
    let kept = ring(&[&r.a, &b2], &[&r.sa, &r.sb], &r.vault);
    assert_eq!(
        failed(plan_rotation(&before, &kept, &[])).code(),
        "malformed"
    );
    // A changed agreement key: same signing key, new agreement.
    let b3 = Controller::parse(
        json!({"key": {"form": "raw", "signing": b64(r.b.key().signing()),
                       "agreement": b64(&soft(77).public().agreement)},
               "label": "B", "roles": ["approve", "control", "recover"]}),
        "c",
    )
    .unwrap();
    assert_eq!(b3.id(), r.b.id());
    let after = ring(&[&r.a, &b3], &[&r.sa], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.retiring);
    assert_eq!(plan.lost, vec![r.b.id()]);
}

#[test]
fn a_rotation_names_the_slots_it_still_has_to_build() {
    let r = rot();
    let new_vault = vault_of(71);
    let before = ring(&[&r.a, &r.b, &r.c], &[&r.sa, &r.sb, &r.sc], &r.vault);
    // A `vault` entry carrying only A's slot (the signer's own): B and C are slotted before
    // and not now, so they are reported and still need the seed by §7.4.
    let new_a = sealed_for(&r.a, 71, 4);
    let after = ring(&[&r.a, &r.b, &r.c], &[&new_a], &new_vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.vault_changed && !plan.retiring);
    let mut warn = vec![r.b.id(), r.c.id()];
    warn.sort();
    let mut got = plan.without_slot.clone();
    got.sort();
    assert_eq!(got, warn);
    let mut need: Vec<String> = plan
        .rebuild
        .iter()
        .flat_map(|p| p.controllers.clone())
        .collect();
    need.sort();
    assert_eq!(need, warn);
    // Slots for the new vault open to the new seed only.
    let controllers = map_of(&[&r.a, &r.b, &r.c]);
    open(&new_a, &new_vault, &controllers, &[&soft(11)], 0).unwrap();
    locked(open(&new_a, &r.vault, &controllers, &[&soft(11)], 0));
    // Removed controller plus rotation at once (a removal proposed by a seed holder): the
    // removed key's slot is dropped, the others rebuilt.
    let after = ring(
        &[&r.a, &r.b],
        &[&new_a, &sealed_for(&r.b, 71, 5)],
        &new_vault,
    );
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.vault_changed && !plan.retiring);
    assert_eq!(plan.lost, vec![r.c.id()]);
    assert!(plan.without_slot.is_empty() && plan.rebuild.is_empty());
}

#[test]
fn a_result_that_deletes_or_changes_a_slot_without_a_vault_change_is_refused() {
    let r = rot();
    let before = ring(&[&r.a, &r.b], &[&r.sa, &r.sb], &r.vault);
    // Deleted.
    let deleted = ring(&[&r.a, &r.b], &[&r.sa], &r.vault);
    assert_eq!(
        failed(plan_rotation(&before, &deleted, &[])).code(),
        "malformed"
    );
    // Changed (same controller, other ciphertext).
    let changed = ring(&[&r.a, &r.b], &[&r.sa, &sealed_for(&r.b, 70, 9)], &r.vault);
    assert_eq!(
        failed(plan_rotation(&before, &changed, &[])).code(),
        "malformed"
    );
    // Duplicate-aware: a multiset, not a set.
    let twice = ring(&[&r.a, &r.b], &[&r.sa, &r.sa, &r.sb], &r.vault);
    plan_rotation(&before, &twice, &[]).unwrap();
    let before2 = ring(&[&r.a, &r.b], &[&r.sa, &r.sa, &r.sb], &r.vault);
    assert_eq!(
        failed(plan_rotation(&before2, &before, &[])).code(),
        "malformed"
    );
    // Labels and order may change; slots for existing controllers may be added.
    let mut relabelled = r.sb.to_value().unwrap();
    relabelled["label"] = json!("renamed");
    let relabelled = Slot::from_value(&relabelled).unwrap();
    let ok = ring(&[&r.a, &r.b], &[&relabelled, &r.sa], &r.vault);
    let plan = plan_rotation(&before, &ok, &[]).unwrap();
    assert!(!plan.retiring && plan.rebuild.is_empty());
    let extra = ring(
        &[&r.a, &r.b],
        &[&r.sa, &r.sb, &sealed_for(&r.a, 70, 6)],
        &r.vault,
    );
    plan_rotation(&before, &extra, &[]).unwrap();
}

#[test]
fn vault_entries_and_self_slots_are_checked() {
    let r = rot();
    let controllers = map_of(&[&r.a, &r.b]);
    let new_a = sealed_for(&r.a, 71, 4);
    let new_b = sealed_for(&r.b, 71, 5);
    let v =
        |slots: &[&Slot]| -> Vec<Value> { slots.iter().map(|s| s.to_value().unwrap()).collect() };
    // A `vault` entry needs a slot naming its signer.
    validate_vault_entry_slots(&controllers, &v(&[&new_a, &new_b]), &r.a.id()).unwrap();
    validate_vault_entry_slots(&controllers, &v(&[&new_a]), &r.a.id()).unwrap();
    assert_eq!(
        failed(validate_vault_entry_slots(
            &controllers,
            &v(&[&new_b]),
            &r.a.id()
        ))
        .code(),
        "malformed"
    );
    assert_eq!(
        failed(validate_vault_entry_slots(&controllers, &[], &r.a.id())).code(),
        "malformed"
    );
    // A self-slot adds slots naming only its signer and keeps everything else.
    let old = v(&[&r.sa]);
    let added = sealed_for(&r.b, 70, 8);
    validate_self_slot(&controllers, &old, &v(&[&r.sa, &added]), &r.b.id()).unwrap();
    for (name, after, signer) in [
        ("names another", v(&[&r.sa, &added]), r.a.id()),
        ("adds nothing", v(&[&r.sa]), r.b.id()),
        ("drops one", v(&[&added]), r.b.id()),
        ("not a controller", v(&[&r.sa, &added]), "5".repeat(32)),
    ] {
        assert_eq!(
            failed(validate_self_slot(&controllers, &old, &after, &signer)).code(),
            "malformed",
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// §8.3 previousVault and §17.1 the restricted open.

#[test]
fn previous_vault_is_sealed_to_the_new_vault_under_its_label() {
    let (old, new) = (seed(70), seed(71));
    let (old_pub, new_pub) = (old.public().unwrap(), new.public().unwrap());
    let sealed = old.seal_previous(&new, &mut Entropy::new([3; 32])).unwrap();
    // Whoever opens the new vault opens this.
    let reached = new
        .open_previous(&sealed, &old_pub, &default_account())
        .unwrap();
    assert_eq!(reached.public().unwrap(), old_pub);
    // The HPKE `info` and AAD are exactly the §8.3 label (checked with the 0.4 HPKE).
    let info = format!(
        "colophon/vault-previous/5\n{}\n{}",
        new_pub.id(),
        old_pub.id()
    );
    let dh = colophon_core::vault::derive([71; 32])
        .unwrap()
        .agree(&sealed.enc)
        .unwrap();
    let plain = SealedKey {
        enc: sealed.enc.clone(),
        ciphertext: sealed.ciphertext.clone(),
    }
    .finish_open(&new_pub.agreement, &dh, info.as_bytes())
    .unwrap();
    assert_eq!(plain, vec![70; 32]);
    // Any other old vault, any other new seed, and a swapped label fail as vaultLocked.
    locked(new.open_previous(&sealed, &vault_of(72), &default_account()));
    locked(seed(72).open_previous(&sealed, &old_pub, &default_account()));
    assert!(SealedKey {
        enc: sealed.enc.clone(),
        ciphertext: sealed.ciphertext.clone()
    }
    .finish_open(
        &new_pub.agreement,
        &dh,
        format!(
            "colophon/vault-previous/5\n{}\n{}",
            old_pub.id(),
            new_pub.id()
        )
        .as_bytes()
    )
    .is_err());
    // Chains: opening the new vault reaches the old, then the one before.
    let older = seed(69);
    let hop = older
        .seal_previous(&old, &mut Entropy::new([4; 32]))
        .unwrap();
    let step2 = reached
        .open_previous(&hop, &older.public().unwrap(), &default_account())
        .unwrap();
    assert_eq!(step2.public().unwrap(), older.public().unwrap());
    // H1 (the checker's first way in): the target is a seed the core holds, never a bare
    // public vault, and an opened seed is refused as a target. `reached` and `step2` are
    // opened seeds.
    let probe = seed(0x42);
    assert_eq!(
        failed(probe.seal_previous(&reached, &mut Entropy::new([3; 32]))).code(),
        "malformed"
    );
    assert!(!reached.is_new() && !step2.is_new() && new.is_new());
    // An opened seed can still be the *old* seed being sealed forward.
    let fresh = seed(0x77);
    reached
        .seal_previous(&fresh, &mut Entropy::new([5; 32]))
        .unwrap();
}

#[test]
fn the_host_opens_its_own_vault_seals_and_never_a_colophon_label() {
    let s = seed(70);
    let public = s.public().unwrap();
    let seal = |info: &[u8], plain: &[u8]| {
        let sealed =
            SealedKey::seal(&public.agreement, plain, info, &mut Entropy::new([8; 32])).unwrap();
        colophon_core::v05::vault::SealedBox {
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
        }
    };
    let backup = seal(b"galley.backup/1", b"a host backup key, longer than a seed");
    assert_eq!(
        s.open_host_format(&backup, b"galley.backup/1").unwrap(),
        b"a host backup key, longer than a seed"
    );
    // Wrong label: the AAD fails.
    locked(s.open_host_format(&backup, b"galley.backup/2"));
    // A colophon/ label is refused even when the seal is perfectly valid: the seed's own
    // slot-style seals, epoch seals and previousVault are the core's.
    for label in [
        &b"colophon/epoch/3\nx"[..],
        b"colophon/vault-previous/5\nx",
        b"colophon/vault-slot/4\nx",
        b"colophon/",
    ] {
        let sealed = seal(label, &[1; 32]);
        let f = failed(s.open_host_format(&sealed, label));
        assert_eq!(f, Failure::Refused(Reason::OutOfScope));
    }
    // A label that merely contains colophon/ later, or differs in case, is a host label.
    let other = seal(b"x/colophon/y", b"fine");
    assert_eq!(
        s.open_host_format(&other, b"x/colophon/y").unwrap(),
        b"fine"
    );
    // Another vault cannot open it, and bounds apply.
    locked(seed(71).open_host_format(&backup, b"galley.backup/1"));
    assert_eq!(
        failed(s.open_host_format(&backup, &vec![b'x'; 1025])).code(),
        "malformed"
    );
    let mut huge = backup.clone();
    huge.ciphertext = vec![0; 65_537];
    assert_eq!(
        failed(s.open_host_format(&huge, b"galley.backup/1")).code(),
        "malformed"
    );
    let mut short = backup.clone();
    short.ciphertext = vec![0; 15];
    assert_eq!(
        failed(s.open_host_format(&short, b"galley.backup/1")).code(),
        "malformed"
    );
    let mut bad_point = backup.clone();
    bad_point.enc = vec![4; 65];
    assert_eq!(
        failed(s.open_host_format(&bad_point, b"galley.backup/1")).code(),
        "malformed"
    );
    // A seal of the seed itself is just a 32-byte plaintext to the host; the host gets bytes it
    // sealed, not the core's.
    let own = seal(b"galley.seed-backup/1", &[70; 32]);
    assert_eq!(
        s.open_host_format(&own, b"galley.seed-backup/1").unwrap(),
        vec![70; 32]
    );
}

// ---------------------------------------------------------------------------------------------
// §7.3 Pairing and §7.4 moving the seed.

fn account(n: u8) -> AccountId {
    AccountId::parse(&format!("{n:064x}")).unwrap()
}

/// A confirmed pairing by the QR path, as both devices would hold it.
fn confirmed(acct: &AccountId, e: &[u8], nb: [u8; 32], na: [u8; 32]) -> ConfirmedPairing {
    QrJoiner::begin(acct, e, nb).unwrap().receive_nonce(na)
}
fn permit(limiter: &mut FailureLimiter) -> Permit {
    limiter.permit(1_000).unwrap()
}

#[test]
fn pairing_commit_then_reveal_both_sides() {
    let acct = account(1);
    let t = TransferKey::new([21; 32]).unwrap();
    let e = t.public();
    let (nb, na) = ([0xb1; 32], [0xa1; 32]);
    let mut limiter = FailureLimiter::new();
    // J commits first and reveals once; H sends nA only after the commitment.
    let (joiner, c) = Joiner::begin(&acct, &e, nb).unwrap();
    assert_eq!(c, commitment(&acct, &e, &nb).unwrap());
    let waiting = ExistingWaiting::receive_commitment(&acct, c, permit(&mut limiter));
    let (awaiting, sent) = waiting.send_nonce(na);
    assert_eq!(sent, na);
    let (reveal, j_code) = joiner.reveal(na).unwrap();
    assert_eq!((&reveal.e, reveal.nb), (&e, nb));
    let h_code = awaiting.finish(&reveal.e, &reveal.nb).unwrap();
    assert_eq!(h_code.digits(), j_code.digits());
    assert_eq!(h_code.digits(), code(&acct, &e, &na, &nb).unwrap());
    assert_eq!(h_code.digits().len(), 6);
    assert!(h_code.digits().bytes().all(|b| b.is_ascii_digit()));
    let hp = h_code.confirm();
    let jp = j_code.confirm();
    assert_eq!(hp, jp);
    assert_eq!(hp.transfer_info(), jp.transfer_info());
}

#[test]
fn pairing_aborts_on_a_substituted_key_or_nonce() {
    let acct = account(1);
    let e = TransferKey::new([21; 32]).unwrap().public();
    let attacker = TransferKey::new([22; 32]).unwrap().public();
    let (nb, na) = ([0xb1; 32], [0xa1; 32]);
    let (_, c) = Joiner::begin(&acct, &e, nb).unwrap();
    let mut limiter = FailureLimiter::new();
    let mut go = |e2: &[u8], nb2: &[u8; 32], other: &AccountId| {
        ExistingWaiting::receive_commitment(other, c, permit(&mut limiter))
            .send_nonce(na)
            .0
            .finish(e2, nb2)
    };
    assert_eq!(
        go(&attacker, &nb, &acct).unwrap_err(),
        PairingAbort::CommitmentMismatch
    );
    assert_eq!(
        go(&e, &[0x2d; 32], &acct).unwrap_err(),
        PairingAbort::CommitmentMismatch
    );
    assert_eq!(
        go(&e, &nb, &account(2)).unwrap_err(),
        PairingAbort::CommitmentMismatch
    );
    assert_eq!(
        go(&[4; 65], &nb, &acct).unwrap_err(),
        PairingAbort::InvalidPoint
    );
    assert!(go(&e, &nb, &acct).is_ok());
    assert_eq!(
        PairingAbort::CommitmentMismatch.to_string(),
        "abort: commitment mismatch"
    );
    let base = code(&acct, &e, &na, &nb).unwrap();
    assert_ne!(base, code(&acct, &e, &[0xa2; 32], &nb).unwrap());
}

/// M2: the limiter enforces. Before: no session step consulted it, a rejected code was not
/// recordable, and a clock moved back reopened the budget.
#[test]
fn the_failure_limiter_gates_sessions_and_records_every_failure() {
    let acct = account(1);
    let e = TransferKey::new([21; 32]).unwrap().public();
    let (nb, na) = ([0xb1; 32], [0xa1; 32]);
    let t0 = 1_000_000_000_i64;
    let mut limiter = FailureLimiter::new();
    // A substituted-E relay commits honestly: the person rejects the code, which records.
    for i in 0..5 {
        let permit = limiter.permit(t0 + i).unwrap();
        let em = TransferKey::new([30 + i as u8; 32]).unwrap().public();
        let (j, c) = Joiner::begin(&acct, &em, [i as u8; 32]).unwrap();
        let (h, sent) = ExistingWaiting::receive_commitment(&acct, c, permit).send_nonce(na);
        let (r, _) = j.reveal(sent).unwrap();
        let code = h.finish(&r.e, &r.nb).unwrap();
        code.reject(&mut limiter, t0 + i);
    }
    // The sixth session cannot start: no permit, so no session step is reachable.
    assert_eq!(limiter.permit(t0 + 10).unwrap_err(), LimitReached);
    assert!(!limiter.may_start(t0 + 10));
    // A clock moved back an hour does not reopen the budget.
    assert!(!limiter.may_start(t0 - 3_600_000));
    assert_eq!(limiter.permit(t0 - 7_200_000).unwrap_err(), LimitReached);
    // An abandoned session (a timeout) records too.
    let mut other = FailureLimiter::new();
    for i in 0..5 {
        other.permit(t0 + i).unwrap().abandon(&mut other, t0 + i);
    }
    assert!(other.permit(t0 + 6).is_err());
    // A mismatch records through `finish_limited`; a success does not.
    let mut third = FailureLimiter::new();
    let attacker = TransferKey::new([22; 32]).unwrap().public();
    let (_, c) = Joiner::begin(&acct, &e, nb).unwrap();
    let p = third.permit(t0).unwrap();
    let r = ExistingWaiting::receive_commitment(&acct, c, p)
        .send_nonce(na)
        .0
        .finish_limited(&attacker, &nb, &mut third, t0);
    assert!(r.is_err());
    let p = third.permit(t0).unwrap();
    ExistingWaiting::receive_commitment(&acct, c, p)
        .send_nonce(na)
        .0
        .finish_limited(&e, &nb, &mut third, t0)
        .unwrap();
    // One failure only; failures expire after an hour.
    for i in 1..5 {
        third.record_failure(t0 + i);
    }
    assert!(!third.may_start(t0 + 5));
    assert!(third.may_start(t0 + 3_600_005));
    // The ledger, with its latest time, is plain data the host persists.
    let json = serde_json::to_string(&limiter).unwrap();
    let back: FailureLimiter = serde_json::from_str(&json).unwrap();
    assert_eq!(back, limiter);
    assert!(!back.may_start(t0 - 3_600_000));
}

/// M1: the QR path and the code path are different session types. A code-flow `Joiner` has no
/// way to show its `nB`, so a relay cannot learn it before the commit-reveal order allows.
#[test]
fn the_qr_alternative_is_a_separate_session_with_both_nonces_and_no_code() {
    let acct = account(1);
    let t = TransferKey::new([21; 32]).unwrap();
    let (nb, na) = ([0xb1; 32], [0xa1; 32]);
    let mut limiter = FailureLimiter::new();
    let j = QrJoiner::begin(&acct, &t.public(), nb).unwrap();
    let qr = j.payload();
    let scanned = ScannedQr::scan(&acct, &qr, permit(&mut limiter)).unwrap();
    let (h, sent) = scanned.send_nonce(na);
    let jp = j.receive_nonce(sent);
    assert_eq!(h, jp);
    // Another account's QR is refused; so is a QR with an invalid point.
    assert_eq!(
        ScannedQr::scan(&account(2), &qr, permit(&mut limiter)).unwrap_err(),
        PairingAbort::WrongAccount
    );
    let mut bad = qr.clone();
    bad.e = vec![4; 65];
    assert_eq!(
        ScannedQr::scan(&acct, &bad, permit(&mut limiter)).unwrap_err(),
        PairingAbort::InvalidPoint
    );
    assert_eq!(
        QrJoiner::begin(&acct, &[4; 65], nb).unwrap_err(),
        PairingAbort::InvalidPoint
    );
}

#[test]
fn the_seed_moves_to_a_new_device_under_the_transfer_label() {
    let state = account_state();
    let acct = state.account().clone();
    let vault = vault_of(70);
    let device = TransferKey::new([21; 32]).unwrap();
    let e = device.public();
    let (nb, na) = ([0xb1; 32], [0xa1; 32]);
    let pairing = confirmed(&acct, &e, nb, na);
    // The exact info and AAD of §7.4.
    let expected = format!(
        "colophon/vault-transfer/5\n{}\n{}\n{}{}",
        acct,
        colophon_core::v05::ids::key_id(&e),
        "a1".repeat(32),
        "b1".repeat(32)
    );
    assert_eq!(pairing.transfer_info(), expected.clone().into_bytes());
    let sealed = seal_seed_for_transfer(&seed(70), &pairing, &mut Entropy::new([30; 32])).unwrap();
    // The new device opens it and checks the vault.
    let got = device.open_seed(&sealed, &pairing, &vault).unwrap();
    assert_eq!(got.public().unwrap(), vault);
    // Independent check of the label and the HPKE: E's scalar is the first valid scalar of
    // §7.5 over the device's entropy seed (the 0.4 entropy expansion, with the signing half
    // of a software key standing in for an agreement key).
    let scalar = Entropy::new([21; 32]).take::<32>().unwrap();
    let key = SoftwareKeys::from_scalars(&scalar, &scalar).unwrap();
    assert_eq!(key.public().agreement, e);
    let dh = key.agree(&sealed.enc).unwrap();
    let plain = SealedKey {
        enc: sealed.enc.clone(),
        ciphertext: sealed.ciphertext.clone(),
    }
    .finish_open(&e, &dh, expected.as_bytes())
    .unwrap();
    assert_eq!(plain, vec![70; 32]);
    // Wrong nonces, another key, another account, another vault: vaultLocked.
    for (name, other) in [
        ("na", confirmed(&acct, &e, nb, [0xa2; 32])),
        ("nb", confirmed(&acct, &e, [0xb2; 32], na)),
        ("account", confirmed(&account(2), &e, nb, na)),
        ("swapped nonces", confirmed(&acct, &e, na, nb)),
    ] {
        let r = device.open_seed(&sealed, &other, &vault);
        assert_eq!(
            r.unwrap_err(),
            Failure::Refused(Reason::VaultLocked),
            "{name}"
        );
    }
    locked(device.open_seed(&sealed, &pairing, &vault_of(71)));
    // A transfer key that is not E cannot use this pairing.
    let stranger = TransferKey::new([23; 32]).unwrap();
    assert_eq!(
        failed(stranger.open_seed(&sealed, &pairing, &vault)).code(),
        "malformed"
    );
    // A seal for another seed is vaultLocked against this vault.
    let wrong = seal_seed_for_transfer(&seed(71), &pairing, &mut Entropy::new([30; 32])).unwrap();
    locked(device.open_seed(&wrong, &pairing, &vault));
    // The new device then builds a slot with the opened seed, for a controller of the
    // verified keyring (here the account vector's device), and opens it with that key.
    let device_key = soft(11);
    let cid = device_key.id();
    let plan = SlotPlan {
        controllers: vec![cid.clone()],
        label: "Mac".into(),
    };
    let slot = SlotBuild::begin(
        &plan,
        &SlotTarget::verified(&state, &got).unwrap(),
        [31; 32],
    )
    .unwrap()
    .finish(&got, &[])
    .unwrap();
    open(
        &slot,
        &vault,
        &state.keyring().controllers,
        &[&device_key],
        0,
    )
    .unwrap();
}

/// H1, the checker's second way in. Before: `SlotBuild` took the caller's controller map, so a
/// `sealed` slot for a caller's raw key gave the caller the seed. Now an opened seed is only
/// sealed to controllers of the verifier's state.
#[test]
fn an_opened_seed_is_only_sealed_to_controllers_of_the_verified_keyring() {
    let state = account_state();
    // An opened seed: unlock the account's own slot with the device key.
    let device = soft(11);
    let slot = Slot::from_value(&state.keyring().slots[0]).unwrap();
    let opened = open_as(
        state.account(),
        &slot,
        &VaultPublic::from_pair(&state.keyring().vault),
        &state.keyring().controllers,
        &[&device],
        0,
    )
    .unwrap();
    assert!(!opened.is_new());
    let verified = SlotTarget::verified(&state, &opened).unwrap();
    // The attacker's raw key is not in the verified keyring: refused at `begin`.
    let mine = soft(0x99);
    let attacker = raw_controller(&mine, &["approve"], "mine");
    let plan = SlotPlan {
        controllers: vec![attacker.id()],
        label: "x".into(),
    };
    assert_eq!(
        failed(SlotBuild::begin(&plan, &verified, [3; 32])).code(),
        "malformed"
    );
    // The genesis route takes the caller's controllers but only a new seed: the opened seed is
    // refused at `finish`, and the caller cannot make the opened seed new.
    let map = map_of(&[&attacker]);
    let genesis = SlotTarget::genesis(&seed(70), &map).unwrap();
    let b = SlotBuild::begin(&plan, &genesis, [3; 32]).unwrap();
    assert_eq!(failed(b.finish(&opened, &[])).code(), "malformed");
    assert_eq!(
        failed(SlotTarget::genesis(&opened, &map)).code(),
        "malformed"
    );
    // The rotation route likewise needs the new seed, and keeps the verified controllers.
    assert_eq!(
        failed(SlotTarget::rotation(&state, &opened, &opened)).code(),
        "malformed"
    );
    let new_seed = seed(71);
    let rotation = SlotTarget::rotation(&state, &new_seed, &opened).unwrap();
    assert_eq!(
        failed(SlotBuild::begin(&plan, &rotation, [3; 32])).code(),
        "malformed"
    );
    let ok = SlotPlan {
        controllers: vec![device.id()],
        label: "Mac".into(),
    };
    let b = SlotBuild::begin(&ok, &rotation, [3; 32]).unwrap();
    // The opened seed is of the old vault, not the rotation's new one.
    locked(b.finish(&opened, &[]));
    SlotBuild::begin(&ok, &rotation, [3; 32])
        .unwrap()
        .finish(&new_seed, &[])
        .unwrap();
    // A verified-target build for the verified controller works with the opened seed.
    let ok_plan = SlotPlan {
        controllers: vec![device.id()],
        label: "Mac".into(),
    };
    SlotBuild::begin(&ok_plan, &verified, [4; 32])
        .unwrap()
        .finish(&opened, &[])
        .unwrap();
}

/// Entropy handling: a build resumes the entropy after the draws `begin` made, so building a
/// PRF slot twice from the same seed is reproducible.
#[test]
fn slot_builds_are_reproducible_from_their_entropy_seed() {
    let f = fixture();
    let a = build(&f, &[&f.ids[1], &f.ids[0]], 5).unwrap();
    let b = build(&f, &[&f.ids[1], &f.ids[0]], 5).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------------------------
// Fix round: M3, L2, L3.

/// M3 (the checker's probe): a controller that remains but was demoted or re-keyed, and had a
/// slot, is reported in `without_slot`, and still after the `vault` entry when the host carries
/// the list.
#[test]
fn a_remaining_demoted_or_rekeyed_controller_is_reported_without_a_slot() {
    let r = rot();
    let before = ring(&[&r.a, &r.b], &[&r.sa, &r.sb], &r.vault);
    // Demoted: B loses `recover` and its slot.
    let b_demoted = raw_controller(&soft(12), &["approve", "control"], "B");
    let after = ring(&[&r.a, &b_demoted], &[&r.sa], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.retiring);
    assert!(plan.without_slot.contains(&r.b.id()), "B is warned");
    // The vault entry (A's slot only): B still has none, carried from the earlier step.
    let new_seed = seed(71);
    let new_a = {
        let controllers = map_of(&[&r.a]);
        SlotBuild::begin(
            &SlotPlan {
                controllers: vec![r.a.id()],
                label: "A".into(),
            },
            &SlotTarget::genesis(&new_seed, &controllers).unwrap(),
            [3; 32],
        )
        .unwrap()
        .finish(&new_seed, &[])
        .unwrap()
    };
    let after2 = ring(&[&r.a, &b_demoted], &[&new_a], &new_seed.public().unwrap());
    let plan2 = plan_rotation(&after, &after2, &plan.without_slot).unwrap();
    assert!(plan2.vault_changed);
    assert!(
        plan2.without_slot.contains(&r.b.id()),
        "still warned after the rotation"
    );
    // Once B has a slot in the new vault it is no longer reported.
    let b_slot = {
        let controllers = map_of(&[&b_demoted]);
        SlotBuild::begin(
            &SlotPlan {
                controllers: vec![b_demoted.id()],
                label: "B".into(),
            },
            &SlotTarget::genesis(&new_seed, &controllers).unwrap(),
            [4; 32],
        )
        .unwrap()
        .finish(&new_seed, &[])
        .unwrap()
    };
    let after3 = ring(
        &[&r.a, &b_demoted],
        &[&new_a, &b_slot],
        &new_seed.public().unwrap(),
    );
    let plan3 = plan_rotation(&after2, &after3, &plan2.without_slot).unwrap();
    assert!(plan3.without_slot.is_empty());
    // Re-keyed (agreement changed) behaves the same.
    let b_rekeyed = Controller::parse(
        json!({"key": {"form": "raw", "signing": b64(r.b.key().signing()),
                       "agreement": b64(&soft(77).public().agreement)},
               "label": "B", "roles": ["approve", "control", "recover"]}),
        "c",
    )
    .unwrap();
    let after = ring(&[&r.a, &b_rekeyed], &[&r.sa], &r.vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.without_slot.contains(&r.b.id()));
}

/// L2: a controller that appears only inside a combined slot cannot build a `vault` entry
/// alone, so it is not a candidate signer.
#[test]
fn vault_signers_exclude_controllers_that_are_only_in_a_combined_slot() {
    let all = ["approve", "control", "recover"];
    let a = raw_controller(&soft(11), &all, "A");
    let d = raw_controller(&soft(14), &all, "D");
    let b = raw_controller(&soft(12), &all, "B");
    let c = raw_controller(&soft(13), &all, "C");
    let ctrls = map_of(&[&a, &b, &c, &d]);
    let new_seed = seed(70);
    let target = SlotTarget::genesis(&new_seed, &ctrls).unwrap();
    let one = |id: &Controller, e: u8| {
        SlotBuild::begin(
            &SlotPlan {
                controllers: vec![id.id()],
                label: "s".into(),
            },
            &target,
            [e; 32],
        )
        .unwrap()
        .finish(&new_seed, &[])
        .unwrap()
    };
    let combined = SlotBuild::begin(
        &SlotPlan {
            controllers: vec![b.id(), c.id()],
            label: "BC".into(),
        },
        &target,
        [9; 32],
    )
    .unwrap()
    .finish(&new_seed, &[])
    .unwrap();
    let (sa, sd) = (one(&a, 1), one(&d, 2));
    let vault = vault_of(70);
    let before = ring(&[&a, &b, &c, &d], &[&sa, &sd, &combined], &vault);
    // D is removed: its slot drops and the vault retires.
    let after = ring(&[&a, &b, &c], &[&sa, &combined], &vault);
    let plan = plan_rotation(&before, &after, &[]).unwrap();
    assert!(plan.retiring);
    assert_eq!(plan.vault_signers, vec![a.id()]);
}

/// L3: `refused:vaultLocked` is a `Reason`, so callers matching on `Failure` see it.
#[test]
fn vault_locked_is_a_reason() {
    let f = Failure::Refused(Reason::VaultLocked);
    assert_eq!(f.code(), "refused:vaultLocked");
    assert_eq!(Reason::VaultLocked.as_str(), "vaultLocked");
    let err = VaultSeed::check(&[1; 31], &vault_of(70), &default_account()).unwrap_err();
    assert_eq!(err, f);
}

/// §7.3 (revision 13): the QR payload is the canonical JSON of the closed object
/// `{"account","e","nB","protocol"}`; a reader refuses anything else.
#[test]
fn the_qr_payload_round_trips_as_canonical_json_and_refuses_everything_else() {
    use colophon_core::v05::pairing::QrPayload;
    let acct = account(1);
    let t = TransferKey::new([21; 32]).unwrap();
    let qr = QrJoiner::begin(&acct, &t.public(), [0xb1; 32])
        .unwrap()
        .payload();
    let bytes = qr.to_bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.starts_with(&format!("{{\"account\":\"{}\",\"e\":\"", acct.as_str())));
    assert!(text.ends_with("\",\"protocol\":\"colophon/pair-qr/5\"}"));
    assert!(text.contains(",\"nB\":\""));
    assert_eq!(QrPayload::from_bytes(&bytes).unwrap(), qr);
    // Refusals: another protocol, an extra or missing member, wrong lengths, a bad point,
    // non-canonical bytes, an account ID that is not 64 hex characters, and plain garbage.
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let with = |f: &dyn Fn(&mut Value)| {
        let mut x = v.clone();
        f(&mut x);
        colophon_core::v05::encoding::canonical(&x).unwrap()
    };
    let bads: Vec<Vec<u8>> = vec![
        with(&|x| x["protocol"] = json!("colophon/pair-qr/4")),
        with(&|x| x["extra"] = json!(1)),
        with(&|x| {
            x.as_object_mut().unwrap().remove("nB");
        }),
        with(&|x| x["nB"] = json!(b64(&[1u8; 31]))),
        with(&|x| x["e"] = json!(b64(&[4u8; 65]))),
        with(&|x| x["e"] = json!(b64(&[4u8; 64]))),
        with(&|x| x["account"] = json!("ab")),
        // Same members, keys out of order: not canonical.
        format!(
            "{{\"protocol\":\"colophon/pair-qr/5\",\"account\":\"{}\",\"e\":\"{}\",\"nB\":\"{}\"}}",
            acct.as_str(),
            v["e"].as_str().unwrap(),
            v["nB"].as_str().unwrap()
        )
        .into_bytes(),
        b"not json".to_vec(),
        b"[]".to_vec(),
    ];
    for (i, b) in bads.iter().enumerate() {
        assert!(
            QrPayload::from_bytes(b).is_err(),
            "bad payload {i} accepted"
        );
    }
}
