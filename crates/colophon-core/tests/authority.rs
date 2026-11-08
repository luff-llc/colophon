#![allow(clippy::unwrap_used)]
mod support;
use colophon_core::{
    authority::{Authority, Controller, Keyring, Role},
    crypto::{Entropy, PublicIdentity},
    hpke::SealedKey,
    keys::{testing::SyntheticAuthenticator, AuthorityEnvelope, Cosignature, KeyDescriptor},
    library::{Library, SignatureResult},
    model::*,
    records::{self, canonical, SignedRecord},
    slots::{self, Slot},
    vault,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::{keys, NOW};
const RP: &str = "id.luff.works";
struct Harness {
    records: Records,
    controllers: Vec<Controller>,
}
fn raw(n: u8, roles: Vec<Role>) -> Controller {
    let p = keys(n).public();
    Controller {
        key: KeyDescriptor::Raw {
            signing: p.signing,
            agreement: Some(p.agreement),
        },
        label: format!("raw {n}"),
        roles,
        verification: None,
    }
}
fn passkey(roles: Vec<Role>) -> Controller {
    Controller {
        key: SyntheticAuthenticator::new()
            .unwrap()
            .descriptor(RP, Some(vec!["android:apk-key-hash:test".into()]))
            .unwrap(),
        label: "Passkey".into(),
        roles,
        verification: None,
    }
}
fn all() -> Vec<Role> {
    vec![Role::Approve, Role::Control, Role::Recover]
}
fn slot(v: &PublicIdentity, c: &Controller, seed: [u8; 32]) -> Slot {
    if c.key.is_webauthn() {
        Slot::from_prf(
            &seed,
            &v.id(),
            &c.id(),
            &c.label,
            &[6; 32],
            &[7; 32],
            &mut Entropy::new([8; 32]),
        )
        .unwrap()
    } else {
        Slot::seal(
            &seed,
            &v.id(),
            &c.id(),
            &c.label,
            c.key.agreement().unwrap(),
            &mut Entropy::new([9; 32]),
        )
        .unwrap()
    }
}
fn sign(c: &Controller, body: &[u8]) -> SignatureResult {
    if c.key.is_webauthn() {
        let a = SyntheticAuthenticator::new()
            .unwrap()
            .assertion(body, RP, "https://a.b.id.luff.works", 5, true)
            .unwrap();
        SignatureResult {
            signature: a.signature,
            assertion: Some(a.assertion),
        }
    } else {
        let k = (1..=250)
            .map(keys)
            .find(|k| k.public().id() == c.id())
            .unwrap();
        SignatureResult {
            signature: k.sign(body),
            assertion: None,
        }
    }
}
impl Harness {
    fn new(controllers: Vec<Controller>, threshold: u64, recover: u64) -> Self {
        let mut sorted = controllers.clone();
        sorted.sort_by_key(Controller::id);
        let vault = vault::derive([70; 32]).unwrap().public();
        let slots = sorted.iter().map(|c| slot(&vault, c, [70; 32])).collect();
        let k = Keyring {
            controllers: sorted,
            threshold,
            recover_threshold: recover,
            vault,
            slots,
        };
        let mut h = Self {
            records: Records::new(),
            controllers,
        };
        let signers: Vec<_> = h
            .controllers
            .iter()
            .enumerate()
            .filter(|(_, c)| c.roles.contains(&Role::Control))
            .map(|(i, _)| i)
            .collect();
        h.push(
            json!({"kind":"genesis","label":"Library","namespaces":["notes"],"keyring":k}),
            &signers,
        );
        h
    }
    fn default() -> Self {
        Self::new(vec![raw(11, all())], 1, 1)
    }
    fn state(&self) -> Authority {
        Authority::replay(&self.records).unwrap()
    }
    fn value(&self, action: Value, primary: usize) -> Value {
        let seq = self.records.len() + 1;
        let previous = self
            .records
            .values()
            .next_back()
            .map(|raw| records::digest(&AuthorityEnvelope::from_json(raw).unwrap().body));
        let mut v = action;
        for (key, value) in [
            ("protocol", json!(colophon_core::protocol::AUTHORITY)),
            ("seq", json!(seq)),
            ("previous", json!(previous)),
            ("issued", json!(NOW)),
            ("by", json!(self.controllers[primary].id())),
        ] {
            v[key] = value;
        }
        v
    }
    fn envelope(&self, v: &Value, signers: &[usize]) -> AuthorityEnvelope {
        let body = canonical(v).unwrap();
        let primary = sign(&self.controllers[signers[0]], &body);
        let mut cs: Vec<_> = signers[1..]
            .iter()
            .map(|i| {
                let c = &self.controllers[*i];
                let s = sign(c, &body);
                Cosignature::new(c.id(), s.signature, s.assertion)
            })
            .collect();
        cs.sort_by(|a, b| a.signer.cmp(&b.signer));
        AuthorityEnvelope::new(
            body,
            primary.signature,
            primary.assertion,
            if cs.is_empty() { None } else { Some(cs) },
        )
        .unwrap()
    }
    fn push(&mut self, action: Value, signers: &[usize]) {
        let v = self.value(action, signers[0]);
        let env = self.envelope(&v, signers);
        self.records.insert(
            format!("authority/{:08}.json", self.records.len() + 1),
            env.encode().unwrap(),
        );
    }
    fn outcome(&self, action: Value, signers: &[usize]) -> String {
        let v = self.value(action, signers[0]);
        self.outcome_value(v, signers)
    }
    fn outcome_value(&self, v: Value, signers: &[usize]) -> String {
        let env = self.envelope(&v, signers);
        self.outcome_envelope(env)
    }
    fn outcome_envelope(&self, env: AuthorityEnvelope) -> String {
        let mut r = self.records.clone();
        r.insert(
            format!("authority/{:08}.json", r.len() + 1),
            env.encode().unwrap(),
        );
        match Authority::replay(&r) {
            Ok(_) => "accept".into(),
            Err(e) => e.0.split(':').next().unwrap().to_owned(),
        }
    }
    fn epoch(&self, vault: &PublicIdentity, n: u64) -> Epoch {
        let mut recipients = vec![vault.clone()];
        if self.records.len() > 1 {
            recipients.extend(
                self.state()
                    .members
                    .into_values()
                    .filter(|m| m.member.revoked_at.is_none())
                    .map(|m| m.public),
            );
        }
        Epoch {
            namespace: "notes".into(),
            epoch: n,
            seals: recipients
                .into_iter()
                .map(|p| {
                    let seal = SealedKey::seal(
                        &p.agreement,
                        &[n as u8; 32],
                        &colophon_core::authority::key_info(&self.state().id, "notes", n, &p.id()),
                        &mut Entropy::new([n as u8 + 30; 32]),
                    )
                    .unwrap();
                    (p.id(), seal)
                })
                .collect(),
        }
    }
    fn rekey(&mut self) {
        let e = self.epoch(&self.state().keyring.vault, 1);
        self.push(json!({"kind":"rekey","epochs":[e]}), &[0]);
        assert_eq!(self.state().latest, 2);
    }
    fn request(&self, member: PublicIdentity, kind: MemberKind) -> Vec<u8> {
        let r = Request {
            protocol: colophon_core::protocol::REQUEST.into(),
            library_id: self.state().id,
            member: member.clone(),
            label: "Member".into(),
            kind,
            namespaces: vec!["notes".into()],
            access: vec![Access::Read, Access::Write],
            created: NOW.into(),
        };
        let body = canonical(&r).unwrap();
        let signer = (1..=250)
            .map(keys)
            .find(|k| k.public().id() == member.id())
            .unwrap();
        SignedRecord {
            signature: signer.sign(&body),
            body,
        }
        .encode()
        .unwrap()
    }
    fn grant(&self, member: PublicIdentity, kind: MemberKind, import: bool) -> Value {
        let mut grant = json!({"namespaces":["notes"],"access":["read","write"]});
        if import {
            grant["import"] = json!(true);
            grant["expires"] = json!("2027-01-01T00:00:00Z");
        }
        let shares = self.state().epochs["notes"]
            .keys()
            .map(|n| Epoch {
                namespace: "notes".into(),
                epoch: *n,
                seals: BTreeMap::from([(
                    member.id(),
                    SealedKey::seal(
                        &member.agreement,
                        &[*n as u8; 32],
                        &colophon_core::authority::key_info(
                            &self.state().id,
                            "notes",
                            *n,
                            &member.id(),
                        ),
                        &mut Entropy::new([50; 32]),
                    )
                    .unwrap(),
                )]),
            })
            .collect::<Vec<_>>();
        use base64::Engine;
        json!({"kind":"grant","request":base64::engine::general_purpose::STANDARD.encode(self.request(member,kind)),"grant":grant,"shares":shares})
    }
    fn rotation(&self, mut k: Keyring, seed: [u8; 32]) -> Value {
        k.vault = vault::derive(seed).unwrap().public();
        k.slots = k
            .controllers
            .iter()
            .map(|c| slot(&k.vault, c, seed))
            .collect();
        let shares = self.state().epochs["notes"]
            .keys()
            .map(|n| Epoch {
                namespace: "notes".into(),
                epoch: *n,
                seals: BTreeMap::from([(
                    k.vault.id(),
                    SealedKey::seal(
                        &k.vault.agreement,
                        &[*n as u8; 32],
                        &colophon_core::authority::key_info(
                            &self.state().id,
                            "notes",
                            *n,
                            &k.vault.id(),
                        ),
                        &mut Entropy::new([51; 32]),
                    )
                    .unwrap(),
                )]),
            })
            .collect::<Vec<_>>();
        let e = self.epoch(
            &k.vault,
            self.state().epoch_at("notes", self.state().latest).unwrap() + 1,
        );
        json!({"kind":"keyring","keyring":k,"shares":shares,"epochs":[e]})
    }
}
#[test]
fn authority_genesis_raw_threshold_two_and_genesis_only_accept() {
    assert_eq!(Harness::default().state().members.len(), 0);
    let h = Harness::new(vec![raw(11, all()), passkey(all())], 2, 2);
    assert_eq!(h.state().latest, 1);
    assert!(h.state().epochs.is_empty());
    let h = Harness::new(vec![raw(11, all()), raw(12, vec![Role::Recover])], 1, 2);
    assert_eq!(h.state().keyring.recover_threshold, 2);
}
#[test]
fn authority_seq_two_full_rekey_accept_and_malformed_cases() {
    let mut h = Harness::default();
    for a in [
        json!({"kind":"layout","layout":2}),
        json!({"kind":"rekey","epochs":[]}),
        json!({"kind":"rekey","epochs":[h.epoch(&h.state().keyring.vault,2)]}),
    ] {
        assert_eq!(h.outcome(a, &[0]), "malformed");
    }
    h.rekey();
    assert_eq!(h.state().latest, 2);
    assert_eq!(
        h.outcome(json!({"kind":"rekey","epochs":[]}), &[0]),
        "malformed"
    );
    let mut v = h.value(json!({"kind":"layout","layout":2}), 0);
    v["protocol"] = json!("colophon/authority/3");
    assert_eq!(h.outcome_value(v, &[0]), "malformed");
}
#[test]
fn authority_rules_threshold_mixed_single_and_extra_cosignature_bad_signature() {
    let mut h = Harness::new(
        vec![raw(11, all()), raw(12, all()), raw(13, vec![Role::Approve])],
        2,
        2,
    );
    h.rekey();
    assert_eq!(
        h.outcome(json!({"kind":"layout","layout":2}), &[0]),
        "badSignature"
    );
    assert_eq!(
        h.outcome(json!({"kind":"layout","layout":2}), &[0, 2]),
        "badSignature"
    );
    assert_eq!(
        h.outcome(
            json!({"kind":"rekey","epochs":[h.epoch(&h.state().keyring.vault,2)]}),
            &[0, 1]
        ),
        "badSignature"
    );
    let v = h.value(json!({"kind":"layout","layout":2}), 0);
    let mut e = h.envelope(&v, &[0, 1]);
    e.cosignatures.as_mut().unwrap()[0].signature[0] ^= 1;
    assert_eq!(h.outcome_envelope(e), "badSignature");
    assert_eq!(
        h.outcome(json!({"kind":"layout","layout":2}), &[0, 1]),
        "accept"
    );
    let mut h = Harness::new(vec![raw(11, vec![Role::Control])], 1, 0);
    h.rekey();
    assert_eq!(
        h.outcome(
            json!({"kind":"rekey","epochs":[h.epoch(&h.state().keyring.vault,2)]}),
            &[0]
        ),
        "accept"
    );
}
#[test]
fn authority_unknown_content_authorized_newer_format_otherwise_bad_signature() {
    let mut h = Harness::new(
        vec![raw(11, all()), raw(12, all()), raw(13, vec![Role::Approve])],
        2,
        2,
    );
    h.rekey();
    for signers in [&[0][..], &[2][..]] {
        assert_eq!(h.outcome(json!({"kind":"future"}), signers), "badSignature");
    }
    assert_eq!(h.outcome(json!({"kind":"future"}), &[0, 1]), "newerFormat");
    let mut k = serde_json::to_value(&h.state().keyring).unwrap();
    k["controllers"][0]["future"] = json!(true);
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[2]),
        "badSignature"
    );
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[0, 1]),
        "newerFormat"
    );
    for f in ["future", "roles", "key", "slots"] {
        let mut k = serde_json::to_value(&h.state().keyring).unwrap();
        match f {
            "roles" => k["controllers"][0]["roles"] = json!(["future"]),
            "key" => k["controllers"][0]["key"]["form"] = json!("future"),
            "slots" => k["slots"][0]["kind"] = json!("future"),
            _ => k["future"] = json!(1),
        };
        assert_eq!(
            h.outcome(json!({"kind":"keyring","keyring":k}), &[0, 1]),
            "newerFormat",
            "{f}"
        );
    }
}
#[test]
fn authority_recovery_add_approve_only_accept_and_forbidden_changes_bad_signature() {
    let mut h = Harness::new(vec![raw(11, all()), raw(12, vec![Role::Control])], 2, 1);
    h.rekey();
    let mut k = h.state().keyring;
    k.controllers.push(raw(13, vec![Role::Approve]));
    k.controllers.sort_by_key(Controller::id);
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
        "accept"
    );
    for change in [
        "control",
        "remove",
        "demote",
        "threshold",
        "recoverThreshold",
        "vault",
        "label",
        "slotLabel",
        "duplicateSlot",
    ] {
        let mut next = serde_json::to_value(&k).unwrap();
        match change {
            "control" => {
                let i = k
                    .controllers
                    .iter()
                    .position(|c| c.id() == keys(13).public().id())
                    .unwrap();
                next["controllers"][i]["roles"] = json!(["control"]);
            }
            "remove" => {
                next["controllers"].as_array_mut().unwrap().remove(0);
            }
            "demote" => next["controllers"][0]["roles"] = json!(["approve"]),
            "threshold" => next["threshold"] = json!(1),
            "recoverThreshold" => next["recoverThreshold"] = json!(0),
            "vault" => next["vault"] = json!(vault::derive([71; 32]).unwrap().public()),
            "label" => next["controllers"][0]["label"] = json!("changed"),
            "slotLabel" => next["slots"][0]["label"] = json!("changed"),
            _ => {
                next["slots"].as_array_mut().unwrap().pop();
            }
        }
        assert_eq!(
            h.outcome(json!({"kind":"keyring","keyring":next}), &[0]),
            "badSignature",
            "{change}"
        );
    }
    let mut zero = Harness::new(
        vec![
            raw(11, vec![Role::Approve, Role::Control]),
            raw(12, vec![Role::Approve]),
        ],
        1,
        0,
    );
    zero.rekey();
    assert_eq!(
        zero.outcome(
            json!({"kind":"keyring","keyring":zero.state().keyring}),
            &[1]
        ),
        "badSignature"
    );
}
#[test]
fn authority_slots_multiset_relabel_reorder_accept_deletion_requires_rotation() {
    let mut h = Harness::default();
    h.rekey();
    let mut k = h.state().keyring;
    k.slots.push(k.slots[0].clone());
    h.push(json!({"kind":"keyring","keyring":k}), &[0]);
    h.state();
    let mut k = h.state().keyring;
    k.slots.reverse();
    if let Slot::Sealed { label, .. } = &mut k.slots[0] {
        *label = "renamed".into();
    }
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
        "accept"
    );
    k.slots.pop();
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
        "malformed"
    );
    assert_eq!(
        h.outcome(
            json!({"kind":"keyring","keyring":h.state().keyring,"shares":[]}),
            &[0]
        ),
        "malformed"
    );
    // A recovery quorum cannot drop even one duplicate route.
    let mut h = Harness::new(vec![raw(11, all()), raw(12, vec![Role::Control])], 2, 1);
    h.rekey();
    let mut k = h.state().keyring;
    k.slots.push(k.slots[0].clone());
    h.push(json!({"kind":"keyring","keyring":k}), &[0, 1]);
    h.state();
    let mut k = h.state().keyring;
    k.slots.pop();
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
        "badSignature"
    );
}
#[test]
fn authority_removal_demotion_agreement_change_rotation_and_vault_reuse() {
    let mut h = Harness::new(vec![raw(11, all()), raw(12, all())], 1, 1);
    h.rekey();
    for change in ["remove", "demote", "agreement", "slot"] {
        let mut k = h.state().keyring;
        match change {
            "remove" => {
                k.controllers.retain(|c| c.id() != keys(12).public().id());
                k.slots
                    .retain(|s| !s.controllers().contains(&keys(12).public().id()));
            }
            "demote" => {
                k.controllers
                    .iter_mut()
                    .find(|c| c.id() == keys(12).public().id())
                    .unwrap()
                    .roles = vec![Role::Approve]
            }
            "agreement" => {
                let c = k
                    .controllers
                    .iter_mut()
                    .find(|c| c.id() == keys(12).public().id())
                    .unwrap();
                if let KeyDescriptor::Raw { agreement, .. } = &mut c.key {
                    *agreement = Some(keys(14).public().agreement);
                }
            }
            _ => {
                k.slots.pop();
            }
        }
        assert_eq!(
            h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
            "malformed",
            "{change}"
        );
        assert_eq!(
            h.outcome(h.rotation(k, [71; 32]), &[0]),
            "accept",
            "{change}"
        );
    }
    let a = h.rotation(h.state().keyring, [71; 32]);
    h.push(a, &[0]);
    assert_eq!(
        h.state().keyring.vault,
        vault::derive([71; 32]).unwrap().public()
    );
    assert_eq!(
        h.outcome(h.rotation(h.state().keyring, [70; 32]), &[0]),
        "malformed"
    );
    // The fresh vault can actually decrypt historical epoch 1.
    let state = h.state();
    let v = vault::derive([71; 32]).unwrap();
    let seal = &state.epochs["notes"][&1].1.seals[&v.public().id()];
    assert_eq!(
        seal.finish_open(
            &v.public().agreement,
            &v.agree(&seal.enc).unwrap(),
            &state.key_info("notes", 1, &v.public().id())
        )
        .unwrap(),
        [1; 32]
    );
}
#[test]
fn authority_key_principals_collisions_malformed_across_history() {
    let mut h = Harness::default();
    h.rekey();
    assert_eq!(
        h.outcome(h.grant(keys(11).public(), MemberKind::Device, false), &[0]),
        "malformed"
    );
    let vault = h.state().keyring.vault;
    let mut m = keys(14).public();
    m.agreement = vault.agreement;
    assert_eq!(
        h.outcome(h.grant(m, MemberKind::Device, false), &[0]),
        "malformed"
    );
    for collision in ["agreement", "usage"] {
        let mut k = h.state().keyring;
        let mut c = raw(12, vec![Role::Approve]);
        if let KeyDescriptor::Raw { signing, agreement } = &mut c.key {
            *agreement = Some(if collision == "usage" {
                signing.clone()
            } else {
                keys(11).public().agreement
            });
        }
        k.controllers.push(c);
        k.controllers.sort_by_key(Controller::id);
        assert_eq!(
            h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
            "malformed"
        );
    }
    let old = raw(12, vec![Role::Approve]);
    let mut k = h.state().keyring;
    k.controllers.push(old.clone());
    k.controllers.sort_by_key(Controller::id);
    h.push(json!({"kind":"keyring","keyring":k}), &[0]);
    h.state();
    let mut k = h.state().keyring;
    k.controllers.retain(|c| c.id() != old.id());
    let a = h.rotation(k, [71; 32]);
    h.push(a, &[0]);
    h.state();
    let mut k = h.state().keyring;
    k.controllers.push(old);
    k.controllers.sort_by_key(Controller::id);
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
        "malformed"
    );
}
#[test]
fn authority_import_grant_control_accept_and_constraints_named_outcomes() {
    let mut h = Harness::new(
        vec![raw(11, all()), raw(12, vec![Role::Approve]), passkey(all())],
        2,
        2,
    );
    h.rekey();
    let g = h.grant(keys(14).public(), MemberKind::App, true);
    assert_eq!(h.outcome(g.clone(), &[0, 2]), "accept");
    assert_eq!(h.outcome(g.clone(), &[1]), "badSignature");
    for kind in [MemberKind::Agent, MemberKind::Server] {
        assert_eq!(
            h.outcome(h.grant(keys(14).public(), kind, true), &[0, 2]),
            "malformed"
        );
    }
    for field in ["readOnly", "expiry", "missingExpiry", "false"] {
        let mut g = g.clone();
        match field {
            "readOnly" => g["grant"]["access"] = json!(["read"]),
            "expiry" => g["grant"]["expires"] = json!(NOW),
            "false" => g["grant"]["import"] = json!(false),
            _ => {
                g["grant"].as_object_mut().unwrap().remove("expires");
            }
        };
        assert_eq!(h.outcome(g, &[0, 2]), "malformed", "{field}");
    }
    assert_eq!(
        h.outcome(h.grant(keys(14).public(), MemberKind::Device, false), &[2]),
        "accept"
    );
}
#[test]
fn authority_webauthn_every_attached_failure_bad_signature() {
    let mut h = Harness::new(vec![passkey(all())], 1, 1);
    h.rekey();
    let v = h.value(json!({"kind":"layout","layout":2}), 0);
    let valid = h.envelope(&v, &[0]);
    assert_eq!(h.outcome_envelope(valid.clone()), "accept");
    let a = valid.assertion.clone().unwrap();
    let auth = SyntheticAuthenticator::new().unwrap();
    for case in [
        "challenge",
        "rp",
        "origin",
        "userinfo",
        "port",
        "crossOrigin",
        "create",
        "UP",
        "UV",
        "duplicate",
        "longDER",
        "paddingDER",
        "trailingDER",
        "foreignKey",
    ] {
        let mut env = valid.clone();
        let mut data: Value = serde_json::from_slice(&a.client_data).unwrap();
        let mut ad = a.authenticator_data.clone();
        match case {
            "challenge" => data["challenge"] = json!("wrong"),
            "rp" => ad[0] ^= 1,
            "origin" => data["origin"] = json!("https://foreign.example"),
            "userinfo" => data["origin"] = json!("https://u@id.luff.works"),
            "port" => data["origin"] = json!("https://id.luff.works:443"),
            "crossOrigin" => data["crossOrigin"] = json!(true),
            "create" => data["type"] = json!("webauthn.create"),
            "UP" => ad[32] = 4,
            "UV" => ad[32] = 1,
            _ => {}
        }
        let client = if case == "duplicate" {
            b"{\"type\":\"webauthn.get\",\"type\":\"webauthn.get\"}".to_vec()
        } else {
            canonical(&data).unwrap()
        };
        let signed = if case == "foreignKey" {
            SyntheticAuthenticator::from_scalar(&[2; 32])
                .unwrap()
                .sign_bytes(ad, client, false)
                .unwrap()
        } else {
            auth.sign_bytes(ad, client, true).unwrap()
        };
        env.signature = signed.signature;
        env.assertion = Some(signed.assertion);
        match case {
            "longDER" => {
                env.signature.insert(1, 0x81);
            }
            "paddingDER" => {
                env.signature.insert(4, 0);
            }
            "trailingDER" => env.signature.push(0),
            _ => {}
        }
        assert_eq!(h.outcome_envelope(env), "badSignature", "{case}");
    }
    let signed = auth
        .assertion(&valid.body, RP, "android:apk-key-hash:test", 5, true)
        .unwrap();
    let mut env = valid;
    env.signature = signed.signature;
    env.assertion = Some(signed.assertion);
    assert_eq!(h.outcome_envelope(env), "accept");
}
#[test]
fn authority_closed_schemas_slots_and_imported_from_malformed() {
    let mut h = Harness::default();
    h.rekey();
    let k = serde_json::to_value(h.state().keyring).unwrap();
    for case in [
        "emptyCombined",
        "oneCombined",
        "duplicateControllers",
        "rawPRF",
        "wrongSize",
        "null",
        "rp",
        "origins",
    ] {
        let mut k = k.clone();
        let id = keys(11).public().id();
        match case {
            "emptyCombined" | "oneCombined" | "duplicateControllers" => {
                let ids = match case {
                    "emptyCombined" => vec![],
                    "oneCombined" => vec![id.clone()],
                    _ => vec![id.clone(), id.clone()],
                };
                let parts = ids
                    .iter()
                    .map(|_| json!({"kind":"sealed","sealed":k["slots"][0]["sealed"]}))
                    .collect::<Vec<_>>();
                k["slots"] = json!([{"kind":"combined","controllers":ids,"label":"Combined","parts":parts,"box":base64_bytes(&[0;60])}]);
            }
            "rawPRF" => {
                k["slots"] = json!([{"kind":"prf","controllers":[id],"label":"PRF","salt":base64_bytes(&[1;32]),"box":base64_bytes(&[0;60])}])
            }
            "wrongSize" => k["slots"][0]["sealed"]["ciphertext"] = json!(base64_bytes(&[0; 47])),
            "null" => k["controllers"][0]["verification"] = Value::Null,
            "rp" | "origins" => {
                let mut c = serde_json::to_value(passkey(vec![Role::Approve])).unwrap();
                if case == "rp" {
                    c["key"]["rp"] = json!("-id.luff.works");
                } else {
                    c["key"]["origins"] = json!(["https:example"]);
                }
                k["controllers"].as_array_mut().unwrap().push(c);
                k["controllers"].as_array_mut().unwrap().sort_by_key(|c| {
                    records::id(&base64_decode(c["key"]["signing"].as_str().unwrap()))
                });
            }
            _ => {}
        }
        assert_eq!(
            h.outcome(json!({"kind":"keyring","keyring":k}), &[0]),
            "malformed",
            "{case}"
        );
    }
    for bad in ["X".repeat(32), "a".repeat(31), "g".repeat(32)] {
        let mut r = Harness::default();
        let raw = r.records.values().next().unwrap();
        let env = AuthorityEnvelope::from_json(raw).unwrap();
        let mut v: Value = serde_json::from_slice(&env.body).unwrap();
        v["importedFrom"] = json!(bad);
        let e = r.envelope(&v, &[0]);
        r.records
            .insert("authority/00000001.json".into(), e.encode().unwrap());
        assert!(Authority::replay(&r.records)
            .unwrap_err()
            .0
            .starts_with("malformed"));
    }
}
fn base64_bytes(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}
#[test]
fn authority_duplicate_body_empty_cosignatures_and_raw_member_envelopes_malformed() {
    let mut h = Harness::default();
    h.rekey();
    let v = h.value(json!({"kind":"layout","layout":2}), 0);
    let mut e = h.envelope(&v, &[0]);
    e.body = String::from_utf8(e.body)
        .unwrap()
        .replacen("\"layout\":2", "\"layout\":2,\"layout\":2", 1)
        .into_bytes();
    e.signature = keys(11).sign(&e.body);
    let mut r = h.records.clone();
    r.insert("authority/00000003.json".into(), canonical(&e).unwrap());
    assert!(Authority::replay(&r)
        .unwrap_err()
        .0
        .starts_with("malformed"));
    let mut value = serde_json::to_value(h.envelope(&v, &[0])).unwrap();
    value["cosignatures"] = json!([]);
    assert!(AuthorityEnvelope::from_json(&canonical(&value).unwrap())
        .unwrap_err()
        .0
        .starts_with("malformed"));
    for f in ["assertion", "cosignatures"] {
        let mut v = json!({"body":base64_bytes(b"{}"),"signature":base64_bytes(&[0;64])});
        v[f] = json!([]);
        assert!(
            colophon_core::authority::raw_record(&canonical(&v).unwrap())
                .unwrap_err()
                .0
                .starts_with("malformed")
        );
    }
}
#[test]
fn authority_cose_registration_malformed_cases() {
    let mut valid = vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20];
    let key = keys(11).public().signing;
    valid.extend(&key[1..33]);
    valid.extend([0x22, 0x58, 0x20]);
    valid.extend(&key[33..]);
    assert!(colophon_core::keys::cose::parse(&valid).is_ok());
    for case in ["extra", "duplicate", "trailing"] {
        let mut b = valid.clone();
        match case {
            "extra" => {
                b[0] = 0xa6;
                b.extend([4, 0]);
            }
            "duplicate" => {
                b[0] = 0xa6;
                b.extend([1, 2]);
            }
            _ => b.push(0),
        };
        assert!(
            colophon_core::keys::cose::parse(&b)
                .unwrap_err()
                .0
                .starts_with("malformed"),
            "{case}"
        );
    }
}
#[test]
fn authority_library_creation_unlock_prf_get_and_failure_atomicity() {
    let (mut lib, member, _) = support::create();
    assert_eq!(lib.authority().latest, 4);
    assert_eq!(lib.authority().members.len(), 1);
    assert_ne!(
        lib.authority().keyring.controllers[0].id(),
        member.public().id()
    );
    let before = lib.records().clone();
    let key = SyntheticAuthenticator::new()
        .unwrap()
        .descriptor(RP, None)
        .unwrap();
    let pending = lib.begin_prf_slot(key.clone(), [91; 32]).unwrap();
    let auth = SyntheticAuthenticator::new().unwrap();
    let mut client = json!({"type":"webauthn.get","challenge":pending.challenge,"origin":"https://id.luff.works"});
    use sha2::{Digest, Sha256};
    let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
    ad.extend([5, 0, 0, 0, 0]);
    client["type"] = json!("webauthn.create");
    let signed = auth
        .sign_bytes(ad.clone(), canonical(&client).unwrap(), false)
        .unwrap();
    assert!(lib
        .finish_prf_slot(
            pending,
            SignatureResult {
                signature: signed.signature,
                assertion: Some(signed.assertion)
            },
            &[8; 32],
            "New",
            [92; 32]
        )
        .unwrap_err()
        .0
        .starts_with("badSignature"));
    let pending = lib.begin_prf_slot(key.clone(), [93; 32]).unwrap();
    client["type"] = json!("webauthn.get");
    client["challenge"] = json!(pending.challenge);
    let signed = auth
        .sign_bytes(ad, canonical(&client).unwrap(), false)
        .unwrap();
    let slot = lib
        .finish_prf_slot(
            pending,
            SignatureResult {
                signature: signed.signature,
                assertion: Some(signed.assertion),
            },
            &[8; 32],
            "New",
            [94; 32],
        )
        .unwrap();
    // Publishing the checked route under a descriptor with the same signing point but another
    // credential (or relying party) is refused: the check binds the whole descriptor.
    let substituted = match key.clone() {
        KeyDescriptor::WebAuthn {
            signing, rp, origins, ..
        } => KeyDescriptor::WebAuthn {
            signing,
            rp,
            credential: vec![0xEE; 16],
            origins,
        },
        other => panic!("expected a WebAuthn descriptor, got {other:?}"),
    };
    let swapped = Controller {
        key: substituted,
        label: "New".into(),
        roles: vec![Role::Approve],
        verification: None,
    };
    let refused = lib
        .begin_add_passkey(swapped, slot.clone(), &[keys(201).public().id()], NOW)
        .err()
        .map(|e| e.0)
        .unwrap_or_default();
    assert!(refused.starts_with("malformed"), "{refused}");
    let c = Controller {
        key,
        label: "New".into(),
        roles: vec![Role::Approve],
        verification: None,
    };
    let p = lib
        .begin_add_passkey(c, slot, &[keys(201).public().id()], NOW)
        .unwrap();
    support::apply(&mut lib, p, &member);
    assert_eq!(lib.authority().keyring.controllers.len(), 2);
    assert_eq!(lib.authority().keyring.slots.len(), 2);
    assert_eq!(
        lib.finish_unlock_slot(1, &[slots::OpeningSecret::Prf(&[9; 32])])
            .unwrap_err()
            .0,
        "vaultLocked"
    );
    // The previous unlocked seed survives a failed slot open.
    assert!(matches!(
        lib.begin_rekey(&["notes".into()], NOW, [95; 32]).unwrap(),
        Outcome::Success { .. }
    ));
    assert_ne!(lib.records(), &before);
    let foreign = vault::derive([99; 32]).unwrap().public();
    assert_eq!(
        vault::check_seed(&[202; 32], &foreign).unwrap_err().0,
        "vaultLocked"
    );
    let locked = Library::open(lib.records().clone(), member.public()).unwrap();
    assert!(locked.begin_prf_slot(passkey(all()).key, [96; 32]).is_err());
}
#[test]
fn authority_slot_opening_sealed_prf_combined_accept_wrong_secrets_vault_locked() {
    let h = Harness::new(vec![raw(11, all()), passkey(vec![Role::Approve])], 1, 1);
    let mut k = h.state().keyring;
    let raw_id = keys(11).public().id();
    let pass = passkey(vec![Role::Approve]);
    let combined = Slot::combined(
        &[70; 32],
        &k.vault.id(),
        &[raw_id.clone(), pass.id()],
        "Two parts",
        &[
            slots::NewPart::Sealed {
                agreement: &keys(11).public().agreement,
            },
            slots::NewPart::Prf {
                salt: &[6; 32],
                output: &[7; 32],
            },
        ],
        &mut Entropy::new([90; 32]),
    )
    .unwrap();
    k.slots = vec![
        slot(&k.vault, &raw(11, all()), [70; 32]),
        slot(&k.vault, &pass, [70; 32]),
        combined,
    ];
    let original = AuthorityEnvelope::from_json(h.records.values().next().unwrap()).unwrap();
    let mut body: Value = serde_json::from_slice(&original.body).unwrap();
    body["keyring"] = json!(k);
    let env = h.envelope(&body, &[0]);
    let records = Records::from([("authority/00000001.json".into(), env.encode().unwrap())]);
    let mut lib = Library::open(records, keys(14).public()).unwrap();
    for index in 0..3 {
        let dh = lib
            .begin_unlock_slot(index)
            .unwrap()
            .into_iter()
            .filter_map(|i| match i {
                slots::OpeningInput::Ecdh { enc, .. } => Some(keys(11).agree(enc).unwrap()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let secrets = match index {
            0 => vec![slots::OpeningSecret::Ecdh(&dh[0])],
            1 => vec![slots::OpeningSecret::Prf(&[7; 32])],
            _ => vec![
                slots::OpeningSecret::Ecdh(&dh[0]),
                slots::OpeningSecret::Prf(&[7; 32]),
            ],
        };
        lib.finish_unlock_slot(index, &secrets).unwrap();
    }
    assert_eq!(
        lib.finish_unlock_slot(1, &[slots::OpeningSecret::Prf(&[8; 32])])
            .unwrap_err()
            .0,
        "vaultLocked"
    );
    // A structurally valid route carrying another vault's seed fails the identity check.
    let mut k = lib.authority().keyring.clone();
    k.slots = vec![slot(&k.vault, &raw(11, all()), [71; 32])];
    body["keyring"] = json!(k);
    let env = h.envelope(&body, &[0]);
    let mut lib = Library::open(
        Records::from([("authority/00000001.json".into(), env.encode().unwrap())]),
        keys(14).public(),
    )
    .unwrap();
    let slots::OpeningInput::Ecdh { enc, .. } = lib.begin_unlock_slot(0).unwrap()[0] else {
        panic!()
    };
    let dh = keys(11).agree(enc).unwrap();
    assert_eq!(
        lib.finish_unlock_slot(0, &[slots::OpeningSecret::Ecdh(&dh)])
            .unwrap_err()
            .0,
        "vaultLocked"
    );
}
#[test]
fn authority_epoch_recipients_at_introduction_revocation_and_expiry() {
    let mut h = Harness::default();
    h.rekey();
    let g = h.grant(keys(14).public(), MemberKind::Device, false);
    h.push(g, &[0]);
    h.state();
    let e = h.epoch(&h.state().keyring.vault, 2);
    assert_eq!(
        h.outcome(json!({"kind":"rekey","epochs":[e.clone()]}), &[0]),
        "accept"
    );
    for id in [h.state().keyring.vault.id(), keys(14).public().id()] {
        let mut e = e.clone();
        e.seals.remove(&id);
        assert_eq!(
            h.outcome(json!({"kind":"rekey","epochs":[e]}), &[0]),
            "malformed"
        );
    }
    let mut e = e;
    e.seals.remove(&keys(14).public().id());
    assert_eq!(
        h.outcome(
            json!({"kind":"revoke","memberID":keys(14).public().id(),"kept":[],"epochs":[e]}),
            &[0]
        ),
        "accept"
    );
    let mut h = Harness::default();
    h.rekey();
    let mut g = h.grant(keys(14).public(), MemberKind::Device, false);
    g["grant"]["expires"] = json!(NOW);
    h.push(g, &[0]);
    h.state();
    let mut e = h.epoch(&h.state().keyring.vault, 2);
    e.seals.remove(&keys(14).public().id());
    let mut v = h.value(json!({"kind":"rekey","epochs":[e]}), 0);
    v["issued"] = json!(support::LATER);
    assert_eq!(h.outcome_value(v, &[0]), "accept");
    let rotation = h.rotation(h.state().keyring, [71; 32]);
    for omitted in ["shares", "epochs"] {
        let mut a = rotation.clone();
        a.as_object_mut().unwrap().remove(omitted);
        assert_eq!(h.outcome(a, &[0]), "malformed");
    }
}
#[test]
fn authority_webauthn_single_uv_optional_controller_verification_and_layout_monotonic() {
    let mut h = Harness::new(vec![passkey(all())], 1, 1);
    h.rekey();
    let v = h.value(h.grant(keys(14).public(), MemberKind::Device, false), 0);
    let mut env = h.envelope(&v, &[0]);
    let a = SyntheticAuthenticator::new()
        .unwrap()
        .assertion(&env.body, RP, "https://id.luff.works", 1, false)
        .unwrap();
    env.signature = a.signature;
    env.assertion = Some(a.assertion);
    assert_eq!(h.outcome_envelope(env.clone()), "accept");
    // A prior descriptor's verification flag makes UV mandatory even on a single-rule grant.
    let mut original = AuthorityEnvelope::from_json(h.records.values().next().unwrap()).unwrap();
    let mut genesis: Value = serde_json::from_slice(&original.body).unwrap();
    genesis["keyring"]["controllers"][0]["verification"] = json!(true);
    original = h.envelope(&genesis, &[0]);
    let mut h2 = Harness {
        records: Records::from([("authority/00000001.json".into(), original.encode().unwrap())]),
        controllers: h.controllers.clone(),
    };
    h2.rekey();
    let v = h2.value(h2.grant(keys(14).public(), MemberKind::Device, false), 0);
    let mut env = h2.envelope(&v, &[0]);
    let a = SyntheticAuthenticator::new()
        .unwrap()
        .assertion(&env.body, RP, "https://id.luff.works", 1, false)
        .unwrap();
    env.signature = a.signature;
    env.assertion = Some(a.assertion);
    assert_eq!(h2.outcome_envelope(env), "badSignature");
    h.push(json!({"kind":"layout","layout":2}), &[0]);
    h.state();
    assert_eq!(
        h.outcome(json!({"kind":"layout","layout":1}), &[0]),
        "malformed"
    );
    assert_eq!(
        h.outcome(json!({"kind":"layout","layout":3}), &[0]),
        "newerFormat"
    );
}
#[test]
fn authority_operation_payload_null_accept_and_import_expiry_checks_signed_created() {
    let (mut lib, member, _) = support::create();
    support::write(
        &mut lib,
        &member,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"Notebook","optional":null}),
        100,
    );
    assert!(
        support::success(lib.view("notes", NOW).unwrap()).admitted[0].payload["optional"].is_null()
    );
    let mut h = Harness::default();
    h.rekey();
    let mut g = h.grant(keys(14).public(), MemberKind::Device, true);
    g["grant"]["expires"] = json!(support::LATER);
    h.push(g, &[0]);
    h.state();
    let member = keys(14);
    let mut lib = support::opened(h.records, &member);
    let later = "2026-11-04T12:02:00Z";
    assert!(
        matches!(lib.begin_write("notes",colophon_core::imports::BATCH_KIND,json!({}),later,[111;32]).unwrap(),Outcome::Failure{reason,..} if reason=="expired")
    );
    let mut operation = support::op(
        colophon_core::imports::BATCH_KIND,
        1,
        lib.authority().latest,
        json!({}),
    );
    operation.created = later.into();
    let records = support::adversarial(&lib, &member, &member, "notes", operation, 1, 112);
    lib.merge(records).unwrap();
    assert_eq!(
        support::success(lib.view("notes", NOW).unwrap()).refused[0].reason,
        "expired"
    );
}
#[test]
fn authority_writer_checked_combined_route_rotation_and_no_registration_bypass() {
    use colophon_core::library::CombinedPart;
    let (mut lib, member, controller) = support::create();
    let auth = SyntheticAuthenticator::new().unwrap();
    let key = auth.descriptor(RP, None).unwrap();
    let pending = lib.begin_prf_slot(key.clone(), [151; 32]).unwrap();
    use sha2::{Digest, Sha256};
    let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
    ad.extend([5, 0, 0, 0, 0]);
    let cd=canonical(&json!({"type":"webauthn.get","challenge":pending.challenge,"origin":"https://id.luff.works"})).unwrap();
    let signed = auth.sign_bytes(ad, cd, false).unwrap();
    let proof = lib
        .finish_prf_part(
            pending,
            SignatureResult {
                signature: signed.signature,
                assertion: Some(signed.assertion),
            },
            &[41; 32],
        )
        .unwrap();
    let pass = Controller {
        key: key.clone(),
        label: "Passkey".into(),
        roles: vec![Role::Approve],
        verification: None,
    };
    let owner = lib
        .authority()
        .keyring
        .controller(&controller.public().id())
        .unwrap()
        .clone();
    let pending = lib
        .begin_combined_slot(
            vec![
                CombinedPart::Sealed { controller: owner },
                CombinedPart::Prf {
                    controller: pass.clone(),
                    verified: proof,
                },
            ],
            "Combined",
            None,
            [152; 32],
        )
        .unwrap();
    let enc = match pending.begin_open().unwrap()[0] {
        slots::OpeningInput::Ecdh { enc, .. } => enc,
        _ => panic!(),
    };
    let dh = controller.agree(enc).unwrap();
    let slot = lib
        .finish_combined_slot(
            pending,
            &[
                slots::OpeningSecret::Ecdh(&dh),
                slots::OpeningSecret::Prf(&[41; 32]),
            ],
        )
        .unwrap();
    let action = lib
        .begin_add_controller(pass.clone(), Some(slot), &[controller.public().id()], NOW)
        .unwrap();
    support::apply(&mut lib, action, &member);
    let unchecked = Slot::from_prf(
        &[202; 32],
        &lib.authority().keyring.vault.id(),
        &pass.id(),
        "Unchecked",
        &[49; 32],
        &[50; 32],
        &mut Entropy::new([153; 32]),
    )
    .unwrap();
    // A route checked for the old vault cannot be republished as a fresh vault's route.
    let mut stale = lib.authority().keyring.clone();
    stale.vault = vault::derive([205; 32]).unwrap().public();
    assert!(lib
        .begin_keyring(
            stale,
            Some([205; 32]),
            &[controller.public().id()],
            NOW,
            [158; 32]
        )
        .unwrap_err()
        .0
        .starts_with("malformed"));
    let mut k = lib.authority().keyring.clone();
    k.slots.push(unchecked);
    assert!(lib
        .begin_keyring(k, None, &[controller.public().id()], NOW, [154; 32])
        .unwrap_err()
        .0
        .starts_with("malformed"));
    let pending = lib.begin_prf_slot(key, [155; 32]).unwrap();
    let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
    ad.extend([5, 0, 0, 0, 0]);
    let cd=canonical(&json!({"type":"webauthn.get","challenge":pending.challenge,"origin":"https://id.luff.works"})).unwrap();
    let signed = auth.sign_bytes(ad, cd, false).unwrap();
    let prf = lib
        .finish_prf_slot_for(
            pending,
            SignatureResult {
                signature: signed.signature,
                assertion: Some(signed.assertion),
            },
            &[51; 32],
            "Rotated",
            [203; 32],
            [156; 32],
        )
        .unwrap();
    let mut k = lib.authority().keyring.clone();
    k.vault = vault::derive([203; 32]).unwrap().public();
    k.slots = vec![prf];
    let action = lib
        .begin_keyring(
            k,
            Some([203; 32]),
            &[controller.public().id()],
            NOW,
            [157; 32],
        )
        .unwrap();
    support::apply(&mut lib, action, &member);
    lib.finish_unlock_slot(0, &[slots::OpeningSecret::Prf(&[51; 32])])
        .unwrap();
}
#[test]
fn authority_recovery_equal_quorum_can_add_control_and_new_controller_slot() {
    let mut h = Harness::new(
        vec![raw(11, vec![Role::Control]), raw(12, vec![Role::Recover])],
        1,
        1,
    );
    h.rekey();
    let mut k = h.state().keyring;
    let new = raw(13, vec![Role::Control]);
    k.slots.push(slot(&k.vault, &new, [70; 32]));
    k.controllers.push(new);
    k.controllers.sort_by_key(Controller::id);
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[1]),
        "accept"
    );
    let mut k = h.state().keyring;
    let mut old = k.slots[0].clone();
    if let Slot::Sealed { label, .. } = &mut old {
        *label = "extra old route".into();
    }
    k.slots.push(old);
    assert_eq!(
        h.outcome(json!({"kind":"keyring","keyring":k}), &[1]),
        "badSignature"
    );
}
#[test]
fn authority_library_controller_threshold_removal_rotates_and_preserves_member() {
    let (mut lib, member, owner) = support::create();
    let next = raw(15, vec![Role::Approve, Role::Control]);
    let route = lib
        .build_sealed_slot(&next, "Second", None, [161; 32])
        .unwrap();
    let action = lib
        .begin_add_controller(next.clone(), Some(route), &[owner.public().id()], NOW)
        .unwrap();
    support::apply(&mut lib, action, &member);
    let action = lib
        .begin_thresholds(2, 0, &[owner.public().id()], NOW)
        .unwrap();
    support::apply(&mut lib, action, &member);
    let action = lib
        .begin_thresholds(1, 0, &[owner.public().id(), next.id()], NOW)
        .unwrap();
    let signatures = action
        .steps
        .iter()
        .map(|s| {
            if s.signer.id() == next.id() {
                keys(15).sign(&s.body)
            } else {
                owner.sign(&s.body)
            }
        })
        .collect();
    lib.finish(action, signatures).unwrap();
    let route = lib
        .build_sealed_slot(&next, "Rotated", Some([204; 32]), [162; 32])
        .unwrap();
    let action = lib
        .begin_remove_controller(
            &owner.public().id(),
            [204; 32],
            vec![route],
            &[owner.public().id()],
            NOW,
            [163; 32],
        )
        .unwrap();
    support::apply(&mut lib, action, &member);
    lib.select_controller(&next.id()).unwrap();
    let enc = match lib.begin_unlock_slot(0).unwrap()[0] {
        slots::OpeningInput::Ecdh { enc, .. } => enc,
        _ => panic!(),
    };
    let dh = keys(15).agree(enc).unwrap();
    lib.finish_unlock_slot(0, &[slots::OpeningSecret::Ecdh(&dh)])
        .unwrap();
    assert_eq!(lib.authority().keyring.controllers.len(), 1);
    assert_eq!(lib.authority().members.len(), 1);
    assert_eq!(
        lib.authority().members[&member.public().id()]
            .member
            .revoked_at,
        None
    );
    assert_eq!(lib.authority().epochs["notes"].len(), 2);
}
#[test]
fn authority_library_webauthn_challenges_cosignatures_and_atomic_finish() {
    let mut h = Harness::new(vec![raw(11, all()), passkey(all())], 2, 2);
    h.rekey();
    let mut lib = Library::open(h.records.clone(), keys(14).public()).unwrap();
    let signers = h.controllers.iter().map(Controller::id).collect::<Vec<_>>();
    let action = lib
        .prepare_authority(
            colophon_core::authority::Action::Layout { layout: 2 },
            &signers[0],
            &signers,
            NOW,
        )
        .unwrap();
    assert_eq!(
        action.steps[1].challenge,
        Some(colophon_core::keys::challenge(&action.steps[1].body))
    );
    let results = action
        .steps
        .iter()
        .map(|s| {
            sign(
                h.controllers
                    .iter()
                    .find(|c| c.id() == s.signer.id())
                    .unwrap(),
                &s.body,
            )
        })
        .collect::<Vec<_>>();
    let mut bad = results.clone();
    bad[1].signature[0] ^= 1;
    assert!(lib
        .finish_authority(action.clone(), bad)
        .unwrap_err()
        .0
        .starts_with("badSignature"));
    assert_eq!(lib.records(), &h.records);
    lib.finish_authority(action, results).unwrap();
    assert_eq!(lib.authority().layout, 2);
}
