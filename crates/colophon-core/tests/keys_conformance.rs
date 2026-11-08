//! Published Colophon 0.4 conformance vectors and their disk-only replay runner.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::crypto::SoftwareKeys;
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
use std::{
    fs,
    path::{Path, PathBuf},
};
const NOW: &str = "2026-11-04T12:00:00.000Z";
fn keys(n: u8) -> SoftwareKeys {
    SoftwareKeys::from_seed([n; 32]).unwrap()
}
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
        let k = [11, 12, 13, 14, 15, 201]
            .into_iter()
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
        let signer = [11, 12, 13, 14, 15, 201]
            .into_iter()
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

// Publish accept records through the Library's public atomic writer. The low-level
// PendingBatch interface permits custom genesis keyrings (begin_create currently
// only prepares a one-raw-controller genesis). Refuse inputs bypass this writer.
fn library_encoded(records: Records) -> Records {
    use colophon_core::library::{PendingBatch, SigningStep};
    let mut written: Records = records
        .iter()
        .filter(|(p, _)| !p.starts_with("authority/"))
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    for (path, bytes) in records.iter().filter(|(p, _)| p.starts_with("authority/")) {
        let env = AuthorityEnvelope::from_json(bytes).unwrap();
        let value = env.body_value().unwrap();
        let k = if written.keys().any(|p| p.starts_with("authority/")) {
            Authority::replay(&written).unwrap().keyring
        } else {
            serde_json::from_value::<Keyring>(value["keyring"].clone()).unwrap()
        };
        let mut signatures = vec![(
            env.primary_signer().unwrap(),
            SignatureResult {
                signature: env.signature,
                assertion: env.assertion,
            },
        )];
        signatures.extend(env.cosignatures.into_iter().flatten().map(|c| {
            (
                c.signer,
                SignatureResult {
                    signature: c.signature,
                    assertion: c.assertion,
                },
            )
        }));
        let mut pending = PendingBatch::default();
        pending.copies = written;
        pending.steps = signatures
            .iter()
            .map(|(id, _)| {
                let signer = k.controller(id).unwrap().key.clone();
                SigningStep {
                    path: path.clone(),
                    body: env.body.clone(),
                    signing: signer.signing().to_vec(),
                    challenge: signer
                        .is_webauthn()
                        .then(|| colophon_core::keys::challenge(&env.body)),
                    signer,
                }
            })
            .collect();
        written = pending
            .finish_with_assertions(signatures.into_iter().map(|(_, s)| s).collect())
            .unwrap();
    }
    assert_eq!(written, records, "exact Library writer bytes");
    written
}

struct Case {
    name: String,
    metadata: Value,
    records: Records,
    input: Value,
    binary: Option<Vec<u8>>,
}
impl Case {
    fn authority(name: &str, sections: &[&str], expected: &str, records: Records) -> Self {
        let records = if expected == "accept" {
            library_encoded(records)
        } else {
            records
        };
        let mut metadata = json!({"description":name.replace('-', " "),"sections":sections,"expected":expected,"probe":"authority"});
        if expected == "accept" {
            metadata["keyring"] = summary(&Authority::replay(&records).unwrap());
        }
        Self {
            name: name.into(),
            metadata,
            records,
            input: json!({}),
            binary: None,
        }
    }
    fn probe(mut self, probe: &str, input: Value) -> Self {
        self.metadata["probe"] = json!(probe);
        self.input = input;
        self
    }
}
fn summary(a: &Authority) -> Value {
    json!({
        "controllers":a.keyring.controllers.iter().map(|c|json!({"id":c.id(),"roles":c.roles})).collect::<Vec<_>>(),
        "threshold":a.keyring.threshold,"recoverThreshold":a.keyring.recover_threshold,
        "vaultID":a.keyring.vault.id(),
        "members":a.members.iter().map(|(id,m)|json!({"id":id,"grant":m.member.grant})).collect::<Vec<_>>()
    })
}
fn appended(h: &Harness, action: Value, signers: &[usize]) -> Records {
    with_envelope(h, h.envelope(&h.value(action, signers[0]), signers))
}
fn with_envelope(h: &Harness, env: AuthorityEnvelope) -> Records {
    let mut records = h.records.clone();
    records.insert(
        format!("authority/{:08}.json", records.len() + 1),
        canonical(&env).unwrap(),
    );
    records
}
fn replace_genesis(h: &Harness, value: Value, signers: &[usize]) -> Records {
    Records::from([(
        "authority/00000001.json".into(),
        h.envelope(&value, signers).encode().unwrap(),
    )])
}
fn genesis_value(h: &Harness) -> Value {
    serde_json::from_slice(
        &AuthorityEnvelope::from_json(h.records.values().next().unwrap())
            .unwrap()
            .body,
    )
    .unwrap()
}
fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
fn unb64(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn push_case(
    cases: &mut Vec<Case>,
    name: &str,
    sections: &[&str],
    expected: &str,
    records: Records,
) {
    cases.push(Case::authority(name, sections, expected, records));
}
fn ready() -> Harness {
    let mut h = Harness::default();
    h.rekey();
    h
}
fn quorum() -> Harness {
    let mut h = Harness::new(
        vec![
            raw(11, all()),
            raw(12, vec![Role::Control]),
            raw(13, vec![Role::Approve]),
        ],
        2,
        1,
    );
    h.rekey();
    h
}
fn slot_harness() -> Harness {
    let mut h = Harness::new(vec![raw(11, all()), passkey(all())], 1, 1);
    let mut v = genesis_value(&h);
    let mut k = h.state().keyring;
    // Ordered parts deliberately differ from sorted controller order.
    k.slots = vec![
        slot(&k.vault, &h.controllers[0], [70; 32]),
        slot(&k.vault, &h.controllers[1], [70; 32]),
        Slot::combined(
            &[70; 32],
            &k.vault.id(),
            &[h.controllers[0].id(), h.controllers[1].id()],
            "Kit and passkey",
            &[
                slots::NewPart::Sealed {
                    agreement: h.controllers[0].key.agreement().unwrap(),
                },
                slots::NewPart::Prf {
                    salt: &[6; 32],
                    output: &[7; 32],
                },
            ],
            &mut Entropy::new([90; 32]),
        )
        .unwrap(),
    ];
    v["keyring"] = json!(k);
    h.records = replace_genesis(&h, v, &[0]);
    h
}
fn authority_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for name in ["genesis-one-raw", "genesis-only"] {
        push_case(
            &mut cases,
            name,
            &["4.2", "6.2", "6.3"],
            "accept",
            Harness::default().records,
        );
    }
    let h = Harness::new(vec![raw(11, all()), passkey(all())], 2, 2);
    push_case(
        &mut cases,
        "genesis-threshold-two",
        &["3.3", "6.3"],
        "accept",
        h.records,
    );
    push_case(
        &mut cases,
        "seq-two-rekey",
        &["5.1", "6.2"],
        "accept",
        ready().records,
    );
    let mut h = Harness::new(vec![passkey(all())], 1, 1);
    h.rekey();
    push_case(
        &mut cases,
        "passkey-grant",
        &["3.3", "6.3", "7"],
        "accept",
        appended(
            &h,
            h.grant(keys(14).public(), MemberKind::Device, false),
            &[0],
        ),
    );
    let q = quorum();
    push_case(
        &mut cases,
        "import-control-quorum",
        &["6.3", "7"],
        "accept",
        appended(
            &q,
            q.grant(keys(14).public(), MemberKind::App, true),
            &[0, 1],
        ),
    );
    let mut h = Harness::new(vec![raw(11, vec![Role::Control])], 1, 0);
    h.rekey();
    push_case(
        &mut cases,
        "control-only-rekey",
        &["6.3"],
        "accept",
        h.records,
    );
    let mut k = q.state().keyring;
    k.controllers.push(raw(15, vec![Role::Approve]));
    k.controllers.sort_by_key(Controller::id);
    push_case(
        &mut cases,
        "recovery-add-approve-only",
        &["6.3"],
        "accept",
        appended(&q, json!({"kind":"keyring","keyring":k}), &[0]),
    );
    for change in ["removal", "demotion"] {
        let mut h = Harness::new(vec![raw(11, all()), raw(12, all())], 1, 1);
        h.rekey();
        let mut k = h.state().keyring;
        if change == "removal" {
            k.controllers.retain(|c| c.id() != keys(12).public().id());
        } else {
            k.controllers
                .iter_mut()
                .find(|c| c.id() == keys(12).public().id())
                .unwrap()
                .roles = vec![Role::Approve];
        }
        let records = appended(&h, h.rotation(k, [71; 32]), &[0]);
        cases.push(Case::authority(&format!("{change}-with-rotation"),&["5.1","6.2"],"accept",records)
            .probe("history",json!({"vaultSeed":b64(&[71;32]),"epochKey":b64(&[1;32]),"openController":if change=="demotion" {keys(12).public().id()} else {keys(11).public().id()}})));
    }
    for (index, name) in ["sealed-slot-open", "prf-slot-open", "combined-slot-open"]
        .into_iter()
        .enumerate()
    {
        cases.push(
            Case::authority(name, &["5.1", "5.2"], "accept", slot_harness().records)
                .probe("slot", json!({"index":index,"prfOutput":b64(&[7;32])})),
        );
    }
    let mut h = Harness::new(vec![passkey(all())], 1, 1);
    h.rekey();
    let body = h.value(json!({"kind":"layout","layout":2}), 0);
    for (name, origin, high) in [
        ("multi-label-origin", "https://a.b.id.luff.works", false),
        ("android-origin", "android:apk-key-hash:test", false),
        ("high-s-webauthn", "https://id.luff.works", true),
        ("low-s-webauthn", "https://id.luff.works", false),
    ] {
        let a = SyntheticAuthenticator::new()
            .unwrap()
            .assertion(&canonical(&body).unwrap(), RP, origin, 5, high)
            .unwrap();
        let mut e = h.envelope(&body, &[0]);
        e.signature = a.signature;
        e.assertion = Some(a.assertion);
        push_case(&mut cases, name, &["3.3"], "accept", with_envelope(&h, e));
    }
    let h = Harness::new(vec![raw(11, all()), raw(12, vec![Role::Recover])], 1, 2);
    push_case(
        &mut cases,
        "recovery-threshold-greater",
        &["4.2"],
        "accept",
        h.records,
    );
    let mut h = ready();
    let mut k = h.state().keyring;
    let mut extra = k.slots[0].clone();
    if let Slot::Sealed { label, .. } = &mut extra {
        *label = "Second label".into();
    }
    k.slots.push(extra);
    h.push(json!({"kind":"keyring","keyring":k}), &[0]);
    let mut k = h.state().keyring;
    k.slots.reverse();
    if let Slot::Sealed { label, .. } = &mut k.slots[0] {
        *label = "Relabeled".into();
    }
    push_case(
        &mut cases,
        "slot-reorder-relabel",
        &["6.2"],
        "accept",
        appended(&h, json!({"kind":"keyring","keyring":k}), &[0]),
    );
    push_case(
        &mut cases,
        "unknown-kind-control",
        &["6.3"],
        "newerFormat",
        appended(&q, json!({"kind":"future"}), &[0, 1]),
    );

    // Correctly signed assertions isolate each WebAuthn check from ECDSA failure.
    let other = Controller {
        key: SyntheticAuthenticator::from_scalar(&[2; 32])
            .unwrap()
            .descriptor(RP, None)
            .unwrap(),
        label: "Other passkey".into(),
        roles: vec![Role::Approve],
        verification: None,
    };
    let mut h = Harness::new(vec![passkey(all()), other], 1, 1);
    h.rekey();
    let v = h.value(json!({"kind":"layout","layout":2}), 0);
    let valid = h.envelope(&v, &[0]);
    let a = valid.assertion.clone().unwrap();
    for name in [
        "wrong-challenge",
        "wrong-rp-hash",
        "foreign-origin",
        "origin-userinfo",
        "origin-port",
        "cross-origin",
        "webauthn-create",
        "up-missing",
        "uv-missing",
        "duplicate-client-data",
        "der-long-length",
        "der-extra-padding",
        "der-trailing",
        "der-non-minimal",
        "foreign-authenticator-key",
    ] {
        let mut cd: Value = serde_json::from_slice(&a.client_data).unwrap();
        let mut ad = a.authenticator_data.clone();
        match name {
            "wrong-challenge" => cd["challenge"] = json!("wrong"),
            "wrong-rp-hash" => ad[0] ^= 1,
            "foreign-origin" => cd["origin"] = json!("https://foreign.example"),
            "origin-userinfo" => cd["origin"] = json!("https://u@id.luff.works"),
            "origin-port" => cd["origin"] = json!("https://id.luff.works:443"),
            "cross-origin" => cd["crossOrigin"] = json!(true),
            "webauthn-create" => cd["type"] = json!("webauthn.create"),
            "up-missing" => ad[32] = 4,
            "uv-missing" => ad[32] = 1,
            _ => {}
        }
        let mut client = canonical(&cd).unwrap();
        if name == "duplicate-client-data" {
            client.splice(1..1, b"\"type\":\"webauthn.get\",".iter().copied());
        }
        let auth = if name == "foreign-authenticator-key" {
            SyntheticAuthenticator::from_scalar(&[2; 32]).unwrap()
        } else {
            SyntheticAuthenticator::new().unwrap()
        };
        let signed = auth.sign_bytes(ad, client, false).unwrap();
        let mut e = valid.clone();
        e.signature = signed.signature;
        e.assertion = Some(signed.assertion);
        match name {
            "der-long-length" => {
                e.signature.insert(1, 0x81);
            }
            "der-extra-padding" | "der-non-minimal" => {
                e.signature.insert(4, 0);
                e.signature[1] += 1;
                e.signature[3] += 1;
            }
            "der-trailing" => e.signature.push(0),
            _ => {}
        }
        push_case(
            &mut cases,
            name,
            &["2.1", "3.3", "10"],
            "badSignature",
            with_envelope(&h, e),
        );
    }
    for (name, signers, action) in [
        (
            "threshold-unmet",
            vec![0],
            json!({"kind":"keyring","keyring":({ let mut k=q.state().keyring; k.threshold=1; k })}),
        ),
        (
            "mixed-role-signers",
            vec![0, 2],
            json!({"kind":"layout","layout":2}),
        ),
        (
            "single-rule-cosignatures",
            vec![0, 1],
            json!({"kind":"rekey","epochs":[q.epoch(&q.state().keyring.vault,2)]}),
        ),
        (
            "layout-minority",
            vec![0],
            json!({"kind":"layout","layout":2}),
        ),
        ("unknown-kind-minority", vec![0], json!({"kind":"future"})),
        (
            "unknown-kind-approve-only",
            vec![2],
            json!({"kind":"future"}),
        ),
        (
            "import-single-rule",
            vec![2],
            q.grant(keys(14).public(), MemberKind::Device, true),
        ),
    ] {
        push_case(
            &mut cases,
            name,
            &["6.3", "7"],
            "badSignature",
            appended(&q, action, &signers),
        );
    }
    let mut extra = Harness::new(vec![raw(11, all()), raw(12, all())], 1, 1);
    extra.rekey();
    let mut e = extra.envelope(
        &extra.value(json!({"kind":"layout","layout":2}), 0),
        &[0, 1],
    );
    e.cosignatures.as_mut().unwrap()[0].signature[0] ^= 1;
    push_case(
        &mut cases,
        "invalid-extra-cosignature",
        &["3.1"],
        "badSignature",
        with_envelope(&extra, e),
    );
    let mut e = q.envelope(&q.value(json!({"kind":"future"}), 0), &[0, 1]);
    e.signature[0] ^= 1;
    push_case(
        &mut cases,
        "unknown-kind-unauthenticated",
        &["6.3"],
        "badSignature",
        with_envelope(&q, e),
    );
    let mut k = json!(q.state().keyring);
    k["controllers"][0]["future"] = json!(true);
    push_case(
        &mut cases,
        "controller-unknown-field-single-rule",
        &["6.3"],
        "badSignature",
        appended(&q, json!({"kind":"keyring","keyring":k}), &[2]),
    );
    let mut h = Harness::new(
        vec![raw(11, vec![Role::Control]), raw(12, vec![Role::Approve])],
        1,
        0,
    );
    h.rekey();
    push_case(
        &mut cases,
        "recovery-disabled",
        &["6.3"],
        "badSignature",
        appended(
            &h,
            json!({"kind":"keyring","keyring":h.state().keyring}),
            &[1],
        ),
    );
    for name in [
        "recovery-add-control",
        "recovery-remove",
        "recovery-demote",
        "recovery-change-threshold",
        "recovery-change-recover-threshold",
        "recovery-change-vault",
    ] {
        let mut k = q.state().keyring;
        match name {
            "recovery-add-control" => {
                k.controllers.push(raw(15, vec![Role::Control]));
                k.controllers.sort_by_key(Controller::id);
            }
            "recovery-remove" => {
                k.controllers.retain(|c| c.id() != keys(12).public().id());
                k.slots
                    .retain(|s| !s.controllers().contains(&keys(12).public().id()));
            }
            "recovery-demote" => {
                k.controllers
                    .iter_mut()
                    .find(|c| c.id() == keys(12).public().id())
                    .unwrap()
                    .roles = vec![Role::Approve]
            }
            "recovery-change-threshold" => k.threshold = 1,
            "recovery-change-recover-threshold" => k.recover_threshold = 0,
            _ => k.vault = vault::derive([71; 32]).unwrap().public(),
        }
        push_case(
            &mut cases,
            name,
            &["6.3"],
            "badSignature",
            appended(&q, json!({"kind":"keyring","keyring":k}), &[0]),
        );
    }
    let mut h = Harness::new(vec![raw(11, all()), raw(12, all())], 1, 1);
    h.rekey();
    for name in [
        "removal-without-rotation",
        "demotion-without-rotation",
        "agreement-change-without-rotation",
        "slot-deletion-without-rotation",
    ] {
        let mut k = h.state().keyring;
        match name {
            "removal-without-rotation" => {
                k.controllers.retain(|c| c.id() != keys(12).public().id());
                k.slots
                    .retain(|s| !s.controllers().contains(&keys(12).public().id()));
            }
            "demotion-without-rotation" => {
                k.controllers
                    .iter_mut()
                    .find(|c| c.id() == keys(12).public().id())
                    .unwrap()
                    .roles = vec![Role::Approve]
            }
            "agreement-change-without-rotation" => {
                if let KeyDescriptor::Raw { agreement, .. } = &mut k
                    .controllers
                    .iter_mut()
                    .find(|c| c.id() == keys(12).public().id())
                    .unwrap()
                    .key
                {
                    *agreement = Some(keys(14).public().agreement);
                }
            }
            _ => {
                k.slots.pop();
            }
        }
        push_case(
            &mut cases,
            name,
            &["6.2"],
            "malformed",
            appended(&h, json!({"kind":"keyring","keyring":k}), &[0]),
        );
    }
    let mut rotating = ready();
    rotating.push(rotating.rotation(rotating.state().keyring, [71; 32]), &[0]);
    push_case(
        &mut cases,
        "vault-reuse-a-b-a",
        &["2.3", "6.2"],
        "malformed",
        appended(
            &rotating,
            rotating.rotation(rotating.state().keyring, [70; 32]),
            &[0],
        ),
    );
    let h = ready();
    push_case(
        &mut cases,
        "shares-without-vault-change",
        &["6.2"],
        "malformed",
        appended(
            &h,
            json!({"kind":"keyring","keyring":h.state().keyring,"shares":[]}),
            &[0],
        ),
    );
    let mut dup = quorum();
    let mut k = dup.state().keyring;
    k.slots.push(k.slots[0].clone());
    dup.push(json!({"kind":"keyring","keyring":k}), &[0, 1]);
    let mut k = dup.state().keyring;
    k.slots.pop();
    push_case(
        &mut cases,
        "recovery-drops-duplicate-slot",
        &["6.3"],
        "badSignature",
        appended(&dup, json!({"kind":"keyring","keyring":k}), &[0]),
    );
    push_case(
        &mut cases,
        "controller-member-collision",
        &["2.3"],
        "malformed",
        appended(
            &h,
            h.grant(keys(11).public(), MemberKind::Device, false),
            &[0],
        ),
    );
    // The request is signed by its real signing key; only its agreement point collides.
    let mut member = keys(14).public();
    member.agreement = h.state().keyring.vault.agreement;
    push_case(
        &mut cases,
        "member-vault-collision",
        &["2.3"],
        "malformed",
        appended(&h, h.grant(member, MemberKind::Device, false), &[0]),
    );
    for name in ["shared-controller-agreement", "signing-equals-agreement"] {
        let mut k = h.state().keyring;
        let mut c = raw(12, vec![Role::Approve]);
        if let KeyDescriptor::Raw { signing, agreement } = &mut c.key {
            *agreement = Some(if name == "signing-equals-agreement" {
                signing.clone()
            } else {
                keys(11).public().agreement
            });
        }
        k.controllers.push(c);
        k.controllers.sort_by_key(Controller::id);
        push_case(
            &mut cases,
            name,
            &["2.3"],
            "malformed",
            appended(&h, json!({"kind":"keyring","keyring":k}), &[0]),
        );
    }
    for name in [
        "combined-empty",
        "combined-one-part",
        "combined-duplicate-controllers",
        "prf-raw-controller",
        "sealed-ciphertext-size",
        "sealed-enc-size",
        "prf-salt-size",
        "prf-box-size",
        "combined-box-size",
        "part-ciphertext-size",
        "part-salt-size",
        "origins-https-prefix",
        "rp-leading-hyphen",
    ] {
        let mut k = json!(h.state().keyring);
        let id = keys(11).public().id();
        match name {
            "combined-empty" | "combined-one-part" | "combined-duplicate-controllers" => {
                let ids = match name {
                    "combined-empty" => vec![],
                    "combined-one-part" => vec![id.clone()],
                    _ => vec![id.clone(), id.clone()],
                };
                let parts = ids
                    .iter()
                    .map(|_| json!({"kind":"sealed","sealed":k["slots"][0]["sealed"]}))
                    .collect::<Vec<_>>();
                k["slots"] = json!([{"kind":"combined","controllers":ids,"label":"Combined","parts":parts,"box":b64(&[0;60])}]);
            }
            "prf-raw-controller" => {
                k["slots"] = json!([{"kind":"prf","controllers":[id],"label":"PRF","salt":b64(&[6;32]),"box":b64(&[0;60])}])
            }
            "sealed-ciphertext-size" => {
                k["slots"][0]["sealed"]["ciphertext"] = json!(b64(&[0; 47]))
            }
            "sealed-enc-size" => k["slots"][0]["sealed"]["enc"] = json!(b64(&[0; 64])),
            "prf-salt-size"
            | "prf-box-size"
            | "combined-box-size"
            | "part-ciphertext-size"
            | "part-salt-size" => {
                k = json!(slot_harness().state().keyring);
                match name {
                    "prf-salt-size" => k["slots"][1]["salt"] = json!(b64(&[6; 31])),
                    "prf-box-size" => k["slots"][1]["box"] = json!(b64(&[0; 59])),
                    "combined-box-size" => k["slots"][2]["box"] = json!(b64(&[0; 59])),
                    "part-ciphertext-size" => {
                        k["slots"][2]["parts"][0]["sealed"]["ciphertext"] = json!(b64(&[0; 47]))
                    }
                    _ => k["slots"][2]["parts"][1]["salt"] = json!(b64(&[6; 31])),
                }
            }
            _ => {
                let mut c = json!(passkey(vec![Role::Approve]));
                if name == "rp-leading-hyphen" {
                    c["key"]["rp"] = json!("-id.luff.works");
                } else {
                    c["key"]["origins"] = json!(["https:example"]);
                }
                k["controllers"].as_array_mut().unwrap().push(c);
                k["controllers"]
                    .as_array_mut()
                    .unwrap()
                    .sort_by_key(|c| records::id(&unb64(&c["key"]["signing"])));
            }
        }
        // All malformed routes are additions: slot preservation cannot mask shape errors.
        let original = json!(h.state().keyring.slots[0]);
        if !k["slots"].as_array().unwrap().contains(&original) {
            k["slots"].as_array_mut().unwrap().insert(0, original);
        }
        push_case(
            &mut cases,
            name,
            &["2.2", "5.2"],
            "malformed",
            appended(&h, json!({"kind":"keyring","keyring":k}), &[0]),
        );
    }
    let mut wrong = slot_harness();
    let mut v = genesis_value(&wrong);
    let mut k = wrong.state().keyring;
    k.slots[0] = slot(&k.vault, &wrong.controllers[0], [71; 32]);
    v["keyring"] = json!(k);
    wrong.records = replace_genesis(&wrong, v, &[0]);
    cases.push(
        Case::authority(
            "slot-foreign-vault-seed",
            &["5.1"],
            "vaultLocked",
            wrong.records,
        )
        .probe("slot", json!({"index":0,"prfOutput":b64(&[7;32])})),
    );
    cases.push(
        Case::authority(
            "wrong-prf-output",
            &["5.2"],
            "vaultLocked",
            slot_harness().records,
        )
        .probe("slot", json!({"index":1,"prfOutput":b64(&[8;32])})),
    );
    let mut e = h.envelope(&h.value(json!({"kind":"layout","layout":2}), 0), &[0]);
    e.body.splice(1..1, b"\"kind\":\"layout\",".iter().copied());
    e.signature = keys(11).sign(&e.body);
    push_case(
        &mut cases,
        "duplicate-body-name",
        &["2.1"],
        "malformed",
        with_envelope(&h, e),
    );
    let e = h.envelope(&h.value(json!({"kind":"layout","layout":2}), 0), &[0]);
    let mut wire: Value = serde_json::from_slice(&e.encode().unwrap()).unwrap();
    wire["cosignatures"] = json!([]);
    let mut records = h.records.clone();
    records.insert("authority/00000003.json".into(), canonical(&wire).unwrap());
    push_case(
        &mut cases,
        "empty-cosignatures",
        &["3.1"],
        "malformed",
        records,
    );
    let first = Harness::default();
    for (name, action) in [
        ("seq-two-not-rekey", json!({"kind":"layout","layout":2})),
        (
            "seq-two-incomplete-rekey",
            json!({"kind":"rekey","epochs":[]}),
        ),
        (
            "seq-two-wrong-epoch",
            json!({"kind":"rekey","epochs":[first.epoch(&first.state().keyring.vault,2)]}),
        ),
    ] {
        push_case(
            &mut cases,
            name,
            &["6.2"],
            "malformed",
            appended(&first, action, &[0]),
        );
    }
    let mut multi = Harness::default();
    let mut v = genesis_value(&multi);
    v["namespaces"] = json!(["notes", "reading.books"]);
    multi.records = replace_genesis(&multi, v, &[0]);
    let epoch = multi.epoch(&multi.state().keyring.vault, 1);
    push_case(
        &mut cases,
        "seq-two-missing-namespace",
        &["6.2"],
        "malformed",
        appended(&multi, json!({"kind":"rekey","epochs":[epoch]}), &[0]),
    );
    let mut v = h.value(json!({"kind":"layout","layout":2}), 0);
    v["protocol"] = json!("colophon/authority/3");
    push_case(
        &mut cases,
        "authority-three",
        &["6.1", "9"],
        "malformed",
        with_envelope(&h, h.envelope(&v, &[0])),
    );
    for (name, kind) in [
        ("import-agent", MemberKind::Agent),
        ("import-server", MemberKind::Server),
    ] {
        push_case(
            &mut cases,
            name,
            &["7"],
            "malformed",
            appended(&q, q.grant(keys(14).public(), kind, true), &[0, 1]),
        );
    }
    for name in [
        "import-read-only",
        "import-expiry-equal",
        "import-expiry-before",
    ] {
        let mut g = q.grant(keys(14).public(), MemberKind::Device, true);
        match name {
            "import-read-only" => g["grant"]["access"] = json!(["read"]),
            "import-expiry-equal" => g["grant"]["expires"] = json!(NOW),
            _ => g["grant"]["expires"] = json!("2026-11-03T12:00:00Z"),
        }
        push_case(
            &mut cases,
            name,
            &["7"],
            "malformed",
            appended(&q, g, &[0, 1]),
        );
    }
    for (name, id) in [
        ("imported-from-uppercase", "A".repeat(32)),
        ("imported-from-short", "a".repeat(31)),
        ("imported-from-nonhex", "g".repeat(32)),
    ] {
        let mut v = genesis_value(&first);
        v["importedFrom"] = json!(id);
        push_case(
            &mut cases,
            name,
            &["6.2", "9"],
            "malformed",
            replace_genesis(&first, v, &[0]),
        );
    }
    cases
}

fn kit() -> SoftwareKeys {
    SoftwareKeys::recovery([33; 32]).unwrap()
}
fn kit_controller() -> Controller {
    let p = kit().public();
    Controller {
        key: KeyDescriptor::Raw {
            signing: p.signing,
            agreement: Some(p.agreement),
        },
        label: "Recovery kit".into(),
        roles: vec![Role::Recover],
        verification: None,
    }
}
fn software(id: &str) -> SoftwareKeys {
    [11, 12, 13, 14, 15, 201]
        .into_iter()
        .map(keys)
        .chain(std::iter::once(kit()))
        .chain(
            [70, 71, 202]
                .into_iter()
                .map(|n| vault::derive([n; 32]).unwrap()),
        )
        .find(|k| k.public().id() == id)
        .unwrap()
}
fn sign_batch(p: &colophon_core::library::PendingBatch) -> Vec<Vec<u8>> {
    p.steps
        .iter()
        .map(|s| software(&s.signer.id()).sign(&s.body))
        .collect()
}
fn apply_batch(lib: &mut Library, p: colophon_core::library::PendingBatch) {
    let signatures = p
        .steps
        .iter()
        .map(|s| {
            if s.signer.is_webauthn() {
                let a = SyntheticAuthenticator::new()
                    .unwrap()
                    .assertion(&s.body, RP, "https://id.luff.works", 5, false)
                    .unwrap();
                SignatureResult {
                    signature: a.signature,
                    assertion: Some(a.assertion),
                }
            } else {
                SignatureResult {
                    signature: software(&s.signer.id()).sign(&s.body),
                    assertion: None,
                }
            }
        })
        .collect();
    lib.finish_authority(p, signatures).unwrap();
}
fn success<T: std::fmt::Debug>(o: Outcome<T>) -> T {
    match o {
        Outcome::Success { value, .. } => value,
        other => panic!("expected success: {other:?}"),
    }
}
fn unlock_owner(lib: &mut Library) {
    lib.select_controller(&keys(201).public().id()).unwrap();
    let slots::OpeningInput::Ecdh { enc, .. } = lib.begin_unlock_slot(0).unwrap()[0] else {
        panic!("owner slot")
    };
    let dh = keys(201).agree(enc).unwrap();
    lib.finish_unlock_slot(0, &[slots::OpeningSecret::Ecdh(&dh)])
        .unwrap();
}
fn base_library() -> Library {
    let p = Library::begin_create(
        colophon_core::library::CreateOptions {
            owner: keys(201).public(),
            member: keys(14).public(),
            vault_seed: [202; 32],
            import_expires: None,
            recovery: None,
            imported_from: None,
            label: "Colophon 0.4 deterministic library".into(),
            owner_label: "Device owner".into(),
            namespaces: vec![
                "listening.podcasts".into(),
                "notes".into(),
                "reading.books".into(),
                "reading.saved".into(),
            ],
        },
        NOW,
        [100; 32],
    )
    .unwrap();
    let signatures = sign_batch(&p);
    let p = p.advance_create(signatures).unwrap();
    let signatures = sign_batch(&p);
    let records = p.finish(signatures).unwrap();
    let mut lib = Library::open(records, keys(14).public()).unwrap();
    unlock_owner(&mut lib);
    lib
}
fn complete_library() -> Case {
    let mut lib = base_library();
    let pass = passkey(vec![Role::Approve, Role::Control]);
    let pending = lib.begin_prf_slot(pass.key.clone(), [101; 32]).unwrap();
    let salt = pending.salt;
    let client=canonical(&json!({"type":"webauthn.get","challenge":pending.challenge,"origin":"https://id.luff.works"})).unwrap();
    use sha2::{Digest, Sha256};
    let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
    ad.extend([5, 0, 0, 0, 0]);
    let assertion = SyntheticAuthenticator::new()
        .unwrap()
        .sign_bytes(ad, client, false)
        .unwrap();
    let ceremony = json!({"key":pass.key,"salt":b64(&salt),"prfOutput":b64(&[7;32]),"assertion":assertion.assertion,"signature":b64(&assertion.signature)});
    let slot = lib
        .finish_prf_slot(
            pending,
            SignatureResult {
                signature: assertion.signature,
                assertion: Some(assertion.assertion),
            },
            &[7; 32],
            "Passkey",
            [102; 32],
        )
        .unwrap();
    let p = lib
        .begin_add_passkey(pass, slot, &[keys(201).public().id()], NOW)
        .unwrap();
    apply_batch(&mut lib, p);
    let kit = kit_controller();
    let slot = lib.build_sealed_slot(&kit, "Kit", None, [103; 32]).unwrap();
    let mut k = lib.authority().keyring.clone();
    k.controllers.push(kit);
    k.controllers.sort_by_key(Controller::id);
    k.slots.push(slot);
    k.recover_threshold = 1;
    let p = lib
        .begin_keyring(k, None, &[keys(201).public().id()], NOW, [109; 32])
        .unwrap();
    apply_batch(&mut lib, p);
    for (seed, ns, kind, payload) in [
        (
            104,
            "notes",
            "createNotebook",
            json!({"id":"notebook","title":"Notebook","optional":null}),
        ),
        (
            105,
            "reading.books",
            "addBook",
            json!({"id":"book","title":"Synthetic book","creator":"Example writer"}),
        ),
        (
            106,
            "reading.saved",
            "capture",
            json!({"id":"saved","title":"Synthetic document"}),
        ),
        (
            107,
            "listening.podcasts",
            "follow",
            json!({"id":"show","title":"Synthetic show","url":"https://example.test/feed"}),
        ),
    ] {
        let p = success(lib.begin_write(ns, kind, payload, NOW, [seed; 32]).unwrap());
        let signatures = sign_batch(&p);
        lib.merge(p.finish(signatures).unwrap()).unwrap();
    }
    let views: BTreeMap<_, _> = lib
        .authority()
        .namespaces
        .iter()
        .map(|ns| {
            let view = success(lib.view(ns, NOW).unwrap());
            assert_eq!(view.admitted.len(), 1, "{ns}");
            assert!(view.refused.is_empty(), "{ns}");
            (ns.clone(), serde_json::to_value(view).unwrap())
        })
        .collect();
    let mut case = Case::authority(
        "library",
        &["2.1", "5.2", "6.2", "7", "8"],
        "accept",
        lib.records().clone(),
    )
    .probe(
        "library",
        json!({"memberID":keys(14).public().id(),"views":views,"prfCeremony":ceremony}),
    );
    case.metadata["description"]=json!("Complete deterministic 0.4 library: owner, passkey and recovery kit controllers; separate device member; one write per domain. Replaces the retired 0.3 library fixture without altering it.");
    case
}
fn other_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let point = SyntheticAuthenticator::new()
        .unwrap()
        .descriptor(RP, None)
        .unwrap()
        .signing()
        .to_vec();
    let valid = [
        vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20],
        point[1..33].to_vec(),
        vec![0x22, 0x58, 0x20],
        point[33..].to_vec(),
    ]
    .concat();
    for name in [
        "cose-extra-key",
        "cose-duplicate-key",
        "cose-trailing-bytes",
    ] {
        let mut bytes = valid.clone();
        match name {
            "cose-extra-key" => {
                bytes[0] = 0xa6;
                bytes.extend([4, 0]);
            }
            "cose-duplicate-key" => {
                bytes[3] = 1;
                bytes[4] = 2;
            }
            _ => bytes.push(0),
        }
        let mut c = Case::authority(name, &["2.5"], "malformed", Records::new())
            .probe("cose", json!({"file":"input.cbor"}));
        c.binary = Some(bytes);
        cases.push(c);
    }
    // Registration gives PRF bytes but no fresh, verified get assertion. Low-level
    // cryptography can build this box; the Library writer must refuse to publish it.
    let lib = base_library();
    let pass = passkey(vec![Role::Approve, Role::Control]);
    let slot = Slot::from_prf(
        &[202; 32],
        &lib.authority().keyring.vault.id(),
        &pass.id(),
        "Registration output",
        &[6; 32],
        &[7; 32],
        &mut Entropy::new([108; 32]),
    )
    .unwrap();
    cases.push(Case::authority("registration-prf-output",&["5.2","8"],"malformed",lib.records().clone())
        .probe("registrationPrf",json!({"controller":pass,"slot":slot,"source":"registration","salt":b64(&[6;32]),"prfOutput":b64(&[7;32]),"signers":[keys(201).public().id()]})));
    cases
}

// All byte strings in intermediates and keys.json are standard padded base64.
fn hpke_values(sealed: &slots::Sealed, controller: &str, info: &[u8]) -> Value {
    let key = software(controller);
    let recipient = key.public().agreement;
    let dh = key.agree(&sealed.enc).unwrap();
    let shared = colophon_core::hpke::kem_shared_secret(&dh, &sealed.enc, &recipient).unwrap();
    let (aead_key, nonce, exporter) = colophon_core::hpke::key_schedule(&shared, info, 2).unwrap();
    let plaintext = SealedKey {
        enc: sealed.enc.clone(),
        ciphertext: sealed.ciphertext.clone(),
    }
    .finish_open(&recipient, &dh, info)
    .unwrap();
    json!({"info":b64(info),"recipient":b64(&recipient),"enc":b64(&sealed.enc),"ecdh":b64(&dh),"sharedSecret":b64(&shared),"key":b64(&aead_key),"nonce":b64(&nonce),"exporterSecret":b64(&exporter),"plaintext":b64(&plaintext)})
}
fn slot_values(slot: &Slot, v: &PublicIdentity) -> Value {
    let info = slots::slot_info(&v.id(), slot.kind(), slot.controllers());
    match slot {
        Slot::Sealed {
            controllers,
            sealed,
            ..
        } => hpke_values(sealed, &controllers[0], &info),
        Slot::Prf {
            salt, box_bytes, ..
        } => {
            json!({"info":b64(&info),"salt":b64(salt),"ctapInput":b64(&slots::webauthn_prf_input(salt)),"prfOutput":b64(&[7;32]),"key":b64(&slots::prf_key(&[7;32],salt,&info).unwrap()),"nonce":b64(&box_bytes[..12])})
        }
        Slot::Combined {
            controllers,
            parts,
            box_bytes,
            ..
        } => {
            let mut secrets = Vec::new();
            let mut values = Vec::new();
            for (i, p) in parts.iter().enumerate() {
                let pi = slots::part_info(&v.id(), i, p.kind(), &controllers[i]);
                let value = match p {
                    slots::Part::Sealed { sealed } => hpke_values(sealed, &controllers[i], &pi),
                    slots::Part::Prf { salt } => {
                        json!({"info":b64(&pi),"salt":b64(salt),"ctapInput":b64(&slots::webauthn_prf_input(salt)),"prfOutput":b64(&[7;32]),"plaintext":b64(&slots::prf_key(&[7;32],salt,&pi).unwrap())})
                    }
                };
                secrets.push(unb64(&value["plaintext"]).try_into().unwrap());
                values.push(value);
            }
            json!({"info":b64(&info),"parts":values,"key":b64(&slots::combined_key(&secrets,&info).unwrap()),"nonce":b64(&box_bytes[..12])})
        }
    }
}
fn intermediates(records: &Records) -> Value {
    let mut values = Vec::new();
    let mut epoch_values = Vec::new();
    // Only valid prefixes have meaningful slot/epoch derivations. Refused
    // entries preserve their exact bytes without pretending their keys open.
    let mut prefix = Records::new();
    for (path, bytes) in records.iter().filter(|(p, _)| p.starts_with("authority/")) {
        prefix.insert(path.clone(), bytes.clone());
        if Authority::replay(&prefix).is_err() {
            continue;
        }
        let Ok(e) = AuthorityEnvelope::from_json(bytes) else {
            continue;
        };
        let Ok(v) = colophon_core::keys::strict_json::parse(&e.body) else {
            continue;
        };
        let state = Authority::replay(&prefix).unwrap();
        for field in ["epochs", "shares"] {
            if let Some(epochs) = v[field].as_array() {
                for epoch in epochs {
                    let e: Epoch = serde_json::from_value(epoch.clone()).unwrap();
                    for (recipient, seal) in e.seals {
                        let info = state.key_info(&e.namespace, e.epoch, &recipient);
                        let value = hpke_values(
                            &slots::Sealed {
                                enc: seal.enc,
                                ciphertext: seal.ciphertext,
                            },
                            &recipient,
                            &info,
                        );
                        epoch_values.push(json!({"record":path,"field":field,"namespace":e.namespace,"epoch":e.epoch,"recipientID":recipient,"hpke":value}));
                    }
                }
            }
        }
        if let Ok(k) = serde_json::from_value::<Keyring>(v["keyring"].clone()) {
            if k.validate().is_ok() {
                // Malformed collision fixtures may carry keys unrelated to the
                // encrypted routes: only valid published keyring routes qualify.
                let valid = k.slots.iter().all(|s| {
                    s.controllers().iter().all(|id| {
                        k.controller(id).is_some_and(|c| {
                            c.key.is_webauthn()
                                || software(id).public().agreement
                                    == c.key.agreement().unwrap_or_default()
                        })
                    })
                });
                if valid {
                    values.push(json!({"record":path,"vaultID":k.vault.id(),"vault":k.vault,"slots":k.slots.iter().map(|s|slot_values(s,&k.vault)).collect::<Vec<_>>()}));
                }
            }
        }
    }
    json!({"encoding":"base64","keyrings":values,"epochs":epoch_values})
}
fn published_keys() -> Value {
    let software_keys=[11,12,13,14,15,201].into_iter().map(|n| {
        let mut e=Entropy::new([n;32]);let signing=e.take::<32>().unwrap();let agreement=e.take::<32>().unwrap();let p=keys(n).public();
        assert_eq!(SoftwareKeys::from_scalars(&signing,&agreement).unwrap().public(),p);
        json!({"seed":b64(&[n;32]),"signingScalar":b64(&signing),"agreementScalar":b64(&agreement),"id":p.id(),"public":p})
    }).collect::<Vec<_>>();
    json!({"warning":"PUBLIC TEST SECRETS. Never use these keys or seeds for real data.","encoding":"base64","software":software_keys,
        "authenticators":[{"signingScalar":b64(&[1;32]),"descriptor":SyntheticAuthenticator::new().unwrap().descriptor(RP,Some(vec!["android:apk-key-hash:test".into()])).unwrap()},{"signingScalar":b64(&[2;32]),"descriptor":SyntheticAuthenticator::from_scalar(&[2;32]).unwrap().descriptor(RP,None).unwrap()}],
        "kit":{"kit":b64(&[33;32]),"public":kit().public()},
        "vaults":([70,71,202].into_iter().map(|n|json!({"seed":b64(&[n;32]),"public":vault::derive([n;32]).unwrap().public()})).collect::<Vec<_>>()),
        "entropy":"Every deterministic entropy argument is [n; 32]; generator source publishes n at each call.","prfOutput":b64(&[7;32])})
}
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.4")
}
fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}
fn write_case(path: &Path, c: &Case) {
    fs::create_dir_all(path.join("records")).unwrap();
    for (name, bytes) in &c.records {
        let file = path.join("records").join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    write_json(&path.join("case.json"), &c.metadata);
    write_json(&path.join("input.json"), &c.input);
    write_json(&path.join("intermediates.json"), &intermediates(&c.records));
    if let Some(bytes) = &c.binary {
        fs::write(path.join("input.cbor"), bytes).unwrap();
    }
}
fn read_records(path: &Path) -> Records {
    fn walk(base: &Path, dir: &Path, records: &mut Records) {
        for entry in fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(base, &p, records);
            } else {
                records.insert(
                    p.strip_prefix(base).unwrap().to_str().unwrap().into(),
                    fs::read(p).unwrap(),
                );
            }
        }
    }
    let mut r = Records::new();
    if path.is_dir() {
        walk(path, path, &mut r);
    }
    r
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn category<T>(result: colophon_core::Result<T>) -> String {
    match result {
        Ok(_) => "accept".into(),
        Err(e) => e.0.split(':').next().unwrap().into(),
    }
}
fn open_slot(lib: &mut Library, index: usize, prf: &[u8]) -> colophon_core::Result<()> {
    let inputs = lib.begin_unlock_slot(index)?;
    let dh = inputs
        .iter()
        .map(|i| match i {
            slots::OpeningInput::Ecdh {
                controller, enc, ..
            } => Some(software(controller).agree(enc).unwrap()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let secrets = dh
        .iter()
        .map(|s| match s {
            Some(dh) => slots::OpeningSecret::Ecdh(dh),
            None => slots::OpeningSecret::Prf(prf),
        })
        .collect::<Vec<_>>();
    lib.finish_unlock_slot(index, &secrets)
}
fn replay_prf_ceremony(records: &Records, input: &Value) {
    // Rebuild the PRF route from the published get assertion, before accepting
    // any of the subsequent keyring records. This exercises the host contract
    // on default replay as well as during opt-in generation.
    let prefix = records
        .iter()
        .filter(|(path, _)| {
            path.starts_with("requests/")
                || (path.starts_with("authority/") && path.as_str() <= "authority/00000004.json")
        })
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    let mut lib = Library::open(prefix, keys(14).public()).unwrap();
    unlock_owner(&mut lib);
    let ceremony = &input["prfCeremony"];
    let key = serde_json::from_value(ceremony["key"].clone()).unwrap();
    let pending = lib.begin_prf_slot(key, [101; 32]).unwrap();
    assert_eq!(pending.salt.to_vec(), unb64(&ceremony["salt"]));
    let assertion = serde_json::from_value(ceremony["assertion"].clone()).unwrap();
    let slot = lib
        .finish_prf_slot(
            pending,
            SignatureResult {
                signature: unb64(&ceremony["signature"]),
                assertion: Some(assertion),
            },
            &unb64(&ceremony["prfOutput"]),
            "Passkey",
            [102; 32],
        )
        .unwrap();
    let bytes = &records["authority/00000005.json"];
    let env = AuthorityEnvelope::from_json(bytes).unwrap();
    let next: Value = serde_json::from_slice(&env.body).unwrap();
    let k: Keyring = serde_json::from_value(next["keyring"].clone()).unwrap();
    assert_eq!(k.slots.last().unwrap(), &slot);
    let pass = k
        .controller(slot.controllers()[0].as_str())
        .unwrap()
        .clone();
    let action = lib
        .begin_add_passkey(pass, slot, &[keys(201).public().id()], NOW)
        .unwrap();
    assert_eq!(action.steps[0].body, env.body);
    lib.finish_authority(
        action,
        vec![SignatureResult {
            signature: env.signature,
            assertion: env.assertion,
        }],
    )
    .unwrap();
    assert_eq!(&lib.records()["authority/00000005.json"], bytes);
}

fn replay(path: &Path) {
    let c = read_json(&path.join("case.json"));
    let input = read_json(&path.join("input.json"));
    let records = read_records(&path.join("records"));
    assert_eq!(
        read_json(&root().join("keys/keys.json")),
        published_keys(),
        "published secrets"
    );
    assert_eq!(
        read_json(&path.join("intermediates.json")),
        intermediates(&records),
        "cryptographic intermediates: {}",
        path.display()
    );
    let result = match c["probe"].as_str().unwrap() {
        "authority" => category(Authority::replay(&records)),
        "cose" => category(colophon_core::keys::cose::parse(
            &fs::read(path.join("input.cbor")).unwrap(),
        )),
        "slot" => {
            let mut lib = Library::open(records.clone(), keys(14).public()).unwrap();
            category(open_slot(
                &mut lib,
                input["index"].as_u64().unwrap() as usize,
                &unb64(&input["prfOutput"]),
            ))
        }
        "registrationPrf" => {
            let mut lib = Library::open(records.clone(), keys(14).public()).unwrap();
            unlock_owner(&mut lib);
            let controller = serde_json::from_value(input["controller"].clone()).unwrap();
            let slot = serde_json::from_value(input["slot"].clone()).unwrap();
            let signers = serde_json::from_value::<Vec<String>>(input["signers"].clone()).unwrap();
            category(lib.begin_add_passkey(controller, slot, &signers, NOW))
        }
        "history" => {
            let mut lib = Library::open(records.clone(), keys(14).public()).unwrap();
            let index = lib
                .authority()
                .keyring
                .slots
                .iter()
                .position(|s| {
                    s.controllers()
                        .contains(&input["openController"].as_str().unwrap().into())
                })
                .unwrap();
            open_slot(&mut lib, index, &[7; 32]).unwrap();
            let a = lib.authority();
            let v = vault::derive(unb64(&input["vaultSeed"]).try_into().unwrap()).unwrap();
            for (ns, epochs) in &a.epochs {
                for (n, (_, e)) in epochs {
                    let seal = &e.seals[&v.public().id()];
                    let plaintext = seal
                        .finish_open(
                            &v.public().agreement,
                            &v.agree(&seal.enc).unwrap(),
                            &a.key_info(ns, *n, &v.public().id()),
                        )
                        .unwrap();
                    assert_eq!(plaintext, vec![*n as u8; 32]);
                }
            }
            "accept".into()
        }
        "library" => {
            replay_prf_ceremony(&records, &input);
            let mut lib = Library::open(
                records.clone(),
                software(input["memberID"].as_str().unwrap()).public(),
            )
            .unwrap();
            // Replay all controller routes and the member's own epoch seals.
            for index in 0..lib.authority().keyring.slots.len() {
                open_slot(&mut lib, index, &[7; 32]).unwrap();
            }
            for step in lib.begin_unlock() {
                let dh = software(input["memberID"].as_str().unwrap())
                    .agree(&step.peer)
                    .unwrap();
                lib.finish_unlock(&step.namespace, step.epoch, &dh).unwrap();
            }
            for (ns, expected) in input["views"].as_object().unwrap() {
                let view = success(lib.view(ns, NOW).unwrap());
                assert_eq!(serde_json::to_value(view).unwrap(), *expected, "{ns}");
            }
            let notes = success(lib.view("notes", NOW).unwrap());
            assert!(notes.admitted[0].payload["optional"].is_null());
            "accept".into()
        }
        other => panic!("unknown probe: {other}"),
    };
    assert_eq!(
        result,
        c["expected"].as_str().unwrap(),
        "{}",
        path.display()
    );
    if result == "accept" {
        assert_eq!(
            summary(&Authority::replay(&records).unwrap()),
            c["keyring"],
            "keyring summary"
        );
    }
}

const COVERAGE: &str = r#"
| §10 accept bullet | Cases |
| --- | --- |
| Genesis with one raw controller | genesis-one-raw |
| Genesis with threshold 2 (raw plus WebAuthn) | genesis-threshold-two |
| Seq-2 rekey | seq-two-rekey |
| A passkey-signed grant | passkey-grant |
| An import grant under the control rule | import-control-quorum |
| Rekey signed by a control-only controller | control-only-rekey |
| Recovery only adds; approve-only addition below control quorum | recovery-add-approve-only |
| Removal with rotation; new vault reads history | removal-with-rotation |
| Demotion with rotation; demoted controller keeps a new slot | demotion-with-rotation |
| PRF, sealed and two-part combined slots opened | prf-slot-open, sealed-slot-open, combined-slot-open |
| Multi-label subdomain origin | multi-label-origin |
| Allowlisted Android origin | android-origin |
| High-S WebAuthn signature | high-s-webauthn (also low-s-webauthn) |
| Genesis-only library | genesis-only |
| recoverThreshold greater than threshold | recovery-threshold-greater |
| Slot reordering and relabeling without rotation | slot-reorder-relabel |
| Unknown kind signed under control rule (newerFormat) | unknown-kind-control |
| Null inside an operation payload | operation-payload-null (complete library in ../library/) |

| §10 refuse bullet | Cases |
| --- | --- |
| Wrong challenge | wrong-challenge |
| Wrong RP hash | wrong-rp-hash |
| Foreign origin | foreign-origin |
| Origin with user information or port | origin-userinfo, origin-port |
| crossOrigin true | cross-origin |
| webauthn.create | webauthn-create |
| UP missing | up-missing |
| UV missing where required | uv-missing |
| Non-minimal DER | der-non-minimal |
| Another controller's key | foreign-authenticator-key |
| Threshold unmet | threshold-unmet |
| Mixed-role signers | mixed-role-signers |
| Invalid extra cosignature | invalid-extra-cosignature |
| Cosignatures on a single-rule kind | single-rule-cosignatures |
| recoverThreshold 0 used for recovery | recovery-disabled |
| Recovery adding control below control quorum | recovery-add-control |
| Recovery removes, demotes, changes threshold or vault | recovery-remove, recovery-demote, recovery-change-threshold, recovery-change-recover-threshold, recovery-change-vault |
| Removal or demotion without rotation | removal-without-rotation, demotion-without-rotation |
| Vault reuse A→B→A | vault-reuse-a-b-a |
| Shares without vault change | shares-without-vault-change |
| Layout with one of two signatures | layout-minority |
| Import grant under single rule or to agent | import-single-rule, import-agent |
| Key in two principals: controller/member, member/vault | controller-member-collision, member-vault-collision |
| Empty or one-part combined slot | combined-empty, combined-one-part |
| Duplicate controllers in combined slot | combined-duplicate-controllers |
| PRF slot naming raw controller | prf-raw-controller |
| Wrong sizes | sealed-ciphertext-size, sealed-enc-size, prf-salt-size, prf-box-size, combined-box-size, part-ciphertext-size, part-salt-size |
| Slot opens seed for another vault | slot-foreign-vault-seed |
| Wrong PRF output | wrong-prf-output |
| Duplicate JSON names in body and clientData | duplicate-body-name, duplicate-client-data |
| COSE extra/duplicate keys or trailing bytes | cose-extra-key, cose-duplicate-key, cose-trailing-bytes |
| Empty cosignatures array | empty-cosignatures |
| Unauthenticated unknown kind gives badSignature | unknown-kind-unauthenticated |
| Authenticated unknown kind gives newerFormat | unknown-kind-control |
| Seq 2 not full rekey | seq-two-not-rekey, seq-two-incomplete-rekey, seq-two-wrong-epoch, seq-two-missing-namespace |
| 0.3 authority body | authority-three |
| Unknown kind signed by one approve controller | unknown-kind-approve-only |
| Unknown controller field under single rule | controller-unknown-field-single-rule |
| DER long-form length, trailing bytes, extra padding | der-long-length, der-trailing, der-extra-padding |
| Two controllers sharing agreement point | shared-controller-agreement |
| Signing equals agreement | signing-equals-agreement |
| Slot deletion without rotation | slot-deletion-without-rotation |
| Agreement change without rotation | agreement-change-without-rotation |
| Recovery drops duplicate slot | recovery-drops-duplicate-slot |
| PRF slot built from registration output (host check) | registration-prf-output |
| Origins entry starts with https: | origins-https-prefix |
| RP label starts with hyphen | rp-leading-hyphen |
| Import grant read-only, expires not after issued, server | import-read-only, import-expiry-equal, import-expiry-before, import-server |
| importedFrom not 32 lowercase hex | imported-from-uppercase, imported-from-short, imported-from-nonhex |
"#;
#[test]
fn generate_keys_conformance() {
    if std::env::var("COLOPHON_WRITE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let mut cases = authority_cases();
    cases.extend(other_cases());
    let library = complete_library();
    let mut null_case = Case::authority(
        "operation-payload-null",
        &["2.1", "7"],
        "accept",
        library.records.clone(),
    )
    .probe("library", library.input.clone());
    null_case.metadata["description"]=json!("Encrypted notes operation retains an explicit null payload member; full Library replay and domain views match.");
    cases.push(null_case);
    let dest = root();
    fs::create_dir_all(dest.join("keys")).unwrap();
    write_json(&dest.join("keys/keys.json"), &published_keys());
    let mut readme=String::from("# Colophon 0.4 keys conformance vectors\n\nAll keys and seeds are public test secrets. `keys.json` publishes software seeds, private scalars, authenticator keys, kit and vault seeds. Byte strings in JSON use padded standard base64; record files preserve exact signed bytes.\n\nEach case has `case.json` (description, normative sections, named outcome and an accept keyring summary), `records/`, `input.json` (host-only inputs), and `intermediates.json` (slot/part keys, PRF keys, ECDH and HPKE secrets, vault identity; epoch and share HPKE schedules for valid prefixes). COSE registration cases have an empty records directory and exact `input.cbor`: registration precedes authority. Empty directories may be absent in source distributions; the runner handles them. The registration PRF case attempts to publish a cryptographically valid slot without a verified get assertion.\n\n`probe` selects authority replay, slot opening, history opening, registration, COSE parsing, or complete Library replay. A slot refuse case must replay authority successfully before attempting the failing opening. All other record cases replay the entire chain. Recovery rule failures are badSignature under §6.3. The newerFormat case appears in both §10 accept and refuse lists with the same mandated outcome.\n\nGenerate: `COLOPHON_WRITE_VECTORS=1 cargo test -p colophon-core --test keys_conformance`\n\nReplay: `cargo test -p colophon-core --test keys_conformance`\n\nSet PATH and CARGO_NET_OFFLINE as required by the handoff before cargo. Generation is opt-in; default tests only read published files. The runner checks all intermediates and final keyring summaries and checks completeness against the inventory below. `../library/` supplies the complete deterministic 0.4 library replacing the retired 0.3 library vector; the historical 0.3 tree is untouched.\n\n## Case inventory\n\n| Case | Spec sections | Outcome |\n| --- | --- | --- |\n");
    let mut names = std::collections::BTreeSet::new();
    for case in &cases {
        assert!(names.insert(&case.name), "duplicate case name");
        write_case(&dest.join("keys").join(&case.name), case);
        readme.push_str(&format!(
            "| [{}]({}/case.json) | {} | {} |\n",
            case.name,
            case.name,
            case.metadata["sections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| format!("§{}", v.as_str().unwrap()))
                .collect::<Vec<_>>()
                .join(", "),
            case.metadata["expected"].as_str().unwrap()
        ));
    }
    readme.push_str("\n## Coverage of every §10 bullet\n");
    readme.push_str(COVERAGE);
    fs::write(dest.join("keys/README.md"), readme).unwrap();
    write_case(&dest.join("library"), &library);
    fs::write(dest.join("library/README.md"),"# Deterministic Colophon 0.4 library\n\nOwner controller, synthetic PRF passkey controller, recovery-kit controller, and a separate device member. `records/` contains exact Library API output: authority, member request and one operation per listening.podcasts, notes, reading.books and reading.saved. `input.json` publishes expected complete domain views, member ID and the PRF construction assertion. `case.json` publishes the expected keyring. `intermediates.json` publishes vault and slot secrets. Keys are in ../keys/keys.json. All secrets are public and unsafe for real data. Replaces the retired 0.3 library fixture; no historical files are changed.\n").unwrap();
}
#[test]
fn replay_every_keys_conformance_vector() {
    if std::env::var("COLOPHON_WRITE_VECTORS").as_deref() == Ok("1") {
        return;
    }
    let base = root().join("keys");
    let readme = fs::read_to_string(base.join("README.md")).unwrap();
    let mut cases = fs::read_dir(&base)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect::<Vec<_>>();
    cases.sort();
    assert!(!cases.is_empty());
    for case in &cases {
        assert!(readme.contains(&format!(
            "| [{}]",
            case.file_name().unwrap().to_str().unwrap()
        )));
        replay(case);
    }
    let inventory = readme.lines().filter(|l| l.starts_with("| [")).count();
    assert_eq!(cases.len(), inventory, "every listed case is replayed");
    // Every coverage mapping must resolve to a real published case (or library).
    for line in COVERAGE.lines().filter(|l| l.starts_with('|')).skip(2) {
        let column = line.split('|').nth(2).unwrap().trim();
        if column == "Cases" || column == "---" {
            continue;
        }
        let column = column
            .replace(" (also low-s-webauthn)", ", low-s-webauthn")
            .replace(" (complete library in ../library/)", "");
        for name in column.split(", ") {
            assert!(
                base.join(name).join("case.json").is_file(),
                "missing coverage: {name}"
            );
        }
    }
}
#[test]
fn replay_complete_keyring_library() {
    if std::env::var("COLOPHON_WRITE_VECTORS").as_deref() == Ok("1") {
        return;
    }
    replay(&root().join("library"));
}
