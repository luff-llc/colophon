//! Tests of the 0.4 in-place upgrade builder (`v05::write::upgrade`, spec §16.1): the entry
//! reproduces the candidate vectors' bytes from their inputs (the 0.4 base chain, the published
//! keys, the chosen settings), the upgraded account verifies as 0.5 and carries its members,
//! epochs and records, and each refusal the spec names is refused at prepare or finish with its
//! reason.
//!
//! The host's side (keys and signing) is written here, independently of the vector generator
//! (`tests/v5_candidate/`); expected outcomes come from the spec text.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::model::Records as Legacy;
use colophon_core::v05::encoding::{canonical, digest, parse_date};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::write::authority::*;
use colophon_core::v05::write::upgrade::*;
use colophon_core::v05::write::*;
use colophon_core::v05::Failure;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}
fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

// ---------------------------------------------------------------------------------------------
// The host's side.

struct Key {
    sk: SigningKey,
}
fn key_from_scalar(scalar: &[u8]) -> Key {
    Key {
        sk: SigningKey::from_slice(scalar).unwrap(),
    }
}
fn der_int(x: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = x.iter().copied().skip_while(|b| *b == 0).collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    let mut out = vec![2, v.len() as u8];
    out.extend(v);
    out
}
fn der(raw: &[u8]) -> Vec<u8> {
    let mut inner = der_int(&raw[..32]);
    inner.extend(der_int(&raw[32..]));
    let mut out = vec![0x30, inner.len() as u8];
    out.extend(inner);
    out
}
impl Key {
    fn sign_raw(&self, body: &[u8]) -> Vec<u8> {
        let s: P256Signature = self.sk.sign(body);
        s.to_bytes().to_vec()
    }
    fn sign_webauthn(&self, rp: &str, challenge: &str) -> SignatureResult {
        let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
        auth.push(0x05);
        auth.extend([0, 0, 0, 1]);
        let client = canonical(&json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": format!("https://{rp}"),
        }))
        .unwrap();
        let mut m = auth.clone();
        m.extend(Sha256::digest(&client));
        SignatureResult {
            signature: der(&self.sign_raw(&m)),
            assertion: Some((auth, client)),
        }
    }
}

fn published_scalars() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut put = |public: &str, scalar: &str| {
        out.insert(key_id(&dec(public)), dec(scalar));
    };
    let c = repo().join("conformance/0.5/candidate");
    for f in ["keys.json", "rules/keys-r4.json"] {
        for k in read_json(&c.join(f))["keys"].as_object().unwrap().values() {
            put(
                k["signing"].as_str().unwrap(),
                k["scalar"].as_str().unwrap(),
            );
        }
    }
    let v = read_json(&repo().join("conformance/0.4/keys/keys.json"));
    for a in v["authenticators"].as_array().unwrap() {
        put(
            a["descriptor"]["signing"].as_str().unwrap(),
            a["signingScalar"].as_str().unwrap(),
        );
    }
    for s in v["software"].as_array().unwrap() {
        put(
            s["public"]["signing"].as_str().unwrap(),
            s["signingScalar"].as_str().unwrap(),
        );
    }
    out
}

fn sign_steps(steps: &[SigningStep], scalars: &BTreeMap<String, Vec<u8>>) -> Vec<SignatureResult> {
    steps
        .iter()
        .map(|s| {
            let k = key_from_scalar(&scalars[s.signer()]);
            match s.challenge() {
                None => SignatureResult {
                    signature: k.sign_raw(s.body()),
                    assertion: None,
                },
                Some(ch) => k.sign_webauthn("id.example", ch),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Inputs: the 0.4 base chains, the settings.

fn base_chain(case: &str) -> Legacy {
    let dir = repo()
        .join("conformance/0.4/keys")
        .join(case)
        .join("records/authority");
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            let mut bytes = std::fs::read(p).unwrap();
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            (format!("authority/{:08}.json", i + 1), bytes)
        })
        .collect()
}

fn vector_entry(rel: &str) -> Vec<u8> {
    let mut b = std::fs::read(repo().join("conformance/0.5/candidate").join(rel)).unwrap();
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    b
}

fn policy() -> Value {
    json!({"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
           "linkMaxAge": 86400, "memberRule": "single", "recoveryDelay": 259200,
           "rate": {"account": {"bytes": 16777216, "entries": 256},
                    "signer": {"bytes": 4194304, "entries": 64}}})
}

const T_UPGRADE: i64 = 1_794_387_600_000; // 2026-11-11T09:00:00Z
const NOW: i64 = 1_794_470_400_000; // 2026-11-12T08:00:00Z

fn first_controller(chain: &Legacy) -> String {
    let g = &chain["authority/00000001.json"];
    let env: Value = serde_json::from_slice(g).unwrap();
    let body: Value = serde_json::from_slice(&dec(env["body"].as_str().unwrap())).unwrap();
    key_id(&dec(body["keyring"]["controllers"][0]["key"]["signing"]
        .as_str()
        .unwrap()))
}

fn params(chain: &Legacy) -> UpgradeParams {
    UpgradeParams {
        policy: policy(),
        add_threshold: 1,
        count_by: "keys".into(),
        issued_ms: T_UPGRADE,
        signers: vec![first_controller(chain)],
    }
}

fn objects_of(chain: &Legacy, extra: &[Vec<u8>]) -> Objects {
    let mut o = Objects {
        entries: chain.values().cloned().collect(),
        ..Objects::default()
    };
    o.entries.extend(extra.iter().cloned());
    o
}

fn build(chain: &Legacy, p: &UpgradeParams) -> Result<Vec<u8>, Failure> {
    let scalars = published_scalars();
    let pending = prepare_upgrade(chain, p, NOW)?;
    let sigs = sign_steps(pending.steps(), &scalars);
    Ok(pending.finish(sigs)?.entries[0].1.clone())
}

// ---------------------------------------------------------------------------------------------
// Vectors.

#[test]
fn accept_vector_reproduces_from_the_base_chain_the_keys_and_the_settings() {
    let chain = base_chain("seq-two-rekey");
    let built = build(&chain, &params(&chain)).unwrap();
    assert_eq!(
        built,
        vector_entry("upgrade/accept/records/authority/00000003.json")
    );
    // The same bytes under the other vectors' `then-*` extensions share this entry.
    assert_eq!(
        built,
        vector_entry("upgrade/then-v5-layout/records/authority/00000003.json")
    );
}

#[test]
fn the_upgraded_account_verifies_as_05_and_the_0_4_prefix_is_unchanged() {
    let chain = base_chain("seq-two-rekey");
    let built = build(&chain, &params(&chain)).unwrap();
    let v = verify_history(&objects_of(&chain, &[built]), &Persisted::default(), NOW);
    assert!(v.stop.is_none(), "{:?}", v.stop);
    assert_eq!(v.code(), "ok");
    assert_eq!(v.seq(), 3);
    let s = v.state.unwrap();
    assert_eq!(s.upgrade_seq, Some(3));
    assert_eq!(s.keyring().policy.recovery_delay(), 259_200);
}

/// The vector's own refusals, re-expressed as what the builder says before a host is asked to
/// sign. Each reason is the verifier's.
#[test]
fn prepare_refuses_what_the_upgrade_vectors_refuse() {
    let chain = base_chain("seq-two-rekey");
    let ok = params(&chain);
    // policy.headMaxAge below its range (30-86,400).
    let mut p = ok.clone();
    p.policy["headMaxAge"] = json!(10);
    let e = prepare_upgrade(&chain, &p, NOW).unwrap_err();
    assert!(matches!(e, Failure::Malformed(_)), "{e:?}");
    // addThreshold above threshold (1), and zero.
    for n in [2, 0] {
        let mut p = ok.clone();
        p.add_threshold = n;
        let e = prepare_upgrade(&chain, &p, NOW).unwrap_err();
        assert!(matches!(e, Failure::Malformed(_)), "{n}: {e:?}");
    }
    // countBy holders: a 0.4 controller has no holder.
    let mut p = ok.clone();
    p.count_by = "holders".into();
    assert!(matches!(
        prepare_upgrade(&chain, &p, NOW).unwrap_err(),
        Failure::Malformed(_)
    ));
    // An unknown countBy.
    let mut p = ok.clone();
    p.count_by = "people".into();
    assert!(prepare_upgrade(&chain, &p, NOW).is_err());
    // A policy with an unknown field is not carried.
    let mut p = ok.clone();
    p.policy["surprise"] = json!(1);
    assert!(prepare_upgrade(&chain, &p, NOW).is_err());
    // A signer that is not a controller: badSignature.
    let mut p = ok.clone();
    p.signers = vec!["0".repeat(32)];
    assert!(matches!(
        prepare_upgrade(&chain, &p, NOW).unwrap_err(),
        Failure::BadSignature(_)
    ));
    // No signer, and a signer twice.
    let mut p = ok.clone();
    p.signers = vec![];
    assert!(prepare_upgrade(&chain, &p, NOW).is_err());
    let mut p = ok.clone();
    p.signers = vec![ok.signers[0].clone(), ok.signers[0].clone()];
    assert!(prepare_upgrade(&chain, &p, NOW).is_err());
    // `issued` before the previous entry's.
    let mut p = ok.clone();
    p.issued_ms = 0;
    assert!(prepare_upgrade(&chain, &p, NOW).is_err());
    // `issued` outside the years 0001-9999.
    let mut p = ok.clone();
    p.issued_ms = i64::MAX;
    assert!(prepare_upgrade(&chain, &p, NOW).is_err());
}

#[test]
fn prepare_refuses_an_upgrade_at_seq_two() {
    let chain = base_chain("genesis-only");
    assert_eq!(chain.len(), 1);
    // The vector `at-seq-two`: a library whose seq 2 must be its rekey.
    let e = prepare_upgrade(&chain, &params(&chain), NOW).unwrap_err();
    assert!(
        matches!(e, Failure::Malformed(ref m) if m.contains("seq 2")),
        "{e:?}"
    );
}

#[test]
fn prepare_refuses_a_second_upgrade_and_a_history_that_already_holds_05() {
    let chain = base_chain("seq-two-rekey");
    let upgraded = build(&chain, &params(&chain)).unwrap();
    let mut twice = chain.clone();
    twice.insert("authority/00000003.json".into(), upgraded.clone());
    let e = prepare_upgrade(&twice, &params(&chain), NOW).unwrap_err();
    assert!(
        matches!(e, Failure::NewerFormat(ref m) if m.contains("already upgraded")),
        "{e:?}"
    );
    // A `/5` entry after the upgrade (the `then-v5-layout` vector's seq 4).
    twice.insert(
        "authority/00000004.json".into(),
        vector_entry("upgrade/then-v5-layout/records/authority/00000004.json"),
    );
    assert!(prepare_upgrade(&twice, &params(&chain), NOW).is_err());
}

#[test]
fn prepare_refuses_a_damaged_0_4_history() {
    let chain = base_chain("seq-two-rekey");
    // A flipped signature byte in entry 2.
    let mut bad = chain.clone();
    let env: Value = serde_json::from_slice(&bad["authority/00000002.json"]).unwrap();
    let mut sig = dec(env["signature"].as_str().unwrap());
    sig[5] ^= 1;
    let mut env2 = env.clone();
    env2["signature"] = json!(b64(&sig));
    bad.insert("authority/00000002.json".into(), canonical(&env2).unwrap());
    assert!(prepare_upgrade(&bad, &params(&chain), NOW).is_err());
    // A gap.
    let mut gap = chain.clone();
    gap.remove("authority/00000002.json");
    assert!(prepare_upgrade(&gap, &params(&chain), NOW).is_err());
    // No records, and garbage.
    assert!(prepare_upgrade(&Legacy::new(), &params(&chain), NOW).is_err());
    let mut junk = Legacy::new();
    junk.insert("authority/00000001.json".into(), b"{".to_vec());
    assert!(prepare_upgrade(&junk, &params(&chain), NOW).is_err());
}

// ---------------------------------------------------------------------------------------------
// Finish verifies the exact bytes it returns.

#[test]
fn finish_refuses_a_signature_by_another_key_and_returns_nothing() {
    let chain = base_chain("seq-two-rekey");
    let pending = prepare_upgrade(&chain, &params(&chain), NOW).unwrap();
    let scalars = published_scalars();
    // Sign with a key that is not the controller's.
    let other = key_from_scalar(
        scalars
            .values()
            .find(|s| **s != scalars[pending.steps()[0].signer()])
            .unwrap(),
    );
    let sigs = vec![SignatureResult {
        signature: other.sign_raw(pending.steps()[0].body()),
        assertion: None,
    }];
    let e = pending.finish(sigs).unwrap_err();
    assert!(matches!(e, Failure::BadSignature(_)), "{e:?}");
}

#[test]
fn finish_refuses_a_signature_over_other_bytes_and_a_wrong_count() {
    let chain = base_chain("seq-two-rekey");
    let scalars = published_scalars();
    let pending = prepare_upgrade(&chain, &params(&chain), NOW).unwrap();
    let k = key_from_scalar(&scalars[pending.steps()[0].signer()]);
    let mut body = pending.steps()[0].body().to_vec();
    body.push(b' ');
    let e = pending
        .finish(vec![SignatureResult {
            signature: k.sign_raw(&body),
            assertion: None,
        }])
        .unwrap_err();
    assert!(matches!(e, Failure::BadSignature(_)), "{e:?}");
    let pending = prepare_upgrade(&chain, &params(&chain), NOW).unwrap();
    assert!(pending.finish(vec![]).is_err());
}

#[test]
fn finish_holds_an_upgrade_issued_in_the_future() {
    let chain = base_chain("seq-two-rekey");
    let scalars = published_scalars();
    let mut p = params(&chain);
    p.issued_ms = NOW + 3_600_000;
    let pending = prepare_upgrade(&chain, &p, NOW).unwrap();
    let sigs = sign_steps(pending.steps(), &scalars);
    let e = pending.finish(sigs).unwrap_err();
    assert!(matches!(e, Failure::Unavailable(_)), "{e:?}");
}

// ---------------------------------------------------------------------------------------------
// End to end: an account with members, epochs and records upgrades, takes a 0.5 entry, and
// still admits its old records (§11.5).

/// The `upgraded-fence` vector's authority entries below the upgrade (seq 1..3) are the 0.4
/// account: a member and a legacy epoch. Everything above is rebuilt here.
fn fence_dir() -> PathBuf {
    repo().join("conformance/0.5/candidate/records/upgraded-fence")
}
fn fence_prefix() -> Legacy {
    (1..=3)
        .map(|n| {
            let p = fence_dir().join(format!("records/authority/{n:08}.json"));
            let mut b = std::fs::read(p).unwrap();
            if b.last() == Some(&b'\n') {
                b.pop();
            }
            (format!("authority/{n:08}.json"), b)
        })
        .collect()
}

#[test]
fn an_account_with_members_epochs_and_records_upgrades_and_still_admits_its_records() {
    use colophon_core::v05::records::{judge_records, EpochKeys, HeldRecord, RecordAuthority};
    use colophon_core::v05::vault::EcdhOutput;
    let prefix = fence_prefix();
    let p = params(&prefix);
    let upgrade = build(&prefix, &p).unwrap();
    assert_eq!(
        upgrade,
        vector_entry("records/upgraded-fence/records/authority/00000004.json")
    );
    // The vector's later authority entries stay as they are (written by members and the
    // controller); the entry at seq 4 is the one built here.
    let mut entries: Vec<Vec<u8>> = prefix.values().cloned().collect();
    entries.push(upgrade);
    for n in 5..=9 {
        let p = fence_dir().join(format!("records/authority/{n:08}.json"));
        if p.exists() {
            entries.push(vector_entry(&format!(
                "records/upgraded-fence/records/authority/{n:08}.json"
            )));
        }
    }
    let objects = Objects {
        entries,
        ..Objects::default()
    };
    let auth = RecordAuthority::from_objects(&objects, NOW).unwrap();
    auth.require_clean().unwrap();
    assert_eq!(auth.upgrade_seq(), Some(4));
    let case = read_json(&fence_dir().join("case.json"));
    let mut keys = EpochKeys::new();
    for h in case["holders"].as_array().unwrap() {
        let id = h["member"].as_str().unwrap();
        let sk = p256::SecretKey::from_slice(&dec(h["agreement"].as_str().unwrap())).unwrap();
        for ns in auth.namespaces() {
            for epoch in 1..=auth.latest_epoch(ns) {
                let Some(req) = auth.epoch_seal_request(ns, epoch, id) else {
                    continue;
                };
                let pk = p256::PublicKey::from_sec1_bytes(&req.enc).unwrap();
                let dh = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                let dh = EcdhOutput::from_host(dh.raw_secret_bytes().as_slice()).unwrap();
                keys.insert(auth.open_epoch(ns, epoch, id, &dh).unwrap())
                    .unwrap();
            }
        }
    }
    let mut held = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<HeldRecord>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut es: Vec<PathBuf> = rd.map(|e| e.unwrap().path()).collect();
        es.sort();
        for p in es {
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.push(HeldRecord {
                    path: p
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    bytes: std::fs::read(&p).unwrap(),
                });
            }
        }
    }
    walk(&fence_dir(), &fence_dir().join("ops"), &mut held);
    let j = judge_records(&auth, &keys, &held);
    let want = case["expected"]["records"].as_object().unwrap();
    let mut admitted_legacy = 0;
    for r in &j.records {
        assert_eq!(
            r.outcome.code(),
            want[&r.path].as_str().unwrap(),
            "{}",
            r.path
        );
        admitted_legacy += (r.outcome.code() == "admitted") as usize;
    }
    assert!(admitted_legacy >= 1);
    for path in case["expected"]["opened"].as_array().unwrap() {
        assert!(
            j.records
                .iter()
                .find(|r| r.path == path.as_str().unwrap())
                .unwrap()
                .plaintext
                .is_some(),
            "{path}: admitted but did not open"
        );
    }
}

#[test]
fn the_upgraded_account_accepts_a_05_entry() {
    let chain = base_chain("seq-two-rekey");
    let scalars = published_scalars();
    let p = params(&chain);
    let upgrade = build(&chain, &p).unwrap();
    let objects = objects_of(&chain, &[upgrade]);
    let by = p.signers[0].clone();
    // A `/5` layout transition under the control rule, then its activation (the vector
    // `then-v5-layout`, built here by the authority builders).
    let t = prepare_transition(
        &objects,
        NOW,
        &TransitionParams {
            anchor: None,
            issued_ms: T_UPGRADE + 1_000,
            signers: vec![by.clone()],
            rule: TransitionRule::Control,
            change: json!({"layout": 2}),
        },
    )
    .unwrap();
    let sigs = sign_steps(t.steps(), &scalars);
    let transition = t.finish(sigs).unwrap().pending[0].clone();
    let mut held = objects.clone();
    held.pending.push(transition.clone());
    let body_digest = digest(&dec(serde_json::from_slice::<Value>(&transition).unwrap()
        ["body"]
        .as_str()
        .unwrap()));
    let a = prepare_activate(&held, NOW, &body_digest).unwrap();
    let rec = a.finish(vec![]).unwrap();
    assert_eq!(rec.entries[0].0, 4);
    let mut all = held.clone();
    all.entries.push(rec.entries[0].1.clone());
    let v = verify_history(&all, &Persisted::default(), NOW);
    assert_eq!((v.code().as_str(), v.seq()), ("ok", 4));
    let _ = parse_date;
}

// ---------------------------------------------------------------------------------------------
// The 0.4 control rule: the threshold, the `control` role, UV.

fn controller_ids(chain: &Legacy) -> Vec<(String, Vec<String>, bool)> {
    let g: Value = serde_json::from_slice(&chain["authority/00000001.json"]).unwrap();
    let b: Value = serde_json::from_slice(&dec(g["body"].as_str().unwrap())).unwrap();
    b["keyring"]["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                key_id(&dec(c["key"]["signing"].as_str().unwrap())),
                c["roles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r.as_str().unwrap().to_string())
                    .collect(),
                c["key"]["form"] == "webauthn",
            )
        })
        .collect()
}

#[test]
fn a_signer_below_the_threshold_or_without_control_is_refused_and_the_quorum_upgrades() {
    let chain = base_chain("import-control-quorum");
    let cs = controller_ids(&chain);
    let control: Vec<&String> = cs
        .iter()
        .filter(|(_, r, _)| r.contains(&"control".to_string()))
        .map(|(i, _, _)| i)
        .collect();
    let approve_only = &cs
        .iter()
        .find(|(_, r, _)| r == &vec!["approve".to_string()])
        .unwrap()
        .0;
    assert_eq!(control.len(), 2);
    let mut p = params(&chain);
    // One control signer under a threshold of two: refused.
    p.signers = vec![control[0].clone()];
    let e = prepare_upgrade(&chain, &p, NOW).unwrap_err();
    assert!(
        matches!(e, Failure::BadSignature(ref m) if m.contains("0.4 control rule")),
        "{e:?}"
    );
    // Two signers, one of them approve-only: refused.
    p.signers = vec![control[0].clone(), approve_only.clone()];
    assert!(matches!(
        prepare_upgrade(&chain, &p, NOW).unwrap_err(),
        Failure::BadSignature(_)
    ));
    // The quorum upgrades. The first signer is `by`; the cosignature is ordered by ID.
    p.signers = vec![control[1].clone(), control[0].clone()];
    let pending = prepare_upgrade(&chain, &p, NOW).unwrap();
    assert_eq!(pending.steps().len(), 2);
    assert_eq!(pending.steps()[0].role(), StepRole::Primary);
    assert_eq!(pending.steps()[1].role(), StepRole::Cosignature);
    let sigs = sign_steps(pending.steps(), &published_scalars());
    let env = pending.finish(sigs).unwrap().entries[0].1.clone();
    let v = verify_history(&objects_of(&chain, &[env]), &Persisted::default(), NOW);
    assert_eq!((v.code().as_str(), v.seq()), ("ok", 4));
    // A cosignature that leaves the primary out of the sorted list is still assembled sorted.
}

#[test]
fn a_webauthn_controller_signs_an_upgrade_only_with_user_verification() {
    let chain = base_chain("passkey-grant");
    let cs = controller_ids(&chain);
    let (id, _, webauthn) = &cs[0];
    assert!(*webauthn);
    let mut p = params(&chain);
    p.signers = vec![id.clone()];
    let scalars = published_scalars();
    let pending = prepare_upgrade(&chain, &p, NOW).unwrap();
    let step = &pending.steps()[0];
    assert!(step.uv(), "the 0.4 rule demands UV of a WebAuthn signer");
    let rp = step
        .descriptor()
        .unwrap()
        .webauthn()
        .unwrap()
        .rp()
        .to_string();
    let ch = step.challenge().unwrap().to_string();
    let k = key_from_scalar(&scalars[id]);
    // Without UV (flags 0x01): refused by the verifier's rule, nothing returned.
    let mut no_uv = k.sign_webauthn(&rp, &ch);
    let (mut auth, client) = no_uv.assertion.clone().unwrap();
    auth[32] = 0x01;
    let mut m = auth.clone();
    m.extend(Sha256::digest(&client));
    no_uv.signature = der(&k.sign_raw(&m));
    no_uv.assertion = Some((auth, client));
    let e = pending.finish(vec![no_uv]).unwrap_err();
    assert!(matches!(e, Failure::BadSignature(_)), "{e:?}");
    // With UV it is accepted.
    let pending = prepare_upgrade(&chain, &p, NOW).unwrap();
    let ok = k.sign_webauthn(&rp, &ch);
    let env = pending.finish(vec![ok]).unwrap().entries[0].1.clone();
    let v = verify_history(&objects_of(&chain, &[env]), &Persisted::default(), NOW);
    assert_eq!((v.code().as_str(), v.seq()), ("ok", 4));
}
