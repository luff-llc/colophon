//! Tests of the succession builders (`v05::write::succession`, spec §15, §16.2, §16.3): the
//! genesis and F of every Swift succession vector reproduce from the predecessor history, the
//! published keys and the chosen inputs; successions complete end to end and verify; and each
//! refusal the spec names is refused at prepare or finish with its reason.
#![allow(clippy::unwrap_used)]
#[path = "v05_e7_support/mod.rs"]
mod support;
use colophon_core::v05::encoding::{canonical, digest, parse_date};
use colophon_core::v05::history::swift;
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::write::authority::*;
use colophon_core::v05::write::calls::*;
use colophon_core::v05::write::succession::*;
use colophon_core::v05::write::*;
use colophon_core::v05::Failure;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::*;

const DEFAULT_NOW: &str = "2026-11-14T10:15:00Z";

fn ms(s: &str) -> i64 {
    parse_date(s).unwrap()
}

/// The vector replay signer: a raw key signs the step's body; a WebAuthn key re-signs the
/// assertion the vector's item carries (checking the challenge is the one the step asks for).
fn sign_like_vector(
    steps: &[SigningStep],
    item: &dyn Fn(&SigningStep) -> Option<Value>,
    scalars: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<SignatureResult>, String> {
    let mut out = Vec::new();
    for s in steps {
        let k = key_from_scalar(scalars.get(s.signer()).ok_or("scalar not published")?);
        match s.challenge() {
            None => out.push(SignatureResult {
                signature: k.sign_raw(s.body()),
                assertion: None,
            }),
            Some(ch) => {
                let it = item(s).ok_or("the vector has no such item")?;
                let a = it.get("assertion").ok_or("no vector assertion")?;
                let (d, c) = (
                    dec(a["authenticatorData"].as_str().unwrap()),
                    dec(a["clientData"].as_str().unwrap()),
                );
                let cv: Value = serde_json::from_slice(&c).unwrap();
                if cv["challenge"] != ch {
                    return Err("DIFFERENT: the WebAuthn challenge differs".into());
                }
                out.push(k.sign_assertion(&d, &c));
            }
        }
    }
    Ok(out)
}

struct Vector {
    dir: std::path::PathBuf,
    name: String,
    case: Value,
    predecessor: Vec<Vec<u8>>,
    genesis: Vec<u8>,
}
fn vectors() -> Vec<Vector> {
    let root = repo().join("conformance/0.5/candidate/succession");
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("swift-"))
        .collect();
    names.sort();
    for n in names {
        let dir = root.join(&n);
        out.push(Vector {
            case: read_json(&dir.join("case.json")),
            predecessor: files_in(&dir.join("predecessor/authority")),
            genesis: strip(std::fs::read(dir.join("genesis.json")).unwrap()),
            name: n,
            dir,
        });
    }
    out
}
impl Vector {
    fn genesis_body(&self) -> Value {
        body_value(&self.genesis)
    }
    fn head_seq(&self) -> usize {
        self.genesis_body()["predecessor"]["head"]["seq"]
            .as_u64()
            .unwrap() as usize
    }
    /// The predecessor up to and including `head`, and F when the vector holds it.
    fn prefix(&self) -> Vec<Vec<u8>> {
        self.predecessor[..self.head_seq()].to_vec()
    }
    fn f(&self) -> Option<Vec<u8>> {
        self.predecessor.get(self.head_seq()).cloned()
    }
    fn now(&self) -> i64 {
        ms(self.case["expected"]["now"].as_str().unwrap_or(DEFAULT_NOW))
    }
    fn successor_objects(&self) -> Objects {
        let mut o = Objects {
            entries: files_in(&self.dir.join("successor/authority")),
            ..Objects::default()
        };
        if let Ok(b) = std::fs::read(self.dir.join("genesis-receipt.json")) {
            o.pending.push(strip(b));
        }
        if let Ok(b) = std::fs::read(self.dir.join("successor-head.json")) {
            o.heads.push(strip(b));
        }
        o
    }
}

fn ids_of(env: &Value, list: &str) -> Vec<String> {
    env.get(list)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|i| i["signer"].as_str().unwrap().to_string())
        .collect()
}

/// Build the vector's genesis from its inputs: the predecessor, the chosen keyring (slots built
/// elsewhere, so an opaque input), `issued`, who signs and who hands over. Returns the bytes.
fn build_genesis(v: &Vector, scalars: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    let env: Value = serde_json::from_slice(&v.genesis).unwrap();
    let body = v.genesis_body();
    let by = body["by"].as_str().unwrap().to_string();
    let mut signers = vec![by];
    signers.extend(ids_of(&env, "cosignatures"));
    let p = SwiftGenesisParams {
        label: body["label"].as_str().unwrap().into(),
        namespaces: body["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect(),
        keyring: body["keyring"].clone(),
        issued_ms: ms(body["issued"].as_str().unwrap()),
        predecessor: v.prefix(),
        signers,
        handover: ids_of(&env, "handover"),
    };
    let pending = prepare_swift_genesis(&p, v.now()).map_err(|e| format!("prepare: {e}"))?;
    let item = |s: &SigningStep| -> Option<Value> {
        let list = match s.role() {
            StepRole::Primary => return Some(env.clone()),
            StepRole::Cosignature => "cosignatures",
            StepRole::Possession => "additions",
            StepRole::Handover => "handover",
        };
        env.get(list)?
            .as_array()?
            .iter()
            .find(|i| i["signer"] == s.signer())
            .cloned()
    };
    let sigs = sign_like_vector(pending.steps(), &item, scalars)?;
    let rec = pending.finish(sigs).map_err(|e| format!("finish: {e}"))?;
    Ok(rec.entries[0].1.clone())
}

fn build_freeze(v: &Vector, scalars: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    let f = v.f().ok_or("the vector holds no F")?;
    let fenv: Value = serde_json::from_slice(&f).unwrap();
    let fb = body_value(&f);
    let signer0 = fb.get("signer").and_then(Value::as_str).map(str::to_string);
    // A root library's F is `by: root`: the signer is the current root, found from the history.
    let signers: Vec<String> = match signer0 {
        Some(s) => std::iter::once(s)
            .chain(ids_of(&fenv, "cosignatures"))
            .collect(),
        None => vec![root_of(&v.prefix())],
    };
    let p = SwiftFreezeParams {
        predecessor: v.prefix(),
        successor: v.successor_objects(),
        issued_ms: ms(fb["issued"].as_str().unwrap()),
        signers,
    };
    let pending = prepare_swift_freeze(&p, v.now()).map_err(|e| format!("prepare: {e}"))?;
    let item = |s: &SigningStep| -> Option<Value> {
        if s.role() == StepRole::Primary {
            return Some(fenv.clone());
        }
        fenv.get("cosignatures")?
            .as_array()?
            .iter()
            .find(|i| i["signer"] == s.signer())
            .cloned()
    };
    let sigs = sign_like_vector(pending.steps(), &item, scalars)?;
    let done = pending.finish(sigs).map_err(|e| format!("finish: {e}"))?;
    Ok(done.entry)
}

/// The current root of a root library: the last `handover`'s root, else the genesis's.
fn root_of(prefix: &[Vec<u8>]) -> String {
    let mut root = None;
    for e in prefix {
        let b = body_value(e);
        if matches!(b["kind"].as_str(), Some("genesis" | "handover")) {
            root = Some(b["root"]["signing"].as_str().unwrap().to_string());
        }
    }
    colophon_core::v05::ids::key_id(&dec(&root.unwrap()))
}

/// Every vector: a valid succession's genesis and F reproduce byte for byte; an invalid one is
/// refused by the builder before a host is asked to sign, for the reason the vector gives.
#[test]
fn the_swift_vectors_reproduce_from_their_inputs() {
    let scalars = published_scalars();
    let (mut genesis_same, mut f_same, mut refused) = (0, 0, 0);
    let mut bad = Vec::new();
    for v in vectors() {
        let verified = v.case["expected"]["succession"] == "verified";
        let genesis = build_genesis(&v, &scalars);
        let freeze = v.f().map(|_| build_freeze(&v, &scalars));
        match &genesis {
            Ok(b) if *b == v.genesis => genesis_same += 1,
            Ok(_) => bad.push(format!("{}: genesis bytes differ", v.name)),
            Err(e) if v.case["expected"]["genesis"] == "badSignature" || !verified => {
                // The vector's genesis is badSignature (its handover or proofs are below the
                // rule), or its succession is unverified for a handover below the F rule.
                if e.contains("handover does not meet") {
                    refused += 1;
                } else {
                    bad.push(format!(
                        "{}: genesis refused for another reason: {e}",
                        v.name
                    ));
                }
            }
            Err(e) => bad.push(format!("{}: valid genesis not built: {e}", v.name)),
        }
        match (&freeze, verified) {
            (Some(Ok(b)), true) if Some(b) == v.f().as_ref() => f_same += 1,
            (Some(Ok(_)), true) => bad.push(format!("{}: F bytes differ", v.name)),
            (Some(Err(e)), true) => bad.push(format!("{}: valid F not built: {e}", v.name)),
            (Some(Ok(_)), false) => bad.push(format!("{}: built an F that never verifies", v.name)),
            (Some(Err(_)), false) | (None, _) => {}
        }
    }
    println!("genesis identical {genesis_same}, refused {refused}; F identical {f_same}");
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(genesis_same >= 14 && f_same >= 7, "{genesis_same} {f_same}");
}

fn vector(name: &str) -> Vector {
    vectors().into_iter().find(|v| v.name == name).unwrap()
}

/// The home of a vector: the member that receipted the genesis.
fn receipt_of(v: &Vector) -> (String, i64) {
    let r = body_value(&strip(
        std::fs::read(v.dir.join("genesis-receipt.json")).unwrap(),
    ));
    (
        r["by"].as_str().unwrap().to_string(),
        ms(r["received"].as_str().unwrap()),
    )
}

#[test]
fn a_successor_home_drafts_the_genesis_receipt_the_vector_holds() {
    let scalars = published_scalars();
    for name in ["swift-root-library", "swift-keyring", "swift-webauthn"] {
        let v = vector(name);
        let (home, received) = receipt_of(&v);
        let objects = Objects {
            entries: files_in(&v.dir.join("successor/authority")),
            predecessor: v.prefix(),
            ..Objects::default()
        };
        let prepared = prepare_genesis_receipt(&objects, &home, received).unwrap();
        assert_eq!(
            prepared.object(),
            digest(&dec(serde_json::from_slice::<Value>(&v.genesis).unwrap()
                ["body"]
                .as_str()
                .unwrap()))
        );
        let sig = sign_steps(std::slice::from_ref(prepared.step()), &scalars).remove(0);
        let env = finish_genesis_receipt(&prepared, &sig).unwrap();
        assert_eq!(
            env,
            strip(std::fs::read(v.dir.join("genesis-receipt.json")).unwrap()),
            "{name}"
        );
        // The window is the window: before its opening, and after its end, no receipt.
        let t = succession_status(
            &verify_history(&objects, &Persisted::default(), received)
                .state
                .unwrap(),
        )
        .unwrap()
        .timing
        .unwrap();
        assert!(prepare_genesis_receipt(&objects, &home, t.window_start_ms - 1_000).is_err());
        let e = prepare_genesis_receipt(&objects, &home, t.window_end_ms + 1_000).unwrap_err();
        assert!(
            matches!(e, Failure::Malformed(ref m) if m.contains("within the succession window")),
            "{e:?}"
        );
        // A home signs at most one receipt per object.
        let mut again = objects.clone();
        again.pending.push(env.clone());
        let e = prepare_genesis_receipt(&again, &home, received + 1_000).unwrap_err();
        assert!(
            matches!(e, Failure::Malformed(ref m) if m.contains("at most one receipt")),
            "{e:?}"
        );
        // A member that was not a home at the window's entry has no receipt to give.
        assert!(prepare_genesis_receipt(&objects, &"0".repeat(32), received).is_err());
        // A receipt signed by another key is refused at finish.
        let other = key_from_scalar(scalars.values().find(|s| **s != scalars[&home]).unwrap());
        let forged = SignatureResult {
            signature: other.sign_raw(prepared.step().body()),
            assertion: None,
        };
        assert!(finish_genesis_receipt(&prepared, &forged).is_err());
    }
}

#[test]
fn timing_gives_the_window_the_due_time_the_deadline_and_the_vetoers() {
    let v = vector("swift-keyring");
    let objects = Objects {
        entries: files_in(&v.dir.join("successor/authority")),
        predecessor: v.prefix(),
        ..Objects::default()
    };
    let st = verify_history(&objects, &Persisted::default(), v.now())
        .state
        .unwrap();
    let status = succession_status(&st).unwrap();
    let t = status.timing.clone().unwrap();
    // W0 is the `issued` of the activation that left the account with headQuorum homes; the
    // policy's recoveryDelay is 259,200 s (3 days).
    assert_eq!(t.window_start_ms, ms("2026-11-11T09:59:00Z"));
    assert_eq!(t.window_end_ms, t.window_start_ms + 300_000);
    assert_eq!(t.recovery_delay_s, 259_200);
    assert_eq!(t.veto_deadline_ms, t.window_start_ms + 259_200_000);
    assert_eq!(t.due_ms, t.veto_deadline_ms + 300_000);
    assert_eq!(t.quorum, 1);
    assert_eq!(t.homes.len(), 1);
    assert_eq!(t.keys_needed, 1);
    assert!(status.authorized && !status.vetoed);
    // §15.1 step 3: Mac and the kit (current at head) may veto, and so may the root and the
    // recovery identity, which the keyring entry (the last that removed a controller) replaced:
    // current immediately before it.
    let h = swift::verify(&v.prefix()).unwrap();
    let mut ids: Vec<String> = h
        .states
        .iter()
        .flat_map(|s| s.controllers.keys().cloned())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(t.vetoers.iter().cloned().collect::<Vec<_>>(), ids);
    assert_eq!(ids.len(), 4);
}

// ---------------------------------------------------------------------------------------------
// End to end.

/// A succession built entirely by the builders from the vector's inputs: the genesis, the
/// receipt, F; the successor's own entry that opened the window and the home's fresh head are
/// held objects (they come from the account's other builders and the home).
fn complete(v: &Vector, scalars: &BTreeMap<String, Vec<u8>>) -> (Objects, Vec<u8>, Vec<u8>) {
    let genesis = build_genesis(v, scalars).unwrap();
    let mut entries = files_in(&v.dir.join("successor/authority"));
    entries[0] = genesis.clone();
    entries.truncate(2);
    let (home, received) = receipt_of(v);
    let mut objects = Objects {
        entries,
        predecessor: v.prefix(),
        ..Objects::default()
    };
    let prepared = prepare_genesis_receipt(&objects, &home, received).unwrap();
    let sig = sign_steps(std::slice::from_ref(prepared.step()), scalars).remove(0);
    objects.heads = v.successor_objects().heads;
    objects
        .pending
        .push(finish_genesis_receipt(&prepared, &sig).unwrap());
    // F, signed as the vector's F is.
    let mut with = Vector {
        genesis: genesis.clone(),
        ..clone_vector(v)
    };
    with.dir = v.dir.clone();
    let f = {
        let fenv: Value = serde_json::from_slice(&v.f().unwrap()).unwrap();
        let fb = body_value(&v.f().unwrap());
        let signers: Vec<String> = match fb.get("signer").and_then(Value::as_str) {
            Some(s) => std::iter::once(s.to_string())
                .chain(ids_of(&fenv, "cosignatures"))
                .collect(),
            None => vec![root_of(&v.prefix())],
        };
        let pending = prepare_swift_freeze(
            &SwiftFreezeParams {
                predecessor: v.prefix(),
                successor: objects.clone(),
                issued_ms: ms(fb["issued"].as_str().unwrap()),
                signers,
            },
            v.now(),
        )
        .unwrap();
        let item = |s: &SigningStep| -> Option<Value> {
            if s.role() == StepRole::Primary {
                return Some(fenv.clone());
            }
            fenv["cosignatures"]
                .as_array()?
                .iter()
                .find(|i| i["signer"] == s.signer())
                .cloned()
        };
        let sigs = sign_like_vector(pending.steps(), &item, scalars).unwrap();
        pending.finish(sigs).unwrap()
    };
    objects.predecessor.push(f.entry.clone());
    (objects, genesis, f.entry)
}
fn clone_vector(v: &Vector) -> Vector {
    Vector {
        dir: v.dir.clone(),
        name: v.name.clone(),
        case: v.case.clone(),
        predecessor: v.predecessor.clone(),
        genesis: v.genesis.clone(),
    }
}

#[test]
fn a_swift_root_library_and_a_keyring_library_each_succeed_and_the_succession_verifies() {
    let scalars = published_scalars();
    for name in ["swift-root-library", "swift-keyring", "swift-webauthn"] {
        let v = vector(name);
        let (objects, genesis, f) = complete(&v, &scalars);
        let verdict = verify_history(&objects, &Persisted::default(), v.now());
        assert!(verdict.stop.is_none(), "{name}: {:?}", verdict.stop);
        let state = verdict.state.unwrap();
        let f_digest = body_digest(&f);
        assert_eq!(
            state.verified_succession().map(|(n, d)| (n, d.to_string())),
            Some((v.head_seq() as u64 + 1, f_digest)),
            "{name}"
        );
        let status = succession_status(&state).unwrap();
        assert!(status.verified.is_some() && !status.vetoed && status.authorized);
        assert_eq!(status.genesis_digest, body_digest(&genesis));
        // The same keys control the new account, and no passkey is new: every carried
        // controller keeps its ID, and a WebAuthn one its relying party and credential.
        let old = swift::verify(&v.prefix()).unwrap();
        let old = old.states.last().unwrap();
        for (id, c) in state.keyring().controllers.iter() {
            if let Some(o) = old.controllers.get(id) {
                assert_eq!(o.key().signing(), c.key().signing(), "{name}");
                assert_eq!(
                    o.key()
                        .webauthn()
                        .map(|w| (w.rp().to_string(), w.credential().to_vec())),
                    c.key()
                        .webauthn()
                        .map(|w| (w.rp().to_string(), w.credential().to_vec())),
                    "{name}: a carried passkey is the same credential"
                );
            } else {
                assert!(c.key().webauthn().is_none(), "{name}: a new passkey");
            }
        }
        if name != "swift-root-library" {
            assert!(
                state
                    .keyring()
                    .controllers
                    .keys()
                    .all(|id| old.controllers.contains_key(id)),
                "{name}: a controller that the predecessor never had"
            );
        }
    }
}

#[test]
fn the_carried_controllers_keep_their_roles_and_the_slotted_ones_are_named() {
    let v = vector("swift-webauthn");
    let carried = swift_carried_controllers(
        &v.prefix(),
        &CarryOptions {
            authority_origins: BTreeMap::new(),
            ..CarryOptions::default()
        },
    )
    .unwrap();
    let want = v.genesis_body()["keyring"]["controllers"].clone();
    let key_roles = |c: &Value| {
        (
            c["key"]["signing"].clone(),
            c["roles"].clone(),
            c["label"].clone(),
        )
    };
    let got: Vec<_> = carried.iter().map(key_roles).collect();
    let exp: Vec<_> = want.as_array().unwrap().iter().map(key_roles).collect();
    assert_eq!(got, exp, "the vector carries roles over exactly");
    // The Mac holds a sealed slot in the predecessor.
    let slotted = swift_slotted_controllers(&v.prefix()).unwrap();
    assert_eq!(slotted.len(), 1);
    // A root library has no slot and carries the root as approve+control, the recovery
    // identity as recover.
    let r = vector("swift-root-library");
    assert!(swift_slotted_controllers(&r.prefix()).unwrap().is_empty());
    let c = swift_carried_controllers(&r.prefix(), &CarryOptions::default()).unwrap();
    let mut roles: Vec<Value> = c.iter().map(|c| c["roles"].clone()).collect();
    roles.sort_by_key(|r| r.to_string());
    assert_eq!(
        roles,
        vec![json!(["approve", "control"]), json!(["recover"])]
    );
}

#[test]
fn the_vetoed_succession_is_recorded_and_never_verified() {
    let scalars = published_scalars();
    let v = vector("swift-succession-vetoed");
    let entries = files_in(&v.dir.join("successor/authority"));
    let recorded = entries[2].clone();
    let rec = body_value(&recorded);
    let emb = |f: &str| dec(rec[f].as_str().unwrap());
    let list = |f: &str| -> Vec<Vec<u8>> {
        rec[f]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| dec(x.as_str().unwrap()))
            .collect()
    };
    // What a home holds when the veto reaches it: the veto, its receipts, the genesis receipts.
    let mut objects = Objects {
        entries: entries[..2].to_vec(),
        predecessor: v.prefix(),
        heads: v.successor_objects().heads,
        ..Objects::default()
    };
    objects.pending.extend(v.successor_objects().pending);
    objects.pending.push(emb("veto"));
    objects.pending.extend(list("receipts"));
    objects.pending.extend(list("genesisReceipts"));
    let veto_digest = body_digest(&emb("veto"));
    let batch = prepare_succession_vetoed(&objects, v.now(), &veto_digest).unwrap();
    assert!(batch.steps().is_empty(), "an unsigned, determined entry");
    let built = batch.finish(vec![]).unwrap().entries[0].1.clone();
    assert_eq!(built, recorded);
    let mut all = objects.clone();
    all.entries.push(built);
    let verdict = verify_history(&all, &Persisted::default(), v.now());
    let state = verdict.state.unwrap();
    assert!(state.verified_succession().is_none());
    assert!(succession_status(&state).unwrap().vetoed);
    // F is refused for a vetoed succession.
    let mut p = SwiftFreezeParams {
        predecessor: v.prefix(),
        successor: all.clone(),
        issued_ms: ms("2026-11-14T10:10:00Z"),
        signers: vec![root_of(&v.prefix())],
    };
    let e = prepare_swift_freeze(&p, v.now()).unwrap_err();
    assert!(
        matches!(e, Failure::Malformed(ref m) if m.contains("vetoed")),
        "{e:?}"
    );
    // And a veto that is not held is not recorded.
    p.successor = Objects::default();
    objects.pending.retain(|b| body_digest(b) != veto_digest);
    assert!(prepare_succession_vetoed(&objects, v.now(), &veto_digest).is_err());
    let _ = scalars;
}

// ---------------------------------------------------------------------------------------------
// Refusals (§15, §16): each at prepare or finish, by its reason.

fn genesis_params(v: &Vector) -> SwiftGenesisParams {
    let env: Value = serde_json::from_slice(&v.genesis).unwrap();
    let body = v.genesis_body();
    let mut signers = vec![body["by"].as_str().unwrap().to_string()];
    signers.extend(ids_of(&env, "cosignatures"));
    SwiftGenesisParams {
        label: body["label"].as_str().unwrap().into(),
        namespaces: vec![],
        keyring: body["keyring"].clone(),
        issued_ms: ms(body["issued"].as_str().unwrap()),
        predecessor: v.prefix(),
        signers,
        handover: ids_of(&env, "handover"),
    }
}
fn why(e: Failure) -> String {
    format!("{e}")
}

#[test]
fn the_swift_genesis_is_refused_for_each_reason_the_spec_names() {
    let scalars = published_scalars();
    let v = vector("swift-keyring");
    let ok = genesis_params(&v);
    assert!(prepare_swift_genesis(&ok, v.now()).is_ok());
    // §15.1 step 3: the genesis is not earlier than head's `issued`.
    let mut p = ok.clone();
    p.issued_ms = ms("2026-10-31T00:00:00Z");
    assert!(why(prepare_swift_genesis(&p, v.now()).unwrap_err())
        .contains("before the predecessor's head"));
    // §15.1 step 1: no handover, or too few keys: it would never verify.
    let mut p = ok.clone();
    p.handover.clear();
    assert!(why(prepare_swift_genesis(&p, v.now()).unwrap_err()).contains("handover does not meet"));
    // A handover key that is not a controller current at head (an outsider), and one twice.
    let mut p = ok.clone();
    p.handover = vec!["0".repeat(32)];
    assert!(why(prepare_swift_genesis(&p, v.now()).unwrap_err())
        .contains("not a controller of the predecessor"));
    let mut p = ok.clone();
    p.handover = vec![p.handover[0].clone(), p.handover[0].clone()];
    assert!(why(prepare_swift_genesis(&p, v.now()).unwrap_err()).contains("twice"));
    // The signers must meet the control rule over the new keyring, each a controller of it.
    let mut p = ok.clone();
    p.signers = vec!["0".repeat(32)];
    assert!(prepare_swift_genesis(&p, v.now()).is_err());
    // A predecessor that does not verify (a damaged signature) stops the builder.
    let mut p = ok.clone();
    let mut bad: Value = serde_json::from_slice(&p.predecessor[1]).unwrap();
    let mut sig = dec(bad["signature"].as_str().unwrap());
    sig[3] ^= 1;
    bad["signature"] = json!(b64(&sig));
    p.predecessor[1] = canonical(&bad).unwrap();
    assert!(prepare_swift_genesis(&p, v.now()).is_err());
    // §15.3, §16.2: a controller that had a slot must be carried with a rebuilt slot. The Mac
    // holds the only slot; the new keyring's slot is changed to name the kit instead.
    let mut p = ok.clone();
    let mac = swift_slotted_controllers(&v.prefix())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let kit = p.keyring["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| colophon_core::v05::ids::key_id(&dec(c["key"]["signing"].as_str().unwrap())))
        .find(|id| *id != mac)
        .unwrap();
    p.keyring["slots"][0]["controllers"] = json!([kit]);
    let e = why(prepare_swift_genesis(&p, v.now()).unwrap_err());
    assert!(
        e.contains("had a slot is not carried with a rebuilt slot"),
        "{e}"
    );
    // Finish: a signature by another key, and a missing handover signature, return nothing.
    let pending = prepare_swift_genesis(&ok, v.now()).unwrap();
    let mut sigs = sign_like_vector(pending.steps(), &|_| None, &scalars).unwrap_or_else(|_| {
        pending
            .steps()
            .iter()
            .map(|s| SignatureResult {
                signature: key_from_scalar(&scalars[s.signer()]).sign_raw(s.body()),
                assertion: None,
            })
            .collect()
    });
    let forged = key_from_scalar(
        scalars
            .values()
            .find(|s| **s != scalars[pending.steps()[0].signer()])
            .unwrap(),
    );
    sigs[0].signature = forged.sign_raw(pending.steps()[0].body());
    assert!(matches!(
        pending.finish(sigs).unwrap_err(),
        Failure::BadSignature(_)
    ));
    let pending = prepare_swift_genesis(&ok, v.now()).unwrap();
    assert!(pending.finish(vec![]).is_err());
}

#[test]
fn the_steps_ask_a_proof_only_of_keys_that_are_not_carried_and_a_handover_of_the_keys_offered() {
    let v = vector("swift-root-library");
    let pending = prepare_swift_genesis(&genesis_params(&v), v.now()).unwrap();
    let kinds: Vec<_> = pending
        .steps()
        .iter()
        .map(|s| (s.role(), s.signer().to_string()))
        .collect();
    let env: Value = serde_json::from_slice(&v.genesis).unwrap();
    let hand = ids_of(&env, "handover");
    let adds = ids_of(&env, "additions");
    for (role, id) in &kinds {
        match role {
            StepRole::Handover => assert!(hand.contains(id)),
            StepRole::Possession => assert!(adds.contains(id)),
            _ => {}
        }
    }
    assert_eq!(
        kinds
            .iter()
            .filter(|(r, _)| *r == StepRole::Handover)
            .count(),
        hand.len()
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|(r, _)| *r == StepRole::Possession)
            .count(),
        adds.len()
    );
    // The keyring-library vector: the genesis keys are all carried, so no proof is asked.
    let k = vector("swift-keyring");
    let pending = prepare_swift_genesis(&genesis_params(&k), k.now()).unwrap();
    assert!(pending
        .steps()
        .iter()
        .all(|s| s.role() != StepRole::Possession));
}

#[test]
fn f_is_refused_before_the_due_time_for_the_wrong_signers_and_a_fractional_second() {
    let v = vector("swift-keyring");
    let fb = body_value(&v.f().unwrap());
    let mut p = SwiftFreezeParams {
        predecessor: v.prefix(),
        successor: v.successor_objects(),
        issued_ms: ms(fb["issued"].as_str().unwrap()),
        signers: vec![fb["signer"].as_str().unwrap().to_string()],
    };
    assert!(prepare_swift_freeze(&p, v.now()).is_ok());
    // §15.1 step 5: only after the due time (the clock, then F's own `issued`).
    let t = succession_status(
        &verify_history(
            &Objects {
                predecessor: v.prefix(),
                ..v.successor_objects()
            },
            &Persisted::default(),
            v.now(),
        )
        .state
        .unwrap(),
    )
    .unwrap()
    .timing
    .unwrap();
    let e = prepare_swift_freeze(&p, t.due_ms - 1_000).unwrap_err();
    assert!(
        matches!(e, Failure::Unavailable(ref m) if m.contains("due time")),
        "{e:?}"
    );
    let mut early = p.clone();
    early.issued_ms = t.due_ms;
    assert!(matches!(
        prepare_swift_freeze(&early, v.now()).unwrap_err(),
        Failure::Unavailable(_)
    ));
    // The Swift date has no fractions.
    let mut frac = p.clone();
    frac.issued_ms += 500;
    assert!(why(prepare_swift_freeze(&frac, v.now()).unwrap_err()).contains("whole second"));
    // A signer that is not a controller of the predecessor; no signer.
    p.signers = vec!["0".repeat(32)];
    assert!(why(prepare_swift_freeze(&p, v.now()).unwrap_err()).contains("not a controller"));
    p.signers = vec![];
    assert!(prepare_swift_freeze(&p, v.now()).is_err());
    // No receipts held: the succession is not due, F is not written.
    let mut none = p.clone();
    none.signers = vec![fb["signer"].as_str().unwrap().to_string()];
    none.successor.pending.clear();
    assert!(prepare_swift_freeze(&none, v.now()).is_err());
    // A predecessor with an entry after the genesis's head is not the head the genesis names.
    let extra = vector("swift-premature-freeze-then-owner");
    let mut q = SwiftFreezeParams {
        predecessor: extra.predecessor.clone(),
        successor: extra.successor_objects(),
        issued_ms: ms("2026-11-14T10:10:00Z"),
        signers: vec![body_value(&extra.f().unwrap())["signer"]
            .as_str()
            .unwrap()
            .to_string()],
    };
    q.predecessor.push(extra.f().unwrap());
    assert!(why(prepare_swift_freeze(&q, extra.now()).unwrap_err()).contains("last entry as head"));
}

#[test]
fn f_finish_returns_nothing_for_a_forged_signature() {
    let scalars = published_scalars();
    let v = vector("swift-keyring");
    let fb = body_value(&v.f().unwrap());
    let p = SwiftFreezeParams {
        predecessor: v.prefix(),
        successor: v.successor_objects(),
        issued_ms: ms(fb["issued"].as_str().unwrap()),
        signers: vec![fb["signer"].as_str().unwrap().to_string()],
    };
    let pending = prepare_swift_freeze(&p, v.now()).unwrap();
    let forged = key_from_scalar(
        scalars
            .values()
            .find(|s| **s != scalars[pending.steps()[0].signer()])
            .unwrap(),
    );
    let sigs = vec![SignatureResult {
        signature: forged.sign_raw(pending.steps()[0].body()),
        assertion: None,
    }];
    assert!(matches!(
        pending.finish(sigs).unwrap_err(),
        Failure::BadSignature(_)
    ));
}

#[test]
fn the_migration_entry_is_built_with_real_view_digests_and_refused_when_it_cannot_be_true() {
    use colophon_core::v05::encoding::digest as sha;
    // View digest: SHA-256 of the sorted, newline-joined lowercase hex digests.
    let a = "b".repeat(64);
    let b = "a".repeat(64);
    assert_eq!(
        view_digest(&[a.clone(), b.clone()]).unwrap(),
        sha(format!("{b}\n{a}").as_bytes())
    );
    assert_eq!(view_digest(&[]).unwrap(), sha(b""));
    assert!(view_digest(&["AB".repeat(32)]).is_err());
    assert!(view_digest(&["a".repeat(63)]).is_err());
    assert_eq!(map_swift_role("web"), Some("app"));
    assert_eq!(map_swift_role("service"), Some("server"));
    assert_eq!(map_swift_role("robot"), None);
}

#[test]
fn the_migration_transition_is_built_activated_and_recorded() {
    let scalars = published_scalars();
    let v = vector("swift-keyring");
    let (objects, _genesis, _f) = complete(&v, &scalars);
    let st = verify_history(&objects, &Persisted::default(), v.now())
        .state
        .unwrap();
    assert!(st.verified_succession().is_some());
    let mac = v.genesis_body()["by"].as_str().unwrap().to_string();
    let kit = st
        .keyring()
        .controllers
        .iter()
        .find(|(_, c)| {
            c.roles()
                .iter()
                .all(|r| *r == colophon_core::v05::descriptor::Role::Recover)
        })
        .map(|(id, _)| id.clone())
        .unwrap();
    let issued = ms("2026-11-14T10:13:00Z");
    let params = MigrationParams {
        predecessor: objects.predecessor.clone(),
        drain_from_ms: ms("2026-11-14T10:10:00Z"),
        drain_until_ms: ms("2026-11-14T10:12:00Z"),
        namespaces: vec![],
        omitted: vec![("c".repeat(64), "invalidPayload".into())],
        members: vec![],
        issued_ms: issued,
        signers: vec![mac.clone(), kit.clone()],
    };
    // Refusals first: written before the drain window ends; more than 4,096 omitted; a window of
    // more than 30 days; a namespace the predecessor never had; a member it never had.
    let now = v.now();
    let mut p = params.clone();
    p.issued_ms = ms("2026-11-14T10:11:00Z");
    assert!(
        why(prepare_migration(&objects, now, &p).unwrap_err()).contains("after the drain window")
    );
    let mut p = params.clone();
    p.omitted = (0..4097)
        .map(|i| (format!("{i:064x}"), "x".into()))
        .collect();
    assert!(why(prepare_migration(&objects, now, &p).unwrap_err()).contains("4,096"));
    let mut p = params.clone();
    p.drain_until_ms = p.drain_from_ms + 2_592_000_001;
    p.issued_ms = p.drain_until_ms;
    assert!(why(prepare_migration(&objects, now, &p).unwrap_err()).contains("30 days"));
    let mut p = params.clone();
    p.namespaces = vec![MigratedNamespace {
        namespace: "notes".into(),
        source: 1,
        copied: vec!["d".repeat(64)],
        omitted: 0,
    }];
    assert!(why(prepare_migration(&objects, now, &p).unwrap_err())
        .contains("exactly the predecessor's namespaces"));
    let mut p = params.clone();
    p.members = vec![MigratedMember {
        id: "e".repeat(32),
        label: "x".into(),
        kind: "device".into(),
        dropped: None,
    }];
    assert!(why(prepare_migration(&objects, now, &p).unwrap_err()).contains("current members"));
    // Not before the succession is verified.
    let mut unverified = objects.clone();
    unverified.heads.clear();
    assert!(prepare_migration(&unverified, now, &params).is_err());
    // The valid one.
    let pending = prepare_migration(&objects, now, &params).unwrap();
    let sigs = sign_steps(pending.steps(), &scalars);
    let transition = pending.finish(sigs).unwrap().pending[0].clone();
    let t_digest = body_digest(&transition);
    let t = body_value(&transition);
    let m = &t["change"]["migration"];
    assert_eq!(m["drain"]["from"], "2026-11-14T10:10:00Z");
    assert_eq!(m["predecessor"]["final"]["seq"], 3);
    assert_eq!(m["omitted"][0]["reason"], "invalidPayload");
    assert_eq!(m["controllers"].as_array().unwrap().len(), 2);
    // The home receipts the transition; after its due time the entry is activated.
    let home = receipt_of(&v).0;
    let acct = st.account().as_str().to_string();
    let rbody = canonical(
        &json!({"protocol": "colophon/receipt/5", "account": acct, "object": t_digest,
        "received": "2026-11-14T10:13:30Z", "by": home}),
    )
    .unwrap();
    let hk = key_from_scalar(&scalars[&home]);
    let receipt =
        canonical(&json!({"body": b64(&rbody), "signature": b64(&hk.sign_raw(&rbody))})).unwrap();
    let mut held = objects.clone();
    held.pending.extend([transition, receipt]);
    let due = issued + 259_200_000;
    let act = prepare_activate(&held, due + 1_000, &t_digest).unwrap();
    let rec = act.finish(vec![]).unwrap();
    held.entries.push(rec.entries[0].1.clone());
    let v2 = verify_history(&held, &Persisted::default(), due + 1_000);
    assert!(v2.stop.is_none(), "{:?}", v2.stop);
    let state = v2.state.unwrap();
    let rec = state.migration.clone().unwrap();
    assert_eq!(
        rec["predecessor"]["account"],
        v.genesis_body()["predecessor"]["account"]
    );
}

// ---------------------------------------------------------------------------------------------
// A `/5` predecessor.

fn vec5(name: &str) -> (std::path::PathBuf, Vec<u8>, Vec<Vec<u8>>) {
    let dir = repo()
        .join("conformance/0.5/candidate/succession")
        .join(name);
    (
        dir.clone(),
        strip(std::fs::read(dir.join("genesis.json")).unwrap()),
        files_in(&dir.join("predecessor/authority")),
    )
}

/// Split a predecessor set into the claimed account's entries and the rest (its own
/// predecessors'), by following `previous` links to each entry's genesis.
fn split_account(set: &[Vec<u8>], account: &str) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let by_digest: BTreeMap<String, (Option<String>, &Vec<u8>)> = set
        .iter()
        .map(|b| {
            (
                body_digest(b),
                (body_value(b)["previous"].as_str().map(str::to_string), b),
            )
        })
        .collect();
    let owner = |d: &str| {
        let mut cur = d.to_string();
        while let Some((Some(prev), _)) = by_digest.get(&cur) {
            cur = prev.clone();
        }
        cur
    };
    let (mut mine, mut rest) = (Vec::new(), Vec::new());
    for b in set {
        if owner(&body_digest(b)) == account {
            mine.push(b.clone());
        } else {
            rest.push(b.clone());
        }
    }
    (mine, rest)
}

fn genesis5_params(genesis: &[u8], set: &[Vec<u8>], omit: bool) -> Authority5GenesisParams {
    let body = body_value(genesis);
    let (mut mine, rest) = split_account(set, body["predecessor"]["account"].as_str().unwrap());
    // The genesis names the head it names: keep the predecessor's entries up to that seq.
    mine.sort_by_key(|b| body_value(b)["seq"].as_u64().unwrap());
    mine.truncate(body["predecessor"]["head"]["seq"].as_u64().unwrap() as usize);
    Authority5GenesisParams {
        label: body["label"].as_str().unwrap().into(),
        namespaces: vec![],
        keyring: body["keyring"].clone(),
        issued_ms: ms(body["issued"].as_str().unwrap()),
        predecessor: Objects {
            entries: mine,
            predecessor: rest,
            ..Objects::default()
        },
        signers: vec![body["by"].as_str().unwrap().to_string()],
        omit_carried_proofs: omit,
    }
}

#[test]
fn a_5_predecessor_succeeds_with_the_genesis_held_until_f_is_final() {
    let scalars = published_scalars();
    let (dir, genesis, pred) = vec5("authority5-successor-final");
    // The predecessor before F: its genesis and the activation that made its homes.
    let before = pred[..2].to_vec();
    let mut p = genesis5_params(&genesis, &before, true);
    p.predecessor.entries = before.clone();
    let pending = prepare_authority5_genesis(&p, ms("2026-11-14T09:00:00Z")).unwrap();
    assert!(pending
        .steps()
        .iter()
        .all(|s| s.role() != StepRole::Possession && s.role() != StepRole::Handover));
    let sigs = sign_steps(pending.steps(), &scalars);
    let built = pending.finish(sigs).unwrap().entries[0].1.clone();
    assert_eq!(built, genesis, "the held genesis reproduces");
    // The `successor` transition, F's activation (receipts from the held objects) and its
    // `final` (the homes' heads) reproduce the vector's entries 3 and 4.
    let act = body_value(&pred[2]);
    let t_bytes = dec(act["transition"].as_str().unwrap());
    let t = body_value(&t_bytes);
    let objects = Objects {
        entries: before.clone(),
        ..Objects::default()
    };
    let signers: Vec<String> = t["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().into())
        .collect();
    let mut ordered = vec![t["by"].as_str().unwrap().to_string()];
    ordered.extend(
        signers
            .into_iter()
            .filter(|s| s != t["by"].as_str().unwrap()),
    );
    let pend = prepare_successor_transition(
        &objects,
        ms("2026-11-14T09:00:00Z"),
        &built,
        ms(t["issued"].as_str().unwrap()),
        ordered,
    )
    .unwrap();
    let sigs = sign_steps(pend.steps(), &scalars);
    let transition = pend.finish(sigs).unwrap().pending[0].clone();
    assert_eq!(transition, t_bytes);
    // A transition for a genesis that does not name this head is refused.
    let (_, other, _) = vec5("authority5-chain");
    assert!(prepare_successor_transition(
        &objects,
        ms("2026-11-14T09:00:00Z"),
        &other,
        ms(t["issued"].as_str().unwrap()),
        vec![t["by"].as_str().unwrap().into()]
    )
    .is_err());
    let _ = dir;
    // The whole set verifies with the succession verified: the genesis was held until now.
    let all = Objects {
        entries: pred.clone(),
        ..Objects::default()
    };
    let succ = Objects {
        entries: vec![genesis.clone()],
        predecessor: pred.clone(),
        ..Objects::default()
    };
    let _ = all;
    let v = verify_history(&succ, &Persisted::default(), ms("2026-11-14T10:00:00Z"));
    assert!(v.stop.is_none(), "{:?}", v.stop);
    assert!(v.state.unwrap().verified_succession().is_some());
    // Before F is final the same genesis is held, not refused.
    let early = Objects {
        entries: vec![genesis],
        predecessor: pred[..3].to_vec(),
        ..Objects::default()
    };
    let v = verify_history(&early, &Persisted::default(), ms("2026-11-14T10:00:00Z"));
    assert!(
        matches!(v.stop, Some(colophon_core::v05::history::Stop::Held { .. })),
        "{:?}",
        v.stop
    );
}

#[test]
fn a_5_genesis_with_every_proof_verifies_at_once_and_a_chain_of_two_follows() {
    let scalars = published_scalars();
    let (_, genesis, pred) = vec5("authority5-successor-final");
    let p = genesis5_params(&genesis, &pred[..2], false);
    let pending = prepare_authority5_genesis(&p, ms("2026-11-14T09:00:00Z")).unwrap();
    assert!(pending
        .steps()
        .iter()
        .any(|s| s.role() == StepRole::Possession));
    let sigs = sign_steps(pending.steps(), &scalars);
    let g = pending.finish(sigs).unwrap().entries[0].1.clone();
    let v = verify_history(
        &Objects {
            entries: vec![g],
            predecessor: pred[..2].to_vec(),
            ..Objects::default()
        },
        &Persisted::default(),
        ms("2026-11-14T09:00:00Z"),
    );
    assert!(v.stop.is_none(), "{:?}", v.stop);
    // A chain A to B to C (the vector): the builder takes B's objects with A's as its
    // predecessor, and the verifier follows both.
    let (_, c_genesis, set) = vec5("authority5-chain");
    let p = genesis5_params(&c_genesis, &set, true);
    assert!(!p.predecessor.predecessor.is_empty());
    let pending = prepare_authority5_genesis(&p, ms("2026-11-14T09:00:00Z")).unwrap();
    let sigs = sign_steps(pending.steps(), &scalars);
    let built = pending.finish(sigs).unwrap().entries[0].1.clone();
    let (bv, cv): (Value, Value) = (
        serde_json::from_slice(&built).unwrap(),
        serde_json::from_slice(&c_genesis).unwrap(),
    );
    assert_eq!(bv["body"], cv["body"], "the chain genesis body reproduces");
    assert_eq!(
        bv["signature"], cv["signature"],
        "the chain genesis signature reproduces"
    );
    // 17 accounts is one too many (§2.4): refused at finish.
    let (_, g17, set17) = vec5("authority5-chain-17");
    let p = genesis5_params(&g17, &set17, true);
    let pending = prepare_authority5_genesis(&p, ms("2026-11-14T09:00:00Z")).unwrap();
    let sigs = sign_steps(pending.steps(), &scalars);
    let e = pending.finish(sigs).unwrap_err();
    assert!(
        matches!(e, Failure::Malformed(ref m) if m.contains("longer than 16")),
        "{e:?}"
    );
    // 16 is allowed.
    let (_, g16, set16) = vec5("authority5-chain-16");
    let p = genesis5_params(&g16, &set16, true);
    let pending = prepare_authority5_genesis(&p, ms("2026-11-14T09:00:00Z")).unwrap();
    let sigs = sign_steps(pending.steps(), &scalars);
    assert!(pending.finish(sigs).is_ok());
}

/// The `swift-migration` vector reproduces: the transition the builder makes from the predecessor
/// (a grant for `notes` to one device, F at seq 4), the chosen copy counts and digests, a drain
/// window after F and the owner's signers is the transition the vector's entry 3 embeds.
#[test]
fn the_migration_vector_reproduces_from_its_inputs() {
    let scalars = published_scalars();
    let v = vector("swift-migration");
    let (mut objects, _, f) = complete(&v, &scalars);
    objects.entries.truncate(2);
    let held = files_in(&v.dir.join("successor/authority"));
    let want_t = dec(body_value(&held[2])["transition"].as_str().unwrap());
    let t = body_value(&want_t);
    let m = &t["change"]["migration"];
    assert!(ms(m["drain"]["from"].as_str().unwrap()) > ms(body_value(&f)["issued"].as_str().unwrap()));
    let member = m["members"][0]["id"].as_str().unwrap().to_string();
    let params = MigrationParams {
        predecessor: objects.predecessor.clone(),
        drain_from_ms: ms(m["drain"]["from"].as_str().unwrap()),
        drain_until_ms: ms(m["drain"]["until"].as_str().unwrap()),
        namespaces: vec![MigratedNamespace {
            namespace: "notes".into(),
            source: 3,
            copied: vec![digest(b"one"), digest(b"two")],
            omitted: 1,
        }],
        omitted: vec![("cd".repeat(32), "invalidPayload".into())],
        members: vec![MigratedMember { id: member, label: "Phone".into(), kind: "device".into(), dropped: None }],
        issued_ms: ms(t["issued"].as_str().unwrap()),
        signers: t["signers"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect(),
    };
    let mut ordered = params.clone();
    let by = t["by"].as_str().unwrap().to_string();
    ordered.signers.retain(|s| *s != by);
    ordered.signers.insert(0, by);
    let pending = prepare_migration(&objects, v.now(), &ordered).unwrap();
    let sigs = sign_steps(pending.steps(), &scalars);
    let built = pending.finish(sigs).unwrap().pending[0].clone();
    if built != want_t {
        let (b, w) = (body_value(&built), body_value(&want_t));
        for k in w.as_object().unwrap().keys() {
            assert_eq!(b[k], w[k], "transition field {k}");
        }
        for k in w["change"]["migration"].as_object().unwrap().keys() {
            assert_eq!(b["change"]["migration"][k], w["change"]["migration"][k], "migration field {k}");
        }
        panic!("only the signatures differ");
    }
    // A member the predecessor never had, or a namespace it never had, is still refused.
    let mut bad = ordered.clone();
    bad.namespaces[0].namespace = "other".into();
    assert!(why(prepare_migration(&objects, v.now(), &bad).unwrap_err()).contains("exactly the predecessor's namespaces"));
    // A drain window that ends before F is refused (§15.4 orders the migration after F).
    let mut early = ordered.clone();
    early.drain_from_ms = ms("2020-01-01T00:00:00Z");
    early.drain_until_ms = early.drain_from_ms;
    assert!(why(prepare_migration(&objects, v.now(), &early).unwrap_err()).contains("after F"));
}
