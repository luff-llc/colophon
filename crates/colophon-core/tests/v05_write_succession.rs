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
        self.genesis_body()["predecessor"]["head"]["seq"].as_u64().unwrap() as usize
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
    let signer0 = fb
        .get("signer")
        .and_then(Value::as_str)
        .map(str::to_string);
    // A root library's F is `by: root`: the signer is the current root, found from the history.
    let signers: Vec<String> = match signer0 {
        Some(s) => std::iter::once(s).chain(ids_of(&fenv, "cosignatures")).collect(),
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
                    bad.push(format!("{}: genesis refused for another reason: {e}", v.name));
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
    let r = body_value(&strip(std::fs::read(v.dir.join("genesis-receipt.json")).unwrap()));
    (r["by"].as_str().unwrap().to_string(), ms(r["received"].as_str().unwrap()))
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
        assert_eq!(prepared.object(), digest(&dec(
            serde_json::from_slice::<Value>(&v.genesis).unwrap()["body"].as_str().unwrap())));
        let sig = sign_steps(std::slice::from_ref(prepared.step()), &scalars).remove(0);
        let env = finish_genesis_receipt(&prepared, &sig).unwrap();
        assert_eq!(env, strip(std::fs::read(v.dir.join("genesis-receipt.json")).unwrap()), "{name}");
        // The window is the window: before its opening, and after its end, no receipt.
        let t = succession_status(
            &verify_history(&objects, &Persisted::default(), received).state.unwrap(),
        )
        .unwrap()
        .timing
        .unwrap();
        assert!(prepare_genesis_receipt(&objects, &home, t.window_start_ms - 1_000).is_err());
        let e = prepare_genesis_receipt(&objects, &home, t.window_end_ms + 1_000).unwrap_err();
        assert!(matches!(e, Failure::Malformed(ref m) if m.contains("within the succession window")), "{e:?}");
        // A home signs at most one receipt per object.
        let mut again = objects.clone();
        again.pending.push(env.clone());
        let e = prepare_genesis_receipt(&again, &home, received + 1_000).unwrap_err();
        assert!(matches!(e, Failure::Malformed(ref m) if m.contains("at most one receipt")), "{e:?}");
        // A member that was not a home at the window's entry has no receipt to give.
        assert!(prepare_genesis_receipt(&objects, &"0".repeat(32), received).is_err());
        // A receipt signed by another key is refused at finish.
        let other = key_from_scalar(scalars.values().find(|s| **s != scalars[&home]).unwrap());
        let forged = SignatureResult { signature: other.sign_raw(prepared.step().body()), assertion: None };
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
    let st = verify_history(&objects, &Persisted::default(), v.now()).state.unwrap();
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
    let mut ids: Vec<String> = h.states.iter().flat_map(|s| s.controllers.keys().cloned()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(t.vetoers.iter().cloned().collect::<Vec<_>>(), ids);
    assert_eq!(ids.len(), 4);
}
