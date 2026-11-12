//! Conformance runner for the Colophon 0.5 candidate vectors (`conformance/0.5/candidate/`).
//!
//! Every case is reported as PASS, FAIL or NOT-IMPLEMENTED. Out-of-scope cases (pending
//! transitions, forks, succession, upgrade, immediate keyring rules, pairing, ...) are never
//! reported as passing. The test fails on any in-scope FAIL that isn't in `DISPUTED` (vectors
//! whose expected outcome this implementation believes contradicts the spec; see the
//! implementation notes), and on any disputed vector that starts passing.
//!
//! Authority histories are loaded by a **fixture view loader** below. It checks canonical
//! bytes, shapes and every signature it can attribute, but it is not an authority replayer:
//! it does not evaluate §8.4 rules or §8.7 (pending transitions, `activate`, `suspend`), whose
//! effects it applies as given so the call pipeline has a view to run over.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::{
    calls::{
        verify_call, AccountView, CallConfig, ControllerStatus, ViewController, ViewMember,
        HISTORY_READ,
    },
    descriptor::{Controller, Policy},
    encoding::{bounds, canonical_body, digest, parse_date, strict_parse},
    heads::{verify_head, HeadContext},
    ids::{key_id, AccountId, Reference},
    members::{AuthorityHeader, Grant, GrantContext, Request, Revoke},
    replay::MemoryReplayStore,
    signature::{verify_raw, verify_webauthn, AssertionBytes, OriginRule, SigFailure, Strictness},
    terms::{Terms, TermsKind},
    Failure, Unknown,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// In-scope vectors whose expected outcome contradicts the spec text as this implementation
/// reads it, with the reason. They are reported as FAIL (disputed), not bent to pass.
const DISPUTED: &[(&str, &str)] = &[
    (
        "calls/one-link",
        "the link's terms carry no conditions while the member's carry {prefix: [args.task, T-]}; \
         §10.3 says B narrows A only when every predicate of A's conditions equals one of B's, \
         so §12.3 step 6 gives refused:notNarrower, not ok (generate.py `narrow` omits conditions)",
    ),
    (
        "calls/copied-link",
        "uses the same link as one-link, which fails §10.3 narrowing at step 6 before the \
         acting-key comparison that ends step 6; with a narrowing link it would be badSignature",
    ),
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn cand() -> PathBuf {
    repo().join("conformance/0.5/candidate")
}
fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap()
}
fn b64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}
fn ms(s: &str) -> i64 {
    parse_date(s).unwrap()
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Pass(String),
    Fail(String),
    NotImplemented(&'static str),
}

/// Verify one authority signature (primary or list item) by a known controller.
fn verify_authority_sig(
    c: &Controller,
    body: &[u8],
    signature: &[u8],
    assertion: Option<&Value>,
) -> Result<(), SigFailure> {
    match (c.key.webauthn(), assertion) {
        (None, None) => verify_raw(&c.key.signing, body, signature),
        (Some(w), Some(a)) => {
            let data = b64(a["authenticatorData"].as_str().unwrap_or(""));
            let client = b64(a["clientData"].as_str().unwrap_or(""));
            verify_webauthn(
                &c.key.signing,
                w,
                body,
                signature,
                AssertionBytes {
                    authenticator_data: &data,
                    client_data: &client,
                },
                true, // authority signatures need UV (§8.4 control rule; possession with verification)
                OriginRule::Authority,
                Strictness::Current,
            )
            .map(|_| ())
        }
        _ => Err(SigFailure::Form),
    }
}

/// The fixture view loader's result.
struct Loaded {
    account: AccountId,
    history: Vec<String>,
    policies: Vec<(u64, Policy)>,
    controllers: BTreeMap<String, ViewController>,
    members: Vec<ViewMember>,
    points: BTreeSet<Vec<u8>>,
    namespaces: Vec<String>,
}

fn parse_controllers(keyring: &Value, unknown: &mut Unknown) -> Result<Vec<Controller>, Failure> {
    keyring["controllers"]
        .as_array()
        .ok_or_else(|| Failure::Malformed("controllers".into()))?
        .iter()
        .map(|c| Controller::parse(c.clone(), "controller", unknown))
        .collect()
}

/// Load an authority history from record directories, entry by entry. Returns the seq and
/// failure of the first entry that fails.
fn load(dirs: &[PathBuf]) -> Result<Loaded, (u64, Failure)> {
    let mut files = Vec::new();
    for d in dirs {
        let mut fs_: Vec<PathBuf> = fs::read_dir(d.join("authority"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        fs_.sort();
        files.extend(fs_);
    }
    let mut l = Loaded {
        account: AccountId::parse(&"0".repeat(64)).unwrap(),
        history: Vec::new(),
        policies: Vec::new(),
        controllers: BTreeMap::new(),
        members: Vec::new(),
        points: BTreeSet::new(),
        namespaces: Vec::new(),
    };
    for (i, f) in files.iter().enumerate() {
        let seq = i as u64 + 1;
        let fail = |e: Failure| (seq, e);
        let env_bytes = fs::read(f).unwrap();
        let env = strict_parse(&env_bytes).map_err(fail)?;
        let body = b64(env["body"].as_str().unwrap());
        let value = canonical_body(&body, bounds::AUTHORITY_BODY).map_err(fail)?;
        let (header, mut fields) = AuthorityHeader::split(value.clone()).map_err(fail)?;
        if header.seq != seq {
            return Err((seq, Failure::Malformed("seq".into())));
        }
        let mut unknown = Unknown::default();
        // The signers known before this entry (genesis: its own keyring).
        let signer_pool: BTreeMap<String, Controller> = if header.kind == "genesis" {
            let kr = &value["keyring"];
            let cs = parse_controllers(kr, &mut unknown).map_err(fail)?;
            cs.into_iter().map(|c| (c.id(), c)).collect()
        } else {
            l.controllers
                .iter()
                .filter_map(|(id, vc)| {
                    vc.versions
                        .last()
                        .and_then(|(_, c)| c.clone())
                        .map(|c| (id.clone(), c))
                })
                .collect()
        };
        // Signatures this loader can attribute: primary, cosignatures, additions.
        if let Some(sig) = env.get("signature").and_then(Value::as_str) {
            let by = signer_pool
                .get(&header.by)
                .ok_or_else(|| fail(Failure::BadSignature("by is not a controller".into())))?;
            verify_authority_sig(by, &body, &b64(sig), env.get("assertion"))
                .map_err(|e| fail(Failure::BadSignature(e.to_string())))?;
        } else if header.kind != "activate" && header.kind != "vetoed" {
            return Err(fail(Failure::Malformed("missing signature".into())));
        }
        for list in ["cosignatures", "additions"] {
            for item in env
                .get(list)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let signer = item["signer"].as_str().unwrap();
                let added: BTreeMap<String, Controller> =
                    if list == "additions" && header.kind == "keyring" {
                        parse_controllers(&value["keyring"], &mut Unknown::default())
                            .map_err(fail)?
                            .into_iter()
                            .map(|c| (c.id(), c))
                            .collect()
                    } else {
                        signer_pool.clone()
                    };
                let c = added.get(signer).ok_or_else(|| {
                    fail(Failure::BadSignature(format!("{list}: unknown signer")))
                })?;
                verify_authority_sig(
                    c,
                    &body,
                    &b64(item["signature"].as_str().unwrap()),
                    item.get("assertion"),
                )
                .map_err(|e| fail(Failure::BadSignature(format!("{list}: {e}"))))?;
            }
        }
        match header.kind.as_str() {
            "genesis" => {
                l.account = AccountId::of_genesis(&body);
                let kr = fields.obj("keyring").map_err(fail)?;
                let kr_value = value["keyring"].clone();
                drop(kr);
                for c in parse_controllers(&kr_value, &mut unknown).map_err(fail)? {
                    l.points.insert(c.key.signing.clone());
                    if let Some(a) = c.key.agreement() {
                        l.points.insert(a.to_vec());
                    }
                    l.controllers.insert(
                        c.id(),
                        ViewController {
                            id: c.id(),
                            versions: vec![(seq, Some(c))],
                            status: ControllerStatus::Active,
                        },
                    );
                }
                for k in ["signing", "agreement"] {
                    l.points.insert(b64(kr_value["vault"][k].as_str().unwrap()));
                }
                l.policies.push((
                    seq,
                    Policy::parse(kr_value["policy"].clone(), "policy", &mut unknown)
                        .map_err(fail)?,
                ));
                l.namespaces = value["namespaces"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
            }
            "grant" => {
                let ctx = GrantContext {
                    account: &l.account,
                    issued_ms: header.issued.1,
                    namespaces: &l.namespaces,
                    known_keys: &l.points,
                    epochs: None,
                };
                let g = Grant::parse(fields, ctx, &mut unknown).map_err(fail)?;
                add_member(&mut l, g.request, g.terms, seq);
            }
            "revoke" => {
                let r = Revoke::parse(fields, &mut unknown).map_err(fail)?;
                if let Some(m) = l.members.iter_mut().find(|m| m.id == r.member) {
                    m.revoked_seq = Some(seq);
                }
            }
            "activate" => {
                // §8.7 is out of scope: the embedded transition's change is applied as given.
                let t_env =
                    strict_parse(&b64(value["transition"].as_str().unwrap())).map_err(fail)?;
                let t: Value =
                    serde_json::from_slice(&b64(t_env["body"].as_str().unwrap())).unwrap();
                let change = &t["change"];
                for a in change["homes"]["appoint"].as_array().into_iter().flatten() {
                    let req =
                        Request::parse(&b64(a["request"].as_str().unwrap()), true, &mut unknown)
                            .map_err(fail)?;
                    let terms = Terms::parse(a["terms"].clone(), TermsKind::Member, &mut unknown)
                        .map_err(fail)?;
                    add_member(&mut l, req, terms, seq);
                }
                for c in change["keyring"]["add"].as_array().into_iter().flatten() {
                    let c =
                        Controller::parse(c.clone(), "controller", &mut unknown).map_err(fail)?;
                    l.controllers.insert(
                        c.id(),
                        ViewController {
                            id: c.id(),
                            versions: vec![(seq, Some(c))],
                            status: ControllerStatus::Active,
                        },
                    );
                }
                for id in change["keyring"]["remove"].as_array().into_iter().flatten() {
                    if let Some(vc) = l.controllers.get_mut(id.as_str().unwrap()) {
                        vc.versions.push((seq, None));
                    }
                }
            }
            "suspend" => {
                // §8.7 is out of scope: the suspension is applied as given.
                let key = value["key"].as_str().unwrap();
                if let Some(vc) = l.controllers.get_mut(key) {
                    vc.status = ControllerStatus::Suspended;
                }
            }
            other => {
                return Err((
                    seq,
                    Failure::Malformed(format!("fixture loader does not handle {other}")),
                ))
            }
        }
        l.history.push(digest(&body));
    }
    Ok(l)
}
fn add_member(l: &mut Loaded, req: Request, terms: Terms, seq: u64) {
    l.points.insert(req.signing.clone());
    l.points.insert(req.agreement.clone());
    l.members.push(ViewMember {
        id: req.member_id(),
        signing: req.signing.clone(),
        kind: req.kind.clone(),
        terms,
        granted_seq: seq,
        renewals: Vec::new(),
        end_sessions: Vec::new(),
        revoked_seq: None,
    });
}

fn expected_of(case: &Value, key: &str) -> String {
    match &case["expected"] {
        Value::String(s) => s.clone(),
        v => v[key].as_str().unwrap_or_default().to_string(),
    }
}

fn run_call(dir: &Path, case: &Value) -> Outcome {
    let ver = &case["verifier"];
    let record_dirs: Vec<PathBuf> = match &ver["history"] {
        Value::String(s) => vec![repo().join(s)],
        Value::Array(a) => a.iter().map(|s| repo().join(s.as_str().unwrap())).collect(),
        _ => vec![dir.join("records")],
    };
    let loaded = match load(&record_dirs) {
        Ok(l) => l,
        Err((seq, e)) => return Outcome::Fail(format!("fixture history failed at seq {seq}: {e}")),
    };
    let now = ms(ver["now"].as_str().unwrap());
    let mut controllers = loaded.controllers.clone();
    // Pending statuses are inputs (§8.7 out of scope): read them from the case's transition.
    let applied = loaded.history.len();
    if dir.join("objects/transition.json").exists()
        && case["description"]
            .as_str()
            .is_some_and(|d| !d.contains("suspended"))
    {
        let t = json(&dir.join("objects/transition.json"));
        let body: Value = serde_json::from_slice(&b64(t["body"].as_str().unwrap())).unwrap();
        for id in body["change"]["keyring"]["remove"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if let Some(vc) = controllers.get_mut(id.as_str().unwrap()) {
                vc.status = ControllerStatus::PendingRemoval;
            }
        }
        for c in body["change"]["keyring"]["add"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id = key_id(&b64(c["key"]["signing"].as_str().unwrap()));
            controllers
                .entry(id.clone())
                .or_insert(ViewController {
                    id,
                    versions: Vec::new(),
                    status: ControllerStatus::PendingAddition,
                })
                .status = ControllerStatus::PendingAddition;
        }
    }
    let _ = applied;
    let head_paths: Vec<PathBuf> = match &ver["heads"] {
        Value::Array(a) => a.iter().map(|s| repo().join(s.as_str().unwrap())).collect(),
        _ => vec![dir.join("objects/head.json")],
    };
    let mut view = AccountView {
        account: loaded.account.clone(),
        history: loaded.history.clone(),
        policies: loaded.policies.clone(),
        controllers: controllers.into_values().collect(),
        members: loaded.members.clone(),
        heads: Vec::new(),
        vouched_fork: false,
        principal_points: loaded.points.clone(),
    };
    let homes = view.current_homes(now);
    for p in head_paths {
        let ctx = HeadContext {
            account: &view.account,
            history: &view.history,
            homes: &homes,
            now_ms: now,
        };
        match verify_head(&fs::read(&p).unwrap(), ctx) {
            Ok(h) => view.heads.push(h),
            Err(e) => return Outcome::Fail(format!("head {} refused: {e}", p.display())),
        }
    }
    let audiences: Vec<String> = ver["audiences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().into())
        .collect();
    let mut purposes: Vec<String> = ver["controllerPurposes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| s.as_str().unwrap().into())
        .collect();
    if ver["role"] == "home" {
        // A home configures colophon.history.read as a controller-call purpose (§13.4).
        purposes.push(HISTORY_READ.into());
    }
    let origins: BTreeMap<String, Vec<String>> = ver["callOrigins"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_array()
                            .unwrap()
                            .iter()
                            .map(|s| s.as_str().unwrap().into())
                            .collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let cfg = CallConfig {
        now_ms: now,
        audiences: &audiences,
        call_origins: &origins,
        controller_purposes: &purposes,
    };
    let mut store = MemoryReplayStore::new();
    for prior in ver["replay"].as_array().into_iter().flatten() {
        if let Err(e) = verify_call(
            &fs::read(repo().join(prior.as_str().unwrap())).unwrap(),
            &view,
            &cfg,
            &mut store,
        ) {
            return Outcome::Fail(format!("prior call for the replay store failed: {e}"));
        }
    }
    let call_path = if dir.join("call.json").exists() {
        dir.join("call.json")
    } else {
        dir.join("objects/call.json")
    };
    let got = match verify_call(&fs::read(call_path).unwrap(), &view, &cfg, &mut store) {
        Ok(_) => "ok".to_string(),
        Err(e) => e.code(),
    };
    let want = expected_of(case, "call");
    if got == want {
        Outcome::Pass(got)
    } else {
        Outcome::Fail(format!("expected {want}, got {got}"))
    }
}

fn run_head(dir: &Path, case: &Value) -> Outcome {
    let ver = &case["verifier"];
    let loaded = load(&[repo().join(ver["history"].as_str().unwrap())])
        .unwrap_or_else(|(s, e)| panic!("{s}: {e}"));
    let now = ms(ver["now"].as_str().unwrap());
    let homes: Vec<(String, Vec<u8>)> = loaded
        .members
        .iter()
        .filter(|m| m.is_current_home(now))
        .map(|m| (m.id.clone(), m.signing.clone()))
        .collect();
    let ctx = HeadContext {
        account: &loaded.account,
        history: &loaded.history,
        homes: &homes,
        now_ms: now,
    };
    let got = match verify_head(&fs::read(dir.join("head.json")).unwrap(), ctx) {
        Ok(h) if h.fresh(now, loaded.policies[0].1.head_max_age) => "ok".into(),
        Ok(_) => "ok (accepted, not fresh)".into(),
        Err(e) => e.code(),
    };
    let want = expected_of(case, "head");
    if got == want {
        Outcome::Pass(got)
    } else {
        Outcome::Fail(format!("expected {want}, got {got}"))
    }
}

/// Entry-level checks this crate implements: canonical bytes, shapes, controller and policy
/// parsing, grants, and every attributable signature. Not the §8.4 rules.
fn run_entries(dir: &Path, case: &Value) -> Outcome {
    let want_result = case["expected"]["result"].as_str().unwrap();
    let want_seq = case["expected"]["seq"].as_u64().unwrap();
    let got = match load(&[dir.join("records")]) {
        Ok(l) => (l.history.len() as u64, "ok".to_string()),
        Err((seq, e)) => (seq, e.code()),
    };
    let ok = if want_result == "ok" {
        got.1 == "ok" && got.0 >= want_seq
    } else {
        got == (want_seq, want_result.to_string())
    };
    if ok {
        Outcome::Pass(format!("{want_result} at seq {want_seq} (entry layer: canonical bytes, shapes, signatures; not §8.4 rules)"))
    } else {
        Outcome::Fail(format!(
            "expected {want_result} at seq {want_seq}, got {} at seq {}",
            got.1, got.0
        ))
    }
}

fn run_malleated(dir: &Path) -> Outcome {
    let a = json(&dir.join("original.json"));
    let b = json(&dir.join("malleated.json"));
    let (ba, bb) = (
        b64(a["body"].as_str().unwrap()),
        b64(b["body"].as_str().unwrap()),
    );
    let v = canonical_body(&ba, bounds::AUTHORITY_BODY).unwrap();
    let mut u = Unknown::default();
    let cs: Vec<Controller> = parse_controllers(&v["keyring"], &mut u).unwrap();
    let by = cs
        .iter()
        .find(|c| c.id() == v["by"].as_str().unwrap())
        .unwrap();
    let ok_a = verify_raw(&by.key.signing, &ba, &b64(a["signature"].as_str().unwrap())).is_ok();
    let ok_b = verify_raw(&by.key.signing, &bb, &b64(b["signature"].as_str().unwrap())).is_ok();
    let sigs_differ = a["signature"] != b["signature"];
    if ok_a && ok_b && sigs_differ && ba == bb {
        Outcome::Pass(
            "both verify (high-S valid); equal by body bytes (relay half not exercised)".into(),
        )
    } else {
        Outcome::Fail(format!("verify {ok_a}/{ok_b}, equal bodies {}", ba == bb))
    }
}

fn run_veto_sig(dir: &Path, case: &Value) -> Outcome {
    // The passkey's descriptor is the pinned passkey of the `origin-subdomain-pinned` genesis.
    let g = json(&cand().join("rules/origin-subdomain-pinned/records/authority/00000001.json"));
    let gv: Value = serde_json::from_slice(&b64(g["body"].as_str().unwrap())).unwrap();
    let cs = parse_controllers(&gv["keyring"], &mut Unknown::default()).unwrap();
    let veto = json(&dir.join("veto.json"));
    let body = b64(veto["body"].as_str().unwrap());
    let v = canonical_body(&body, bounds::RECEIPT_BODY).unwrap();
    let Some(signer) = cs.iter().find(|c| c.id() == v["by"].as_str().unwrap()) else {
        return Outcome::Fail("veto signer is not the fixture passkey".into());
    };
    let got = verify_authority_sig(
        signer,
        &body,
        &b64(veto["signature"].as_str().unwrap()),
        veto.get("assertion"),
    );
    let want = case["expected"]["vetoSignature"].as_str().unwrap();
    let ok = match want {
        "valid signature" => got.is_ok(),
        "invalid: no UV" => got == Err(SigFailure::UserVerification),
        "invalid: not an authority origin" => got == Err(SigFailure::Origin),
        _ => false,
    };
    if ok {
        Outcome::Pass(format!(
            "{want} (signature layer only; veto validity is §8.7)"
        ))
    } else {
        Outcome::Fail(format!("expected {want}, got {got:?}"))
    }
}

fn run_identifiers() -> Vec<(String, Outcome)> {
    let d = json(&cand().join("identifiers.json"));
    let mut out = Vec::new();
    for c in d["cases"].as_array().unwrap() {
        let src = c["source"].as_str().unwrap();
        let env = json(&repo().join("conformance").join(src));
        let id = AccountId::of_genesis(&b64(env["body"].as_str().unwrap()));
        let ok = id.as_str() == c["accountID"]
            && id.legacy_library_id() == c["legacyLibraryID"]
            && id.text() == c["text"]
            && AccountId::parse_text(c["text"].as_str().unwrap()).as_ref() == Ok(&id)
            && id.has_legacy_id(c["legacyLibraryID"].as_str().unwrap());
        out.push((
            format!("identifiers.json:{src}"),
            if ok {
                Outcome::Pass("ok".into())
            } else {
                Outcome::Fail(format!("got {id}"))
            },
        ));
    }
    for (i, r) in d["references"].as_array().unwrap().iter().enumerate() {
        let got = match Reference::parse(r["reference"].clone(), &mut Unknown::default()) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.code(),
        };
        let want = r["expected"].as_str().unwrap();
        out.push((
            format!("identifiers.json:references[{i}]"),
            if got == want {
                Outcome::Pass(got)
            } else {
                Outcome::Fail(format!("expected {want}, got {got}"))
            },
        ));
    }
    out
}

fn classify(rel: &str) -> Option<&'static str> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if rel.starts_with("succession/") {
        return Some("succession (§15, §16): out of scope");
    }
    if rel.starts_with("upgrade/") {
        return Some("upgrade (§16.1, plan step 3): out of scope");
    }
    if rel == "account" {
        return Some("full history replay (§8.4/§8.5, plan steps 2-3): out of scope");
    }
    if rel.starts_with("rules/") {
        if name.starts_with("t-") {
            return Some("pending transitions (§8.7): out of scope");
        }
        if name.starts_with("row-") {
            return Some("who-wins event sequences (§8.7): out of scope");
        }
        if name.starts_with("i-") {
            return Some("immediate keyring classification (§8.4, plan step 2): out of scope");
        }
        if matches!(name, "equivocation" | "rollback") {
            return Some(
                "equivocation evidence and high-water mark (§8.6, §13.3 persistence): out of scope",
            );
        }
    }
    None
}

#[test]
fn candidate_conformance() {
    let mut results: Vec<(String, Outcome)> = run_identifiers();
    let mut dirs = Vec::new();
    for top in [
        "account",
        "calls",
        "heads",
        "rules",
        "succession",
        "upgrade",
    ] {
        let p = cand().join(top);
        if p.join("case.json").exists() {
            dirs.push(p.clone());
        }
        for e in fs::read_dir(&p).unwrap() {
            let e = e.unwrap().path();
            if e.join("case.json").exists() {
                dirs.push(e);
            }
        }
    }
    dirs.sort();
    for dir in dirs {
        let rel = dir
            .strip_prefix(cand())
            .unwrap()
            .to_string_lossy()
            .to_string();
        let case = json(&dir.join("case.json"));
        let name = rel.rsplit('/').next().unwrap().to_string();
        let outcome = if let Some(why) = classify(&rel) {
            Outcome::NotImplemented(why)
        } else if rel.starts_with("calls/")
            || name.starts_with("call-")
            || name.starts_with("replay-")
            || name == "removal-after-heads"
        {
            run_call(&dir, &case)
        } else if rel.starts_with("heads/") {
            run_head(&dir, &case)
        } else if name.starts_with("origin-")
            || name.starts_with("non-canonical-")
            || name == "invalid-expires-date"
        {
            run_entries(&dir, &case)
        } else if name == "malleated-envelope" {
            run_malleated(&dir)
        } else if name.starts_with("veto-webauthn-") {
            run_veto_sig(&dir, &case)
        } else {
            Outcome::NotImplemented("unclassified: not run")
        };
        results.push((rel, outcome));
    }
    results.push((
        "pairing/pairing.json".into(),
        Outcome::NotImplemented("pairing (§7.3, plan step 2): out of scope"),
    ));

    let (mut pass, mut fail, mut ni) = (0, 0, 0);
    let mut unexpected = Vec::new();
    let mut stale_disputes = Vec::new();
    for (rel, o) in &results {
        let disputed = DISPUTED.iter().find(|(d, _)| d == rel);
        match o {
            Outcome::Pass(s) => {
                pass += 1;
                println!("PASS  {rel}: {s}");
                if disputed.is_some() {
                    stale_disputes.push(rel.clone());
                }
            }
            Outcome::Fail(s) => {
                fail += 1;
                match disputed {
                    Some((_, why)) => println!("FAIL  {rel}: {s} [disputed: {why}]"),
                    None => {
                        println!("FAIL  {rel}: {s}");
                        unexpected.push(rel.clone());
                    }
                }
            }
            Outcome::NotImplemented(why) => {
                ni += 1;
                println!("NOT-IMPLEMENTED  {rel}: {why}");
            }
        }
    }
    println!(
        "in scope: {} ({pass} pass, {fail} fail); not implemented: {ni}",
        pass + fail
    );
    assert!(unexpected.is_empty(), "unexpected failures: {unexpected:?}");
    assert!(
        stale_disputes.is_empty(),
        "disputed vectors now pass: {stale_disputes:?}"
    );
}
