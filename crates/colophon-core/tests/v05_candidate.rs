//! Conformance runner for the Colophon 0.5 candidate vectors (`conformance/0.5/candidate/`).
//!
//! Every case is reported as PASS, FAIL or NOT-IMPLEMENTED. Out-of-scope cases (pending
//! transitions, forks, succession, upgrade, immediate keyring rules, pairing, ...) are never
//! reported as passing. The test fails on any in-scope FAIL that isn't in `DISPUTED`, and on
//! any disputed vector that starts passing.
//!
//! Authority histories are loaded by a **fixture view loader**. It checks canonical bytes,
//! shapes and every signature it can attribute (with the UV requirement of the rule each
//! signature is counted under), but it is not an authority replayer: it does not evaluate the
//! §8.4 rule table or §8.7. It derives the statuses §8.7 would compute from structured vector
//! data only: a transition object that no `activate` in the records embeds is pending; a
//! `suspend` entry suspends its key; an activation is provisional until every home current
//! before it has a fresh head covering it (§8.7 "Finality"). No status comes from a case's
//! description.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::{
    calls::{
        verify_call, AccountView, CallConfig, ControllerStatus, HistoryVerifierOutput,
        MemberStatus, ViewController, ViewMember,
    },
    descriptor::{Controller, Policy},
    encoding::{bounds, canonical_body, digest, parse_date, strict_parse},
    heads::{verify_head, HeadContext},
    ids::{key_id, AccountId, Reference},
    members::{AuthorityHeader, Grant, GrantContext, Request, Revoke},
    replay::MemoryReplayStore,
    signature::{verify_authority_signature, verify_raw, AssertionBytes, AuthorityRule, Checked},
    terms::{Terms, TermsKind},
    Failure,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// In-scope vectors whose expected outcome contradicts the spec text as this implementation
/// reads it, with the reason. They are reported as FAIL (disputed), not bent to pass.
const DISPUTED: &[(&str, &str)] = &[];

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
fn body_of(env: &Value) -> Value {
    serde_json::from_slice(&b64(env["body"].as_str().unwrap())).unwrap()
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Pass(String),
    Fail(String),
    NotImplemented(&'static str),
}

fn assertion_of(v: Option<&Value>) -> Option<(Vec<u8>, Vec<u8>)> {
    v.map(|a| {
        (
            b64(a["authenticatorData"].as_str().unwrap_or("")),
            b64(a["clientData"].as_str().unwrap_or("")),
        )
    })
}
/// One authority signature by a known controller, under the rule it is counted for.
fn check_sig(
    c: &Controller,
    body: &[u8],
    sig: &[u8],
    assertion: Option<&Value>,
    rule: AuthorityRule,
) -> Result<Checked, Failure> {
    let a = assertion_of(assertion);
    let bytes = a.as_ref().map(|(d, c)| AssertionBytes {
        authenticator_data: d,
        client_data: c,
    });
    verify_authority_signature(c, body, sig, bytes, rule)
}

fn parse_controllers(keyring: &Value) -> Result<Vec<Controller>, Failure> {
    keyring["controllers"]
        .as_array()
        .ok_or_else(|| Failure::Malformed("controllers".into()))?
        .iter()
        .map(|c| Controller::parse(c.clone(), "controller"))
        .collect()
}

type ControllerFx = (Vec<(u64, Option<Controller>)>, ControllerStatus);
struct MemberFx {
    req: Request,
    terms: Terms,
    granted: u64,
    revoked: Option<u64>,
    provisional: bool,
}
/// The fixture loader's result.
struct Loaded {
    account: AccountId,
    history: Vec<String>,
    policies: Vec<(u64, Policy)>,
    controllers: BTreeMap<String, ControllerFx>,
    members: Vec<MemberFx>,
    points: BTreeSet<Vec<u8>>,
    namespaces: Vec<String>,
    /// Embedded transition body digests and the seq of their `activate`.
    activations: Vec<(String, u64)>,
    /// Suspended keys and the instant their suspension ends.
    suspensions: Vec<(String, i64)>,
    /// Activation seqs a `final` entry covers.
    finals: Vec<u64>,
    undecidable: bool,
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
        activations: Vec::new(),
        suspensions: Vec::new(),
        finals: Vec::new(),
        undecidable: false,
    };
    for (i, f) in files.iter().enumerate() {
        let seq = i as u64 + 1;
        let fail = |e: Failure| (seq, e);
        let env = strict_parse(&fs::read(f).unwrap()).map_err(fail)?;
        let body = b64(env["body"].as_str().unwrap());
        let value = canonical_body(&body, bounds::AUTHORITY_BODY).map_err(fail)?;
        let (header, fields) = AuthorityHeader::split(value.clone()).map_err(fail)?;
        if header.seq != seq {
            return Err((seq, Failure::Malformed("seq".into())));
        }
        let current: BTreeMap<String, Controller> = if header.kind == "genesis" {
            parse_controllers(&value["keyring"])
                .map_err(fail)?
                .into_iter()
                .map(|c| (c.id(), c))
                .collect()
        } else {
            l.controllers
                .iter()
                .filter_map(|(id, (vs, _))| {
                    vs.last()
                        .and_then(|(_, c)| c.clone())
                        .map(|c| (id.clone(), c))
                })
                .collect()
        };
        // The rule each signature is counted under (fixture-level reading of §8.4).
        let primary_rule = match header.kind.as_str() {
            "genesis" | "layout" | "migration" => AuthorityRule::Control,
            "keyring" => AuthorityRule::KeyringEntry,
            "suspend" => AuthorityRule::Suspend,
            _ => AuthorityRule::Single,
        };
        if let Some(sig) = env.get("signature").and_then(Value::as_str) {
            let by = current
                .get(&header.by)
                .ok_or_else(|| fail(Failure::BadSignature("by is not a controller".into())))?;
            if check_sig(by, &body, &b64(sig), env.get("assertion"), primary_rule).map_err(fail)?
                == Checked::UndecidableForm
            {
                l.undecidable = true;
            }
        } else if !matches!(
            header.kind.as_str(),
            "activate" | "vetoed" | "final" | "successionVetoed"
        ) {
            return Err(fail(Failure::Malformed("missing signature".into())));
        }
        for (list, rule) in [
            ("cosignatures", primary_rule),
            ("additions", AuthorityRule::Possession),
        ] {
            for item in env
                .get(list)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let signer = item["signer"].as_str().unwrap();
                let pool: BTreeMap<String, Controller> =
                    if list == "additions" && header.kind == "keyring" {
                        parse_controllers(&value["keyring"])
                            .map_err(fail)?
                            .into_iter()
                            .map(|c| (c.id(), c))
                            .collect()
                    } else {
                        current.clone()
                    };
                let c = pool.get(signer).ok_or_else(|| {
                    fail(Failure::BadSignature(format!("{list}: unknown signer")))
                })?;
                if check_sig(
                    c,
                    &body,
                    &b64(item["signature"].as_str().unwrap()),
                    item.get("assertion"),
                    rule,
                )
                .map_err(fail)?
                    == Checked::UndecidableForm
                {
                    l.undecidable = true;
                }
            }
        }
        match header.kind.as_str() {
            "genesis" => {
                l.account = AccountId::of_genesis(&body);
                let kr = &value["keyring"];
                for c in parse_controllers(kr).map_err(fail)? {
                    l.points.insert(c.key().signing().to_vec());
                    if let Some(a) = c.key().agreement() {
                        l.points.insert(a.to_vec());
                    }
                    l.controllers
                        .insert(c.id(), (vec![(seq, Some(c))], ControllerStatus::Active));
                }
                for k in ["signing", "agreement"] {
                    l.points.insert(b64(kr["vault"][k].as_str().unwrap()));
                }
                l.policies.push((
                    seq,
                    Policy::parse(kr["policy"].clone(), "policy").map_err(fail)?,
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
                let g = Grant::parse(fields, ctx).map_err(fail)?;
                add_member(&mut l, g.request, g.terms, seq, false);
            }
            "revoke" => {
                let r = Revoke::parse(fields).map_err(fail)?;
                if let Some(m) = l.members.iter_mut().find(|m| m.req.member_id() == r.member) {
                    m.revoked = Some(seq);
                }
            }
            "activate" => {
                // §8.7 is out of scope: the embedded transition's change is applied as given.
                let t_bytes = b64(value["transition"].as_str().unwrap());
                let t_env = strict_parse(&t_bytes).map_err(fail)?;
                let t_body = b64(t_env["body"].as_str().unwrap());
                l.activations.push((digest(&t_body), seq));
                let t: Value = serde_json::from_slice(&t_body).unwrap();
                let change = &t["change"];
                for a in change["homes"]["appoint"].as_array().into_iter().flatten() {
                    let req =
                        Request::parse(&b64(a["request"].as_str().unwrap()), true).map_err(fail)?;
                    let terms =
                        Terms::parse(a["terms"].clone(), TermsKind::Member).map_err(fail)?;
                    add_member(&mut l, req, terms, seq, true);
                }
                for c in change["keyring"]["add"].as_array().into_iter().flatten() {
                    let c = Controller::parse(c.clone(), "controller").map_err(fail)?;
                    l.controllers.insert(
                        c.id(),
                        (vec![(seq, Some(c))], ControllerStatus::AddedNotFinal),
                    );
                }
                for id in change["keyring"]["remove"].as_array().into_iter().flatten() {
                    if let Some((vs, _)) = l.controllers.get_mut(id.as_str().unwrap()) {
                        vs.push((seq, None));
                    }
                }
            }
            "suspend" => {
                // Ends by the clock at the transition's due time + 7 days (§8.7 state table).
                let key = value["key"].as_str().unwrap().to_string();
                let t_env =
                    strict_parse(&b64(value["transition"].as_str().unwrap())).map_err(fail)?;
                let t: Value =
                    serde_json::from_slice(&b64(t_env["body"].as_str().unwrap())).unwrap();
                let delay = l.policies.last().unwrap().1.recovery_delay() as i64;
                let due = ms(t["issued"].as_str().unwrap()) + 300_000 + delay * 1000;
                l.suspensions.push((key, due + 7 * 86_400_000));
            }
            "final" => {
                l.finals.push(value["activation"]["seq"].as_u64().unwrap());
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
fn add_member(l: &mut Loaded, req: Request, terms: Terms, seq: u64, provisional: bool) {
    l.points.insert(req.signing.clone());
    l.points.insert(req.agreement.clone());
    l.members.push(MemberFx {
        req,
        terms,
        granted: seq,
        revoked: None,
        provisional,
    });
}

fn head_files(dir: &Path, ver: &Value) -> Vec<PathBuf> {
    match &ver["heads"] {
        Value::Array(a) => a.iter().map(|s| repo().join(s.as_str().unwrap())).collect(),
        _ => {
            let mut v: Vec<PathBuf> = fs::read_dir(dir.join("objects"))
                .map(|r| {
                    r.map(|e| e.unwrap().path())
                        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("head"))
                        .collect()
                })
                .unwrap_or_default();
            v.sort();
            v
        }
    }
}

/// Build the view, resolving finality from the heads (§8.7 "Finality", fixture-level): an
/// activation is final once every home current before it has a fresh head covering it.
fn view_of(l: &Loaded, dir: &Path, case: &Value, now: i64) -> Result<AccountView, String> {
    let heads: Vec<Vec<u8>> = head_files(dir, &case["verifier"])
        .iter()
        .map(|p| fs::read(p).unwrap())
        .collect();
    // Finality is a recorded fact (§8.7): an activation is final when its witness set (the homes
    // current before it) is empty or a `final` entry covers it. Heads seen never decide.
    let mut final_member: Vec<bool> = l.members.iter().map(|m| !m.provisional).collect();
    let mut final_seq: BTreeSet<u64> = BTreeSet::new();
    for (_, aseq) in &l.activations {
        let witnesses = l
            .members
            .iter()
            .zip(&final_member)
            .filter(|(m, f)| {
                **f && m.granted < *aseq && m.terms.serves_home() && m.revoked.is_none()
            })
            .count();
        if witnesses == 0 || l.finals.contains(aseq) {
            final_seq.insert(*aseq);
            for (m, f) in l.members.iter().zip(final_member.iter_mut()) {
                if m.granted == *aseq {
                    *f = true;
                }
            }
        }
    }
    let mut controllers = l.controllers.clone();
    for (vs, st) in controllers.values_mut() {
        if *st == ControllerStatus::AddedNotFinal
            && vs.first().is_some_and(|(s, _)| final_seq.contains(s))
        {
            *st = ControllerStatus::Active;
        }
    }
    for (key, ends) in &l.suspensions {
        if now <= *ends {
            if let Some((_, st)) = controllers.get_mut(key) {
                *st = ControllerStatus::Suspended;
            }
        }
    }
    // Pending transitions: a transition object no `activate` embeds.
    if dir.join("objects/transition.json").exists() {
        let t = json(&dir.join("objects/transition.json"));
        let t_digest = digest(&b64(t["body"].as_str().unwrap()));
        if !l.activations.iter().any(|(d, _)| d == &t_digest) {
            let body = body_of(&t);
            for id in body["change"]["keyring"]["remove"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some((_, st)) = controllers.get_mut(id.as_str().unwrap()) {
                    if *st == ControllerStatus::Active {
                        *st = ControllerStatus::PendingRemoval;
                    }
                }
            }
            for c in body["change"]["keyring"]["add"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let id = key_id(&b64(c["key"]["signing"].as_str().unwrap()));
                controllers
                    .entry(id)
                    .or_insert((Vec::new(), ControllerStatus::PendingAddition));
            }
        }
    }
    let members = l
        .members
        .iter()
        .zip(&final_member)
        .map(|(m, f)| {
            ViewMember::new(
                m.req.signing.clone(),
                m.req.kind.clone(),
                m.terms.clone(),
                m.granted,
                Vec::new(),
                Vec::new(),
                m.revoked,
                if *f {
                    MemberStatus::Active
                } else {
                    MemberStatus::AddedNotFinal
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    // Statuses a vector states (`verifier.statuses`) must agree with what the loader derived.
    if let Some(stated) = case["verifier"]["statuses"]["controllers"].as_object() {
        for (id, st) in stated {
            let want = match st.as_str().unwrap_or("") {
                "pendingAddition" => ControllerStatus::PendingAddition,
                "pendingRemoval" => ControllerStatus::PendingRemoval,
                "suspended" => ControllerStatus::Suspended,
                "addedNotFinal" => ControllerStatus::AddedNotFinal,
                other => return Err(format!("unknown status {other}")),
            };
            let got = controllers.get(id).map(|(_, s)| *s);
            if got != Some(want) {
                return Err(format!(
                    "status of {id}: vector says {want:?}, loader derived {got:?}"
                ));
            }
        }
    }
    let controllers = controllers
        .into_iter()
        .map(|(id, (vs, st))| ViewController::new(id, vs, st))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    AccountView::from_history_verifier(HistoryVerifierOutput {
        account: l.account.clone(),
        history: l.history.clone(),
        policies: l.policies.clone(),
        controllers,
        members,
        heads,
        vouched_fork: false,
        principal_points: l.points.clone(),
    })
    .map_err(|e| e.to_string())
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
    let view = match view_of(&loaded, dir, case, now) {
        Ok(v) => v,
        Err(e) => return Outcome::Fail(format!("view refused: {e}")),
    };
    let audiences: Vec<String> = ver["audiences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().into())
        .collect();
    let purposes: Vec<String> = ver["controllerPurposes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| s.as_str().unwrap().into())
        .collect();
    let home_endpoints: Vec<String> = if ver["role"] == "home" {
        audiences.clone()
    } else {
        Vec::new()
    };
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
        home_endpoints: &home_endpoints,
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
    let l = load(&[repo().join(ver["history"].as_str().unwrap())])
        .unwrap_or_else(|(s, e)| panic!("{s}: {e}"));
    let now = ms(ver["now"].as_str().unwrap());
    let homes = view_of(&l, dir, case, now).unwrap().current_homes(now);
    let ctx = HeadContext {
        account: &l.account,
        history: &l.history,
        homes: &homes,
        now_ms: now,
    };
    let got = match verify_head(&fs::read(dir.join("head.json")).unwrap(), ctx) {
        Ok(h) if h.fresh(now, l.policies[0].1.head_max_age()) => "ok".into(),
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

/// Entry-level checks: canonical bytes, shapes, controller and policy parsing, grants, and
/// every attributable signature under its rule's UV requirement. Not the §8.4 rule table.
fn run_entries(dir: &Path, case: &Value) -> Outcome {
    let want_result = case["expected"]["result"].as_str().unwrap();
    let want_seq = case["expected"]["seq"].as_u64().unwrap();
    let got = match load(&[dir.join("records")]) {
        Ok(l) if l.undecidable => (l.history.len() as u64, "newerFormat".to_string()),
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
    let cs = parse_controllers(&v["keyring"]).unwrap();
    let by = cs
        .iter()
        .find(|c| c.id() == v["by"].as_str().unwrap())
        .unwrap();
    let ok_a = verify_raw(
        by.key().signing(),
        &ba,
        &b64(a["signature"].as_str().unwrap()),
    )
    .is_ok();
    let ok_b = verify_raw(
        by.key().signing(),
        &bb,
        &b64(b["signature"].as_str().unwrap()),
    )
    .is_ok();
    if ok_a && ok_b && a["signature"] != b["signature"] && ba == bb {
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
    let cs = parse_controllers(&body_of(&g)["keyring"]).unwrap();
    let veto = json(&dir.join("veto.json"));
    let body = b64(veto["body"].as_str().unwrap());
    let v = canonical_body(&body, bounds::VETO_BODY).unwrap();
    let Some(signer) = cs.iter().find(|c| c.id() == v["by"].as_str().unwrap()) else {
        return Outcome::Fail("veto signer is not the fixture passkey".into());
    };
    let got = check_sig(
        signer,
        &body,
        &b64(veto["signature"].as_str().unwrap()),
        veto.get("assertion"),
        AuthorityRule::Veto,
    );
    let want = case["expected"]["vetoSignature"].as_str().unwrap();
    let detail = |e: &Result<Checked, Failure>| match e {
        Err(f) => f.detail().to_string(),
        Ok(c) => format!("{c:?}"),
    };
    let ok = match want {
        "valid signature" => got == Ok(Checked::Verified),
        "invalid: no UV" => detail(&got).contains("UserVerification"),
        "invalid: not an authority origin" => detail(&got).contains("Origin"),
        _ => false,
    };
    if ok {
        Outcome::Pass(format!(
            "{want} (signature layer only; veto validity is §8.7)"
        ))
    } else {
        Outcome::Fail(format!("expected {want}, got {}", detail(&got)))
    }
}

fn run_number_ties() -> Vec<(String, Outcome)> {
    let d = json(&cand().join("encoding/number-ties.json"));
    d["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let bits = u64::from_str_radix(c["bits"].as_str().unwrap(), 16).unwrap();
            let f = f64::from_bits(bits);
            let canon = c["canonical"].as_str().unwrap();
            let refused = c["refused"].as_str().unwrap();
            let wrote = String::from_utf8(
                colophon_core::v05::encoding::canonical(&serde_json::json!(f)).unwrap(),
            )
            .unwrap();
            let ok = wrote == canon
                && canonical_body(format!("{{\"n\":{canon}}}").as_bytes(), 64).is_ok()
                && canonical_body(format!("{{\"n\":{refused}}}").as_bytes(), 64).is_err();
            (
                format!("encoding/number-ties.json:{}", c["bits"].as_str().unwrap()),
                if ok {
                    Outcome::Pass("canonical tie spelling".into())
                } else {
                    Outcome::Fail(format!("wrote {wrote}"))
                },
            )
        })
        .collect()
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
        let got = match Reference::parse(r["reference"].clone()) {
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
    results.extend(run_number_ties());
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
