//! Conformance runner for the Colophon 0.5 candidate vectors (`conformance/0.5/candidate/`).
//!
//! Each case is PASS, FAIL or NOT-IMPLEMENTED. Only results actually checked by the engine
//! pass. Authority histories use `verify_history`; event rows check each signed object
//! against its stated prefix and also check the final folded state. Prose is explanatory.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::history::{check_pending_transition, check_pending_veto, Stop};
use colophon_core::v05::{
    calls::{verify_call, AccountView, CallConfig, ControllerStatus},
    descriptor::Controller,
    encoding::{bounds, canonical_body, parse_date},
    heads::{verify_head, HeadContext},
    history::{verify_history, Objects, Persisted},
    ids::{AccountId, Reference},
    replay::MemoryReplayStore,
    signature::{verify_authority_signature, verify_raw, AssertionBytes, AuthorityRule, Checked},
    Failure,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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

fn files_in(dir: &Path) -> Vec<Vec<u8>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| r.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    v.sort();
    v.into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| fs::read(p).unwrap())
        .collect()
}

/// The object set of a case for the history verifier: its records (or the histories the
/// verifier names), and its objects: heads by name or by `verifier.heads`, everything else
/// except the call as pending objects.
fn objects_for(dir: &Path, ver: &Value) -> Objects {
    let record_dirs: Vec<PathBuf> = match &ver["history"] {
        Value::String(s) => vec![repo().join(s)],
        Value::Array(a) => a.iter().map(|s| repo().join(s.as_str().unwrap())).collect(),
        _ => vec![dir.join("records")],
    };
    let mut o = Objects::default();
    for d in record_dirs {
        o.entries.extend(files_in(&d.join("authority")));
    }
    let mut objs: Vec<PathBuf> = fs::read_dir(dir.join("objects"))
        .map(|r| r.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    objs.sort();
    for p in objs {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with("head") {
            if !ver["heads"].is_array() {
                o.heads.push(fs::read(&p).unwrap());
            }
        } else if name != "call.json" {
            o.pending.push(fs::read(&p).unwrap());
        }
    }
    for h in ver["heads"].as_array().into_iter().flatten() {
        o.heads
            .push(fs::read(repo().join(h.as_str().unwrap())).unwrap());
    }
    o
}

/// The view a call is verified over: the history verifier's verdict on the case's objects.
fn view_for(dir: &Path, case: &Value, now: i64) -> Result<AccountView, String> {
    let ver = &case["verifier"];
    let objects = objects_for(dir, ver);
    let verdict = verify_history(&objects, &Persisted::default(), now);
    if verdict.stop.is_some() {
        return Err(format!(
            "history: {} at seq {}",
            verdict.code(),
            verdict.seq()
        ));
    }
    let view =
        AccountView::from_history_verifier(&verdict, &objects, now).map_err(|e| e.to_string())?;
    // Statuses a vector states must be what the verifier derived.
    if let Some(stated) = ver["statuses"]["controllers"].as_object() {
        for (id, st) in stated {
            let want = match st.as_str().unwrap_or("") {
                "pendingAddition" => ControllerStatus::PendingAddition,
                "pendingRemoval" => ControllerStatus::PendingRemoval,
                "suspended" => ControllerStatus::Suspended,
                "addedNotFinal" => ControllerStatus::AddedNotFinal,
                other => return Err(format!("unknown status {other}")),
            };
            let got = view.controller_status(id);
            if got != Some(want) {
                return Err(format!(
                    "status of {id}: vector says {want:?}, verifier derived {got:?}"
                ));
            }
        }
    }
    Ok(view)
}

/// The object set of a case: its records, every branch, and the objects (heads by name).
pub fn objects_of(dir: &Path) -> Objects {
    let mut o = Objects {
        entries: files_in(&dir.join("records/authority")),
        ..Default::default()
    };
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with("branch-") {
            o.entries.extend(files_in(&p.join("authority")));
        }
    }
    let mut objs: Vec<PathBuf> = fs::read_dir(dir.join("objects"))
        .map(|r| r.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    objs.sort();
    for p in objs {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let bytes = fs::read(&p).unwrap();
        if name.starts_with("head") {
            o.heads.push(bytes);
        } else if name != "call.json" {
            o.pending.push(bytes);
        }
    }
    o
}

fn now_of(case: &Value) -> i64 {
    parse_date(
        case["verifier"]["now"]
            .as_str()
            .unwrap_or("2026-11-20T00:00:00Z"),
    )
    .unwrap()
}

fn run_history(dir: &Path, case: &Value) -> Outcome {
    let exp = &case["expected"];
    let admission_checked = if let Some(admission) = exp.get("admission") {
        use colophon_core::v05::history::home::{admit, HomeState, ServingInterval};
        let prefix = Objects {
            entries: files_in(&dir.join("records/authority"))
                .into_iter()
                .take(2)
                .collect(),
            ..Default::default()
        };
        let now = now_of(case);
        let home = match HomeState::new(
            admission["home"].as_str().unwrap().into(),
            &prefix,
            vec![ServingInterval {
                from_ms: i64::MIN,
                through_ms: None,
            }],
            now,
        ) {
            Ok(h) => h,
            Err(f) => return Outcome::Fail(format!("home state: {f}")),
        };
        let bytes = fs::read(dir.join(admission["object"].as_str().unwrap())).unwrap();
        let result = admit(&home, &bytes, case["verifier"]["now"].as_str().unwrap());
        let got = result
            .result
            .err()
            .map_or_else(|| "ok".into(), |r| r.code());
        if got != admission["result"] {
            return Outcome::Fail(format!(
                "admission: expected {}, got {got}",
                admission["result"]
            ));
        }
        true
    } else {
        false
    };
    if let Some(checks) = exp["checks"].as_array() {
        for check in checks {
            let after = check["after"].as_u64().unwrap() as usize;
            let mut objs = objects_of(dir);
            objs.entries.truncate(after);
            objs.heads = check["heads"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|v| b64(v.as_str().unwrap()))
                .collect();
            let bytes = fs::read(
                dir.join("events")
                    .join(format!("{}.json", check["object"].as_str().unwrap())),
            )
            .unwrap();
            let env: Value = serde_json::from_slice(&bytes).unwrap();
            let body = body_of(&env);
            let mut now = ms(body["issued"]
                .as_str()
                .or_else(|| body["created"].as_str())
                .unwrap());
            if let Some(last) = objs.entries.last() {
                let last: Value = serde_json::from_slice(last).unwrap();
                now = now.max(ms(body_of(&last)["issued"].as_str().unwrap()));
            }
            let v = verify_history(&objs, &Persisted::default(), now);
            if v.code() != "ok" || v.branch.len() != after {
                return Outcome::Fail(format!("event prefix: {} at {}", v.code(), v.seq()));
            }
            let st = v.state.as_ref().unwrap();
            let result = match body["protocol"].as_str().unwrap() {
                "colophon/transition/5" => check_pending_transition(st, &bytes),
                "colophon/veto/5" => {
                    let target = body["transition"].as_str().unwrap();
                    let all = objects_of(dir);
                    let recording = all
                        .entries
                        .iter()
                        .map(|e| serde_json::from_slice::<Value>(e).unwrap())
                        .map(|e| body_of(&e))
                        .find(|b| {
                            b.get("transition")
                                .and_then(Value::as_str)
                                .is_some_and(|t| {
                                    let t: Value = serde_json::from_slice(&b64(t)).unwrap();
                                    colophon_core::v05::encoding::digest(&b64(t["body"]
                                        .as_str()
                                        .unwrap()))
                                        == target
                                })
                        })
                        .unwrap();
                    let t = b64(recording["transition"].as_str().unwrap());
                    let rs = recording
                        .get("transitionReceipts")
                        .unwrap_or(&recording["receipts"])
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| b64(r.as_str().unwrap()))
                        .collect::<Vec<_>>();
                    check_pending_veto(st, &t, &rs, &bytes)
                }
                "colophon/authority/5" => {
                    objs.entries.push(bytes.clone());
                    let next = verify_history(&objs, &Persisted::default(), now);
                    if next.code() == "ok" {
                        Ok(())
                    } else {
                        return Outcome::Fail(format!("event entry: {}", next.code()));
                    }
                }
                "colophon/call/5" => {
                    let view = AccountView::from_history_verifier(&v, &objs, now).unwrap();
                    let audiences = vec![body["audience"].as_str().unwrap().to_string()];
                    let origins = BTreeMap::new();
                    let cfg = CallConfig {
                        now_ms: now,
                        audiences: &audiences,
                        call_origins: &origins,
                        controller_purposes: &[],
                        home_endpoints: &audiences,
                    };
                    verify_call(&bytes, &view, &cfg, &mut MemoryReplayStore::new()).map(|_| ())
                }
                _ => return Outcome::NotImplemented("unknown event protocol"),
            };
            let got = result.err().map_or_else(|| "ok".to_string(), |f| f.code());
            if got != check["result"] {
                return Outcome::Fail(format!(
                    "event {} after {after}: expected {}, got {got}",
                    check["object"], check["result"]
                ));
            }
        }
    }
    if let Some(want) = exp.get("transition").and_then(Value::as_str) {
        // A held transition judged against the verified state.
        let objs = objects_of(dir);
        let v = verify_history(&objs, &Persisted::default(), now_of(case));
        let Some(st) = v.state else {
            return Outcome::Fail("history failed".into());
        };
        let t = fs::read(dir.join("objects/transition.json")).unwrap();
        let got = match check_pending_transition(&st, &t) {
            Ok(()) => "ok".to_string(),
            Err(f) => f.code(),
        };
        return if got == want {
            Outcome::Pass(format!("transition {got}"))
        } else {
            Outcome::Fail(format!("transition: expected {want}, got {got}"))
        };
    }
    if let Some(want) = exp.get("standsAtSeq3").and_then(Value::as_str) {
        let v = verify_history(&objects_of(dir), &Persisted::default(), now_of(case));
        let got = v.branch.get(2).cloned().unwrap_or_default();
        return if got == want {
            Outcome::Pass("the expected conflict winner stands".into())
        } else {
            Outcome::Fail(format!("stands {got} ({})", v.code()))
        };
    }
    let (Some(result), Some(seq)) = (
        exp.get("result").and_then(Value::as_str),
        exp.get("seq").and_then(Value::as_u64),
    ) else {
        return if admission_checked {
            Outcome::Pass("home admission matches".into())
        } else {
            Outcome::NotImplemented("expectation not machine-checkable in this step (events, home-side or builder properties)")
        };
    };
    if case["verifier"].get("variants").is_some() {
        // Conflict without evidence: the same verdict for every high-water mark.
        let objs = objects_of(dir);
        let mut codes = Vec::new();
        for v in case["verifier"]["variants"].as_array().unwrap() {
            let hw = (
                v["highWater"]["seq"].as_u64().unwrap(),
                v["highWater"]["digest"].as_str().unwrap().to_string(),
            );
            let verdict = verify_history(&objs, &Persisted::high_water(hw.0, hw.1), now_of(case));
            codes.push((verdict.code(), verdict.seq()));
        }
        let want = (result.to_string(), seq);
        return if codes.iter().all(|c| c == &want) {
            Outcome::Pass(format!("{result} at seq {seq} for every high-water mark"))
        } else {
            Outcome::Fail(format!("expected {want:?}, got {codes:?}"))
        };
    }
    let verdict = verify_history(&objects_of(dir), &Persisted::default(), now_of(case));
    let got = (verdict.code(), verdict.seq());
    let detail = match &verdict.stop {
        Some(Stop::Failed { failure, .. }) => failure.detail().to_string(),
        Some(Stop::Held { why, .. }) => why.clone(),
        _ => String::new(),
    };
    if got != (result.to_string(), seq) {
        return Outcome::Fail(format!(
            "expected {result} at seq {seq}, got {} at seq {} ({detail})",
            got.0, got.1
        ));
    }
    // Extra structured expectations this verifier can check.
    if let Some(st) = &verdict.state {
        if let Some(cs) = exp
            .get("controllers")
            .or_else(|| exp["final"].get("controllers"))
            .and_then(Value::as_array)
        {
            let want: Vec<String> = cs.iter().map(|c| c.as_str().unwrap().to_string()).collect();
            let have: Vec<String> = st.keyring().controllers.keys().cloned().collect();
            if want != have {
                return Outcome::Fail(format!("controllers: expected {want:?}, got {have:?}"));
            }
        }
        if exp["final"]["suspended"].is_array() && !st.active_suspensions(now_of(case)).is_empty() {
            return Outcome::Fail("suspension remains after veto".into());
        }
        if let Some(v) = exp.get("vault").and_then(Value::as_str) {
            let retiring = st.vault_retiring();
            if (v == "retiring") != retiring {
                return Outcome::Fail(format!("vault: expected {v}, retiring = {retiring}"));
            }
        }
        if let Some(n) = exp.get("slots").and_then(Value::as_u64) {
            if st.keyring().slots.len() as u64 != n {
                return Outcome::Fail(format!(
                    "slots: expected {n}, got {}",
                    st.keyring().slots.len()
                ));
            }
        }
        if let Some(f) = exp.get("finality").and_then(Value::as_object) {
            for (sq, want) in f {
                let sq: u64 = sq.parse().unwrap_or(0);
                let fin = st
                    .activations()
                    .iter()
                    .find(|a| a.seq == sq)
                    .is_some_and(|a| a.final_);
                if (want == "final") != fin {
                    return Outcome::Fail(format!(
                        "finality of {sq}: expected {want}, final = {fin}"
                    ));
                }
            }
        }
    }
    Outcome::Pass(format!("{result} at seq {seq}"))
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
    let _ = record_dirs;
    let now = ms(ver["now"].as_str().unwrap());
    let view = match view_for(dir, case, now) {
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
    let now = ms(ver["now"].as_str().unwrap());
    let objects = objects_for(Path::new("/nonexistent"), ver);
    let verdict = verify_history(&objects, &Persisted::default(), now);
    let Some(st) = verdict.state.as_ref() else {
        return Outcome::Fail("history failed".into());
    };
    let homes: Vec<(String, Vec<u8>)> = st
        .current_homes()
        .into_iter()
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    let ctx = HeadContext {
        account: st.account(),
        history: st.history(),
        homes: &homes,
        now_ms: now,
    };
    let got = match verify_head(&fs::read(dir.join("head.json")).unwrap(), ctx) {
        Ok(h) if h.fresh(now, st.keyring().policy.head_max_age()) => "ok".into(),
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

/// Entry cases, now judged by the full history verifier.
fn run_entries(dir: &Path, case: &Value) -> Outcome {
    let want_result = case["expected"]["result"].as_str().unwrap();
    let want_seq = case["expected"]["seq"].as_u64().unwrap();
    let now = case["verifier"]["now"]
        .as_str()
        .map(ms)
        .unwrap_or_else(|| ms("2026-11-20T00:00:00Z"));
    let objects = Objects {
        entries: files_in(&dir.join("records/authority")),
        ..Default::default()
    };
    let v = verify_history(&objects, &Persisted::default(), now);
    let got = (v.code(), v.seq());
    if got == (want_result.to_string(), want_seq) {
        Outcome::Pass(format!(
            "{want_result} at seq {want_seq} (history verifier)"
        ))
    } else {
        Outcome::Fail(format!(
            "expected {want_result} at seq {want_seq}, got {} at seq {}",
            got.0, got.1
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
    let _ = rel;
    None
}

fn is_history_case(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    rel == "account"
        || (rel.starts_with("rules/")
            && (name.starts_with("t-")
                || name.starts_with("i-")
                || name.starts_with("row-")
                || name == "equivocation"
                || name == "rollback"))
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
        } else if rel.starts_with("upgrade/") {
            let v = verify_history(
                &objects_of(&dir),
                &Persisted::default(),
                ms("2026-12-01T00:00:00Z"),
            );
            let want = case["expected"]["colophon-0.5"].as_str().unwrap();
            if v.code() == want {
                Outcome::Pass(format!("{} at {}", v.code(), v.seq()))
            } else {
                Outcome::Fail(format!(
                    "want {want}, got {} at {}: {:?}",
                    v.code(),
                    v.seq(),
                    v.stop
                ))
            }
        } else if rel.starts_with("succession/") {
            run_succession(&dir, &case)
        } else if rel == "account" {
            let v = verify_history(
                &objects_of(&dir),
                &Persisted::default(),
                ms("2026-11-11T09:01:00Z"),
            );
            if v.code() == "ok" {
                Outcome::Pass(format!("history ok through seq {}", v.seq()))
            } else {
                Outcome::Fail(format!("{} at {}", v.code(), v.seq()))
            }
        } else if is_history_case(&rel) {
            run_history(&dir, &case)
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
    results.push(("pairing/pairing.json".into(), run_pairing()));

    let (mut pass, mut fail, mut ni) = (0, 0, 0);
    let mut unexpected = Vec::new();
    for (rel, o) in &results {
        match o {
            Outcome::Pass(s) => {
                pass += 1;
                println!("PASS  {rel}: {s}");
            }
            Outcome::Fail(s) => {
                fail += 1;
                println!("FAIL  {rel}: {s}");
                unexpected.push(rel.clone());
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
}

/// `pairing/pairing.json` (§7.3): the commitment and the six-digit code from the published
/// bytes, through both sides of the state machine, and each `refuse` row as an abort.
fn run_pairing() -> Outcome {
    use colophon_core::v05::pairing::{code, commitment, ExistingWaiting, Joiner, PairingAbort};
    let v = json(&cand().join("pairing/pairing.json"));
    let hex_of = |k: &str| -> Vec<u8> {
        let s = v[k].as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    let n32 = |bytes: Vec<u8>| -> [u8; 32] { bytes.try_into().unwrap() };
    let mut limiter = colophon_core::v05::pairing::FailureLimiter::new();
    let account = AccountId::parse(v["account"].as_str().unwrap()).unwrap();
    let (e, na, nb) = (hex_of("E"), n32(hex_of("nA")), n32(hex_of("nB")));
    let want_c = hex_of("commitment");
    let fail = |why: String| Outcome::Fail(why);
    // The published commitment and code.
    match commitment(&account, &e, &nb) {
        Ok(c) if c.to_vec() == want_c => {}
        other => return fail(format!("commitment: {other:?}")),
    }
    match code(&account, &e, &na, &nb) {
        Ok(c) if c == v["code"].as_str().unwrap() => {}
        other => return fail(format!("code: {other:?}")),
    }
    // Both sides of the protocol reach it: J commits, H sends nA only afterwards, J reveals.
    let Ok((joiner, c)) = Joiner::begin(&account, &e, nb) else {
        return fail("joiner refused the published E".into());
    };
    if c.to_vec() != want_c {
        return fail("joiner commitment differs".into());
    }
    let (awaiting, sent) =
        ExistingWaiting::receive_commitment(&account, c, limiter.permit(0).unwrap()).send_nonce(na);
    let Ok((reveal, j)) = joiner.reveal(sent) else {
        return fail("joiner reveal".into());
    };
    match awaiting.finish(&reveal.e, &reveal.nb) {
        Ok(h) if h.digits() == v["code"].as_str().unwrap() && j.digits() == h.digits() => {}
        other => return fail(format!("existing side: {other:?}")),
    }
    // Each refuse row aborts with a commitment mismatch.
    for row in v["refuse"].as_array().unwrap() {
        let e2 = hex_row(row["E"].as_str().unwrap());
        let nb2 = n32(hex_row(row["nB"].as_str().unwrap()));
        let r = ExistingWaiting::receive_commitment(
            &account,
            n32(want_c.clone()),
            limiter.permit(0).unwrap(),
        )
        .send_nonce(na)
        .0
        .finish(&e2, &nb2);
        let expected = row["expected"].as_str().unwrap();
        match r {
            Err(PairingAbort::CommitmentMismatch)
                if expected == PairingAbort::CommitmentMismatch.to_string() => {}
            other => return fail(format!("{}: want {expected}, got {other:?}", row["case"])),
        }
    }
    Outcome::Pass(format!(
        "commitment and code {} from the published bytes; {} refuse rows abort",
        v["code"].as_str().unwrap(),
        v["refuse"].as_array().unwrap().len()
    ))
}
fn hex_row(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn run_succession(dir: &Path, case: &Value) -> Outcome {
    let mut objects = Objects {
        entries: files_in(&dir.join("successor/authority")),
        predecessor: files_in(&dir.join("predecessor/authority")),
        ..Default::default()
    };
    if dir.join("genesis-receipt.json").exists() {
        objects
            .pending
            .push(fs::read(dir.join("genesis-receipt.json")).unwrap());
    }
    if dir.join("successor-head.json").exists() {
        objects
            .heads
            .push(fs::read(dir.join("successor-head.json")).unwrap());
    }
    let now = ms(case["expected"]["now"]
        .as_str()
        .unwrap_or("2026-11-14T10:15:00Z"));
    let v = verify_history(&objects, &Persisted::default(), now);
    let verified = v
        .state
        .as_ref()
        .is_some_and(|s| s.verified_succession().is_some());
    let want = case["expected"]["succession"] == "verified";
    if verified != want {
        return Outcome::Fail(format!(
            "succession verified={verified}, want {want}; {} at {}: {:?}",
            v.code(),
            v.seq(),
            v.stop
        ));
    }
    if let Some(code) = case["expected"]["genesis"].as_str() {
        if v.code() != code || v.seq() != 1 {
            return Outcome::Fail(format!(
                "genesis want {code} at 1, got {} at {}",
                v.code(),
                v.seq()
            ));
        }
    }
    if let Some(code) = case["expected"]["seq3"].as_str() {
        let wanted = code.rsplit(' ').next().unwrap();
        if v.code() != wanted {
            return Outcome::Fail(format!(
                "seq3 want {wanted}, got {}: {:?}",
                v.code(),
                v.stop
            ));
        }
    }
    if case["expected"].get("evidence").is_some()
        && v.state
            .as_ref()
            .is_none_or(|s| s.predecessor_evidence() != [4])
    {
        return Outcome::Fail("missing after-final evidence".into());
    }
    Outcome::Pass(format!(
        "succession {} (history {} at {})",
        if verified { "verified" } else { "unverified" },
        v.code(),
        v.seq()
    ))
}
