//! The operations. Each is a function from a JSON request to a JSON response; the dispatcher
//! turns any error into `{"ok":false,"error":…}` and nothing here panics on input.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use colophon_core::v05::account::{Account, Identity};
use colophon_core::v05::calls::{verify_call, AccountView, Call, CallConfig, CallSigner};
use colophon_core::v05::descriptor::HistoryAccess;
use colophon_core::v05::encoding::{bounds, canonical, digest, strict_parse};
use colophon_core::v05::engine::paths::{self, Kind};
use colophon_core::v05::heads::HeadContext;
use colophon_core::v05::history::envelope::AuthEnvelope;
use colophon_core::v05::history::home::{
    admit, admit_first, admit_pending_batch, FirstUpload, HomeState, ReceiptToSign, Refusal,
};
use colophon_core::v05::history::{verify_history, Objects, Persisted, State};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::records::{OperationHeader, RecordAuthority};
use colophon_core::v05::replay::{
    retained, ReplayKey, ReplayState, ReplayStore, Reservation, RETENTION_MS,
};
use colophon_core::v05::signature::RawEnvelope;
use colophon_core::v05::write::calls::{
    finish_head, finish_receipt, prepare_head, prepare_receipt, HeadSpec,
};
use colophon_core::v05::write::{format_date, SignatureResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type R<T> = Result<T, String>;

/// The version of the persisted slot state.
const STATE_VERSION: u32 = 1;
/// The largest request body this module reads (the host bounds a body before it reads it).
const MAX_REQUEST: usize = 24 * 1024 * 1024;
/// Entries a first upload may hold before this home is appointed in them (a bound on what an
/// unappointed home keeps for one account).
const MAX_FIRST_UPLOAD: usize = 512;

/// Run one request. The input is JSON, the output is JSON; nothing panics on bad input.
pub fn handle(input: &[u8]) -> Vec<u8> {
    let out = match run(input) {
        Ok(mut v) => {
            v["ok"] = json!(true);
            v
        }
        Err(e) => json!({"ok": false, "error": e}),
    };
    serde_json::to_vec(&out).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"encode\"}".to_vec())
}

fn run(input: &[u8]) -> R<Value> {
    if input.len() > MAX_REQUEST {
        return Err("request too large".into());
    }
    let req: Value = serde_json::from_slice(input).map_err(|e| e.to_string())?;
    match str_of(&req, "op")? {
        "limits" => Ok(limits()),
        "identity" => identity(&req),
        "init" => init(&req),
        "status" => status(&req),
        "post_authority" => post_authority(&req),
        "post_pending" => post_pending(&req),
        "admit_one" => admit_one(&req),
        "finish_receipt" => op_finish_receipt(&req),
        "head_request" => head_request(&req),
        "finish_head" => op_finish_head(&req),
        "pending_page" => pending_page(&req),
        "pending_object" => pending_object(&req),
        "record_due" => record_due(&req),
        "check_record" => check_record(&req),
        "call_key" => call_key(&req),
        "authorize" => authorize(&req),
        "objects" => objects(&req),
        other => Err(format!("unknown op {other}")),
    }
}

// ---------------------------------------------------------------------------------------------
// Request helpers.

fn str_of<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {k}"))
}
fn i64_of(v: &Value, k: &str) -> R<i64> {
    v.get(k)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing {k}"))
}
fn u64_of(v: &Value, k: &str) -> R<u64> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing {k}"))
}
fn bytes_of(v: &Value, k: &str) -> R<Vec<u8>> {
    B64.decode(str_of(v, k)?).map_err(|e| format!("{k}: {e}"))
}
fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

// ---------------------------------------------------------------------------------------------
// The persisted state: a version, the home's ID, the entries held before it is appointed, and
// the core's own [`HomeState`] once it is.

#[derive(Serialize, Deserialize)]
struct Slot {
    v: u32,
    home: String,
    /// Entries of a first upload held until the history appoints this home (§13.1).
    booting: Vec<String>,
    /// `HomeState::to_bytes`, base64, once appointed.
    home_state: Option<String>,
}
struct Loaded {
    slot: Slot,
    home: Option<HomeState>,
}
impl Loaded {
    fn booting_entries(&self) -> R<Vec<Vec<u8>>> {
        self.slot
            .booting
            .iter()
            .map(|e| B64.decode(e).map_err(|e| e.to_string()))
            .collect()
    }
    fn dump(&self) -> R<String> {
        let mut slot = Slot {
            v: self.slot.v,
            home: self.slot.home.clone(),
            booting: self.slot.booting.clone(),
            home_state: None,
        };
        if let Some(h) = &self.home {
            slot.home_state = Some(b64(&h.to_bytes().map_err(|e| e.to_string())?));
            slot.booting = Vec::new();
        }
        Ok(b64(&serde_json::to_vec(&slot).map_err(|e| e.to_string())?))
    }
}
fn load(req: &Value) -> R<Loaded> {
    let raw = bytes_of(req, "state")?;
    let slot: Slot = serde_json::from_slice(&raw).map_err(|e| format!("state: {e}"))?;
    if slot.v != STATE_VERSION {
        return Err(format!("unknown state version {}", slot.v));
    }
    let home = match &slot.home_state {
        Some(s) => Some(
            HomeState::from_bytes(&B64.decode(s).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        ),
        None => None,
    };
    Ok(Loaded { slot, home })
}

fn init(req: &Value) -> R<Value> {
    let home = str_of(req, "home")?;
    if !colophon_core::v05::ids::is_key_id(home) {
        return Err("home is not a member ID".into());
    }
    let l = Loaded {
        slot: Slot {
            v: STATE_VERSION,
            home: home.to_string(),
            booting: Vec::new(),
            home_state: None,
        },
        home: None,
    };
    Ok(json!({"state": l.dump()?}))
}

fn identity(req: &Value) -> R<Value> {
    let point = bytes_of(req, "signing")?;
    if !colophon_core::v05::descriptor::valid_point(&point) {
        return Err("not a valid P-256 point".into());
    }
    Ok(json!({"id": key_id(&point)}))
}

fn limits() -> Value {
    json!({
        "retentionMs": RETENTION_MS,
        "firstUploadEntries": MAX_FIRST_UPLOAD,
        "authorityPage": 64, "pendingPage": 64, "pendingBatch": 16,
        "authorityBody": bounds::AUTHORITY_BODY,
        "transitionEnvelope": bounds::TRANSITION_ENVELOPE,
    })
}

// ---------------------------------------------------------------------------------------------
// The verified view of a home.

struct View {
    persisted: Persisted,
    state: State,
}
fn view(h: &HomeState, now_ms: i64) -> R<View> {
    let persisted = h.persisted().map_err(|e| e.to_string())?;
    let v = verify_history(&Objects::default(), &persisted, now_ms);
    if v.stop.is_some() {
        return Err(format!("history: {}", v.code()));
    }
    let state = v.state.ok_or("no verified history")?;
    Ok(View { persisted, state })
}

fn status(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let Some(h) = &l.home else {
        return Ok(json!({"appointed": false, "held": l.slot.booting.len(), "home": l.slot.home}));
    };
    let v = match view(h, now_ms) {
        Ok(v) => v,
        Err(e) => return Ok(json!({"appointed": true, "home": l.slot.home, "error": e})),
    };
    let st = &v.state;
    let policy = &st.keyring().policy;
    let peers: Vec<Value> = st
        .current_homes()
        .iter()
        .filter(|m| m.request.member_id() != l.slot.home)
        .map(|m| json!({"id": m.request.member_id(), "endpoints": m.request.endpoints}))
        .collect();
    Ok(json!({
        "appointed": true,
        "home": l.slot.home,
        "account": st.account().as_str(),
        "seq": st.history().len(),
        "digest": st.history().last(),
        "history": if policy.history() == HistoryAccess::Public { "public" } else { "members" },
        "headMaxAge": policy.head_max_age(),
        "headQuorum": policy.head_quorum(),
        "peers": peers,
        "state": l.dump()?,
    }))
}

// ---------------------------------------------------------------------------------------------
// Admission.

fn refusal(r: &Refusal) -> Value {
    match r {
        Refusal::Conflict => json!({"outcome": "conflict"}),
        Refusal::PrimaryRequired(e) => json!({"outcome": "primary", "endpoints": e}),
        other => json!({"outcome": "refused", "result": other.code()}),
    }
}
fn signs(reqs: &[ReceiptToSign]) -> Vec<Value> {
    reqs.iter()
        .map(|r| json!({"object": r.object, "body": b64(&r.body)}))
        .collect()
}
fn entry_seq(bytes: &[u8]) -> R<u64> {
    let env = AuthEnvelope::parse(
        bytes,
        bounds::AUTHORITY_BODY,
        bounds::AUTHORITY_BODY * 2,
        false,
    )
    .map_err(|e| e.to_string())?;
    env.value
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| "entry without seq".into())
}
fn entry_path(seq: u64) -> String {
    format!("authority/{seq:08}.json")
}

fn post_authority(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let malformed = |why: &str| {
        Ok(json!({"outcome": "refused", "result": "malformed", "why": why,
                  "state": l_dump_unchanged(req), "store": [], "sign": [], "accepted": []}))
    };
    let body = bytes_of(req, "body")?;
    let Ok(v) = strict_parse(&body) else {
        return malformed("body is not strict JSON");
    };
    let (Some(from), Some(entries)) = (
        v.get("from").and_then(Value::as_u64),
        v.get("entries").and_then(Value::as_array),
    ) else {
        return malformed("from and entries are required");
    };
    let receipts = v.get("receipts").and_then(Value::as_array);
    let extra = v
        .as_object()
        .is_some_and(|o| o.keys().any(|k| !["from", "entries", "receipts"].contains(&k.as_str())));
    if extra || !(1..=64).contains(&entries.len()) || receipts.is_some_and(|r| r.len() > 64) {
        return malformed("1-64 entries, from, receipts only");
    }
    let mut store = Vec::new();
    let mut sign: Vec<Value> = Vec::new();
    let mut accepted = Vec::new();
    let mut outcome = json!({"outcome": "ok"});
    for (i, e) in entries.iter().enumerate() {
        let Ok(b) = canonical(e) else {
            outcome = json!({"outcome": "refused", "result": "malformed"});
            break;
        };
        let Ok(seq) = entry_seq(&b) else {
            outcome = json!({"outcome": "refused", "result": "malformed"});
            break;
        };
        if seq != from + i as u64 {
            outcome = json!({"outcome": "refused", "result": "malformed",
                             "why": "entries are not contiguous from `from`"});
            break;
        }
        let result: Result<(), Refusal> = match l.home.take() {
            Some(h) => {
                let a = admit(&h, &b, &now);
                l.home = Some(a.state);
                sign.extend(signs(&a.receipts));
                a.result
            }
            None => {
                let held = l.booting_entries()?;
                if held.len() >= MAX_FIRST_UPLOAD && seq as usize > held.len() {
                    Err(Refusal::Verification(
                        colophon_core::v05::Failure::Unavailable("first upload is too long".into()),
                    ))
                } else {
                    match admit_first(&l.slot.home, &held, &b, &now) {
                        Ok(FirstUpload::Held(entries)) => {
                            l.slot.booting = entries.iter().map(|e| b64(e)).collect();
                            Ok(())
                        }
                        Ok(FirstUpload::Home(h)) => {
                            l.home = Some(*h);
                            Ok(())
                        }
                        Err(r) => Err(r),
                    }
                }
            }
        };
        match result {
            Ok(()) => {
                accepted.push(seq);
                store.push(json!({"path": entry_path(seq), "bytes": b64(&b)}));
            }
            Err(r) => {
                outcome = refusal(&r);
                break;
            }
        }
    }
    // Receipts that came with the entries are admitted like any forwarded receipt (§14 leaves
    // their use open: reported as a question). A refused one is ignored.
    if outcome["outcome"] == "ok" {
        for r in receipts.into_iter().flatten() {
            if let (Some(h), Ok(b)) = (l.home.take(), canonical(r)) {
                l.home = Some(admit(&h, &b, &now).state);
            }
        }
    }
    let mut out = outcome;
    out["state"] = json!(l.dump()?);
    out["store"] = json!(store);
    out["sign"] = json!(sign);
    out["accepted"] = json!(accepted);
    out["appointed"] = json!(l.home.is_some());
    Ok(out)
}
/// The request's own state, unchanged (for answers that refuse before touching it).
fn l_dump_unchanged(req: &Value) -> Value {
    req.get("state").cloned().unwrap_or(Value::Null)
}

/// The files a set of pending objects occupies: `transitions/`, `vetoes/` and `receipts/`.
fn pending_files(objects: &Objects) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for p in &objects.pending {
        let Ok(env) = AuthEnvelope::parse(
            p,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            false,
        ) else {
            continue;
        };
        let path = match env.value.get("protocol").and_then(Value::as_str) {
            Some("colophon/transition/5") => paths::pending_path(false, &env.digest),
            Some("colophon/veto/5") => paths::pending_path(true, &env.digest),
            Some("colophon/receipt/5") => {
                match (
                    env.value.get("object").and_then(Value::as_str),
                    env.value.get("by").and_then(Value::as_str),
                ) {
                    (Some(o), Some(by)) => paths::receipt_path(o, by),
                    _ => continue,
                }
            }
            _ => continue,
        };
        out.push((path, p.clone()));
    }
    out
}
fn new_files(before: &Persisted, after: &Persisted) -> Vec<Value> {
    let had: std::collections::BTreeSet<String> = before
        .objects()
        .map(|o| pending_files(o).into_iter().map(|(p, _)| p).collect())
        .unwrap_or_default();
    after
        .objects()
        .map(|o| {
            pending_files(o)
                .into_iter()
                .filter(|(p, _)| !had.contains(p))
                .map(|(p, b)| json!({"path": p, "bytes": b64(&b)}))
                .collect()
        })
        .unwrap_or_default()
}

fn post_pending(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let Some(h) = &l.home else {
        return Ok(json!({"outcome": "refused", "result": "unavailable",
                         "why": "this home holds no history of an account yet",
                         "state": req["state"], "store": [], "sign": []}));
    };
    let body = bytes_of(req, "body")?;
    let parsed = strict_parse(&body)
        .ok()
        .filter(|v| v.as_object().is_some_and(|o| o.len() == 1))
        .and_then(|v| v.get("objects").and_then(Value::as_array).cloned());
    let Some(objects) = parsed.filter(|o| (1..=16).contains(&o.len())) else {
        return Ok(json!({"outcome": "refused", "result": "malformed",
                         "state": req["state"], "store": [], "sign": []}));
    };
    let mut objs = Vec::new();
    for o in &objects {
        match canonical(o) {
            Ok(b) => objs.push(b),
            Err(_) => {
                return Ok(json!({"outcome": "refused", "result": "malformed",
                                 "state": req["state"], "store": [], "sign": []}))
            }
        }
    }
    let before = h.persisted().map_err(|e| e.to_string())?;
    let (next, results, receipts) =
        admit_pending_batch(h, &objs, &now).map_err(|e| e.to_string())?;
    let after = next.persisted().map_err(|e| e.to_string())?;
    let refused: Vec<Value> = results
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            r.as_ref().err().map(|e| {
                let d = AuthEnvelope::parse(
                    &objs[i],
                    bounds::TRANSITION_ENVELOPE,
                    bounds::TRANSITION_ENVELOPE,
                    false,
                )
                .map(|e| e.digest)
                .unwrap_or_default();
                json!({"object": d, "result": e.code()})
            })
        })
        .collect();
    let l2 = Loaded {
        slot: Slot {
            v: STATE_VERSION,
            home: l.slot.home.clone(),
            booting: vec![],
            home_state: None,
        },
        home: Some(next),
    };
    Ok(json!({
        "outcome": if refused.is_empty() { "ok" } else { "refused" },
        "results": refused,
        "state": l2.dump()?,
        "store": new_files(&before, &after),
        "sign": signs(&receipts),
    }))
}

/// One forwarded receipt or head (a head arrives by `PUT {base}/records/heads/<id>.json`).
fn admit_one(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let Some(h) = l.home.take() else {
        return Ok(json!({"outcome": "refused", "result": "unavailable",
                         "state": req["state"], "store": []}));
    };
    let bytes = bytes_of(req, "bytes")?;
    let canon = match strict_parse(&bytes).and_then(|v| canonical(&v)) {
        Ok(c) => c,
        Err(_) => {
            l.home = Some(h);
            return Ok(json!({"outcome": "refused", "result": "malformed",
                             "state": l.dump()?, "store": []}));
        }
    };
    let before = h.persisted().map_err(|e| e.to_string())?;
    let a = admit(&h, &canon, &now);
    let after = a.state.persisted().map_err(|e| e.to_string())?;
    let mut out = match &a.result {
        Ok(()) => json!({"outcome": "ok"}),
        Err(r) => refusal(r),
    };
    l.home = Some(a.state);
    out["state"] = json!(l.dump()?);
    out["store"] = json!(new_files(&before, &after));
    out["sign"] = json!(signs(&a.receipts));
    Ok(out)
}

fn op_finish_receipt(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let h = l.home.take().ok_or("no home state")?;
    let object = str_of(req, "object")?.to_string();
    let sign = ReceiptToSign {
        object: object.clone(),
        body: bytes_of(req, "body")?,
    };
    let prepared = prepare_receipt(&sign).map_err(|e| e.to_string())?;
    let sig = SignatureResult {
        signature: bytes_of(req, "signature")?,
        assertion: None,
    };
    let before = h.persisted().map_err(|e| e.to_string())?;
    let (env, next) = finish_receipt(&h, &prepared, &sig, &now).map_err(|e| e.to_string())?;
    let after = next.persisted().map_err(|e| e.to_string())?;
    l.home = Some(next);
    Ok(json!({
        "state": l.dump()?,
        "envelope": b64(&env),
        "store": new_files(&before, &after),
    }))
}

// ---------------------------------------------------------------------------------------------
// Heads (§13.2, §13.3).

/// This home's newest head in what it holds: `(seq, digest, issued ms)`.
fn own_latest_head(objects: &Objects, home: &str) -> Option<(u64, String, i64)> {
    objects
        .heads
        .iter()
        .filter_map(|h| {
            let raw = RawEnvelope::parse(h, bounds::HEAD_BODY, false).ok()?;
            let by = raw.value.get("by")?.as_str()?;
            let a = raw.value.get("authority")?;
            let issued =
                colophon_core::v05::encoding::parse_date(raw.value.get("issued")?.as_str()?)?;
            if by != home {
                return None;
            }
            Some((a["seq"].as_u64()?, a["digest"].as_str()?.to_string(), issued))
        })
        .max_by_key(|(_, _, i)| *i)
}

/// Whether a head is due, and if so its body to sign, after the §13.3 guard.
fn head_request(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let Some(h) = l.home.take() else {
        return Ok(json!({"sign": null, "why": "not appointed", "state": req["state"]}));
    };
    let v = view(&h, now_ms)?;
    let st = &v.state;
    let seq = st.history().len() as u64;
    let digest = st.history().last().cloned().ok_or("empty history")?;
    let is_home = st
        .current_homes()
        .iter()
        .any(|m| m.request.member_id() == l.slot.home && m.expires_ms.is_none_or(|e| now_ms <= e));
    let half = (st.keyring().policy.head_max_age() as i64) * 500;
    let due = match v.persisted.objects().and_then(|o| own_latest_head(o, &l.slot.home)) {
        None => true,
        Some((s, d, issued)) => (s, &d) != (seq, &digest) || now_ms - issued >= half,
    };
    if !is_home || !due {
        l.home = Some(h);
        return Ok(json!({"sign": null, "why": if is_home { "fresh" } else { "not a current home" },
                         "state": l.dump()?}));
    }
    let issued = format_date(now_ms);
    let now = issued.clone();
    match h.guard_head(seq, &digest, &issued, &now) {
        Ok((next, _guard)) => {
            let account = st.account().clone();
            let body = canonical(&json!({
                "protocol": "colophon/head/5",
                "account": account.as_str(),
                "authority": {"seq": seq, "digest": digest},
                "issued": issued,
                "by": l.slot.home,
            }))
            .map_err(|e| e.to_string())?;
            l.home = Some(next);
            Ok(json!({
                "sign": {"body": b64(&body), "seq": seq, "digest": digest, "issued": issued},
                "state": l.dump()?,
            }))
        }
        // The guard says no (an older `issued`, a second digest at a seq): not an error, the
        // home signs nothing and says why.
        Err(e) => {
            l.home = Some(h);
            Ok(json!({"sign": null, "why": e.to_string(), "state": l.dump()?}))
        }
    }
}

fn op_finish_head(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let h = l.home.take().ok_or("no home state")?;
    let (seq, digest, issued) = (
        u64_of(req, "seq")?,
        str_of(req, "digest")?.to_string(),
        str_of(req, "issued")?.to_string(),
    );
    let now = format_date(now_ms);
    // The guard again: a retry of the same head is allowed, and the token is the only way to
    // prepare a head for signing.
    let (h, guard) = h
        .guard_head(seq, &digest, &issued, &now)
        .map_err(|e| e.to_string())?;
    let v = view(&h, now_ms)?;
    let st = &v.state;
    let account = st.account().clone();
    let prepared = prepare_head(
        &HeadSpec {
            account: &account,
            seq,
            digest: &digest,
            issued: &issued,
            by: &l.slot.home,
        },
        &guard,
    )
    .map_err(|e| e.to_string())?;
    let homes: Vec<(String, Vec<u8>)> = st
        .current_homes()
        .iter()
        .filter(|m| m.expires_ms.is_none_or(|e| now_ms <= e))
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    let sig = SignatureResult {
        signature: bytes_of(req, "signature")?,
        assertion: None,
    };
    let env = finish_head(
        &prepared,
        &sig,
        HeadContext {
            account: &account,
            history: st.history(),
            homes: &homes,
            now_ms,
        },
    )
    .map_err(|e| e.to_string())?;
    let a = admit(&h, &env, &now);
    if let Err(r) = &a.result {
        return Err(format!("the home refused its own head: {}", r.code()));
    }
    l.home = Some(a.state);
    Ok(json!({
        "state": l.dump()?,
        "envelope": b64(&env),
        "path": format!("heads/{}.json", l.slot.home),
    }))
}

// ---------------------------------------------------------------------------------------------
// The pending feed (§14).

fn pending_page(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let h = l.home.as_ref().ok_or("no home state")?;
    let page = h
        .pending_page(
            u64_of(req, "after")?,
            u64_of(req, "limit")? as usize,
            now_ms,
        )
        .map_err(|e| e.to_string())?;
    let objects: Vec<Value> = page
        .objects
        .iter()
        .map(|o| {
            json!({"seq": o.seq, "digest": o.digest, "kind": o.kind, "envelope": b64(&o.envelope)})
        })
        .collect();
    Ok(json!({"objects": objects, "more": page.more}))
}

fn pending_object(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let h = l.home.as_ref().ok_or("no home state")?;
    let d = h
        .pending_object(str_of(req, "digest")?, now_ms)
        .map_err(|e| e.to_string())?;
    Ok(match d {
        None => json!({"found": false}),
        Some(d) => json!({"found": true, "envelope": b64(&d.envelope),
                          "receipts": d.receipts.iter().map(|r| b64(r)).collect::<Vec<_>>()}),
    })
}

// ---------------------------------------------------------------------------------------------
// Recording entries (§8.7): the determined `activate`, `vetoed`, `final` (and, for a successor
// home, `successionVetoed`), built by the same code a host's account uses, then admitted.

fn record_due(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let Some(mut h) = l.home.take() else {
        return Ok(json!({"entries": [], "state": req["state"], "store": [], "sign": []}));
    };
    let persisted = h.persisted().map_err(|e| e.to_string())?;
    let objects = persisted.objects().cloned().unwrap_or_default();
    let before = h.persisted().map_err(|e| e.to_string())?;
    let mut note = Value::Null;
    let mut stored = Vec::new();
    let mut sign = Vec::new();
    let mut result = "ok".to_string();
    match Account::open(
        objects,
        Vec::new(),
        None,
        Identity::Member(l.slot.home.clone()),
        now_ms,
    ) {
        Err(e) => note = json!(e.to_string()),
        Ok(mut account) => match account.record_due() {
            Err(e) => note = json!(e.to_string()),
            Ok(done) => {
                'all: for f in done {
                    for (seq, bytes) in f.entries {
                        let a = admit(&h, &bytes, &now);
                        h = a.state;
                        sign.extend(signs(&a.receipts));
                        match a.result {
                            Ok(()) => {
                                stored.push(json!({"path": entry_path(seq), "bytes": b64(&bytes)}))
                            }
                            Err(r) => {
                                result = r.code();
                                break 'all;
                            }
                        }
                    }
                }
            }
        },
    }
    let after = h.persisted().map_err(|e| e.to_string())?;
    stored.extend(new_files(&before, &after));
    l.home = Some(h);
    Ok(json!({
        "state": l.dump()?,
        "store": stored,
        "sign": sign,
        "result": result,
        "note": note,
    }))
}

// ---------------------------------------------------------------------------------------------
// Records, live values, blob chunks.

fn check_record(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let path = str_of(req, "path")?;
    let bytes = bytes_of(req, "bytes")?;
    let refuse = |code: &str| Ok(json!({"allowed": false, "code": code}));
    let Some(kind) = paths::classify(path) else {
        return refuse("malformed");
    };
    match kind {
        Kind::Blob(name) => {
            if digest(&bytes) != name {
                return refuse("malformed");
            }
            Ok(json!({"allowed": true}))
        }
        Kind::Op { .. } | Kind::Live { .. } | Kind::History => {
            let h = l.home.as_ref().ok_or("no home state")?;
            let persisted = h.persisted().map_err(|e| e.to_string())?;
            let objects = persisted.objects().cloned().unwrap_or_default();
            let ra = RecordAuthority::from_objects(&objects, now_ms).map_err(|e| e.to_string())?;
            let Ok((header, env)) = OperationHeader::parse(&bytes) else {
                return refuse("malformed");
            };
            // A member of the verified history signed it, and the path says what the header says.
            let Some(m) = ra.member(&header.author) else {
                return refuse("notGranted");
            };
            if &header.account != ra.account() {
                return refuse("malformed");
            }
            let path_ok = match &kind {
                Kind::Live { author, namespace, slot } => {
                    header.live.as_ref().is_some_and(|s| &s.slot == slot)
                        && &header.author == author
                        && &header.namespace == namespace
                }
                Kind::History => {
                    header.live.is_some()
                        && path
                            == format!(
                                "history/{}/{}/{:012}-{}.json",
                                header.author, header.namespace, header.clock, header.id
                            )
                }
                _ => header.check_path(path).is_ok(),
            };
            if !path_ok {
                return refuse("malformed");
            }
            if OperationHeader::verify(&env, &m.request.signing).is_err() {
                return refuse("badSignature");
            }
            Ok(json!({"allowed": true}))
        }
        // History, heads, predecessors and pending objects arrive by their own endpoints.
        _ => refuse("malformed"),
    }
}

// ---------------------------------------------------------------------------------------------
// Calls (§12.3, §12.4) and who may read (§13.4).

/// The replay store of one request: the host looked up the row for this call's key.
struct OneRow {
    existing: Option<(i64, String)>,
    reserved: bool,
}
impl ReplayStore for OneRow {
    fn lookup(&self, _key: &ReplayKey, now_ms: i64) -> Option<ReplayState> {
        self.existing
            .as_ref()
            .filter(|(at, _)| retained(*at, now_ms))
            .map(|(_, d)| ReplayState::Completed {
                digest: d.clone(),
                result: "ok".into(),
                effect: None,
            })
    }
    fn reserve(&mut self, key: &ReplayKey, digest: &str, now_ms: i64) -> Reservation {
        if let Some(s) = self.lookup(key, now_ms) {
            return if s.digest() == digest {
                Reservation::Replay
            } else {
                Reservation::Conflict
            };
        }
        self.reserved = true;
        Reservation::Reserved
    }
    fn complete(
        &mut self,
        _: &ReplayKey,
        _: &str,
        _: Option<colophon_core::v05::replay::EffectRecord>,
    ) -> Result<(), colophon_core::v05::replay::ReplayError> {
        Ok(())
    }
    fn abandon(&mut self, _: &ReplayKey) -> Result<(), colophon_core::v05::replay::ReplayError> {
        Ok(())
    }
    fn recover(
        &mut self,
        _: &ReplayKey,
        _: Option<colophon_core::v05::replay::EffectRecord>,
    ) -> Result<ReplayState, colophon_core::v05::replay::ReplayError> {
        Err(colophon_core::v05::replay::ReplayError::Missing)
    }
}

/// The replay key of a call, text form, for the host's table (parse only: nothing is judged).
fn call_key(req: &Value) -> R<Value> {
    let bytes = bytes_of(req, "call")?;
    let Ok(call) = Call::parse(&bytes) else {
        return Ok(json!({"parsed": false}));
    };
    let k = call.replay_key();
    Ok(json!({
        "parsed": true,
        "key": key_text(&k),
        "digest": call.digest,
        "purpose": call.purpose,
    }))
}

/// Whether a request may read the history (`class` `history`), read records (`records_read`) or
/// write them (`records_write`), by this home's §13.4 and §14 rules. A bearer token is the
/// host's concern and is never passed here: it is storage access only.
fn authorize(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let class = str_of(req, "class")?;
    let h = l.home.as_ref().ok_or("no home state")?;
    let v = view(h, now_ms)?;
    if class == "history" && v.state.keyring().policy.history() == HistoryAccess::Public {
        return Ok(json!({"allowed": true, "via": "public"}));
    }
    let wanted: &[&str] = match class {
        "history" => &["colophon.history.read"],
        "records_read" => &["colophon.home.read", "colophon.history.read"],
        "records_write" => &["colophon.home.write"],
        other => return Err(format!("unknown class {other}")),
    };
    let Some(call_text) = req.get("call").and_then(Value::as_str) else {
        return Ok(json!({"allowed": false, "code": "none"}));
    };
    let call = B64.decode(call_text).map_err(|e| e.to_string())?;
    let base = str_of(req, "base")?.to_string();
    let verdict = verify_history(&Objects::default(), &v.persisted, now_ms);
    let objects = v.persisted.objects().cloned().unwrap_or_default();
    let view = AccountView::from_history_verifier(&verdict, &objects, now_ms)
        .map_err(|e| e.to_string())?;
    let existing = req.get("existing").filter(|e| !e.is_null()).map(|e| {
        (
            e["at"].as_i64().unwrap_or(0),
            e["digest"].as_str().unwrap_or_default().to_string(),
        )
    });
    let mut store = OneRow {
        existing,
        reserved: false,
    };
    let audiences = [base.clone()];
    let origins = std::collections::BTreeMap::new();
    let cfg = CallConfig {
        now_ms,
        audiences: &audiences,
        call_origins: &origins,
        controller_purposes: &[],
        home_endpoints: &audiences,
    };
    // Which purpose the call carries is the call's own business; the home allows the ones that
    // `class` names and nothing else (§13.4, §14).
    let parsed = Call::parse(&call).map_err(|e| e.to_string());
    if let Ok(c) = &parsed {
        if !wanted.contains(&c.purpose.as_str()) {
            return Ok(json!({"allowed": false, "code": "refused:outOfScope"}));
        }
    }
    match verify_call(&call, &view, &cfg, &mut store) {
        Ok(vc) => {
            let signer = match &vc.call.signer {
                CallSigner::Member(id) => json!({"member": id}),
                CallSigner::Controller(id) => json!({"controller": id}),
            };
            let k = &vc.replay_key;
            Ok(json!({
                "allowed": true, "via": "call", "signer": signer,
                "reserve": {
                    "key": key_text(k),
                    "at": now_ms, "digest": vc.call.digest,
                },
            }))
        }
        Err(f) => Ok(json!({"allowed": false, "code": f.code()})),
    }
}

// ---------------------------------------------------------------------------------------------
// Everything the home holds, for the host to serve and to reconcile its files with its state.

fn objects(req: &Value) -> R<Value> {
    let l = load(req)?;
    let mut files = Vec::new();
    let mut heads = Vec::new();
    if let Some(h) = &l.home {
        let p = h.persisted().map_err(|e| e.to_string())?;
        if let Some(o) = p.objects() {
            for e in &o.entries {
                let seq = entry_seq(e)?;
                files.push(json!({"path": entry_path(seq), "bytes": b64(e)}));
            }
            for (path, bytes) in pending_files(o) {
                files.push(json!({"path": path, "bytes": b64(&bytes)}));
            }
            for hd in &o.heads {
                if let Ok(raw) = RawEnvelope::parse(hd, bounds::HEAD_BODY, false) {
                    if let Some(by) = raw.value.get("by").and_then(Value::as_str) {
                        heads.push(json!({"path": format!("heads/{by}.json"), "bytes": b64(hd)}));
                    }
                }
            }
        }
    } else {
        for e in l.booting_entries()? {
            let seq = entry_seq(&e)?;
            files.push(json!({"path": entry_path(seq), "bytes": b64(&e)}));
        }
    }
    Ok(json!({"files": files, "heads": heads}))
}

/// The replay key as one text, the host's table key.
fn key_text(k: &ReplayKey) -> String {
    [
        k.account.as_str(),
        k.audience.as_str(),
        k.acting_key.as_str(),
        k.purpose.as_str(),
        k.request_id.as_str(),
    ]
    .join("\n")
}
