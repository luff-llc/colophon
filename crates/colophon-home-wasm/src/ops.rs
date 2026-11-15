//! The operations. Each is a function from a JSON request to a JSON response; the dispatcher
//! turns any error into `{"ok":false,"error":…}` and nothing here panics on input.
//!
//! **Storage follows state.** Every operation that changes the state returns `store`: the files
//! the host must hold afterwards that it may not hold yet (`{"path","bytes"}`; a `heads/` path
//! replaces the file there, every other path is written once). [`objects`] returns the whole set,
//! for the host to reconcile its files with its state at start-up. The host commits the state,
//! then stores, under one lock, so after any request everything the state holds is on disk, and
//! the head it signs is over entries already stored.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use colophon_core::v05::account::{Account, Identity};
use colophon_core::v05::calls::{
    home_purposes, home_record_writes, verify_home_request, AccountView, Call, CallConfig,
    CallSigner, HomeRequest, HomeWrite,
};
use colophon_core::v05::descriptor::HistoryAccess;
use colophon_core::v05::encoding::{bounds, canonical, digest, parse_date, strict_parse};
use colophon_core::v05::engine::paths::{self, Kind};
use colophon_core::v05::heads::HeadContext;
use colophon_core::v05::history::envelope::AuthEnvelope;
use colophon_core::v05::history::home::{
    admit, admit_first, admit_pending_batch, admit_with, FirstUpload, HomeState, ReceiptToSign, Refusal,
};
use colophon_core::v05::history::{verify_history, Objects, Persisted, State, Stop};
use colophon_core::v05::ids::{key_id, AccountId};
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
use std::collections::BTreeMap;

type R<T> = Result<T, String>;

/// The version of the persisted slot state: 2 binds the slot to one account.
const STATE_VERSION: u32 = 2;
/// The largest request body this module reads (the host bounds a body before it reads it).
const MAX_REQUEST: usize = 24 * 1024 * 1024;
/// Entries a first upload may hold before this home is appointed in them (a bound on what an
/// unappointed home keeps for its one account).
const MAX_FIRST_UPLOAD: usize = 512;
/// Replay rows one principal may always hold, however many principals share the table.
const MIN_SHARE: usize = 64;
/// Replay rows of a slot when the host names no capacity.
const DEFAULT_REPLAY_ROWS: usize = 65_536;

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
        "classify" => classify(&req),
        "access" => access(&req),
        "call_key" => call_key(&req),
        "replay_keep" => replay_keep(&req),
        "replay_recover" => replay_recover(&req),
        "post_authority" => post_authority(&req),
        "post_pending" => post_pending(&req),
        "admit_one" => admit_one(&req),
        "finish_receipt" => op_finish_receipt(&req),
        "head_request" => head_request(&req),
        "finish_head" => op_finish_head(&req),
        "authority_page" => authority_page(&req),
        "pending_page" => pending_page(&req),
        "pending_object" => pending_object(&req),
        "record_due" => record_due(&req),
        "check_record" => check_record(&req),
        "peer_answer" => peer_answer(&req),
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
// The persisted state: a version, the home's ID, the account the slot was provisioned for, the
// entries held before the home is appointed, and the core's own [`HomeState`] once it is.

#[derive(Serialize, Deserialize)]
struct Slot {
    v: u32,
    home: String,
    /// The one account this slot serves (§13.1 first upload: its genesis digest).
    account: String,
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
            account: self.slot.account.clone(),
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
/// What the home holds as verifier input (its checkpoint's objects, which are never stale).
fn held(h: &HomeState) -> R<Objects> {
    Ok(h.persisted()
        .map_err(|e| e.to_string())?
        .objects()
        .cloned()
        .unwrap_or_default())
}

/// A new slot, provisioned by the operator for one account before anything is uploaded.
fn init(req: &Value) -> R<Value> {
    let home = str_of(req, "home")?;
    if !colophon_core::v05::ids::is_key_id(home) {
        return Err("home is not a member ID".into());
    }
    let account = AccountId::parse(str_of(req, "account")?).map_err(|e| e.to_string())?;
    let l = Loaded {
        slot: Slot {
            v: STATE_VERSION,
            home: home.to_string(),
            account: account.as_str().to_string(),
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
        "replayRows": DEFAULT_REPLAY_ROWS,
        "authorityPage": 64, "pendingPage": 64, "pendingBatch": 16,
        "authorityBody": bounds::AUTHORITY_BODY,
        "transitionEnvelope": bounds::TRANSITION_ENVELOPE,
    })
}

// ---------------------------------------------------------------------------------------------
// The verified view of a home.

struct View {
    persisted: Persisted,
    /// The verified state; at an unresolved fork, the verified prefix before it.
    state: State,
    /// The seq of the unresolved fork the history stops at (§8.6 rule 3), if any.
    fork: Option<u64>,
}
fn view(h: &HomeState, now_ms: i64) -> R<View> {
    let persisted = h.persisted().map_err(|e| e.to_string())?;
    let v = verify_history(&Objects::default(), &persisted, now_ms);
    let fork = match &v.stop {
        None => None,
        Some(Stop::Fork { seq }) => Some(*seq),
        Some(_) => return Err(format!("history: {}", v.code())),
    };
    let state = v.state.ok_or("no verified history")?;
    Ok(View { persisted, state, fork })
}

fn status(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let Some(h) = &l.home else {
        return Ok(json!({"appointed": false, "held": l.slot.booting.len(),
                         "home": l.slot.home, "account": l.slot.account}));
    };
    let v = match view(h, now_ms) {
        Ok(v) => v,
        Err(e) => {
            return Ok(json!({"appointed": true, "home": l.slot.home,
                             "account": l.slot.account, "error": e}))
        }
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
        "fork": v.fork,
    }))
}

// ---------------------------------------------------------------------------------------------
// Paths and who may do what (§13.4, §14). The host asks; it holds no rule.

/// The kind of a file in a home slot, by the engine's path grammar, or `null`: the host's
/// storage scan and log replay use it, so the slot's grammar is the module's.
fn classify(req: &Value) -> R<Value> {
    let kind = paths::classify(str_of(req, "path")?).and_then(|k| match k {
        Kind::Authority(_) => Some("authority"),
        Kind::Predecessor(_) => Some("predecessor"),
        Kind::Pending => Some("pending"),
        Kind::Receipt => Some("receipt"),
        Kind::Head => Some("head"),
        Kind::Op { .. } => Some("op"),
        Kind::Live { .. } => Some("live"),
        Kind::History => Some("history"),
        Kind::Blob(_) => Some("blob"),
        Kind::Request => None,
    });
    Ok(json!({"kind": kind}))
}

/// What a request reads or writes.
enum Class {
    /// `GET {base}`: the home's identity, always.
    Identity,
    /// Admitted by the module itself, with no other authorization (§14): `POST /authority`,
    /// `POST /pending`, and a head forwarded by `PUT records/heads/<id>.json`.
    Admit,
    /// The head: always public (§13.4).
    Head,
    /// History, transitions, vetoes and receipts (§13.4).
    History,
    /// Records, live values, blob chunks and the change feed.
    RecordsRead,
    /// Writes, with what they write.
    Write(Vec<HomeWrite>),
}

fn answer(status: u16) -> R<Value> {
    Ok(json!({"allowed": false, "status": status}))
}
fn not_allowed(allow: &str) -> R<Value> {
    Ok(json!({"allowed": false, "status": 405, "allow": allow}))
}

/// The whole access decision for one request (§13.4, §14, §12.3, §12.4):
/// `{"allowed":true,"via":…,"kind":…,"reserve":…}` or `{"allowed":false,"status":…}` with a
/// `result` for 403 and 429. A home that is not appointed serves nothing it holds: everything
/// but its identity and the admission requests answers 404. Once appointed, the head is public,
/// the history follows `policy.history`, and records always need a call: a member's own key, or
/// what §13.4 and §14 allow. The replay table's share is per principal (a member or controller,
/// with every link key under it), so one caller over its share is refused alone.
fn access(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let method = str_of(req, "method")?;
    let section = req.get("section").and_then(Value::as_str).unwrap_or("");
    let rest = req.get("rest").and_then(Value::as_str);
    let read = matches!(method, "GET" | "HEAD");
    let class = match (section, rest) {
        ("", None) => match method {
            "GET" => Class::Identity,
            _ => return not_allowed("GET"),
        },
        ("head", None) => match method {
            "GET" => Class::Head,
            _ => return not_allowed("GET"),
        },
        ("authority", None) | ("pending", None) => match method {
            "GET" => Class::History,
            "POST" => Class::Admit,
            _ => return not_allowed("GET, POST"),
        },
        ("pending", Some(d)) => match method {
            "GET" if d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()) => Class::History,
            "GET" => return answer(404),
            _ => return not_allowed("GET"),
        },
        ("changes", None) => match method {
            "GET" => Class::RecordsRead,
            _ => return not_allowed("GET"),
        },
        ("predecessor", _) => return answer(404),
        ("records", Some(p)) => {
            let Some(kind) = paths::classify(p).filter(|k| !matches!(k, Kind::Request)) else {
                return Ok(json!({"allowed": false, "status": 400, "error": "Invalid record path"}));
            };
            match (read, method, kind) {
                (true, _, Kind::Head) => Class::Head,
                (true, _, Kind::Authority(_) | Kind::Pending | Kind::Receipt) => Class::History,
                // This home serves no predecessor (§15.1; not in this round).
                (true, _, Kind::Predecessor(_)) => return answer(404),
                (true, _, _) => Class::RecordsRead,
                (false, "PUT", Kind::Head) => Class::Admit,
                // What a write writes is the core's rule, the one a signer builds its call by.
                (
                    false,
                    "PUT",
                    Kind::Op { .. } | Kind::History | Kind::Live { .. } | Kind::Blob(_),
                ) => match home_record_writes(p) {
                    Some(writes) => Class::Write(writes),
                    None => return answer(400),
                },
                // History objects arrive by POST /authority and POST /pending.
                (false, _, _) => return not_allowed("GET"),
            }
        }
        _ => return answer(404),
    };
    if matches!(class, Class::Identity | Class::Admit) {
        return Ok(json!({"allowed": true, "via": "open"}));
    }
    let Some(h) = l.home.as_ref() else {
        return answer(404);
    };
    if matches!(class, Class::Head) {
        return Ok(json!({"allowed": true, "via": "public"}));
    }
    let v = view(h, now_ms)?;
    let public = v.state.keyring().policy.history() == HistoryAccess::Public;
    if matches!(class, Class::History) && public {
        return Ok(json!({"allowed": true, "via": "public"}));
    }
    let Some(call_text) = req.get("call").and_then(Value::as_str) else {
        return answer(401);
    };
    let call = B64.decode(call_text).map_err(|e| e.to_string())?;
    let refuse = |code: String| Ok(json!({"allowed": false, "status": 403, "result": code}));
    // Before any history work: a call that does not parse, or whose purpose does not fit the
    // method and path (the core's rule, checked again in `verify_home_request`: only a path that
    // serves the history takes `colophon.history.read`), is refused at once.
    let path = str_of(req, "path")?;
    match Call::parse(&call) {
        Ok(c) if home_purposes(method, path).contains(&c.purpose.as_str()) => {}
        Ok(_) => return refuse("refused:outOfScope".into()),
        Err(f) => return refuse(f.code()),
    }
    let base = str_of(req, "base")?.to_string();
    let objects = held(h)?;
    let verdict = verify_history(&objects, &v.persisted, now_ms);
    let account_view = AccountView::from_history_verifier(&verdict, &objects, now_ms)
        .map_err(|e| e.to_string())?;
    let existing = req.get("existing").filter(|e| !e.is_null()).map(|e| {
        (
            e["at"].as_i64().unwrap_or(0),
            e["digest"].as_str().unwrap_or_default().to_string(),
        )
    });
    let mut store = OneRow { existing };
    let audiences = [base.clone()];
    let origins = BTreeMap::new();
    let cfg = CallConfig {
        now_ms,
        audiences: &audiences,
        call_origins: &origins,
        controller_purposes: &[],
        home_endpoints: &audiences,
    };
    // The purpose fits the method, the call passes §12.3 (a write as §14 allows it, by what it
    // writes), and it is bound to the request it arrived on: `args` is exactly the method, the
    // path and query relative to the home's base as sent, and the SHA-256 of the body. One rule
    // in the core, the one a signer builds its call by; nothing is reserved for a refused call.
    let writes: &[HomeWrite] = match &class {
        Class::Write(writes) => writes,
        _ => &[],
    };
    let request = HomeRequest {
        method,
        path,
        body_sha256: str_of(req, "bodySha256")?,
        writes,
    };
    let vc = match verify_home_request(&call, &account_view, &cfg, &mut store, &request) {
        Ok(vc) => vc,
        Err(f) => return refuse(f.code()),
    };
    // The replay table (§12.4): this principal's live rows, against its share of the table.
    let signer = signer_text(&vc.call.signer);
    let mut live = 0usize;
    let mut oldest: Option<i64> = None;
    let mut drop = Vec::new();
    for row in req
        .get("signerRows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let at = row["at"].as_i64().unwrap_or(i64::MIN);
        if retained(at, now_ms) {
            live += 1;
            oldest = Some(oldest.map_or(at, |o| o.min(at)));
        } else {
            drop.push(row["key"].clone());
        }
    }
    let capacity = req
        .get("replayRows")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_REPLAY_ROWS, |n| n as usize);
    let principals = v.state.keyring().controllers.len()
        + v.state
            .members()
            .iter()
            .filter(|m| m.revoked_seq.is_none())
            .count();
    let share = (capacity / principals.max(1)).max(MIN_SHARE);
    if live >= share {
        let wait_ms = oldest.map_or(60_000, |o| (o + RETENTION_MS + 1 - now_ms).max(1_000));
        return Ok(json!({"allowed": false, "status": 429, "result": "refused:window",
                         "retryAfter": (wait_ms + 999) / 1000, "drop": drop}));
    }
    Ok(json!({
        "allowed": true, "via": "call", "signer": signer, "drop": drop,
        "reserve": {"key": key_text(&vc.replay_key), "signer": signer, "at": now_ms,
                    "digest": vc.call.digest},
    }))
}

fn signer_text(s: &CallSigner) -> String {
    match s {
        CallSigner::Member(id) => format!("member:{id}"),
        CallSigner::Controller(id) => format!("controller:{id}"),
    }
}

/// The replay store of one request: the host looked up the row for this call's key.
struct OneRow {
    existing: Option<(i64, String)>,
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

/// The replay key of a call, text form, and the principal it names, for the host's table
/// (parse only: nothing is judged; [`access`] verifies).
fn call_key(req: &Value) -> R<Value> {
    let bytes = bytes_of(req, "call")?;
    let Ok(call) = Call::parse(&bytes) else {
        return Ok(json!({"parsed": false}));
    };
    let k = call.replay_key();
    Ok(json!({
        "parsed": true,
        "key": key_text(&k),
        "signer": signer_text(&call.signer),
        "digest": call.digest,
        "purpose": call.purpose,
    }))
}

/// Which replay rows are still kept (§12.4: while `now − reservedAt ≤ 7,260 s`), for the host's
/// compaction: `rows` are `{"key","at"}`; the answer lists the keys to keep.
fn replay_keep(req: &Value) -> R<Value> {
    let now_ms = i64_of(req, "now")?;
    let keep: Vec<Value> = req
        .get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r["at"].as_i64().is_some_and(|at| retained(at, now_ms)))
        .map(|r| r["key"].clone())
        .collect();
    Ok(json!({"keep": keep}))
}

/// §12.4 crash recovery: a reservation left pending is resolved from its effect's record, never
/// by running the effect again: `completed` when the effect is there (`present`), otherwise
/// `abandoned`. The reservation itself stays, so the call is refused as a replay either way.
fn replay_recover(req: &Value) -> R<Value> {
    let states: Vec<Value> = req
        .get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|r| {
            let state = if r["present"].as_bool() == Some(true) {
                "completed"
            } else {
                "abandoned"
            };
            json!({"key": r["key"], "state": state})
        })
        .collect();
    Ok(json!({"states": states}))
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

// ---------------------------------------------------------------------------------------------
// The files a state occupies.

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

/// The head this home serves for each home it holds heads of: the newest `issued` (§14 `GET
/// {base}/head` is "the latest head"; a peer's head is served the same way).
fn served_heads(objects: &Objects) -> BTreeMap<String, Vec<u8>> {
    let mut best: BTreeMap<String, (i64, Vec<u8>)> = BTreeMap::new();
    for h in &objects.heads {
        let Ok(raw) = RawEnvelope::parse(h, bounds::HEAD_BODY, false) else {
            continue;
        };
        let (Some(by), Some(issued)) = (
            raw.value.get("by").and_then(Value::as_str),
            raw.value
                .get("issued")
                .and_then(Value::as_str)
                .and_then(parse_date),
        ) else {
            continue;
        };
        let path = format!("heads/{by}.json");
        if best
            .get(&path)
            .is_none_or(|(i, b)| (issued, h) > (*i, b))
        {
            best.insert(path, (issued, h.clone()));
        }
    }
    best.into_iter().map(|(p, (_, b))| (p, b)).collect()
}

/// Every file a held object set occupies: entries, pending objects and the served heads.
fn files_of(objects: &Objects, now_ms: i64) -> R<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    // `authority/<seq>.json` holds the entry the home's branch has at that seq. When the home
    // holds more than one candidate at a seq (§8.6), the verdict says which one stands; at an
    // unresolved fork the candidates from the fork on have no file (they are served from the
    // state, `authority_page`).
    let mut by_seq: BTreeMap<u64, Vec<(String, &Vec<u8>)>> = BTreeMap::new();
    for e in &objects.entries {
        let d = AuthEnvelope::parse(e, bounds::AUTHORITY_BODY, bounds::AUTHORITY_BODY * 2, false)
            .map_err(|e| e.to_string())?
            .digest;
        let at = by_seq.entry(entry_seq(e)?).or_default();
        if !at.iter().any(|(x, _)| *x == d) {
            at.push((d, e));
        }
    }
    let branch: Option<Vec<String>> = by_seq
        .values()
        .any(|c| c.len() > 1)
        .then(|| verify_history(objects, &Persisted::default(), now_ms).branch);
    for (seq, candidates) in by_seq {
        let chosen = match &branch {
            None => candidates.first().map(|(_, b)| *b),
            Some(br) => {
                let want = usize::try_from(seq - 1).ok().and_then(|i| br.get(i));
                candidates.iter().find(|(d, _)| Some(d) == want).map(|(_, b)| *b)
            }
        };
        if let Some(b) = chosen {
            out.insert(entry_path(seq), b.clone());
        }
    }
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
        // The first stored envelope of an object stays (§14).
        out.entry(path).or_insert_with(|| p.clone());
    }
    out.extend(served_heads(objects));
    Ok(out)
}
/// The files as the host stores them. `replace`: the path holds what the state says now and its
/// bytes may change (a head; an entry when §8.6 changes which candidate stands at a seq); every
/// other path is written once.
fn file_list(files: BTreeMap<String, Vec<u8>>) -> Vec<Value> {
    files
        .into_iter()
        .map(|(p, b)| {
            let replace = p.starts_with("heads/") || p.starts_with("authority/");
            json!({"path": p, "bytes": b64(&b), "replace": replace})
        })
        .collect()
}
/// What `after` holds that `before` did not (a head path whose bytes changed included).
fn new_files(before: &Objects, after: &Objects, now_ms: i64) -> R<Vec<Value>> {
    let had = files_of(before, now_ms)?;
    Ok(file_list(
        files_of(after, now_ms)?
            .into_iter()
            .filter(|(p, b)| had.get(p) != Some(b))
            .collect(),
    ))
}
fn files_before(l: &Loaded) -> R<Objects> {
    match &l.home {
        Some(h) => held(h),
        None => Ok(Objects {
            entries: l.booting_entries()?,
            ..Default::default()
        }),
    }
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
fn protocol_of(bytes: &[u8]) -> Option<String> {
    let env = RawEnvelope::parse(bytes, bounds::AUTHORITY_BODY, false).ok()?;
    env.value
        .get("protocol")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn post_authority(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let malformed = |why: &str| {
        Ok(json!({"outcome": "refused", "result": "malformed", "why": why,
                  "state": req.get("state").cloned().unwrap_or(Value::Null),
                  "store": [], "sign": [], "accepted": []}))
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
    // `receipts` holds receipt envelopes only; anything else there is malformed, and nothing of
    // the request is admitted.
    let mut receipt_bytes = Vec::new();
    for r in receipts.into_iter().flatten() {
        match canonical(r) {
            Ok(b) if protocol_of(&b).as_deref() == Some("colophon/receipt/5") => {
                receipt_bytes.push(b)
            }
            _ => return malformed("receipts holds receipt envelopes only"),
        }
    }
    let before = files_before(&l)?;
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
                let later: Vec<Vec<u8>> =
                    entries[i + 1..].iter().filter_map(|e| canonical(e).ok()).collect();
                let a = admit_with(&h, &b, &later, &now);
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
                    match admit_first(&l.slot.home, &l.slot.account, &held, &b, &now) {
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
            Ok(()) => accepted.push(seq),
            Err(r) => {
                outcome = refusal(&r);
                break;
            }
        }
    }
    // Receipts that came with the entries are admitted as `POST /pending` admits them, and
    // stored like any other object.
    if outcome["outcome"] == "ok" {
        for b in &receipt_bytes {
            if let Some(h) = l.home.take() {
                let a = admit(&h, b, &now);
                sign.extend(signs(&a.receipts));
                l.home = Some(a.state);
            }
        }
    }
    let after = files_before(&l)?;
    let mut out = outcome;
    out["state"] = json!(l.dump()?);
    out["store"] = json!(new_files(&before, &after, now_ms)?);
    out["sign"] = json!(sign);
    out["accepted"] = json!(accepted);
    out["appointed"] = json!(l.home.is_some());
    Ok(out)
}

fn post_pending(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let unchanged = req.get("state").cloned().unwrap_or(Value::Null);
    // §14 422: one result per refused object, in request order (the shape the engine's own test
    // home answers; the engine reads it as the refusal's text).
    let refused_all = |code: &str| {
        Ok(json!({"outcome": "refused", "results": [code], "state": unchanged,
                  "store": [], "sign": []}))
    };
    let Some(h) = &l.home else {
        return refused_all("unavailable");
    };
    let body = bytes_of(req, "body")?;
    let parsed = strict_parse(&body)
        .ok()
        .filter(|v| v.as_object().is_some_and(|o| o.len() == 1))
        .and_then(|v| v.get("objects").and_then(Value::as_array).cloned());
    let Some(objects) = parsed.filter(|o| (1..=16).contains(&o.len())) else {
        return refused_all("malformed");
    };
    let mut objs = Vec::new();
    for o in &objects {
        match canonical(o) {
            Ok(b) => objs.push(b),
            Err(_) => return refused_all("malformed"),
        }
    }
    let before = held(h)?;
    let (next, results, receipts) =
        admit_pending_batch(h, &objs, &now).map_err(|e| e.to_string())?;
    let after = held(&next)?;
    let refused: Vec<Value> = results
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| json!(e.code())))
        .collect();
    let l2 = Loaded {
        slot: Slot {
            v: STATE_VERSION,
            home: l.slot.home.clone(),
            account: l.slot.account.clone(),
            booting: vec![],
            home_state: None,
        },
        home: Some(next),
    };
    Ok(json!({
        "outcome": if refused.is_empty() { "ok" } else { "refused" },
        "results": refused,
        "state": l2.dump()?,
        "store": new_files(&before, &after, now_ms)?,
        "sign": signs(&receipts),
    }))
}

/// One forwarded head (`PUT {base}/records/heads/<id>.json`): admitted by the core; the path
/// must name the head's own home, which must be another home than this one.
fn admit_one(req: &Value) -> R<Value> {
    let mut l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let now = format_date(now_ms);
    let unchanged = req.get("state").cloned().unwrap_or(Value::Null);
    let Some(h) = l.home.take() else {
        return Ok(json!({"outcome": "refused", "result": "unavailable",
                         "state": unchanged, "store": []}));
    };
    let bytes = bytes_of(req, "bytes")?;
    let canon = match strict_parse(&bytes).and_then(|v| canonical(&v)) {
        Ok(c) => c,
        Err(_) => {
            return Ok(json!({"outcome": "refused", "result": "malformed",
                             "state": unchanged, "store": []}))
        }
    };
    if let Some(path) = req.get("path").and_then(Value::as_str) {
        let by = RawEnvelope::parse(&canon, bounds::HEAD_BODY, false)
            .ok()
            .and_then(|r| {
                (r.value.get("protocol").and_then(Value::as_str) == Some("colophon/head/5"))
                    .then(|| r.value.get("by").and_then(Value::as_str).map(str::to_string))
                    .flatten()
            });
        let ok = by
            .as_deref()
            .is_some_and(|b| path == format!("heads/{b}.json") && b != l.slot.home);
        if !ok {
            return Ok(json!({"outcome": "refused", "result": "malformed",
                             "why": "a head is stored under its own home, another than this one",
                             "state": unchanged, "store": []}));
        }
    }
    let before = held(&h)?;
    let a = admit(&h, &canon, &now);
    let after = held(&a.state)?;
    let mut out = match &a.result {
        Ok(()) => json!({"outcome": "ok"}),
        Err(r) => refusal(r),
    };
    out["store"] = json!(new_files(&before, &after, now_ms)?);
    out["sign"] = json!(signs(&a.receipts));
    l.home = Some(a.state);
    out["state"] = json!(l.dump()?);
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
    let before = held(&h)?;
    let (env, next) = finish_receipt(&h, &prepared, &sig, &now).map_err(|e| e.to_string())?;
    let after = held(&next)?;
    l.home = Some(next);
    Ok(json!({
        "state": l.dump()?,
        "envelope": b64(&env),
        "store": new_files(&before, &after, now_ms)?,
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
            let issued = parse_date(raw.value.get("issued")?.as_str()?)?;
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
    if v.fork.is_some() {
        // §8.6 rule 3: until a `resolve` activates, the home's verified history is the prefix
        // before the fork; it signs no head (a head over the prefix would be behind its own).
        return Ok(json!({"sign": null, "why": "the history stops at an unresolved fork", "state": req["state"]}));
    }
    let st = &v.state;
    let seq = st.history().len() as u64;
    let digest = st.history().last().cloned().ok_or("empty history")?;
    let is_home = st
        .current_homes()
        .iter()
        .any(|m| m.request.member_id() == l.slot.home && m.expires_ms.is_none_or(|e| now_ms <= e));
    let half = (st.keyring().policy.head_max_age() as i64) * 500;
    let due = match v
        .persisted
        .objects()
        .and_then(|o| own_latest_head(o, &l.slot.home))
    {
        None => true,
        Some((s, d, issued)) => (s, &d) != (seq, &digest) || now_ms - issued >= half,
    };
    if !is_home || !due {
        let why = if is_home { "fresh" } else { "not a current home" };
        return Ok(json!({"sign": null, "why": why, "state": req["state"]}));
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
        Err(e) => Ok(json!({"sign": null, "why": e.to_string(), "state": req["state"]})),
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
    let before = held(&h)?;
    let a = admit(&h, &env, &now);
    if let Err(r) = &a.result {
        return Err(format!("the home refused its own head: {}", r.code()));
    }
    let after = held(&a.state)?;
    l.home = Some(a.state);
    Ok(json!({
        "state": l.dump()?,
        "envelope": b64(&env),
        "store": new_files(&before, &after, now_ms)?,
    }))
}

// ---------------------------------------------------------------------------------------------
// Reads (§14): from the state itself, so a read never sees a state its files do not match.

fn authority_page(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let h = l.home.as_ref().ok_or("no home state")?;
    let after = u64_of(req, "after")?;
    let limit = u64_of(req, "limit")?.clamp(1, 64);
    let v = view(h, now_ms)?;
    let by_digest: BTreeMap<String, &Vec<u8>> = v
        .persisted
        .objects()
        .map(|o| {
            o.entries
                .iter()
                .filter_map(|e| {
                    AuthEnvelope::parse(e, bounds::AUTHORITY_BODY, bounds::AUTHORITY_BODY * 2, false)
                        .ok()
                        .map(|env| (env.digest, e))
                })
                .collect()
        })
        .unwrap_or_default();
    let history = v.state.history();
    let mut entries = Vec::new();
    for d in history.iter().skip(after.min(history.len() as u64) as usize) {
        if entries.len() as u64 >= limit {
            break;
        }
        let bytes = by_digest.get(d).ok_or("an entry on the branch is not held")?;
        entries.push(b64(bytes));
    }
    let mut more = after + (entries.len() as u64) < history.len() as u64;
    // At an unresolved fork the home serves the fork (§8.6: every verifier holding the same
    // objects reaches the same verdict): after the verified prefix, every candidate it holds
    // from the fork's seq on, in seq then digest order, never splitting one seq across pages.
    if let Some(fork) = v.fork {
        let mut rest: Vec<(u64, String, &Vec<u8>)> = by_digest
            .iter()
            .filter_map(|(d, b)| entry_seq(b).ok().map(|s| (s, d.clone(), *b)))
            .filter(|(s, _, _)| *s >= fork && *s > after)
            .collect();
        rest.sort();
        if !more && !rest.is_empty() {
            let mut i = 0;
            while i < rest.len() {
                let seq = rest[i].0;
                let n = rest[i..].iter().take_while(|(s, _, _)| *s == seq).count();
                if !entries.is_empty() && entries.len() + n > limit as usize {
                    more = true;
                    break;
                }
                entries.extend(rest[i..i + n].iter().map(|(_, _, b)| b64(b)));
                i += n;
            }
        }
    }
    Ok(json!({"entries": entries, "more": more, "fork": v.fork}))
}

fn pending_page(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = i64_of(req, "now")?;
    let h = l.home.as_ref().ok_or("no home state")?;
    let page = h
        .pending_page(
            u64_of(req, "after")?,
            u64_of(req, "limit")?.clamp(1, 64) as usize,
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
// Forwarding (§13.1): what a peer's answer to one forwarded object means.

/// Whether a peer's answer to `POST {peer}/pending` with one object delivered it: a 200, or a
/// 422 whose result is a permanent refusal with a stated reason (a §8.5 failure of the object
/// itself, or `refused:late`). `unavailable`, `held`, `refused:early`, the admission caps
/// (which free up as objects are recorded), any other status and any result this home does not
/// know are transient: the object is offered again. Receipts in a 200 are returned for the
/// host to admit.
fn peer_answer(req: &Value) -> R<Value> {
    let status = u64_of(req, "status")?;
    let body = req
        .get("body")
        .and_then(Value::as_str)
        .map(|b| B64.decode(b).unwrap_or_default())
        .unwrap_or_default();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if status == 200 {
        let receipts: Vec<Value> = v["receipts"].as_array().cloned().unwrap_or_default();
        return Ok(json!({"delivered": true, "receipts": receipts}));
    }
    if status != 422 {
        return Ok(json!({"delivered": false, "why": format!("status {status}")}));
    }
    let codes: Vec<String> = match &v {
        Value::Array(a) => a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect(),
        Value::Object(o) => o
            .get("result")
            .and_then(Value::as_str)
            .map(|c| vec![c.to_string()])
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let permanent = |c: &str| {
        matches!(
            c,
            "malformed"
                | "badSignature"
                | "newerFormat"
                | "refused:late"
                | "refused:fork"
                | "refused:revoked"
                | "refused:expired"
                | "refused:outOfScope"
                | "refused:notGranted"
                | "refused:conflict"
        )
    };
    let delivered = !codes.is_empty() && codes.iter().all(|c| permanent(c));
    Ok(json!({"delivered": delivered, "why": codes.join(",")}))
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
    let objects = held(&h)?;
    let before = objects.clone();
    let mut note = Value::Null;
    let mut sign = Vec::new();
    let mut result = "ok".to_string();
    let mut recorded = 0usize;
    match Account::open(
        objects.clone(),
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
                    for (_, bytes) in f.entries {
                        let a = admit(&h, &bytes, &now);
                        h = a.state;
                        sign.extend(signs(&a.receipts));
                        match a.result {
                            Ok(()) => recorded += 1,
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
    if recorded == 0 && note.is_null() {
        note = waiting(&h, &objects, now_ms);
    }
    let after = held(&h)?;
    l.home = Some(h);
    Ok(json!({
        "state": l.dump()?,
        "store": new_files(&before, &after, now_ms)?,
        "sign": sign,
        "result": result,
        "note": note,
    }))
}

/// Why nothing was recorded: what each held transition, veto and activation is waiting for.
fn waiting(h: &HomeState, objects: &Objects, now_ms: i64) -> Value {
    use colophon_core::v05::write::authority::{prepare_activate, prepare_final, prepare_vetoed};
    let mut why: Vec<String> = objects
        .pending
        .iter()
        .filter_map(|p| {
            AuthEnvelope::parse(p, bounds::TRANSITION_ENVELOPE, bounds::TRANSITION_ENVELOPE, false)
                .ok()
        })
        .filter_map(|e| match e.value.get("protocol").and_then(Value::as_str) {
            Some("colophon/transition/5") => prepare_activate(objects, now_ms, &e.digest)
                .err()
                .map(|x| format!("activate {}: {x}", &e.digest[..8])),
            Some("colophon/veto/5") => {
                let t = e
                    .value
                    .get("transition")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                prepare_vetoed(objects, now_ms, &t, &e.digest)
                    .err()
                    .map(|x| format!("vetoed {}: {x}", &e.digest[..8]))
            }
            _ => None,
        })
        .collect();
    if let Ok(v) = view(h, now_ms) {
        for a in v.state.activations().iter().filter(|a| !a.final_) {
            if let Err(e) = prepare_final(objects, now_ms, a.seq) {
                why.push(format!("final {}: {e}", a.seq));
            }
        }
    }
    if why.is_empty() {
        Value::Null
    } else {
        json!(format!("waiting: {}", why.join("; ")))
    }
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
            let objects = held(h)?;
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
                Kind::Live {
                    author,
                    namespace,
                    slot,
                } => {
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
// Everything the home holds, for the host to serve and to reconcile its files with its state.

fn objects(req: &Value) -> R<Value> {
    let l = load(req)?;
    let now_ms = req.get("now").and_then(Value::as_i64).unwrap_or(i64::MAX / 2);
    Ok(json!({"files": file_list(files_of(&files_before(&l)?, now_ms)?)}))
}
