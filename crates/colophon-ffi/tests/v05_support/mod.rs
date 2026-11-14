//! The host's side of the journeys: key custody (`host.rs`, shared with the wasm crate's test),
//! a record source implementing the callback, and a simulated home.
#![allow(dead_code, clippy::unwrap_used, clippy::too_many_arguments)]
mod host;
pub use host::*;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::home::{
    admit as home_admit, admit_pending_batch, HomeState, ServingInterval,
};
use colophon_core::v05::history::Objects;
use colophon_core::v05::write::calls::{finish_receipt, prepare_receipt};
use colophon_core::v05::write::{format_date, SignatureResult};
use colophon_ffi::v05::api::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The host's record store, implementing the source callback the way an app would.
#[derive(Clone, Default)]
pub struct MemSource {
    pub files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    pub reads: Arc<Mutex<u64>>,
    pub garbage: Arc<Mutex<bool>>,
}
impl MemSource {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().unwrap().insert(path.into(), bytes);
    }
    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).cloned()
    }
    pub fn listing(&self) -> String {
        s(&json!(self.files.lock().unwrap().keys().collect::<Vec<_>>()))
    }
    pub fn store(&self, stores_json: &Value) {
        for it in stores_json.as_array().unwrap() {
            self.put(it["path"].as_str().unwrap(), unb64(it["bytes"].as_str().unwrap()));
        }
    }
    pub fn copy_of(&self) -> MemSource {
        let m = MemSource::new();
        *m.files.lock().unwrap() = self.files.lock().unwrap().clone();
        m
    }
}
impl HostSource for MemSource {
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
        *self.reads.lock().unwrap() += 1;
        if *self.garbage.lock().unwrap() {
            return Ok(vec![0xff; 17]);
        }
        self.get(&path)
            .ok_or_else(|| AccountError::host(format!("missing {path}")))
    }
    fn version(&self, _path: String) -> Result<String, AccountError> {
        Ok(String::new())
    }
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError> {
        Ok(self.get(&path).unwrap_or_default())
    }
}

// --- A simulated home, driven by the requests the engine emits --------------------------------

pub fn entry_seq(bytes: &[u8]) -> u64 {
    let v: Value = serde_json::from_slice(bytes).unwrap();
    let body = unb64(v["body"].as_str().unwrap());
    let b: Value = serde_json::from_slice(&body).unwrap();
    b["seq"].as_u64().unwrap()
}
fn resp(status: u16, body: Value) -> (u16, Vec<u8>) {
    (status, serde_json::to_vec(&body).unwrap())
}
fn q_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

pub struct SimHome {
    pub id: String,
    pub base: String,
    pub state: HomeState,
    pub entries: BTreeMap<u64, Vec<u8>>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub log: Vec<String>,
    pub account: String,
}
impl SimHome {
    pub fn new(account: &str, home: &str, base: &str, objects: &Objects, now_ms: i64) -> Self {
        let state = HomeState::new(
            home.to_string(),
            objects,
            vec![ServingInterval {
                from_ms: 0,
                through_ms: None,
            }],
            now_ms,
        )
        .unwrap();
        let mut entries = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut log = Vec::new();
        for e in &objects.entries {
            let seq = entry_seq(e);
            entries.insert(seq, e.clone());
            let p = format!("authority/{seq:08}.json");
            files.insert(p.clone(), e.clone());
            log.push(p);
        }
        Self {
            id: home.to_string(),
            base: base.trim_end_matches('/').to_string(),
            state,
            entries,
            files,
            log,
            account: account.to_string(),
        }
    }
    fn head_env(&self, host: &Host, now_ms: i64) -> Option<Vec<u8>> {
        let seq = self.entries.keys().max().copied()?;
        let e = &self.entries[&seq];
        let v: Value = serde_json::from_slice(e).unwrap();
        let body = unb64(v["body"].as_str().unwrap());
        let body = canonical(&json!({
            "protocol": "colophon/head/5", "account": self.account,
            "authority": {"seq": seq, "digest": digest(&body)}, "by": self.id,
            "issued": format_date(now_ms),
        }))
        .unwrap();
        Some(
            canonical(&json!({"body": b64(&body),
                "signature": b64(&host.keys[&self.id].sign(&body))}))
            .unwrap(),
        )
    }
    fn sign_receipts(
        &mut self,
        host: &Host,
        reqs: Vec<colophon_core::v05::history::home::ReceiptToSign>,
        now_ms: i64,
    ) -> Vec<Value> {
        let now = format_date(now_ms);
        let mut out = Vec::new();
        for r in reqs {
            let prepared = prepare_receipt(&r).unwrap();
            let sig = SignatureResult {
                signature: host.keys[&self.id].sign(prepared.step().body()),
                assertion: None,
            };
            if let Ok((env, next)) = finish_receipt(&self.state, &prepared, &sig, &now) {
                self.state = next;
                out.push(serde_json::from_slice(&env).unwrap());
            }
        }
        out
    }
    fn store(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(path.to_string(), bytes);
        self.log.push(path.to_string());
    }
    /// Answer one request the engine emitted (the JSON `exchange_next` returned).
    pub fn call(&mut self, host: &Host, req: &Value, now_ms: i64) -> (u16, Vec<u8>) {
        let url = req["url"].as_str().unwrap();
        let rest = url.strip_prefix(&self.base).expect("another home's URL");
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let method = req["method"].as_str().unwrap();
        let body = unb64(req["body"].as_str().unwrap());
        let headers = |k: &str| {
            req["headers"].as_array().unwrap().iter().find_map(|h| {
                (h[0].as_str().unwrap().eq_ignore_ascii_case(k))
                    .then(|| h[1].as_str().unwrap().to_string())
            })
        };
        let now = format_date(now_ms);
        match (method, path) {
            ("GET", "/head") => match self.head_env(host, now_ms) {
                Some(h) => (200, h),
                None => resp(404, json!({})),
            },
            ("GET", "/authority") => {
                let after: u64 = q_get(query, "after").and_then(|s| s.parse().ok()).unwrap_or(0);
                let limit: usize = q_get(query, "limit").and_then(|s| s.parse().ok()).unwrap_or(64);
                let all: Vec<&Vec<u8>> = self.entries.range(after + 1..).map(|(_, e)| e).collect();
                let page: Vec<Value> = all
                    .iter()
                    .take(limit.min(64))
                    .map(|e| serde_json::from_slice(e).unwrap())
                    .collect();
                resp(200, json!({"entries": page, "receipts": [], "more": all.len() > limit.min(64)}))
            }
            ("POST", "/authority") => {
                let v: Value = serde_json::from_slice(&body).unwrap();
                let mut receipts = Vec::new();
                for e in v["entries"].as_array().unwrap() {
                    let b = canonical(e).unwrap();
                    let a = home_admit(&self.state, &b, &now);
                    self.state = a.state.clone();
                    match a.result {
                        Ok(()) => {
                            let seq = entry_seq(&b);
                            self.entries.entry(seq).or_insert_with(|| b.clone());
                            let p = format!("authority/{seq:08}.json");
                            if !self.files.contains_key(&p) {
                                self.store(&p, b);
                            }
                            receipts.extend(self.sign_receipts(host, a.receipts, now_ms));
                        }
                        Err(colophon_core::v05::history::home::Refusal::Conflict) => {
                            let h = self
                                .head_env(host, now_ms)
                                .map(|h| serde_json::from_slice::<Value>(&h).unwrap())
                                .unwrap_or(json!({}));
                            return resp(409, h);
                        }
                        Err(r) => return resp(422, json!({"result": r.code()})),
                    }
                }
                let head = self
                    .head_env(host, now_ms)
                    .map(|h| serde_json::from_slice::<Value>(&h).unwrap());
                resp(200, json!({"head": head, "receipts": receipts}))
            }
            ("GET", "/pending") => {
                let after: u64 = q_get(query, "after").and_then(|s| s.parse().ok()).unwrap_or(0);
                let limit: usize = q_get(query, "limit").and_then(|s| s.parse().ok()).unwrap_or(64);
                let page = self.state.pending_page(after, limit.min(64), now_ms).unwrap();
                resp(200, json!({
                    "objects": page.objects.iter().map(|o| json!({"seq": o.seq, "digest": o.digest, "kind": o.kind,
                        "envelope": serde_json::from_slice::<Value>(&o.envelope).unwrap()})).collect::<Vec<_>>(),
                    "more": page.more}))
            }
            ("POST", "/pending") => {
                let v: Value = serde_json::from_slice(&body).unwrap();
                let objs: Vec<Vec<u8>> = v["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| canonical(o).unwrap())
                    .collect();
                let (next, results, receipts) = admit_pending_batch(&self.state, &objs, &now).unwrap();
                self.state = next;
                let refused: Vec<Value> = results
                    .iter()
                    .filter_map(|r| r.as_ref().err().map(|e| json!(e.code())))
                    .collect();
                if !refused.is_empty() {
                    return resp(422, json!(refused));
                }
                let rs = self.sign_receipts(host, receipts, now_ms);
                resp(200, json!({"receipts": rs}))
            }
            ("GET", "/changes") => {
                let after: usize = q_get(query, "after").and_then(|s| s.parse().ok()).unwrap_or(0);
                let limit: usize = q_get(query, "limit").and_then(|s| s.parse().ok()).unwrap_or(500).min(500);
                if after > self.log.len() {
                    return resp(410, json!({}));
                }
                let slice = &self.log[after..];
                let page: Vec<&String> = slice.iter().take(limit).collect();
                let entries: Vec<Value> = page
                    .iter()
                    .map(|p| json!({"path": p, "size": self.files[*p].len(),
                        "sha256": digest(&self.files[*p])}))
                    .collect();
                resp(200, json!({"entries": entries, "cursor": (after + page.len()).to_string(), "more": slice.len() > limit}))
            }
            ("GET", p) if p.starts_with("/records/") => match self.files.get(&p["/records/".len()..]) {
                Some(b) => (200, b.clone()),
                None => resp(404, json!({})),
            },
            ("PUT", p) if p.starts_with("/records/") => {
                let rec = p["/records/".len()..].to_string();
                if let Some(name) = rec.strip_prefix("blobs/") {
                    if digest(&body) != name {
                        return resp(400, json!({}));
                    }
                }
                let live = rec.starts_with("state/");
                match (self.files.get(&rec).cloned(), headers("If-None-Match"), headers("If-Match")) {
                    (None, Some(_), None) => {
                        self.store(&rec, body);
                        resp(201, json!({}))
                    }
                    (Some(old), Some(_), None) if !live => {
                        if old == body { resp(200, json!({})) } else { resp(412, json!({})) }
                    }
                    (Some(old), None, Some(m)) if live => {
                        if format!("\"{}\"", digest(&old)) == m {
                            self.store(&rec, body);
                            resp(200, json!({}))
                        } else {
                            resp(412, json!({}))
                        }
                    }
                    (Some(old), Some(_), None) if live => {
                        if old == body { resp(200, json!({})) } else { resp(412, json!({})) }
                    }
                    _ => resp(428, json!({})),
                }
            }
            _ => resp(404, json!({})),
        }
    }
}

/// Run one full pass of `engine` with `home`, as an app would: the loop is the host's, the
/// requests and what to store come from the exports' JSON.
pub fn sync_pass(
    engine: &AccountEngine,
    src: &MemSource,
    home_id: &str,
    sim: &mut SimHome,
    host: &Host,
    now_ms: i64,
) -> Vec<Value> {
    let mut faults = Vec::new();
    engine.advance(now_ms).unwrap();
    engine.refresh(src.listing()).unwrap();
    for _ in 0..100_000 {
        let step = j(&engine.exchange_next(home_id.into()).unwrap());
        match step["step"].as_str().unwrap() {
            "done" => return faults,
            "waiting" => panic!("the loop answers every request"),
            "needCall" => {
                let n = &step["need"];
                engine
                    .exchange_provide_call(
                        home_id.into(),
                        n["ticket"].as_u64().unwrap(),
                        format!("call-{}", n["ticket"]).into_bytes(),
                    )
                    .unwrap();
            }
            "request" => {
                let r = &step["request"];
                let (status, body) = sim.call(host, r, now_ms);
                let report = j(&engine
                    .exchange_answer(
                        home_id.into(),
                        r["ticket"].as_u64().unwrap(),
                        status as u32,
                        "[]".into(),
                        body,
                    )
                    .unwrap());
                src.store(&report["store"]);
                faults.extend(report["faults"].as_array().unwrap().clone());
            }
            other => panic!("{other}"),
        }
    }
    panic!("a pass did not end");
}
