//! `AccountEngine`: the session an app runs. It holds the core's engine (which holds the
//! account), reads the host's record source, and exposes reads, writes, live state, blobs,
//! imports, checkpoints and the exchange with a home as values the host performs.
use super::account::{
    account_reads, account_stores, agreements_json, changes_json, denial_json, epoch_secrets,
    finished_json, identity, opening_inputs_json, opening_secrets, records, slots_json, stores_of,
};
use super::action::{
    begin, next_owner, prf_results, signatures, signer_choice, step_json, AccountAction,
    EngineWrites, Prepared,
};
use super::fault::AccountError;
use super::json::*;
use super::{guard, lock, HostSource, Source};
use colophon_core::blobs::BlobRead;
use colophon_core::blobs::BlobWriter;
use colophon_core::model::Outcome;
use colophon_core::v05::account::Identity;
use colophon_core::v05::engine::blobs::BlobAvailability;
use colophon_core::v05::engine::exchange::{Fault, Method, Report, Request, Response, Step};
use colophon_core::v05::engine::live::PendingLive;
use colophon_core::v05::engine::{Engine, EngineOptions, OpenMode, Saved};
use colophon_core::v05::records::HeldRecord;
use colophon_core::v05::write::SignatureResult;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;

type R<T> = Result<T, AccountError>;

/// Default records read per batch.
const DEFAULT_BATCH: u64 = 16_384;

/// The account engine over a host record source.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountEngine {
    eng: Mutex<Engine<Source>>,
    owner: u64,
}

fn denial_error(d: &colophon_core::model::Denial) -> AccountError {
    AccountError::denied(&d.reason, &d.detail)
}
fn saved_from(text: &str) -> R<Option<Saved>> {
    if text.is_empty() {
        return Ok(None);
    }
    let v = parse(text, "saved state")?;
    let mut parts = BTreeMap::new();
    if let Some(o) = v.get("parts").and_then(Value::as_object) {
        if o.len() > MAX_NAMES {
            return Err(AccountError::bound("too many saved parts"));
        }
        for (k, p) in o {
            parts.insert(
                k.clone(),
                decode(
                    p.as_str()
                        .ok_or_else(|| AccountError::bad("a saved part is base64"))?,
                    "part",
                )?,
            );
        }
    }
    Ok(Some(Saved {
        verifier: b64(&v, "verifier")?,
        checkpoint: b64(&v, "checkpoint")?,
        parts,
    }))
}
fn paths_arg(text: &str, what: &str) -> R<Vec<String>> {
    names_of(&parse(text, what)?, what)
}
fn method(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
    }
}
fn request_json(r: &Request) -> Value {
    json!({"ticket": r.ticket, "home": r.home, "method": method(r.method), "url": r.url,
        "headers": r.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "body": enc(&r.body)})
}
fn fault_json(f: &Fault) -> Value {
    match f {
        Fault::Rollback { home } => json!({"kind": "rollback", "home": home}),
        Fault::Fork { home } => json!({"kind": "fork", "home": home}),
        Fault::BadObject { home, code } => json!({"kind": "badObject", "home": home, "code": code}),
        Fault::ForeignAccount { home } => json!({"kind": "foreignAccount", "home": home}),
        Fault::NoProgress { home, feed } => {
            json!({"kind": "noProgress", "home": home, "feed": feed})
        }
        Fault::Mismatch { home, path } => json!({"kind": "mismatch", "home": home, "path": path}),
        Fault::Refused { home, what, code } => {
            json!({"kind": "refused", "home": home, "what": what, "code": code})
        }
        Fault::Conflict { home, path } => json!({"kind": "conflict", "home": home, "path": path}),
        Fault::Race { home, path } => json!({"kind": "race", "home": home, "path": path}),
        Fault::Unauthorized {
            home,
            purpose,
            audience,
        } => {
            json!({"kind": "unauthorized", "home": home, "purpose": purpose, "audience": audience})
        }
        Fault::Redirect { home, endpoints } => {
            json!({"kind": "redirect", "home": home, "endpoints": endpoints})
        }
        Fault::Malformed { home, why } => json!({"kind": "malformed", "home": home, "why": why}),
        Fault::CursorReset { home } => json!({"kind": "cursorReset", "home": home}),
        Fault::More { home, feed } => json!({"kind": "more", "home": home, "feed": feed}),
        Fault::HeadAhead { home } => json!({"kind": "headAhead", "home": home}),
        Fault::Status { home, status } => json!({"kind": "status", "home": home, "status": status}),
    }
}
fn report_json(r: &Report) -> R<String> {
    to_string(&json!({
        "store": stores(&r.store),
        "changes": ser_value!(r.changes)?,
        "faults": r.faults.iter().map(fault_json).collect::<Vec<_>>(),
    }))
}

impl AccountEngine {
    fn with_account<T>(
        &self,
        f: impl FnOnce(&colophon_core::v05::account::Account) -> R<T>,
    ) -> R<T> {
        guard(|| f(lock(&self.eng)?.account()))
    }
    pub(crate) fn open_inner(
        host: Box<dyn HostSource>,
        listing: String,
        identity_text: String,
        account: String,
        namespaces: String,
        batch: u64,
        saved: String,
        mut key: Vec<u8>,
        now_ms: i64,
    ) -> R<Self> {
        guard(|| {
            let listing = paths_arg(&listing, "listing")?;
            let me = identity(&identity_text)?;
            let ns = paths_arg(&namespaces, "namespaces")?;
            let k = fixed::<32>(&key, "the sealed-state key")?;
            key.fill(0);
            let saved = saved_from(&saved)?;
            let mut options = EngineOptions::new(&account, k);
            options.namespaces = ns;
            options.batch = usize::try_from(if batch == 0 { DEFAULT_BATCH } else { batch })
                .map_err(|_| AccountError::bound("batch"))?;
            let e = Engine::open(
                Source::new(host),
                listing,
                me,
                options,
                saved.as_ref(),
                now_ms,
            )?;
            Ok(Self {
                eng: Mutex::new(e),
                owner: next_owner(),
            })
        })
    }
    fn begin_inner(&self, spec: String, mut entropy: Vec<u8>) -> R<AccountAction> {
        let r = guard(|| {
            let spec = parse(&spec, "the action")?;
            if matches!(
                spec.get("action").and_then(Value::as_str),
                Some("link") | Some("call")
            ) {
                return Err(AccountError::bad(
                    "links and calls are prepared on AccountCore: their artifact is not stored",
                ));
            }
            let g = lock(&self.eng)?;
            let e = &*g;
            let w = EngineWrites {
                write: &|ns, k, p, l, s| e.begin_write(ns, k, p, l, s),
            };
            let (kind, p) = begin(e.account(), Some(&w), &spec, &mut entropy)?;
            Ok(match p {
                Prepared::Action(p) => AccountAction::ready(p, self.owner, &kind),
                Prepared::Denied(d) => AccountAction::denied(d, self.owner, &kind),
            })
        });
        entropy.fill(0);
        r
    }
    fn begin_import_inner(
        &self,
        namespace: String,
        batch: String,
        mut entropy: Vec<u8>,
    ) -> R<AccountAction> {
        guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            entropy.fill(0);
            let v = parse(&batch, "the import batch")?;
            let b: colophon_core::imports::ImportBatch =
                serde_json::from_value(v).map_err(|_| AccountError::bad("not an import batch"))?;
            let g = lock(&self.eng)?;
            Ok(match g.begin_import(&namespace, &b, seed)? {
                Ok(p) => AccountAction::ready(p, self.owner, "import"),
                Err(d) => AccountAction::denied(d, self.owner, "import"),
            })
        })
    }
    fn provide_prf_inner(&self, action: &AccountAction, results: String) -> R<()> {
        guard(|| {
            let r = prf_results(&results)?;
            let p = action.take(self.owner)?;
            let g = lock(&self.eng)?;
            let next = g.account().provide_prf(p, r)?;
            action.put_back(next)
        })
    }
    fn finish_inner(&self, action: &AccountAction, sigs: String) -> R<String> {
        guard(|| {
            let sigs = signatures(&sigs)?;
            let p = action.take(self.owner)?;
            let w = lock(&self.eng)?.finish_write(p, sigs)?;
            to_string(&json!({"stores": stores(&w.stores), "changes": ser_value!(w.changes)?}))
        })
    }
    fn begin_blob_inner(
        &self,
        namespace: String,
        media_type: String,
        mut entropy: Vec<u8>,
    ) -> R<AccountBlobWriter> {
        guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            entropy.fill(0);
            match lock(&self.eng)?.begin_blob(&namespace, media_type, seed)? {
                Outcome::Success { value, .. } => Ok(AccountBlobWriter {
                    w: Mutex::new(Some(value)),
                }),
                Outcome::Failure { reason, detail, .. } => {
                    Err(AccountError::denied(&reason, &detail))
                }
            }
        })
    }
    fn begin_live_inner(
        &self,
        namespace: String,
        kind: String,
        payload: String,
        mut entropy: Vec<u8>,
    ) -> R<AccountLiveWrite> {
        guard(|| {
            let seed = fixed::<32>(&entropy, "entropy")?;
            entropy.fill(0);
            let p = parse(&payload, "payload")?;
            match lock(&self.eng)?.begin_live_write(&namespace, &kind, p, seed)? {
                Ok(pl) => Ok(AccountLiveWrite {
                    st: Mutex::new(Some(pl)),
                    owner: self.owner,
                }),
                Err(d) => Err(denial_error(&d)),
            }
        })
    }
    fn finish_live_inner(&self, live: &AccountLiveWrite, signature: String) -> R<String> {
        guard(|| {
            let sig = signatures(&signature)?;
            let [sig]: [SignatureResult; 1] = sig
                .try_into()
                .map_err(|_| AccountError::bad("a live write has exactly one signature"))?;
            let pl = {
                let mut s = lock(&live.st)?;
                if live.owner != self.owner {
                    return Err(AccountError::wrong_object(
                        "this live write was prepared by another session",
                    ));
                }
                s.take()
                    .ok_or_else(|| AccountError::consumed("this live write is finished"))?
            };
            let w = lock(&self.eng)?.finish_live_write(pl, sig)?;
            to_string(&json!({
                "stores": stores(&w.stores),
                "replaces": w.replaces.as_ref().map(|(p, d)| json!({"path": p, "sha256": d})),
                "changes": ser_value!(w.changes)?,
            }))
        })
    }
}
account_reads!(AccountEngine);

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountEngine {
    /// How the open treated saved state: `cold`, `resumed` or `invalidated: <why>`.
    pub fn open_mode(&self) -> Result<String, AccountError> {
        guard(|| {
            Ok(match lock(&self.eng)?.open_mode() {
                OpenMode::Cold => "cold".into(),
                OpenMode::Resumed => "resumed".into(),
                OpenMode::Invalidated(w) => format!("invalidated: {w}"),
            })
        })
    }
    /// Work the engine did, as JSON.
    pub fn stats(&self) -> Result<String, AccountError> {
        guard(|| {
            let s = lock(&self.eng)?.stats();
            to_string(
                &json!({"recordsRead": s.records_read, "signaturesVerified": s.signatures_verified,
                "payloadsDecrypted": s.payloads_decrypted, "walkedLast": s.walked_last,
                "foldsAppliedLast": s.folds_applied_last, "ignoredPaths": s.ignored_paths,
                "heldPaths": s.held_paths, "unreadPaths": s.unread_paths}),
            )
        })
    }
    /// Read every listed record not yet read and judge them. Called after unlock; also by
    /// `finish_unlock_slot` and `finish_unlock_epochs`.
    pub fn load(&self) -> Result<String, AccountError> {
        guard(|| changes_json(&lock(&self.eng)?.load()?))
    }
    /// Take a fresh listing (a JSON array of every path) and read what is new.
    pub fn refresh(&self, listing: String) -> Result<String, AccountError> {
        guard(|| {
            let l = paths_arg(&listing, "listing")?;
            changes_json(&lock(&self.eng)?.refresh(l)?)
        })
    }
    /// The host stored these paths itself (a write's stores, a fetch): read and judge them.
    pub fn apply_paths(&self, paths: String) -> Result<String, AccountError> {
        guard(|| {
            let p = paths_arg(&paths, "paths")?;
            changes_json(&lock(&self.eng)?.apply_paths(p)?)
        })
    }
    /// Move the clock forward.
    pub fn advance(&self, now_ms: i64) -> Result<String, AccountError> {
        guard(|| changes_json(&lock(&self.eng)?.advance(now_ms)?))
    }
    /// Open a slot, then read the records once. `secrets` as `AccountCore.finish_unlock_slot`.
    pub fn finish_unlock_slot(&self, index: u64, secrets: String) -> Result<String, AccountError> {
        guard(|| {
            let i = usize::try_from(index).map_err(|_| AccountError::bound("slot index"))?;
            let s = opening_secrets(&secrets)?;
            changes_json(&lock(&self.eng)?.finish_unlock_slot(i, &s)?)
        })
    }
    /// A member opens its shares, then the records are read once.
    pub fn finish_unlock_epochs(&self, answers: String) -> Result<String, AccountError> {
        guard(|| {
            let mut g = lock(&self.eng)?;
            let s = epoch_secrets(g.account(), &answers)?;
            changes_json(&g.finish_unlock_epochs(s)?)
        })
    }
    /// Paths a checkpoint covered that the listing no longer names.
    pub fn missing_covered(&self) -> Result<String, AccountError> {
        guard(|| to_string(&json!(lock(&self.eng)?.missing_covered())))
    }
    /// Namespaces whose budget cannot be judged until more is read.
    pub fn budget_scope_unavailable(&self) -> Result<String, AccountError> {
        guard(|| to_string(&json!(lock(&self.eng)?.budget_scope_unavailable())))
    }
    /// Covered paths judged again because their bytes changed.
    pub fn rejudged(&self) -> Result<String, AccountError> {
        guard(|| to_string(&json!(lock(&self.eng)?.rejudged())))
    }
    /// Why `namespace` is not readable now (`{"reason","detail"}`), or an empty string.
    pub fn access(&self, namespace: String) -> Result<String, AccountError> {
        guard(|| match lock(&self.eng)?.access(&namespace)? {
            Some(d) => to_string(&denial_json(&d)),
            None => Ok(String::new()),
        })
    }
    /// The revision of a namespace's fold (changes whenever its view does).
    pub fn revision(&self, namespace: String) -> Result<u64, AccountError> {
        guard(|| Ok(lock(&self.eng)?.revision(&namespace)))
    }
    /// Every namespace's revision, as `{"ns": n}`.
    pub fn revisions(&self) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.revisions()))
    }
    /// What this session is in the verified history.
    pub fn me(&self) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.me()))
    }
    /// Members with their terms and standing.
    pub fn members(&self) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.members()))
    }
    /// The ledger.
    pub fn ledger(&self) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.ledger()))
    }
    /// A namespace's folded view.
    pub fn view(&self, namespace: String) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.view(&namespace)?))
    }
    /// A named domain query; `args` is JSON.
    pub fn query(
        &self,
        namespace: String,
        name: String,
        args: String,
    ) -> Result<String, AccountError> {
        guard(|| {
            let a = parse_or_null(&args, "args")?;
            ser!(lock(&self.eng)?.query(&namespace, &name, a)?)
        })
    }
    /// One page (1 to 200) of admitted operations in fold order, with `nextOffset`.
    pub fn history(
        &self,
        namespace: String,
        offset: u64,
        limit: u64,
    ) -> Result<String, AccountError> {
        guard(|| {
            let o = usize::try_from(offset).map_err(|_| AccountError::bound("offset"))?;
            let l = usize::try_from(limit).map_err(|_| AccountError::bound("limit"))?;
            ser!(lock(&self.eng)?.history(&namespace, o, l)?)
        })
    }
    /// One admitted operation by the path it was stored at.
    pub fn operation_at(&self, namespace: String, path: String) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.operation_at(&namespace, &path)?))
    }
    /// Hold live candidates the host fetched (`[{"path","bytes"}]`).
    pub fn apply_live(&self, candidates: String) -> Result<String, AccountError> {
        guard(|| {
            let c: Vec<HeldRecord> = records(&candidates)?;
            changes_json(&lock(&self.eng)?.apply_live(c)?)
        })
    }
    /// Live candidates refused for being below their witness: `[[path, generation]]`.
    pub fn stale_live(&self) -> Result<String, AccountError> {
        guard(|| {
            to_string(&Value::Array(
                lock(&self.eng)?
                    .stale_live()
                    .iter()
                    .map(|(p, g)| json!([p, g]))
                    .collect(),
            ))
        })
    }
    /// The verdict on each held live candidate: `[[path, verdict]]`.
    pub fn live_verdicts(&self) -> Result<String, AccountError> {
        guard(|| {
            to_string(&Value::Array(
                lock(&self.eng)?
                    .live_verdicts()
                    .iter()
                    .map(|(p, v)| json!([p, format!("{v:?}")]))
                    .collect(),
            ))
        })
    }
    /// The sealed state to store atomically: `{"verifier","checkpoint","parts":{ns:b64}}`, a
    /// cache sealed under the key given at open. `nonce_seed` is 32 fresh bytes.
    pub fn save(&self, mut nonce_seed: Vec<u8>) -> Result<String, AccountError> {
        let r = guard(|| {
            let n = fixed::<32>(&nonce_seed, "the nonce seed")?;
            let s = lock(&self.eng)?.save(n)?;
            to_string(
                &json!({"verifier": enc(&s.verifier), "checkpoint": enc(&s.checkpoint),
                "parts": s.parts.iter().map(|(k, v)| (k.clone(), json!(enc(v)))).collect::<serde_json::Map<_, _>>()}),
            )
        });
        nonce_seed.fill(0);
        r
    }
    /// Recheck up to `limit` held paths against the source; a change is a sticky integrity
    /// error. Returns `{"checked","remaining"}`.
    pub fn verify_batch(&self, limit: u64) -> Result<String, AccountError> {
        guard(|| {
            let l = usize::try_from(limit).map_err(|_| AccountError::bound("limit"))?;
            let p = lock(&self.eng)?.verify_batch(l)?;
            to_string(&json!({"checked": p.checked, "remaining": p.remaining}))
        })
    }
    /// The signed manifest of a blob, as an outcome JSON.
    pub fn blob_manifest(&self, namespace: String, digest: String) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.blob_manifest(&namespace, &digest)?))
    }
    /// Authenticate one fetched chunk and return its plaintext. A refusal is `Denied`.
    pub fn open_blob_chunk(
        &self,
        namespace: String,
        digest: String,
        index: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, AccountError> {
        guard(|| {
            bounded(&ciphertext, 1 << 20, "a blob chunk")?;
            let i = usize::try_from(index).map_err(|_| AccountError::bound("index"))?;
            match lock(&self.eng)?.open_blob_chunk(&namespace, &digest, i, &ciphertext)? {
                Outcome::Success { value, .. } => Ok(value),
                Outcome::Failure { reason, detail, .. } => {
                    Err(AccountError::denied(&reason, &detail))
                }
            }
        })
    }
    /// The plaintext of one held chunk.
    pub fn blob_chunk(
        &self,
        namespace: String,
        digest: String,
        index: u64,
    ) -> Result<Vec<u8>, AccountError> {
        guard(|| {
            let i = usize::try_from(index).map_err(|_| AccountError::bound("index"))?;
            blob_bytes(lock(&self.eng)?.blob_chunk(&namespace, &digest, i)?)
        })
    }
    /// The whole blob's authenticated plaintext. `Unavailable` when chunks are not held.
    pub fn read_blob(&self, namespace: String, digest: String) -> Result<Vec<u8>, AccountError> {
        guard(|| blob_bytes(lock(&self.eng)?.read_blob(&namespace, &digest)?))
    }
    /// How much of a blob is held: `{"state":"complete"|"partial"|"missing"|"inaccessible",..}`.
    pub fn blob_availability(
        &self,
        namespace: String,
        digest: String,
    ) -> Result<String, AccountError> {
        guard(|| {
            to_string(
                &match lock(&self.eng)?.blob_availability(&namespace, &digest)? {
                    BlobAvailability::Complete => json!({"state": "complete"}),
                    BlobAvailability::Partial { present, total } => {
                        json!({"state": "partial", "present": present, "total": total})
                    }
                    BlobAvailability::Missing => json!({"state": "missing"}),
                    BlobAvailability::Inaccessible(d) => {
                        json!({"state": "inaccessible", "detail": d})
                    }
                },
            )
        })
    }
    /// Chunk paths of required blobs this device does not hold.
    pub fn required_blob_fetches(&self, namespace: String) -> Result<String, AccountError> {
        guard(|| to_string(&json!(lock(&self.eng)?.required_blob_fetches(&namespace)?)))
    }
    /// The homes the account names, as the exchange sees them.
    pub fn exchange_homes(&self) -> Result<String, AccountError> {
        guard(|| ser!(lock(&self.eng)?.exchange_homes()))
    }
    /// Set (or clear, with an empty string) the storage bearer token for a home.
    pub fn exchange_set_bearer(&self, home: String, token: String) -> Result<(), AccountError> {
        guard(|| {
            if token.len() > 8192 {
                return Err(AccountError::bound("a bearer token is at most 8 KiB"));
            }
            lock(&self.eng)?.exchange_set_bearer(&home, (!token.is_empty()).then_some(token));
            Ok(())
        })
    }
    /// The next step of a pass with `home`, as JSON: `{"step":"request","request":{..}}`,
    /// `{"step":"waiting"}`, `{"step":"needCall","need":{..}}` or `{"step":"done"}`. The host
    /// performs the request and answers it with `exchange_answer`.
    pub fn exchange_next(&self, home: String) -> Result<String, AccountError> {
        guard(|| {
            to_string(&match lock(&self.eng)?.exchange_next(&home)? {
                Step::Request(r) => json!({"step": "request", "request": request_json(&r)}),
                Step::Waiting => json!({"step": "waiting"}),
                Step::NeedCall(n) => json!({"step": "needCall", "need": {"ticket": n.ticket,
                    "home": n.home, "audience": n.audience, "purpose": n.purpose,
                    "method": method(n.method), "url": n.url}}),
                Step::Done => json!({"step": "done"}),
            })
        })
    }
    /// Give the call the host built for a `needCall` step. It is bound to that ticket.
    pub fn exchange_provide_call(
        &self,
        home: String,
        ticket: u64,
        call: Vec<u8>,
    ) -> Result<(), AccountError> {
        guard(|| {
            bounded(&call, 16_384, "a call")?;
            lock(&self.eng)?.exchange_provide_call(&home, ticket, &call)?;
            Ok(())
        })
    }
    /// Answer the request with `ticket`: the response's status, headers (`[[name, value]]` JSON)
    /// and body. Everything the home sent is verified before anything changes. Returns the
    /// report: `{"store":[{path,bytes}],"changes":{..},"faults":[{kind,..}]}`.
    pub fn exchange_answer(
        &self,
        home: String,
        ticket: u64,
        status: u32,
        headers: String,
        body: Vec<u8>,
    ) -> Result<String, AccountError> {
        guard(|| {
            bounded(&body, 128 << 20, "a response body")?;
            let status = u16::try_from(status).map_err(|_| AccountError::bound("status"))?;
            let hv = parse(&headers, "headers")?;
            let arr = hv
                .as_array()
                .ok_or_else(|| AccountError::bad("headers is an array of pairs"))?;
            if arr.len() > 256 {
                return Err(AccountError::bound("too many headers"));
            }
            let mut hs = Vec::new();
            for h in arr {
                match (
                    h.get(0).and_then(Value::as_str),
                    h.get(1).and_then(Value::as_str),
                ) {
                    (Some(k), Some(v)) => hs.push((k.to_string(), v.to_string())),
                    _ => return Err(AccountError::bad("a header is [name, value]")),
                }
            }
            let r = lock(&self.eng)?.exchange_answer(
                &home,
                ticket,
                Response {
                    status,
                    headers: hs,
                    body,
                },
            )?;
            report_json(&r)
        })
    }
    /// Queue the pulls of the chunks of a blob this device lacks. Returns how many.
    pub fn exchange_want_blob(
        &self,
        home: String,
        namespace: String,
        digest: String,
    ) -> Result<u64, AccountError> {
        guard(|| Ok(lock(&self.eng)?.exchange_want_blob(&home, &namespace, &digest)? as u64))
    }
    /// Homes whose verified receipt of `object` the account holds.
    pub fn receipted_by(&self, object: String) -> Result<String, AccountError> {
        guard(|| to_string(&json!(lock(&self.eng)?.receipted_by(&object))))
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// Open an engine over the host's source. `listing` is a JSON array of every path the
    /// source holds; `identity` is `controller:<id>` or `member:<id>`; `account` is the 64-hex
    /// account ID from enrollment or creation; `namespaces` a JSON array (empty array: all);
    /// `batch` the records judged per step (0: the default); `saved` the JSON `Engine.save`
    /// returned (or empty); `key` the 32-byte device-held key that seals saved state. The
    /// engine keeps `key` for `save` and the saved-state check, as the core's engine does; it
    /// never returns it. Nothing is read from records until a slot or shares are opened.
    #[uniffi::constructor]
    pub fn open(
        source: Box<dyn HostSource>,
        listing: String,
        identity: String,
        account: String,
        namespaces: String,
        batch: u64,
        saved: String,
        key: Vec<u8>,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::open_inner(
            source, listing, identity, account, namespaces, batch, saved, key, now_ms,
        )
        .map(std::sync::Arc::new)
    }
    /// Prepare an action (see `AccountCore.begin`); a `write` is prepared by the engine, which
    /// retains the live heads it supersedes. Links and calls are prepared on `AccountCore`.
    pub fn begin(
        &self,
        spec: String,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountAction>, AccountError> {
        self.begin_inner(spec, entropy).map(std::sync::Arc::new)
    }
    /// Prepare an import batch (`namespace`, the batch as JSON) under a grant that carries
    /// `import`. `entropy` is 32 fresh bytes.
    pub fn begin_import(
        &self,
        namespace: String,
        batch: String,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountAction>, AccountError> {
        self.begin_import_inner(namespace, batch, entropy)
            .map(std::sync::Arc::new)
    }
    /// Give the PRF assertions an action asked for.
    pub fn provide_prf(
        &self,
        action: std::sync::Arc<AccountAction>,
        results: String,
    ) -> Result<(), AccountError> {
        self.provide_prf_inner(&action, results)
    }
    /// Finish a prepared action with the host's signatures. Returns
    /// `{"stores":[{path,bytes}],"changes":{..}}`: the exact bytes to store, in order, which
    /// the core verified before returning them.
    pub fn finish(
        &self,
        action: std::sync::Arc<AccountAction>,
        signatures: String,
    ) -> Result<String, AccountError> {
        self.finish_inner(&action, signatures)
    }
    /// Prepare a live write (a passive position sample); `payload` is JSON.
    pub fn begin_live_write(
        &self,
        namespace: String,
        kind: String,
        payload: String,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountLiveWrite>, AccountError> {
        self.begin_live_inner(namespace, kind, payload, entropy)
            .map(std::sync::Arc::new)
    }
    /// Finish a live write with its one raw signature (`[{"signature"}]`).
    pub fn finish_live_write(
        &self,
        live: std::sync::Arc<AccountLiveWrite>,
        signature: String,
    ) -> Result<String, AccountError> {
        self.finish_live_inner(&live, signature)
    }
    /// Start a streaming blob upload (32 fresh bytes). The writer holds the epoch key it needs
    /// until it is finished or dropped.
    pub fn begin_blob(
        &self,
        namespace: String,
        media_type: String,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountBlobWriter>, AccountError> {
        self.begin_blob_inner(namespace, media_type, entropy)
            .map(std::sync::Arc::new)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    pub fn begin(&self, spec: String, entropy: Vec<u8>) -> Result<AccountAction, AccountError> {
        self.begin_inner(spec, entropy)
    }
    pub fn begin_import(
        &self,
        namespace: String,
        batch: String,
        entropy: Vec<u8>,
    ) -> Result<AccountAction, AccountError> {
        self.begin_import_inner(namespace, batch, entropy)
    }
    pub fn provide_prf(&self, action: &AccountAction, results: String) -> Result<(), AccountError> {
        self.provide_prf_inner(action, results)
    }
    pub fn finish(
        &self,
        action: &AccountAction,
        signatures: String,
    ) -> Result<String, AccountError> {
        self.finish_inner(action, signatures)
    }
    pub fn begin_live_write(
        &self,
        namespace: String,
        kind: String,
        payload: String,
        entropy: Vec<u8>,
    ) -> Result<AccountLiveWrite, AccountError> {
        self.begin_live_inner(namespace, kind, payload, entropy)
    }
    pub fn finish_live_write(
        &self,
        live: &AccountLiveWrite,
        signature: String,
    ) -> Result<String, AccountError> {
        self.finish_live_inner(live, signature)
    }
    pub fn begin_blob(
        &self,
        namespace: String,
        media_type: String,
        entropy: Vec<u8>,
    ) -> Result<AccountBlobWriter, AccountError> {
        self.begin_blob_inner(namespace, media_type, entropy)
    }
}

fn blob_bytes(r: BlobRead) -> R<Vec<u8>> {
    match r {
        BlobRead::Available(b) => Ok(b),
        BlobRead::Missing => Err(AccountError::Unavailable {
            code: "unavailable".into(),
            detail: "the blob is not held here".into(),
        }),
        BlobRead::Inaccessible(d) => Err(AccountError::denied("notReadable", &d)),
        BlobRead::Invalid(d) => Err(AccountError::Malformed {
            code: "malformed".into(),
            detail: d,
        }),
    }
}

/// A streaming blob upload. Holds an epoch key until finished or dropped; never keep it.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountBlobWriter {
    w: Mutex<Option<BlobWriter>>,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountBlobWriter {
    /// Seal at most 64 KiB; returns `{"path","bytes"}`: store the ciphertext at the path
    /// before the manifest is published.
    pub fn push(&self, plaintext: Vec<u8>) -> Result<String, AccountError> {
        guard(|| {
            bounded(&plaintext, 64 * 1024, "a blob chunk")?;
            let mut g = lock(&self.w)?;
            let w = g
                .as_mut()
                .ok_or_else(|| AccountError::consumed("this blob writer is finished"))?;
            let (p, c) = w.push(&plaintext)?;
            to_string(&json!({"path": p, "bytes": enc(&c)}))
        })
    }
    /// Finish: the manifest as JSON, to publish in the operation that names the blob. The
    /// writer and its key are gone afterwards.
    pub fn finish(&self) -> Result<String, AccountError> {
        guard(|| {
            let w = lock(&self.w)?
                .take()
                .ok_or_else(|| AccountError::consumed("this blob writer is finished"))?;
            ser!(w.finish()?)
        })
    }
}

/// A prepared live write: one raw signature over one header.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountLiveWrite {
    st: Mutex<Option<PendingLive>>,
    owner: u64,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountLiveWrite {
    /// The one step to sign (same shape as an action step).
    pub fn step(&self) -> Result<String, AccountError> {
        guard(|| {
            let g = lock(&self.st)?;
            let p = g
                .as_ref()
                .ok_or_else(|| AccountError::consumed("this live write is finished"))?;
            to_string(&step_json(p.step()))
        })
    }
    /// The slot's generation.
    pub fn generation(&self) -> Result<u64, AccountError> {
        guard(|| {
            let g = lock(&self.st)?;
            Ok(g.as_ref()
                .ok_or_else(|| AccountError::consumed("this live write is finished"))?
                .generation())
        })
    }
    /// The slot path.
    pub fn state_path(&self) -> Result<String, AccountError> {
        guard(|| {
            let g = lock(&self.st)?;
            Ok(g.as_ref()
                .ok_or_else(|| AccountError::consumed("this live write is finished"))?
                .state_path()
                .to_string())
        })
    }
}
#[allow(dead_code)]
fn _unused(_: &[(String, Vec<u8>)], _: &colophon_core::v05::account::Finished) {
    let _ = (stores_of, finished_json, agreements_json);
}
