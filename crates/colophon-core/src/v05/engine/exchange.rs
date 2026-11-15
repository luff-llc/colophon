//! Exchange with a home (§13, §14; 0.3 §8.4 incorporated by §11.8), as sans-IO values.
//!
//! The host runs the transport. The engine builds the next [`Request`] for a home
//! ([`Engine::exchange_next`]) and consumes the [`Response`] ([`Engine::exchange_answer`]); a
//! request is named by an opaque ticket the engine issued, so the host cannot hand back a
//! request the engine did not make. A pass goes in the order the spec asks: the head, the
//! authority history (pulled, then pushed), pending objects (pulled; ours submitted), the change
//! feed with the scoped cursor, blob chunks pushed before records, immutable records pulled and
//! pushed, live slots by conditional replacement, then the chunks of required blobs.
//!
//! **A home is untrusted.** Every object it serves goes to the account, which verifies it, and
//! to nothing else: an entry is taken only if the history verifier accepts it; a head only if
//! it verifies against the held history and the per-home marks (a head behind its home's mark is
//! `refused:rollback`; one with a different digest at a held seq is `refused:fork`); a record only
//! if its bytes hash to the digest the home listed *and* the account admits it; a live slot only
//! if `v05::live` makes it a head above its witness; a blob chunk only if its name is the
//! SHA-256 of its bytes. Cursors move only on verified progress: the authority cursor is the
//! account's own verified seq, never the home's claim; the pending and change cursors advance
//! only when the home's numbers are strictly increasing. What a home does that cannot be
//! followed is reported as a [`Fault`], never followed.
//!
//! **Credentials.** A bearer token is storage access only (0.3 §8.1). Where a home demands an
//! `Authorization: Colophon <call>` (§13.4, §14), a 401 or 403 is reported as
//! [`Fault::Unauthorized`] naming the audience and purpose; the host builds the call with
//! [`Account::begin_call`](crate::v05::account::Account::begin_call) (it holds the signing keys)
//! and gives it to [`Engine::exchange_authorize`]. The engine never signs.
use super::{paths, Engine, Have, RecordSource};
use crate::v05::account::{Changes, Incoming};
use crate::v05::encoding::{canonical, encode_base64url};
use crate::v05::history::Objects;
use crate::v05::records::HeldRecord;
use crate::v05::{malformed, require, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The most bytes of a response body the engine reads.
pub const MAX_BODY: usize = 128 * 1024 * 1024;
/// Change-feed pages read in one pass; the rest waits for the next pass (reported as `More`).
pub const MAX_CHANGE_PAGES: u32 = 64;
/// Change-feed entries read in one pass.
pub const MAX_CHANGE_ENTRIES: usize = 50_000;
/// Pending-feed pages read in one pass (§14 bounds a complete listing at 10,368 objects: 163
/// pages of 64); the rest waits for the next pass (reported as `More`).
pub const MAX_PENDING_PAGES: u32 = 163;
/// Pending-feed objects read in one pass.
pub const MAX_PENDING_ENTRIES: usize = MAX_PENDING_PAGES as usize * PAGE;
/// Record pulls queued in one pass (the rest waits for the next pass, reported as `More`).
pub const MAX_PULLS_PER_PASS: usize = MAX_CHANGE_ENTRIES;
/// Live-slot pulls queued in one pass.
pub const MAX_LIVE_PULLS_PER_PASS: usize = 16_384;
/// Digests of junk a home served that the engine remembers.
pub const MAX_JUNK: usize = 4_096;
/// Entries, objects or receipts per authority and pending page (§14).
pub const PAGE: usize = 64;

/// HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
}
/// A request for the host to send.
#[derive(Clone, Debug)]
pub struct Request {
    /// The ticket to answer with.
    pub ticket: u64,
    /// The home whose pass it belongs to (answer it with this home).
    pub home: String,
    /// The method.
    pub method: Method,
    /// The full URL. It is at `home`'s base, except for a `GET …/head` of another home of the
    /// account (public, carrying no credential), fetched when `headQuorum` is above 1 because a
    /// call needs that many homes' fresh heads: the host sends it to the home its URL names.
    pub url: String,
    /// Headers, including `Authorization` when the engine holds a credential for it.
    pub headers: Vec<(String, String)>,
    /// The body (empty for a GET).
    pub body: Vec<u8>,
}
/// What the host got back.
#[derive(Clone, Debug)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// What the engine reports a home did that it did not follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The home's head is behind its mark, or its history stops before ours (`refused:rollback`).
    Rollback {
        /// The home.
        home: String,
    },
    /// The home's head names a different digest at a held seq (`refused:fork`).
    Fork {
        /// The home.
        home: String,
    },
    /// An object the home served did not verify; the code.
    BadObject {
        /// The home.
        home: String,
        /// The result code.
        code: String,
    },
    /// The home served another account's genesis in this account's slot.
    ForeignAccount {
        /// The home.
        home: String,
    },
    /// A page that moved nothing: the home is withholding, replaying or stuck.
    NoProgress {
        /// The home.
        home: String,
        /// Which feed.
        feed: String,
    },
    /// A listed record's bytes do not hash to the digest the home listed, or a blob chunk's
    /// name is not the hash of its bytes.
    Mismatch {
        /// The home.
        home: String,
        /// The path.
        path: String,
    },
    /// The home refused what we sent.
    Refused {
        /// The home.
        home: String,
        /// What was refused.
        what: String,
        /// The code.
        code: String,
    },
    /// An immutable path holds different bytes on the home (412): reported, never overwritten.
    Conflict {
        /// The home.
        home: String,
        /// The path.
        path: String,
    },
    /// A live replacement lost a race (412 on `If-Match`): the engine keeps its newer head and
    /// the host lists again.
    Race {
        /// The home.
        home: String,
        /// The path.
        path: String,
    },
    /// The home wants a call (401/403).
    Unauthorized {
        /// The home.
        home: String,
        /// `colophon.home.read` or `colophon.home.write`.
        purpose: String,
        /// The audience: the home's base.
        audience: String,
    },
    /// A non-primary home sent us to the primary (421).
    Redirect {
        /// The home.
        home: String,
        /// The primary's endpoints, as sent.
        endpoints: Vec<String>,
    },
    /// The home's answer was not in the shape §14 gives.
    Malformed {
        /// The home.
        home: String,
        /// What.
        why: String,
    },
    /// The home's cursor was no longer honoured (410): the engine lists again.
    CursorReset {
        /// The home.
        home: String,
    },
    /// A feed has more than this pass reads: the rest is for the next pass.
    More {
        /// The home.
        home: String,
        /// Which feed.
        feed: String,
    },
    /// The home's head names an entry it does not serve (§13.3): it is ahead of what it gives.
    HeadAhead {
        /// The home.
        home: String,
    },
    /// Another status the engine does not follow.
    Status {
        /// The home.
        home: String,
        /// The status.
        status: u16,
    },
}

/// What one answer produced.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Bytes for the host to store, verified: `(path, bytes)`.
    pub store: Vec<(String, Vec<u8>)>,
    /// What the account changed.
    pub changes: Changes,
    /// Faults of the home, never followed.
    pub faults: Vec<Fault>,
}

/// The next step of a pass.
#[derive(Clone, Debug)]
pub enum Step {
    /// Send this and answer it.
    Request(Request),
    /// A request is outstanding: answer it first.
    Waiting,
    /// The next request needs a fresh `Authorization: Colophon` call (§12.4: a call is never
    /// reused). Build one for exactly this and give it to [`Engine::exchange_provide_call`].
    NeedCall(CallNeed),
    /// The pass is complete.
    Done,
}

/// What one request needs a call for: everything the host signs. The request is built by the
/// engine and is already fixed when it asks, so a call made from these fields is exactly the
/// call the home checks (§14): audience `audience`, purpose `purpose`, and `args` exactly
/// [`crate::v05::calls::home_call_args`]`(method, path, body_sha256)`.
/// [`Engine::exchange_begin_call`] builds it. A call given for this ticket cannot be attached
/// to another request, home or purpose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallNeed {
    /// The ticket the call is bound to.
    pub ticket: u64,
    /// The home.
    pub home: String,
    /// The audience: the home's base.
    pub audience: String,
    /// `colophon.home.read` or `colophon.home.write`.
    pub purpose: String,
    /// The request's method.
    pub method: Method,
    /// The request's URL: `audience` followed by `path`.
    pub url: String,
    /// The path and query relative to the home's base, exactly as the request will send it.
    pub path: String,
    /// The lowercase hex SHA-256 of the request's body (of the empty string when none).
    pub body_sha256: String,
}
impl Method {
    /// The method's name, upper case.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tag {
    Head,
    /// The head of another home of the account (`peer`, at its `base`): a call needs fresh heads
    /// from `headQuorum` homes (§12.3 step 4), fetched before anything that needs a call.
    PeerHead {
        peer: String,
        base: String,
    },
    PullAuthority,
    PushAuthority {
        last: u64,
    },
    PullPending,
    PushPending {
        digests: Vec<String>,
        /// SHA-256 hex of the receipts among them (remembered as sent to this home).
        receipts: Vec<String>,
    },
    PullPredecessor {
        seq: u64,
    },
    PutPredecessor {
        seq: u64,
    },
    Changes,
    PullRecord {
        path: String,
        sha: String,
    },
    PutRecord {
        path: String,
        sha: String,
    },
    PutBlob {
        path: String,
    },
    PullBlob {
        path: String,
    },
    PullLive {
        path: String,
        sha: String,
    },
    PutLive {
        path: String,
        sha: String,
        generation: u64,
    },
    GenesisCheck {
        sha: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Head,
    PullAuthority,
    PushAuthority,
    Pending,
    Changes,
    PushBlobs,
    Records,
    Live,
    LivePush,
    PullBlobs,
    Done,
}

type Queued = (Tag, Method, String, Vec<u8>, Vec<(String, String)>);

/// What the engine keeps per home.
#[derive(Debug)]
struct Home {
    phase: Phase,
    queue: VecDeque<Queued>,
    /// The home's own pending cursor (0 to start).
    pending_after: u64,
    /// The change feed's opaque cursor, bound to the namespace scope.
    changes_cursor: Option<String>,
    /// What the home holds: path to SHA-256 hex.
    remote: BTreeMap<String, String>,
    /// The highest seq the home is known to hold verified.
    acked: u64,
    /// The request being answered.
    inflight: Option<(u64, Tag)>,
    /// Cursor resets this pass.
    stalls: u8,
    /// A foreign library, a rollback or a refusal: the rest of the pass is skipped.
    halted: bool,
    bearer: Option<String>,
    /// Learned from a 401: reads (or writes) of this home need a call each.
    require_read: bool,
    require_write: bool,
    /// A request waiting for its call, and the call given for it.
    awaiting: Option<(u64, Queued)>,
    provided: Option<(u64, String)>,
    /// This pass's head, when it names an entry the account does not hold yet: judged again once
    /// the authority pull is complete (§13.3: the history is fetched further if needed).
    ahead: Option<Vec<u8>>,
    /// The request in flight, and whether it carried a call (for the 401 retry).
    last_item: Option<Queued>,
    carried_call: bool,
    /// This pass's change-feed bounds.
    pass_pages: u32,
    pass_entries: usize,
    pass_seen: BTreeSet<(String, String)>,
    seen_cursors: BTreeSet<String>,
    /// This pass's pending-feed bounds, and the objects waiting for their merge.
    pend_pages: u32,
    pend_entries: usize,
    /// Receipts (by SHA-256 hex) already submitted to this home.
    sent_receipts: BTreeSet<String>,
    /// Predecessor entries pulled this pass.
    pred_pulled: usize,
    /// Faults found while planning, reported with the next answer.
    notes: Vec<Fault>,
    genesis_asked: BTreeSet<String>,
    /// Digests of same-body genesis envelopes the home lists; one body is one object.
    twins: BTreeSet<String>,
    /// Digests of bytes this home served that were no record (bounded).
    junk: BTreeSet<String>,
    /// Slot values this home served this pass, verified: path to `(generation, sha)`.
    verified_live: BTreeMap<String, (u64, String)>,
    /// Per slot, the highest generation this home is known to have held.
    home_live: BTreeMap<String, u64>,
    /// Pulled records waiting to be judged in one batch.
    pulled: Vec<(String, Vec<u8>)>,
}
impl Default for Home {
    fn default() -> Self {
        Self {
            phase: Phase::Head,
            queue: VecDeque::new(),
            pending_after: 0,
            changes_cursor: None,
            remote: BTreeMap::new(),
            acked: 0,
            inflight: None,
            stalls: 0,
            halted: false,
            bearer: None,
            require_read: false,
            require_write: false,
            awaiting: None,
            provided: None,
            ahead: None,
            last_item: None,
            carried_call: false,
            pass_pages: 0,
            pass_entries: 0,
            pass_seen: BTreeSet::new(),
            seen_cursors: BTreeSet::new(),
            pend_pages: 0,
            pend_entries: 0,
            sent_receipts: BTreeSet::new(),
            pred_pulled: 0,
            notes: Vec::new(),
            genesis_asked: BTreeSet::new(),
            twins: BTreeSet::new(),
            junk: BTreeSet::new(),
            verified_live: BTreeMap::new(),
            home_live: BTreeMap::new(),
            pulled: Vec::new(),
        }
    }
}

/// The part of a home's memory a checkpoint keeps: the cursors and the remembered remote set
/// (0.3 §8.4: "persist the cursor and the remembered remote set"). A cursor the home no longer
/// honours is answered 410 and the engine lists again from the start.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SavedHome {
    /// The home's pending cursor.
    pub pending_after: u64,
    /// The change feed's cursor, bound to the checkpoint's namespace scope.
    pub changes_cursor: Option<String>,
    /// What the home held: path to SHA-256 hex.
    pub remote: BTreeMap<String, String>,
    /// The highest seq the home acknowledged.
    pub acked: u64,
    /// Per live slot, the highest generation the home is known to have held.
    #[serde(default)]
    pub home_live: BTreeMap<String, u64>,
}

impl State {
    pub(crate) fn export(&self) -> BTreeMap<String, SavedHome> {
        self.homes
            .iter()
            .map(|(k, h)| {
                (
                    k.clone(),
                    SavedHome {
                        pending_after: h.pending_after,
                        changes_cursor: h.changes_cursor.clone(),
                        remote: h.remote.clone(),
                        acked: h.acked,
                        home_live: h.home_live.clone(),
                    },
                )
            })
            .collect()
    }
    pub(crate) fn import(&mut self, saved: BTreeMap<String, SavedHome>, verified_seq: u64) {
        for (k, h) in saved.into_iter().take(16) {
            let e = self.homes.entry(k).or_default();
            e.pending_after = h.pending_after;
            e.changes_cursor = h.changes_cursor;
            e.remote = h.remote.into_iter().take(super::MAX_LISTING).collect();
            e.acked = h.acked.min(verified_seq);
            e.home_live = h.home_live.into_iter().take(super::MAX_LISTING).collect();
        }
    }
}

/// The engine's exchange memory.
#[derive(Default, Debug)]
pub struct State {
    homes: BTreeMap<String, Home>,
    next_ticket: u64,
    /// Homes that have receipted an object: object digest to home IDs. Local memory only.
    receipted: BTreeMap<String, BTreeSet<String>>,
}

fn is_public(tag: &Tag) -> bool {
    matches!(
        tag,
        Tag::Head | Tag::PeerHead { .. } | Tag::PushAuthority { .. } | Tag::PushPending { .. }
    )
}
/// The sequence number of an authority entry's body, for naming a predecessor file.
fn entry_seq(bytes: &[u8]) -> Option<u64> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    let b = crate::v05::encoding::decode_base64(
        v.get("body")?.as_str()?,
        crate::v05::encoding::bounds::AUTHORITY_BODY,
    )
    .ok()?;
    serde_json::from_slice::<Value>(&b)
        .ok()?
        .get("seq")?
        .as_u64()
}
/// Predecessor entries pulled or pushed in one pass.
pub const MAX_PREDECESSOR_PER_PASS: usize = 256;
fn purpose_of(method: Method) -> String {
    crate::v05::calls::home_call_purpose(method.as_str()).into()
}
fn base_of(endpoint: &str) -> String {
    endpoint.trim_end_matches('/').to_string()
}
fn q(v: &str) -> String {
    v.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn body_json(r: &Response) -> std::result::Result<Value, String> {
    if r.body.len() > MAX_BODY {
        return Err("the body exceeds its bound".into());
    }
    crate::v05::encoding::strict_parse(&r.body).map_err(|e| e.code())
}
fn envelopes(v: &Value, max: usize) -> std::result::Result<Vec<Vec<u8>>, String> {
    if v.is_null() {
        return Ok(Vec::new());
    }
    let list = v.as_array().ok_or("not an array")?;
    if list.len() > max {
        return Err("too many objects in a page".into());
    }
    list.iter()
        .map(|e| canonical(e).map_err(|x| x.code()))
        .collect()
}
fn json_post() -> Vec<(String, String)> {
    vec![("Content-Type".into(), "application/json".into())]
}

impl<S: RecordSource> Engine<S> {
    /// The homes this account names and their endpoints, as the verified state has them.
    pub fn exchange_homes(&self) -> Vec<crate::v05::account::HomeInfo> {
        self.account.homes()
    }

    /// Set the bearer token (storage access only) for a home.
    pub fn exchange_set_bearer(&mut self, home: &str, token: Option<String>) {
        self.exchange
            .homes
            .entry(home.to_string())
            .or_default()
            .bearer = token;
    }

    /// Give the engine the call the host built for the request `NeedCall` named. It is bound to
    /// that ticket, consumed by it, and attached to nothing else (§12.4: calls are not reused).
    pub fn exchange_provide_call(&mut self, home: &str, ticket: u64, call: &[u8]) -> Result<()> {
        require(call.len() <= 16_384, "a call is small")?;
        let h = self.home_mut(home);
        require(
            h.awaiting.as_ref().is_some_and(|(t, _)| *t == ticket),
            "no request of this home is waiting for a call under this ticket",
        )?;
        h.provided = Some((ticket, encode_base64url(call)));
        Ok(())
    }

    /// Prepare the call for the request a `NeedCall` named (`ticket`), signed by this session's
    /// own `key`: everything in it is read from the request the engine built (audience, purpose,
    /// method, path and body digest), so it cannot be bound to anything else. The host signs its
    /// one step, gets the envelope from [`Engine::finish_write`] (`artifact`; the signer's own
    /// judgement by the home's rule) and gives it to [`Engine::exchange_provide_call`].
    pub fn exchange_begin_call(
        &self,
        home: &str,
        ticket: u64,
        key: &[u8],
        request_id: [u8; 32],
    ) -> Result<crate::v05::account::PendingAction> {
        self.check_ready()?;
        let h = self
            .exchange
            .homes
            .get(home)
            .ok_or_else(|| malformed("no pass with this home"))?;
        let item = match &h.awaiting {
            Some((t, item)) if *t == ticket => item,
            _ => {
                return Err(malformed(
                    "no request of this home is waiting for a call under this ticket",
                ))
            }
        };
        let endpoint = self
            .account
            .homes()
            .into_iter()
            .find(|i| i.id == home)
            .and_then(|i| i.endpoints.first().map(|e| base_of(e)))
            .ok_or_else(|| malformed("the home names no endpoint"))?;
        let call = crate::v05::account::HomeCall {
            audience: endpoint,
            method: item.1.as_str().to_string(),
            path: item.2.clone(),
            body_sha256: super::hex(&super::sha(&item.3)),
        };
        self.account.begin_home_call(key, &call, request_id)
    }

    /// The next request of a pass with `home`, a request that needs its own call, whether one is
    /// outstanding, or that the pass is done. A pass is strictly ordered: authority before
    /// records before live state before blobs. After `Done` the next call starts a new pass.
    pub fn exchange_next(&mut self, home: &str) -> Result<Step> {
        self.check_ready()?;
        let info = self
            .account
            .homes()
            .into_iter()
            .find(|h| h.id == home)
            .ok_or_else(|| malformed("not a home of this account"))?;
        let endpoint = info
            .endpoints
            .first()
            .map(|e| base_of(e))
            .ok_or_else(|| malformed("the home names no endpoint"))?;
        loop {
            let h = self.exchange.homes.entry(home.to_string()).or_default();
            if h.inflight.is_some() {
                return Ok(Step::Waiting);
            }
            if let Some((ticket, item)) = h.awaiting.take() {
                if h.provided.as_ref().is_some_and(|(t, _)| *t == ticket) {
                    let (_, call) = h.provided.take().unwrap_or_default();
                    return Ok(Step::Request(self.make_request(
                        home,
                        &endpoint,
                        ticket,
                        item,
                        Some(call),
                    )));
                }
                let need = CallNeed {
                    ticket,
                    home: home.to_string(),
                    audience: endpoint.clone(),
                    purpose: purpose_of(item.1),
                    method: item.1,
                    url: format!("{endpoint}{}", item.2),
                    path: item.2.clone(),
                    body_sha256: super::hex(&super::sha(&item.3)),
                };
                h.awaiting = Some((ticket, item));
                return Ok(Step::NeedCall(need));
            }
            if h.halted {
                h.queue.clear();
                h.phase = Phase::Done;
            }
            if let Some(item) = h.queue.pop_front() {
                let public = is_public(&item.0);
                let needs = !public
                    && ((item.1 == Method::Get && h.require_read)
                        || (item.1 != Method::Get && h.require_write));
                let ticket = self.exchange.next_ticket;
                self.exchange.next_ticket += 1;
                if needs {
                    let h = self.home_mut(home);
                    h.awaiting = Some((ticket, item));
                    continue;
                }
                return Ok(Step::Request(
                    self.make_request(home, &endpoint, ticket, item, None),
                ));
            }
            // The queue is empty: plan the next phase, or finish.
            let phase = h.phase;
            if phase == Phase::Done {
                h.phase = Phase::Head;
                h.halted = false;
                h.stalls = 0;
                h.verified_live.clear();
                return Ok(Step::Done);
            }
            if phase == Phase::Head {
                h.ahead = None;
                h.pass_pages = 0;
                h.pass_entries = 0;
                h.pass_seen.clear();
                h.seen_cursors.clear();
                h.pend_pages = 0;
                h.pend_entries = 0;
                h.pred_pulled = 0;
                h.genesis_asked.clear();
                h.verified_live.clear();
            }
            h.phase = match phase {
                Phase::Head => Phase::PullAuthority,
                Phase::PullAuthority => Phase::PushAuthority,
                Phase::PushAuthority => Phase::Pending,
                Phase::Pending => Phase::Changes,
                Phase::Changes => Phase::PushBlobs,
                Phase::PushBlobs => Phase::Records,
                Phase::Records => Phase::Live,
                Phase::Live => Phase::LivePush,
                Phase::LivePush => Phase::PullBlobs,
                Phase::PullBlobs | Phase::Done => Phase::Done,
            };
            self.plan(home, phase)?;
        }
    }

    /// Abandon the pass with `home`: the request in flight (if any) is forgotten, the queue is
    /// emptied, what was pulled and verified is judged and taken, and the next
    /// [`Engine::exchange_next`] starts a new pass. The engine stays consistent: nothing
    /// unverified is held, no cursor moves past an object that was not taken, and a late answer
    /// to the forgotten request is refused as not outstanding.
    pub fn exchange_abort(&mut self, home: &str) -> Result<Report> {
        self.check_ready()?;
        let mut report = Report::default();
        {
            let h = self.home_mut(home);
            h.inflight = None;
            h.awaiting = None;
            h.provided = None;
            h.last_item = None;
            h.carried_call = false;
            h.queue.clear();
            h.phase = Phase::Head;
            h.ahead = None;
            h.halted = false;
            h.stalls = 0;
            h.verified_live.clear();
        }
        self.flush_pulled(home, &mut report)?;
        Ok(report)
    }

    fn make_request(
        &mut self,
        home: &str,
        endpoint: &str,
        ticket: u64,
        item: Queued,
        call: Option<String>,
    ) -> Request {
        let (tag, method, path, body, mut headers) = item.clone();
        let endpoint = match &tag {
            Tag::PeerHead { base, .. } => base.clone(),
            _ => endpoint.to_string(),
        };
        let h = self.home_mut(home);
        if matches!(tag, Tag::PeerHead { .. }) {
            // Another home's public head: no credential of this home goes with it.
        } else if let Some(c) = &call {
            headers.push(("Authorization".into(), format!("Colophon {c}")));
        } else if let Some(b) = h.bearer.clone() {
            headers.push(("Authorization".into(), format!("Bearer {b}")));
        }
        h.carried_call = call.is_some();
        h.last_item = Some(item);
        h.inflight = Some((ticket, tag));
        Request {
            ticket,
            home: home.to_string(),
            method,
            url: format!("{endpoint}{path}"),
            headers,
            body,
        }
    }

    fn enqueue(
        &mut self,
        home: &str,
        tag: Tag,
        method: Method,
        path: String,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) {
        self.exchange
            .homes
            .entry(home.to_string())
            .or_default()
            .queue
            .push_back((tag, method, path, body, headers));
    }
    fn home_mut(&mut self, home: &str) -> &mut Home {
        self.exchange.homes.entry(home.to_string()).or_default()
    }

    /// Queue the requests of `phase`.
    fn plan(&mut self, home: &str, phase: Phase) -> Result<()> {
        match phase {
            Phase::Head => {
                self.enqueue(home, Tag::Head, Method::Get, "/head".into(), vec![], vec![]);
                // With `headQuorum` above 1 a call needs other homes' heads too: they are public,
                // and fetched here, before anything that may need a call.
                if self.account.policy().head_quorum > 1 {
                    for peer in self.account.homes() {
                        if peer.id == home {
                            continue;
                        }
                        if let Some(base) = peer.endpoints.first().map(|e| base_of(e)) {
                            self.enqueue(
                                home,
                                Tag::PeerHead {
                                    peer: peer.id.clone(),
                                    base,
                                },
                                Method::Get,
                                "/head".into(),
                                vec![],
                                vec![],
                            );
                        }
                    }
                }
            }
            Phase::PullAuthority => {
                let after = self.account.head().0;
                self.enqueue(
                    home,
                    Tag::PullAuthority,
                    Method::Get,
                    format!("/authority?after={after}&limit={PAGE}"),
                    vec![],
                    vec![],
                );
            }
            Phase::PushAuthority => self.plan_push_authority(home)?,
            Phase::Pending => {
                let after = self.home_mut(home).pending_after;
                self.enqueue(
                    home,
                    Tag::PullPending,
                    Method::Get,
                    format!("/pending?after={after}&limit={PAGE}"),
                    vec![],
                    vec![],
                );
                self.plan_push_pending(home)?;
            }
            Phase::Changes => {
                let cursor = self.home_mut(home).changes_cursor.clone();
                let p = self.changes_path(cursor.as_deref());
                self.enqueue(home, Tag::Changes, Method::Get, p, vec![], vec![]);
            }
            Phase::PushBlobs => self.plan_push(home, true)?,
            Phase::Records => {
                self.plan_pull_records(home);
                self.plan_push(home, false)?;
                self.plan_predecessor(home);
            }
            Phase::Live => self.plan_live(home),
            Phase::LivePush => self.plan_live_push(home),
            Phase::PullBlobs => self.plan_pull_blobs(home)?,
            Phase::Done => {}
        }
        Ok(())
    }

    fn changes_path(&self, cursor: Option<&str>) -> String {
        let mut p = String::from("/changes?limit=500");
        if let Some(c) = cursor {
            p.push_str(&format!("&after={}", q(c)));
        }
        let mut ns = self.options.namespaces.clone();
        ns.sort();
        ns.dedup();
        for n in ns {
            p.push_str(&format!("&namespace={}", q(&n)));
        }
        p
    }

    fn plan_push_authority(&mut self, home: &str) -> Result<()> {
        let acked = self.home_mut(home).acked;
        let verified = self.account.head().0;
        if acked >= verified {
            return Ok(());
        }
        let branch = self.account.branch_digests().to_vec();
        let mut by_digest: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for e in &self.account.objects().entries {
            if let Ok(env) = crate::v05::history::envelope::AuthEnvelope::parse(
                e,
                crate::v05::encoding::bounds::AUTHORITY_BODY,
                crate::v05::encoding::bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) {
                by_digest.entry(env.digest).or_insert_with(|| e.clone());
            }
        }
        let mut seq = acked + 1;
        while seq <= verified {
            let mut entries: Vec<Value> = Vec::new();
            let from = seq;
            while seq <= verified && entries.len() < PAGE {
                let Some(b) = branch
                    .get((seq - 1) as usize)
                    .and_then(|d| by_digest.get(d))
                else {
                    break;
                };
                entries.push(serde_json::from_slice(b).map_err(|e| malformed(e.to_string()))?);
                seq += 1;
            }
            if entries.is_empty() {
                break;
            }
            let body = canonical(&json!({"from": from, "entries": entries, "receipts": []}))?;
            self.enqueue(
                home,
                Tag::PushAuthority { last: seq - 1 },
                Method::Post,
                "/authority".into(),
                body,
                json_post(),
            );
        }
        Ok(())
    }

    /// What `home` is owed (§14 `POST /pending`, §17.5 "Submitting"): the transitions and vetoes
    /// this account holds that it has not receipted, while they can still be receipted (300 s
    /// after their `issued`); a held veto of the succession (it names the successor's genesis,
    /// §15.1 step 4); and the receipts other homes made of them, so that every home holds the
    /// quorum's receipts.
    fn plan_push_pending(&mut self, home: &str) -> Result<()> {
        use crate::v05::encoding::bounds;
        let now = self.account.now_ms();
        // Only what is still pending: a transition with a recording entry on the branch is
        // history now, and its home needs no submission.
        let mut open: BTreeSet<String> = BTreeSet::new();
        for t in self.account.pending() {
            open.insert(t.digest.clone());
            open.extend(t.vetoes.iter().cloned());
        }
        let status =
            crate::v05::history::succession_status(self.account.record_authority().state());
        let succession_start = status
            .as_ref()
            .and_then(|s| s.timing.as_ref().map(|t| t.window_start_ms));
        let genesis = status.map(|s| s.genesis_digest);
        let sent = self.home_mut(home).sent_receipts.clone();
        let mut todo: Vec<(String, Vec<u8>, bool)> = Vec::new();
        let mut receipts: Vec<(String, Vec<u8>, String)> = Vec::new();
        for p in &self.account.objects().pending {
            let Ok(env) = crate::v05::history::envelope::AuthEnvelope::parse(
                p,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                true,
            ) else {
                continue;
            };
            match env.value.get("protocol").and_then(Value::as_str) {
                Some(proto @ ("colophon/transition/5" | "colophon/veto/5")) => {
                    // A veto of the succession is submitted only when it verifies against it
                    // (eligible signers, signatures and UV, inside its deadline): a forged one in
                    // the folder is never sent.
                    let succession_veto = proto == "colophon/veto/5"
                        && genesis.is_some()
                        && env.value.get("transition").and_then(Value::as_str)
                            == genesis.as_deref()
                        && crate::v05::history::succession::veto_is_valid(
                            self.account.record_authority().state(),
                            p,
                        );
                    if !(open.contains(&env.digest) || succession_veto) {
                        continue;
                    }
                    // A home refuses what it first sees 300 s after its `issued`.
                    let issued = env
                        .value
                        .get("issued")
                        .and_then(Value::as_str)
                        .and_then(crate::v05::encoding::parse_date);
                    if issued.is_none_or(|i| now > i.saturating_add(300_000)) {
                        continue;
                    }
                    if self.receipted_by(&env.digest).iter().any(|h| h == home) {
                        continue;
                    }
                    todo.push((env.digest, p.clone(), false));
                }
                Some("colophon/receipt/5") => {
                    let sha = super::hex(&super::sha(p));
                    if sent.contains(&sha) {
                        continue;
                    }
                    // Another home's receipt of an object this home may need: only a receipt
                    // a current home signed, of an object still pending or of the genesis.
                    let Some((object, by, _)) = self.receipt_fields(p) else {
                        continue;
                    };
                    if by == home
                        || !(open.contains(&object) || genesis.as_deref() == Some(object.as_str()))
                    {
                        continue;
                    }
                    // Its window must hold too: a receipt of a transition or veto (§13.5), or of
                    // the successor's genesis (§15.1 step 2).
                    let in_window = self.receipt_of(p).is_some()
                        || (genesis.as_deref() == Some(object.as_str())
                            && succession_start.is_some_and(|w0| {
                                crate::v05::history::succession::receipt_is_valid(
                                    self.account.record_authority().state(),
                                    p,
                                    &object,
                                    w0,
                                    i64::MAX,
                                )
                            }));
                    if !in_window {
                        continue;
                    }
                    receipts.push((object, p.clone(), sha));
                }
                _ => {}
            }
        }
        let mut items: Vec<(String, Vec<u8>, Option<String>)> =
            todo.into_iter().map(|(d, b, _)| (d, b, None)).collect();
        items.extend(receipts.into_iter().map(|(d, b, s)| (d, b, Some(s))));
        for chunk in items.chunks(16) {
            let objs: Vec<Value> = chunk
                .iter()
                .filter_map(|(_, b, _)| serde_json::from_slice(b).ok())
                .collect();
            let body = canonical(&json!({"objects": objs}))?;
            self.enqueue(
                home,
                Tag::PushPending {
                    digests: chunk.iter().map(|(d, _, _)| d.clone()).collect(),
                    receipts: chunk.iter().filter_map(|(_, _, s)| s.clone()).collect(),
                },
                Method::Post,
                "/pending".into(),
                body,
                json_post(),
            );
        }
        Ok(())
    }

    /// The history of a Swift predecessor, through its final entry, that this account's homes
    /// serve (§14): pulled when the account claims a Swift predecessor and holds less than the
    /// claim needs, and published to a home that does not list it.
    fn plan_predecessor(&mut self, home: &str) {
        let Some(s) =
            crate::v05::history::succession_status(self.account.record_authority().state())
        else {
            return;
        };
        if s.format != "colophon/swift-keyring/2" {
            return;
        }
        let through = s.head_seq.saturating_add(1);
        let held: BTreeSet<u64> = self
            .account
            .objects()
            .predecessor
            .iter()
            .filter_map(|b| entry_seq(b))
            .collect();
        let remote: BTreeSet<String> = self.home_mut(home).remote.keys().cloned().collect();
        let mut budget = MAX_PREDECESSOR_PER_PASS;
        // Pull the first entry this account lacks; the answer queues the next.
        if let Some(seq) = (1..=through).find(|n| !held.contains(n)) {
            self.enqueue(
                home,
                Tag::PullPredecessor { seq },
                Method::Get,
                format!("/predecessor/authority/{seq:08}.json"),
                vec![],
                vec![],
            );
        }
        // Publish what we hold and the home does not list.
        let entries: Vec<(u64, Vec<u8>)> = self
            .account
            .objects()
            .predecessor
            .iter()
            .filter_map(|b| entry_seq(b).map(|n| (n, b.clone())))
            .filter(|(n, _)| *n <= through)
            .collect();
        for (seq, bytes) in entries {
            if budget == 0 {
                break;
            }
            let path = format!("predecessor/authority/{seq:08}.json");
            if remote.contains(&path) {
                continue;
            }
            budget -= 1;
            self.enqueue(
                home,
                Tag::PutPredecessor { seq },
                Method::Put,
                format!("/predecessor/authority/{seq:08}.json"),
                bytes,
                vec![
                    ("If-None-Match".into(), "*".into()),
                    ("Content-Type".into(), "application/json".into()),
                ],
            );
        }
    }

    fn on_pull_predecessor(
        &mut self,
        home: &str,
        seq: u64,
        r: &Response,
        report: &mut Report,
    ) -> Result<()> {
        if r.status == 404 {
            return Ok(());
        }
        if r.status != 200 {
            report.faults.push(Fault::Status {
                home: home.into(),
                status: r.status,
            });
            return Ok(());
        }
        // One entry: it must be the entry the request named, and within the bound.
        if r.body.len() > crate::v05::encoding::bounds::AUTHORITY_BODY.saturating_mul(2)
            || entry_seq(&r.body) != Some(seq)
        {
            report.faults.push(Fault::BadObject {
                home: home.into(),
                code: "notAPredecessorEntry".into(),
            });
            return Ok(());
        }
        let before = self.account.objects().predecessor.len();
        // A home's forged entry is a fault of that home, never an error of the engine.
        if self
            .merge_objects(
                Objects {
                    predecessor: vec![r.body.clone()],
                    ..Default::default()
                },
                report,
                home,
            )
            .is_err()
        {
            report.faults.push(Fault::BadObject {
                home: home.into(),
                code: "notAPredecessorEntry".into(),
            });
            return Ok(());
        }
        if self.account.objects().predecessor.len() == before {
            return Ok(());
        }
        let path = format!("predecessor/authority/{seq:08}.json");
        if !self.ix.have.contains_key(&path) {
            self.ix.have.insert(
                path.clone(),
                Have {
                    sha: super::sha(&r.body),
                    version: None,
                },
            );
            self.ix.listing.insert(path.clone());
            report.store.push((path, r.body.clone()));
        }
        let h = self.home_mut(home);
        h.pred_pulled += 1;
        if h.pred_pulled >= MAX_PREDECESSOR_PER_PASS {
            report.faults.push(Fault::More {
                home: home.into(),
                feed: "predecessor".into(),
            });
            return Ok(());
        }
        let Some(s) =
            crate::v05::history::succession_status(self.account.record_authority().state())
        else {
            return Ok(());
        };
        if seq < s.head_seq.saturating_add(1) {
            self.enqueue(
                home,
                Tag::PullPredecessor { seq: seq + 1 },
                Method::Get,
                format!("/predecessor/authority/{:08}.json", seq + 1),
                vec![],
                vec![],
            );
        }
        Ok(())
    }

    /// Homes whose receipt of `object` the account holds and verifies (a current home's own
    /// signature on exactly that object, inside its window), plus those whose answer the engine
    /// verified itself: what §17.5 asks the host to show.
    pub fn receipted_by(&self, object: &str) -> Vec<String> {
        let mut out: BTreeSet<String> = self
            .exchange
            .receipted
            .get(object)
            .cloned()
            .unwrap_or_default();
        for p in &self.account.objects().pending {
            if let Some((o, by)) = self.receipt_of(p) {
                if o == object {
                    out.insert(by);
                }
            }
        }
        out.into_iter().collect()
    }

    /// Immutable paths the engine knows locally (listed or written) of a kind, sorted.
    fn local_paths(&self, blobs: bool) -> Vec<String> {
        self.ix
            .listing
            .iter()
            .chain(self.ix.have.keys())
            .filter(|p| match paths::classify(p) {
                Some(paths::Kind::Blob(_)) => blobs,
                Some(paths::Kind::Op { namespace, .. }) => {
                    !blobs && super::in_scope(&self.options, &namespace)
                }
                Some(paths::Kind::History) => !blobs,
                _ => false,
            })
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn plan_push(&mut self, home: &str, blobs: bool) -> Result<()> {
        let remote = self.home_mut(home).remote.clone();
        let chunks = if blobs {
            self.admitted_chunk_paths()?
        } else {
            BTreeSet::new()
        };
        for p in self.local_paths(blobs) {
            if remote.contains_key(&p) {
                continue;
            }
            let bytes = if blobs {
                match self.source.read_blob(&p) {
                    Ok(crate::blobs::BlobRead::Available(b)) => b,
                    _ => continue,
                }
            } else {
                match self.source.read(&p) {
                    Ok(b) => b,
                    Err(_) => continue,
                }
            };
            if bytes.len() > super::MAX_RECORD {
                continue;
            }
            // Only what the engine judged a valid object of this account is sent: an admitted
            // or held record (not junk), evidence whose signature verifies, a chunk an
            // admitted manifest names. A same-body twin that does not verify is never pushed.
            let ok = if blobs {
                chunks.contains(&p)
            } else if matches!(paths::classify(&p), Some(paths::Kind::History)) {
                self.history_is_valid(&p, &bytes)
            } else {
                self.account
                    .verdict_of(&p, &bytes)
                    .is_some_and(|c| !super::is_not_a_record(&c))
            };
            if !ok {
                continue;
            }
            let sha = super::hex(&super::sha(&bytes));
            let tag = if blobs {
                Tag::PutBlob { path: p.clone() }
            } else {
                Tag::PutRecord {
                    path: p.clone(),
                    sha,
                }
            };
            self.enqueue(
                home,
                tag,
                Method::Put,
                format!("/records/{p}"),
                bytes,
                vec![
                    ("If-None-Match".into(), "*".into()),
                    ("Content-Type".into(), "application/octet-stream".into()),
                ],
            );
        }
        Ok(())
    }

    /// Evidence under `history/` is a signed live-stamped header of a member: path, account and
    /// signature are checked here (one signature).
    fn history_is_valid(&self, path: &str, bytes: &[u8]) -> bool {
        let Ok((h, _)) = crate::v05::records::OperationHeader::parse(bytes) else {
            return false;
        };
        if h.live.is_none()
            || &h.account != self.account.id()
            || path
                != format!(
                    "history/{}/{}/{:012}-{}.json",
                    h.author, h.namespace, h.clock, h.id
                )
        {
            return false;
        }
        let Some(m) = self.account.record_authority().member(&h.author) else {
            return false;
        };
        crate::v05::signature::RawEnvelope::parse(
            bytes,
            crate::v05::encoding::bounds::OPERATION_HEADER_BODY,
            false,
        )
        .and_then(|e| crate::v05::records::OperationHeader::verify(&e, &m.request.signing))
        .is_ok()
    }

    /// The chunk paths the admitted blob manifests of the open namespaces name.
    fn admitted_chunk_paths(&self) -> Result<BTreeSet<String>> {
        let mut out = BTreeSet::new();
        for ns in self.account.record_authority().namespaces().to_vec() {
            if !super::in_scope(&self.options, &ns) || !self.account.is_namespace_open(&ns) {
                continue;
            }
            let mut after = String::new();
            while let crate::model::Outcome::Success { value, .. } =
                self.query(&ns, "blobs", json!({"limit": 1000, "after": after}))?
            {
                let page = value.get("value").cloned().unwrap_or(value);
                let rows = page["blobs"].as_array().cloned().unwrap_or_default();
                for r in &rows {
                    if let Some(d) = r["digest"].as_str() {
                        if let crate::model::Outcome::Success { value: m, .. } =
                            self.blob_manifest(&ns, d)?
                        {
                            out.extend(m.chunks.iter().map(|c| c.path.clone()));
                        }
                    }
                }
                match page["next"].as_str() {
                    Some(n) if !rows.is_empty() => after = n.to_string(),
                    _ => break,
                }
            }
        }
        Ok(out)
    }

    fn plan_pull_records(&mut self, home: &str) {
        let (remote, junk) = {
            let h = self.home_mut(home);
            (h.remote.clone(), h.junk.clone())
        };
        let mut queued = 0usize;
        for (p, sha) in remote {
            let want = matches!(
                paths::classify(&p),
                Some(paths::Kind::Op { namespace, .. }) if super::in_scope(&self.options, &namespace)
            );
            // Absent here, or present with other bytes than the home lists (0.3 §8.4 step 3:
            // a difference is pulled, judged and reported); never what this home already
            // served as junk.
            let differs = self
                .ix
                .have
                .get(&p)
                .is_none_or(|h| super::hex(&h.sha) != sha)
                || self.repull.contains(&p);
            if want && differs && !junk.contains(&sha) {
                if queued >= MAX_PULLS_PER_PASS {
                    self.home_mut(home).notes.push(Fault::More {
                        home: home.into(),
                        feed: "records".into(),
                    });
                    break;
                }
                queued += 1;
                self.enqueue(
                    home,
                    Tag::PullRecord {
                        path: p.clone(),
                        sha,
                    },
                    Method::Get,
                    format!("/records/{p}"),
                    vec![],
                    vec![],
                );
            }
        }
    }

    /// Pull the slots the home lists that differ from ours. Nothing is written here: a value
    /// goes to a slot only after the home's current one was pulled and verified
    /// ([`Engine::plan_live_push`]).
    fn plan_live(&mut self, home: &str) {
        let remote = self.home_mut(home).remote.clone();
        let mut queued = 0usize;
        for (p, sha) in &remote {
            if let Some(paths::Kind::Live { namespace, .. }) = paths::classify(p) {
                if !super::in_scope(&self.options, &namespace) {
                    continue;
                }
                let ours = self.ix.live_have.get(p).map(|h| super::hex(&h.sha));
                if ours.as_deref() != Some(sha.as_str()) {
                    if queued >= MAX_LIVE_PULLS_PER_PASS {
                        self.home_mut(home).notes.push(Fault::More {
                            home: home.into(),
                            feed: "live".into(),
                        });
                        break;
                    }
                    queued += 1;
                    self.enqueue(
                        home,
                        Tag::PullLive {
                            path: p.clone(),
                            sha: sha.clone(),
                        },
                        Method::Get,
                        format!("/records/{p}"),
                        vec![],
                        vec![],
                    );
                }
            }
        }
    }

    /// Replace the home's slot values with our heads, only where that is safe (0.3 §8.2): the
    /// home's current value was pulled and verified in this pass and our head's generation is
    /// strictly higher; `If-Match` carries the digest of the value verified. A slot the home
    /// does not hold is created. An older head never replaces a newer value.
    fn plan_live_push(&mut self, home: &str) {
        let (remote, verified) = {
            let h = self.home_mut(home);
            (h.remote.clone(), h.verified_live.clone())
        };
        let me = match self.account.me() {
            crate::v05::account::Standing::Member(m) => Some(m.member.id),
            _ => None,
        };
        let mine: Vec<(String, Vec<u8>, u64)> = self
            .account
            .live_heads()
            .iter()
            .filter(|h| Some(&h.author) == me.as_ref())
            .map(|h| (h.path.clone(), h.bytes.clone(), h.generation))
            .collect();
        for (p, bytes, generation) in mine {
            let sha = super::hex(&super::sha(&bytes));
            let cond = match remote.get(&p) {
                Some(r) if *r == sha => continue,
                Some(r) => match verified.get(&p) {
                    Some((g, vsha)) if vsha == r && generation > *g => {
                        ("If-Match".to_string(), format!("\"{r}\""))
                    }
                    _ => continue,
                },
                None => ("If-None-Match".to_string(), "*".to_string()),
            };
            self.enqueue(
                home,
                Tag::PutLive {
                    path: p.clone(),
                    sha,
                    generation,
                },
                Method::Put,
                format!("/records/{p}"),
                bytes,
                vec![
                    cond,
                    ("Content-Type".into(), "application/octet-stream".into()),
                ],
            );
        }
    }

    fn plan_pull_blobs(&mut self, home: &str) -> Result<()> {
        let remote = self.home_mut(home).remote.clone();
        let mut namespaces: Vec<String> = self.account.record_authority().namespaces().to_vec();
        namespaces.retain(|n| super::in_scope(&self.options, n));
        let mut seen = BTreeSet::new();
        for ns in namespaces {
            if !self.account.is_namespace_open(&ns) {
                continue;
            }
            for p in self.required_blob_fetches(&ns)? {
                if seen.insert(p.clone()) && remote.contains_key(&p) {
                    self.enqueue(
                        home,
                        Tag::PullBlob { path: p.clone() },
                        Method::Get,
                        format!("/records/{p}"),
                        vec![],
                        vec![],
                    );
                }
            }
        }
        Ok(())
    }

    /// Queue the pulls of the chunks of one blob this device does not hold and the home lists
    /// (an optional blob is fetched lazily, on first read: 0.3 §7.2). The next
    /// [`Engine::exchange_next`] sends them. Returns how many were queued.
    pub fn exchange_want_blob(
        &mut self,
        home: &str,
        namespace: &str,
        digest: &str,
    ) -> Result<usize> {
        self.check_ready()?;
        let manifest = match self.blob_manifest(namespace, digest)? {
            crate::model::Outcome::Success { value, .. } => value,
            crate::model::Outcome::Failure { detail, .. } => {
                return Err(crate::v05::Failure::Unavailable(detail))
            }
        };
        let remote = self.home_mut(home).remote.clone();
        let mut n = 0;
        for c in &manifest.chunks {
            let held = matches!(
                self.source.read_blob(&c.path),
                Ok(crate::blobs::BlobRead::Available(_))
            );
            if !held && remote.contains_key(&c.path) {
                self.enqueue(
                    home,
                    Tag::PullBlob {
                        path: c.path.clone(),
                    },
                    Method::Get,
                    format!("/records/{}", c.path),
                    vec![],
                    vec![],
                );
                n += 1;
            }
        }
        Ok(n)
    }

    // -----------------------------------------------------------------------------------------

    /// Consume the answer to the request with `ticket`. Everything the home sent is verified
    /// before it changes anything; faults are returned, never followed.
    pub fn exchange_answer(
        &mut self,
        home: &str,
        ticket: u64,
        response: Response,
    ) -> Result<Report> {
        self.check_ready()?;
        let tag = {
            let h = self
                .exchange
                .homes
                .get_mut(home)
                .ok_or_else(|| malformed("no pass with this home"))?;
            match h.inflight.take() {
                Some((t, tag)) if t == ticket => tag,
                other => {
                    h.inflight = other;
                    return Err(malformed("not the request outstanding for this home"));
                }
            }
        };
        let mut report = Report::default();
        let pulls = matches!(tag, Tag::PullRecord { .. });
        // A 401/403: a home that wants a call for this kind of request says so once; the
        // request is asked again with a fresh call. A request that carried a call and was
        // refused, or a public one, ends the pass.
        if let Tag::PeerHead { peer, .. } = &tag {
            self.home_mut(home).last_item = None;
            self.on_peer_head(peer, &response, &mut report)?;
            return Ok(report);
        }
        if matches!(response.status, 401 | 403) {
            let item = self.home_mut(home).last_item.take();
            let carried = self.home_mut(home).carried_call;
            if let (Some(item), false, false) = (item.clone(), carried, is_public(&tag)) {
                let h = self.home_mut(home);
                if item.1 == Method::Get {
                    h.require_read = true;
                } else {
                    h.require_write = true;
                }
                h.queue.push_front(item);
                return Ok(report);
            }
            let method = item.map_or(Method::Get, |i| i.1);
            let audience = self
                .account
                .homes()
                .into_iter()
                .find(|h| h.id == home)
                .and_then(|h| h.endpoints.first().map(|e| base_of(e)))
                .unwrap_or_default();
            report.faults.push(Fault::Unauthorized {
                home: home.into(),
                purpose: purpose_of(method),
                audience,
            });
            self.halt(home);
            if pulls {
                self.flush_pulled(home, &mut report)?;
            }
            return Ok(report);
        }
        match tag {
            Tag::Head => self.on_head(home, &response, &mut report)?,
            Tag::PeerHead { .. } => {}
            Tag::PullAuthority => self.on_pull_authority(home, &response, &mut report)?,
            Tag::PushAuthority { last } => {
                self.on_push_authority(home, last, &response, &mut report)?
            }
            Tag::PullPending => self.on_pull_pending(home, &response, &mut report)?,
            Tag::PushPending { digests, receipts } => {
                self.on_push_pending(home, &digests, &receipts, &response, &mut report)?
            }
            Tag::PullPredecessor { seq } => {
                self.on_pull_predecessor(home, seq, &response, &mut report)?
            }
            Tag::PutPredecessor { seq } => {
                if matches!(response.status, 200 | 201 | 412) {
                    self.home_mut(home).remote.insert(
                        format!("predecessor/authority/{seq:08}.json"),
                        String::new(),
                    );
                } else {
                    report.faults.push(Fault::Status {
                        home: home.into(),
                        status: response.status,
                    });
                }
            }
            Tag::Changes => self.on_changes(home, &response, &mut report)?,
            Tag::PullRecord { path, sha } => {
                self.on_pull_record(home, &path, &sha, &response, &mut report)?
            }
            Tag::PutRecord { path, sha } => {
                self.on_put(home, &path, &sha, false, &response, &mut report)
            }
            Tag::PutBlob { path } => self.on_put(home, &path, "", false, &response, &mut report),
            Tag::PullBlob { path } => self.on_pull_blob(home, &path, &response, &mut report),
            Tag::PullLive { path, sha } => {
                self.on_pull_live(home, &path, &sha, &response, &mut report)?
            }
            Tag::PutLive {
                path,
                sha,
                generation,
            } => {
                if matches!(response.status, 200 | 201) {
                    let g = self
                        .home_mut(home)
                        .home_live
                        .entry(path.clone())
                        .or_default();
                    *g = (*g).max(generation);
                }
                self.on_put(home, &path, &sha, true, &response, &mut report)
            }
            Tag::GenesisCheck { sha } => self.on_genesis(home, &sha, &response, &mut report)?,
        }
        report
            .faults
            .extend(std::mem::take(&mut self.home_mut(home).notes));
        // What the pulls of this pass fetched and verified is judged and taken on its own
        // merits once the last queued pull has been answered, whether that answer was a record,
        // a 404, junk or a wrong digest: one bad answer costs only itself (0.3 §8.4 step 3).
        if pulls
            && !self
                .home_mut(home)
                .queue
                .iter()
                .any(|q| matches!(q.0, Tag::PullRecord { .. }))
        {
            self.flush_pulled(home, &mut report)?;
        }
        Ok(report)
    }

    fn halt(&mut self, home: &str) {
        let h = self.home_mut(home);
        h.halted = true;
        h.queue.clear();
    }

    fn merge_objects(&mut self, objects: Objects, report: &mut Report, home: &str) -> Result<()> {
        if objects.entries.is_empty()
            && objects.pending.is_empty()
            && objects.heads.is_empty()
            && objects.predecessor.is_empty()
        {
            return Ok(());
        }
        let now = self.account.now_ms();
        let c = self.account.merge(
            Incoming {
                objects,
                records: Vec::new(),
            },
            now,
        )?;
        for (_, code) in &c.heads.refused {
            // A head that names an entry we do not hold yet is `unavailable`, not wrong: the
            // pass pulls the history first, and a head that is ahead of it waits for the next.
            if code == "unavailable" {
                continue;
            }
            report.faults.push(if code.contains("rollback") {
                Fault::Rollback { home: home.into() }
            } else if code.contains("fork") {
                Fault::Fork { home: home.into() }
            } else {
                Fault::BadObject {
                    home: home.into(),
                    code: code.clone(),
                }
            });
        }
        if c.foreign > 0 {
            report
                .faults
                .push(Fault::ForeignAccount { home: home.into() });
        }
        super::absorb(&mut report.changes, c);
        Ok(())
    }

    fn on_head(&mut self, home: &str, r: &Response, report: &mut Report) -> Result<()> {
        match r.status {
            404 => {}
            200 => {
                if r.body.len() > crate::v05::encoding::bounds::HEAD_BODY * 2 {
                    report.faults.push(Fault::Malformed {
                        home: home.into(),
                        why: "an oversized head".into(),
                    });
                    self.halt(home);
                    return Ok(());
                }
                self.judge_head(home, r.body.clone(), false, report)?;
            }
            s => report.faults.push(Fault::Status {
                home: home.into(),
                status: s,
            }),
        }
        Ok(())
    }

    /// Another home's head, fetched for a call's quorum: taken if the account accepts it, and
    /// otherwise reported against that home (never ending this home's pass). A head ahead of the
    /// held history is kept as held and judged again by the next verification.
    fn on_peer_head(&mut self, peer: &str, r: &Response, report: &mut Report) -> Result<()> {
        match r.status {
            200 if r.body.len() <= crate::v05::encoding::bounds::HEAD_BODY * 2 => {
                let o = Objects {
                    heads: vec![r.body.clone()],
                    ..Default::default()
                };
                self.merge_objects(o, report, peer)?;
            }
            200 => report.faults.push(Fault::Malformed {
                home: peer.into(),
                why: "an oversized head".into(),
            }),
            404 => {}
            s => report.faults.push(Fault::Status {
                home: peer.into(),
                status: s,
            }),
        }
        Ok(())
    }

    /// Judge the home's head. The head is fetched first in a pass, so that a call can be built
    /// for what follows (§12.3 step 4 needs fresh heads); a head that names an entry the account
    /// does not hold yet is not wrong (§13.3: the verifier fetches further), and is judged again
    /// once the authority pull is complete (`last`). Only then is it `HeadAhead`.
    fn judge_head(
        &mut self,
        home: &str,
        body: Vec<u8>,
        last: bool,
        report: &mut Report,
    ) -> Result<()> {
        let claimed = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| {
                crate::v05::encoding::decode_base64(v.get("body")?.as_str()?, 4_096)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            })
            .and_then(|b| b["authority"]["seq"].as_u64());
        let before = report.faults.len();
        let refused_before = report.changes.heads.refused.len();
        let accepted_before = report.changes.heads.accepted.len();
        let o = Objects {
            heads: vec![body.clone()],
            ..Default::default()
        };
        self.merge_objects(o, report, home)?;
        let ahead = report.changes.heads.refused[refused_before.min(report.changes.heads.refused.len())..]
            .iter()
            .any(|(_, c)| c == "unavailable");
        if ahead {
            if last {
                // The head names an entry the pass could not fetch: it is ahead of what the home
                // serves (§13.3: not wrong, but not to be hidden).
                report.faults.push(Fault::HeadAhead { home: home.into() });
            } else {
                self.home_mut(home).ahead = Some(body);
            }
        }
        if report.faults.len() == before {
            // A head the verifier accepted says how far the home holds our history; it bounds
            // what we push and is evidence of nothing else.
            let accepted = report.changes.heads.accepted
                [accepted_before.min(report.changes.heads.accepted.len())..]
                .iter()
                .any(|h| h == home);
            if let (Some(s), true) = (claimed, accepted) {
                let verified = self.account.head().0;
                let h = self.home_mut(home);
                h.acked = h.acked.max(s.min(verified));
            }
        } else if !report.faults[before..]
            .iter()
            .all(|f| matches!(f, Fault::HeadAhead { .. }))
        {
            self.halt(home);
        }
        Ok(())
    }

    fn on_pull_authority(&mut self, home: &str, r: &Response, report: &mut Report) -> Result<()> {
        let bad = |this: &mut Self, report: &mut Report, f: Fault| {
            report.faults.push(f);
            this.halt(home);
        };
        if r.status != 200 {
            bad(
                self,
                report,
                Fault::Status {
                    home: home.into(),
                    status: r.status,
                },
            );
            return Ok(());
        }
        let v = match body_json(r) {
            Ok(v) => v,
            Err(why) => {
                bad(
                    self,
                    report,
                    Fault::Malformed {
                        home: home.into(),
                        why,
                    },
                );
                return Ok(());
            }
        };
        let (entries, receipts) = match (
            envelopes(&v["entries"], PAGE),
            envelopes(&v["receipts"], PAGE * 8),
        ) {
            (Ok(e), Ok(r)) => (e, r),
            (Err(why), _) | (_, Err(why)) => {
                bad(
                    self,
                    report,
                    Fault::Malformed {
                        home: home.into(),
                        why,
                    },
                );
                return Ok(());
            }
        };
        let before = self.account.head();
        let held_before = self.account.objects().entries.len();
        let none_new = entries.is_empty();
        self.merge_objects(
            Objects {
                entries: entries.clone(),
                pending: receipts.clone(),
                ..Default::default()
            },
            report,
            home,
        )?;
        self.note_receipts(&receipts);
        let after = self.account.head();
        // Store what the verifier took (on its branch).
        let branch = self.account.branch_digests().to_vec();
        for e in &entries {
            let Ok(env) = crate::v05::history::envelope::AuthEnvelope::parse(
                e,
                crate::v05::encoding::bounds::AUTHORITY_BODY,
                crate::v05::encoding::bounds::AUTHORITY_BODY.saturating_mul(2),
                false,
            ) else {
                continue;
            };
            if let Some(i) = branch.iter().position(|d| *d == env.digest) {
                let path = format!("authority/{:08}.json", i + 1);
                if !self.ix.have.contains_key(&path) {
                    self.ix.have.insert(
                        path.clone(),
                        Have {
                            sha: super::sha(e),
                            version: None,
                        },
                    );
                    self.ix.listing.insert(path.clone());
                    report.store.push((path, e.clone()));
                }
            }
        }
        let moved = after.0 > before.0;
        let more = v["more"].as_bool().unwrap_or(false);
        if (!none_new || more) && !moved && self.account.objects().entries.len() == held_before {
            bad(
                self,
                report,
                Fault::NoProgress {
                    home: home.into(),
                    feed: "authority".into(),
                },
            );
            return Ok(());
        }
        if !more {
            if let Some(head) = self.home_mut(home).ahead.take() {
                self.judge_head(home, head, true, report)?;
            }
        }
        if more {
            if moved {
                // The cursor is our verified seq, never the home's claim.
                self.enqueue(
                    home,
                    Tag::PullAuthority,
                    Method::Get,
                    format!("/authority?after={}&limit={PAGE}", after.0),
                    vec![],
                    vec![],
                );
            } else {
                bad(
                    self,
                    report,
                    Fault::NoProgress {
                        home: home.into(),
                        feed: "authority".into(),
                    },
                );
            }
        }
        Ok(())
    }

    fn on_push_authority(
        &mut self,
        home: &str,
        last: u64,
        r: &Response,
        report: &mut Report,
    ) -> Result<()> {
        match r.status {
            200 => {
                if let Ok(v) = body_json(r) {
                    let mut o = Objects::default();
                    if let Ok(rs) = envelopes(&v["receipts"], PAGE * 8) {
                        o.pending = rs;
                    }
                    if !v["head"].is_null() {
                        if let Ok(h) = canonical(&v["head"]) {
                            o.heads.push(h);
                        }
                    }
                    let rs = o.pending.clone();
                    self.merge_objects(o, report, home)?;
                    self.note_receipts(&rs);
                }
                // A home's acknowledgement of a batch acknowledges every entry in it (§11.8).
                let verified = self.account.head().0;
                let h = self.home_mut(home);
                h.acked = h.acked.max(last.min(verified));
            }
            409 => {
                if let Ok(v) = body_json(r) {
                    if let Ok(h) = canonical(&v) {
                        self.merge_objects(
                            Objects {
                                heads: vec![h],
                                ..Default::default()
                            },
                            report,
                            home,
                        )?;
                    }
                }
                report.faults.push(Fault::Conflict {
                    home: home.into(),
                    path: "authority".into(),
                });
                self.halt(home);
            }
            421 => {
                let endpoints = body_json(r)
                    .ok()
                    .and_then(|v| v.get("endpoints").or(v.get("primary")).cloned())
                    .and_then(|v| v.as_array().cloned())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                report.faults.push(Fault::Redirect {
                    home: home.into(),
                    endpoints,
                });
                self.halt(home);
            }
            422 => {
                let code = body_json(r)
                    .ok()
                    .and_then(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .or_else(|| v["result"].as_str().map(str::to_string))
                    })
                    .unwrap_or_else(|| "refused".into());
                report.faults.push(Fault::Refused {
                    home: home.into(),
                    what: "authority".into(),
                    code,
                });
                self.halt(home);
            }
            s => {
                report.faults.push(Fault::Status {
                    home: home.into(),
                    status: s,
                });
                self.halt(home);
            }
        }
        Ok(())
    }

    /// A receipt counts when this account's current home signed it for exactly that object and
    /// its `received` lies in the object's window (§13.5: not before `issued`, at most 300 s
    /// after). Anything else is not a receipt of it.
    fn receipt_of(&self, e: &[u8]) -> Option<(String, String)> {
        let (object, by, received) = self.receipt_fields(e)?;
        // The object's `issued`: from the transition or veto the account holds.
        let issued = self.account.objects().pending.iter().find_map(|p| {
            let env = crate::v05::history::envelope::AuthEnvelope::parse(
                p,
                crate::v05::encoding::bounds::TRANSITION_ENVELOPE,
                crate::v05::encoding::bounds::TRANSITION_ENVELOPE,
                true,
            )
            .ok()?;
            (env.digest == object)
                .then(|| {
                    env.value
                        .get("issued")
                        .and_then(Value::as_str)
                        .and_then(crate::v05::encoding::parse_date)
                })
                .flatten()
        })?;
        (received >= issued && received <= issued.saturating_add(300_000)).then_some((object, by))
    }

    /// `(object, by, received)` of a receipt of this account that a current home signed.
    fn receipt_fields(&self, e: &[u8]) -> Option<(String, String, i64)> {
        let raw = crate::v05::signature::RawEnvelope::parse(
            e,
            crate::v05::encoding::bounds::HEAD_BODY,
            false,
        )
        .ok()?;
        let v = &raw.value;
        if v.get("protocol").and_then(Value::as_str) != Some("colophon/receipt/5")
            || v.get("account").and_then(Value::as_str) != Some(self.account.id().as_str())
        {
            return None;
        }
        let object = v.get("object").and_then(Value::as_str)?.to_string();
        let by = v.get("by").and_then(Value::as_str)?.to_string();
        let received =
            crate::v05::encoding::parse_date(v.get("received").and_then(Value::as_str)?)?;
        let key = self
            .account
            .record_authority()
            .state()
            .current_homes()
            .iter()
            .find(|m| m.request.member_id() == by)
            .map(|m| m.request.signing.clone())?;
        raw.verify(&key).ok()?;
        Some((object, by, received))
    }

    fn note_receipts(&mut self, receipts: &[Vec<u8>]) {
        for e in receipts {
            if let Some((object, by)) = self.receipt_of(e) {
                self.exchange
                    .receipted
                    .entry(object)
                    .or_default()
                    .insert(by);
            }
        }
    }

    /// How a pending object stands before it is held: `Some(false)` for a transition, a receipt
    /// or a succession veto that verifies as far as a holder can tell (the envelope's
    /// signatures against the keys the verified history names), `Some(true)` for an ordinary
    /// veto that waits for its transition to be held, `None` for what is not an object of this
    /// account's pending feed or does not verify. Nothing unverified is held.
    fn pending_standing(&self, b: &[u8]) -> Option<bool> {
        let env = crate::v05::history::envelope::AuthEnvelope::parse(
            b,
            crate::v05::encoding::bounds::TRANSITION_ENVELOPE,
            crate::v05::encoding::bounds::TRANSITION_ENVELOPE,
            true,
        )
        .ok()?;
        if env.value.get("account").and_then(Value::as_str) != Some(self.account.id().as_str()) {
            return None;
        }
        let state = self.account.record_authority().state();
        match env.value.get("protocol").and_then(Value::as_str)? {
            "colophon/transition/5" => crate::v05::history::check_pending_transition(state, b)
                .is_ok()
                .then_some(false),
            "colophon/receipt/5" => self.receipt_fields(b).map(|_| false),
            "colophon/veto/5" => {
                if crate::v05::history::succession::veto_is_valid(state, b) {
                    Some(false)
                } else {
                    Some(true)
                }
            }
            _ => None,
        }
    }

    /// Whether the held history verifies this ordinary veto of a held transition.
    fn veto_verifies(&self, b: &[u8]) -> bool {
        use crate::v05::encoding::bounds;
        let state = self.account.record_authority().state();
        let pending = &self.account.objects().pending;
        let Ok(v) = crate::v05::history::envelope::AuthEnvelope::parse(
            b,
            bounds::VETO_BODY,
            bounds::VETO_ENVELOPE,
            true,
        ) else {
            return false;
        };
        let Some(target) = v.value.get("transition").and_then(Value::as_str) else {
            return false;
        };
        for t in pending {
            let Ok(te) = crate::v05::history::envelope::AuthEnvelope::parse(
                t,
                bounds::TRANSITION_ENVELOPE,
                bounds::TRANSITION_ENVELOPE,
                true,
            ) else {
                continue;
            };
            if te.digest != target
                || te.value.get("protocol").and_then(Value::as_str) != Some("colophon/transition/5")
            {
                continue;
            }
            let issued = te
                .value
                .get("issued")
                .and_then(Value::as_str)
                .and_then(crate::v05::encoding::parse_date)
                .unwrap_or(0);
            if crate::v05::write::authority::choose_receipts(
                state, pending, &te.digest, issued, None,
            )
            .is_ok_and(|r| crate::v05::history::check_pending_veto(state, t, &r, b).is_ok())
            {
                return true;
            }
        }
        false
    }

    /// Hold the verified objects of one page of the pending feed, and hand the host the ones
    /// the account took. A transition, receipt or succession veto is taken first; a veto of a
    /// transition then needs that transition held. Objects that do not verify are dropped.
    fn take_pending(
        &mut self,
        objects: Vec<Vec<u8>>,
        home: &str,
        report: &mut Report,
    ) -> Result<()> {
        let mut first: Vec<Vec<u8>> = Vec::new();
        let mut vetoes: Vec<Vec<u8>> = Vec::new();
        for b in objects {
            match self.pending_standing(&b) {
                Some(false) => first.push(b),
                Some(true) => vetoes.push(b),
                None => {}
            }
        }
        let mut taken = first.clone();
        if !first.is_empty() {
            self.merge_objects(
                Objects {
                    pending: first.clone(),
                    ..Default::default()
                },
                report,
                home,
            )?;
        }
        let late: Vec<Vec<u8>> = vetoes
            .into_iter()
            .filter(|b| self.veto_verifies(b))
            .collect();
        if !late.is_empty() {
            self.merge_objects(
                Objects {
                    pending: late.clone(),
                    ..Default::default()
                },
                report,
                home,
            )?;
            taken.extend(late);
        }
        self.note_receipts(&taken);
        for b in &taken {
            if let Some(path) = verified_pending_path(b) {
                if !self.ix.have.contains_key(&path) {
                    self.ix.have.insert(
                        path.clone(),
                        Have {
                            sha: super::sha(b),
                            version: None,
                        },
                    );
                    self.ix.listing.insert(path.clone());
                    report.store.push((path, b.clone()));
                }
            }
        }
        Ok(())
    }

    fn on_pull_pending(&mut self, home: &str, r: &Response, report: &mut Report) -> Result<()> {
        if r.status != 200 {
            report.faults.push(Fault::Status {
                home: home.into(),
                status: r.status,
            });
            return Ok(());
        }
        let v = match body_json(r) {
            Ok(v) => v,
            Err(why) => {
                report.faults.push(Fault::Malformed {
                    home: home.into(),
                    why,
                });
                return Ok(());
            }
        };
        let Some(list) = v["objects"].as_array().filter(|l| l.len() <= PAGE) else {
            report.faults.push(Fault::Malformed {
                home: home.into(),
                why: "no objects page".into(),
            });
            return Ok(());
        };
        let after = self.home_mut(home).pending_after;
        let mut last = after;
        let mut fresh: Vec<Vec<u8>> = Vec::new();
        let mut entries = 0usize;
        let mut stop = false;
        for it in list {
            let (Some(seq), Some(env)) = (it["seq"].as_u64(), it.get("envelope")) else {
                report.faults.push(Fault::Malformed {
                    home: home.into(),
                    why: "an object without seq or envelope".into(),
                });
                stop = true;
                break;
            };
            if seq <= last {
                // Cursors are the home's own increasing integers and never reused.
                report.faults.push(Fault::NoProgress {
                    home: home.into(),
                    feed: "pending".into(),
                });
                stop = true;
                break;
            }
            last = seq;
            entries += 1;
            if let Ok(b) = canonical(env) {
                fresh.push(b);
            }
        }
        let (pages, total) = {
            let h = self.home_mut(home);
            h.pend_pages += 1;
            h.pend_entries += entries;
            (h.pend_pages, h.pend_entries)
        };
        let more = v["more"].as_bool().unwrap_or(false);
        let capped = pages >= MAX_PENDING_PAGES || total >= MAX_PENDING_ENTRIES;
        // The objects of this page are verified and held first (a page that fails to merge
        // leaves the cursor where it was), and only then does the cursor move past them: a
        // cursor never passes an object the engine has not taken.
        self.take_pending(fresh, home, report)?;
        if last > after {
            self.home_mut(home).pending_after = last;
        }
        if more && !stop {
            if last == after {
                report.faults.push(Fault::NoProgress {
                    home: home.into(),
                    feed: "pending".into(),
                });
            } else if capped {
                report.faults.push(Fault::More {
                    home: home.into(),
                    feed: "pending".into(),
                });
            } else {
                self.enqueue(
                    home,
                    Tag::PullPending,
                    Method::Get,
                    format!("/pending?after={last}&limit={PAGE}"),
                    vec![],
                    vec![],
                );
            }
        }
        Ok(())
    }

    fn on_push_pending(
        &mut self,
        home: &str,
        digests: &[String],
        receipts: &[String],
        r: &Response,
        report: &mut Report,
    ) -> Result<()> {
        if matches!(r.status, 200 | 422) {
            // A receipt the home took, or refused for good, is not sent to it again.
            let h = self.home_mut(home);
            if h.sent_receipts.len() < 16_384 {
                h.sent_receipts.extend(receipts.iter().cloned());
            }
        }
        match r.status {
            200 => {
                if let Ok(v) = body_json(r) {
                    if let Ok(rs) = envelopes(&v["receipts"], PAGE * 8) {
                        self.merge_objects(
                            Objects {
                                pending: rs.clone(),
                                ..Default::default()
                            },
                            report,
                            home,
                        )?;
                        self.note_receipts(&rs);
                    }
                }
            }
            422 => {
                let code = body_json(r)
                    .ok()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "refused".into());
                report.faults.push(Fault::Refused {
                    home: home.into(),
                    what: digests.join(","),
                    code,
                });
            }
            s => report.faults.push(Fault::Status {
                home: home.into(),
                status: s,
            }),
        }
        Ok(())
    }

    fn on_changes(&mut self, home: &str, r: &Response, report: &mut Report) -> Result<()> {
        if r.status == 410 {
            let h = self.home_mut(home);
            h.changes_cursor = None;
            h.remote.clear();
            h.pass_seen.clear();
            h.seen_cursors.clear();
            h.stalls += 1;
            let again = h.stalls <= 1;
            report.faults.push(Fault::CursorReset { home: home.into() });
            if again {
                let p = self.changes_path(None);
                self.enqueue(home, Tag::Changes, Method::Get, p, vec![], vec![]);
            }
            return Ok(());
        }
        if r.status != 200 {
            report.faults.push(Fault::Status {
                home: home.into(),
                status: r.status,
            });
            return Ok(());
        }
        let v = match body_json(r) {
            Ok(v) => v,
            Err(why) => {
                report.faults.push(Fault::Malformed {
                    home: home.into(),
                    why,
                });
                return Ok(());
            }
        };
        let Some(entries) = v["entries"].as_array().filter(|e| e.len() <= 1_000) else {
            report.faults.push(Fault::Malformed {
                home: home.into(),
                why: "no entries page".into(),
            });
            return Ok(());
        };
        let ours = self
            .ix
            .have
            .get("authority/00000001.json")
            .map(|h| super::hex(&h.sha));
        let mut fresh = 0usize;
        let mut ask: Vec<String> = Vec::new();
        let mut overflow = false;
        {
            let options = &self.options;
            let h = self.exchange.homes.entry(home.to_string()).or_default();
            h.pass_pages += 1;
            for e in entries {
                let (Some(p), Some(sha)) = (e["path"].as_str(), e["sha256"].as_str()) else {
                    if e["deleted"] != true {
                        report.faults.push(Fault::Malformed {
                            home: home.into(),
                            why: "an entry without path or digest".into(),
                        });
                    }
                    continue;
                };
                let Some(kind) = paths::classify(p) else {
                    continue;
                };
                // A record or slot of a namespace this replica does not read is never pulled
                // or compared with: it is not remembered.
                if let paths::Kind::Op { namespace, .. } | paths::Kind::Live { namespace, .. } =
                    &kind
                {
                    if !super::in_scope(options, namespace) {
                        continue;
                    }
                }
                if !crate::v05::encoding::is_lower_hex(sha, 64) {
                    continue;
                }
                // An entry repeated as it was is not news, whatever cursor carries it.
                if h.pass_seen.contains(&(p.to_string(), sha.to_string())) {
                    continue;
                }
                // The remembered set is full: this entry cannot be remembered, so the cursor
                // must not move past it. Reported, never skipped silently.
                if h.remote.len() >= super::MAX_LISTING && !h.remote.contains_key(p) {
                    overflow = true;
                    continue;
                }
                h.pass_seen.insert((p.to_string(), sha.to_string()));
                fresh += 1;
                h.pass_entries += 1;
                h.remote.insert(p.to_string(), sha.to_string());
                // 0.3 §8.4 step 2: a genesis under another envelope is checked once; if it is
                // the same body it is the same object, and never asked about again.
                if p == "authority/00000001.json"
                    && ours.as_deref() != Some(sha)
                    && !h.twins.contains(sha)
                    && h.genesis_asked.insert(sha.to_string())
                {
                    ask.push(sha.to_string());
                }
            }
        }
        if overflow {
            report.faults.push(Fault::More {
                home: home.into(),
                feed: "remote".into(),
            });
        }
        for sha in ask {
            self.enqueue(
                home,
                Tag::GenesisCheck { sha },
                Method::Get,
                "/records/authority/00000001.json".into(),
                vec![],
                vec![],
            );
        }
        let cursor = v["cursor"].as_str().map(str::to_string);
        let more = v["more"].as_bool().unwrap_or(false);
        // A cursor must strictly advance: one seen before this pass, or the one we sent, is a
        // replay.
        let h = self.home_mut(home);
        let repeated = cursor.as_ref().is_some_and(|c| {
            Some(c) == h.changes_cursor.as_ref() && more || h.seen_cursors.contains(c)
        });
        if let Some(c) = &cursor {
            h.seen_cursors.insert(c.clone());
        }
        if more && (fresh == 0 || repeated) {
            report.faults.push(Fault::NoProgress {
                home: home.into(),
                feed: "changes".into(),
            });
            self.halt(home);
            return Ok(());
        }
        if overflow {
            // Not past what could not be remembered: the next pass reads this page again.
            return Ok(());
        }
        if cursor.is_some() {
            h.changes_cursor = cursor.clone();
        }
        if more {
            if h.pass_pages >= MAX_CHANGE_PAGES || h.pass_entries >= MAX_CHANGE_ENTRIES {
                report.faults.push(Fault::More {
                    home: home.into(),
                    feed: "changes".into(),
                });
            } else {
                let p = self.changes_path(cursor.as_deref());
                self.enqueue(home, Tag::Changes, Method::Get, p, vec![], vec![]);
            }
        }
        Ok(())
    }

    fn on_genesis(
        &mut self,
        home: &str,
        sha: &str,
        r: &Response,
        report: &mut Report,
    ) -> Result<()> {
        let theirs = crate::v05::history::envelope::AuthEnvelope::parse(
            &r.body,
            crate::v05::encoding::bounds::AUTHORITY_BODY,
            crate::v05::encoding::bounds::AUTHORITY_BODY.saturating_mul(2),
            false,
        )
        .ok()
        .map(|e| e.digest);
        let ours = self.account.branch_digests().first().cloned();
        if r.status == 200 && theirs.is_some() && theirs == ours {
            // The same body under another envelope is the same object (§2.2): not news. It
            // changes nothing and queues nothing.
            let h = self.home_mut(home);
            if h.twins.len() < MAX_JUNK {
                h.twins.insert(sha.to_string());
            }
        } else {
            report
                .faults
                .push(Fault::ForeignAccount { home: home.into() });
            self.halt(home);
        }
        Ok(())
    }

    fn on_pull_record(
        &mut self,
        home: &str,
        path: &str,
        sha: &str,
        r: &Response,
        report: &mut Report,
    ) -> Result<()> {
        if r.status != 200 {
            report.faults.push(Fault::Status {
                home: home.into(),
                status: r.status,
            });
            return Ok(());
        }
        if super::hex(&super::sha(&r.body)) != sha || r.body.len() > super::MAX_RECORD {
            report.faults.push(Fault::Mismatch {
                home: home.into(),
                path: path.into(),
            });
            self.forget_listing(home, path);
            return Ok(());
        }
        // Judge before it is held: what is no record is dropped, its digest remembered so it
        // is not fetched again, and it never enters the account.
        if !self.account.would_hold(path, &r.body) {
            let h = self.home_mut(home);
            if h.junk.len() < MAX_JUNK {
                h.junk.insert(sha.to_string());
            }
            report.faults.push(Fault::BadObject {
                home: home.into(),
                code: "notARecord".into(),
            });
            self.forget_listing(home, path);
            return Ok(());
        }
        // A difference from what is held at the path is reported (0.3 §8.4 step 3): another
        // body is a conflict (we keep ours); the same body under another envelope is one object.
        if self.ix.have.contains_key(path) {
            let held = self.source.read(path).ok();
            let body_of = |b: &[u8]| {
                crate::v05::records::OperationHeader::parse(b)
                    .ok()
                    .map(|(h, _)| h.digest())
            };
            let local_is_record = held
                .as_ref()
                .and_then(|b| self.account.verdict_of(path, b))
                .is_some_and(|c| !super::is_not_a_record(&c));
            if local_is_record {
                if body_of(&r.body) != held.as_deref().and_then(body_of) {
                    report.faults.push(Fault::Conflict {
                        home: home.into(),
                        path: path.into(),
                    });
                }
                // Settled: a twin of a record we hold (another envelope of its body, or another
                // body at its path) is reported once and not fetched again every pass.
                let h = self.home_mut(home);
                if h.junk.len() < MAX_JUNK {
                    h.junk.insert(sha.to_string());
                }
                return Ok(());
            }
            // The local bytes are no record: the home's replace them.
            self.ix.have.remove(path);
        }
        // Held for the batch; `exchange_answer` judges the batch when it is full and when the
        // last queued pull has been answered, whatever that answer was.
        let batch = self.options.batch;
        let h = self.home_mut(home);
        h.pulled.push((path.to_string(), r.body.clone()));
        if h.pulled.len() >= batch {
            self.flush_pulled(home, report)?;
        }
        Ok(())
    }

    /// Judge the pulled records in one batch (one merge, not one per record) and hand the host
    /// the ones the account holds as records.
    fn flush_pulled(&mut self, home: &str, report: &mut Report) -> Result<()> {
        let pulled = std::mem::take(&mut self.home_mut(home).pulled);
        if pulled.is_empty() {
            return Ok(());
        }
        let now = self.account.now_ms();
        let c = self.account.merge(
            Incoming {
                objects: Objects::default(),
                records: pulled
                    .iter()
                    .map(|(p, b)| HeldRecord {
                        path: p.clone(),
                        bytes: b.clone(),
                    })
                    .collect(),
            },
            now,
        )?;
        super::absorb(&mut report.changes, c);
        for (path, bytes) in pulled {
            match self.account.verdict_of(&path, &bytes) {
                Some(code) if !super::is_not_a_record(&code) => {
                    self.repull.remove(&path);
                    self.ix.have.insert(
                        path.clone(),
                        Have {
                            sha: super::sha(&bytes),
                            version: None,
                        },
                    );
                    self.ix.listing.insert(path.clone());
                    report.store.push((path, bytes));
                }
                _ => {
                    report.faults.push(Fault::BadObject {
                        home: home.into(),
                        code: "notARecord".into(),
                    });
                    let h = self.home_mut(home);
                    if h.junk.len() < MAX_JUNK {
                        h.junk.insert(super::hex(&super::sha(&bytes)));
                    }
                }
            }
        }
        Ok(())
    }

    /// What a home listed for `path` did not hold up: forget it and the cursor that carried it,
    /// so the next pass lists the home again from the start instead of trusting its listing.
    fn forget_listing(&mut self, home: &str, path: &str) {
        let h = self.home_mut(home);
        h.remote.remove(path);
        h.changes_cursor = None;
    }

    fn on_put(
        &mut self,
        home: &str,
        path: &str,
        sha: &str,
        live: bool,
        r: &Response,
        report: &mut Report,
    ) {
        match r.status {
            200 | 201 => {
                let digest = if sha.is_empty() {
                    // A blob chunk's name is its digest.
                    path.strip_prefix("blobs/").unwrap_or_default().to_string()
                } else {
                    sha.to_string()
                };
                self.home_mut(home).remote.insert(path.to_string(), digest);
            }
            412 if live => report.faults.push(Fault::Race {
                home: home.into(),
                path: path.into(),
            }),
            412 => report.faults.push(Fault::Conflict {
                home: home.into(),
                path: path.into(),
            }),
            428 => report.faults.push(Fault::Refused {
                home: home.into(),
                what: path.into(),
                code: "a live slot needs a condition".into(),
            }),
            s => report.faults.push(Fault::Status {
                home: home.into(),
                status: s,
            }),
        }
    }

    fn on_pull_blob(&mut self, home: &str, path: &str, r: &Response, report: &mut Report) {
        let name = path.strip_prefix("blobs/").unwrap_or_default();
        if r.status != 200 {
            report.faults.push(Fault::Status {
                home: home.into(),
                status: r.status,
            });
            return;
        }
        // A chunk's name MUST be the SHA-256 of its bytes (0.3 §8.2, §8.4 step 5).
        if r.body.len() > 65_552 || super::hex(&super::sha(&r.body)) != name {
            report.faults.push(Fault::Mismatch {
                home: home.into(),
                path: path.into(),
            });
            self.forget_listing(home, path);
            return;
        }
        self.ix.listing.insert(path.to_string());
        report.store.push((path.to_string(), r.body.clone()));
    }

    fn on_pull_live(
        &mut self,
        home: &str,
        path: &str,
        sha: &str,
        r: &Response,
        report: &mut Report,
    ) -> Result<()> {
        if r.status != 200 {
            report.faults.push(Fault::Status {
                home: home.into(),
                status: r.status,
            });
            return Ok(());
        }
        if super::hex(&super::sha(&r.body)) != sha || r.body.len() > super::MAX_RECORD {
            report.faults.push(Fault::Mismatch {
                home: home.into(),
                path: path.into(),
            });
            return Ok(());
        }
        let cand = HeldRecord {
            path: path.to_string(),
            bytes: r.body.clone(),
        };
        // Verify before anything else: the value is a valid live record of this account, or it
        // is not a value to compare with.
        let valid = matches!(
            self.account.preview_live(cand.clone(), false)?,
            crate::v05::live::LiveVerdict::Current
                | crate::v05::live::LiveVerdict::Superseded
                | crate::v05::live::LiveVerdict::Retained
        );
        if !valid {
            report.faults.push(Fault::BadObject {
                home: home.into(),
                code: "notALiveValue".into(),
            });
            return Ok(());
        }
        let generation = crate::v05::records::OperationHeader::parse(&r.body)
            .map(|(h, _)| h.clock)
            .unwrap_or(0);
        let seen = {
            let h = self.home_mut(home);
            let seen = h.home_live.get(path).copied().unwrap_or(0);
            h.verified_live
                .insert(path.to_string(), (generation, sha.to_string()));
            let e = h.home_live.entry(path.to_string()).or_default();
            *e = (*e).max(generation);
            seen
        };
        // A home that serves a value lower than one it held before has gone back (a rollback of
        // *that home*). A home merely behind our own head (it has not seen our newer sample yet)
        // is not that: the value is verified and our head replaces it.
        if generation < seen {
            report.faults.push(Fault::Rollback { home: home.into() });
            return Ok(());
        }
        let below_witness = self
            .live_witness
            .get(path)
            .is_some_and(|(g, _)| generation < *g);
        if below_witness {
            return Ok(());
        }
        let c = self.apply_live(vec![cand])?;
        super::absorb(&mut report.changes, c);
        if self
            .account
            .live_heads()
            .iter()
            .any(|h| h.path == path && h.bytes == r.body)
        {
            // Only a verified current head is handed to the host to store over the slot.
            report.store.push((path.to_string(), r.body.clone()));
        }
        Ok(())
    }
}

/// The path of a pending object, or `None` for what the engine does not store.
fn verified_pending_path(env: &[u8]) -> Option<String> {
    let raw = crate::v05::signature::RawEnvelope::parse(
        env,
        crate::v05::encoding::bounds::TRANSITION_ENVELOPE,
        true,
    )
    .ok()?;
    match raw.value.get("protocol").and_then(Value::as_str)? {
        "colophon/transition/5" => Some(paths::pending_path(
            false,
            &crate::v05::encoding::digest(&raw.body),
        )),
        "colophon/veto/5" => Some(paths::pending_path(
            true,
            &crate::v05::encoding::digest(&raw.body),
        )),
        "colophon/receipt/5" => Some(paths::receipt_path(
            raw.value.get("object")?.as_str()?,
            raw.value.get("by")?.as_str()?,
        )),
        _ => None,
    }
}
