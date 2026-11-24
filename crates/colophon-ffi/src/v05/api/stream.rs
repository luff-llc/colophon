//! The 0.6 home stream client (`docs/colophon-0.6-stream.md`, host contract in
//! `docs/colophon-0.6-sync-stream.md`): the core's sans-IO `HomeStream` behind a handle.
//!
//! The host owns the WebSocket, the HTTP client and the clock; the handle only says what to do
//! next and takes what happened. Every policy (the ticket budget and its window, the breaker,
//! the daily cap, the backoff and its jitter, the safety poll, frame numbering) is the core's:
//! this file converts values and adds nothing. A frame is a hint: nothing it carries reaches the
//! engine, which still verifies everything through an ordinary exchange pass on `Wake`.
//!
//! The ticket is a bearer credential until it is presented. It is held inside the core; it
//! leaves only in the `url` of a `Connect` step, which the host must not log (`log_url` is the
//! same URL with the ticket redacted by the core's `redact_url`). Nothing here implements
//! `Debug`, and no error carries a ticket, a call or a frame.
use super::action::AccountAction;
use super::engine::AccountEngine;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::engine::exchange::{Method, Request, Response};
use colophon_core::v05::engine::stream as cs;

/// The largest close code (RFC 6455 codes are 16-bit).
const MAX_CLOSE_CODE: u32 = 65_535;
/// The largest text frame taken from the host: the core reads at most `MAX_MESSAGE` and treats
/// anything larger as a violation, so a larger argument is refused before it is copied.
const MAX_FRAME_ARG: usize = 1 << 20;
/// The most headers an answer may carry.
const MAX_HEADERS: usize = 256;

pub(crate) fn config_in(c: StreamConfig) -> cs::StreamConfig {
    cs::StreamConfig {
        backoff_base_ms: c.backoff_base_ms,
        backoff_cap_ms: c.backoff_cap_ms,
        coalesce_ms: c.coalesce_ms,
        seed: c.seed,
        ping_ms: c.ping_ms,
        idle_ms: c.idle_ms,
        stable_ms: c.stable_ms,
        mint_budget: c.mint_budget,
        mint_window_ms: c.mint_window_ms,
        safety_poll_ms: c.safety_poll_ms,
        suspend_after: c.suspend_after,
        suspend_ms: c.suspend_ms,
        max_mints_per_day: c.max_mints_per_day,
        retry_allowance: c.retry_allowance,
    }
}
pub(crate) fn config_out(c: &cs::StreamConfig) -> StreamConfig {
    StreamConfig {
        backoff_base_ms: c.backoff_base_ms,
        backoff_cap_ms: c.backoff_cap_ms,
        coalesce_ms: c.coalesce_ms,
        seed: c.seed,
        ping_ms: c.ping_ms,
        idle_ms: c.idle_ms,
        stable_ms: c.stable_ms,
        mint_budget: c.mint_budget,
        mint_window_ms: c.mint_window_ms,
        safety_poll_ms: c.safety_poll_ms,
        suspend_after: c.suspend_after,
        suspend_ms: c.suspend_ms,
        max_mints_per_day: c.max_mints_per_day,
        retry_allowance: c.retry_allowance,
    }
}

fn step_out(s: cs::StreamStep) -> StreamStep {
    let mut o = StreamStep {
        kind: StreamStepKind::Wake,
        url: None,
        log_url: None,
        text: None,
        code: None,
        until: None,
        wake_at: None,
    };
    match s {
        cs::StreamStep::Wake => {}
        cs::StreamStep::NeedTicketCall => o.kind = StreamStepKind::NeedTicketCall,
        cs::StreamStep::Connect { url } => {
            o.kind = StreamStepKind::Connect;
            o.log_url = Some(cs::redact_url(&url));
            o.url = Some(url);
        }
        cs::StreamStep::Send { text } => {
            o.kind = StreamStepKind::Send;
            o.text = Some(text);
        }
        cs::StreamStep::Close { code } => {
            o.kind = StreamStepKind::Close;
            o.code = Some(u32::from(code));
        }
        cs::StreamStep::Waiting => o.kind = StreamStepKind::Waiting,
        cs::StreamStep::Sleep { until } => {
            o.kind = StreamStepKind::Sleep;
            o.until = until;
        }
    }
    o
}

fn blocked_out(b: &cs::Blocked) -> (StreamBlockedKind, Option<String>) {
    match b {
        cs::Blocked::AccessEnded => (StreamBlockedKind::AccessEnded, None),
        cs::Blocked::Released => (StreamBlockedKind::Released, None),
        cs::Blocked::Refused(r) => (StreamBlockedKind::Refused, Some(r.clone())),
        cs::Blocked::Unsupported => (StreamBlockedKind::Unsupported, None),
    }
}

pub(crate) fn status_out(s: &cs::StreamStatus) -> StreamStatus {
    let mut o = StreamStatus {
        kind: StreamStatusKind::Connecting,
        until: None,
        blocked: None,
        refused: None,
    };
    match s {
        cs::StreamStatus::Backoff(t) => {
            o.kind = StreamStatusKind::Backoff;
            o.until = Some(*t);
        }
        cs::StreamStatus::Connecting => {}
        cs::StreamStatus::Live => o.kind = StreamStatusKind::Live,
        cs::StreamStatus::Closing => o.kind = StreamStatusKind::Closing,
        cs::StreamStatus::Blocked(b) => {
            o.kind = StreamStatusKind::Blocked;
            let (k, r) = blocked_out(b);
            o.blocked = Some(k);
            o.refused = r;
        }
        cs::StreamStatus::Throttled(t) => {
            o.kind = StreamStatusKind::Throttled;
            o.until = Some(*t);
        }
        cs::StreamStatus::Suspended(t) => {
            o.kind = StreamStatusKind::Suspended;
            o.until = Some(*t);
        }
    }
    o
}

fn event_out(e: cs::StreamEvent) -> StreamEvent {
    let mut o = StreamEvent {
        kind: StreamEventKind::Connected,
        principal: None,
        expires_at: None,
        cursor: None,
        json: None,
        text: None,
        code: None,
        reference: None,
        reason: None,
        retry_at: None,
        blocked: None,
        refused: None,
    };
    match e {
        cs::StreamEvent::Connected {
            principal,
            expires_at,
        } => {
            o.principal = Some(principal);
            o.expires_at = expires_at;
        }
        cs::StreamEvent::Cursor(c) => {
            o.kind = StreamEventKind::Cursor;
            o.cursor = c;
        }
        cs::StreamEvent::Notice(v) => {
            o.kind = StreamEventKind::Notice;
            o.json = Some(v.to_string());
        }
        cs::StreamEvent::Route(v) => {
            o.kind = StreamEventKind::Route;
            o.json = Some(v.to_string());
        }
        cs::StreamEvent::Session(t) => {
            o.kind = StreamEventKind::Session;
            o.text = Some(t);
        }
        cs::StreamEvent::Ack(v) => {
            o.kind = StreamEventKind::Ack;
            o.json = Some(v.to_string());
        }
        cs::StreamEvent::Error { code, reference } => {
            o.kind = StreamEventKind::Error;
            o.code = Some(code);
            o.reference = reference;
        }
        cs::StreamEvent::Resync { reason } => {
            o.kind = StreamEventKind::Resync;
            o.reason = Some(reason);
        }
        cs::StreamEvent::Bye { reason } => {
            o.kind = StreamEventKind::Bye;
            o.reason = Some(reason);
        }
        cs::StreamEvent::Violation(why) => {
            o.kind = StreamEventKind::Violation;
            o.reason = Some(why);
        }
        cs::StreamEvent::Down { retry_at } => {
            o.kind = StreamEventKind::Down;
            o.retry_at = Some(retry_at);
        }
        cs::StreamEvent::Blocked(b) => {
            o.kind = StreamEventKind::Blocked;
            let (k, r) = blocked_out(&b);
            o.blocked = Some(k);
            o.refused = r;
        }
    }
    o
}
fn events_out(v: Vec<cs::StreamEvent>) -> Vec<StreamEvent> {
    v.into_iter().map(event_out).collect()
}

fn request_out(r: Request) -> HttpRequest {
    HttpRequest {
        ticket: r.ticket,
        home: r.home,
        method: match r.method {
            Method::Get => HttpMethod::Get,
            Method::Post => HttpMethod::Post,
            Method::Put => HttpMethod::Put,
        },
        url: r.url,
        headers: r
            .headers
            .into_iter()
            .map(|(name, value)| Header { name, value })
            .collect(),
        body: r.body,
    }
}

fn answer_in(a: HttpAnswer) -> R<Response> {
    // A ticket answer or a refused upgrade is small; the core reads at most 4 KiB of either.
    bytes_ok(&a.body, 1 << 20, "a stream answer body")?;
    if a.headers.len() > MAX_HEADERS {
        return Err(AccountError::bound("too many headers"));
    }
    let status = u16::try_from(a.status).map_err(|_| AccountError::bound("an HTTP status"))?;
    Ok(Response {
        status,
        headers: a.headers.into_iter().map(|h| (h.name, h.value)).collect(),
        body: a.body,
    })
}

/// A stream client for one home. One per home; it holds no engine. Calls are serialized: a
/// second thread waits for the first.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct HomeStream {
    s: Cell<cs::HomeStream>,
}

impl HomeStream {
    pub(crate) fn wrap(s: cs::HomeStream) -> Self {
        Self { s: Cell::new(s) }
    }
    fn new_inner(
        home: String,
        base: String,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> R<Self> {
        guard(|| {
            if home.is_empty() || home.len() > 256 {
                return Err(AccountError::bound("a home ID is 1 to 256 bytes"));
            }
            if base.is_empty() || base.len() > 2_048 {
                return Err(AccountError::bound("a base URL is 1 to 2,048 bytes"));
            }
            if cursor.as_ref().is_some_and(|c| c.len() > 256) {
                return Err(AccountError::bound("a cursor is at most 256 bytes"));
            }
            Ok(Self::wrap(cs::HomeStream::new(
                &home,
                &base,
                config_in(config),
                cursor,
            )))
        })
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl HomeStream {
    /// What to do at `now_ms` (monotonic milliseconds on the host's clock).
    pub fn next(&self, now_ms: i64) -> Result<StreamStep, AccountError> {
        guard(|| {
            let mut s = self.s.lock()?;
            let mut o = step_out(s.next(now_ms));
            o.wake_at = s.wake_at().map(|w| w.max(now_ms));
            Ok(o)
        })
    }
    /// The ticket request for the call the host signed (`stream_begin_call`, then `finish`,
    /// whose `artifact` this is): `POST {base}/stream/ticket` with no body. Refused unless a
    /// `NeedTicketCall` step is outstanding.
    pub fn ticket_request(&self, call: Vec<u8>, now_ms: i64) -> Result<HttpRequest, AccountError> {
        guard(|| {
            bytes_ok(&call, 16_384, "a call")?;
            Ok(request_out(self.s.lock()?.ticket_request(&call, now_ms)?))
        })
    }
    /// The host could not build or sign the ticket call (for example the engine answered
    /// `Unavailable` before its first pass). The stream backs off and asks again.
    pub fn ticket_call_failed(&self, now_ms: i64) -> Result<Vec<StreamEvent>, AccountError> {
        guard(|| Ok(events_out(self.s.lock()?.ticket_call_failed(now_ms))))
    }
    /// The home's answer to the ticket request; none when it could not be sent.
    pub fn on_ticket(
        &self,
        answer: Option<HttpAnswer>,
        now_ms: i64,
    ) -> Result<Vec<StreamEvent>, AccountError> {
        guard(|| {
            let r = answer.map(answer_in).transpose()?;
            Ok(events_out(self.s.lock()?.on_ticket(r.as_ref(), now_ms)))
        })
    }
    /// The socket opened (101).
    pub fn on_open(&self, now_ms: i64) -> Result<(), AccountError> {
        guard(|| {
            self.s.lock()?.on_open(now_ms);
            Ok(())
        })
    }
    /// The home refused the upgrade with this HTTP answer.
    pub fn on_refused(
        &self,
        answer: HttpAnswer,
        now_ms: i64,
    ) -> Result<Vec<StreamEvent>, AccountError> {
        guard(|| {
            let r = answer_in(answer)?;
            Ok(events_out(self.s.lock()?.on_refused(&r, now_ms)))
        })
    }
    /// One text frame from the home, unchanged.
    pub fn on_frame(&self, text: String, now_ms: i64) -> Result<Vec<StreamEvent>, AccountError> {
        guard(|| {
            bytes_ok(text.as_bytes(), MAX_FRAME_ARG, "a stream frame")?;
            Ok(events_out(self.s.lock()?.on_frame(&text, now_ms)))
        })
    }
    /// The socket closed with `code`, or without one (none: the transport failed or the socket
    /// never opened).
    pub fn on_closed(
        &self,
        code: Option<u32>,
        now_ms: i64,
    ) -> Result<Vec<StreamEvent>, AccountError> {
        guard(|| {
            let code = code
                .map(|c| {
                    if c > MAX_CLOSE_CODE {
                        Err(AccountError::bound("a close code is at most 65535"))
                    } else {
                        Ok(c as u16)
                    }
                })
                .transpose()?;
            Ok(events_out(self.s.lock()?.on_closed(code, now_ms)))
        })
    }
    /// The account's verified history is at `seq` (`head_seq`): call it after every pass and on
    /// open. A blocked stream is tried again, and the ticket budget restarts, once it changes.
    pub fn on_history(&self, seq: u64) -> Result<(), AccountError> {
        guard(|| {
            self.s.lock()?.on_history(seq);
            Ok(())
        })
    }
    /// Try again now (foreground entry, a network change, an explicit user action; never from a
    /// timer). The core bounds what this allows.
    pub fn retry_now(&self) -> Result<(), AccountError> {
        guard(|| {
            self.s.lock()?.retry_now();
            Ok(())
        })
    }
    /// Where the stream stands.
    pub fn status(&self) -> Result<StreamStatus, AccountError> {
        guard(|| Ok(status_out(&self.s.lock()?.status())))
    }
    /// Whether the host's ordinary poll timer should run: always, unless the stream is live.
    pub fn polling(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.s.lock()?.polling()))
    }
    /// The resume cursor held now, to persist beside the exchange checkpoint.
    pub fn cursor(&self) -> Result<Option<String>, AccountError> {
        guard(|| Ok(self.s.lock()?.cursor().map(str::to_string)))
    }
    /// The configuration in force (after `stream_client` applied the account's floor).
    pub fn config(&self) -> Result<StreamConfig, AccountError> {
        guard(|| Ok(config_out(self.s.lock()?.config())))
    }
    /// The home.
    pub fn home(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.s.lock()?.home().to_string()))
    }
    /// Reconnect attempts since a connection was last live for `stable_ms`.
    pub fn attempts(&self) -> Result<u32, AccountError> {
        guard(|| Ok(self.s.lock()?.attempts()))
    }
    /// Tickets minted since the last stable connection (the breaker's count).
    pub fn unstable_mints(&self) -> Result<u32, AccountError> {
        guard(|| Ok(self.s.lock()?.unstable_mints()))
    }
    /// A `subscribe` frame for `(namespace, cell)` to send on the live socket.
    pub fn subscribe(
        &self,
        namespace: String,
        cell: String,
        id: Option<String>,
    ) -> Result<String, AccountError> {
        guard(|| Ok(self.s.lock()?.subscribe(&namespace, &cell, id.as_deref())?))
    }
    /// An `unsubscribe` frame.
    pub fn unsubscribe(
        &self,
        namespace: String,
        cell: String,
        id: Option<String>,
    ) -> Result<String, AccountError> {
        guard(|| {
            Ok(self
                .s
                .lock()?
                .unsubscribe(&namespace, &cell, id.as_deref())?)
        })
    }
    /// A `session` message carrying `frame`, a sealed session frame's JSON text exactly as the
    /// endpoint produced it (a `Send` effect's bytes, at most 16,384), to send on the live
    /// socket. The frame is carried verbatim: the message is `{"type":"session",["id":…,]"frame":`
    /// followed by those bytes and `}`.
    pub fn session_frame(&self, frame: String, id: Option<String>) -> Result<String, AccountError> {
        guard(|| {
            bytes_ok(frame.as_bytes(), cs::MAX_SESSION_FRAME, "a session frame")?;
            Ok(self.s.lock()?.session_frame(&frame, id.as_deref())?)
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl HomeStream {
    /// A stream client for `home` at `base` (its endpoint), resuming from `cursor` (one saved
    /// from a `Cursor` event). An application normally uses `AccountEngine.stream_client`, which
    /// takes the base from the account and applies its safety-poll floor.
    #[uniffi::constructor]
    pub fn new(
        home: String,
        base: String,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::new_inner(home, base, config, cursor).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl HomeStream {
    /// A stream client for `home` at `base`, resuming from `cursor`.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        home: String,
        base: String,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> Result<HomeStream, AccountError> {
        Self::new_inner(home, base, config, cursor)
    }
}

/// The documented stream configuration (core `StreamConfig::default`).
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn stream_default_config() -> StreamConfig {
    config_out(&cs::StreamConfig::default())
}

/// `url` with its `ticket` parameter redacted (core `redact_url`), for logs.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn stream_redact_url(url: String) -> String {
    cs::redact_url(&url)
}

impl AccountEngine {
    fn stream_client_inner(
        &self,
        home: String,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> R<HomeStream> {
        guard(|| {
            if cursor.as_ref().is_some_and(|c| c.len() > 256) {
                return Err(AccountError::bound("a cursor is at most 256 bytes"));
            }
            let s = self.run(|e| Ok(e.stream_client(&home, config_in(config), cursor)?))?;
            Ok(HomeStream::wrap(s))
        })
    }
    fn stream_call_inner(&self, home: String, key: Vec<u8>, entropy: Vec<u8>) -> R<AccountAction> {
        let mut entropy = entropy;
        let r = guard(|| {
            let sd = super::engine::seeds32(&entropy, 1)?;
            self.ensure_live()?;
            let p = self.run(|e| Ok(e.stream_begin_call(&home, &key, sd[0])?))?;
            Ok(AccountAction::ready(p, self.owner, ActionKind::Call))
        });
        wipe(&mut entropy);
        r
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// A stream client for `home`, at the home's first endpoint, resuming from `cursor`; the
    /// safety poll is lowered to the account's `recoveryDelay / 6` when that is shorter, and the
    /// client starts at the verified history's seq.
    pub fn stream_client(
        &self,
        home: String,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> Result<std::sync::Arc<HomeStream>, AccountError> {
        self.stream_client_inner(home, config, cursor)
            .map(std::sync::Arc::new)
    }
    /// Prepare the `colophon.home.stream` call that mints a ticket at `home`, signed by this
    /// session's own `key`. 32 bytes of entropy (the request ID). `finish` judges it by the home's
    /// own rule and returns the envelope as `artifact`, for `HomeStream.ticket_request`. Before
    /// the first pass with the home this is `Unavailable` (no fresh head): call
    /// `ticket_call_failed`.
    pub fn stream_begin_call(
        &self,
        home: String,
        key: Vec<u8>,
        entropy: Vec<u8>,
    ) -> Result<std::sync::Arc<AccountAction>, AccountError> {
        self.stream_call_inner(home, key, entropy)
            .map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// A stream client for `home`, at the home's first endpoint, resuming from `cursor`.
    pub fn stream_client(
        &self,
        home: String,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> Result<HomeStream, AccountError> {
        self.stream_client_inner(home, config, cursor)
    }
    /// Prepare the `colophon.home.stream` call that mints a ticket at `home`. 32 bytes of
    /// entropy. `finish` returns the envelope as `artifact`.
    pub fn stream_begin_call(
        &self,
        home: String,
        key: Vec<u8>,
        entropy: Vec<u8>,
    ) -> Result<AccountAction, AccountError> {
        self.stream_call_inner(home, key, entropy)
    }
}
