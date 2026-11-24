//! A sans-IO client of a home's stream (proposed for Colophon 0.6, `docs/colophon-0.6-stream.md`;
//! host contract in `docs/colophon-0.6-sync-stream.md`).
//!
//! The stream makes sync prompt; it never makes it trusted. **A frame is a hint.** A `change`,
//! `head` or `notice` frame, a `resync`, or a reconnect that may have missed something, asks the
//! host to run an ordinary exchange pass ([`StreamStep::Wake`], coalesced); that pass fetches and
//! verifies everything through `/changes` and record reads, exactly as a poll does. Nothing a
//! frame carries reaches the [`Account`](crate::v05::account::Account): this type holds no
//! engine, and the only thing it keeps from a frame is the opaque resume cursor.
//!
//! The host owns the socket and the clock. It asks [`HomeStream::next`] what to do; mints a ticket
//! with a signed `colophon.home.stream` call ([`Engine::stream_begin_call`], then
//! [`HomeStream::ticket_request`]); opens the WebSocket at the URL of [`StreamStep::Connect`];
//! feeds text frames to [`HomeStream::on_frame`], a refused upgrade to
//! [`HomeStream::on_refused`] and a close to [`HomeStream::on_closed`]. While
//! [`HomeStream::polling`] is true (the stream is down, refused, blocked or unsupported) the host
//! keeps its ordinary poll timer.
//!
//! Reconnection uses jittered exponential backoff, capped, reset by a good `hello`. The jitter is
//! a fixed function of the caller's seed ([`StreamConfig::seed`]): no randomness and no clock is
//! read here.
use super::exchange::{Method, Request, Response};
use super::{Engine, RecordSource};
use crate::v05::encoding::strict_parse;
use crate::v05::{malformed, require, Result};
use serde_json::{json, Value};

/// The stream protocol a `hello` must name.
pub const STREAM_PROTOCOL: &str = "colophon/home-stream/6";
/// The ticket route, relative to a home's base.
pub const TICKET_PATH: &str = "/stream/ticket";
/// How long a ticket lives on the home's clock.
pub const TICKET_LIFE_MS: i64 = 30_000;
/// A ticket older than this on our clock is not presented (clock skew and transit margin).
pub const TICKET_USE_MS: i64 = 20_000;
/// The largest server message read (the home's own message limit is 20,480 bytes).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// The largest session envelope a client sends (the home refuses larger with `tooLarge`).
pub const MAX_SESSION_FRAME: usize = 16_384;
/// The rolling window of [`StreamConfig::max_mints_per_day`].
pub const DAY_MS: i64 = 86_400_000;
/// Close code this client sends for a frame-number gap or another protocol violation.
pub const CLOSE_PROTOCOL: u16 = 1002;
/// Close code this client sends when the connection went silent past `idleMs`.
pub const CLOSE_IDLE: u16 = 1001;
/// How long a ticket call handed out by [`StreamStep::NeedTicketCall`] may stay unanswered (no
/// [`HomeStream::ticket_request`] or [`HomeStream::ticket_call_failed`]) before it counts as a
/// failed call and the stream backs off.
pub const SIGN_TIMEOUT_MS: i64 = 60_000;

/// The host's choices for one stream. `Default` gives the documented values.
#[derive(Clone, Debug)]
pub struct StreamConfig {
    /// The first reconnect delay (before jitter). Default 1 s.
    pub backoff_base_ms: i64,
    /// The largest reconnect delay. Default 60 s.
    pub backoff_cap_ms: i64,
    /// How long a wake waits for more frames before it is reported. Default 250 ms.
    pub coalesce_ms: i64,
    /// The seed of the jitter sequence (the host supplies randomness once).
    pub seed: u64,
    /// `pingMs` and `idleMs` to use when a `hello` names none. Defaults 20 s and 60 s.
    pub ping_ms: i64,
    /// See `ping_ms`.
    pub idle_ms: i64,
    /// How long a connection must stay live before its `hello` resets the backoff. A home that
    /// sends `hello` and closes at once keeps backing off. Default 60 s.
    pub stable_ms: i64,
    /// The most tickets minted (calls signed) in any `mint_window_ms`: past it the stream stays
    /// on polling ([`StreamStatus::Throttled`]) until the window clears or the history changes,
    /// so no home can make a device sign (or prompt for) calls without bound. Default 8.
    pub mint_budget: u32,
    /// See `mint_budget`. Default 10 minutes.
    pub mint_window_ms: i64,
    /// While live, a pass is woken at least this often whatever the frames say, so a silent but
    /// connected home is never worse than polling. [`Engine::stream_client`] lowers it to
    /// `recoveryDelay / 6` (§17.5) when that is shorter. Default 60 s.
    pub safety_poll_ms: i64,
    /// Consecutive tickets minted without a stable connection (one live for `stable_ms`) after
    /// which the stream is [`StreamStatus::Suspended`]: it mints nothing until the history
    /// changes, the host calls [`HomeStream::retry_now`], or `suspend_ms` passes. Default 16 (two
    /// spent ticket windows).
    pub suspend_after: u32,
    /// How long a suspension lasts at most. Default 6 hours.
    pub suspend_ms: i64,
    /// The most tickets signed in any rolling 24 hours, whatever the connections did: past it
    /// the stream is [`StreamStatus::Suspended`] until the oldest of them is a day old, the
    /// history changes, or [`HomeStream::retry_now`] grants `retry_allowance` more. Default 96.
    pub max_mints_per_day: u32,
    /// The extra tickets [`HomeStream::retry_now`] allows past `max_mints_per_day`. They count in
    /// the same day, so no number of calls lets more than `max_mints_per_day +
    /// retry_allowance` through in 24 hours. Default 8.
    pub retry_allowance: u32,
}
impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            backoff_base_ms: 1_000,
            backoff_cap_ms: 60_000,
            coalesce_ms: 250,
            seed: 0x9e37_79b9_7f4a_7c15,
            ping_ms: 20_000,
            idle_ms: 60_000,
            stable_ms: 60_000,
            mint_budget: 8,
            mint_window_ms: 600_000,
            safety_poll_ms: 60_000,
            suspend_after: 16,
            suspend_ms: 6 * 3_600_000,
            max_mints_per_day: 96,
            retry_allowance: 8,
        }
    }
}

/// Why the stream will not be tried again until the account's history changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// Stream authorization ended (close 1008, upgrade `refused:revoked`): revoked, suspended,
    /// sessions ended, expired, or lost the role.
    AccessEnded,
    /// The home's slot was released (`bye` `released`, `resume: false`, then the close).
    Released,
    /// The ticket mint was refused (401/403, with the home's result when it gave one).
    Refused(String),
    /// The home does not serve the stream (a 0.5 home, an unappointed one, another protocol).
    Unsupported,
}

/// Where the stream stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamStatus {
    /// Waiting to (re)connect at this time.
    Backoff(i64),
    /// A ticket is needed or being minted, or the socket is opening.
    Connecting,
    /// Open, `hello` received.
    Live,
    /// Closing at this client's request.
    Closing,
    /// Not tried again until the history changes ([`HomeStream::on_history`]).
    Blocked(Blocked),
    /// The ticket budget is spent: polling until this time, or until the history changes.
    Throttled(i64),
    /// Too many tickets in a row led to no stable connection: polling, and minting nothing until
    /// this time, a change of the history, or [`HomeStream::retry_now`].
    Suspended(i64),
}

/// What the host should do now. Its `Debug` never shows the ticket a `Connect` URL carries.
#[derive(Clone, PartialEq, Eq)]
pub enum StreamStep {
    /// Run an exchange pass with this home now (frames since the last wake are coalesced).
    Wake,
    /// Mint a ticket: build a call with [`Engine::stream_begin_call`], sign and finish it, and give
    /// the envelope to [`HomeStream::ticket_request`].
    NeedTicketCall,
    /// Open a WebSocket at `url` (`wss://` for an `https://` home), then report it with
    /// [`HomeStream::on_open`], [`HomeStream::on_refused`] or [`HomeStream::on_closed`].
    Connect {
        /// The URL, with the ticket and the resume cursor.
        url: String,
    },
    /// Send this text frame on the open socket.
    Send {
        /// The frame.
        text: String,
    },
    /// Close the socket with this code, then call [`HomeStream::on_closed`].
    Close {
        /// The close code.
        code: u16,
    },
    /// A ticket request or a socket is outstanding: wait for its answer or a frame.
    Waiting,
    /// Nothing to do until `until` (or until a frame or a host event arrives). `None`: nothing is
    /// scheduled (the stream is blocked); keep polling.
    Sleep {
        /// When to ask again.
        until: Option<i64>,
    },
}

impl std::fmt::Debug for StreamStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wake => f.write_str("Wake"),
            Self::NeedTicketCall => f.write_str("NeedTicketCall"),
            Self::Connect { url } => f
                .debug_struct("Connect")
                .field("url", &redact_url(url))
                .finish(),
            Self::Send { text } => f.debug_struct("Send").field("text", text).finish(),
            Self::Close { code } => f.debug_struct("Close").field("code", code).finish(),
            Self::Waiting => f.write_str("Waiting"),
            Self::Sleep { until } => f.debug_struct("Sleep").field("until", until).finish(),
        }
    }
}

/// `url` with the value of its `ticket` parameter replaced: a ticket is a bearer credential
/// until it is presented, and must not reach logs.
pub fn redact_url(url: &str) -> String {
    let Some((head, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let query: Vec<String> = query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some(("ticket", _)) => "ticket=<redacted>".to_string(),
            _ => kv.to_string(),
        })
        .collect();
    format!("{head}?{}", query.join("&"))
}

/// A ticket held by the client: compared and cloned, never shown by `Debug`.
#[derive(Clone, PartialEq, Eq)]
struct Secret(String);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// What a frame or a transport event told the host.
#[derive(Clone, Debug, PartialEq)]
pub enum StreamEvent {
    /// `hello` was received: the stream is live.
    Connected {
        /// The principal the home names.
        principal: String,
        /// When the stream's authorization expires (ms), if it does.
        expires_at: Option<i64>,
    },
    /// Persist this resume cursor (`None`: forget the saved one).
    Cursor(Option<String>),
    /// A `notice` frame, passed through (a wake is also scheduled: the pass reads `/pending`).
    Notice(Value),
    /// A `route` frame, passed through.
    Route(Value),
    /// A `session` frame: the server's message text, byte for byte, for the session layer.
    /// Not read here.
    Session(String),
    /// `subscribed` or `unsubscribed`, passed through.
    Ack(Value),
    /// An `error` frame: a client frame was refused; the connection stays open.
    Error {
        /// The error code.
        code: String,
        /// The `ref` it names, if any.
        reference: Option<String>,
    },
    /// The resume cursor could not be continued (`gone` or `tooFar`); a wake is scheduled.
    Resync {
        /// The home's reason.
        reason: String,
    },
    /// The home said it is about to close (`bye`).
    Bye {
        /// `restart` or `released`.
        reason: String,
    },
    /// The home broke the stream's rules (a gap in frame numbers, a malformed frame): the client
    /// closes and resumes.
    Violation(String),
    /// The stream is down; it is tried again at this time.
    Down {
        /// When the next attempt is due.
        retry_at: i64,
    },
    /// The stream will not be tried until the history changes.
    Blocked(Blocked),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Conn {
    /// Waiting until the time to start minting.
    Backoff(i64),
    /// A ticket call is needed.
    NeedTicket,
    /// A ticket call was handed out at this time and is being built or signed: no second one is
    /// handed out until it is answered or [`SIGN_TIMEOUT_MS`] passes.
    Signing(i64),
    /// The ticket request is out.
    Minting,
    /// A ticket, minted at this time.
    Ticket(Secret, i64),
    /// The socket is opening.
    Opening,
    /// Open; `hello` not yet received when `hello` is false.
    Open { hello: bool },
    /// Closing at our request, for this reason; whether the close was asked of the host yet.
    Closing(Closing, bool),
    /// Not tried until the history changes from `seq`.
    Blocked(Blocked, Option<u64>),
    /// The ticket budget is spent until this time.
    Throttled(i64),
    /// Suspended until this time (see [`StreamConfig::suspend_after`]).
    Suspended(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Closing {
    Protocol,
    Idle,
    Unsupported,
}

/// The stream client for one home.
#[derive(Clone, Debug)]
pub struct HomeStream {
    home: String,
    base: String,
    config: StreamConfig,
    conn: Conn,
    /// The resume cursor: the last `change` cursor handled (or a `hello` cursor with no replay).
    cursor: Option<String>,
    /// The cursor the connection was opened with.
    opened_after: Option<String>,
    attempts: u32,
    rng: u64,
    /// The next frame number expected on this connection.
    expect: u64,
    last_rx: i64,
    last_ping: i64,
    ping_ms: i64,
    idle_ms: i64,
    wake_at: Option<i64>,
    /// The home's last head and notice number seen (from `hello` or frames).
    head: Option<Value>,
    notice: u64,
    /// What `bye` said: `(resume, retryMs)`.
    bye: Option<(bool, Option<i64>)>,
    /// The history seq the host last reported.
    history: Option<u64>,
    /// Whether a `hello` was ever received (the first wakes a catch-up).
    ever_live: bool,
    next_ticket: u64,
    /// When this connection's `hello` came, until it has been live `stable_ms` (then the backoff
    /// resets and this is cleared).
    live_since: Option<i64>,
    /// When the tickets of the current window were asked for.
    mints: std::collections::VecDeque<i64>,
    /// When a pass was last woken while live (the safety poll counts from here).
    last_wake: i64,
    /// Tickets minted (or signed for) since the last stable connection.
    unstable: u32,
    /// The last `now` the host gave: a smaller one is a clock rollback.
    clock: Option<i64>,
    /// When the tickets of the last 24 hours were signed.
    day: std::collections::VecDeque<i64>,
    /// Tickets past the daily budget that `retry_now` still allows.
    extra: u32,
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

fn is_ticket(t: &str) -> bool {
    t.len() == 43
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn result_of(body: &[u8]) -> Option<String> {
    if body.len() > 4_096 {
        return None;
    }
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("result")?
        .as_str()
        .map(str::to_string)
}

fn retry_after(r: &Response) -> Option<i64> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, v)| v.trim().parse::<i64>().ok())
        .map(|s| s.clamp(0, 3_600) * 1_000)
}

impl HomeStream {
    /// A stream client for `home` at `base` (its endpoint), resuming from `cursor` (one saved
    /// from [`StreamEvent::Cursor`], or the exchange's own change cursor), ready to connect.
    pub fn new(home: &str, base: &str, config: StreamConfig, cursor: Option<String>) -> Self {
        let rng = config.seed | 1;
        Self {
            home: home.to_string(),
            base: base.trim_end_matches('/').to_string(),
            ping_ms: config.ping_ms,
            idle_ms: config.idle_ms,
            config,
            conn: Conn::NeedTicket,
            cursor,
            opened_after: None,
            attempts: 0,
            rng,
            expect: 1,
            last_rx: 0,
            last_ping: 0,
            wake_at: None,
            head: None,
            notice: 0,
            bye: None,
            history: None,
            ever_live: false,
            next_ticket: 1,
            live_since: None,
            mints: std::collections::VecDeque::new(),
            last_wake: 0,
            unstable: 0,
            clock: None,
            day: std::collections::VecDeque::new(),
            extra: 0,
        }
    }

    /// Tickets minted since the last stable connection (the circuit breaker's count).
    pub fn unstable_mints(&self) -> u32 {
        self.unstable
    }

    /// Take the host's `now`. Time should be monotonic milliseconds; when it goes back, every
    /// remembered instant after it is brought back to it and every deadline is due at once, so a
    /// rollback never delays the safety poll, the idle check, a backoff or a window clearing past
    /// its configured duration from the rollback point. The live safety poll is made due now.
    fn observe(&mut self, now: i64) -> i64 {
        if self.clock.is_some_and(|c| now < c) {
            let clamp = |t: &mut i64| *t = (*t).min(now);
            clamp(&mut self.last_rx);
            clamp(&mut self.last_ping);
            self.last_wake = now.saturating_sub(self.config.safety_poll_ms.max(0));
            if let Some(t) = self.live_since.as_mut() {
                clamp(t);
            }
            if let Some(t) = self.wake_at.as_mut() {
                clamp(t);
            }
            for t in self.mints.iter_mut().chain(self.day.iter_mut()) {
                clamp(t);
            }
            match &mut self.conn {
                Conn::Backoff(t) | Conn::Throttled(t) => clamp(t),
                Conn::Suspended(t) => {
                    *t = (*t).min(now.saturating_add(self.config.suspend_ms.max(DAY_MS)))
                }
                // A ticket's age can no longer be told: it is not presented.
                Conn::Ticket(_, at) => *at = i64::MIN,
                Conn::Signing(at) => clamp(at),
                _ => {}
            }
        }
        self.clock = Some(now);
        now
    }

    /// Credit the open connection's uptime: each whole `stable_ms` of it resets the backoff and
    /// takes one off the breaker's count (never below zero). A connection the home holds for one
    /// `stable_ms` and then drops earns one credit, not a fresh breaker.
    fn uptime(&mut self, now: i64) {
        let step = self.config.stable_ms.max(1);
        let Some(t) = self.live_since else { return };
        let whole = now.saturating_sub(t) / step;
        if whole <= 0 {
            return;
        }
        self.attempts = 0;
        self.unstable = self
            .unstable
            .saturating_sub(u32::try_from(whole).unwrap_or(u32::MAX));
        self.live_since = Some(t.saturating_add(whole.saturating_mul(step)));
    }

    /// A ticket was signed (or signing was attempted) at `now`.
    fn record_mint(&mut self, now: i64) {
        self.mints.push_back(now);
        self.day.push_back(now);
        self.unstable = self.unstable.saturating_add(1);
        let cap = usize::try_from(self.config.max_mints_per_day.max(1)).unwrap_or(usize::MAX);
        if self.day.len() > cap {
            self.extra = self.extra.saturating_sub(1);
        }
    }

    /// The configuration in force (after [`Engine::stream_client`] applied the account's floor).
    pub fn config(&self) -> &StreamConfig {
        &self.config
    }
    /// The home.
    pub fn home(&self) -> &str {
        &self.home
    }
    /// The resume cursor held now.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
    /// Reconnect attempts since a connection was last live for `stable_ms`.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Where the stream stands.
    pub fn status(&self) -> StreamStatus {
        match &self.conn {
            Conn::Backoff(t) => StreamStatus::Backoff(*t),
            Conn::NeedTicket
            | Conn::Signing(_)
            | Conn::Minting
            | Conn::Ticket(..)
            | Conn::Opening => {
                StreamStatus::Connecting
            }
            Conn::Open { hello: true } => StreamStatus::Live,
            Conn::Open { hello: false } => StreamStatus::Connecting,
            Conn::Closing(..) => StreamStatus::Closing,
            Conn::Blocked(b, _) => StreamStatus::Blocked(b.clone()),
            Conn::Throttled(t) => StreamStatus::Throttled(*t),
            Conn::Suspended(t) => StreamStatus::Suspended(*t),
        }
    }

    /// Whether the host's ordinary poll timer should run: always, unless the stream is live.
    pub fn polling(&self) -> bool {
        self.status() != StreamStatus::Live
    }

    /// When the host should call [`HomeStream::next`] again at the latest (monotonic ms), even
    /// if nothing happens meanwhile: the earliest of a coalesced wake, a backoff or budget
    /// window ending, a ticket call timing out, and, on an open socket, the idle check, the ping,
    /// the safety poll and the stability mark. `Some(now)`-or-earlier means at once (a ticket
    /// call or a connect is due); `None` means only an event (an answer, a frame, a close) or a
    /// change of history moves the stream.
    pub fn wake_at(&self) -> Option<i64> {
        let state = match &self.conn {
            Conn::Backoff(t) | Conn::Throttled(t) | Conn::Suspended(t) => Some(*t),
            Conn::NeedTicket => Some(i64::MIN),
            Conn::Signing(at) => Some(at.saturating_add(SIGN_TIMEOUT_MS)),
            Conn::Ticket(..) => Some(i64::MIN),
            Conn::Closing(_, false) => Some(i64::MIN),
            Conn::Open { hello } => {
                let idle = self.last_rx.saturating_add(self.idle_ms).saturating_add(1);
                if *hello {
                    let ping = self
                        .last_ping
                        .max(self.last_rx)
                        .saturating_add(self.ping_ms);
                    let safety = self.last_wake.saturating_add(self.config.safety_poll_ms);
                    let stable = self
                        .live_since
                        .map_or(i64::MAX, |t| t.saturating_add(self.config.stable_ms));
                    Some(idle.min(ping).min(safety).min(stable))
                } else {
                    Some(idle)
                }
            }
            Conn::Minting | Conn::Opening | Conn::Closing(_, true) | Conn::Blocked(..) => None,
        };
        match (state, self.wake_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The next thing to do at `now` (milliseconds on the host's clock).
    pub fn next(&mut self, now: i64) -> StreamStep {
        let now = self.observe(now);
        if self.wake_at.is_some_and(|t| now >= t) {
            self.wake_at = None;
            self.last_wake = now;
            return StreamStep::Wake;
        }
        if self.conn == (Conn::Open { hello: true }) {
            // A connection that stayed up long enough has earned a fresh backoff.
            self.uptime(now);
            // The safety poll: never longer than `safety_poll_ms` without a pass, whatever the
            // home sends (pongs and unknown frames keep a socket alive, not the sync).
            if now.saturating_sub(self.last_wake) >= self.config.safety_poll_ms {
                self.last_wake = now;
                return StreamStep::Wake;
            }
        }
        let wake = self.wake_at;
        let soonest = |t: Option<i64>| match (t, wake) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match self.conn.clone() {
            Conn::Backoff(t) | Conn::Throttled(t) if now >= t => self.ticket_step(now, wake),
            Conn::Backoff(t) | Conn::Throttled(t) => StreamStep::Sleep {
                until: soonest(Some(t)),
            },
            Conn::Suspended(t) if now >= t => {
                self.unstable = 0;
                self.ticket_step(now, wake)
            }
            Conn::Suspended(t) => StreamStep::Sleep {
                until: soonest(Some(t)),
            },
            Conn::NeedTicket => self.ticket_step(now, wake),
            Conn::Signing(at) if now.saturating_sub(at) >= SIGN_TIMEOUT_MS => {
                // The call was never answered: a signature may have been made, so it counts
                // like a mint, and the stream backs off.
                self.record_mint(now);
                let _ = self.down(now, None);
                self.next(now)
            }
            Conn::Signing(_) => StreamStep::Waiting,
            Conn::Closing(why, false) => {
                self.conn = Conn::Closing(why, true);
                StreamStep::Close {
                    code: match why {
                        Closing::Idle => CLOSE_IDLE,
                        Closing::Protocol | Closing::Unsupported => CLOSE_PROTOCOL,
                    },
                }
            }
            Conn::Minting | Conn::Opening | Conn::Closing(_, true) => StreamStep::Waiting,
            Conn::Ticket(_, at) if now.saturating_sub(at) > TICKET_USE_MS => {
                // Too old to present safely: mint another.
                self.ticket_step(now, wake)
            }
            Conn::Ticket(ticket, _) => {
                let scheme_base = if let Some(rest) = self.base.strip_prefix("https://") {
                    format!("wss://{rest}")
                } else if let Some(rest) = self.base.strip_prefix("http://") {
                    format!("ws://{rest}")
                } else {
                    self.base.clone()
                };
                let mut url = format!("{scheme_base}/stream?ticket={}", q(&ticket.0));
                if let Some(c) = &self.cursor {
                    url.push_str(&format!("&after={}", q(c)));
                }
                self.opened_after = self.cursor.clone();
                self.conn = Conn::Opening;
                StreamStep::Connect { url }
            }
            Conn::Open { hello } => {
                if now.saturating_sub(self.last_rx) > self.idle_ms {
                    self.conn = Conn::Closing(Closing::Idle, true);
                    return StreamStep::Close { code: CLOSE_IDLE };
                }
                if hello && now.saturating_sub(self.last_ping.max(self.last_rx)) >= self.ping_ms {
                    self.last_ping = now;
                    return StreamStep::Send {
                        text: json!({"type": "ping", "t": now}).to_string(),
                    };
                }
                let idle = self.last_rx.saturating_add(self.idle_ms).saturating_add(1);
                let ping = self
                    .last_ping
                    .max(self.last_rx)
                    .saturating_add(self.ping_ms);
                let safety = self.last_wake.saturating_add(self.config.safety_poll_ms);
                let stable = self
                    .live_since
                    .map_or(i64::MAX, |t| t.saturating_add(self.config.stable_ms));
                StreamStep::Sleep {
                    until: soonest(Some(if hello {
                        idle.min(ping).min(safety).min(stable)
                    } else {
                        idle
                    })),
                }
            }
            Conn::Blocked(..) => StreamStep::Sleep { until: wake },
        }
    }

    /// The ticket request for the call the host built ([`Engine::stream_begin_call`]): `POST
    /// {base}/stream/ticket` with no body. Answer it with [`HomeStream::on_ticket`].
    pub fn ticket_request(&mut self, call: &[u8], now: i64) -> Result<Request> {
        let now = self.observe(now);
        require(
            matches!(self.conn, Conn::NeedTicket | Conn::Signing(_)),
            "the stream is not waiting for a ticket call",
        )?;
        require(!call.is_empty() && call.len() <= 16_384, "a call is small")?;
        self.conn = Conn::Minting;
        self.record_mint(now);
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        Ok(Request {
            ticket,
            home: self.home.clone(),
            method: Method::Post,
            url: format!("{}{TICKET_PATH}", self.base),
            headers: vec![(
                "Authorization".into(),
                format!("Colophon {}", crate::v05::encoding::encode_base64url(call)),
            )],
            body: Vec::new(),
        })
    }

    /// The host could not build the ticket call (for example [`Engine::stream_begin_call`]
    /// answered `Unavailable` because the home's head is not fresh: run a pass, which fetches it).
    /// The stream backs off and asks again.
    pub fn ticket_call_failed(&mut self, now: i64) -> Vec<StreamEvent> {
        let now = self.observe(now);
        if !matches!(self.conn, Conn::NeedTicket | Conn::Signing(_)) {
            return Vec::new();
        }
        // A signature may have been asked for: it counts like a mint.
        self.record_mint(now);
        self.down(now, None)
    }

    /// The home's answer to the ticket request (or `None` when it could not be sent).
    pub fn on_ticket(&mut self, response: Option<&Response>, now: i64) -> Vec<StreamEvent> {
        let now = self.observe(now);
        if self.conn != Conn::Minting {
            return Vec::new();
        }
        let Some(r) = response else {
            return self.down(now, None);
        };
        match r.status {
            200 => {
                let v: Option<Value> = (r.body.len() <= 4_096)
                    .then(|| serde_json::from_slice(&r.body).ok())
                    .flatten();
                let ticket = v
                    .as_ref()
                    .and_then(|v| v.get("ticket"))
                    .and_then(Value::as_str)
                    .filter(|t| is_ticket(t));
                // The ticket is presented only at the documented path: a home cannot send it
                // elsewhere.
                let path_ok = v
                    .as_ref()
                    .and_then(|v| v.get("path"))
                    .and_then(Value::as_str)
                    .is_none_or(|p| p == "/stream");
                match (ticket, path_ok) {
                    (Some(t), true) => {
                        self.conn = Conn::Ticket(Secret(t.to_string()), now);
                        Vec::new()
                    }
                    _ => {
                        let mut out = vec![StreamEvent::Violation(
                            "a ticket answer not in the documented shape".into(),
                        )];
                        out.extend(self.down(now, None));
                        out
                    }
                }
            }
            401 | 403 => self.block(Blocked::Refused(
                result_of(&r.body).unwrap_or_else(|| r.status.to_string()),
            )),
            404 | 405 | 501 => self.block(Blocked::Unsupported),
            _ => self.down(now, retry_after(r)),
        }
    }

    /// The socket opened (101). Frames follow.
    pub fn on_open(&mut self, now: i64) {
        let now = self.observe(now);
        if self.conn == Conn::Opening {
            self.conn = Conn::Open { hello: false };
            self.expect = 1;
            self.last_rx = now;
            self.last_ping = now;
            self.bye = None;
        }
    }

    /// The home refused the upgrade with an HTTP answer.
    pub fn on_refused(&mut self, response: &Response, now: i64) -> Vec<StreamEvent> {
        let now = self.observe(now);
        if self.conn != Conn::Opening {
            return Vec::new();
        }
        let result = result_of(&response.body);
        match (response.status, result.as_deref()) {
            (403, Some("refused:revoked")) => self.block(Blocked::AccessEnded),
            (404, _) => self.block(Blocked::Unsupported),
            (429, _) | (503, _) => self.down(now, retry_after(response)),
            // An unknown, used or expired ticket, or anything else: mint another, backing off.
            _ => self.down(now, None),
        }
    }

    /// One text frame from the home.
    pub fn on_frame(&mut self, text: &str, now: i64) -> Vec<StreamEvent> {
        let now = self.observe(now);
        let hello_seen = match self.conn {
            Conn::Open { hello } => hello,
            _ => return Vec::new(),
        };
        if text.len() > MAX_MESSAGE {
            return self.violation("a message over the size bound");
        }
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return self.violation("a frame that is not JSON");
        };
        let (Some(kind), Some(n)) = (
            v.get("type").and_then(Value::as_str),
            v.get("n").and_then(Value::as_u64),
        ) else {
            return self.violation("a frame without type and n");
        };
        // Numbered from 1 with no gap: anything else means frames were lost.
        if n != self.expect {
            return self.violation("a gap in frame numbers");
        }
        self.expect += 1;
        self.last_rx = now;
        if !hello_seen && kind != "hello" {
            return self.violation("a first frame that is not hello");
        }
        let mut out = Vec::new();
        match kind {
            "hello" if hello_seen => return self.violation("a second hello"),
            "hello" => {
                if v.get("protocol").and_then(Value::as_str) != Some(STREAM_PROTOCOL) {
                    self.conn = Conn::Closing(Closing::Unsupported, false);
                    return vec![StreamEvent::Violation("another stream protocol".into())];
                }
                let limit = |k: &str, d: i64| {
                    v.get("limits")
                        .and_then(|l| l.get(k))
                        .and_then(Value::as_i64)
                        .filter(|x| *x > 0)
                        .unwrap_or(d)
                };
                self.ping_ms = limit("pingMs", self.config.ping_ms).clamp(1_000, 600_000);
                self.idle_ms = limit("idleMs", self.config.idle_ms)
                    .clamp(self.ping_ms.saturating_add(1_000), 1_200_000);
                self.conn = Conn::Open { hello: true };
                // The backoff resets only once this connection has stayed up `stable_ms`
                // (`next`, `on_closed`): a `hello` alone proves nothing.
                self.live_since = Some(now);
                self.last_wake = now;
                out.push(StreamEvent::Connected {
                    principal: v
                        .get("principal")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    expires_at: v.get("expiresAt").and_then(Value::as_i64),
                });
                let head = v.get("head").cloned().filter(|h| !h.is_null());
                let notice = v.get("notice").and_then(Value::as_u64).unwrap_or(0);
                // A first connection (or one with nothing to resume from) catches up; after
                // that, a head or notice that moved while we were away wakes a pass. Missed
                // changes arrive as the replay that follows (or a `resync`).
                if !self.ever_live
                    || self.opened_after.is_none()
                    || head != self.head
                    || notice > self.notice
                {
                    self.wake(now);
                }
                self.ever_live = true;
                self.head = head;
                self.notice = self.notice.max(notice);
                if self.opened_after.is_none() {
                    // No replay follows: the hello's cursor is where this connection resumes.
                    if let Some(c) = v.get("cursor").and_then(Value::as_str) {
                        self.cursor = Some(c.to_string());
                        out.push(StreamEvent::Cursor(self.cursor.clone()));
                    }
                }
            }
            "change" => {
                if let Some(c) = v.get("cursor").and_then(Value::as_str) {
                    if c.len() <= 256 {
                        self.cursor = Some(c.to_string());
                        out.push(StreamEvent::Cursor(self.cursor.clone()));
                    }
                }
                self.wake(now);
            }
            "head" => {
                self.head = Some(json!({"seq": v.get("seq"), "digest": v.get("digest")}));
                self.wake(now);
            }
            "notice" => {
                if let Some(x) = v.get("notice").and_then(Value::as_u64) {
                    self.notice = self.notice.max(x);
                }
                out.push(StreamEvent::Notice(v));
                self.wake(now);
            }
            "route" => out.push(StreamEvent::Route(v)),
            "session" => out.push(StreamEvent::Session(text.to_string())),
            "subscribed" | "unsubscribed" => out.push(StreamEvent::Ack(v)),
            "pong" => {}
            "error" => out.push(StreamEvent::Error {
                code: v
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                reference: v.get("ref").and_then(Value::as_str).map(str::to_string),
            }),
            "resync" => {
                let reason = v
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if reason == "gone" {
                    // The cursor names nothing the home can continue: forget it.
                    self.cursor = None;
                    out.push(StreamEvent::Cursor(None));
                }
                out.push(StreamEvent::Resync { reason });
                self.wake(now);
            }
            "bye" => {
                let resume = v.get("resume").and_then(Value::as_bool).unwrap_or(false);
                let retry = v
                    .get("retryMs")
                    .and_then(Value::as_i64)
                    .map(|r| r.clamp(0, 600_000));
                self.bye = Some((resume, retry));
                out.push(StreamEvent::Bye {
                    reason: v
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                });
            }
            // A client ignores frame types it does not know.
            _ => {}
        }
        out
    }

    /// The socket closed, with the close code when there was one (`None`: the transport failed,
    /// or the socket never opened).
    pub fn on_closed(&mut self, code: Option<u16>, now: i64) -> Vec<StreamEvent> {
        let now = self.observe(now);
        let ours = match &self.conn {
            Conn::Closing(c, _) => Some(*c),
            Conn::Open { .. } | Conn::Opening => None,
            _ => return Vec::new(),
        };
        let bye = self.bye.take();
        self.uptime(now);
        self.live_since = None;
        if let Some(c) = ours {
            return match c {
                Closing::Unsupported => self.block(Blocked::Unsupported),
                Closing::Protocol | Closing::Idle => self.down(now, None),
            };
        }
        match code {
            Some(1008) => self.block(Blocked::AccessEnded),
            // The home closes a released slot with `bye` `released` (`resume: false`) and 1001.
            // A bare 1001 is also RFC 6455 "going away", which proxies and load balancers send
            // when they restart: without the `bye` it is a drop, and the client resumes.
            _ if bye.is_some_and(|(resume, _)| !resume) => self.block(Blocked::Released),
            Some(1012) => {
                // A restart: come back after `retryMs`, not counted as a failure.
                let wait = bye.and_then(|(_, r)| r).unwrap_or(1_000);
                let jitter = self.jitter(self.config.backoff_base_ms);
                let at = now.saturating_add(wait).saturating_add(jitter);
                self.conn = Conn::Backoff(at);
                vec![StreamEvent::Down { retry_at: at }]
            }
            // 1000, 1009, 1011, 4008 (idle), 4013 (slow consumer), an abnormal close: reconnect
            // and resume, backing off.
            _ => self.down(now, None),
        }
    }

    /// The account's verified history is at `seq` (call it after every pass, and on open). A
    /// stream blocked by the home's judgement of our standing is tried again once it changes.
    pub fn on_history(&mut self, seq: u64) {
        // A new history is a new standing: the ticket budget starts again.
        if self.history.is_some_and(|h| h != seq) {
            self.mints.clear();
            self.day.clear();
            self.extra = 0;
            self.unstable = 0;
            if matches!(self.conn, Conn::Throttled(_) | Conn::Suspended(_)) {
                self.conn = Conn::NeedTicket;
            }
        }
        if let Conn::Blocked(_, at) = &mut self.conn {
            match *at {
                Some(a) if a != seq => {
                    self.conn = Conn::NeedTicket;
                    self.attempts = 0;
                }
                None => *at = Some(seq),
                Some(_) => {}
            }
        }
        self.history = Some(seq);
    }

    /// Try again now whatever the stream's state (for example on foreground entry after a long
    /// time, or when the network changed): a blocked or backing-off stream mints a new ticket.
    /// An open stream is left alone, and the 10-minute window still holds. It clears the
    /// breaker's count and allows `retry_allowance` tickets past the daily budget (counted in the
    /// same day, so a host that calls this from a timer by mistake still signs at most
    /// `max_mints_per_day + retry_allowance` a day). Call it on an explicit user action or on
    /// foreground entry, never from a timer.
    pub fn retry_now(&mut self) {
        self.unstable = 0;
        self.extra = self.config.retry_allowance;
        if matches!(
            self.conn,
            Conn::Backoff(_) | Conn::Blocked(..) | Conn::Suspended(_)
        ) {
            self.conn = Conn::NeedTicket;
        }
    }

    /// A `subscribe` frame for `(namespace, cell)` to send on the live socket.
    pub fn subscribe(&self, namespace: &str, cell: &str, id: Option<&str>) -> Result<String> {
        self.client_frame("subscribe", namespace, cell, id)
    }
    /// An `unsubscribe` frame.
    pub fn unsubscribe(&self, namespace: &str, cell: &str, id: Option<&str>) -> Result<String> {
        self.client_frame("unsubscribe", namespace, cell, id)
    }
    fn client_frame(&self, kind: &str, ns: &str, cell: &str, id: Option<&str>) -> Result<String> {
        require(
            self.status() == StreamStatus::Live,
            "the stream is not live",
        )?;
        require(
            id.is_none_or(|i| i.len() <= 64),
            "an id is at most 64 characters",
        )?;
        let mut v = json!({"type": kind, "namespace": ns, "cell": cell});
        if let Some(i) = id {
            v["id"] = json!(i);
        }
        Ok(v.to_string())
    }
    /// A `session` message carrying `frame` (the session codec's frame: one canonical JSON
    /// object, at most 16,384 bytes) to send on the live socket. The frame must be a strict JSON
    /// object and is otherwise not judged here; its text is carried verbatim, so the home and
    /// every receiver see the bytes the codec produced.
    pub fn session_frame(&self, frame: &str, id: Option<&str>) -> Result<String> {
        require(
            self.status() == StreamStatus::Live,
            "the stream is not live",
        )?;
        require(
            frame.len() <= MAX_SESSION_FRAME,
            "a session frame is at most 16,384 bytes",
        )?;
        require(
            id.is_none_or(|i| i.len() <= 64),
            "an id is at most 64 characters",
        )?;
        let parsed = strict_parse(frame.as_bytes())
            .map_err(|_| malformed("the session frame is not strict JSON"))?;
        require(parsed.is_object(), "the session frame is an object")?;
        let id = match id {
            Some(i) => format!(",\"id\":{}", Value::from(i)),
            None => String::new(),
        };
        Ok(format!("{{\"type\":\"session\"{id},\"frame\":{frame}}}"))
    }

    // ---------------------------------------------------------------------------------------

    /// Ask for a ticket call, unless the ticket budget of the window is spent: then stay on
    /// polling until the oldest mint leaves the window.
    fn ticket_step(&mut self, now: i64, wake: Option<i64>) -> StreamStep {
        // The daily budget, whatever the connections did.
        while self
            .day
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= DAY_MS)
        {
            self.day.pop_front();
        }
        let cap = usize::try_from(self.config.max_mints_per_day.max(1)).unwrap_or(usize::MAX);
        let ceiling = cap.saturating_add(usize::try_from(self.config.retry_allowance).unwrap_or(0));
        if self.day.len() >= ceiling || (self.day.len() >= cap && self.extra == 0) {
            // Until enough of the day's mints are a day old to be under the budget again.
            let until = self
                .day
                .get(self.day.len().saturating_sub(cap))
                .map_or(now, |t| t.saturating_add(DAY_MS))
                .max(now);
            self.conn = Conn::Suspended(until);
            return StreamStep::Sleep {
                until: Some(wake.map_or(until, |w| w.min(until))),
            };
        }
        if self.unstable >= self.config.suspend_after.max(1) {
            let until = now.saturating_add(self.config.suspend_ms.max(0));
            self.conn = Conn::Suspended(until);
            return StreamStep::Sleep {
                until: Some(wake.map_or(until, |w| w.min(until))),
            };
        }
        let window = self.config.mint_window_ms.max(1);
        while self
            .mints
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= window)
        {
            self.mints.pop_front();
        }
        let budget = usize::try_from(self.config.mint_budget.max(1)).unwrap_or(usize::MAX);
        if self.mints.len() >= budget {
            let until = self.mints.front().map_or(now, |t| t.saturating_add(window));
            self.conn = Conn::Throttled(until);
            return StreamStep::Sleep {
                until: Some(wake.map_or(until, |w| w.min(until))),
            };
        }
        // One ticket call at a time: until it is answered `next` waits.
        self.conn = Conn::Signing(now);
        StreamStep::NeedTicketCall
    }

    fn wake(&mut self, now: i64) {
        if self.wake_at.is_none() {
            self.wake_at = Some(now.saturating_add(self.config.coalesce_ms.max(0)));
        }
    }

    fn violation(&mut self, why: &str) -> Vec<StreamEvent> {
        self.conn = Conn::Closing(Closing::Protocol, false);
        vec![StreamEvent::Violation(why.into())]
    }

    fn block(&mut self, why: Blocked) -> Vec<StreamEvent> {
        self.conn = Conn::Blocked(why.clone(), self.history);
        vec![StreamEvent::Blocked(why)]
    }

    /// The stream failed: back off and try again. `at_least` is a delay the home asked for.
    fn down(&mut self, now: i64, at_least: Option<i64>) -> Vec<StreamEvent> {
        let delay = self.backoff().max(at_least.unwrap_or(0));
        self.attempts = self.attempts.saturating_add(1);
        let at = now.saturating_add(delay);
        self.conn = Conn::Backoff(at);
        vec![StreamEvent::Down { retry_at: at }]
    }

    /// The delay before the next attempt: `min(cap, base · 2^attempts)`, jittered to between half
    /// and all of it ("equal jitter").
    fn backoff(&mut self) -> i64 {
        let base = self.config.backoff_base_ms.max(1);
        let cap = self.config.backoff_cap_ms.max(base);
        let exp = base.saturating_mul(1_i64 << self.attempts.min(30));
        let full = exp.min(cap);
        let half = full / 2;
        let j = self.jitter(half.saturating_add(1));
        half.saturating_add(j)
    }

    /// A value in `0..bound` from the caller-seeded sequence (xorshift64).
    fn jitter(&mut self, bound: i64) -> i64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        let bound = u64::try_from(bound.max(1)).unwrap_or(1);
        i64::try_from(x % bound).unwrap_or(0)
    }
}

impl<S: RecordSource> Engine<S> {
    /// A stream client for `home`, at the home's first endpoint, resuming from `cursor`.
    pub fn stream_client(
        &self,
        home: &str,
        config: StreamConfig,
        cursor: Option<String>,
    ) -> Result<HomeStream> {
        let base = self
            .account
            .homes()
            .into_iter()
            .find(|h| h.id == home)
            .and_then(|h| h.endpoints.first().cloned())
            .ok_or_else(|| malformed("not a home of this account, or it names no endpoint"))?;
        let mut config = config;
        let floor = i64::try_from(self.account.policy().recovery_delay)
            .unwrap_or(i64::MAX / 1_000)
            .saturating_mul(1_000)
            / 6;
        if floor > 0 {
            config.safety_poll_ms = config.safety_poll_ms.min(floor);
        }
        let mut s = HomeStream::new(home, &base, config, cursor);
        s.on_history(self.account.head().0);
        Ok(s)
    }

    /// The call that mints a stream ticket at `home` (`colophon.home.stream`, bound to `POST
    /// {base}/stream/ticket` with no body), signed by this session's own `key`. The host signs
    /// its step, gets the envelope from [`Engine::finish_write`] (`artifact`; judged by the
    /// home's own rule first) and gives it to [`HomeStream::ticket_request`].
    pub fn stream_begin_call(
        &self,
        home: &str,
        key: &[u8],
        request_id: [u8; 32],
    ) -> Result<crate::v05::account::PendingAction> {
        self.check_ready()?;
        self.account.refuse_call_if_stopped()?;
        let audience = self
            .account
            .homes()
            .into_iter()
            .find(|h| h.id == home)
            .and_then(|h| {
                h.endpoints
                    .first()
                    .map(|e| e.trim_end_matches('/').to_string())
            })
            .ok_or_else(|| malformed("not a home of this account, or it names no endpoint"))?;
        let acked = self.exchange.acked(home);
        let call = crate::v05::account::HomeCall {
            audience,
            method: "POST".into(),
            path: TICKET_PATH.into(),
            body_sha256: super::hex(&super::sha(&[])),
            as_of: (acked > 0).then_some(acked),
        };
        self.account.begin_home_call(key, &call, request_id)
    }
}
