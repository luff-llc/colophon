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
/// Close code this client sends for a frame-number gap or another protocol violation.
pub const CLOSE_PROTOCOL: u16 = 1002;
/// Close code this client sends when the connection went silent past `idleMs`.
pub const CLOSE_IDLE: u16 = 1001;

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
}

/// What the host should do now.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The ticket request is out.
    Minting,
    /// A ticket, minted at this time.
    Ticket(String, i64),
    /// The socket is opening.
    Opening,
    /// Open; `hello` not yet received when `hello` is false.
    Open { hello: bool },
    /// Closing at our request, for this reason; whether the close was asked of the host yet.
    Closing(Closing, bool),
    /// Not tried until the history changes from `seq`.
    Blocked(Blocked, Option<u64>),
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
        }
    }

    /// The home.
    pub fn home(&self) -> &str {
        &self.home
    }
    /// The resume cursor held now.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
    /// Reconnect attempts since the last good `hello`.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Where the stream stands.
    pub fn status(&self) -> StreamStatus {
        match &self.conn {
            Conn::Backoff(t) => StreamStatus::Backoff(*t),
            Conn::NeedTicket | Conn::Minting | Conn::Ticket(..) | Conn::Opening => {
                StreamStatus::Connecting
            }
            Conn::Open { hello: true } => StreamStatus::Live,
            Conn::Open { hello: false } => StreamStatus::Connecting,
            Conn::Closing(..) => StreamStatus::Closing,
            Conn::Blocked(b, _) => StreamStatus::Blocked(b.clone()),
        }
    }

    /// Whether the host's ordinary poll timer should run: always, unless the stream is live.
    pub fn polling(&self) -> bool {
        self.status() != StreamStatus::Live
    }

    /// The next thing to do at `now` (milliseconds on the host's clock).
    pub fn next(&mut self, now: i64) -> StreamStep {
        if self.wake_at.is_some_and(|t| now >= t) {
            self.wake_at = None;
            return StreamStep::Wake;
        }
        let wake = self.wake_at;
        let soonest = |t: Option<i64>| match (t, wake) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match self.conn.clone() {
            Conn::Backoff(t) if now >= t => {
                self.conn = Conn::NeedTicket;
                StreamStep::NeedTicketCall
            }
            Conn::Backoff(t) => StreamStep::Sleep {
                until: soonest(Some(t)),
            },
            Conn::NeedTicket => StreamStep::NeedTicketCall,
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
            Conn::Ticket(_, at) if now - at > TICKET_USE_MS => {
                // Too old to present safely: mint another.
                self.conn = Conn::NeedTicket;
                StreamStep::NeedTicketCall
            }
            Conn::Ticket(ticket, _) => {
                let scheme_base = if let Some(rest) = self.base.strip_prefix("https://") {
                    format!("wss://{rest}")
                } else if let Some(rest) = self.base.strip_prefix("http://") {
                    format!("ws://{rest}")
                } else {
                    self.base.clone()
                };
                let mut url = format!("{scheme_base}/stream?ticket={}", q(&ticket));
                if let Some(c) = &self.cursor {
                    url.push_str(&format!("&after={}", q(c)));
                }
                self.opened_after = self.cursor.clone();
                self.conn = Conn::Opening;
                StreamStep::Connect { url }
            }
            Conn::Open { hello } => {
                if now - self.last_rx > self.idle_ms {
                    self.conn = Conn::Closing(Closing::Idle, true);
                    return StreamStep::Close { code: CLOSE_IDLE };
                }
                if hello && now - self.last_ping.max(self.last_rx) >= self.ping_ms {
                    self.last_ping = now;
                    return StreamStep::Send {
                        text: json!({"type": "ping", "t": now}).to_string(),
                    };
                }
                let idle = self.last_rx + self.idle_ms + 1;
                let ping = self.last_ping.max(self.last_rx) + self.ping_ms;
                StreamStep::Sleep {
                    until: soonest(Some(if hello { idle.min(ping) } else { idle })),
                }
            }
            Conn::Blocked(..) => StreamStep::Sleep { until: wake },
        }
    }

    /// The ticket request for the call the host built ([`Engine::stream_begin_call`]): `POST
    /// {base}/stream/ticket` with no body. Answer it with [`HomeStream::on_ticket`].
    pub fn ticket_request(&mut self, call: &[u8]) -> Result<Request> {
        require(
            self.conn == Conn::NeedTicket,
            "the stream is not waiting for a ticket call",
        )?;
        require(!call.is_empty() && call.len() <= 16_384, "a call is small")?;
        self.conn = Conn::Minting;
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
        if self.conn != Conn::NeedTicket {
            return Vec::new();
        }
        self.down(now, None)
    }

    /// The home's answer to the ticket request (or `None` when it could not be sent).
    pub fn on_ticket(&mut self, response: Option<&Response>, now: i64) -> Vec<StreamEvent> {
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
                        self.conn = Conn::Ticket(t.to_string(), now);
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
                self.idle_ms =
                    limit("idleMs", self.config.idle_ms).clamp(self.ping_ms + 1_000, 1_200_000);
                self.conn = Conn::Open { hello: true };
                self.attempts = 0;
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
        let ours = match &self.conn {
            Conn::Closing(c, _) => Some(*c),
            Conn::Open { .. } | Conn::Opening => None,
            _ => return Vec::new(),
        };
        let bye = self.bye.take();
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
                let at = now + wait + self.jitter(self.config.backoff_base_ms);
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
    /// An open stream is left alone.
    pub fn retry_now(&mut self) {
        if matches!(self.conn, Conn::Backoff(_) | Conn::Blocked(..)) {
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
    /// A `session` frame carrying `envelope` (the session layer's `{"body","signature"}` JSON,
    /// at most 16,384 bytes) to send on the live socket. The envelope is not judged here.
    pub fn session_frame(&self, envelope: &str, id: Option<&str>) -> Result<String> {
        require(
            self.status() == StreamStatus::Live,
            "the stream is not live",
        )?;
        require(
            envelope.len() <= MAX_SESSION_FRAME,
            "a session frame is at most 16,384 bytes",
        )?;
        require(
            id.is_none_or(|i| i.len() <= 64),
            "an id is at most 64 characters",
        )?;
        let frame: Value = serde_json::from_str(envelope)
            .map_err(|_| malformed("the session envelope is not JSON"))?;
        require(frame.is_object(), "the session envelope is an object")?;
        let mut v = json!({"type": "session", "frame": frame});
        if let Some(i) = id {
            v["id"] = json!(i);
        }
        Ok(v.to_string())
    }

    // ---------------------------------------------------------------------------------------

    fn wake(&mut self, now: i64) {
        if self.wake_at.is_none() {
            self.wake_at = Some(now + self.config.coalesce_ms.max(0));
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
        let at = now + delay;
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
        full / 2 + self.jitter(full / 2 + 1)
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
