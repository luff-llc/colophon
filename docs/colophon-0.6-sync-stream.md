# Sync over the stream (Colophon 0.6 draft, engine side)

**Status:** draft, 2026-11-23. This page covers the engine side of two proposed home features:
batch reads ([colophon-0.6-w1-batch.md](colophon-0.6-w1-batch.md)) and the home stream
([colophon-0.6-stream.md](colophon-0.6-stream.md)). Both are additive. A 0.5 home still syncs
with the same engine, and the poll path is unchanged.

The rule behind both: **the stream only makes sync sooner, and batches only make it cheaper.
Neither makes anything trusted.** A stream frame never reaches the account. It can only ask for
an ordinary exchange pass, and that pass fetches and verifies everything through `/changes` and
record reads, as a poll does. Each record in a batch is checked exactly like a single
`GET {base}/records/<path>`.

## 1. Batch catch-up (`v05::engine::exchange`, `v05::engine::batch`)

Nothing changes for the host. The records phase of a pass now queues `POST {base}/records/batch`
requests instead of single GETs when all of the following hold:

- reads at the home need a call (the engine learned this from a 401 earlier in the pass), so each
  single GET would cost its own signature;
- the home has not refused a batch this session;
- at least two records are wanted.

Batches hold at most 256 paths and a 64 KiB body, split in order. Each batch is a request of its
own with `Step::NeedCall`. `CallNeed.purpose` is `colophon.home.read`, and `exchange_begin_call`
builds the call with `Account::begin_home_batch_call`, bound to the body and checked path by path
as the home will check it. So a host's existing `NeedCall` handling works without change. A call
is never reused: a truncated answer's remainder is requested with a fresh call.

**Verification.** A 200 answer is read strictly before any of it is used
(`batch::parse`). It must be an object with `records` and `truncated`. Each item must be for the
requested path, in request order, with no extra, repeated or missing items unless `truncated` is
set. A truncated answer must hold at least one item, and the whole answer must be at most 4 MiB.
A found item needs an `etag` of 64 lowercase hex in quotes and standard-base64 `bytes` that hash
to it. A 413 item needs `etag` and `size`. A 404 or 503 item is accepted as such, and any other
item status is refused. If any of this fails, the whole batch fails: a `Fault::Malformed` is
reported, nothing in the answer is used, and its records are read singly in the same pass. Once
an answer is well formed, each found item goes through `take_record`, the same function a single
GET uses:

- the bytes must hash to the digest that `/changes` listed (else `Fault::Mismatch`, and the
  listing is forgotten);
- the record must be at most `MAX_RECORD`;
- `would_hold` must accept it;
- the conflict and twin rules apply;
- it is merged in the same judged batch.

A 404 item is reported as `Fault::Status { status: 404 }` and a 413 item is fetched by single
GET, both as for a single read.

**Fallback.** This never fails a sync.

| Batch answer | Engine |
| --- | --- |
| 4xx except 429 (a 0.5.2 home answers 405, an unappointed home 404, older homes something else) | Marks the home unsupported for the session (`exchange_batch_support` returns `Some(false)`). Reads this batch and every queued batch singly, in this pass. No fault is reported. |
| 429, 5xx | Reports `Fault::Status`. Reads singly for the rest of this pass and tries batches again next pass. |
| Malformed 200 | Reports `Fault::Malformed`. Reads singly for the rest of this pass. |

## 2. The stream client (`v05::engine::stream`)

`HomeStream` is a sans-IO state machine. It has no sockets, no async code and no clock, and it
does not hold the engine. The host passes in the time, and it seeds the jitter once
(`StreamConfig::seed`).

**Time.** `now` must be monotonic milliseconds: a monotonic clock, not wall time. The client is
robust anyway, and all of its time arithmetic saturates, so even extreme values (0, `i64::MAX`,
`i64::MIN`) cannot panic. If `now` goes back:

- remembered instants are brought back to it, and deadlines are due at once;
- the live safety poll fires immediately;
- the idle check and the ticket window count from the rollback point;
- a held ticket is not presented, because its age can no longer be told.

A rollback therefore never delays anything past its configured duration.

### Host contract (Swift, Kotlin, JS)

1. **Run a pass first.** A ticket call, like any call, needs a fresh head of the home (§12.3 step
   4). Before the first pass, `stream_begin_call` or `finish_write` fails with
   `Unavailable("too few fresh heads…")`. When that happens, call `ticket_call_failed(now)` and
   keep polling.
2. Create one client per home: `engine.stream_client(home, StreamConfig::default(), saved_cursor)`.
3. Loop on `client.next(now)` and act on the step:
   - `NeedTicketCall`: call `engine.stream_begin_call(home, key, request_id)`, sign its step,
     call `engine.finish_write(action, sigs)` and take `artifact`, then call
     `client.ticket_request(&artifact, now)`. Send the request (`POST {base}/stream/ticket`, no body)
     and pass the answer to `client.on_ticket(Some(&resp), now)`, or pass `None` on a transport
     error.
   - `Connect { url }`: open a WebSocket at `url`. For an `https` home the URL is already
     `wss://…/stream?ticket=…&after=…`. On 101 call `on_open(now)`. On an HTTP refusal call
     `on_refused(&resp, now)`. On a transport failure call `on_closed(None, now)`.
   - `Send { text }`: send this text frame (an application `ping`).
   - `Close { code }`: close the socket, then call `on_closed(Some(code), now)`.
   - `Wake`: run an ordinary exchange pass with the home now. Then call
     `client.on_history(engine.account().head().0)`. While the stream is live, `Wake` also comes
     at least every `safety_poll_ms`, whatever the home sends.
   - `Sleep { until }`: wait for a frame, a host event or `until`. `None` means nothing is
     scheduled.
   - `Waiting`: a request or socket is still outstanding.
4. Feed every text frame to `on_frame(text, now)`, and every close to `on_closed(code, now)`.
   Handle the returned events:
   - `Cursor(c)`: persist the cursor (`None` means forget it).
   - `Notice`, `Route`: pass these through to the UI or the notices code.
   - `Session(text)`: hand the server's message, byte for byte, to the session layer. The stream
     does not read it.
   - `Error`, `Ack`: replies to client frames.
   - `Violation`, `Down`, `Blocked`: diagnostics.
5. **Polling.** Whenever `client.polling()` is true (connecting, backing off, throttled,
   blocked or unsupported), keep the existing poll timer at its existing interval. While the
   stream is live, the timer can be skipped. The client then emits `Wake` itself at least every
   `safety_poll_ms`: 60 s by default, lowered by `stream_client` to `recoveryDelay / 6` when that
   is shorter (§17.5). So pending transitions are seen no later than a 0.5 poll would see them,
   even when a connected home sends only pongs or unknown frames. Also run a pass on foreground
   entry and on a local change. The stream does not replace the pending feed: every pass still
   reads it.
6. **Logging.** `StreamStep`, `HomeStream` and their contents can be logged with `{:?}`: their
   `Debug` shows a `Connect` URL with `ticket=<redacted>` (`stream::redact_url`), and the held
   ticket as `<redacted>`. The exchange's `Request` shows `Authorization` as `<redacted>` and
   its body as a length. The `url` field itself carries the ticket, so the host must not log it
   or its own WebSocket URL.
7. Use `subscribe`, `unsubscribe` and `session_frame` to build client frames for session cells.
   They work only while the stream is live. `session_frame` takes the session codec's frame
   bytes as text and carries them verbatim as the message's `frame` value (stream §5.2).

### Behaviour

- **Wakes.** These schedule a wake: a `change`, `head` or `notice` frame, a `resync`, the first
  `hello`, a `hello` without a resume cursor, and a `hello` whose head or notice number moved.
  Wakes are coalesced over `coalesce_ms` (250 ms), so a burst of frames gives one pass.
- **Cursor.** The client keeps the last `change` cursor it handled. On a connection opened
  without `after`, it keeps the `hello` cursor. On reconnect it sends this cursor as `after`.
  `resync` `gone` forgets the cursor, and `tooFar` keeps it. Each case wakes a pass, and the pass
  catches up from the exchange's own `/changes` cursor. That cursor never moves on a stream
  frame.
- **Frame numbers.** `hello` must be `n = 1` and the first frame. After that, `n` must rise by
  exactly 1. Any of the following closes the socket with code 1002 and resumes from the last
  handled cursor, with backoff:
  - a gap in `n`;
  - a frame without `type` or `n`;
  - non-JSON text;
  - a second `hello`;
  - a message over 64 KiB.

  Frames that arrive while the socket is closing are ignored.
- **Liveness.** After `pingMs` with nothing received (20 s from `hello.limits`), the client
  sends `{"type":"ping","t":…}`. After `idleMs` (60 s) with nothing received, it closes with 1001
  and resumes.
- **Backoff.** The delay is `min(cap, base · 2^attempts)` with base 1 s and cap 60 s. "Equal
  jitter" puts the actual delay between half and all of that, using xorshift seeded from
  `StreamConfig::seed`. A `hello` alone does not reset `attempts`: the connection must stay live
  for `stable_ms` (60 s), so a home that says `hello` and closes keeps backing off. A 429 waits at
  least `Retry-After`. A restart (`bye` `restart`, close 1012) waits `retryMs` plus up to 1 s of
  jitter and does not count as a failure. With seed 1 the schedule is 542, 1,328, 2,846, 4,376, 11,182, 28,271,
  49,933, 30,709, 31,293 and 33,062 ms.
- **Ticket signing is bounded in three layers.** Every reconnect signs a call, which may use a
  hardware key or prompt the user, and the home decides when a connection drops. Polling
  continues under every layer.
  1. **Rolling 10-minute window:** at most `mint_budget` (8) tickets in any `mint_window_ms`.
     Past it the stream is `Throttled(until)` until the oldest mint leaves the window.
  2. **Circuit breaker with decay:** each ticket signed (or attempted, `ticket_call_failed`)
     adds one to a count. Each whole `stable_ms` (60 s) of continuous uptime removes one, never
     below zero, so a connection held for 60 s and then dropped earns one credit, not a reset.
     At `suspend_after` (16) the stream is `Suspended(until)`. It mints nothing until the
     history changes, `retry_now` is called, or `suspend_ms` (6 hours) passes.
  3. **Daily budget:** at most `max_mints_per_day` (96) tickets in any rolling 24 hours,
     whatever the connections did. Past it the stream is `Suspended` until enough of those
     mints are a day old, or the history changes. `retry_now` clears the breaker's count and
     allows `retry_allowance` (8) more, counted in the same day. A host that calls it from a
     timer by mistake therefore still signs at most 104 a day. Call it only on an explicit user
     action or on foreground entry.

  **Worst case:** 96 signatures a day from a hostile home, or 104 if the host calls `retry_now`.
  These are the measured totals over 7 days:

  | Home | Signatures |
  | --- | --- |
  | `hello` then close, forever | 64 a day |
  | Holds one connection in four for 60 s | 85 on day 1, 575 in 7 days |
  | Holds one connection in four for 20 minutes | 96 a day, 672 in 7 days |

  A flaky network where two connections in three hold for half an hour signs about 72 a day
  and never suspends. Changes to the verified history reset all three layers, and a hostile
  home cannot cause one.
- **Do not reconnect until the history changes** (`Blocked`; the client resumes after
  `on_history` reports a different seq, or after `retry_now`):

  | Case | Reason |
  | --- | --- |
  | Close 1008 (access ended: revoked, suspended, sessions ended, expired, lost the role) | `AccessEnded` |
  | Upgrade refused 403 `refused:revoked` | `AccessEnded` |
  | `bye` with `resume: false`, then any close | `Released` |
  | Ticket mint 401 or 403 | `Refused(result)` |
  | Ticket mint 404, 405 or 501 (a 0.5 home, or an unappointed one) | `Unsupported` |
  | `hello` for another protocol | `Unsupported` |

- **Reconnect with backoff:** close 1000, 1009, 1011, 4008, 4013, a bare 1001, or an abnormal
  close; upgrade refused 401 or 403 `refused:ticket`, 429 or 503; ticket 429 or 5xx. A ticket
  older than 20 s on the host's clock is not presented, and a new one is minted instead.
- **A frame is a hint.** `HomeStream` holds no engine, and none of its events carries record
  bytes, entries or paths: a host has nothing from the stream to merge. The test
  `a_forged_change_frame_makes_the_engine_accept_nothing_a_poll_would_not` sends forged `change`
  and `head` frames. It shows that the woken pass ends with exactly the head, records and stored
  paths of a device that only polled, and that no request names a forged path.

## 3. Measured round trips

The simulated home requires a call for every guarded read, like a real home. Round trips are the
HTTP requests a pass sends. The figures come from
`tests/v05_engine_batch.rs` (`measure_a_cold_catch_up_of_2000_records`, opt-in) and
`tests/v05_engine_stream.rs`, and they match the real relay
(`crates/colophon-home-wasm/tests/v06_relay_sync.rs`).

**Cold catch-up of 2,000 records** (a device holding the authority only):

| | Round trips | Calls signed |
| --- | --- | --- |
| 0.5 engine, today | 2,008: 1 head, 2 pending (one is the 401 that teaches "calls needed"), 5 `/changes` pages, 2,000 record GETs | about 2,006 |
| This engine, 0.5 home (batch refused with 405) | 2,009: the same plus one batch probe, made once per session | about 2,006 |
| This engine, 0.6 home | **16**: 1 head, 2 pending, 5 `/changes` pages, **8 batches** (⌈2,000 / 256⌉) | **14** |

At 600 records the counts are 606 and 8. In the real-relay test, 5 records take one batch.

**Single-record update** (device A writes one record; device B is current):

| | B's round trips | Latency |
| --- | --- | --- |
| Poll | 4 (head, pending, `/changes`, one GET), plus 3 for every idle poll (head, pending, `/changes`) | Up to the poll interval (20 s in the Apple session, 60 s or more elsewhere) |
| Stream wake | 4 for the same pass, with no idle polls while live | The coalescing window (250 ms) |

Keeping the stream costs one ticket mint and one upgrade per connection, plus an application
ping only after 20 s of silence. A single record is read with a GET, because a batch of one
saves nothing. With two or more records the stream-woken pass batches them: the real relay
served 5 records in 4 round trips instead of 8.

## 4. Doc ambiguities found (no server bug found)

Items 2, 3, 5, 6, 7, 8 and 9 are now written into the drafts, describing what the reference home
does (`colophon-0.6-w1-batch.md`, `colophon-0.6-stream.md` §1.1, §2, §4 and §7). Item 4 is
written as client guidance. Items 1 and 5 would each need a server change to resolve properly:
a published feature list, and one expiry format.

Neither the reference relay nor the simulated home showed a server bug. The engine was run
against `relay/server.js` (Bun, home module in WebAssembly) in all existing real-relay suites
(`v05_relay_journeys`, `_home`, `_h2`, `_succession`, `_stopped`), which now batch. The new
`v06_relay_sync` covers both features: it mints a ticket, upgrades a real WebSocket, receives
`hello`, receives `change` frames for another device's writes, wakes, and reads them in one
batch. The points below are places where the two drafts are ambiguous or silent.

1. **Batch support cannot be discovered.** `GET {base}` publishes nothing, and the W1 draft does
   not say what a home without batches answers. 0.5.2 answers 405, an unappointed 0.6 home 404,
   and 0.5.0 and 0.5.1 something unspecified: the route did not exist, and a home-read call on a
   POST is likely refused with 403. The engine therefore treats any 4xx except 429 as "no
   batches this session". Suggestion: publish `"features":["records/batch","stream"]` in
   `GET {base}`, or require 404 or 405 from a home without batches.
2. **A truncated answer with no item** is neither allowed nor forbidden. The first item always
   fits or comes back as 413, so it cannot happen at an honest home, and the engine treats it as
   malformed. The draft should say that a truncated answer holds at least one item.
3. **Batches on 0.3 token slots.** `relay.js` also serves `POST /records/batch` on non-home
   (0.3 bearer) slots without a call (`relay.js`, the `section === 'records' && recordPath ===
   'batch'` branch). The W1 draft does not mention it.
4. **Close 1001 is overloaded.** The stream draft uses it for "released, do not resume at this
   home", but RFC 6455 1001 is "going away", which proxies and load balancers send on restart.
   This client blocks only on `bye` `resume: false` and treats a bare 1001 as a drop. The draft
   should make the `bye` normative, or move "released" to a 4xxx code.
5. **The two expiry formats differ.** The ticket answer's `expires` is an ISO date string in the
   relay (`stream.js` `mint`), while `hello.expiresAt` is milliseconds. The draft gives neither
   format for `expires`. The client ignores `expires` and stops presenting a ticket 20 s after
   it was minted, by its own clock.
6. **`pingMs` is undefined.** The draft lists it in `limits` but does not say whether it is the
   home's WebSocket ping interval or a cadence it expects from clients. Browsers do not expose
   WebSocket-level pings, so a client cannot see liveness without application frames. This
   client sends an application `ping` after `pingMs` of silence and treats `idleMs` of silence
   as dead. The draft should say that clients SHOULD do this.
7. **Interchangeable cursors.** The draft says "one format", but `/changes` takes `namespace`
   filters and the stream does not. It should state that a cursor from a namespace-filtered
   `/changes` is valid as `after` and vice versa (positions are global). It should also say that
   `change` frames arrive for every namespace, so a scoped replica gets wakes for namespaces it
   does not read. The client does not filter them, although it could.
8. **Replay without `after`** is not stated: the draft should say that a connection without
   `after` gets no replay and that `hello.cursor` is then the live position. The client assumes
   this.
9. **A ticket needs a fresh head.** A ticket call is an ordinary call, so it needs fresh heads
   (§12.3 step 4), and a device cannot mint before it has read the home's head. §1.1 should say
   so. The host contract above handles it.

## 5. What the bindings need next

The stream object and `stream_begin_call` / `stream_client` are now exported in both binding crates
([bindings-05.md](bindings-05.md) §10); the per-platform WebSocket transports below are still to do.


- **Batch:** nothing new. `CallNeed` and `exchange_begin_call` already cover it.
  `exchange_batch_support(home)` is a read-only diagnostic and can be exposed.
- **Stream:** an object wrapping `HomeStream` with `next`, `ticket_request`, `on_ticket`,
  `on_open`, `on_refused`, `on_frame`, `on_closed`, `ticket_call_failed`, `on_history`,
  `retry_now`, `polling`, `status`, `config`, `cursor`, `subscribe`, `unsubscribe` and `session_frame` (`ticket_request` takes `now`, for the ticket budget);
  `StreamStep`, `StreamEvent`, `StreamStatus`, `Blocked` and `StreamConfig` as records and enums;
  and `Engine::stream_begin_call` and `Engine::stream_client`. Each platform needs a WebSocket
  transport: `URLSessionWebSocketTask`, OkHttp or `java.net.http.WebSocket`, and the browser
  `WebSocket`. It must report close codes and give the client text frames unchanged. The host
  also persists `Cursor` events next to its exchange checkpoint.
- Not done: filtering wakes by the namespaces a replica reads (item 7), driving session cells
  above the stream, and a stream fast path that skips the head and pending reads for a pure
  record change.
