# 0.6 hosts: the home stream and session cells (JavaScript)

**Status:** stage 2 of Colophon 0.6 for JavaScript. Stage 1 is the binding surface of
[bindings-05.md](bindings-05.md) §10 (`HomeStream`, `SessionEndpoint` and the engine's stream and
session calls). This stage adds the host layer that drives that surface over a real WebSocket, in
`js/src/hosts` (`@colophon/core/hosts`), and proves the flagship behaviour end to end. The Swift and
Kotlin hosts follow the same shape.

The rule is the one stage 1 states: the core decides, the host carries. The host owns the socket,
the ticket request, the timers and the durable store. It adds no retry timing, cap or backoff of its
own, and it never reads, rewrites or logs a ticket, an unredacted URL or a frame's plaintext.

## 1. The API

| Object | What it is |
| --- | --- |
| `HostAccount` | What the hosts need from the account: `account`, `member`, `engine()` (read again for every call), `streamCall(home)` (the `colophon.home.stream` call, signed and judged by the core), `exchange()` (one ordinary pass), `signRaw(body)` (the member key's `r‖s` over a delegation body). `accountOf(session)` makes one from a restored `ColophonSession`; its `exchange` is the session's own `syncNow`, so passes never overlap the app's poll loop. |
| `HomeStreamHost` | One per home. `start`, `stop`, `status`, `polling`, `cursor`, `live`, `retryNow` (foreground entry, a network change, a user action; never a timer), `historyChanged` (the app's own poll moved the history), `attach(cell)` / `detach(cell)`, `sendSession(frame)`, `on(listener)`, `onPass(listener)`. Options: the account, the home's member ID, the ticket `transport` (default `FetchHomeTransport`), the `socket` factory (default the runtime's `WebSocket`), the `clock`, `configure` (adjusts `stream_default_config()`), a saved `cursor` and `saveCursor`. |
| `SessionCellHost` | One member of one cell: `SessionCellHost.open(options, listener)` loads the stored claim, makes the endpoint, has the member key sign its delegation, attaches to the carrier and joins. `command(name, json)` (resolves once the endpoint ran it), `deliver`, `linkUp`, `linkDown`, `accountChanged`, `leave`, `close`, `current` (the endpoint, for its read-only calls), `stats`. Options: account, carrier, namespace, cell, `store` (a fenced `ClaimStore`, §3), `policy`, `clock`, `state` (the application's state for `join`), `delegationMs`, `persistRetryMs`, `persistTimeoutMs`, `persistAttempts`, `maxCommands`, `random`. |
| `ClaimStore`, `MemoryClaimStore`, `privateClaimStore(store, name)`, `FencedClaimStore` | The fenced claim store contract and the reference stores that apply it: in memory, in one file of a session's `PrivateStore`, or over any `read`/`write` of the record. |
| `CellSession` | The small typed API over a cell host: `CellSession.join(options)`; `state` (`joined`, `holder`, `isHolder`, `gated`, `claim`, `state`, `seq`, `entitled`, `canWrite`) and `subscribe`; `events` (the core's events with bytes decoded); `take`, `ask`, `pass`, `decline`, `release`, `publish`, `submit`, `presence`, `ping`, `leave`, `close`. |
| `sessionFrameText(message)` | The exact text of a `session` message's `frame` value, or none (no `frame`, `frame` twice, or not one JSON object). |
| `webSocketFactory(class?)` | The standard `WebSocket` behind `SocketFactory` (see §5 for what a browser cannot report). |
| `HostClock`, `systemClock` | Monotonic and wall milliseconds and a timer; `performance.now()`, `Date.now()` and `setTimeout` by default. |

## 2. The stream loop

`HomeStreamHost` asks `HomeStream.next(now)` what to do and does it, until the answer is `Waiting` or
`Sleep`:

- `Wake`: one exchange pass through the account, then `on_history(head_seq)`. A wake during a pass
  runs one more pass after it. Every cell attached is then told `accountChanged`.
- `NeedTicketCall`: `streamCall`, then `ticket_request`, the request through the transport, and
  `on_ticket` with the answer (or with none on a transport error). A call that cannot be made is
  `ticket_call_failed`. The core hands it out once and answers `Waiting` until then; a call not
  answered within its `SIGN_TIMEOUT_MS` counts as failed.
- `Connect`: opens the socket at `url`; `on_open`, `on_frame` for every text message, `on_refused`
  where the runtime shows the refused upgrade, `on_closed` with the code (or none). Events from a
  socket the host already replaced are ignored. Only `log_url` is ever reported.
- `Send`: the text on the socket. `Close`: closes the socket, then `on_closed(code)`.
- `Waiting` and `Sleep { until }`: one timer, at `wake_at` (and `until`, whichever is first) on the
  monotonic clock, so a wake that falls due while a call is signed is still run.

A socket is owned (kept, or closed at once if the host was stopped meanwhile) before any listener
hears of it, and every callback checks that its socket is still the current one.

Events: `Connected` subscribes every attached cell; an `Ack` of `subscribed` is the cell's link up,
and leaving `Live` (a close, a refusal, a violation) is every cell's link down; `Cursor` goes to
`saveCursor`; `Session` is routed by the frame's own `namespace` and `cell` and delivered as the
frame's text. Every event is also reported to listeners. While `polling` is true the app keeps its
existing poll timer.

## 3. The cell loop

`SessionCellHost` is the reference host loop of [bindings-05.md](bindings-05.md) §10. Every input
(a frame, a tick, a link change, a command, a completed write, a delegation renewal) is a job on one
serial queue: jobs run one at a time, never inside another, and events reach listeners only between
jobs, so nothing a listener, store, socket or timer does can re-enter the endpoint.

- Every input is one endpoint call, and its step is carried out in order: `Send` to the carrier
  (`sent`, or `unsent` with reason `carrier` when it is down), `Event` to the application, `Persist`
  to the store, `Unsent` reported with its code. Drops and `discarded` are reported, never dropped
  silently.
- **Order.** Every input takes its place in the queue when it is admitted (a command when
  `command` is called, a frame when it is delivered), and inputs run in that order. One exception
  follows from the reference loop: a command the endpoint refuses with `session:persistPending` is
  held, and every command admitted after it is held behind it, in order, until the write completes;
  frames, ticks and link changes admitted meanwhile still go to the endpoint, which keeps them behind
  the `Persist` and runs them at the acknowledgement, so they run before the held commands. Among
  commands the admission order is never changed.
- A `Persist` is acknowledged with `persisted(id)` only when its `save` resolved, as a later job.
  The write is marked in progress before any store code runs. **One save is in flight at a time.**
  A save that fails is a failed attempt, retried after `persistRetryMs`. A save that has not settled
  within `persistTimeoutMs` (default 10 s) is a failed attempt too, but the next save starts only
  once it has settled: each further deadline it passes counts again, so a save that never settles
  ends in `failed` (`store`) without a second save ever being issued. A save that succeeds only
  after its deadline acknowledges nothing; the claim is saved again under the next fence. Only a
  completed save becomes the claim a new endpoint starts from.
- **Fencing.** Every save carries a fence `{generation, seq}` (`js/src/hosts/claim-store.ts`).
  An instance's generation is one more than the one the store holds when it opens, and it reserves
  it before saving any claim, by saving the claim it loaded under `{generation, 0}`; saves are then
  numbered within it, and a rebuilt endpoint moves to the next generation (after the last save has
  settled). The store refuses (`stale`) any save whose fence is not greater than the one it holds,
  so the held fence never goes back, and since every instance's generation is in the store before
  it saves a claim, a save from an earlier instance or attempt that settles late is refused instead
  of overwriting a newer claim. The fence is stored with the claim, so it survives restarts. The
  reference stores apply the check; a custom store must. A refused reservation means another
  instance holds the cell: `open` fails. A refused claim save means the same, and the cell fails
  with reason `superseded`. One live host per cell and store is assumed.
- **A store that keeps failing fails the cell.** After `persistAttempts` consecutive failed or
  overdue attempts of one write (default 20) the host stops acting: its endpoint is freed, it is detached
  from the carrier and sends nothing more, every held and new command is refused (`CellHostError`
  `failed`), and it reports `failed` with reason `store`. To the other members it is a member that
  went quiet: its role lapses to them. An application opens a new host once storage works again,
  from the last stored claim, so the restart rules apply.
- A command refused with `session:persistPending` stays first in line and runs when the write
  completes; later commands wait behind it, in order. At most `maxCommands` (64) are held; one more
  is refused at once with `commandQueueFull`, and the order of those accepted never changes. Frames,
  ticks and link changes go to the endpoint, which keeps them.
- The tick timer is armed from the `next_deadline` of the latest step. While a `Persist` is
  outstanding that is absent, so nothing ticks until the acknowledgement's step re-arms it.
- `open` that fails (the delegation cannot be signed, the endpoint cannot be made, the join is
  refused) closes the host: detached, its endpoint freed, the error thrown. A rebuild that fails
  leaves the host `failed` (reason `rebuild`), with every held and new command refused.
- `session:staleAccount`: `set_account(engine.session_account(ns, now))`, then the input once more.
  After an exchange pass the host installs the new view before anything else is delivered. A new
  session number of this member makes a new endpoint, since it needs a new session key (§S2).
- `session:clockBackwards` and a view of another engine (`session:wrongView`, after the session
  reopened its engine): the endpoint is discarded and made again from the stored claim, with new
  randomness and a new delegation, and joins with the application's state, so the restart rules of
  §S6 apply. Frames that arrive meanwhile are reported as `missed`.
- `tick` at `next_deadline`; the delegation is renewed an hour before it ends.
- Frames reach `receive` as the carrier's text, unchanged: `sessionFrameText` takes the `frame`
  value's span out of the message, never a re-serialised value. It checks the whole message as one
  strict JSON object (strings and their escapes, numbers, literals, nesting up to 66 levels, nothing
  after it), counts only a top-level member named `frame`, and refuses a message that names `frame`
  twice in any spelling. Re-serialising can change the bytes
  (an escape is decoded, a duplicate name collapsed) and can turn a non-canonical frame into one the
  codec would accept; `test06/cell-host.test.ts` shows a frame with one `-` escape that
  `JSON.stringify(JSON.parse(…))` turns into the sender's canonical bytes, while the carried text is
  refused by the receiver.

## 4. What was run

`scripts/test-js.sh` runs these with the rest of the JavaScript tests, and `js/scripts/test-hosts.sh`
(`npm run test:hosts`) runs only these. Both build the web05 module, the conformance module (into
`js/.conformance/`, which the package neither includes nor imports, as a test checks) and the
relay's home module, typecheck strictly and run `bun test test06`:

- `stream-host.test.ts`: the core's real `HomeStream` with a fake socket, transport and clock. Every
  step kind; the ticket only in the socket URL; ping after `pingMs`, close 1001 after `idleMs`,
  backoff and a new ticket; a frame-number gap closed with 1002; close 1008 blocked until the
  history changes; 1012 and 1000 backing off; a transport failure; an upgrade refused 429 (at least
  `Retry-After`) and 403 `refused:revoked`; ticket answers 404 (unsupported, still polling), 403
  (refused) and a failed call; one signature while `NeedTicketCall` repeats; cursors saved and
  presented; subscription, link up on the ack, routing as the frame's own text, link down on close;
  a wake during a pass; a call never signed counted as failed through the `wake_at` timer; `stop`
  from a `connect` listener and from inside the socket factory leaving no socket open; listeners
  calling back into the host from every event.
- `frames.test.ts`: `sessionFrameText` on escaped quotes, `frame` inside strings and nested
  objects, duplicate and escaped-duplicate `frame` names, unicode escapes, whitespace, invalid
  tokens and numbers, bad escapes, control characters, trailing data and deep nesting.
- `cell-host.test.ts`: real endpoints of two members of a local account over an in-memory carrier,
  with a manual clock and stores the test completes. A `Persist` holding back the take, the state
  and `becameHolder` until its write completes; a frame and a tick kept and a command held during a
  write, then run in order; a failed write retried and acknowledged once; a stale view replaced and
  the input run; a backwards clock rebuilding the endpoint from the stored claim (a new key, gated,
  then retaking); frames passed as their own text, and the re-serialisation case above; listeners
  that call back into the host (commands, inputs, a backwards clock) from every event, the rebuild
  waiting for the write in progress and starting from the claim it stored; an `open` whose
  delegation cannot be signed leaving nothing attached; a failed rebuild refusing held and new
  commands; a store that keeps failing failing the cell; bounded command admission keeping order;
  a command, a frame and a command admitted from a listener running in exactly that order, and
  behind a write the held commands keeping their order with the frame run at the acknowledgement;
  a save that never settles counted as failed at its deadline until the cell fails; an overdue
  save waited for (no second save in flight), its late success saved again under the next fence,
  and the store ending with the latest claim; an older instance's save settling late after a
  replacement instance saved a newer claim, refused by the store; a refused reservation failing
  `open`; close and failure cancelling every retry and deadline timer; and in every test at most
  one save in flight;
  and, at unit level, a revoked member's frames dropped by a member holding the new head.
- `conformance.test.ts`: through `colophon-conformance-wasm`, every machine transcript in
  `conformance/0.6-sessions/` (26), the 9 `offset.json` cases, and `wire/vectors.json` (19 frames,
  20 scenario steps, 26 negative frames), plus strict decoding.
- `handoff.test.ts` and `scenarios.test.ts`: the end-to-end proof below.

### The end-to-end proof

A real home (`relay/server.js` on Bun with the Rust home module, started as `js/test05` starts it), an
account with two members A and B entitled to write `listening.podcasts`, each with its own
`ColophonSession`, `HomeStreamHost` over a real WebSocket and `now-playing` cell, on loopback.

1. **Handoff** (default policy). A takes and publishes an anchor with a position; B follows it and
   pings A for the clock offset. B's "play" asks; A's application pauses and passes its stopped
   position (§S12); A observes that it is no longer holder (`yielded`) and B becomes holder by the
   pass with exactly A's last state, then plays on from that position, which A follows. A sends no
   holder frame afterwards. Measured on loopback: from B's ask to A observing the change about 2 ms,
   to B holding about 3.5 ms. A take does not displace a holder that is live and answering (§S5),
   so the handoff between live devices is ask and pass; a take is what follows a lapse (step 3).
2. **Restart** (the fast policy below). A, holding, is closed and opened again from its stored claim
   with a new endpoint and key: it holds locally but `gated`, sends a hello and no holder frame, and
   retakes after `askTimeoutMs` (about 305 ms against 300) with the state its application kept.
3. **Offline past the timeout.** A's network is cut while it holds. B sees A lapse after 1.5 s and
   takes (holding about 1 ms after its take command, with A's last state); A keeps acting locally.
   When A's network returns, it reconnects, sends its hello, sends no holder frame, and yields to
   B's greater claim; B's application is given what A held (`displaced`).
4. **A slow store during a pass.** Both stores take 500 ms per write. B's application passes to A
   when A asks: B's `pass` is sent only after its write completes (about 502 ms), A's `ack` only
   after A's; frames and a tick arriving meanwhile are kept and run after, a command B issued during
   its write is held and run after it, and nothing is lost (`queueFull` never occurs).
5. **Revocation mid-session**, with nothing injected. B revokes A by an authority change on its own
   device (both devices hold the person's owner key) and installs the new head before the home has
   it. A, still on the old head, publishes over its socket; the home still carries the frame, and
   B's endpoint drops it on arrival (`delegation`), changing nothing. Once B's pass gives the home
   the revocation, the home ends A's stream (`Blocked`, `AccessEnded`) and A's frames no longer leave
   the device. A's poll brings the revocation in: A's next command reports the stale view, and with
   the new view installed A is not entitled.

The fast policy is the default with `beatMs` 400, `holderTimeoutMs` 1,500, `askTimeoutMs` 300 and
`presenceTimeoutMs` 1,500; the rules are the same as with the defaults.

The session's own test suites (`npm test`, `bun test test05`) still pass with the two worker
additions this stage makes (`streamCall`, `transportOf`).

## 5. What the runtimes cannot report, and what was not run

- A browser's `WebSocket` hides a refused upgrade's HTTP answer, so a 401, 403 or 429 is reported
  as `on_closed(None)`, a transport failure: the stream backs off within the ticket budget and the
  breaker instead of reading the refusal (a revoked member then learns it from its next pass, and
  close 1008 still blocks a live stream). Bun's and Node's standard `WebSocket` hide it too; a
  `SocketFactory` built on a client that exposes the answer can call `refused`.
- A browser's `close` accepts only 1000 and 3000–4999, so the core's 1001 and 1002 are sent as 1000;
  the core is told the close it asked for.
- CI: the `wasm-and-js` job does not call `scripts/test-js.sh`; it runs its own steps, so it does
  not run these tests until it gains steps for them.
- Run under Bun 1.4 on macOS only. Not run: a browser (the hosts use only `WebSocket`, `fetch`,
  `crypto.getRandomValues`, `performance.now` and timers, but the test06 suites were not run in
  headless Chrome), Node, a real network between the devices, or a home other than the reference
  relay.
