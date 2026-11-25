# 0.6 hosts: the home stream and session cells (JavaScript and Swift)

**Status:** stage 2 of Colophon 0.6 for JavaScript. Stage 1 is the binding surface of
[bindings-05.md](bindings-05.md) §10 (`HomeStream`, `SessionEndpoint` and the engine's stream and
session calls). This stage adds the host layer that drives that surface over a real WebSocket, in
`js/src/hosts` (`@colophon/core/hosts`), and proves the flagship behaviour end to end. The Swift host (§6) follows the same shape; the Kotlin host
is built separately.

The rule is the one stage 1 states: the core decides, the host carries. The host owns the socket,
the ticket request, the timers and the durable store. It adds no retry timing, cap or backoff of its
own, and it never reads, rewrites or logs a ticket, an unredacted URL or a frame's plaintext.

## 1. The API

| Object | What it is |
| --- | --- |
| `HostAccount` | What the hosts need from the account: `account`, `member`, `engine()` (read again for every call), `streamCall(home)` (the `colophon.home.stream` call, signed and judged by the core), `exchange()` (one ordinary pass), `signRaw(body)` (the member key's `r‖s` over a delegation body). `accountOf(session)` makes one from a restored `ColophonSession`; its `exchange` is the session's own `syncNow`, so passes never overlap the app's poll loop. |
| `HomeStreamHost` | One per home. `start`, `stop`, `status`, `polling`, `cursor`, `live`, `retryNow` (foreground entry, a network change, a user action; never a timer), `historyChanged` (the app's own poll moved the history), `attach(cell)` / `detach(cell)`, `sendSession(frame)`, `on(listener)`, `onPass(listener)`. Options: the account, the home's member ID, the ticket `transport` (default `FetchHomeTransport`), the `socket` factory (default the runtime's `WebSocket`), the `clock`, `configure` (adjusts `stream_default_config()`), a saved `cursor` and `saveCursor`. |
| `SessionCellHost` | One member of one cell: `SessionCellHost.open(options, listener)` loads the stored claim, makes the endpoint, has the member key sign its delegation, attaches to the carrier and joins. `command(name, json)` (resolves once the endpoint ran it), `deliver`, `linkUp`, `linkDown`, `accountChanged`, `leave`, `close`, `current` (the endpoint, for its read-only calls), `stats`. Options: account, carrier, namespace, cell, `store` (a fenced `ClaimStore`, §3), `policy`, `clock`, `state` (the application's state for `join`), `delegationMs`, `persistRetryMs`, `persistTimeoutMs`, `persistAttempts`, `maxCommands`, `random`. |
| `ClaimStore`, `MemoryClaimStore`, `privateClaimStore(store, name)` | The claim store contract (a linearizable compare-and-set and a cheap `fence()` read, §3) and the two stores that provide it: `MemoryClaimStore`, and `privateClaimStore` over an `AtomicPrivateStore` (`IndexedDBPrivateStore`, `MemoryPrivateStore`, which gain `update`, an atomic read-decide-write). There is no file-backed claim store yet: `privateClaimStore` refuses a store without `update`, such as `FilePrivateStore`, and a Node or Bun host supplies its own `ClaimStore` (§3a). |
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
- **Fencing.** Every save carries a fence `{generation, seq}` of two non-negative safe integers
  (anything else is refused), and the fence the host last saw held. `ClaimStore.save(record,
  expected)` is a compare-and-set, linearizable across every client of the same storage (other
  instances, tabs and processes): it writes only if the held fence is exactly `expected` and the
  new one is greater, else it is `stale` and writes nothing. A store that reads, compares and writes
  as separate steps is incorrect: two clients could both read fence F and both write, and two hosts
  would each believe they hold the cell. The shipped stores make it one step: `MemoryClaimStore`
  synchronously, and `privateClaimStore` through `AtomicPrivateStore.update`, which
  `IndexedDBPrivateStore` runs as one `readwrite` transaction (get, compare, put).
  `privateClaimStore` refuses a private store without `update` (the file-backed `FilePrivateStore`)
  with an error saying that file-backed claim persistence is not available yet and that a
  `ClaimStore` must be supplied; nothing falls back to separate steps.
- **Unfenced claims.** 0.6 has not been released, so no claim was ever stored without a fence and
  there is nothing to migrate: a stored record without a valid fence is refused.
- A host **opens and rebuilds by reserving** the next generation: a compare-and-set of the claim it
  holds under `{generation + 1, 0}` from the fence it read. Of two that read the same fence, only
  one can store; the other is `stale`, and its open fails (`CellHostError` `superseded`) or its
  rebuild fails the cell (`failed`, reason `superseded`). The held fence changes only by a save made
  from exactly the previous one, so it never goes back, and a save from an older instance or attempt
  that settles late finds a fence it did not expect and changes nothing. The fence is stored with
  the claim, so it survives restarts. After a save fails or is `stale`, the host reads the held
  fence: one of its own (a save it could not see complete) is adopted and the claim saved again;
  another instance's means it no longer holds the cell.
- **A superseded host stops within one beat.** Every `beatMs` (the cell policy's) the host reads
  the held fence alone (`ClaimStore.fence()`: a directory listing, or one small record). The check
  is never skipped: while a write is in flight the held fence may already be that write's, which is
  one of the host's own fences (its current generation, at most its latest seq) and counts as its
  own. Any other fence fails the cell with `superseded` at once. One read starts each beat and must
  answer within it; when `fenceCheckMisses` (3) consecutive beats end with a read that failed or did
  not answer, the cell fails closed with reason `store`, three beats after the first such read
  began, since a host that cannot tell whether it still holds the cell must stop. A host that
  another instance replaced sends for at most one beat after the replacement reserved its
  generation, or three when the store also stops answering.
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

## 3a. Implementing a `ClaimStore`

A `ClaimStore` for other storage (files, a database, a platform key-value store) must provide the
contract of §3 (`load`, `fence`, and `save(record, expected)` as a compare-and-set linearizable
across every client of the same storage) and these three properties:

1. **No reader sees a commit before it is irrevocable.** From the moment `load` or `fence` of any
   client can return a new fence, that fence is held: no step of the save that wrote it, nor any
   other save, may withdraw it. A design that makes a candidate visible and then validates it (and
   removes it on failure) breaks "a stale save writes nothing": a reader can observe a fence that
   then disappears, a host can be judged superseded by a save that failed, and another client can
   reserve from a predecessor that is withdrawn.
2. **Success is reported only once the commit is durable.** `stored` means the record, and
   whatever makes it findable (for files, the directory entry, synced), survives a crash. A step
   whose durability cannot be confirmed (a failed directory sync, for example) makes the save fail,
   never `stored`.
3. **Anything unrecognised in the store's namespace fails closed.** An entry the store cannot
   read, parse or validate (a malformed name or record, a fence outside the safe-integer range, a
   link or other unexpected kind of entry) is an error from `load`, `fence` and `save`, never
   skipped: skipping it could report a lower fence than the one held.

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
- `claim-fence.test.ts`: two clients of one storage (a fake whose reads and compare-and-sets are
  separate transactions, run in every one of the six interleavings of two opens) racing to open,
  leaving exactly one holder after one beat; a rebuild racing an open in all three interleavings;
  a private store without `update` (the file store) refused by `privateClaimStore`; a superseded
  holder failing within one beat and sending nothing after; fences that are not non-negative safe
  integers refused. The browser run adds eight `IndexedDBPrivateStore` clients of one database
  racing from one fence, twice: one stored each time.
- Fence checks in `cell-host.test.ts`: run every beat while a write is in flight without mistaking
  the host's own write for another instance; three rejected or three unanswered checks failing the
  cell closed, measured on the fake clock (rejected reads at beats one to three fail it at the third;
  unanswered ones three beats after the first began); one miss alone not.
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

## 6. The Swift host

`ColophonHosts` (a library product of the root package, `swift/Sources/ColophonHosts`) is the same host
for Apple platforms, on the generated `HomeStream` and `SessionEndpoint` of `ColophonKit`. It follows
§2 and §3 rule for rule; this section gives the Swift names and what differs because of the runtime.

| Type | What it is |
| --- | --- |
| `ColophonHostAccount` | The account a host acts for: `ColophonHostAccount(session:)` from a ready `ColophonSession` (on the main actor). It is opaque: the engine, the member key and the exchange (the session's own `syncNow`) stay inside the hosts, which reach them only from their serial queues. The session reaches the hosts through SPI (`@_spi(Hosts)`), never its public API. |
| `HomeStreamHost` | An actor, one per home. `init(account:home:transport:socket:clock:configure:cursor:saveCursor:client:)`; `start()`, `stop()`, `retryNow()`, `historyChanged()` and `on(_:)` are `nonisolated` and may be called from anywhere, listeners included; `status`, `polling`, `cursor`, `live`, `attach(_:)`, `detach(_:)`, `sendSession(_:)`, `onPass(_:)`. |
| `SessionCellHost` | An actor, one member of one cell: `SessionCellHost.open(_:listener:)` with `CellHostOptions` (the same options as §1). `submit(_:json:)` admits a command synchronously and returns a `CellCommand` whose `value()` waits for it; `command(_:json:)` does both. `deliver`, `linkUp`, `linkDown`, `accountChanged`, `close` are `nonisolated`; `leave()`, `state`, `writePending`, `stats`; `snapshot` (a `CellState` value) and `storedClaim` are readable without entering the actor. |
| `CellSession` | The typed API: `CellSession.join(_:)`; `state` (`CellState`: `joined`, `holder`, `isHolder`, `gated`, `claim`, `state`, `seq`, `entitled`, `canWrite`), `subscribe(_:)`, `events(_:)` (`CellEvent`, bytes decoded); `take`, `ask`, `pass(to:snapshot:)`, `decline`, `release`, `publish`, `submit`, `presence`, `ping`, `leave`, `close`. |
| `ClaimStore`, `Fence`, `StoredClaim`, `compareAndSet(held:record:expected:)` | The contract of §3. A fence is two integers in 0 … 2^53 − 1 (the range every host stores exactly); anything else is `ClaimStoreError.badFence`. |
| `MemoryClaimStore`, `SQLiteClaimStore` | The stores that provide it (below). |
| `SessionFrames.frameText(ofMessage:)` | `sessionFrameText` of §1, over the message's UTF-8 bytes. |
| `URLSessionSocketFactory`, `SocketFactory`, `HostSocket`, `SocketHandlers` | The socket behind a small interface; tests inject a fake. |
| `HostClock`, `SystemClock` | Monotonic and wall milliseconds and a timer. `SystemClock` reads `CLOCK_MONOTONIC`, which keeps counting while the device sleeps, and sleeps on the continuous clock. |

**One serial queue per host.** Each host is an actor whose inputs arrive through one ordered stream
(`AsyncStream`) and run one at a time, in arrival order. A stream host's job never suspends. A cell
host's job may suspend to read the engine (`HostAccount.engine()`), but the next job starts only when it
ends, so actor re-entrancy never lets two jobs interleave over the endpoint; the work that runs beside the
jobs (a save in flight, the per-beat fence read, a delegation being signed, a rebuild) touches only the
host's own fencing state and hands its result back as a later job. Listeners are synchronous closures,
called between jobs; anything they do (a command, a frame, `accountChanged`, `stop`) is a later job, in
the order they did it. A command's caller resumes only after the listeners heard the events of the job
that ran it. Socket callbacks arrive on one serial delegate queue and reach the host in order.

**What is not public.** Nothing public hands out the engine, a raw signer, the endpoint, the stream client or an
account view, or lets a caller act on them outside a host's queue: the account behind `ColophonHostAccount`, the
endpoint and an injected client are internal. `swift/Tests/ColophonHostsTests/ColophonHosts.public-api` pins every
public declaration of the module, and a test fails on any change to it or on a public declaration naming those types.

**History.** The head is read for `historyChanged` one read at a time (a request during a read runs one more after
it), and a sequence below the greatest one already given to `on_history` is discarded, whether it came from a read
or from a pass: the history the core is told never goes back.

**The engine.** The hosts' account keeps the `AccountEngine` handle of the session's current
`ColophonEngine` and takes a new one when the session opens another engine. Stream and endpoint calls go
straight to the handle, which serializes its own calls; they do not queue behind a long call on the
engine actor's queue (an endpoint reads the engine's gate, never its lock: bindings-05 §10).

**The socket.** `URLSessionSocketFactory` opens a `URLSessionWebSocketTask` (only `wss`, and `ws` to a
loopback address when `allowingLoopback` is set) in its own ephemeral session, never logs or reports its
URL, and reports `open`, every text message in order, and one end. Unlike a browser's `WebSocket`,
`URLSessionWebSocketTask` keeps the HTTP response of a refused upgrade on the task: its status and headers
reach the core through `on_refused` (the end-to-end suite shows a ticket the home never issued reported as
`refused 403`). The body is not available, so the answer's body is empty: a 429 or 503 is read with its
`Retry-After`, a 404 as unsupported, and a `403 refused:revoked` as an unrecognised refusal, which backs off
within the ticket budget (close 1008 still ends a live stream). A failure without a response is
`on_closed(None)`. `close(code:)` sends the code the step names (`CloseCode` is an open enumeration).

### 6a. The durable claim store

`SQLiteClaimStore(path:name:busyTimeout:)` keeps each cell's claim in one row of one table of a SQLite
database, through the system's `libsqlite3` (part of the OS; no dependency is added):

```sql
CREATE TABLE colophon_claims (name TEXT PRIMARY KEY NOT NULL,
  generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740991),
  seq INTEGER NOT NULL CHECK (seq BETWEEN 0 AND 9007199254740991),
  claim TEXT) STRICT
```

- **The compare-and-set** is one `BEGIN IMMEDIATE` transaction: read the row, compare, write, commit.
  `BEGIN IMMEDIATE` takes the database's write lock before the read, so of all the clients of one file
  (instances, processes, an app and its extensions sharing a container) exactly one is between its read
  and its commit at a time, and each compares against what the last commit left. A client that cannot
  take the lock within `busyTimeout` (5 s) fails the save with an error, never `stale`; the host treats it
  as a failed attempt and reads the held fence before trying again (§3).
- **Durability.** WAL mode with `synchronous = FULL` and `fullfsync = ON` (`checkpoint_fullfsync = ON`
  for checkpoints): a commit returns only after its WAL frames are synced with `F_FULLFSYNC`, which on
  Apple platforms also flushes the drive's cache, so `stored` survives a crash or power loss. In WAL mode a
  commit becomes visible to other connections only when it updates the WAL index, after that sync, so no
  reader can see a fence that could still be withdrawn (§3a, 1 and 2). `synchronous = NORMAL` would make a
  commit visible before it is synced and could lose the last commits on power loss; it is not used. The
  store checks that WAL and `FULL` are in force when it opens and refuses to open otherwise.
- **Failing closed** (§3a, 3). The database file is the store's alone: `sqlite_schema` must hold exactly the
  claim table and its primary key's index. Any other object (a trigger that could delete or rewrite the row, a
  view under the table's name, another table or index) is an error when the store opens and inside every read
  and write transaction, so one added later is found at the next read or save. Every write is read back
  inside its transaction and must equal what was written before it commits; anything unexpected rolls back.
  The table is `STRICT` and range-checked, and every read checks each column's type and range. A file that
  is not a database cannot be opened.
- **Settings are read back.** SQLite accepts an unknown or ignored pragma silently, so each connection sets
  the busy timeout (its result checked) and `journal_mode`, `synchronous`, `fullfsync`,
  `checkpoint_fullfsync` and `trusted_schema = OFF`, then reads every one back (and the busy timeout) and
  refuses to open unless each reports the value required. A client that cannot take the write lock within
  the busy timeout fails its save (a failed attempt to the host), and writes nothing.
- **File protection.** On iOS, iPadOS, visionOS, tvOS and watchOS the database and its WAL and index files
  are created with `completeUntilFirstUserAuthentication` (`SQLITE_OPEN_FILEPROTECTION_...`): readable while
  the device is locked after its first unlock. A device playing in the background with its screen locked
  must keep checking its fence every beat; under `complete` protection those reads would fail and the cell
  would fail closed (`store`) after three beats. A store whose reads fail does exactly that (tested by
  injecting the failure).
- Each instance is one client with two connections, each on its own serial queue (SQLite's calls block,
  and never run on the cooperative pool): one writes, one reads `load` and the per-beat `fence`, so a slow
  write does not delay a fence check. Several cells may share one file under different `name`s.

A store for other storage follows §3a. There is no file-and-lock or file-and-rename store: both designs
fail §3a (a lock that can be stolen; a commit visible before it is irrevocable).

### 6b. Suspension and the background on iOS

The host adds no machinery for the app's life cycle; the core's steps cover it, and the app's part is
small. What Apple documents (TN2277, "Networking and Multitasking"): a suspended app runs no code, and
the system may reclaim a suspended app's sockets at times it does not document; on resume an operation on
a reclaimed socket fails. An app with the `audio` background mode is not suspended while it plays, and
becomes eligible for suspension when playback stops. A background task (`beginBackgroundTask`) gives
limited time to finish work, not a way to keep a socket open.

- **Suspended.** Nothing runs: no frame is read, no tick or timer fires (timers on the continuous clock
  fire at once on resume if they fell due). The other members see the device go quiet: a holder lapses to
  them after `holderTimeoutMs` and one of them may take. On resume the host's pending timers fire and the
  socket reports its end (a failure, `on_closed(None)`), or the home's idle close; either way every cell
  hears `linkDown`, and the stream backs off and reconnects through its own steps. `CLOCK_MONOTONIC` kept
  counting, so the endpoint sees the true length of the outage, never a backwards clock; a holder that
  was out of contact is gated and then retakes or yields (§S6), as the offline journey shows.
- **Playing audio in the background** (the `audio` mode, an active audio session): the app keeps
  running, so the socket, the ticks and the beat continue, and the playing device receives an `ask` and
  can `pass` from the background. When playback stops the app may be suspended as above; an application
  that passes or releases the role should do so before it stops its audio session.
- **What an app does.** Call `HomeStreamHost.retryNow()` on entering the foreground (and on a network
  change), so the stream reconnects at once instead of waiting out a backoff; keep the existing poll timer
  while `polling` is true. Nothing else is required: the core's steps, not the host, decide when to
  reconnect, mint or lapse.

Not verified: these behaviours on an iOS device or simulator, and the protection class on a locked device.
The Swift suites run on macOS only.

### 6c. What was run

`scripts/test-swift-hosts.sh` builds a macOS slice of `colophon-ffi` and of the conformance crate and
the relay's home module (or takes them from `COLOPHON_FFI_LIB`, `COLOPHON_CONFORMANCE_LIB`,
`COLOPHON_HOME_WASM` and `UNIFFI_BINDGEN`), keeps private copies in `.build/hosts06`, and runs:

- `ColophonHostsTests` (`swift/Tests/ColophonHostsTests`), on macOS with the real `HomeStream` and real
  endpoints of a local account: `StreamHostTests` (the matrix of `stream-host.test.ts`, the socket
  factory refusing anything but `wss` or an allowed loopback `ws`, and a pass completing with an older head after
  a newer read, discarded), `PublicAPITests` (the pinned public surface), `CellHostTests` (that of
  `cell-host.test.ts`, every test also checking that no cell ever had two saves in flight),
  `ClaimFenceTests` (two clients of one storage opening in all six interleavings, a rebuild racing an
  open in all three, a superseded holder stopping within one beat, fences out of range, and the SQLite
  store: its compare-and-set across connections, eight clients of one file racing from one fence twice,
  two hosts on two connections opening at once, a restart from what it stored, failing closed on a foreign
  table, trigger, view, index or file before open and on a trigger added after it, every setting read back
  on both connections, a write that fails before its commit rolling back, a save that cannot take the write
  lock failing at the busy timeout, and a cell whose reads start failing failing closed with `store`),
  `FramesTests` (the adversarial matrix of `frames.test.ts`), `ShippingSurfaceTests` (the 9 `offset.json`
  cases through the shipping `sessionClockSample`, and no conformance name in the shipped package), and
  `EndToEndTests`.
- `swift/Conformance06`, a separate test-only package that links the conformance crate's artifact:
  every machine transcript (26), `wire/vectors.json` (19 frames, 20 scenario steps, 26 negative frames)
  and strict decoding. The root package neither links nor exports it.

`EndToEndTests` runs the five journeys of §4 against `relay/server.js` on Bun with the home module, each
member with its own `HomeStreamHost` over a real `URLSessionWebSocketTask` on loopback. Measured on one
Mac: from B's ask to A observing that it yielded about 1.2 ms, to B holding about 2 ms; a restarted holder
retakes after about 303 ms against `askTimeoutMs` 300; B sees A lapse 1.5 s after A's network is cut and
holds about 1 ms after its take; A yields about 15 ms after its network returns; the revoked member's frame
is dropped by B (`delegation`), the home ends its stream (`Blocked`, `AccessEnded`), and its next command
reports the stale view and then `entitled = false`. One difference from §4 journey 4: the stores take
250 ms per write, under the fast policy's `askTimeoutMs` (300). A holder whose pass is being written sends
nothing as holder meanwhile, so with a longer write the asker may take on its own once `askTimeoutMs` has
passed without a holder frame (§S5) and then receives the pass as a late pass; whether it does depends on
whether a beat happened to reach it in that window.

Not run: iOS, visionOS or a simulator (only a macOS slice is built), a real network, or a home other
than the reference relay. Not verified for the SQLite store: clients in separate processes (the tests use
several connections in one process, which take the same file locks), durability across a crash or power
loss (it rests on SQLite's documented WAL and `F_FULLFSYNC` behaviour, not on a test), and reads on a
locked device.
