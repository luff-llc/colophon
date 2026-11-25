# 0.6 hosts: the home stream and session cells (JavaScript, Kotlin)

**Status:** stage 2 of Colophon 0.6 for JavaScript. Stage 1 is the binding surface of
[bindings-05.md](bindings-05.md) §10 (`HomeStream`, `SessionEndpoint` and the engine's stream and
session calls). This stage adds the host layer that drives that surface over a real WebSocket, in
`js/src/hosts` (`@colophon/core/hosts`), and proves the flagship behaviour end to end. The Kotlin host
(JVM and Android) follows the same shape and is described in §6; the Swift host follows it too.

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

## 6. Kotlin (JVM and Android)

`com.luff.colophon.hosts` in `sdk/kotlin` is the same host layer for Kotlin, over the generated `HomeStream` and
`SessionEndpoint` of `colophon_ffi.kt`. It is plain Kotlin in `src/main`, which the Android library compiles too, so it
uses nothing Android lacks; the one JVM-only piece (the `java.net.http` socket) is in `src/jvm`, which only the JVM
module compiles. The Android pieces are in `sdk/android` (`org.luff.colophon.hosts`). No dependency was added: the JVM
module still has JNA and kotlinx-coroutines only.

### 6.1 The API

| Object | What it is |
| --- | --- |
| `HostAccount`, `accountOf(session)`, `transportOf(session, home)` | As in §1: `account`, `member`, `engine()` (the `AccountEngine`, read again for every call), `suspend streamCall(home)`, `suspend exchange()` (the session's own `syncNow`), `suspend signRaw(body)`. Two session additions back it: `SessionWorker.streamCall` (the `colophon.home.stream` call, signed and judged like any call) and `transportOf`. |
| `HomeStreamHost(StreamHostOptions)` | `start`, `stop`, `status`, `polling`, `cursor`, `live`, `retryNow`, `historyChanged`, `attach`/`detach`, `sendSession(frame)`, `on(listener)`, `onPass(listener)`; `carrier()` adapts it to `CellCarrier`. Options: account, home, `socket` (a `SocketFactory`, required), `transport` (default `HttpHomeTransport`), `clock`, `configure`, `cursor`, `saveCursor`, `client`, `dispatcher`. |
| `SessionCellHost.open(CellHostOptions, listener)` | `command(name, json): Deferred<Unit>`, `deliver`, `linkUp`, `linkDown`, `accountChanged`, `leave`, `close`, `current`, `phase`, `storedClaim`, `writePending`, `stats`. Options as in §1 (`persistRetryMs`, `persistTimeoutMs`, `persistAttempts`, `fenceCheckMisses`, `maxCommands`, `delegationMs`, `random`, `state`), plus `dispatcher`. Events are the `CellHostEvent` sealed class; failures are `CellHostError` with a `Code`. |
| `CellSession.join(options)` | `state: CellState` (`joined`, `holder`, `isHolder`, `gated`, `claim`, `state`, `seq`, `entitled`, `canWrite`), `subscribe`, `events` (`CellEvent`, bytes decoded); `take`, `ask`, `pass`, `decline`, `release`, `publish`, `submit`, `presence`, `ping` (each returns a `Deferred`), `leave`, `close`. Show the role as held only when `isHolder && !gated`. |
| `ClaimStore`, `Fence`, `StoredClaim`, `SaveResult`, `compareAndSet`, `MemoryClaimStore` | §3's contract with `suspend` calls; a fence is two integers in 0..2^53 − 1. |
| `SqliteClaimStore` (Android) | The durable store, §6.3. |
| `Frames.sessionFrameText`, `frameCell`, `frameBytes`, `frameText` | §3's frame extraction, with the same adversarial matrix (`FramesTest`). |
| `HostClock`, `SystemHostClock`, `AndroidHostClock` | Monotonic and wall milliseconds and a timer. On Android use `AndroidHostClock` (`elapsedRealtime`, which counts deep sleep). |
| `SocketFactory`, `HostSocket`, `SocketHandlers`, `JdkWebSocketFactory` (JVM) | The transport, §6.4. |

**One serial context per host.** Each host runs every job and every one of its coroutines on one serial dispatcher (by
default its own lane of `Dispatchers.Default`; a test passes a dispatcher it drives). A job is ordinary,
non-suspending code: it calls the endpoint and carries out the step, and nothing can run between two of its lines. The
work that suspends (a store save, a signature, a ticket request, a pass) runs as a coroutine on the same context and
comes back as a new job, so a suspension never lets another job interleave with endpoint state. Socket reports,
timers and calls from other threads only enqueue. Listeners are called on the host's context, between jobs; whatever
they call is a later job. A command is admitted (takes its place among frames, ticks and link changes) when `command`
is called, from any thread, and its `Deferred` completes after the events of the step that ran it reached the
listeners. A `ClaimStore` must not block its caller: the shipped SQLite store moves its I/O to `Dispatchers.IO`.

Everything else is §2 and §3 as written: the same steps, effects in order, the acknowledgement only after the durable
write, single-flight fenced saves with a write deadline and bounded attempts, the reservation on open and rebuild, the
beat-by-beat fence check with three misses failing closed, the bounded command hold, `staleAccount`, `clockBackwards`,
`wrongView`, a new session number, `gated`, and `ask` answered by `pass` between live devices.

### 6.2 The JVM stores

The JVM module ships `MemoryClaimStore` (one record behind a lock; the compare and the write are one step for every
client sharing the object) and the `ClaimStore` interface. It ships no durable JVM store: the JDK has no embedded
database, a file-and-lock or file-and-rename design does not meet §3a (a lock can be stolen; a commit can be visible
before it is irrevocable), and a SQLite driver would be a new dependency. A desktop or server host supplies its own
store over storage that gives a linearizable compare-and-set.

### 6.3 The Android store

`SqliteClaimStore` uses the platform's SQLite (`android.database.sqlite`): one database file in `noBackupFilesDir` (a
restored backup would bring back an old fence), one table `claims (cell TEXT PRIMARY KEY, claim TEXT, generation
INTEGER, seq INTEGER)`, one row per cell.

- `save` is one `BEGIN IMMEDIATE` transaction (`beginTransactionNonExclusive`): the write lock is taken before the row is
  read, the compare-and-set is applied, the row written, and the transaction committed. A stale save rolls back. Every
  client of the file (another object, thread or process) is serialized by SQLite's lock, so the compare-and-set is
  linearizable.
- The file is opened with `journal_mode=WAL` and `synchronous=FULL`, and both are read back (anything else refuses to
  open). With FULL in WAL mode the log is synced at each commit before the commit is published to other connections,
  so a reader never sees a commit that a power failure could take back, and `STORED` is returned only after the commit
  returned. Android's default for a database that sets nothing is WAL with `synchronous=NORMAL`, which can lose a
  commit already seen: that is why the mode is set explicitly.
- It fails closed: a schema other than its own table and primary-key index, a claim that is not text or null, a fence
  half that is not an integer in range, is `ClaimStoreCorrupt` from `load`, `fence` and `save`.

`SqliteClaimStoreTest` (an instrumented test in `sdk/android/src/androidTest`) races six clients of one file from one
fence over 25 rounds (exactly one stores each time), checks a stale save writes nothing, a reopen, the journal mode,
and fail-closed rows and schemas. It needs a device or an emulator.

### 6.4 The transport

The host owns the socket's lifecycle through `SocketFactory.open(url, handlers): HostSocket` (`send(text)`,
`close(code)`) and `SocketHandlers` (`open`, `message`, `refused(answer)`, `closed(code?)`), reported from any thread.
The host owns a socket before any listener hears of it, ignores reports from a socket it replaced, and `stop()` closes
the current socket at once from any thread, including one whose upgrade is still outstanding.

**JVM: `JdkWebSocketFactory`** (`java.net.http.WebSocket`, Java 11; the module targets 17). Fragments are joined and a
message is bounded (64 KiB, the core's own bound). A refused upgrade is reported with its status and headers through
`refused`; the JDK discards the refused answer's body, so a `403 {"result":"refused:revoked"}` reaches the core as a 403
without a result, which backs off and mints again within the budget and the breaker rather than ending access at once
(a revoked member still learns it from its next pass, and close 1008 still ends a live stream). A close code the JDK
will not send from a client (1002) is sent as 1000 and the core is told its own code. Closing a socket still opening
drops the connection when the upgrade completes.

**Android has no `java.net.http` and no WebSocket client in the SDK.** The options:

1. *An app-supplied `SocketFactory` over a client the app already has.* About thirty lines over OkHttp (below). It
   costs the SDK nothing, but it is only available to an app that already ships a WebSocket-capable client.
2. *A minimal RFC 6455 client in the SDK over `SSLSocket`.* Its whole scope: the client role only; `wss` only; the
   HTTP/1.1 upgrade with a random `Sec-WebSocket-Key`, verification of `Sec-WebSocket-Accept`, `Upgrade` and
   `Connection`, and reading a refusal's status line, headers and a bounded body (which `java.net.http` cannot give);
   text messages out (masked, one frame each) and in (unmasked frames only, continuation frames joined, a message bound
   of 20,480 bytes, the home's own message limit, enforced while reading); ping answered by pong; the close handshake
   both ways with a deadline; no extensions, no compression, no subprotocols, binary messages dropped. The parts that
   decide its safety: TLS through the platform's default `SSLSocketFactory` with explicit hostname verification (an
   `SSLSocket` does not verify the host name by itself: set `SSLParameters.endpointIdentificationAlgorithm = "HTTPS"`
   before the handshake, or check with `HttpsURLConnection.getDefaultHostnameVerifier()`), the platform's trust store
   and network security configuration as `HttpsURLConnection` uses them, no trust-all path and no plain `ws` outside a
   loopback testing option; connect, handshake and read timeouts; UTF-8 validated strictly; every length checked before
   allocation. Size: about 500 to 700 lines and a test suite of similar size. Testing: the same five journeys against
   the reference relay with both socket factories on the JVM (`SSLSocket` exists on both platforms, so the client is
   JVM-testable, and `java.net.http` is the differential reference), a scripted loopback server for the edge cases
   (fragmented and interleaved control frames, a masked server frame, a reserved bit or opcode, a length over the
   bound, a 64-bit length, a bad accept key, a refused upgrade with and without a body, a close without a code, a close
   during the upgrade, a peer that stops answering), and a TLS test with a wrong host name that must fail.
3. *A dependency.* OkHttp 4 is about 0.8 MB and needs Okio (about 0.35 MB) and the Kotlin standard library, before
   shrinking; it brings its own connection pool, and the SDK would then pin a version the app must align with. It
   breaks the SDK's rule of no third-party networking dependency and any app's rule of no third-party dependencies.

An app-supplied OkHttp adapter, as an example (not part of the SDK):

```kotlin
class OkHttpSocketFactory(private val client: OkHttpClient) : SocketFactory {
    override fun open(url: String, handlers: SocketHandlers): HostSocket {
        val ended = AtomicBoolean(false)
        fun end(code: Int?) { if (ended.compareAndSet(false, true)) handlers.closed(code) }
        val ws = client.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) { if (!ended.get()) handlers.open() }
            override fun onMessage(webSocket: WebSocket, text: String) { if (!ended.get()) handlers.message(text) }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) { webSocket.close(1000, null); end(code) }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = end(code)
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (response == null || response.code == 101) return end(null)
                if (!ended.compareAndSet(false, true)) return
                val body = runCatching { response.peekBody(65_536).bytes() }.getOrDefault(ByteArray(0))
                val headers = response.headers.map { (n, v) -> Header(n, v) }
                handlers.refused(HttpAnswer(response.code.toUInt(), headers, body))
            }
        })
        return object : HostSocket {
            override fun send(text: String) { check(ws.send(text)) { "not sent" } }
            override fun close(code: Int) { ended.set(true); if (!ws.close(code, null)) ws.cancel() }
        }
    }
}
```

Session frames need the stream: an HTTP long-poll fallback carries no session frames, so it would not provide handoff.

### 6.5 Android: Doze, standby, a foreground service, and the network

From the Android documentation ("Optimize for Doze and App Standby", "Power management restrictions"): in Doze (screen
off, unplugged and, for deep Doze, stationary) the system suspends network access, ignores wake locks and defers
alarms, jobs and syncs to maintenance windows that come less often over time; in App Standby an idle app's network is
deferred (in the *rare* and *restricted* buckets it is disabled). The app-state table lists a process running a
foreground service as having no network restriction, while the device-state table lists network as restricted while
Doze is active; the documentation does not say which wins for a foreground service in Doze, and this was not measured
on a device. A foreground service also keeps the app out of App Standby.

What the host does, whatever the cause: a socket that stops (the network suspended, a NAT timeout, Doze) is reported
by the client as closed, or found dead by the core's own ping after `pingMs` and idle close after `idleMs`; the stream
host reports the close to the core, every attached cell gets `linkDown`, and the core backs off and reconnects through
its own steps (a new ticket, the saved cursor), at which point the cells get `linkUp` on the subscription's ack. Timers
cannot fire while the CPU is suspended; they fire late on wake and the core is given the true time
(`AndroidHostClock` counts sleep), so a holder that slept past `holderTimeoutMs` is lapsed to the others and returns
gated (§S6) rather than acting as holder at once.

What an app must do:

- Keep the playing device's process in a foreground service of type `mediaPlayback` while it holds `now-playing`: that
  device is the one that must receive an `ask` and `pass`. Without it the process may be frozen or killed, and its
  role lapses to the others after `holderTimeoutMs`, which is correct but is not a handoff.
- Call `HomeStreamHost.retryNow()` on foreground entry and when `ConnectivityManager.NetworkCallback` reports a usable
  network again, never from a timer (the core bounds it). There is nothing to call when the network drops: the
  socket's close does it.
- Use `AndroidHostClock` and `SqliteClaimStore`, and while `polling` is true keep the session's own poll.
- Test with `adb shell dumpsys deviceidle force-idle` and `am set-inactive <package> true`, as the documentation
  describes. These behaviours were not run on a device here.

### 6.6 What was run

`scripts/test-kotlin.sh` builds the release library, checks the committed bindings, builds the conformance library
and checks its committed test-only bindings (`sdk/kotlin/src/conformance`), builds the home module, pins those three
files in `sdk/kotlin/build/native` (another checkout sharing the cargo target cannot replace them mid-run), and runs
every Kotlin test. The 0.6 host tests are `com.luff.colophon.hosts.*`:

- `StreamHostTest` (15), `CellHostTest` (22), `ClaimFenceTest` (5: two clients opening in all six interleavings, a
  rebuild racing an open in all three, eight threads racing the memory store from one fence over 20 rounds, a
  superseded holder stopping within one beat, fences out of range), `FramesTest` (4), on the core's real objects with
  a manual clock, a driven dispatcher and fake sockets, transports and stores, as the JavaScript tests do.
- `ConformanceTest` (3): the 26 machine transcripts, the 9 `offset.json` cases and `wire/vectors.json` (frames,
  scenario steps and negative frames), strict decoding, and that no shipped source names the conformance surface.
- `HandoffTest` and `ScenariosTest`: the end-to-end proof of §4 through the Kotlin hosts over `java.net.http`
  WebSockets to the reference relay, which binds a port of its own choosing (port 0) and whose standard error is kept
  and shown when a test fails. All five journeys pass. In journey 4 each write takes 200 ms, below the fast policy's
  `askTimeoutMs` (300 ms): a holder sends nothing while its write is outstanding, and an asker that hears no holder
  frame for `askTimeoutMs` after asking may take (§S5), so with a 500 ms write the asker sometimes, correctly, takes
  instead of being passed to.

Not run: the Android library was not built (no Android SDK platform 35 was available) and no instrumented test was
run, so `SqliteClaimStore` and `AndroidHostClock` are unrun on a device; the shipped Kotlin sources and those two
files were typechecked against an API 34 `android.jar`. No device, emulator, Doze or standby behaviour was observed.
