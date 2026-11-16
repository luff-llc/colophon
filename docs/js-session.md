# The JavaScript session on Colophon 0.5

`ColophonSession` (`@colophon/core/session`, source in `js/src/session/`) is the one object a web app holds over a
Colophon 0.5 account. It gives a web app what [the Apple session](session.md) and [the Kotlin session](android.md) give
native apps, with the same names where JavaScript allows, over the `web05` wasm-bindgen exports
([bindings-05.md](bindings-05.md)). It also runs under Bun and Node (tools, agents, tests).

What the session decides: nothing about the account. Every verdict (phase, access, notices, deadlines, who may veto) is
the engine's; the session only chooses what to show and what to call next.

The 0.4 package (`@colophon/core`, `js/src/index.ts`, [js-api.md](js-api.md)) is unchanged and still built from the same
wasm module. What still applies from it: the build (`js/scripts/build.sh`), and the shape of its WebCrypto and passkey
providers, which the session's own `WebCryptoKeyProvider` and `PasskeyProvider` follow. Its `Library` object and
`KeyProvider` are 0.4 only.

## The pieces

| File | What it is |
| --- | --- |
| `wasm.ts` | Loads the module once (`init`). `plain()` copies a record the glue returned into plain values (camelCase, `bigint` for `u64`/`i64`) and frees the wasm object; every call builds fresh records, because a record passed to a call is consumed by it. |
| `medium.ts`, `indexeddb.ts`, `node.ts` | `RecordMedium`: the record store the engine reads. `IndexedDBMedium` (browser), `FileMedium` (Node and Bun, `@colophon/core/session/node`), `MemoryMedium` (tests, with fault injection). |
| `private.ts` | `PrivateStore` (the session journal and the sealed saved state), `DeviceSecretStore` (the 32-byte key that seals saved state). |
| `keys.ts`, `passkey.ts` | `AsyncKeyProvider`, `KeyCustody` (answers the engine's signing steps, PRF requests, unlock inputs and epoch agreements), `WebCryptoKeyProvider`, `PasskeyProvider`. |
| `secrets.ts` | `SecretBytes`: secret memory the SDK owns and zeroes. |
| `transport.ts` | `HomeTransport`, `FetchHomeTransport`, `HomeLimits`. |
| `engine.ts`, `worker.ts`, `session.ts` | One `AccountEngine` with its lifecycle; the worker that runs every operation; the facade that publishes state. |
| `blobs.ts` | `putBlob`, `blobAvailability`, `blobData`, `prefetchBlob`, `downloadRequiredBlobs`, `setBlobReference`. |
| `gate.ts` | `gateContent` (what a library screen shows for each phase), `attachPageLifecycle` (lock when the page is hidden). |

## Configuration

```ts
import { init, ColophonSession, IndexedDBMedium, IndexedDBPrivateStore, WebCryptoKeyStore, WebCryptoKeyProvider,
         WebCryptoDeviceSecrets, PasskeyProvider, attachPageLifecycle } from '@colophon/core/session';

await init(wasmUrl);                                             // once; a bundled app passes the module's URL
const session = new ColophonSession({
  memberLabel: 'Taupe', namespaces: ['listening.podcasts'],
  medium: await IndexedDBMedium.open('library'),
  privateStore: new IndexedDBPrivateStore('library-private'),
  keys: await WebCryptoKeyProvider.openOrCreate('member', new WebCryptoKeyStore()),   // this device's member key
  ownerController: passkey,                                      // the person's passkey: approve, veto, add a device
  deviceSecrets: new WebCryptoDeviceSecrets(),
  homes: [{ endpoint: 'https://home.example/v1/libraries/acct/' }],
});
attachPageLifecycle(session);
await session.restore();
session.subscribe(state => render(state));
```

* `keys` is the content member: it signs records and opens the member's epoch shares (a silent ECDH). `ownerController`
  is a controller of the account, asked only for owner operations: creation, approving a member, revoking, adding a
  controller, veto, seed transfer.
* **Homes (spec §18).** `create()` refuses with `noHome` unless `homes` is non-empty or `createWithoutHome` is set, and a
  home whose endpoint is not `https` is `insecureHome`. `HomeConfiguration.request` is called with the new account's ID
  and answers with the home's signed member request; the session appoints the home in a transition signed by the owner
  and records its activation at once.
* `now` is the clock the engine judges by; tests move it. `exchangeTimeMs` is the longest one exchange with one home may
  take (default 180 s).

State is `session.state`: a frozen value the session replaces on every change and never changes in place (the records
inside it are shared, so treat them as read-only). `subscribe` is told when it is replaced.

**A creation can be finished later.** The genesis is stored first and the journal marks the setup as pending; appointing
the homes and approving this device follow. If one of those fails (a home that does not answer, a cancelled prompt, a
closed tab), the phase is `failed` with `state.setupPending`, and `retry()` (or `create()`) finishes the setup from where
it stopped: a home already appointed is not appointed again. No account is left that nobody can enter.

## Storage

The engine's source callbacks are **synchronous** (bindings-05.md §3a: a `Promise` returned to the engine is a `Host`
error), so `RecordMedium.listing`, `read` and `readBlob` are synchronous and `write` is asynchronous.

* **`IndexedDBMedium`** keeps everything it stores in memory, so reads are answered at once. `write` is **one
  `readwrite` transaction with strict durability**: IndexedDB commits all of a batch or none of it, across a failure, a
  closed tab or a kill, and the in-memory copy changes only after the commit. Inside the transaction each path is
  compared with what the database really holds, so a second tab cannot make this one replace an immutable record. Other
  tabs on the same store are told through a `BroadcastChannel` and read again. **Bound:** the whole store is in memory,
  blob chunks included. That suits records and modest blobs; a store over OPFS synchronous access handles (in a worker)
  is the follow-up for large media.
* **`FileMedium`** publishes each batch through a journal in `.colophon.nosync/`: staged and synchronised files with a
  record of the batch, a rename of the staging folder to `commit-…` (the commit point), then renames into place. Before
  the commit point a failure leaves nothing; after it the next `listing`, `write` or open completes the batch. A
  committed batch is never discarded: if it cannot be completed the store is `unavailable` and the journal is kept.
  **A read never sees a batch half applied:** a reader that finds a `commit-…` folder takes the lock (waiting for a
  writer still at work) and completes the batch before it answers, or fails as `unavailable`. The lock is a file
  created exclusively that holds its holder's token; only the holder removes it, a dead holder's lock is taken over by
  a rename that is checked, and a holder asks again that it still holds the lock just before the commit point. There
  is no kernel lock here (Node and Bun have no portable one), so two processes can still overlap in the instant
  between one's check and its rename; batches are then still whole, each in its own journal folder.
* **The private store and the pairing ledger.** `IndexedDBPrivateStore` writes each value in one `readwrite`
  transaction with **strict durability**, the strongest commit IndexedDB offers: when the promise resolves the browser
  has committed it to disk. The session writes the sealed pairing ledger and its generation, and awaits both, before it
  releases a ceremony's nonce. `FilePrivateStore` (Node) syncs the file, renames it into place and syncs the directory.
  `MemoryPrivateStore` keeps nothing across a reload; a host's own `PrivateStore` gives only the durability it implements,
  and the five-an-hour bound across crashes is as durable as that. Starts are serialized by
  a Web Lock shared by every tab and worker of the origin; where the platform has no `navigator.locks` (Node, Bun) the
  lock covers one process only, so two processes over one `FilePrivateStore` are not coordinated.
* A batch is checked whole before anything is stored (`planBatch`): a bad path, a size over 40 MiB or different bytes at
  an immutable path refuses all of it. Exact duplicates are idempotent; `state/` and `heads/` are replaceable.

If the store refuses the stores of a finished action, the engine is ahead of the store: it is discarded and reopened
from what is really stored, and the error is thrown.

## Keys and secrets

* **`WebCryptoKeyProvider`**: two P-256 keys with **non-extractable** private halves. `openOrCreate` keeps the
  `CryptoKey` handles in IndexedDB (`WebCryptoKeyStore`, an atomic insert so two tabs end with one key); nothing can
  export the private key, the browser included. This is software custody in the browser profile: script on the origin
  can use the key while the page is open, and it proves nothing about a person being present. A person's controller
  should be a passkey.
* **`PasskeyProvider`**: WebAuthn ES256 with user verification, and the PRF extension for the vault slot. Every ceremony
  is a `get` restricted to the one credential. `register` asks for PRF, records `authorityOrigins` (default: this
  page's origin) and makes sure every authority origin is also in `origins`; the core parses the attestation.
  `user.id` is the UTF-8 account ID when the account exists, else 32 random bytes (spec §17.4). **A passkey that
  returns no PRF output where one is needed fails (`unsupportedHere`): there is no fallback and no stand-in secret.**
  The core takes only `https://<host>` (no port) as a web origin, so a page served from `http://localhost` cannot own
  an account with a passkey.
* **`WebCryptoDeviceSecrets`**: the key that seals saved state is never stored. IndexedDB holds one non-extractable
  HMAC key and a random salt per account; the 32 bytes are `HMAC(key, salt)`, computed when asked. `remove` deletes
  the salt.
* **`SecretBytes`** holds every secret the SDK handles (PRF outputs, ECDH results, epoch shares, the device key) and
  overwrites it on `close`. The buffer WebCrypto or WebAuthn returns is adopted, not copied. Answers are built one by
  one, and **if a later provider fails, every secret built so far is wiped before the error propagates**
  (`collectSecrets`). The secrets of a finished or refused call are wiped in a `finally`. A secret that arrives after
  its prompt was abandoned is wiped on arrival.

What the SDK cannot reach, exactly: copies the browser keeps inside WebCrypto and WebAuthn before it hands a value
over; copies the JavaScript engine makes when it moves or grows an array; the copy into the wasm heap (the Rust side
overwrites that one: the three secret records are wiped by the call that consumes them, and freed blocks by the
zero-on-free allocator); and a page that is frozen or paged out. No secret is in an error, a `toString` or a
`toJSON`.

## Transport

`FetchHomeTransport` sends with no cookies, no cache, no referrer and **no followed redirect**. Only `https` is sent;
plain `http` goes only to a literal loopback address and only with the testing option. The URL is parsed and the host
compared whole (`localhost`, an IPv4 literal in `127.0.0.0/8`, `::1`), never by prefix, and a URL with a username or
password is refused. A response is read in pieces and refused when it passes its bound (the head 64 KiB, a blob chunk
1 MiB, a record 41 MiB, anything else 32 MiB), and one deadline (60 s) covers the whole request, the body included.

A runtime that shows a 3xx answer (Bun, Node) hands it to the engine, which reports it. A browser hides it (an opaque
redirect): that is `HomeProblem.redirected`, and the pass is abandoned.

**A browser needs CORS from the home.** The reference relay answers CORS only for the origins its operator lists, in
`cors.origins` in the config file or `COLOPHON_RELAY_CORS_ORIGINS` (comma separated), each exactly `scheme://host[:port]`
and compared whole. The list is empty by default, and then no CORS header is sent; the browser tests reach the relay
through a same-origin proxy. A deployed web client needs the home itself (devices reach it directly) to answer
preflights without a call and to send, on every answer including refusals, CORS headers for its allowed origins: the
methods GET, POST and PUT, the request headers `Authorization`, `Content-Type`, `If-Match` and `If-None-Match`, and the
exposed headers `ETag`, `Retry-After` and `WWW-Authenticate`. A refusal without them reaches the page as a network
failure, and the engine never sees its code. Two answers the runtime writes before the relay sees the request, an
automatic `100 Continue` and the HTTP parser's `431` for oversized headers, carry no CORS headers.

## The exchange

`syncNow(signal?)` is one exchange per home; passes never overlap (callers queue). The loop is the engine's:
`exchange_next` returns a request, a "needs a call", waiting or done. For a `NeedCall` the session checks that the need
is for the configured home and audience, asks the engine for the call (`exchange_begin_call`), signs it with the member
key, and gives the envelope back; a call the core's own check refuses is `HomeProblem.callRefused` with its code, and
nothing is sent. A request for another home is sent only if it is that home's public head and carries no credential.
Passes repeat until one moves nothing (at most four). A home is held to 20,000 steps a pass and to `exchangeTimeMs`,
which covers the transport whatever the transport does with its signal.

**However a pass ends that is not `Done`, it ends in `exchange_abort`:** a transport failure, an engine error, a bound,
the deadline, an aborted `signal`, a cancellation that arrives after the home answered and before the engine has the
answer, or the session being locked. The next pass never finds the engine waiting for an answer nobody will give; if it
ever does (`Waiting`), the pass is abandoned and run again once.

`record_due` runs on every refresh and on a 60-second schedule. The background loop polls every
`recoveryDelay / 6` (15 s while a change is pending), with a capped, jittered backoff after a failure; a local change
wakes it.

## Phases, the gate, and lock

Phases: `opening`, `noLibrary`, `creating`, `waitingForApproval` (with its code), `ready`, `refreshing`,
`waitingForDownload`, `retry`, `denied`, `unavailable`, `updateRequired`, `stopped`, `failed`, `locked`. `gateContent(state,
usable)` maps a phase to the library or to a screen with its actions; content is shown only while the session says it
is usable.

### A stopped account, a home's refusals, waiting for approval (freeze package)

**Stopped.** When a layout raise (spec §20) becomes final in the history this device verified, or it judges an authority
entry `newerFormat`, the engine's status carries `stopped` and the session's phase is **stopped** (Swift
`.stopped(seq:layout:)`, Kotlin `SessionPhase.Stopped(seq, layout)`, JS `{ kind: 'stopped', seq, layout? }`): this app must
be updated to continue with this account. It comes only from the verified status, never from a home's answer or a
refusal. What the device holds stays readable (`hasUsableContent` is true, as of the stop); every write is refused by the
core (`newerFormat`) and the phase stays, with no fault shown; no exchange runs (`syncState` is disabled, the loop waits
for an event with no timer or backoff, and no home is contacted); it persists across relaunch; lock, unlock and sign-out
work. The gate shows the content with a status line, or the screen `library.stopped` ("Update to continue"), with no retry.
While stopped the session does not refresh content: what it held when the stop was verified stays readable, and records
that arrive later are not admitted (the engine ignores them as well). The session persists the stop in its sealed saved
state the moment it sees it, so a relaunch whose store has lost the raise is still stopped (see `docs/bindings-05.md`).
The existing `updateRequired` remains for an account the engine cannot open at all.

**A home's refusals.** A home's error answer is read for its `result` only, validated against the §1 grammar (a named
result, or `refused:` and a reason of a lower-case letter then letters and digits, at most 48 characters) from a JSON body
of at most 64 KiB; no other byte of the body is kept (`HomeRefusal`, JS `homeRefusal`). A `refused:<name>` the session does
not know, the reserved `refused:overQuota`, `refused:noEntitlement`, `refused:closed` and `refused:notProvisioned`
included, is the existing home issue `remoteCallRefused`, now with the name as given and the home's `Retry-After`: it
refuses only that request (the pass goes on), except a refusal of this device's signed call (403), which ends the pass as
before; a 403 that names a refusal for a request that carried no call is not retried with a call. It is never a state of
the account. A `Retry-After` (whole seconds, 1 to 86,400) is honoured, as session policy (0.5 specifies it only for 429 and a home that
cannot sign a due head): the home is not
contacted again before then, and its refusal stays shown meanwhile. `503 {"result":"unavailable"}`, which a stopped home
answers (§13.6), is the issue `homeUnavailable`: the sync state is offline with "The home is not available right now"
(`HomeWords`), the loop backs off, and the device is not stopped. The retry signal of a refusal body is deferred (§16 of
the design), so `Retry-After` is the only signal honoured.

**Waiting for approval.** 0.5 keeps `refused:revoked` for a call by a member no grant names (`refused:notGranted` is
reserved). A device that asked to join and holds no grant for itself (its standing is unknown) shows a home's or its own
check's `refused:revoked` as the issue `waitingForApproval`, not as revoked; its phase is `waitingForApproval`. A device
that holds its own verified revocation is `denied`, as before.

`lock()` is synchronous and immediate: it overwrites the engine's keys and opened plaintext, locks any owner engine
open for an operation, frees every blob writer in use (each holds an epoch key; no chunk is encrypted after `lock`),
and aborts every key ceremony and exchange pass in flight. It does not wait for the operation
in flight or for **a key prompt nobody answers**: every provider call races the session's abort signal, so a hung
prompt ends as `cancelled` and holds neither `lock` nor the operations queued behind it. `attachPageLifecycle` locks
when the page is hidden (at once by default; a delay or `'never'` is a setting) and unlocks or refreshes when it is
shown. Unlocking a device member is silent.

## Writes, reads, blobs, notices

`perform(command, observed)` refreshes, requires `observed.revision` to be current, prepares, signs, finishes, **writes
the stores all or none**, then publishes the new state. `query` and `view` read. The blob calls keep the other SDKs'
names. `notices` and `duties` carry what spec §17.5 and §18 say a person must see: pending transitions with `vetoable`,
unseen activations, `noHome`, the sole-device warning, dead transitions, delivery routes, the removal follow-up
(`removeFollowUp`, `keepFollowUp`). `veto`, `proposeTransition`, `resign` and `suspendKey` submit to every home until
each receipted it or 300 s passed. A veto is submitted and waited for by **its own digest** (`vetoes/<digest>.json`),
not the transition's; it is also done when the transition is no longer pending, because once a home has recorded the
veto the other homes have nothing left to receipt. `acknowledgeActivation` marks one activation seen and never dismisses a pending
transition.

## Differences from the Swift and Kotlin sessions

* Records are plain objects with camelCase names; `u64` and `i64` are `bigint`; enums are the glue's numeric enums
  (`glue.StandingKind.Member`). Phases and problems are tagged unions (`{ kind: 'ready' }`).
* Cancellation is an `AbortSignal`. `lock()` and `shutdown()` are synchronous.
* Blob calls are functions taking the session (`putBlob(session, data, …)`), and take bytes, not files or streams.
* `RecordMedium.write` is asynchronous; `changes(listener)` returns the function that stops it.
* Not built here: the session-level steps of the Swift move (`ColophonMigration`), a UI kit, `rejoin` with a recovery
  kit screen, file watching for `FileMedium`.

## What was run, and what was not

`scripts/test-js.sh` builds the two wasm modules and the glue, builds and typechecks the TypeScript (the SDK strictly;
the tests against the SDK's own types), and runs:

* **Under Bun** (`bun test js/test05`): the reference journey of `crates/colophon-ffi/tests/v05_relay_journey.rs`
  through `ColophonSession` against the real relay (`bun relay/server.js --test-clock`, the Rust home module, signed
  calls required), with one home under `policy.history` `members` and `public` and with two homes at `headQuorum` 2. It
  asserts the exact `refused:revoked` from the home, and from the device's own check under `public`. And unit tests:
  the loopback rule; the transport's redirect, bounds and deadline; secrets wiped when a later provider fails;
  all-or-none batches (a throw at every step of a file batch, a real SIGKILL at every step, a committed batch that
  cannot be completed is kept); a pass cancelled while the transport waits, after it answered, offline, and with a home
  that never answers, each followed by a clean pass; a key prompt nobody answers and `lock`; lock in the middle of a
  pass; a store that refuses a finished write; a relaunch over files that resumes from saved state; a reader during a
  file batch; the file lock; a blob writer ended by `lock`; a creation whose home setup fails, finished by `retry`.
* **In a real browser engine** (`bun js/test05/run-browser.ts`: headless Chrome driven over the DevTools protocol by
  Bun, no npm driver): the same three journeys; `IndexedDBMedium` (a refused batch stores nothing, a reopen holds
  exactly what was committed, a second instance cannot make the first replace a record); `CryptoKey` handles that
  survive a reopen and cannot be exported; the derived device key; a hidden redirect; and **a passkey owner through a
  real WebAuthn ceremony with PRF** (Chrome's CTAP 2.1 virtual authenticator with user verification): an account
  created on browser storage, signed in again after a reload from saved state, a second device approved by assertion;
  and a passkey without PRF refused.

Not run, exactly:

* Safari and Firefox. Only Chrome (Chromium's engine) was run.
* A platform authenticator or a hardware security key: the passkey ceremony ran against Chrome's virtual
  authenticator.
* A tab killed in the middle of an IndexedDB transaction. The all-or-none guarantee there is IndexedDB's own; the test
  shows refused batches and reopen, not a kill.
* A deployed home across origins (CORS, above). The browser run goes through a same-origin proxy.
* A device on the Swift or Kotlin SDK and a JavaScript device on one account. Each SDK runs the same journey against
  the same relay through the same core; they have not been run together.
* The pairing ceremony and seed transfer (`transferSeed`, `acceptSeedTransfer`) are passed through to the engine and
  have no journey here.
* Delivery-route registration has no home that offers it yet.
* `*_json` results pass through `JSON.parse` in `query` and the blob manifest reader: a `u64` above 2^53 inside them
  loses precision (bindings-05.md §9). `view` returns the engine's text untouched.

The package is not published. Publishing it, and its version, wait for the owner.
