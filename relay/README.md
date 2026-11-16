# Colophon reference relay, and a Colophon 0.5 home

A small Bun server. It is the 0.3 HTTP exchange ([spec §8](../spec/colophon-0.3.md#8-http-exchange),
incorporated by 0.5 §11.8): per library slot, signed and encrypted records on disk, moved between
devices. And, for a slot you mark as a **home**, the server of Colophon 0.5
([§13 homes and heads](../spec/colophon-0.5.md#13-homes-and-heads),
[§14 exchange](../spec/colophon-0.5.md#14-exchange)): it keeps a copy of one account's history, orders
and receipts authority changes, signs heads, and serves members.

A relay is untrusted by clients. A home must itself be correct, so every decision a home makes is
made by the same Rust code the verifier uses (see "How it is built"). Slots that are not homes
behave exactly as the 0.3 relay always did: a token is storage access, never membership, and the
relay holds no keys. `GET {base}` keeps the marker `colophon/relay/3` (0.5 §20 lists it, and §14
says a home *adds* `home` to that response).

One home per account is the supported configuration in 0.5. Several homes for one account work in
the tests, but exchange between them (forwarding and candidate exchange) is experimental
(spec §13.1; open issues in `docs/multi-home-open-issues.md`).

## Run it

```sh
bun relay/server.js token       # a new bearer token and its SHA-256 (as before)
bun relay/server.js home-key    # a new home key: a private P-256 JWK. Keep it secret.
```

A plain 0.3 slot:

```sh
COLOPHON_RELAY_TOKENS="home=<token>" COLOPHON_RELAY_DATA=./relay-data bun relay/server.js
```

A 0.5 home. The account names this home in a member request whose `service.endpoints` is the
slot's public URL (it must be `https://`); that URL is the slot's `base`, and the call audience:

```sh
bun relay/server.js home-key > home-key.jwk        # once; chmod 600; never commit it
cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm
COLOPHON_RELAY_HOME_SLOTS="acct=<account ID>@https://home.example.org/v1/libraries/acct" \
COLOPHON_HOME_KEY_FILE=home-key.jwk                         \
COLOPHON_HOME_WASM=target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm \
COLOPHON_RELAY_DATA=./relay-data  bun relay/server.js
# {"listening":{"host":"127.0.0.1","port":8787,"tls":false}}
curl http://127.0.0.1:8787/v1/libraries/acct      # {"protocol":"colophon/relay/3", ..., "home":{"member":"<ID>"}}
```

The `member` in that answer is the home's ID (the key ID of its signing key). Give the signing point
of the key (the JWK's `x`, `y`) and any agreement point to the host that appoints the home. The
home holds no account secret: no controller or member key, no PRF output, no seed (§13.1).

| Setting | Env | Default |
| --- | --- | --- |
| Listen host / port | `COLOPHON_RELAY_HOST`, `COLOPHON_RELAY_PORT` (0 picks a free port) | `127.0.0.1`, `8787` |
| Data directory | `COLOPHON_RELAY_DATA` | `./relay-data` |
| Config file | `COLOPHON_RELAY_CONFIG` or `--config` | none |
| Plain tokens | `COLOPHON_RELAY_TOKENS="slot=token,…"` (or `tokenSha256` in a config file) | none |
| Token-free slots (tests only) | `COLOPHON_RELAY_OPEN="slot"` | none |
| Home slots | `COLOPHON_RELAY_HOME_SLOTS="slot=<account ID>@<base URL>,…"` (config: `libraries.slot = {"home":true,"account":…,"base":…}`) | none |
| Home key | `COLOPHON_HOME_KEY_FILE` (preferred) or `home.keyFile` in the config; `COLOPHON_HOME_KEY` (the JWK itself) is readable from the process environment, so prefer a file | required for a home |
| Home module | `COLOPHON_HOME_WASM`, or `home.wasm` | required for a home |
| Scheduler tick | `COLOPHON_RELAY_TICK_MS` or `tickMs` | `2000` |
| Other homes | config `resolve`: `{"https://other.example/v1/libraries/acct": "http://10.0.0.7:8787/v1/libraries/acct"}` (the endpoint an account names, to the URL to reach it) | the endpoint itself |
| Request rate | `limits.requestsPerMinute` (per address) | `1200` |
| TLS | `COLOPHON_RELAY_TLS_CERT`, `COLOPHON_RELAY_TLS_KEY`, or `"tls":{…}` | off |

**Provisioning.** The operator creates a home slot for one account, by its account ID, before
anything is uploaded. Its first upload is accepted only if it starts with the genesis whose digest
is that ID; anything else is refused and nothing is held. The relay refuses to start a home slot
with no account, or one whose stored state belongs to another account or another home key.

**Credentials.** At a home slot a bearer token authorizes nothing (it is ignored, with a warning
at start-up): every request that needs authorization takes `Authorization: Colophon …`. The key
comes from a file (or the environment) and is imported as a non-extractable WebCrypto key, after
checking that its `x`, `y` are the public half of its `d`: it is never logged, served or written
to the data directory. `COLOPHON_RELAY_CLOCK_FILE` replaces the clock with the milliseconds in a
file. It is a test hook: it works only when the relay is started with `--test-clock`, and the
relay refuses to start with it otherwise.

Production use is over TLS (directly, or behind Caddy/nginx or Tailscale, as for the 0.3 relay:
pass `Authorization`, `If-None-Match`, `If-Match` and `Content-Length`, do not buffer bodies).

## What a home serves (0.5 §14)

At `{base}` (`/v1/libraries/<slot>`), in addition to the 0.3 endpoints (`changes`, `records/...`):

| Request | Answer |
| --- | --- |
| `GET {base}` | 200 as 0.3 plus `"home":{"member":"<ID>"}` |
| `GET {base}/head` | 200 the latest head this home signed, after producing the due one (§13.3); 503 with `Retry-After: 1` when a head is due and cannot be signed yet (the clock has not passed the latest head's `issued`, or the history stops at a fork): the older head is never served in its place; 404 if none. Public. The same at `records/heads/<this home>.json`. |
| `GET {base}/authority?after=&limit=` | 200 `{"entries","receipts","more"}`, 1–64 from `after + 1`, under 13.4; `receipts` holds the receipts of a successor genesis. At a fork: the prefix, then every candidate held from the fork's seq, in seq then digest order |
| `GET {base}/predecessor/authority/<8 digits>.json` | 200 a Swift predecessor's entry; 404. A history path (§13.4) |
| `PUT {base}/predecessor/authority/<8 digits>.json` | a predecessor entry: 201 stored, 200 held already, 412 another entry at that seq, 422 `{"result"}`. Needs a `colophon.home.write` call by a controller (see "Predecessor entries") |
| `POST {base}/authority` | `{"from","entries","receipts"}`: 200 `{"head","receipts"}`; 409 with the current head; 421 `{"endpoints"}` from a non-primary home; 422 `{"result"}`. No credential needed. |
| `GET {base}/pending?after=&limit=` | 200 `{"objects":[{"seq","digest","kind","envelope"}],"more"}` under 13.4 |
| `GET {base}/pending/{digest}` | 200 `{"envelope","receipts"}`; 404 |
| `POST {base}/pending` | `{"objects":[…]}`, 1–16: 200 `{"receipts"}`; 422 a JSON array with the result string of each refused object, in request order. Receipts in a batch are taken first, so an object later in it finds them. No credential needed. |

**Before it is appointed** a home serves nothing it holds: every path but `GET {base}` and the two
`POST`s answers 404. **Once appointed**, every access decision is the Rust module's (§13.4, §14):
the head (`/head`, `records/heads/*`) is public; the history (`authority`, `pending`, and
`records/authority/`, `transitions/`, `vetoes/`, `receipts/`) follows `policy.history`: `public`,
or a call; records, blob chunks and the change feed always need a call. A call is
`Authorization: Colophon <base64url call envelope>`, verified under §12.3 with `{base}` as the
audience, and bound to its request: its `args` are exactly
`{"method": <HTTP method>, "path": <path and query relative to {base}, as sent>, "body": <hex SHA-256 of the body>}`,
its purpose `colophon.home.read` for GET and HEAD (`colophon.history.read` is accepted on the
history paths only, never for records, blob chunks or the change feed) and `colophon.home.write`
otherwise. A current member may write records, live
values and blob chunks under its own author ID in namespaces its terms grant; a revoked member is
refused as soon as the revocation is in the history the home holds. Refused: 401 with
`WWW-Authenticate: Colophon` when there is no call, 403 `{"result":"<§1 code>"}` for a call that
is refused (another request's call is `refused:outOfScope`, another audience's
`refused:audience`), 429 `{"result":"refused:window"}` with `Retry-After` when that caller (a
member or controller, with all its link keys) is over its share of the replay table; other
callers are not affected.

**First upload.** `POST /authority` with the history from seq 1, the provisioned account's genesis
first, keeps each entry that verifies; entries up to the one that appoints this home are judged by
§8 alone (an account created long ago can appoint a new home), and the clock and receipt-window
rules apply from the appointment on. `receipts` in the request holds receipt envelopes only.

**What the home does by itself**, on its own clock, every tick: it appends the determined `activate`,
`vetoed` and `final` entries when they are due (the exact bytes come from the Rust code that a
host's own account uses), and for a successor home `successionVetoed` and its receipt of the
successor genesis inside the succession window; signs a head when one is due (at least every
`headMaxAge / 2`, and for every new entry); keeps a serving lease (`alive.json`: it may serve until the lease's end and renews it
before then, writing it durably at start-up before it listens; at start-up the module closes the
serving interval at the last lease's end, never earlier, §13.1); and forwards what it stores to the account's other
current homes: each listed transition, veto and receipt to `{peer}/pending`, a transition or veto
together with the receipts it holds of it (so a peer judging a late veto holds the in-window
receipt), their receipts of what it sent come back and are admitted; its heads to
`PUT {peer}/records/heads/<its ID>.json` (never one it is due to replace), and the entries of
its history after that peer's latest head to `POST {peer}/authority`, so a peer holds every
recording entry this home appended and can sign a head over it (otherwise, at `headQuorum` 2, a
home whose only head covers its own `final` would leave the other home waiting for ever). Before
any head is produced the home appends what is due at its clock. An object a
peer did not take (a transient refusal such as `unavailable`, or any status or result the module
does not read as delivered or permanently refused) is offered again every pass while this home
still lists it.

**Forks** (§8.6). A non-primary home stores a valid entry at a seq it holds when a primary head
covers it, and keeps a current home's head over another digest at a held seq as fork evidence (at
most four per home); holding two candidates it stops at the fork: it serves both, signs no head,
answers `refused:fork` (422) to entries and transitions that depend on either branch, and takes a
`resolve` (judged on the branch it is anchored on), its vetoes and receipts, and the `activate`
that settles the fork. The primary stores the first valid entry per seq (409 for another). An
entry file whose seq another candidate comes to stand at is replaced.

**A home that was offline.** At a non-primary home, an immediate entry a primary head covers is
stored however far its `issued` is behind the home's clock (the primary applied the clock rule);
the head may name a later entry of the same upload. A home's serving interval closes at the end
of the last lease it recorded (uptime is never under-recorded; whatever is uncertain counts as
serving), so an `activate` of a transition whose window fell wholly while it was down is stored.

**Predecessor entries** (§14, §15.1). A successor's home serves its Swift predecessor's entries
under `{base}/predecessor/` and `records/predecessor/`. It takes one by `PUT` only under a
`colophon.home.write` call by a controller with `approve` or `control` (not suspended) or a `sign`
controller listing `{base}`, never a member's (nothing in 0.5 says who may; this is the strictest
rule that lets the moving device publish), and only when the account claims a Swift predecessor,
the entry's `seq` is its path's and at most F's, and the history verifier with it does not stop.
Before the first upload appoints the home, a Swift successor's genesis cannot be verified without
its predecessor, so: the first upload is refused (`unavailable`) but the provisioned account's
genesis is held (its digest is the account ID: nobody else can make it); the predecessor is then
published with no call, from the head the genesis claims down, each entry taken only if it is the
one the chain names (the claimed `head.digest`, then each staged entry's `previous`); and the
first upload is sent again. One entry per seq, at most the claimed head's seq, 512 entries and
8 MiB per slot; bytes that do not fit the chain are refused and nothing of them is kept, so
flooding cannot take a place the genuine entry needs. Nothing staged is served.

**Notices are not built** (§13.1, §17.5): see "Notices" below.

## Storage layout

```
<dataDir>/<slot>/meta.json        {"instance": "<random>"}: cursors are bound to it
<dataDir>/<slot>/log.jsonl        append-only change log: {"path","size","sha256"} per line
<dataDir>/<slot>/records/...      the files, at their spec paths (below)
<dataDir>/<slot>/tmp/             staging for atomic writes
<dataDir>/<slot>/home-state.json  home slots: the Rust module's opaque, versioned state
<dataDir>/<slot>/replay.log       home slots: the call replay store, append-only (a reservation line,
                                  fsynced before any effect; a completion line after it)
<dataDir>/<slot>/forward.json     home slots: what each other home has been sent
<dataDir>/<slot>/alive.json       home slots: the serving lease's end (serving intervals, §13.1)
```

Home slots add `authority/<8 digits>.json`, `transitions/<digest>.json`, `vetoes/<digest>.json`,
`receipts/<object digest>/<home ID>.receipt.json` and `heads/<home ID>.json` to the 0.3 paths.
`home-state.json` is the commit point: every operation computes the next state in the module, the
relay writes it atomically (staged file, `fsync`, rename), and only then stores the files and signs
what remains to be signed, all under one lock. The files are derived from the state; on start,
before anything is served, they are reconciled with it (a missing file is written, a head file
older than the committed head is replaced). History reads come from the state, under the same
lock, so no reader sees an entry before its file. A reservation left pending by a crash is
resolved at start-up from its effect: completed if the record it wrote is there, abandoned
otherwise; the row stays, so the call is a replay either way. A request that fails admission stores no file
(its state change, such as a first-seen time or a permanent late decision, is kept, as §13.1
asks). A receipt is signed once per object: the module hands the relay one signing request per
object and refuses a second.

The 0.3 guarantees hold as before: immutable files are staged, `fsync`ed and `link(2)`ed into place
(an existing one is never replaced; identical re-PUTs answer 200, different bytes 412), `state/`
replacement needs `If-Match`, blob chunks must hash to their name, paths follow the grammar (a
home slot's grammar is the 0.5 one; `requests/` is not a 0.5 path), symlinks are refused, bodies
above their limit are 413 before anything is read, and a torn log or a changed file gives a new
instance ID so old cursors answer 410. Bounds in a home slot: authority POST 16 MiB, pending POST
12 MiB, 64 entries or 16 objects per request, the replay table 4,096 rows, 1,200 requests a minute
per address.

## How it is built

`relay/home.js` is I/O: sockets, files, the clock, the home's key, timers, calls to other homes. It
writes no verifier rule. It calls `crates/colophon-home-wasm`, a small Rust crate over
`colophon-core` (admission, vetoes, receipts and caps in `history::home`, the history verifier,
`calls`, `heads`, the engine's path grammar, and `Account::record_due` for the recording entries)
built to WebAssembly with a **plain C ABI**: `colophon_alloc`, `colophon_free` and `colophon_home`
over pointers and lengths, one JSON request in and one JSON response out. No wasm-bindgen and no
generated glue: `relay/home.js` instantiates the module with `WebAssembly.instantiate`, so
nothing but a Rust toolchain with the `wasm32-unknown-unknown` target is needed to build it.

```sh
cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm --locked
# target/wasm32-unknown-unknown/release/colophon_home_wasm.wasm
```

The module is pure: the host passes the time and the state, signs only what a response lists
under `sign` (receipt bodies, head bodies) and gives each signature back. It never sees a private
key. A module that traps is dropped and a new instance serves the next request.

## Tests

```sh
cd relay && bun test      # the 0.3 relay's tests, and the home slot's: bounds, paths, no credential, rate limit
cargo test -p colophon-home-wasm --locked   # the module, and the relay as a process with the real engine
```

`cargo test -p colophon-home-wasm` starts this relay with `bun` and drives it over localhost HTTP
with the engine's sans-IO exchange (the two journeys of `v05_engine_journeys.rs`, the listening
and the reading one, against the real relay instead of the simulated home), and the cases only a
home has: a transition receipted, due, activated and final across two homes at `headQuorum` 2,
primary-home ordering (421), a veto in time, a late and a forged object, an unauthorized read, a
replayed call and a call for another audience, a head the §13.3 guard refuses, and a restart in
the middle. It also runs the kill loop (`v05_relay_kill.rs`: at least 200 SIGKILLs at random points of a
journey, some inside `record_due`, with state, storage, heads and receipts checked after each
restart) and the attacks of the 2026-11-15 check.

`scripts/test-home.sh` builds the home module and runs every home test: the Rust tests that start
this relay as a process (`crates/colophon-home-wasm/tests`, including the kill loop) and `bun test`
here. **CI runs that script.** With `CI` or `COLOPHON_REQUIRE_RELAY=1` set, a missing Bun or module
fails those tests; otherwise they are skipped with a printed `SKIPPED:` line naming what is missing.

## Notices (not built: the contract is missing)

§13.1 says a home MUST push a notice to every delivery route registered with it on receipting a
transition, a veto or a `suspend`, and §17.5 that hosts MUST register at least two routes with
every home at setup. 0.5 gives a notice no signed body and no wire format, and nothing defines how
a host registers a route with a home. The Swift and Kotlin sessions expect one: a
`DeliveryRoute {kind: push|email|sms|webhook|other, address, reaches}` and a host-supplied
`registerRoutes(account, routes) -> Bool` closure (`swift/Sources/ColophonSession/HostDuties.swift`,
`SessionTypes.swift`; `sdk/kotlin/.../SessionTypes.kt`), with the HTTP call left to the host. So
this home builds no route store, queue or sender: there is nothing for a session to call that a
second implementation would also implement.

What is missing, and the smallest contract that would close it (a proposal, not built):

- **Register.** `PUT {base}/routes/<route ID>` with body `{"kind","address","reaches"}`, under a
  `colophon.home.write` call by a controller (any role, suspended or not: a recover-only key must
  be able to keep a route) or a current member; the route ID is the lowercase hex SHA-256 of
  `kind ‖ 0x00 ‖ address`. 200 or 201. `DELETE` the same path removes it. `GET {base}/routes`
  (same call, `colophon.home.read`) lists `{"routes":[{"id","kind","reaches","by"}]}`, never the
  addresses. The `Bool` the sessions expect is "201 or 200".
- **What triggers a notice.** The module returns, with every admission that receipted a
  transition, a veto or a `suspend`, a `notify` list: `{"object","kind","issued","deadline"}`.
  The relay appends one queue line per route (`notices.jsonl`, fsynced before the receipt is
  returned), and a sender drains it with retries; the queue survives restarts like the replay log.
- **The text.** Fixed by the home, carrying only public facts: the account ID, the object's kind
  and digest, its veto deadline, and the §17.5 sentence about what the delay protects. Nothing
  from a private record.
- **The sender.** Pluggable (`deliver(route, notice) -> ok | retry | drop`), a test sender that
  writes to a file, and production senders that each need operator credentials outside this
  repository: APNs (a token-signing key and topic per app), FCM (a service account), e-mail (an
  SMTP or provider API key with a verified sender domain), webhooks (an allow-list, since an
  account would otherwise make the home call arbitrary addresses, finding L7 of the H1 check).

## A stopped home

An account that finalizes a raise above layout 2 stops a 0.5 home. The home keeps its
stored data. Public history and the base endpoint remain readable. Head reads return
503 with `Retry-After`; requests needing a call return 503 `{"result":"unavailable"}`,
even without a call. New authority and other pending objects return 422 `newerFormat`.
The home can still receipt timely vetoes and removal-only transitions anchored at or
before its last verified entry, but records no further entries and signs no heads.
Restarting does not clear the stop. Update the home to support the account's new layout.
