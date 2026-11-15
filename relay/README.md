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
COLOPHON_RELAY_TOKENS="acct=<token>"                       \
COLOPHON_RELAY_HOME_SLOTS="acct=https://home.example.org/v1/libraries/acct" \
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
| Home slots | `COLOPHON_RELAY_HOME_SLOTS="slot=<base URL>,…"` (config: `libraries.slot = {"home":true,"base":…}`) | none |
| Home key | `COLOPHON_HOME_KEY` (the JWK) or `COLOPHON_HOME_KEY_FILE`, or `home.keyFile` in the config | required for a home |
| Home module | `COLOPHON_HOME_WASM`, or `home.wasm` | required for a home |
| Scheduler tick | `COLOPHON_RELAY_TICK_MS` or `tickMs` | `2000` |
| Other homes | config `resolve`: `{"https://other.example/v1/libraries/acct": "http://10.0.0.7:8787/v1/libraries/acct"}` (the endpoint an account names, to the URL to reach it) | the endpoint itself |
| Request rate | `limits.requestsPerMinute` (per address) | `1200` |
| TLS | `COLOPHON_RELAY_TLS_CERT`, `COLOPHON_RELAY_TLS_KEY`, or `"tls":{…}` | off |

A home slot with a token still has it for storage access (records, blobs, the change feed); a home
slot with no token accepts only `Authorization: Colophon …` calls there. The key comes from the
environment or a file and is imported as a non-extractable WebCrypto key: it is never logged,
served or written to the data directory. `COLOPHON_RELAY_CLOCK_FILE` replaces the clock with the
milliseconds in a file. It exists for tests that must move time; never set it in production.

Production use is over TLS (directly, or behind Caddy/nginx or Tailscale, as for the 0.3 relay:
pass `Authorization`, `If-None-Match`, `If-Match` and `Content-Length`, do not buffer bodies).

## What a home serves (0.5 §14)

At `{base}` (`/v1/libraries/<slot>`), in addition to the 0.3 endpoints (`changes`, `records/...`):

| Request | Answer |
| --- | --- |
| `GET {base}` | 200 as 0.3 plus `"home":{"member":"<ID>"}` |
| `GET {base}/head` | 200 the latest head this home signed; 404 if none. Public. |
| `GET {base}/authority?after=&limit=` | 200 `{"entries","receipts":[],"more"}`, 1–64 from `after + 1`, under 13.4 |
| `POST {base}/authority` | `{"from","entries","receipts"}`: 200 `{"head","receipts"}`; 409 with the current head; 421 `{"endpoints"}` from a non-primary home; 422 `{"result"}`. No credential needed. |
| `GET {base}/pending?after=&limit=` | 200 `{"objects":[{"seq","digest","kind","envelope"}],"more"}` under 13.4 |
| `GET {base}/pending/{digest}` | 200 `{"envelope","receipts"}`; 404 |
| `POST {base}/pending` | `{"objects":[…]}`, 1–16: 200 `{"receipts"}`; 422 one `{"object","result"}` per refused object. No credential needed. |

Reading the history (`authority`, `pending`, and the files under `records/authority/`,
`transitions/`, `vetoes/`, `receipts/`, `heads/`) follows the account's `policy.history`: `public`, or
an `Authorization: Colophon <base64url call>` with purpose `colophon.history.read` that the Rust code
verifies (§12.3, replay store §12.4) with `{base}` as the audience. **A bearer token never reads
history.** Records and the change feed take the bearer token or a call (`colophon.home.read`,
`colophon.home.write`). Refused: 401 with no credential, 403 `{"result": "<§1 code>"}` for a call
that is refused, 429 `{"result":"refused:window"}` when the replay table is full.

**First upload.** A fresh home slot holds nothing. `POST /authority` with the history from seq 1
keeps each entry that verifies; when the history appoints this home (§13.1 "First upload"), the home
exists from then on and signs its first head.

**What the home does by itself**, on its own clock, every tick: it appends the determined `activate`,
`vetoed` and `final` entries when they are due (the exact bytes come from the Rust code that a
host's own account uses), signs a head when one is due (at least every `headMaxAge / 2`, and for
every new entry), and forwards what it stores to the account's other current homes: transitions,
vetoes and receipts to `{peer}/pending` (their receipts of what it sent come back and are
admitted), its heads to `PUT {peer}/records/heads/<its ID>.json`.

## Storage layout

```
<dataDir>/<slot>/meta.json        {"instance": "<random>"}: cursors are bound to it
<dataDir>/<slot>/log.jsonl        append-only change log: {"path","size","sha256"} per line
<dataDir>/<slot>/records/...      the files, at their spec paths (below)
<dataDir>/<slot>/tmp/             staging for atomic writes
<dataDir>/<slot>/home-state.json  home slots: the Rust module's opaque, versioned state
<dataDir>/<slot>/replay.json      home slots: the call replay store (key, time, digest; 7,260 s)
<dataDir>/<slot>/forward.json     home slots: what each other home has been sent
```

Home slots add `authority/<8 digits>.json`, `transitions/<digest>.json`, `vetoes/<digest>.json`,
`receipts/<object digest>/<home ID>.receipt.json` and `heads/<home ID>.json` to the 0.3 paths.
`home-state.json` is the commit point: every operation computes the next state in the module, the
relay writes it atomically (staged file, `fsync`, rename), and only then stores the files and signs
what remains to be signed. The files are derived from the state; on start they are checked
against it and any missing one is written again. A request that fails admission stores no file
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
the middle. They need `bun` and the built module; without them they print `SKIPPED` and pass.
