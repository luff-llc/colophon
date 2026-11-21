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

## Batch record reads

Home batches implement the [proposed Colophon 0.6 W1 exchange](../docs/colophon-0.6-w1-batch.md).
`POST /v1/libraries/<slot>/records/batch` works on both plain slots and home slots.
Plain slots use the same bearer authorization as single-record GET. On a home
slot, send `Authorization: Colophon <base64url call>` with purpose
`colophon.home.read`, audience equal to the slot's configured base URL, and
these signed arguments:

```json
{"method":"POST","path":"/records/batch","body":"<lowercase hex SHA-256 of the raw request body>"}
```

Send `Content-Type: application/json`, `Content-Length`, and a body of at most
64 KiB:

```json
{"paths":["state/0123456789abcdef0123456789abcdef/notes/current.json","state/0123456789abcdef0123456789abcdef/notes/draft.json"]}
```

`paths` must contain 1–256 unique record paths valid for the slot. Invalid JSON
or paths return 400, a missing `Content-Length` returns 411, an unsupported
content type returns 415, and a body over the bound returns 413. A successful
answer preserves request order:

```json
{
  "records": [
    {"path":"state/0123456789abcdef0123456789abcdef/notes/current.json","status":200,"etag":"\"<sha256>\"","bytes":"<base64>"},
    {"path":"state/0123456789abcdef0123456789abcdef/notes/draft.json","status":404}
  ],
  "truncated": false
}
```

An unappointed home returns 404 before checking credentials or parsing the body.
An appointed home applies its per-address rate limit and checks for a Colophon
authorization header and valid batch structure before taking the slot lock.
It then verifies the bound call under its replay rules. Any current member
calling with its own key may read ciphertext records in any namespace. E2EE
epoch keys control who can decrypt those records.

- Every home batch requires a `colophon.home.read` call, including batches of
  public history or heads. Single GET can serve those paths without a call.
- Batch refuses `colophon.history.read`, so recover-only controllers cannot
  batch history. They can read members-only history with single GET and that purpose.
- A stopped home returns a whole-request 503 for a well-formed batch carrying a
  call. Single GET can still serve public history while the home is stopped.

A missing call returns 401. Refused calls, including revoked, expired, replayed
or mismatched calls, return 403 for the whole request. Rate limits return 429
with `Retry-After`. If the home's own head needs to be refreshed and cannot be
signed, its entry returns 503.

Records are checked against their indexed size and SHA-256 before serving; storage
corruption fails the whole request with 500 and no per-item results. Clients can
fall back to single-record GETs to fetch the unaffected paths. Answers carry `Cache-Control: no-store,
no-transform` and the configured CORS headers. Each response has a strict 4 MiB
encoded JSON/base64 budget, including response framing and per-record overhead.
An individual record exceeding that budget is not read or base64-encoded; its
entry is `{ "path": "…", "status": 413, "etag": "\"<sha256>\"", "size": 4194304 }`
(with its actual raw byte size). Fetch such records via single-record GET. These entries
count as returned paths so pagination always makes progress. When `truncated` is true,
request the unreturned suffix of `paths` in the next batch. A home requires a new
call bound to that next batch's body. Clients can probe the route and use single-record
GET when an older relay returns 404 or 405.

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
| CORS origins | `COLOPHON_RELAY_CORS_ORIGINS="https://app.example,…"` or `cors.origins`: each exactly `scheme://host[:port]`, lower case, compared whole; `*`, `null`, a path or a default port refuse start-up | none: no CORS header |
| Provisioning | config `provision` (below) | off |
| Client address | config `clientAddress`: `{"header": "CF-Connecting-IP", "trustedPeers": ["127.0.0.1", "::1"]}` | the socket address |

**Provisioning.** A home slot serves one account, by its account ID, from before anything is
uploaded. Its first upload is accepted only if it starts with the genesis whose digest is that ID;
anything else is refused and nothing is held. The relay refuses to start a home slot with no
account, or one whose stored state belongs to another account or another home key. A slot is
made in one of two ways:

- The operator configures it (`COLOPHON_RELAY_HOME_SLOTS` or `libraries`), and restarts.
- An app (or an agent the operator has granted, see "Provisioning by a grant" below) creates it,
  with no restart, at the door `POST /v1/provision` when `provision.enabled` is true. The body is `{"slot","base","account"}` with `Content-Type: application/json` and a
  `Content-Length`, as the test apps send it. The answer is 200 with the home's signed member
  request (§9.1), JSON bytes: the account appoints the home with it. The home module builds and
  verifies the request and the home key signs it. The same `{slot, account}` again answers the
  same bytes. The row (`slot` to `{account, base, at, request, by}`) is written to
  `<dataDir>/provisioned.json` (staged, fsynced, renamed) before the answer, and read at
  start-up with the configured slots; a slot both configured and provisioned with different
  accounts refuses start-up. Provisioned slots are scheduled like configured ones.

**The table.** `provisioned.json` is read only when provisioning is on or a regular file of that
name is in the data directory. With provisioning off and no such file the relay reads, scans and
removes nothing of that name (a 0.3 slot called `provisioned.json` works as before; turning
provisioning on with it there refuses start-up until that slot is renamed). When provisioning was
on and is turned off (`enabled: false`) the table file stays: its slots stay served and the door
answers 404; keep `provision.prefix` set, since every row is checked against it. While
provisioning is or has been on, `provisioned.json` (and its staging files, `.provisioned.json.*`,
which the slot grammar already excludes) cannot be slot names; with gate `"grant"`,
`provision-replay` (the provisioning replay table's directory) cannot either. Each row's `by` says
who made it: `{"gate":"open"}`, `{"gate":"token"}`, or `{"gate":"grant","member","key","call"}`
(the grant's member ID, the acting key's ID, and the call's digest); a row written before `by`
existed has none and reads as unknown. The table is never repaired: at start-up it is read up to
a bound (32 KiB of request per row, `max(maxSlots, 200)` rows), it must be exactly as the relay
writes it (no duplicate key, no other field, `by` one of the three shapes), and every row must
have a slot that matches `slotPattern`, `base === prefix + slot`, and a member request that the
module finds well formed, signed by this home's key, and naming the row's account and endpoint.
A bad table refuses start-up with a message naming the row.

**Release, and a lapsed entitlement.** Only a slot that was never appointed and holds no genesis
is ever released (`unclaimedHours`). The release takes the slot out of service first (new requests
answer `refused:notProvisioned`, a waiting change feed is woken and ended, a provision of the name
waits), drains every request and scheduler pass still running on it, and checks again that nothing
is held; only then are its directory and its row removed, and only then can the name be
provisioned again. If an upload landed meanwhile, the release is abandoned and the slot stays. An
appointed home keeps witnessing and receipting the account's authority history until its
revocation is final, whatever the grant's expiry or the state of a subscription: when an
entitlement lapses, the gate may stop new slots and the home may stop serving records, but it keeps
signing heads and receipting authority changes until the account revokes it, or it would block that
account's key changes. (Entitlements are not built in 0.5; gate `"token"` is the smallest one.)
The same holds for a grant: revoking a member that provisioned slots, or its expiry, stops its new
slots and leaves its slots alone. An appointed one keeps being witnessed; one never appointed is
released after `unclaimedHours`, as any other.

| `provision` field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | The door answers 404 when off, and every other answer is as without the setting |
| `prefix` | none, required when on (and while a table file exists) | The public `https://` URL prefix, ending in `/`: `base` must equal `prefix + slot`. Plain `http://` only to a loopback host, for tests; anything else refuses start-up |
| `maxSlots` | `200` | Provisioned slots this home holds |
| `perAddressPerHour` | `10` | New slots (open path), refused tokens and requests no listed path takes, one client address may spend in an hour; separately, the grant requests from one address that may be refused in an hour (see below) |
| `unclaimedHours` | `24` | A provisioned slot holding no genesis this long after it was made is released (its directory, then its row, removed) at the next provision or start-up, on the relay's clock |
| `slotPattern` | `^[a-z0-9][a-z0-9._-]{7,63}$` | Names an app may pick, besides the slot grammar |
| `gate` | `"open"` | Who may provision: `"open"` (anyone within the bounds), `"token"` (`Authorization: Bearer <token>` whose SHA-256 is `tokenSha256`; `bun relay/server.js token` prints one), `"grant"` (a call by a member of the operator account, below), or a list of them, such as `["grant", "open"]`. No value twice, and not `"open"` with `"token"` (open admits everything token would). Anything else refuses start-up |
| `tokenSha256` | none | 64 hex; required with gate `"token"`, compared in constant time |
| `operator` | none, required with `"grant"` | `{"account": "<64-hex ID>", "slot": "<slot>"}`: the operator account, and this home's own slot for it (configured or provisioned) |
| `audience` | none, required with `"grant"` | The door's canonical audience (§10.1), its own: for example `https://home.example/v1/provision`. Not a slot's base, nor `prefix + slot`; one per deployment, so staging's grants do not reach production |
| `grantMaxSlots` | `20` | Slots one grant may hold (made by it, claimed or not; a released slot frees its place) |
| `grantPerHour` | `30` | Verified calls one grant may make in a rolling hour (a new slot, the same one again, or one then refused with 409 or 507), counted from the durable replay table before any history work, so it survives a restart |
| `grants` | `{}` | Per-member overrides: `{"<member ID>": {"maxSlots": N, "perHour": N}}` |
| `grantAttemptsPerAddressPerHour` | `120` | Grant requests one address may make in an hour, charged before any verification (CI hosts share addresses, so it is separate from and higher than `perAddressPerHour`) |
| `replayRows` | `4096` | The provisioning replay table's hard cap, besides each grant's share of it |

| The door answers | When |
| --- | --- |
| 200 the member request | Admitted, or the same `{slot, account}` again |
| 400 `{"result":"malformed"}` | The body is not exactly `{"slot","base","account"}`, the slot breaks the grammar or `slotPattern`, `base` is not `prefix + slot`, or `account` is not 64 lower-case hex |
| 403 `{"result":"refused:noEntitlement"}` | Gate `"token"` and the token is missing or wrong, or no listed path takes the request (counted against the address's hourly share) |
| 403 `{"result":"<code>"}` | A grant's call is refused, with the core's code: `malformed`, `badSignature`, `refused:audience`, `refused:outOfScope`, `refused:revoked`, `refused:expired`, `refused:ended`, `refused:notNarrower`, `refused:window`, `refused:replay`, `refused:conflict`, `refused:fork`. Final: it never falls back to another path |
| 403 | The request carries an `Origin` not on the CORS list (checked before the body is read) |
| 405 | Not `POST` |
| 409 | The slot is held by another account, configured by the operator, or a directory of that name is in the data directory |
| 411, 413 | No `Content-Length`, or a body over 4 KiB |
| 415 | The media type is not `application/json` (checked before the body is read; a browser must preflight such a request, and only a listed origin's preflight succeeds) |
| 429 `{"result":"refused:overQuota"}` | The address is over `perAddressPerHour`, with `Retry-After` (checked first: a guesser over its share learns nothing about its token); for a grant request, the address is over its attempts or its refusals, the replay table is full, or the grant is over `grantPerHour`, each with `Retry-After` |
| 429 `{"result":"refused:window"}` | A grant over its share of the replay table, with `Retry-After` |
| 503 `{"result":"unavailable"}` | A grant request while the operator slot is not set up (not held, no genesis, not appointed, stopped), or its account's heads cannot be judged here |
| 507 `{"result":"refused:overQuota"}` | `maxSlots` are held, or the grant holds `grantMaxSlots` |

The gate is one function, `admitProvision` in `relay/provision.js`: every check goes through it,
and an entitlement presented in `Authorization` is added there, as one more path. `refused:closed` is reserved and
not produced. With provisioning on, a request to a slot this home does not hold answers 404
`{"result":"refused:notProvisioned"}` instead of the 0.3 answer, 401 `WWW-Authenticate: Bearer`.
So the answers tell the kinds of slot apart: an unknown name is 404, a configured token slot asked
without its token is 401, and a home slot answers `GET {base}` with 200. That is intended: slot
names are not secrets, and access is by call (or, at a 0.3 slot, by token), never by knowing a name.

**Provisioning by a grant.** Gate `"grant"` lets a key the operator's own Colophon account has
delegated provision, within bounds, revocable alone: a test rig or agent is granted once and then
runs unattended, with no shared secret. It is operator behaviour of this home, not protocol: it uses
only a member grant whose terms carry `services` (§10.1), a call (§12.2) verified by §12.3 with a
§12.4 replay table, and a revocation (§9.5).

- *The operator account* is one of this home's own slots (`provision.operator.slot`), whose
  account is `provision.operator.account`; this home is its home. So the home holds its verified
  history and signs its heads, and judges a call over that slot's state with no fetching and no
  new trust path. Keep this home the account's one home (the 0.5 default): with more homes and
  `headQuorum` above 1, this home lacks their fresh heads and every grant request is 503. Start-up
  refuses gate `"grant"` without `operator` or `audience`, an operator slot configured or
  provisioned for another account (or a 0.3 slot), and an audience that is not a §10.1 audience or
  is a slot's base. An operator slot named but not set up yet is not a start-up failure: grant
  requests answer 503 until it is.
- *A grant* is an ordinary member of the operator account, one per agent or rig (so each is revoked
  alone), admitted by §9.2 with terms such as
  `{"services":[{"audience":"https://home.example/v1/provision","purposes":["home.provision"]}],
  "expires":"2026-12-19T00:00:00Z","depth":1,
  "conditions":[{"any":[{"prefix":["args.slot","ci-"]},{"not":{"prefix":["args.slot",""]}}]}]}`
  and a label naming it ("later CI on omarchy"). A grant's conditions bind every call its member
  signs, including its reads of the operator account at this home (§12.3 step 7), which name no
  slot; so the condition says "the slot starts with `ci-`, or the call names no slot". A bare
  `{"prefix":["args.slot","ci-"]}` is false for those reads and leaves the rig unable to sync. The terms bound it: this home only (the audience), this
  door only (the purpose), until `expires` (and each link's), slot names (`conditions` on
  `args.slot`, `args.account`), and further delegation (`depth`; a link's key counts against its
  member). How many slots and how often are this home's settings (`grantMaxSlots`,
  `grantPerHour`, `grants`), per member ID, so a grant's links share its limits. The home-wide
  `maxSlots` still caps them all.
- *The request* is the door's usual body with `Authorization: Colophon <base64url call>`. The call
  names the operator account, a member signer (its own key, or one to four links under it),
  `audience` = `provision.audience`, `purpose` = `home.provision` exactly, and `args` = exactly the
  body `{"account","base","slot"}`. The module (op `provision_access`) checks, in order:
  parse; possession (the signature under the call's key, `badSignature`); then, before any history
  work, the account, the audience, the purpose, `args` equal to the body, that the signer is a
  member, its grant's `grantPerHour` (429 `refused:overQuota` with `Retry-After`, from the durable
  replay rows), and that the signer is not this home itself; then the core's `verify_call` with no
  home endpoints and no controller purposes (a controller's call is `refused:outOfScope`: a
  controller's key is for authority, delegation is a member grant). The checks before history work
  run first without the operator slot's lock, so a call they refuse never waits for, or holds up,
  an upload to that slot.
- *Order and durability.* The door holds the operator slot's lock from the verification until the
  row is durable, and an upload to that slot waits for it (and it for an upload): a revocation the
  home has accepted is seen by every later verification, and none verified before it commits after
  it. Then: reserve the call in the provisioning replay table (`<dataDir>/provision-replay`, its
  own, in the same durable format as a slot's, so syncing the operator account and provisioning
  never share rows or shares), write the slot's row naming the call's digest, complete. A
  reservation left pending by a crash is resolved from `provisioned.json` at start-up: completed if
  a row names its digest, else abandoned; never by running it again. The same call again is
  `refused:replay`; a fresh call for an already provisioned `{slot, account}` answers the same bytes
  and counts against its grant's rate (not its slots). A verified call refused with no effect (409:
  the slot is held or in use; 507: the home or the grant has no room) is recorded too, completed,
  so it spends its grant's rate like an admitted one (and is then a replay).
- *Per-address limits.* Every grant request is charged first against
  `grantAttemptsPerAddressPerHour`. A grant request refused before or by the verification (a
  malformed body, a bad call) counts against that address's own grant share of
  `perAddressPerHour`; once that is spent, its grant requests are refused before the module runs.
  An admitted one counts against nothing per address (CI agents share addresses; an admitted
  request is bounded by its grant). A 503 counts against nothing.
- *Gate lists.* With `["grant", "open"]` or `["grant", "token"]`, a request with
  `Authorization: Colophon …` takes the grant path, and its refusal is final (no fallback); a
  `Bearer` takes the token path when `"token"` is listed; anything else takes the open path when
  `"open"` is listed, else 403 `refused:noEntitlement`. Each path keeps its own bounds: grant
  requests their grant and the limits above, open requests `perAddressPerHour`, all `maxSlots`.

*Issuing a grant.* Whoever may admit members to the operator account (a controller with
`approve`, under the account's member rule) approves the agent's own member request with services
terms like those above; nothing new in the account. The agent keeps its member key (Keychain, or a
0600 file on a CI host), syncs the operator account from this home like any member, and signs a
fresh call per slot. A suggested setup: the operator account's `control` and `recover` keys are the
person's; one `approve`-only controller (added by an ordinary keyring entry, which cannot change
controllers) is held by the agent that issues and revokes test grants.

*Revoking a grant* is revoking that member in the operator account, from any of the operator's
devices, and uploading the entry to this home: it takes effect here at once (§12.3 step 5), so a
grant outlives its revocation here by no more than the time between signing the revocation and
uploading it. `endSessions` of the member ends its links (`refused:ended`). The grant's slots are
left alone (the lapsed-entitlement rule above). Accepted and documented: a stolen grant can hold up
to its `grantMaxSlots` permanently by claiming them at once, since appointed slots are kept; keep
the defaults small.

*Seeing what was provisioned.* `bun relay/server.js provisioned <config>` reads the table and the
slots without changing them (the relay may be running) and prints, per slot: the account, when it
was made, `by` (for a grant, the member ID, the label the operator account gives it, and whether it
is revoked now), and whether it is claimed (appointed or holding a first upload). It needs the home
module (`COLOPHON_HOME_WASM` or `home.wasm`).

*Self-hosting.* A person with no operator account uses `"open"` (bounded by `maxSlots`,
`perAddressPerHour` and the release of slots nobody claimed) or the single `"token"`, which is for
an operator's own tools and one-person homes only. There is no list of tokens: labelled tokens
would be a second credential scheme beside the keyring. No app ships a provisioning secret: a
token built into an app is everyone's. A person's own app has two honest paths: a home whose gate
is `"open"`, or a home that checks an entitlement in `admitProvision` (`refused:noEntitlement` is
reserved for it; not built yet). The grant gate is for agents and rigs the operator chooses, not
for the public. On an `"open"` home only the bounds stop one script from taking every slot: slots
nobody claimed free themselves, appointed ones are real accounts and stay. That is acceptable for a
wipeable staging home, not for a production one.

**The client address.** The per-address request limit and `perAddressPerHour` count against one
address, from one function. By default it is the socket address. Behind a proxy (behind a tunnel,
every request comes from 127.0.0.1) set `clientAddress`: the
header is read only when the socket peer is in `trustedPeers`; from a trusted peer a missing or
malformed header (a list, two headers, not an IP address) counts against one shared bucket, never
an unlimited one; from any other peer the header is ignored. The address is used for limits only,
never for access.

**CORS and caching.** Every answer, whoever writes it, carries `Cache-Control: no-store,
no-transform` and no `Content-Encoding`; with a CORS list, `Vary: Origin`, and for a listed
origin `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers: ETag, Retry-After,
WWW-Authenticate` (never `Allow-Credentials`). `OPTIONS` is answered before any slot, call or
rate work: 204, with the allowed methods (`GET, POST, PUT, OPTIONS`) and headers
(`Authorization, Content-Type, If-Match, If-None-Match`) and `Access-Control-Max-Age: 600` for a
listed origin's preflight.

**Clients must send `Content-Length`.** A body without one is refused with 411. A proxy that passes
chunked bodies through (some tunnels do) reaches the relay as 411.

**Credentials.** At a home slot a bearer token authorizes nothing (it is ignored, with a warning
at start-up): every request that needs authorization takes `Authorization: Colophon …`. The key
comes from a file (or the environment) and is imported as a non-extractable WebCrypto key, after
checking that its `x`, `y` are the public half of its `d`: it is never logged, served or written
to the data directory. `COLOPHON_RELAY_CLOCK_FILE` replaces the clock with the milliseconds in a
file. It is a test hook: it works only when the relay is started with `--test-clock`, and the
relay refuses to start with it otherwise. With `--test-clock` a line `tick` on the relay's stdin runs one
scheduler pass over every home slot and answers `{"ticked":true}` on stdout when it is done; with
`COLOPHON_RELAY_TICK_MS=0` (no timer) a test publishes heads only when it asks, and never waits on
real time. Without `--test-clock` stdin is not read.

Production use is over TLS (directly, or behind Caddy/nginx or Tailscale, as for the 0.3 relay:
pass `Authorization`, `If-None-Match`, `If-Match` and `Content-Length`, do not buffer bodies).

## What a home serves

At `{base}` (`/v1/libraries/<slot>`), a home adds the endpoints from 0.5 §14 and the
proposed 0.6 batch read to the 0.3 endpoints (`changes`, `records/...`).

| Request | Answer |
| --- | --- |
| `GET {base}` | 200 as 0.3 plus `"home":{"member":"<ID>"}` |
| `GET {base}/head` | 200 the latest head this home signed, after producing the due one (§13.3); 503 with `Retry-After: 1` when a head is due and cannot be signed yet (the clock has not passed the latest head's `issued`, or the history stops at a fork): the older head is never served in its place; 404 if none. Public. The same at `records/heads/<this home>.json`. |
| `POST {base}/records/batch` | Ordered per-path results under a single `colophon.home.read` call. See [Batch record reads](#batch-record-reads). |
| `GET {base}/authority?after=&limit=` | 200 `{"entries","receipts","more"}`, 1–64 from `after + 1`, under 13.4; `receipts` holds the receipts of a successor genesis. At a fork: the prefix, then every candidate held from the fork's seq, in seq then digest order |
| `GET {base}/predecessor/authority/<8 digits>.json` | 200 a Swift predecessor's entry; 404. A history path (§13.4) |
| `PUT {base}/predecessor/authority/<8 digits>.json` | a predecessor entry: 201 stored, 200 held already, 412 another entry at that seq, 422 `{"result"}`. Needs a `colophon.home.write` call by a controller (see "Predecessor entries") |
| `POST {base}/authority` | `{"from","entries","receipts"}`: 200 `{"head","receipts"}`; 409 with the current head; 421 `{"endpoints"}` from a non-primary home; 422 `{"result"}`. No credential needed. |
| `GET {base}/pending?after=&limit=` | 200 `{"objects":[{"seq","digest","kind","envelope"}],"more"}` under 13.4 |
| `GET {base}/pending/{digest}` | 200 `{"envelope","receipts"}`; 404 |
| `POST {base}/pending` | `{"objects":[…]}`, 1–16: 200 `{"receipts"}`; 422 a JSON array with the result string of each refused object, in request order. Receipts in a batch are taken first, so an object later in it finds them. No credential needed. |

**Before it is appointed** a home serves nothing it holds. It exposes its identity at `GET {base}`
and accepts admission requests such as `POST {base}/authority` and `POST {base}/pending`.
**Once appointed**, access decisions follow the Rust module's rules (§13.4, §14):
the head (`/head`, `records/heads/*`) is public; the history (`authority`, `pending`, and
`records/authority/`, `transitions/`, `vetoes/`, `receipts/`) follows `policy.history`: `public`,
or a call; records, blob chunks and the change feed always need a call. A call is
`Authorization: Colophon <base64url call envelope>`, verified under §12.3 with `{base}` as the
audience, and bound to its request: its `args` are exactly
`{"method": <HTTP method>, "path": <path and query relative to {base}, as sent>, "body": <hex SHA-256 of the body>}`,
its purpose `colophon.home.read` for GET, HEAD and `POST /records/batch` (`colophon.history.read`
is also accepted for GET and HEAD on history paths only) and `colophon.home.write` for writes.
A current member may write records, live
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

**Notice routes and live streams** are available on home slots. See “Notices” and “Live stream” below.

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
<dataDir>/<slot>/routes.json      home slots: registered notice routes (includes private addresses)
<dataDir>/<slot>/notices.jsonl   home slots: durable queue of public notice metadata
<dataDir>/<slot>/notice-commit.json  home slots: temporary journal for crash recovery of a queue append
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

## Notices

A host registers delivery routes with each home (§17.5). Use `Authorization: Colophon <call>`
with the slot's base URL as the audience. Bind the call to the method, the path relative to
that base, and the lowercase SHA-256 digest of the request body (empty bytes for GET and DELETE).
The `kind` is one of `push`, `email`, `sms`, `webhook` or `other`. The `address` is the delivery
destination and `reaches` describes the device or service reached. The route ID is the lowercase
hex SHA-256 of the UTF-8 bytes of `kind`, one zero byte, and the UTF-8 bytes of `address`.

| Request | Purpose | Result |
| --- | --- | --- |
| `PUT {base}/routes/<route ID>` with JSON `{"kind","address","reaches"}` | `colophon.home.write` | 201 on creation or 200 on replacement |
| `DELETE {base}/routes/<route ID>` | `colophon.home.write` | 204 on removal or 404 when absent |
| `GET {base}/routes` | `colophon.home.read` | 200 with `{"routes":[{"id","kind","reaches","by"}]}` |

Any current controller can register or delete a route, including recovery-only and suspended
controllers. A current member can use its own key. Member links use their explicit service
grants. `by` identifies the registering principal as `controller:<ID>` or `member:<ID>`.
The route list omits delivery addresses. PUT takes an `application/json` body up to 4 KiB.
The home stages, fsyncs and renames the route file before acknowledging a change.

When the home admits a suspend or agrees to receipt a new transition or veto, it fsyncs
`notices.jsonl` before responding. It writes one line per registered route, or one line when
no routes are registered. Each line has the account ID, object digest, kind, signed issue
time and veto deadline, in fields `account`, `object`, `kind`, `issued` and `deadline`. Retrying an
already-held object does not duplicate notices. The queue survives restarts. Delivery
providers and signed notice payloads are outside this implementation.

## Live stream

On Bun, connect to `GET {base}/stream` using a WebSocket client that can set the
`Authorization: Colophon <call>` header. Use a fresh `colophon.home.read` call bound to
`{"method":"GET","path":"/stream","body":"<SHA-256 of empty bytes>"}` and the slot's audience.
An appointed home answers a missing call with 401 and a refused call with 403. Reconnecting
requires a fresh call.

The home sends compact JSON text frames after committing an event.

| Frame | When |
| --- | --- |
| `{"type":"head","seq":N,"digest":"..."}` | The slot stores a new signed head |
| `{"type":"change","cursor":N}` | A record write adds a change-log entry |
| `{"type":"notice","object":"...","kind":"...","deadline":"..."}` | A new notice is queued |

The numeric cursor is the slot's change-log position. Record frames carry no path names.
Use the normal authenticated HTTP endpoints to catch up after reconnecting and fetch records
or verify signed objects. The stream only sends live events and accepts no application messages.

## A stopped home

An account that finalizes a raise above layout 2 stops a 0.5 home. An authenticated
authority entry at N+1 on the home's head whose verifier verdict is `newerFormat` also
stops it: the entry passes the header, signature and control-rule checks before its
unknown content is judged. The home answers 422 `{"result":"newerFormat"}`, stores none
of that entry, and durably saves the stop before answering. Its verified history ends at N.
Both causes use the same stopped behavior. The home keeps its stored data.
Public history and the base endpoint remain readable. The base answer lists
the supported layouts in `"layouts":[2]`. Head reads return
503 with `Retry-After`; requests needing a call return 503 `{"result":"unavailable"}`,
even without a call. New authority and other pending objects return 422 `newerFormat`.
The home can still receipt timely vetoes and removal-only transitions anchored at or
before its last verified entry, but records no further entries and signs no heads.
Restarting with an intact state file does not clear the stop. If `home-state.json` is missing
from a slot that retains storage, or the file is damaged, the slot refuses to open; restore
the state file from a backup. A configured home slot prevents relay startup. A provisioned
slot opened at run time logs the failure and answers 503 `{"result":"unavailable"}`; it is
retried on the next request. Only a genuinely empty slot can start without a state file.
Update the home to support the account's new format.
