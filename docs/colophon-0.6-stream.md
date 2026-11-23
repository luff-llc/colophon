# Colophon 0.6 home stream (v2)

**Status:** unfrozen draft, 2026-11-22. Proposed text for Colophon 0.6, open for review. Additive
to [0.5](../spec/colophon-0.5.md): nothing here changes a 0.5 object, verdict or path, and a 0.5
client that polls `GET {base}/changes` and `GET {base}/pending` sees no difference. The reference
home ([`relay/`](../relay/README.md)) implements it.

The stream does two things for a home's connected clients:

1. It **pushes what the home commits**: change-log entries (`change`), the home's heads
   (`head`), queued notices (`notice`) and notice-route changes (`route`). A client can resume
   after a gap from the same cursor `GET {base}/changes` uses.
2. It is the **home carrier** of [0.6 sessions §S9](../spec/colophon-0.6-sessions.md#s9-carriers) (the sessions draft): it
   forwards sealed session frames between connected members of one account.

The home is not a party to a session. It holds no session state, applies no session rule and
cannot read a frame. It checks a frame's outer fields, its size and its own caps, forwards it,
and keeps at most the latest `retain: true` frame per `(namespace, cell, from)` in memory for at
most 60 s. Nothing about a session frame is written to disk or logged.

## 1. Connecting

Two steps: a signed call mints a **stream ticket**, then the WebSocket presents it.

### 1.1 Minting a ticket

`POST {base}/stream/ticket` with no body and `Authorization: Colophon <call>`. The call is a 0.5
§12.2 call verified under §12.3 and §12.4, bound like every call at a home (§14): audience
`{base}`, `args` exactly `{"method":"POST","path":"/stream/ticket","body":"<SHA-256 of empty
bytes>"}`, and purpose **`colophon.home.stream`**. That purpose is reserved (0.5 §12.2) and is
accepted only for this request; this request accepts no other purpose.

Who may mint a ticket: whoever §14 allows `colophon.home.read` at the home, namely:

- a controller holding `approve` or `control` that is not suspended, or a `sign` controller
  whose `audiences` lists `{base}`;
- a current member with its own key;
- a member through links, only when the member's terms and every link's terms grant
  `colophon.home.stream` at `{base}`.

The last case is how a device whose member key is locked streams: while the key is available,
it signs a link to a key it holds in memory, with `services` terms naming `{base}` and
`colophon.home.stream`. The link key then mints tickets without the member key. Recover-only
and suspended controllers cannot stream. They poll `GET {base}/pending` with
`colophon.history.read`.

| Answer | When |
| --- | --- |
| 200 `{"ticket","expires","path":"/stream"}`, `Cache-Control: no-store` | Minted. `expires` is an ISO 8601 date on the home's clock (the reference home's format), unlike `hello.expiresAt`, which is milliseconds. |
| 400 | A body was sent |
| 401 `WWW-Authenticate: Colophon` | No call |
| 403 `{"result"}` | The call is refused (§12.3), including a wrong purpose, audience or binding |
| 405 | Not POST |
| 429 `{"result":"refused:window"}` | Replay share (§12.4), rate, or more than 8 outstanding tickets for this principal (256 per account) |
| 404 | The home is not appointed |
| 503 | Stopped, or shutting down |

The ticket call is an ordinary call. It therefore needs fresh heads from the account's homes
(0.5 §12.3 step 4): a device mints only after it has read the home's head recently, normally in
an exchange pass. A client must not present a ticket anywhere but `{base}/stream`, and must keep
tickets out of logs: until it is presented, a ticket is a bearer credential.

A ticket is 32 random bytes as unpadded base64url (43 characters). It is opaque and bound in
the home's memory to the account, the principal (`controller:<ID>` or `member:<ID>`), the
member's session number (or the first link's `session`), the narrowest expiry of the call's
chain, and the namespaces the member's terms hold `records` entries for. It lives
**30 seconds** on the home's clock and is **single use**: presenting it consumes it, whether or
not the connection then succeeds. A home keeps only the SHA-256 of a ticket. A ticket does not
outlive a restart of the home.

### 1.2 Opening the stream

`GET {base}/stream?ticket=<ticket>[&after=<cursor>]` as a WebSocket upgrade (RFC 6455). Text
frames only. No other query parameter is allowed.

**Why the query, not a first frame.** Browsers cannot set `Authorization` on a WebSocket, so the
ticket must travel in the URL or in a message. In the URL, the home refuses a bad ticket
with an HTTP status before upgrading. No unauthenticated socket holds a slot, and a client
learns 401, 403 or 429 like any other request. The cost is that URLs are often logged. That is
why the ticket is short-lived, single use and useless once redeemed, and why the reference home
never logs request URLs. A deployment behind a proxy SHOULD keep the query out of access logs.
The stream does not use cookies, so cross-site WebSocket hijacking has nothing to ride on, and
the home does not check `Origin`.

On the upgrade the home redeems the ticket, then re-judges the principal's standing at its
committed history (the ticket may be up to 30 s old) and applies the connection caps:

| Answer | When |
| --- | --- |
| 101 | Connected; the first frame is `hello` |
| 400 | An unknown query parameter, or a body |
| 401 `{"result":"refused:ticket"}` | No ticket |
| 403 `{"result":"refused:ticket"}` | Unknown, already used or expired ticket |
| 403 `{"result":"refused:revoked"}` | The principal lost access since minting |
| 429 `{"result":"refused:window"}` | Connection cap: 4 per principal, 64 per account |
| 404 | Not a home slot |
| 503 | Shutting down or released |

A principal is a controller, or a member with every link key under it.

## 2. Frames, home to client

Every frame is a JSON object with `type` and `n`. `n` is the frame's number on this connection,
starting at 1 with `hello` and rising by 1 with no gap. A home that cannot send a frame (a
slow consumer) closes the connection rather than skip a number. So a client that sees every
`n` has missed nothing on this connection.

| `type` | Fields | Meaning |
| --- | --- | --- |
| `hello` | `protocol` (`colophon/home-stream/6`), `account`, `home` (the home's member ID), `instance`, `cursor`, `head` (`{seq, digest}` or `null`), `notice` (last notice number, 0 for none), `principal`, `expiresAt` (ms or `null`), `namespaces`, `limits` | First frame. `cursor` is the change-log position after the replay that follows (§4). `limits`: `frameBytes`, `messageBytes`, `subscriptions`, `framesPerSecond`, `bytesPerSecond`, `sessionFramesPerSecond` and `sessionBytesPerSecond` (the account's shared budget for session frames, §5.2), `retainMs`, `pingMs` (how often the home sends a WebSocket-level ping), `idleMs` (the home closes with 4008 after this long with no pong and no message), `resumeEntries`. Without `after` the home sends no replay, and `cursor` is the live position. |
| `change` | `cursor`, `entry` | One change-log entry, exactly as `GET {base}/changes` lists it (`{"path","size","sha256"}` or `{"path","deleted":true}`), and the cursor `/changes` gives after it (`<instance>.<position>`). |
| `head` | `home`, `seq`, `digest` | The home stored a new head of its own over authority entry `seq` with that digest. |
| `notice` | `notice`, `object`, `kind`, `deadline` | The home queued a notice (§6). `notice` is its number. |
| `route` | `id`, `change` (`put` or `delete`), and for `put`: `kind`, `reaches`, `by` | A notice route changed. Never carries an address. |
| `session` | `frame`, and `retained: true` when given from the retained table | A session frame from another member, byte-for-byte the envelope the sender sent (§5). |
| `subscribed`, `unsubscribed` | `namespace`, `cell`, `ref`? | Acknowledges a subscription change. |
| `pong` | `t`?, `ref`? | Answers `ping`. |
| `error` | `code`, `ref`?, and `dropped` for `rateLimited` | A client frame was refused. The connection stays open. |
| `resync` | `reason` (`gone` or `tooFar`), `after` | The resume cursor could not be replayed (§4). |
| `bye` | `reason` (`restart` or `released`), `resume`, `retryMs`? | Sent just before the home closes the connection itself. |

`ref` echoes the `id` (a string of at most 64 characters) of the client frame being answered.
A client MUST ignore fields and frame types it does not know.

What reaches whom: `change`, `head`, `notice` and `route` go to every connection; any principal
that may stream may read all of them by HTTP anyway. `session` frames go only to members (§5).

## 3. Frames, client to home

| `type` | Fields | The home |
| --- | --- | --- |
| `subscribe` | `namespace`, `cell`, `id`? | Subscribes the connection to the cell when the member is entitled to the namespace (§5.1). It answers `subscribed`, then gives the cell's retained frames. Otherwise it answers `error` `notEntitled` or `badFrame`; past 64 subscriptions it answers `tooMany`. |
| `unsubscribe` | `namespace`, `cell`, `id`? | Removes the subscription; answers `unsubscribed`. |
| `session` | `frame`, `id`? | Forwards the frame (§5.2) or answers `error`. A forwarded frame is not acknowledged: members cannot tell a refusal or drop from loss (§S9). |
| `ping` | `t`?, `id`? | Answers `pong` with the same `t`. |

An unknown `type` answers `error` `unknownType`. A frame that is not a JSON object with a
string `type` answers `badFrame`, and a binary frame answers `binary`. None of these close the
connection. Error codes: `badFrame`, `binary`, `unknownType`, `notEntitled`, `from` (a spoofed
sender), `account`, `tooLarge`, `tooMany`, `rateLimited`.

## 4. Resume

A client resumes with the last `change` cursor it handled, or with a `/changes` cursor: the two
are one format, `<instance>.<position>`. It passes the cursor as `after` on connect. After
`hello`, the home sends every entry after `after` as `change` frames, in order. The last of them
carries `hello.cursor`, and live frames follow. All of this happens before anything else can
run on the home, so no entry is lost or repeated between the replay and the first live frame.

When the cursor cannot be continued, the home sends `resync` instead of the replay:

- `gone`: another instance's cursor, or one beyond the log. `GET {base}/changes` would answer
  410. The client lists from the beginning with `/changes`.
- `tooFar`: more than `limits.resumeEntries` (1,024) entries were missed. The client catches up
  with `GET {base}/changes?after=<its cursor>` until it reaches the cursor of a `change` frame
  it holds.

The stream's cursors and `GET {base}/changes` cursors are interchangeable, whatever `namespace`
filters the `/changes` request named: the position is in the whole change log (a filtered page's
cursor is the position after the last entry it scanned, not the last it returned). The stream
itself sends `change` frames for every namespace, so a client that reads only some namespaces
also gets frames for the others. A connection opened without `after` gets no replay.

Browser WebSocket APIs do not expose WebSocket-level pings. A client that needs to see liveness
SHOULD send a `ping` frame after `pingMs` without a message and treat `idleMs` of silence as a
dead connection.

Live frames keep flowing after `resync`. The cursor format is the same either way, so a client
may also ignore the stream's replay and poll `/changes` from its own cursor; both orders give
the same entries.

Heads, notices and routes are not replayed. `hello.head` names the latest head. A client whose
last seen notice number is below `hello.notice` reads `GET {base}/pending` (0.5 §17.5 requires
reading the pending feed on every sync regardless). Routes are read with `GET {base}/routes`.

## 5. Session frames (the home carrier)

### 5.1 Entitlement

A member is **entitled** to a namespace when its terms hold a `records` entry for it, of any
access. This is the rule of sessions §S1 "Who may join", and the same members a home serves
`/changes` to for that namespace. The home module decides entitlement from the committed
history (`stream_standing`), never the host code. It decides again on every authority commit,
on the sweep, and when a ticket is redeemed. Controllers are not members: a controller's
stream receives no `session` frames and cannot send or subscribe.

### 5.2 Forwarding

A client sends `{"type":"session","frame":<envelope>}`. The envelope is the frame of sessions
§S3 exactly as it will be delivered: `{"body":"<base64>","signature":"<base64>"}`, whose body is
the frame's JSON. The home module (`session_frame`, from
`colophon_core::v05::home_stream::check_session_frame`) checks, in order:

1. the encoded envelope is at most **16,384 bytes** (`tooLarge`);
2. the envelope is strict JSON with exactly `body` and `signature`. The body is strict JSON
   with `protocol` `colophon/session/6`, a namespace and a cell by their grammars, `from` and an
   optional `to` as member IDs, and an optional `retain` that is only `true` (`badFrame`);
3. `account` is the home's account (`account`);
4. `from` is the connection's authenticated member (`from`);
5. the member is entitled to `namespace` (`notEntitled`).

Everything else in the frame (`key`, `n`, `epoch`, `nonce`, `ciphertext`, the signature) is
opaque. It is not decoded, judged or kept. The home then sends `{"type":"session","frame":…}`
to every connection that is open, belongs to a member other than `from` (never back to the
sender, nor to the sender's other connections), is entitled to the namespace, and is subscribed
to `(namespace, cell)`, whether or not the frame carries `to`.

`to` is advice to receivers, not a route (sessions §S3, §S9). A member reachable only through
another member (a bridge) must still receive frames addressed to it, so the home does not narrow
delivery to `to`; a receiver that `to` does not name ignores the frame. The home still checks
that `to`, when present, is a member ID. A successful send has no answer, so the sender hears the
same thing whether or not the member `to` names is connected.

**Fan-out.** Each frame goes to every other subscribed connection of the account, at most
`streamsPerAccount − 1` = 63 with the defaults, so one inbound frame can cost the home 63 sends.
Two caps bound that work:

- per connection, the inbound rate for frames of every type: 50 frames/s (burst 100) and
  256 KiB/s (burst 512 KiB);
- per account, a budget for session frames from all its connections together: 100 frames/s
  (burst 200) and 512 KiB/s (burst 1 MiB).

The account budget is charged for every session frame that passes the checks above, whether or
not anyone is subscribed to its cell, so what a sender hears does not depend on who is connected.
A frame over the budget is dropped, counted and not retained, and its sender gets the same
`rateLimited` error as for its own rate. With the defaults an account makes the home send at
most 100 × 63 = 6,300 session frames/s or 512 KiB/s × 63 ≈ 31.5 MiB/s, with a burst of
1 MiB × 63 = 63 MiB, however many of its connections send and whatever `to` says. The budget is
shared: one connection sending at its own full rate uses half of it. Each receiver's queue is
bounded by `bufferedBytes` (1 MiB): a connection that falls further behind is closed with 4013,
so memory held for undelivered frames is at most 64 MiB per account. Operators who host many
accounts lower `sessionFramesPerSecond`, `sessionBytesPerSecond` or `streamsPerAccount`.

### 5.3 Retained frames

A frame with `retain: true` is also kept, in memory only, as the latest for
`(namespace, cell, from)`. A newer one replaces it. When a member subscribes to the cell, it
receives each retained frame of the other members, marked `retained: true`, whatever its `to`
says. A retained frame lives `retainMs`: 60 s at most, whatever a cell
policy says (the home knows no cells). It is dropped earlier when its sender's access ends or
narrows. A home holds at most 1,024 retained frames per account; when full, a new key is
forwarded but not retained. Nothing retained survives a restart.

### 5.4 What the home learns

For each frame: the account, namespace, cell, sender, the member it is addressed to (when `to`
is present; the home reads it but does not route by it), whether it is retained, its size and its
timing. It also knows which members are connected and subscribed, since it carries frames to
them. It learns nothing about the payload: the ciphertext is under an epoch key the home never
holds (0.5 §11.1).

## 6. Notices and routes

**Notice queue.** When the home admits a suspend, or receipts a new transition or veto, it
appends one line to `notices.jsonl` before answering:
`{"seq","account","object","kind","issued","deadline","routes":[…]}`. `seq` is the notice's
number. It increases, is never reused, and may skip after a failed commit. `routes` lists the
IDs of the routes registered at that moment. A delivery sender keeps its own cursor per route.
(W2 repeated each line once per route with no route ID; that is replaced.) Payloads stay
unsigned, as 0.5 §17.5 says.

**Routes** (`POST {base}/routes`, `DELETE {base}/routes/<id>`, `GET {base}/routes`):

- **Registering.** `POST {base}/routes` with `{"kind","address","reaches"}` registers the
  route, or replaces the caller's own route for that kind and address. The answer is 201
  `{"id"}` for a new route or 200 `{"id"}` for a replacement. A client keeps the ID to delete the
  route later and finds it again in `GET {base}/routes`.
- **IDs reveal no address.** A route ID is HMAC-SHA256 under the slot's **route key** of
  `principal`, a zero byte, `kind`, a zero byte and `address`, in lowercase hex
  (`colophon_core::v05::home_stream::route_id`). The route key is 32 random bytes the host
  generates (the home module takes randomness as input). It is kept with the routes and never
  served. IDs are listed and named in notice lines. Without the key, nobody who can list routes
  can test a guessed phone number, email or webhook URL against an ID. Because the principal is
  part of the input, registering an address answers the same whoever else registered it, so
  there is no cross-principal oracle. (W2 used the unkeyed SHA-256 of `kind` and `address`,
  which a reader of the list could invert by dictionary. A route file in that layout is
  re-keyed when the home opens it.)
- A principal changes and deletes **only routes it registered**. Another principal's route
  answers 403 `{"result":"refused:notGranted"}`, so one stolen key cannot silence another
  device's routes.
- **Caps:** 8 routes per principal and 64 per slot; past either, 507
  `{"result":"refused:overQuota"}`. Replacing one's own route is not a new route.
- **Form**, decided by `colophon_core::v05::home_stream::parse_route`. The body is exactly
  `{"kind","address","reaches"}`. The address is checked per kind: `push` is printable ASCII up to 4,096 bytes; `email` is
  `local@domain` with a DNS domain; `sms` is E.164; `webhook` is `https://` to a public DNS name
  with no user information, port, fragment, IP literal or local-only name (`localhost`,
  `.local`, `.internal`, `.home.arpa`, `.lan`); `other` is up to 1,024 bytes with no control
  characters. `reaches` is 1–128 bytes, has no control characters, and does not contain the
  address, compared case-insensitively.
- **Upkeep** (listing, and changing one's own routes) is open to every current controller,
  recover-only and suspended included, and to members with their own key or through links
  granted `colophon.home.write` (or `colophon.home.read` to list) at `{base}`.
- Routes of a principal that is no longer one (a removed controller, a revoked or expired
  member) are dropped on the next authority commit. Each change is pushed as a `route` frame.
- Not enforced: 0.5 §17.5's deferred idea of requiring two routes on different devices or
  services.

**Delivering to a webhook** (no sender exists yet; this binds any that is added). The checks
above are syntactic, but a public name can resolve, or later rebind, to private infrastructure.
A sender MUST:

1. resolve the host at delivery time, and refuse every resolved address in a loopback,
   private, link-local, unique-local, carrier-grade NAT, multicast, unspecified, documentation
   or other non-global range (for IPv4 at least `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`,
   `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4` and
   `240.0.0.0/4`; for IPv6 at least `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`, `ff00::/8`,
   and IPv4-mapped forms of the IPv4 ranges);
2. connect to the address it checked, pinned for that request (no second resolution), with TLS
   verified for the route's host name;
3. follow no redirect: a 3xx answer is a failed delivery;
4. bound the request in time and bytes, and send nothing but the notice payload.

## 7. Limits and hygiene

| Limit | Reference value | Behaviour |
| --- | --- | --- |
| Session frame | 16,384 bytes encoded | `error` `tooLarge`; the connection stays |
| WebSocket message | 20,480 bytes | Close 1009 |
| Connections | 4 per principal, 64 per account | 429 on upgrade |
| Inbound rate | 50 frames/s (burst 100), 256 KiB/s (burst 512 KiB) per connection | A frame over the rate is **dropped and counted**, never queued. The sender gets `error` `rateLimited` with its running `dropped` total, at most once a second |
| Session frames per account | 100 frames/s (burst 200), 512 KiB/s (burst 1 MiB), all connections together | Dropped, counted and not retained; the sender gets `error` `rateLimited` as above. Charged whether or not anyone is subscribed |
| Outbound backlog | 1 MiB unsent per connection | Close 4013 (slow consumer). The home never skips `n` and never queues without bound |
| Subscriptions | 64 per connection | `error` `tooMany` |
| Retained frames | 60 s, 1,024 per account | §5.3 |
| Tickets | 30 s, single use; 8 outstanding per principal, 256 per account | 429 on minting |
| Liveness | WebSocket ping every 20 s | No pong and no message for 60 s: close 4008 |

Clients that answer WebSocket pings (browsers and common libraries do so automatically) never
reach the idle timeout. A client MAY also send `ping` frames.

**Close codes**

| Code | Meaning | Client should |
| --- | --- | --- |
| 1000 | Normal | |
| 1001 | The slot was released (`bye` `released`) | Not resume at this home, when the `bye` (`resume: false`) came first. RFC 6455 1001 is also "going away", which proxies and load balancers send when they restart: a bare 1001 is a drop, and the client resumes |
| 1008 | Stream authorization ended: revoked, suspended, sessions ended, expired, or lost the role | Not reconnect until its standing changes |
| 1009 | Message too big | Fix the sender |
| 1011 | Internal error | Reconnect with backoff |
| 1012 | The home is restarting (`bye` `restart`, `resume: true`, `retryMs`) | Mint a new ticket after `retryMs` and resume with its last cursor |
| 4008 | Idle timeout | Reconnect and resume |
| 4013 | Slow consumer | Reconnect and resume; the replay or `resync` covers the gap |

**Revocation.** Every authority commit re-judges every open connection at the committed
history. So does a **sweep**, which runs while any connection is open and cannot be turned off.
Its interval is at most 5 s (`sweepMs`, from 1 to 5,000; a larger or zero setting refuses
start-up). Each connection's expiry timer also re-judges it. A failed settle on the sweep still
re-judges standing. A connection whose principal is no longer current is closed with 1008. That covers a
revoked or suspended principal, ended sessions, a different session number, expiry of the member
or the link, and a controller that lost `approve`/`control`/`sign`. A connection whose
namespaces narrowed loses those subscriptions. A home that runs no scheduler (`tickMs` 0) also
settles itself on the sweep, so a removal that falls due is recorded and evicts without waiting
for a request. A stopped home, or one at an unresolved fork, closes every stream with 1008: it
serves no records then either.

**Shutdown.** A home that stops sends `bye` `{reason:"restart", resume:true, retryMs:1000}` and
closes with 1012. A released slot sends `bye` `{reason:"released", resume:false}` and closes
with 1001.

## 8. Runtime

The reference home's stream uses Bun's built-in `ws` module. A relay with home slots therefore
runs only on Bun, and `startRelay` refuses to start a home on another runtime rather than serve
no stream. A relay with only 0.3 token slots needs no stream and still runs on Node.

## 9. Compatibility with 0.5

No 0.5 request, answer or object changes. `GET {base}/changes` keeps its cursor and long poll,
and `GET {base}` publishes no new field. The W2 experiment's header-authorized `GET {base}/stream`
is gone: an `Authorization` header on the upgrade is not a ticket (401). The W2 numeric `change`
cursor is replaced by the `/changes` cursor. W2 never shipped in a release.

## 10. Open questions

- Should the home carrier forward to the sender's other connections (the same member ID on
  two sockets)? Member IDs name one key, so this draft says no.
- Whether a `pass` or `take` frame (§S5) should be retained by default is the sessions draft's
  call. The carrier treats every `retain: true` frame alike.
- A shared ticket store would let several instances serve one audience. The reference home is
  one process.
- Delivery senders and signed notice payloads remain out of scope.
