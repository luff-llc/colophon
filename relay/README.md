# Colophon reference relay

A small, dependency-free Node 22+ server implementing the Colophon 0.3 HTTP exchange
([spec §8](../spec/colophon-0.3.md#8-http-exchange)). It stores each library slot's signed,
encrypted records on disk and moves them between devices. It holds no keys and grants
nothing: a relay token is storage access, never library membership.

Only `node:http`, `node:https`, `node:fs`, `node:path` and `node:crypto` are used.

## Run it locally

```sh
node relay/server.js token          # prints {"token": "...", "tokenSha256": "..."}
COLOPHON_RELAY_TOKENS="home=<token>" COLOPHON_RELAY_DATA=./relay-data node relay/server.js
# {"listening":{"host":"127.0.0.1","port":8787,"tls":false}}
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8787/v1/libraries/home
```

The slot URL `http://127.0.0.1:8787/v1/libraries/home` plus the token is what both SDKs are
configured with (see [docs/sync.md](../docs/sync.md)).

For anything long-lived, use a config file that stores only token hashes:

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "dataDir": "/var/lib/colophon-relay",
  "libraries": {
    "home": { "tokenSha256": "<tokenSha256 from `node relay/server.js token`>" }
  },
  "limits": { "recordBytes": 16777216, "blobBytes": 65552, "pageEntries": 1000, "waitSeconds": 30, "slotBytes": 0 }
}
```

```sh
node relay/server.js --config relay.json
```

| Setting | Env | Default |
| --- | --- | --- |
| Listen host / port | `COLOPHON_RELAY_HOST`, `COLOPHON_RELAY_PORT` (0 picks a free port) | `127.0.0.1`, `8787` |
| Data directory | `COLOPHON_RELAY_DATA` | `./relay-data` |
| Config file | `COLOPHON_RELAY_CONFIG` or `--config` | none |
| Plain tokens (development) | `COLOPHON_RELAY_TOKENS="slot=token,slot2=token2"` | none |
| Token-free slots (tests only) | `COLOPHON_RELAY_OPEN="slot"` | none |
| TLS | `COLOPHON_RELAY_TLS_CERT`, `COLOPHON_RELAY_TLS_KEY` (PEM paths) or `"tls":{"certFile","keyFile"}` | off |

The first stdout line is always `{"listening":{...}}`, so supervisors and tests can start it on
port 0. `SIGINT`/`SIGTERM` stop it cleanly. `GET /healthz` answers without a token.

## Behind Tailscale or HTTPS

Keep the relay on loopback and let something terminate TLS in front of it.

**Tailscale** (private to your tailnet, automatic certificates):

```sh
COLOPHON_RELAY_TOKENS="home=<token>" node relay/server.js        # 127.0.0.1:8787
tailscale serve --bg --https=443 http://127.0.0.1:8787
# Slot URL: https://<machine>.<tailnet>.ts.net/v1/libraries/home
```

Use `tailscale funnel` only if devices outside the tailnet must reach it; the bearer token is then
the only storage gate, so use a long random token and keep the relay's limits.

**Direct HTTPS**: set `COLOPHON_RELAY_TLS_CERT`/`COLOPHON_RELAY_TLS_KEY` and bind the public
interface, or put Caddy/nginx in front with `reverse_proxy 127.0.0.1:8787`. Proxies must pass
`Authorization`, `If-None-Match`, `If-Match` and `Content-Length` through, must not buffer or transform
bodies, and should allow 35-second reads for long-polled `changes?wait=30`. iOS App Transport
Security and Android cleartext policy both require HTTPS outside local development.

## Storage layout and guarantees

```
<dataDir>/<slot>/meta.json      {"instance": "<random>"}: cursors are bound to it
<dataDir>/<slot>/log.jsonl      append-only change log: {"path","size","sha256"} per line
<dataDir>/<slot>/records/...    the records, at their spec paths
<dataDir>/<slot>/tmp/           staging for atomic writes
```

- Immutable records are staged with mode 0600, `fsync`ed, then `link(2)`ed into place, so an existing
  record is never replaced; the directory and log line are `fsync`ed before 201.
- Identical re-PUTs answer 200; different bytes at an immutable path answer 412.
- `state/` creates use `If-None-Match: *`; replacements require `If-Match: "<prior sha256>"`.
  The comparison and replacement are serialized and durable; stale expectations return 412 and
  unconditional replacement returns 428. Clients verify signatures and generations first.
- `requests/` alone supports unconditional replacement and `DELETE`.
- `changes?namespace=notes&namespace=listening.podcasts` filters namespaced ops/state/history,
  retaining authority, requests and legacy flat paths whose namespace is not known from the path.
- Blob chunks (`blobs/<sha256>`) must hash to their name.
- Paths follow the SDK grammar: no traversal, no dot-files, no `%` escapes. Every directory
  component is checked with `lstat` and files are opened with `O_NOFOLLOW`; a symlink anywhere in
  the slot makes the relay refuse to serve it.
- On start, a torn final log line is dropped and records linked before their log line are
  appended. If a logged record is missing or changed, the slot gets a new instance ID, the log is
  rebuilt from disk, and old cursors answer 410 so clients relist.
- Bodies above the limit are 413 and nothing is stored. `slotBytes` sets an optional quota (507).

The relay does not validate signatures or the authority chain. It cannot read payloads, but it
does see paths, sizes, timing, member public keys, labels and grants in authority/request
records, and the public operation metadata (namespace, author, epoch, clock). See
[docs/sync.md](../docs/sync.md#what-the-relay-can-and-cannot-see).

## Tests

```sh
node --test relay/
```

Covers the path grammar, bearer tokens, put-if-absent/412/idempotent re-PUT, the cursor feed and
long-poll, `requests/` mutation, blob digests, size limits, restart and crash recovery, cursor
reset after data loss, symlink refusal and the CLI. The Swift and Kotlin SDK tests also start this
server when `node` is available.
