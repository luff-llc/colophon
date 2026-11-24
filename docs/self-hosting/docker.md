# Running a Colophon home in Docker

`relay/Dockerfile` packages the reference relay (`relay/`, Bun) with the Rust home module as one
image. It is configured by environment variables alone, keeps everything under one volume,
`/data`, and runs as a non-root user (UID 65532) with no shell in the image. On the first
start it makes the home's signing key and a provisioning token for you.

For what a home is and does, read [`relay/README.md`](../../relay/README.md). This page covers
running it in a container.

## Build and run

```sh
docker build -f relay/Dockerfile -t colophon-home:dev .      # from the repository root
```

The build compiles the module (`cargo build --locked --target wasm32-unknown-unknown --release
-p colophon-home-wasm`) with `rust:1.99.1`, then copies only `relay/*.js`, `relay/package.json`
and the `.wasm` onto `oven/bun:1.4.5-distroless`. Both base images are pinned by digest.
Neither stage has an architecture-specific step, so `docker buildx build --platform
linux/amd64,linux/arm64` should work, but only amd64 has been built and tested so far.

With Compose (or as a Portainer stack), edit `COLOPHON_PUBLIC_URL` in
[`relay/docker-compose.yml`](../../relay/docker-compose.yml) and run:

```sh
docker compose -f relay/docker-compose.yml up -d
docker compose -f relay/docker-compose.yml logs colophon-home    # the token, once
```

Or with plain `docker run`:

```sh
docker run -d --name colophon-home --restart unless-stopped \
  -v colophon-home:/data -p 127.0.0.1:8080:8080 \
  -e COLOPHON_PUBLIC_URL=https://home.example.org colophon-home:dev
curl http://127.0.0.1:8080/healthz          # {"ok":true}
```

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `COLOPHON_PUBLIC_URL` | required | The `https://` origin clients reach the home at, with no path. Slots are served at `<origin>/v1/libraries/<slot>`, and provisioning requires `base` = that URL. Plain `http://` works only for a loopback host. |
| `PORT` | `8080` | Listen port. Railway and similar hosts set this themselves. |
| `COLOPHON_HOST` | `0.0.0.0` | Listen address. Use `::` where the platform's private network is IPv6. |
| `COLOPHON_PROVISION` | `on` | `off` turns off the door at `POST /v1/provision`. |
| `COLOPHON_PROVISION_GATE` | `token` | `token`, `open`, `grant`, or a list such as `grant,token` (relay README, "Provisioning"). |
| `COLOPHON_PROVISION_TOKEN_SHA256` | made on first start | The SHA-256 of a token you made (`bun relay/server.js token`). Leave it unset to have a token made and printed once (not in hosted mode). |
| `COLOPHON_PRIVATE_LISTEN` | none | `host:port` of a private listener that alone serves `/v1/provision` and `/v1/operator/*`; the public port then answers 404 for both. Bind it to your private network only. Setting it turns on hosted mode. |
| `COLOPHON_HOSTED` | off | Hosted mode: with gate `token`, `COLOPHON_PROVISION_TOKEN_SHA256` is required, and no token is ever made or printed (a hash left on the volume is not used). |
| `COLOPHON_PROVISION_OPERATOR_ACCOUNT`, `COLOPHON_PROVISION_OPERATOR_SLOT` | none | Required with gate `grant`. The audience is `<origin>/v1/provision`. |
| `COLOPHON_MAX_SLOTS` | `200` | `provision.maxSlots` |
| `COLOPHON_PROVISION_PER_ADDRESS_PER_HOUR` | `10` | `provision.perAddressPerHour` |
| `COLOPHON_PROVISION_UNCLAIMED_HOURS` | `24` | `provision.unclaimedHours` |
| `COLOPHON_SLOT_BYTES` | `0` (no quota) | `limits.slotBytes`: the most bytes one slot may hold |
| `COLOPHON_CORS_ORIGINS` | none | A comma-separated list of exact `scheme://host[:port]` origins |
| `COLOPHON_CLIENT_IP_HEADER`, `COLOPHON_TRUSTED_PROXIES` | none | Set both or neither. The header holding the client's address (for example `X-Real-IP` or `CF-Connecting-IP`), and the peers it is read from: IP addresses or CIDR ranges, comma-separated. A `/0` range is refused. |

Those are read again at every start, and the relay config is rewritten from them. The relay's
plain-slot variables (`COLOPHON_RELAY_TOKENS`, `COLOPHON_RELAY_OPEN`, `COLOPHON_RELAY_HOME_SLOTS`)
and `COLOPHON_RELAY_TICK_MS` still take effect. Variables that would override the layout below
(`COLOPHON_RELAY_DATA`, `_HOST`, `_PORT`, `_CONFIG`, `COLOPHON_HOME_KEY*`, the test hooks) are
removed before the relay starts.

**Your own config.** If `/data/config.json` exists, it is used as-is and nothing is generated.
Relative paths in it are resolved against `/data`. `host`, `port` and `home.wasm` default to
`0.0.0.0`, `PORT` and the image's module if the file leaves them out. Use this for settings the
variables do not cover, such as `resolve` or `limits.requestsPerMinute`.

## What the volume holds

```
/data/secrets/home-key.jwk             the home's private P-256 key (0600). Its member ID is the home's identity
/data/secrets/provision-token.sha256   the token's SHA-256 (gate token). The token itself is not stored
/data/records-dir/                     the relay's data directory: every slot, provisioned.json
/data/run/relay-config.json            the config generated at this start
/data/.container.lock                  held while a container runs on this volume
```

Directories are 0700 and files 0600, owned by UID 65532. The key is generated with the relay's
own `server.js home-key` and checked by the relay's key import before it is put in place. It is
never overwritten or printed. Each start logs one line with the home's member ID:

```json
{"colophonHome":{"config":"generated","member":"6af8ab0c…","base":"https://home.example.org/v1/libraries/<slot>","provisioning":["token"]}}
```

**The key is the home's identity.** Every account that appoints this home names that member ID.
If you lose the volume, you lose the key, and those accounts must appoint a new home. Back it up.

## The provisioning token

**Hosted deployments** (a home you run for other people) set `COLOPHON_PRIVATE_LISTEN` or
`COLOPHON_HOSTED=1`, make the token themselves, keep it in their secret manager, and pass only
its hash in `COLOPHON_PROVISION_TOKEN_SHA256`. The container then refuses to start without that
hash and never prints a token. If a token was ever printed to a log that others can read (an
earlier start without hosted mode), treat it as known: make a new one, set its hash, restart,
and give the new token to your tools. The old one stops working at that restart.

For a home of your own:

On the first start with gate `token` and no `COLOPHON_PROVISION_TOKEN_SHA256`, the log shows:

```
==================== COLOPHON PROVISIONING TOKEN (shown once) ====================
COLOPHON_PROVISION_TOKEN=…
```

Copy it into the app or tool that provisions slots (`Authorization: Bearer <token>` on `POST
/v1/provision`). It is never shown again, and anyone who can read the container's logs can read
it. If you miss it or want a new one, delete `secrets/provision-token.sha256` from the volume and
restart. For example, while the container is stopped:

```sh
docker run --rm -v colophon-home:/data --entrypoint /usr/local/bin/bun colophon-home:dev \
  -e 'require("fs").unlinkSync("/data/secrets/provision-token.sha256")'
```

The token lets someone create new slots and, through the operator API (`/v1/operator/slots/<slot>`,
relay README, "The operator API, and read-only slots"), make a slot's data read-only and writable
again; the account's authority changes are always taken. With `COLOPHON_PRIVATE_LISTEN` set, the
door and the operator API are served only on the private listener. The token never reads or
deletes what a slot holds. It is meant for one operator's own tools. Do not ship it in an app; see
the relay README, "Self-hosting".

## Back up, restore, update

The home is consistent on disk only while no relay is writing to it. To back it up, stop the
container, archive the volume, then start it again:

```sh
docker stop colophon-home
docker run --rm -v colophon-home:/data:ro -v "$PWD":/backup busybox \
  sh -c "umask 077 && tar czf /backup/colophon-home-$(date +%Y%m%d%H%M%S).tar.gz -C /data ."
docker start colophon-home
```

The archive contains the private key. Encrypt it before it leaves the machine. To restore, extract
the archive into an empty volume while no container uses it, keeping the owner (UID 65532) and the
modes:

```sh
docker volume create colophon-home-restored
docker run --rm -v colophon-home-restored:/data -v "$PWD":/backup busybox \
  tar xzpf /backup/colophon-home-<time>.tar.gz -C /data
```

To update, rebuild or pull the new image, then `docker compose up -d` (or stop, remove and run
the container again with the same volume). The volume holds all state, so the container can be
replaced at any time. Read the release notes before moving between minor versions: a home's
state belongs to the format its module writes.

## Moving an existing home into the container

Moving a home that already runs (with `bun relay/server.js`, or in another container) into this
image is an offline handover: stop the old relay first, and start the container only once it
has exited. Two relays must never serve one data directory, and this container cannot see a
relay running outside it.

- Keep the home's key: it is the home's identity. Put it on the volume (for example
  `/data/secrets/home-key.jwk`, mode 0600, owned by UID 65532).
- Put the old data directory on the volume (for example `/data/relay-data/`) and add
  `/data/config.json` with your relay settings, `"dataDir": "./relay-data"` and
  `"home": {"keyFile": "./secrets/home-key.jwk"}`. The container then uses that config as-is.
- Without a `config.json`, the container generates its own layout under `/data/records-dir/`.
  If it finds a relay data directory at `/data` itself (slots, `provisioned.json`, a relay
  lock), it refuses to start rather than create a new, empty home with a new key beside it.

## One container per volume

A relay must never share its data directory. The relay's own lock (`records-dir/.relay.lock`)
names a process ID, but containers do not share process IDs. After an unclean stop (`docker
kill`, out of memory, power loss), the restarted relay would find its own PID in the stale lock
and refuse to start, every time. The entry point therefore keeps a lock of its own,
`/data/.container.lock`, and updates its timestamp every 5 seconds:

- A second container started on the same volume exits at once (status 2), saying another
  container holds it.
- After a clean stop (SIGTERM, as `docker stop` sends) the lock is released, and the next start
  is immediate. `docker stop` took about 0.4 s in testing. On SIGTERM the relay stops taking
  requests (503 with `Retry-After: 1`, long polls included), cuts its calls to other homes
  short, and waits up to 8 seconds for what is in flight: requests, forwarding passes and
  their saved state, and the slot's queued writes. Give the container at least 10 seconds to
  stop (Docker's default; the Compose file gives 15).
- After an unclean stop, a start is refused until the lock is stale. Then the lock is taken
  over, and the relay lock the dead container's relay left (one naming the relay's process ID
  in the container) is removed. A relay lock written by any other process, such as a relay
  running outside the container on the same data directory, is never removed: the start is
  refused (status 2) until that relay is stopped or its lock removed by hand. The same container restarted (same host
  name) waits for two missed updates, 11 seconds; a different container waits 30 seconds. With
  `restart: unless-stopped`, Docker keeps retrying, so the home comes back on its own.
- If a running container finds its lock taken (for example, it was paused for more than 30
  seconds and another container started meanwhile), it exits at once.

This lock works only for containers on one machine that see the same file system clock. Do not
put the volume on network storage that two hosts mount.

## TLS and reverse proxies

The container speaks plain HTTP. Clients need `https://`, so put a TLS-terminating proxy (Caddy,
nginx, Traefik, a Cloudflare or Tailscale tunnel, or the platform's edge) in front of it, and
publish the container's port only on loopback or on the proxy's network. Have the proxy pass
`Authorization`, `If-Match`, `If-None-Match` and `Content-Length`, and not buffer or rechunk
bodies: a body without `Content-Length` is refused with 411.

Behind a proxy, every request comes from the proxy's address. The per-address rate limits would
then put all clients in one bucket. Set `COLOPHON_CLIENT_IP_HEADER` to a header the proxy
*overwrites* with the client's single address (`X-Real-IP` with nginx/Caddy, `CF-Connecting-IP`
behind Cloudflare). Set `COLOPHON_TRUSTED_PROXIES` to the proxy's address or range, for example
the Docker network's subnet (`docker network inspect <net>`). A list such as `X-Forwarded-For:
a, b` is not an address and counts against one shared bucket. The header is used for limits
only, never for access.

## Railway and similar platforms

Set `COLOPHON_PUBLIC_URL` to the service's public domain; the platform sets `PORT`. Tried on
Railway in November 2026:

- Attach a volume mounted at `/data`. The Dockerfile has no `VOLUME` instruction because Railway
  refuses one.
- Railway mounts volumes owned by root, so set `RAILWAY_RUN_UID=0`. The home then starts as
  root, gives `/data` to UID 65532, and becomes that user before it does anything else; the log
  says `started as root; now UID 65532`. Any platform with root-owned volumes works the same way
  when the container is started as root (`docker run --user 0`).
- Set `RAILWAY_DOCKERFILE_PATH=relay/Dockerfile` when deploying from the repository.
- For per-client rate limits, set `COLOPHON_CLIENT_IP_HEADER=X-Real-IP` and
  `COLOPHON_TRUSTED_PROXIES=100.64.0.0/10` (the range Railway's edge connects from).
- A redeploy stops the old container before the new one starts, so the home is briefly
  unavailable; clients retry.

## What the operator can and cannot see

Records in a slot are encrypted and signed by the account's devices; the home stores
ciphertext. The operator (anyone with the volume or a shell on the host) can see:

- slot names, sizes, record paths, timestamps and request patterns;
- each account's authority history and heads (public by design), member requests, receipts;
- the home's own private key, which lets them sign as this home.

They cannot read record contents or forge an account's entries: the home holds no account key,
member key or seed (spec §13.1). They can withhold or delay service.
