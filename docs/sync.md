# Cross-device sync through a relay

An iPhone app and an Android app can share one library through a **relay**: an untrusted HTTP
store of immutable, signed, encrypted records ([spec §8](../spec/colophon-0.2.md#8-http-exchange)).
Each device keeps its own local store as the source of truth. The SDKs list the relay's change
feed, pull the records they lack, push the records the relay lacks, and hand pulled records to
the core like any other external change. The relay never decides who is a member.

```
iPhone: ColophonSession ── FolderRecordStore ──┐                 ┌── FileRecordStore ── ColophonSession: Android
                                               └─ RelaySync ⇄ relay ⇄ RelaySync ─┘
```

## Run the relay

```sh
node relay/server.js token                                   # a token and its SHA-256
COLOPHON_RELAY_TOKENS="home=<token>" COLOPHON_RELAY_DATA=./relay-data node relay/server.js
```

The slot URL is `http://127.0.0.1:8787/v1/libraries/home`. For devices, put it behind HTTPS,
for example `tailscale serve --bg --https=443 http://127.0.0.1:8787` gives
`https://<machine>.<tailnet>.ts.net/v1/libraries/home`. Use a config file with `tokenSha256`
for anything long-lived. See [relay/README.md](../relay/README.md) for configuration, TLS,
storage layout and limits.

One slot holds one library. Every device of every member uses the same slot URL; a token may be
shared between a person's devices or issued per device (one config entry per slot today).

## Configure the Apple SDK

```swift
let token = try RelayToken.load(service: "com.example.myapp")   // Keychain, ThisDeviceOnly
let session = ColophonSession(configuration: .init(
    memberLabel: "My app", namespaces: ["reading.saved"],
    location: .privateContainer(home), privateContainer: home,
    keys: KeychainKeys(service: "com.example.myapp"),
    relay: RelayConfiguration(url: URL(string: "https://relay.example.ts.net/v1/libraries/home")!, token: token)))
```

Save the token once with `RelayToken.save(_:service:)` (for example from a settings screen or a
pairing QR code). Observe `session.syncState`, `lastSynced` and `syncConflicts`; call
`await session.syncNow()` on foreground entry (or `requestSync()` when connectivity returns).
`automatic: false` turns the background loop off so tests and hosts drive passes explicitly.

## Configure the Android SDK

```kotlin
val session = ColophonSession(
    SessionConfiguration.app(
        filesDir = filesDir, memberLabel = "My app", namespaces = listOf("reading.saved"),
        keys = KeystoreKeys.openOrCreate(this, "colophon.member"),
        relay = RelayConfiguration("https://relay.example.ts.net/v1/libraries/home", token),
    ),
)
```

Keep the token in app-private encrypted storage (for example an Android Keystore-wrapped
preference). Collect `session.syncState`; call `session.syncNow()` from `onResume`. Network calls
use `java.net.HttpURLConnection` on `Dispatchers.IO`; there is no new dependency. The app needs
`android.permission.INTERNET`, and cleartext HTTP is blocked outside local development.

## Pairing two devices

1. Device A restores with an empty local store; the SDK lists the relay first. An empty slot is
   `noLibrary`/`NoLibrary`, so A creates the library and its records are pushed.
2. Device B restores with the same slot URL. It pulls A's authority, writes its own signed
   pairing request and pushes it: `waitingForApproval(code)`.
3. A syncs, sees the request in `requests`, compares the six-digit code shown on B, and approves.
4. B syncs, receives the grant and becomes `ready`. Writes on either side now converge.

Revocation works the same way: A's revocation record reaches B on its next pass and B's session
becomes `denied`. Writes B made before seeing it are delivered by the relay but held by every
core (`revokedBackdated`), never folded.

## What the relay can and cannot see

| The relay sees | The relay never sees |
| --- | --- |
| Paths, sizes, digests, upload timing, client IP and token | Namespace keys or any private key |
| Authority history and requests: member public keys, labels, kinds, grants, revocations | Operation kinds and payloads (titles, URLs, notes, positions) |
| Public operation metadata: namespace, author, epoch, clock, authority sequence, claimed date | Blob plaintext |

It can withhold or delay records (a freshness attack) and could refuse to store them. It cannot
forge, alter or reorder their meaning: everything pulled is verified by the core, and a relay
token is never membership. Use a private network or TLS so that metadata stays off the wire.

## Failure states

| `syncState` | Meaning | What happens |
| --- | --- | --- |
| `idle` / `Idle` | Last pass completed | Long-polls the relay (`wait=25`) or waits for a local change |
| `syncing` / `Syncing` | A pass is running | — |
| `offline` / `Offline` | Relay unreachable, or busy (429/503) | Local reads/writes continue; retries with jittered backoff 1 s → 60 s |
| `unauthorized` / `Unauthorized` | 401/403: wrong or revoked storage token | Retries every 5 minutes; replace the token |
| `error` / `Error` | A conflict, a different library in the slot, or a protocol violation | Nothing is overwritten; `syncConflicts` lists conflicting paths |
| `disabled` / `Disabled` | No relay configured | — |

Guarantees, on both platforms:

- **An unreachable relay is never an empty library.** With an empty local store, the session
  stays `unavailable` until a listing succeeds; `create()` also requires a successful listing,
  and joins the relay's library instead of forking one if the slot is not empty.
- **Absence is not deletion.** A relay that lost data (410 on the cursor) is relisted and
  refilled from local records; nothing local is removed.
- **A different library stops sync.** If both sides hold `authority/00000001.json` with
  different bytes, nothing is pulled or pushed.
- **Pulled bytes are checked** against the listed SHA-256 and the record path grammar, then
  appended through the store's immutable, conflict-checked write.
- The cursor and the relay's known paths live in the private container (`relay.json`), never in
  the shared library.

## Tests

```sh
node --test relay/                                   # relay contract
COLOPHON_SOFTWARE_KEYS=1 swift test --filter RelaySyncTests   # Swift, fake + real relay
bash scripts/test-android.sh                         # includes RelaySyncTest (real relay)
bash scripts/test-relay-cross.sh                     # Apple and Android sessions, one relay
```
