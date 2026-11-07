# Handoff: relay sync (branch `relay`)

Cross-device sync for the 0.2 SDK. An iPhone app and an Android app can now share one library
through an untrusted relay that only moves ciphertext.

## What was built

| Part | Files |
| --- | --- |
| Spec §8 "HTTP exchange": slot URLs, `changes?after=&limit=&wait=` cursor feed with 410 reset, GET, put-if-absent (201/200/412), mutable `requests/` (replace, DELETE), bearer token = storage only, limits (16 MiB record, 65,552-byte blob, 1,000/page, 30 s wait), MAY validate / MUST NOT alter, client reconciliation rules and what the relay sees | `spec/colophon-0.2.md` |
| Reference relay: Node 22+, `node:http/https/fs/path/crypto` only; per-slot disk store with `link(2)` atomic writes, fsynced append-only log, cursors bound to a per-slot instance ID, crash recovery and cursor reset on data loss, `lstat`/`O_NOFOLLOW` symlink refusal, path grammar matching the SDKs, blob digest check, size limits, optional quota, constant-time hashed tokens, long-poll, TLS option, CLI `token` helper | `relay/relay.js`, `relay/server.js`, `relay/README.md`, `relay/test/` |
| Swift: `RelayClient` (+ `RelayTransport`, `URLSessionRelayTransport`), `RelaySync` actor, `RelaySyncState` in ColophonKitStorage; `SessionConfiguration.relay: RelayConfiguration?`, `ColophonSession.syncState/lastSynced/syncConflicts/syncNow()/requestSync()/stopSync()`, background long-poll + backoff loop, `RelayToken` Keychain helper | `swift/Sources/ColophonKitStorage/Relay*.swift`, `swift/Sources/ColophonSession/{ColophonSession,SessionWorker,SessionTypes,RelayToken}.swift` |
| Kotlin/Android: same component with `HttpURLConnection` (no new dependency): `RelayClient`, `RelaySync`, `SyncState`, `RelayConfiguration`, `syncState` StateFlow, `syncNow()`, background loop on `Dispatchers.IO` | `sdk/android/src/main/kotlin/org/luff/colophon/{RelayClient,RelaySync,ColophonSession,SessionWorker,SessionTypes}.kt` |
| Tests | `relay/test/relay.test.js`, `swift/Tests/ColophonSessionTests/RelaySyncTests.swift`, `.../CrossPlatformRelayTests.swift`, `sdk/android/src/test/.../RelaySyncTest.kt`, `.../CrossPlatformRelayTest.kt`, `scripts/test-relay-cross.sh` |
| Docs | `docs/sync.md` (new), `docs/new-app.md` step 8, `docs/android.md` relay paragraph |

Behavior both SDKs share: the local store stays the source of truth; a pass lists the feed
from the saved cursor (relisting after 410), refuses a slot whose genesis differs from the local
one, pulls missing records (authority → requests → ops), checks each against the listed
SHA-256, appends through the immutable store, pushes what the relay lacks, reports conflicts
without overwriting, persists cursor + remote set in the private container (`relay.json`), and
refreshes the session when records arrived. **With an empty local store, restore and create
require a successful listing; an unreachable or unauthorized relay yields `unavailable`, never
`noLibrary`, and create joins a non-empty slot instead of forking it.**

## Run it

```sh
node relay/server.js token
COLOPHON_RELAY_TOKENS="home=<token>" node relay/server.js        # 127.0.0.1:8787
tailscale serve --bg --https=443 http://127.0.0.1:8787           # devices: https://<host>.ts.net/v1/libraries/home
bash scripts/test-relay-cross.sh                                 # Apple and Android sessions, one relay
```

The cross-platform script starts a relay on a free port, then alternates real processes:
Apple creates + writes → Android joins (pairing request) → Apple approves → Android writes →
Apple verifies → Android verifies (`["from-android","from-apple"]` on both). Set
`CARGO_OFFLINE=1 GRADLE_OFFLINE=1` without network.

## Checks (Nov 6, 2026, macOS arm64, Node 24.12, JDK 17)

| Check | Result |
| --- | --- |
| `node --test relay/` | 11 tests, 11 pass |
| `COLOPHON_SOFTWARE_KEYS=1 swift test` | exit 0; 72 Swift Testing tests pass (28 + 24 + 1 + 9 + 10), 0 failures; skipped: `crossPlatformStep` (script-only), `ffiPerformance`, `enclaveRequiresExplicitFallback` (pre-existing). Relay suite: 5 tests incl. fake relay, real Node relay two-client journey and automatic background sync |
| `cargo test --locked --offline` | 129 passed, 0 failed (16 result groups) |
| `npm --prefix js test` (after `npm ci` and build) | key-security, Node 24 smoke and Books parity passed |
| `bash scripts/test-android.sh --offline` | BUILD SUCCESSFUL; 49 JVM tests, 0 failures (RelaySyncTest 4/4 against the real relay; CrossPlatformRelayTest skipped outside the script) |
| `bash scripts/test-relay-cross.sh` | all six steps passed; Android steps ran (`skipped="0"`) |

The two-client tests (Swift fake relay, Swift + Node relay, Kotlin + Node relay) cover: owner
create, member join via relay, pairing-code match, approval, writes both ways, identical query
results, then revocation: the member's offline write is pushed but **held** (`revokedBackdated`)
by the owner's core and never folded, the member becomes `denied` after its pass and its session
refuses further writes (`notReady`). Unreachable relay (closed port / simulated outage) and wrong
token produce `unavailable` + `offline`/`unauthorized`; an empty listed slot is `noLibrary`.

Note: `sdk/apple` held an xcframework copied without its folder; I moved the identical slices
into the git-ignored `sdk/apple/ColophonFFI.xcframework` (headers match the generated bindings).

## Gaps

- **Blobs are not synced by the SDKs.** The relay stores and verifies `blobs/<sha256>` chunks and
  the feed lists them, but clients skip them (`RecordStore` has no blob listing; Android has no
  blob store). Needed before imported blob content syncs across devices.
- Each pass reads the full local snapshot and the remote set is kept in memory/`relay.json`
  (O(library)); fine for current sizes, not for 100k-op libraries. Digests of local records are
  cached per process.
- The relay does not validate envelopes, signatures or the authority chain, and implements no
  rate limiting (429/503 are client-handled only). One token per slot; no per-device tokens or
  revocation of storage tokens other than editing config.
- No iOS background execution (BGTask/push) or Android WorkManager scheduling; sync runs while
  the process is alive and on `syncNow()`. Apps must add `INTERNET` permission on Android and use
  HTTPS (ATS / cleartext policy).
- `NSFileCoordinator` folder stores, Keychain token storage and Tailscale/HTTPS deployment were
  not exercised in tests (sandboxed tests use `coordinated: false` and software keys).
- A `requests/` replacement on the relay shows up as a client conflict (0.2 clients keep requests
  immutable), by design.
