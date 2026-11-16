# Colophon architecture

Colophon is a standard first and a library second. The repository holds:

```
spec/          the protocol (colophon-0.1.md)
conformance/   vectors every implementation must reproduce (spec §11)
crates/        the Rust core, the one implementation every platform runs
  colophon-core/   records, identities, authority, admission, sealing, domain reducers
  colophon-wasm/   wasm-bindgen bindings for browsers and Node
  colophon-ffi/    UniFFI bindings for Swift and Kotlin; host-owned keys
js/            @colophon/core: the npm package wrapping colophon-wasm, plus a WebCrypto key provider
playground/    the interactive introduction: a library and an agent, in a browser tab
Package.swift  ColophonSDK: only the Rust-backed 0.3 Apple SDK
swift/         0.3 SDK sources and tests
reference/swift/ independent 0.1 reference package, CLI, tests and legacy migration adapter
docs/          this file and design notes
```

## The core is a pure function of records

The core owns everything that must mean the same thing on every device (section numbers
refer to the 0.1 spec, which 0.3 revises):

- reading and writing records (spec §2): signed bodies, verification over the stored bytes,
  key-derived IDs;
- the authority history (§6): roots, grants, caveats, revocation with `kept`, handover;
- admission (§8.3): admitted, held, refused, each with a reason;
- namespace keys (§4) and operations (§8): unsealing, opening, ordering, sealing;
- domain reducers (§9): cached incremental state, deterministic replay, skipping unknown kinds,
  keeping unknown fields, bounded queries and device-local checkpoints;
- operation and query specs (§9.2, §9.3), so agents' tool lists are generated, not hand-written.

The core does no I/O. It never reads a file, opens a socket or looks at a clock. Hosts hand it
records and get back views and new records to store. That keeps it identical in a browser, on a
phone and on a server, and makes every result reproducible from the vectors.

## Keys stay with the host

Private keys belong to whatever protects them best on that platform: the Secure Enclave, Android
Keystore or StrongBox, a non-extractable WebCrypto key, a passkey, a cloud KMS or HSM. The core
never needs to hold one. Every private-key step is two-phase:

1. **Sign.** The core returns the exact body bytes to sign. The host signs them (ECDSA P-256,
   raw `r || s`) and hands the signature back; the core assembles the record.
2. **Agree.** To open a sealed key (§4) the core returns the ephemeral public key. The host runs
   ECDH with its agreement key and hands back the shared secret; the core derives the wrapping
   key and opens the box.

Two-phase calls work with asynchronous key stores (WebCrypto, Keystore, KMS) without the core
ever awaiting anything. A software key provider is built in for tests, the CLI and the vectors.

## One trust model for end-to-end and server encryption

A server is never trusted by being a server. It reads a namespace only as a member, with a grant
the person can see on their colophon page and end:

| Mode | Holds the namespace key | Enables |
| --- | --- | --- |
| End-to-end (default) | The person's devices and the members they granted | Storage and relays see only ciphertext |
| Server member | Also sealed to a server key held in a KMS or HSM | Search, transcription, push, agents that run while devices sleep |
| Attested server member | Sealed only to a key bound to an attested enclave build | The same, with evidence of which code holds the key |
| Recovery escrow (opt-in) | The recovery kit, sealed to a server key and unlocked by a passkey | Regaining access after losing every device |

Ending a server's access starts a new epoch it isn't sealed to, so it reads nothing written
afterwards. It can't unread what it already decrypted; the interface says so plainly.

## Dependencies

The Swift reference and the apps take no third-party dependencies. The Rust core takes a small,
pinned set of audited crates and nothing else: RustCrypto (`p256`, `aes-gcm`, `hkdf`, `sha2`),
`serde`/`serde_json`, `base64`, `getrandom`, and `wasm-bindgen`/`js-sys` in the WASM bindings crate
only. Native bindings additionally use `uniffi` (proc-macro mode) to generate matching Swift and
Kotlin transports, typed outcomes, and host key-provider callbacks. Every
addition is recorded here with its reason.

## Colophon 0.3: a clean break

The Rust core implements Colophon 0.3. It keeps 0.1's model (members with their own keys, a
user-held authority history, scoped grants, revocation that keeps the past, deterministic folds)
and drops what only existed for the apps that shipped first:

- **No backward compatibility with 0.1 libraries.** No legacy kinds, bridge imports or
  app-named wire constants. Purposes and digest seeds are `colophon/...` strings.
- **One curve family.** P-256 for signing and agreement everywhere, because it is what the
  Secure Enclave, Android Keystore and WebCrypto all hold natively.
- **HPKE for sealing** (RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
  AES-256-GCM), implemented so the decapsulation's ECDH can be done by the host (two-phase).
- **Member kinds are part of the grant**: `device`, `app`, `agent` or `server`. Everything an
  `agent` writes is marked `origin: ai` by the core from the author's key, never by a payload
  field.
- **Caveats are a small closed set** in 0.3: namespaces, read/write, expiry and a write budget.
  Richer delegation (attenuating sub-grants for agent swarms) is the next research step.
- **The keyring and WebAuthn controllers wait** until after 0.3's core is stable.

`spec/colophon-0.3.md` states the format. `conformance/0.3/` holds vectors the Rust core writes
and every other implementation must reproduce. The Swift reference and `conformance/` (0.1)
stay as the record of what shipped.

## Roadmap

1. Rust core (0.3): records, authority, admission, sealing and the `reading.saved`,
   `listening.podcasts` and `notes` folds, with its own conformance vectors.
2. WASM bindings, the `@colophon/core` package and the playground.
3. UniFFI bindings; Swift apps adopt the core behind their existing API.
4. Android moves from the legacy journal to Colophon through the same bindings.
5. Server members: a KMS key provider and the transcript worker as the first server member.
6. Verified-history persistence for fast cold open, bounded-memory host storage, and capability
   negotiation between module versions. Device-local projection checkpoints are implemented.
7. Delegation research for agent swarms (attenuating grants, approval laundering, tamper-evident
   forensics).

## JavaScript session tools (0.5)

The 0.5 session (`js/src/session`, [js-session.md](js-session.md)) adds **no npm dependency and no crate**: the package
still has one build dependency, TypeScript 5.9.3, and nothing at run time. Its tests use tools that are installed on
the machine, never bundled or redistributed:

| Tool | Version | Licence | Why |
| --- | --- | --- | --- |
| Bun (runtime, test runner, bundler) | 1.4.4 | MIT | Already the relay's runtime. Runs `js/test05` (`bun test`), spawns the relays, and bundles the browser test page (`Bun.build`). |
| Google Chrome, headless (Chromium's engine) | 157.0.8103.52 on the build Mac; any current Chrome or Chromium | Chrome: Google's terms, used as installed. Chromium: BSD-3-Clause | The real browser engine of `js/test05/run-browser.ts`: IndexedDB, WebCrypto key handles and WebAuthn with PRF (its virtual authenticator), driven over the DevTools protocol by Bun. No driver package. |
| OpenSSL command line | 4.1.0 on the build Mac; any current version | Apache-2.0 | Makes the throwaway TLS certificate of one browser run (the core takes only `https://<host>` as a web origin). Deleted with the run; never committed. |

## Android host pins (0.3)

| Dependency | Version | Why |
| --- | --- | --- |
| `net.java.dev.jna:jna` (Android AAR) | 5.18.1 | UniFFI 0.32.2 Kotlin transport; the AAR ships `libjnidispatch` per ABI. The same library calls Android libc `renameat2(RENAME_NOREPLACE)` because private app storage denies `link(2)`. The JVM tests keep the JAR. |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` / `android` | 1.10.2 | Session `StateFlow`, single-thread dispatcher, and `withContext` off the main thread. Also the JVM library (`sdk/kotlin`) since the 0.5 session (`com.luff.colophon.session`); `-core` there, `-android` in the app. |
| Android Gradle Plugin | 8.7.3 | Library AAR at compileSdk 35 / minSdk 33, matching Gradle 8.14.3. |
| Kotlin | 2.2.21 | Same pin as the JVM bindings. |
| JUnit 4.13.2 / AndroidX Test 1.6.x | — | JVM unit tests and the instrumented emulator journey. |
| `com.google.zxing:core` | 3.5.3 | Apache-2.0. The Android test app only (`apps/test-android`): encodes and decodes the pairing QR codes (Android has no platform QR API). Not in the SDK or the AAR. |
| `androidx.test:core` | 1.6.1 | Apache-2.0, part of AndroidX Test 1.6.x. The Android test app's instrumented UI test (`ActivityScenario`). |

### Passkeys on Android, and what they pull (resolved for `apps/test-android`, release runtime and instrumented tests)

`sdk/android` and the Android test app depend on Credentials and its Play Services adapter for passkeys (Credential
Manager with PRF). Gradle resolves this graph for the app (`:app:dependencies`, 2026-11-16). **The Play Services
artefacts and GoogleID are under the Android Software Development Kit License, not an open-source licence**: they are
proprietary Google binaries the passkey path needs on devices with Google Play services. Whether to keep them is the
owner's decision; nothing here removes passkey support.

| Dependency | Version | Licence | Why |
| --- | --- | --- | --- |
| `androidx.credentials:credentials` | 1.5.0 | Apache-2.0 | Credential Manager: passkey registration and assertions with PRF. Direct (SDK and app). |
| `androidx.credentials:credentials-play-services-auth` | 1.5.0 | Apache-2.0 | The Credential Manager provider adapter for Google Play services. Direct (SDK and app). |
| `com.google.android.gms:play-services-auth` | 21.1.1 | Android SDK License (not open source) | Pulled by the adapter. |
| `com.google.android.gms:play-services-fido` | 21.0.0 | Android SDK License (not open source) | Pulled by the adapter (FIDO2, passkeys). |
| `com.google.android.gms:play-services-identity-credentials` | 16.0.0-alpha02 | Android SDK License (not open source) | Pulled by the adapter. |
| `com.google.android.gms:play-services-auth-blockstore` | 16.4.0 | Android SDK License (not open source) | Pulled by the adapter. |
| `com.google.android.gms:play-services-auth-api-phone` | 18.0.2 | Android SDK License (not open source) | Pulled by `play-services-auth`. |
| `com.google.android.gms:play-services-auth-base` | 18.0.10 | Android SDK License (not open source) | Pulled by `play-services-auth`. |
| `com.google.android.gms:play-services-base` | 18.5.0 | Android SDK License (not open source) | Pulled by the Play Services artefacts above. |
| `com.google.android.gms:play-services-basement` | 18.4.0 | Android SDK License (not open source) | Pulled by the Play Services artefacts above. |
| `com.google.android.gms:play-services-tasks` | 18.2.0 | Android SDK License (not open source) | Pulled by the Play Services artefacts above. |
| `com.google.android.libraries.identity.googleid:googleid` | 1.1.0 | Android SDK License (not open source) | Pulled by the adapter (Sign in with Google; unused here). |
| `androidx.biometric:biometric` | 1.1.0 | Apache-2.0 | Pulled by Credentials. |
| `androidx.core:core`, `core-ktx` | 1.15.0 | Apache-2.0 | Pulled by Credentials. |
| `androidx.annotation:annotation` 1.8.1, `annotation-experimental` 1.4.1; `androidx.activity:activity` 1.5.1; `androidx.appcompat:appcompat` and `appcompat-resources` 1.2.0; `androidx.arch.core:core-common`, `core-runtime` 2.2.0; `androidx.collection:collection` 1.4.2; `androidx.concurrent:concurrent-futures` 1.1.0; `androidx.cursoradapter` 1.0.0; `androidx.customview` 1.0.0; `androidx.drawerlayout` 1.0.0; `androidx.fragment:fragment` 1.5.7; `androidx.interpolator` 1.0.0; `androidx.lifecycle:*` 2.6.2; `androidx.loader` 1.0.0; `androidx.profileinstaller` 1.3.0; `androidx.savedstate` 1.2.1; `androidx.startup:startup-runtime` 1.1.1; `androidx.tracing:tracing` 1.2.0; `androidx.vectordrawable:*` 1.1.0; `androidx.versionedparcelable` 1.1.1; `androidx.viewpager` 1.0.0 | as listed | Apache-2.0 | AndroidX libraries pulled by Credentials, Biometric and the Play Services artefacts. |
| `com.google.guava:listenablefuture` | 1.0 | Apache-2.0 | Pulled by AndroidX. |
| `org.jetbrains:annotations` | 23.0.0 | Apache-2.0 | Pulled by Kotlin. |
| `org.jetbrains.kotlin:kotlin-stdlib-jdk7` 1.9.0, `kotlin-stdlib-jdk8` 1.8.0 | as listed | Apache-2.0 | Empty compatibility artefacts pulled by older AndroidX POMs. |

Instrumented tests of the Android test app only (never in the APK):

| Dependency | Version | Licence |
| --- | --- | --- |
| `androidx.test:runner` | 1.6.2 | Apache-2.0 |
| `androidx.test.ext:junit` | 1.2.1 | Apache-2.0 |
| `androidx.test:monitor` | 1.7.2 | Apache-2.0 |
| `androidx.test.services:storage` | 1.5.0 | Apache-2.0 |
| `androidx.concurrent:concurrent-futures-ktx` | 1.1.0 | Apache-2.0 |
| `junit:junit` | 4.13.2 | EPL-1.0 |
| `org.hamcrest:hamcrest-core` | 1.3 | BSD-3-Clause |

## Implemented dependency pins (0.3)

The workspace pins direct dependencies exactly and commits `Cargo.lock`. Runtime dependencies
remain within the allowlist above:

| Crate | Version | Enabled features |
| --- | --- | --- |
| `p256` | 0.13.2 | `ecdsa`, `ecdh`, `alloc`; defaults off (no OS RNG) |
| `aes-gcm` | 0.10.3 | `aes`, `alloc`; defaults off |
| `hkdf` | 0.12.4 | defaults off |
| `sha2` | 0.10.9 | defaults off |
| `serde` | 1.0.228 | `derive`, `std`; defaults off |
| `serde_json` | 1.0.145 | `std`; defaults off |
| `base64` | 0.22.1 | `std`; defaults off |
| `wasm-bindgen` | 0.2.130 | `std`; defaults off, bindings only; matches the CLI |
| `uniffi` | 0.32.2 | defaults off; native bindings only; `cli` enabled only for the in-repo generator via `bindgen` |

Neither `getrandom` nor `js-sys` is needed by this implementation. WebCrypto and host-generated
seeds provide randomness. The JavaScript package's sole build dependency is exact-pinned
TypeScript 5.9.3; there are no bundler or runtime npm dependencies.

Revocation embeds replacement epochs in its authority record. Recovery embeds historical
reshares and fresh epochs in its recovery-signed record. Planned handover writes historical
reshares first, then transfers authority with fresh epochs excluding the former root. These
atomic transitions prevent a verified prefix from ending access without advancing encryption.
See the [0.3 specification](../spec/colophon-0.3.md) for the precise wire fields.

## Incremental engine and local caches

The core preserves the public `Library` API while adding reducer-backed queries, local revisions,
change summaries, batched key unlock and authenticated device-local projection checkpoints.
[Engine API](engine.md) defines the query names, paging, digest seed, cache authentication and
invalidation contract. No new crates were added for the engine or its `std::time::Instant`
benchmark. `DomainModule::fold` and the full `NamespaceView` remain compatibility APIs.

Records, parsed verified headers and authenticated plaintext are still retained by `Library`.
This is O(history) memory, despite projection-only reducer state and bounded snapshot retention.
[Performance](performance.md) records this limitation and distinguishes signature-verified cold
open from warm projection restoration; a projection checkpoint is not a verification cache.

## Native bindings and host scheduling

`colophon-ffi` wraps the public `Library` API behind a mutex. It performs no storage I/O,
clock reads, or random generation. Hosts supply timestamps and fresh 32-byte action seeds.
Signing and ECDH use explicit prepare/finish calls, so hosts can suspend without retaining a
Rust lock. The synchronous `KeyProvider` callback convenience is for local platform providers;
async stores use the same steps through `ColophonKit.AsyncKeyProvider`. No Rust executor or
async-trait dependency is required. Prepared session mutations carry a session ID and local
revision: a merge during signing fails with `StaleAction`, requiring a fresh preparation.
Changes conservatively invalidate all declared namespaces until the incremental engine exposes
a compatible change API. Unlock changes identify the namespace whose key became available.

UniFFI's transitive crates are pinned in `Cargo.lock`; its generator is a host build tool and is
not linked into mobile binaries. The Kotlin JVM transport uses JNA 5.18.1, Kotlin 2.2.21, and
Gradle 8.14.3; these are platform tooling/runtime dependencies, not additions to the Rust core.
The Android library (`org.luff.colophon:colophon-android`) additionally depends on
`net.java.dev.jna:jna:5.18.1@aar`. UniFFI's Kotlin bindings load `libjnidispatch` from that
AAR; the JVM JNA JAR does not package Android JNI. The same JNA calls libc
`renameat2(RENAME_NOREPLACE)` because private app storage denies `link(2)`. It also depends
on `kotlinx-coroutines-core`/`android` 1.10.2 for `StateFlow` and the single-thread session
dispatcher, and on Android Gradle Plugin 8.7.3 to assemble the AAR (`minSdk 33`,
`compileSdk 35`). Instrumented tests use AndroidX Test 1.6.x. None of these enter the Rust
core or the Swift products.
The Swift 0.1 reference products retain their existing dependency-free build.

## Apple app lifecycle (0.3)

The additive `ColophonKitStorage` product owns coordinated immutable folder records, App Group
and iCloud location resolution, change notifications and private checkpoint bytes. The
`ColophonSession` product owns process lifecycle, scoped pairing, revisions, typed query caches
and durable destination-bound ingress. Its internal `SessionCore` protocol isolates the current
`ColophonKit` snapshot API from the incoming incremental engine. Neither platform storage nor
extension envelopes grant authority. See [session contracts](session.md) and [new app](new-app.md).
The Android `ColophonSession` in `sdk/android` mirrors that lifecycle over `StateFlow`,
private files, and Android Keystore; see [Android session](android.md).
