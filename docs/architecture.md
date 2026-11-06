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
Package.swift  ColophonSDK: only the Rust-backed 0.2 Apple SDK
swift/         0.2 SDK sources and tests
reference/swift/ independent 0.1 reference package, CLI, tests and legacy migration adapter
docs/          this file and design notes
```

## The core is a pure function of records

The core owns everything that must mean the same thing on every device (section numbers
refer to the 0.1 spec, which 0.2 revises):

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

## Colophon 0.2: a clean break

The Rust core implements Colophon 0.2. It keeps 0.1's model (members with their own keys, a
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
- **Caveats are a small closed set** in 0.2: namespaces, read/write, expiry and a write budget.
  Richer delegation (attenuating sub-grants for agent swarms) is the next research step.
- **The keyring and WebAuthn controllers wait** until after 0.2's core is stable.

`spec/colophon-0.2.md` states the format. `conformance/0.2/` holds vectors the Rust core writes
and every other implementation must reproduce. The Swift reference and `conformance/` (0.1)
stay as the record of what shipped.

## Roadmap

1. Rust core (0.2): records, authority, admission, sealing and the `reading.saved`,
   `listening.podcasts` and `notes` folds, with its own conformance vectors.
2. WASM bindings, the `@colophon/core` package and the playground.
3. UniFFI bindings; Swift apps adopt the core behind their existing API.
4. Android moves from the legacy journal to Colophon through the same bindings.
5. Server members: a KMS key provider and the transcript worker as the first server member.
6. Verified-history persistence for fast cold open, bounded-memory host storage, and capability
   negotiation between module versions. Device-local projection checkpoints are implemented.
7. Delegation research for agent swarms (attenuating grants, approval laundering, tamper-evident
   forensics).

## Implemented dependency pins (0.2)

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
See the [0.2 specification](../spec/colophon-0.2.md) for the precise wire fields.

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
The Swift 0.1 reference products retain their existing dependency-free build.

## Apple app lifecycle (0.2)

The additive `ColophonKitStorage` product owns coordinated immutable folder records, App Group
and iCloud location resolution, change notifications and private checkpoint bytes. The
`ColophonSession` product owns process lifecycle, scoped pairing, revisions, typed query caches
and durable destination-bound ingress. Its internal `SessionCore` protocol isolates the current
`ColophonKit` snapshot API from the incoming incremental engine. Neither platform storage nor
extension envelopes grant authority. See [session contracts](session.md) and [new app](new-app.md).
