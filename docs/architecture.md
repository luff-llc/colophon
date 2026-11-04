# Colophon architecture

Colophon is a standard first and a library second. The repository holds:

```
spec/          the protocol (colophon-0.1.md)
conformance/   vectors every implementation must reproduce (spec §11)
crates/        the Rust core, the one implementation every platform runs
  colophon-core/   records, identities, authority, admission, sealing, domain folds
  colophon-wasm/   wasm-bindgen bindings for browsers and Node
  (colophon-ffi/   UniFFI bindings for Swift and Kotlin: next)
js/            @colophon/core: the npm package wrapping colophon-wasm, plus a WebCrypto key provider
playground/    the interactive introduction: a library and an agent, in a browser tab
swift/         the Swift reference implementation that shipped in LUFF's apps
docs/          this file and design notes
```

## The core is a pure function of records

The core owns everything that must mean the same thing on every device:

- reading and writing records (spec §2): signed bodies, verification over the stored bytes,
  key-derived IDs;
- the authority history (§6): roots, grants, caveats, revocation with `kept`, handover;
- admission (§8.3): admitted, held, refused, each with a reason;
- namespace keys (§4) and operations (§8): unsealing, opening, ordering, sealing;
- domain folds (§9): deterministic, skipping unknown kinds, keeping unknown fields;
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
`serde`/`serde_json`, `base64`, `getrandom`, and `wasm-bindgen` in the bindings crate only. Every
addition is recorded here with its reason.

## Conformance is the contract

Implementations are interchangeable because they reproduce `conformance/expected.json` and
`conformance/keyring/expected.json` from the committed records and keys. The Rust core's test
suite runs those vectors; the Swift reference runs the same ones. A host moves from the Swift
reference to the Rust core one module at a time, only after the vectors pass.

## Roadmap

1. Rust core: verification, authority, admission, unsealing and the `reading.saved` and
   `listening.podcasts` folds, passing the vectors. Writing as a member.
2. WASM bindings, the `@colophon/core` package and the playground.
3. UniFFI bindings; Swift apps adopt the core behind their existing API.
4. Android moves from the legacy journal to Colophon through the same bindings.
5. Server members: a KMS key provider and the transcript worker as the first server member.
6. HPKE (RFC 9180, P-256) for sealing, one curve family everywhere, signed checkpoints for long
   histories, and capability negotiation between module versions.
7. Delegation research for agent swarms (attenuating grants, approval laundering, tamper-evident
   forensics).
