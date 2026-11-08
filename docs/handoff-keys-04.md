# Handoff: Colophon 0.4 keys and keyring

**Spec:** [spec/colophon-0.4-keys.md](../spec/colophon-0.4-keys.md). Implement it **exactly**;
the spec decides every question. If you find an ambiguity, stop and report it. Don't resolve
it in code.
**Branch:** `keys-0.4`, cut from `main` at `4c91add`. Each work package runs in its own
worktree off `keys-0.4`.
**Goal:** move all passkey, keyring and vault logic out of the Swift-only 0.1 package
(Marginalia `packages/Colophon/Sources/ColophonAuthority` and the `ColophonUI` ceremonies)
into the shared Rust core and SDKs, so that iOS, macOS, visionOS, Android, the web and Galley
share one verifier and one writer. Backward compatibility with 0.1 or 0.3 authority is **not**
required. Older libraries move by clean copy ([clean-copy.md](clean-copy.md)).

## Rules for every package

- **Rust:** keep the existing dependency set (`p256`, `aes-gcm`, `hkdf`, `sha2`, `serde`,
  `serde_json`, `base64`). Write the CBOR reader by hand (spec §2.5). Detect duplicate JSON
  members with a custom pass over `serde_json`'s deserializer, never by first- or last-wins.
  The core stays sans-IO with no RNG: hosts pass seeds, as now.
- **Swift:** Swift 6 language mode, no third-party dependencies, no force unwraps or `try!`
  outside tests. **Kotlin:** follow `sdk/kotlin`. **JS:** follow `js/`.
- **Tests:** each package adds focused tests for its own module and runs only those. The full
  suite and cross-binding vectors run once, at integration (W8). There are no simulator
  journeys in this work.
- **Don't** touch the 0.3 conformance vectors, `reference/`, or another package's files.
- Report: changed files, tests run with results, and any spec question. Claude reviews, agy
  reviews, then Claude commits. Codex can't write `.git`.

## Work packages

Wave A packages run in parallel, because their interfaces are fixed by the spec. Later waves
start when the previous one lands.

| ID | Wave | Package | Files | Done when |
| --- | --- | --- | --- | --- |
| **W1** | A | **Keys and signatures**: key descriptor (§2.2), strict JSON parsing (§2.1), COSE parser (§2.5), the WebAuthn verifier (§3.3: origin rules, the `origins` allowlist, minimal DER, low-S normalization inside verification), and the envelope with cosignatures (§3.1) | New `crates/colophon-core/src/keys/` (`descriptor.rs`, `strict_json.rs`, `cose.rs`, `webauthn.rs`, `envelope.rs`) | Unit tests cover every §3.3 refuse case in §10, plus a high-S accept. Includes a synthetic authenticator for tests. |
| **W2** | A | **Vault and slots**: vault derivation (salt `colophon/vault/4`); `sealed`, `prf` and `combined` slots with the `I`/`Ii` info strings; the seed-to-vault check; the PRF transform helper for CTAP hosts; structural validation | New `crates/colophon-core/src/vault.rs`, `slots.rs` | Unit tests: open each slot kind; wrong secret gives `vaultLocked`; foreign seed gives `vaultLocked`; every malformed shape in §10 is rejected |
| **W3** | B | **Authority 4**: rewrite `authority.rs` for §6 and §7. The `/4` body; genesis, rekey (seq 2 rule), grant (with `import`), revoke, keyring and layout; the control, recovery and single rules; recovery only-adds with the approve-only limit; rotation triggers; fresh-vault and one-principal checks; the §6.3 verification order; sealing to vault plus members. Remove root, recovery, reshare, handover and recover. | `crates/colophon-core/src/authority.rs`, and call sites in `library.rs` and `storage.rs` that read root or recovery | Unit tests for every rule in §10. The 0.3 root import role is replaced by the import grant in `imports.rs`. |
| **W4** | C | **Conformance vectors**: a generator binary with fixed seeds and the synthetic authenticator, writing `conformance/0.4/keys/` (records, keys, expected outcomes for every §10 case); plus a Rust runner | `crates/colophon-core/tests/keys_conformance.rs`, `conformance/0.4/keys/` | Every §10 case has a vector, and the runner passes |
| **W5** | C | **Library API and FFI/WASM**: create a library with a keyring genesis; `begin_unlock` over slots, `finish_unlock` with PRF or ECDH secrets; `prepare_authority` returning body, eligible signers and challenges; `finish_authority` with envelopes; add/remove controller, add passkey (PRF-first), recovery add; grant/revoke via controllers. Extend `KeyProvider` with `form`, `assert(challenge) -> {signature, authenticatorData, clientData}` and `prf(salt)`. Remove `begin_handover` and `begin_recover`. Regenerate Swift and Kotlin bindings; update the WASM exports. | `library.rs` (keyring actions), `crates/colophon-ffi/src/lib.rs`, `types.rs`, `crates/colophon-wasm/src/lib.rs`, generated bindings | FFI tests run W4's vectors through the Swift, Kotlin and WASM bindings with identical results |
| **W6** | D | **Apple providers in the SDK**: move `SystemWebAuthnCeremonies`, the WebAuthn presentation anchor and context, Secure Enclave owner keys and `UnlockedIdentity`-style one-presence signing from Marginalia into a new `ColophonKeys` Swift product. Implement the W5 provider protocol: passkey and security-key assertion with PRF; registration that parses COSE through the core; owner keys in Secure Enclave. | `swift/Sources/ColophonKeys/` (new), `Package.swift` | Swift tests with a fake ceremony object. Security-key PRF gated to iOS and macOS 26.4+, never on visionOS (spec C3). |
| **W7** | D | **Android and web providers**: Credential Manager passkeys with PRF where available, and Keystore/StrongBox owner keys (`sdk/android`); a WebAuthn and WebCrypto provider (`js/`) | `sdk/android/…keys/`, `js/src/keys/` | JVM tests with a fake credential manager; JS tests with a fake `navigator.credentials` |
| **W8** | E | **Integration and freeze evidence**: the full Rust suite, all bindings, all vectors, plus a performance check against the spec budgets (WebAuthn verify < 1 ms; 200-entry keyring fold < 20 ms on the oldest supported iPhone class, measured on host with a scaling note) | `docs/performance.md` (section), `docs/handoff-keys-04.md` (results) | Everything green; numbers recorded |

The **clean copy** tool (W9, after W5) and the **Marginalia app cutover** (Taupe, Later,
Marginalia, Margins and Shelf switching from `ColophonAuthority` to `ColophonKeys` plus
`ColophonKit`) are separate handoffs. The cutover goes through Marginalia's coordinator
(`tools/integrate-main.sh`).

## What gets removed afterwards

Once W6 and the cutover land, Marginalia's `ColophonAuthority` keyring code and its ceremonies
are deleted from the app path. Their tests stay in `reference/` history as the behavioral
record.

## Results (2026-11-08)

All packages W1–W9 landed, plus integration fixes. Verified on tree `4c98013`, on an Apple Silicon
Mac (macOS 27, Xcode 27.2, Rust 1.91, Node 24, JDK 17):

| Check | Result |
| --- | --- |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass |
| `cargo test --workspace` | Pass (24 suites, 0 failures), including 98 key vectors and the 0.4 library fixture |
| `wasm32-unknown-unknown` core build | Pass |
| `scripts/generate-bindings.sh` | Pass; generated Swift and Kotlin bindings unchanged |
| `scripts/build-apple.sh` (macOS, iOS, iOS simulator, visionOS, visionOS simulator) | Pass |
| `scripts/test-swift.sh` (root SDK, including `ColophonKeys`) | Pass: 29, 51, 2, 10, 14 and 12 tests |
| `ColophonKeys` device builds | iOS and visionOS pass |
| `swift test --package-path reference/swift` (software keys) | Pass: 368 plus 14 clean-copy plus 14 migration |
| `scripts/test-kotlin.sh`, `scripts/test-android.sh` | Pass (including the relay journeys and real `androidx.credentials` compilation) |
| `npm --prefix js test`, `js/test/*`, playground build and test | Pass |
| Session suite repeated 15 times after the readiness fix | 0 failures |
| Independent security review | Two medium findings, both fixed with regression tests. Final pass: "Ready to ship: yes" |
| Performance | WebAuthn verify about 0.23 ms (budget 1 ms). Cold 200-entry keyring replay about 56 ms against a 20 ms budget: **deviation D-F2-1** (Galley) |

Not verified here:

- real passkey ceremonies on physical devices;
- the clean copy of Mike's actual library, which needs his phone to approve the reader member;
- the Marginalia app cutover (a separate handoff, through its coordinator).
