# Changelog

## 0.4.0 — 2026-11-08

**Keys and the keyring.** A clean break from 0.3's authority: no 0.1 or 0.3 authority record is
interpreted. Older libraries move to 0.4 by clean copy. Spec: [colophon-0.4.md](spec/colophon-0.4.md),
[colophon-0.4-keys.md](spec/colophon-0.4-keys.md).

### Protocol

- A keyring of controllers replaces the root and the recovery identity. Controllers are
  passkeys, security keys, device owner keys and recovery kits, with `approve`, `control`
  and `recover` roles, a control threshold and a recovery threshold.
- Authority records carry `raw` or `webauthn` signatures and cosignatures. WebAuthn checks are
  exact: challenge, origin (with an allowlist for Android app origins), RP hash, flags, strict
  DER, and high-S accepted.
- Epochs are sealed to a vault, which opens through `sealed`, `prf` or `combined` slots. New
  PRF routes are built only from a credential-restricted assertion, and are bound to the
  published descriptors.
- Recovery only adds. It can't manufacture control below the control threshold.
- Removing a controller, demoting one, or changing its agreement key or slots rotates the vault.
- Controllers aren't members, and no key serves two principals. Agents can never hold authority.
- The root import role becomes an expiring `grant.import`.
- `reshare`, `handover` and `recover` are removed.

### SDK

- **Rust core:** `keys`, `vault` and `slots` modules; authority 4; keyring actions; WebAuthn
  registration parsing.
- **FFI and WASM:** the full key surface, including `begin_create_with` with a recovery kit in
  genesis and `importedFrom`.
- **Swift:** sessions with a separate owner controller and member, kit restore, and the new
  `ColophonKeys` product (passkeys, security keys and Secure Enclave owner keys).
- **Kotlin and Android:** the same session model, Credential Manager passkeys and Keystore
  owner keys.
- **JavaScript:** `Library.createWith`, WebAuthn and WebCrypto providers, and the playground
  on 0.4.
- **Clean copy:** `colophon-clean-copy` in `reference/swift`. It reads an old library as a
  member, without its root; imports into a fresh 0.4 library; and verifies by accounting plus
  an independent reference import.

### Conformance and review

- `conformance/0.4/`: 98 key cases and a complete library fixture.
- Two specification review rounds and an independent implementation security review. Two
  medium findings were fixed, and the final pass reported "Ready to ship: yes".
- Known deviation D-F2-1: a cold 200-entry keyring replay takes about 55 ms, against a 20 ms
  budget.

### Fixes along the way

- The Apple build script no longer leaks deployment-target variables into host proc-macro
  links (which broke on macOS 27), and builds each slice in its own target directory.
- Swift sessions serialize blob scans with refreshes, which fixes intermittent `notReady`.
- Android sessions compute kept digests from the full snapshot on revocation, and keep the
  original engine until rejoin succeeds.
