# Colophon 0.4

**Status: interface frozen as v1 on 2026-11-08; implementation and integration complete; final
freeze (S6) awaits Mike's sign-off and the open deviation below.** The normative implementation is `crates/colophon-core`.
`conformance/0.4/` contains its reproducible vectors. 0.4 is a clean break from 0.3's
authority: no 0.1 or 0.3 authority record is interpreted. Older libraries move to 0.4 by
clean copy (`docs/clean-copy.md`).

Colophon 0.4 is [Colophon 0.3](colophon-0.3.md) with its key and authority model replaced by
[**keys and the keyring**](colophon-0.4-keys.md):

| 0.3 | Replaced by (0.4 keys spec) |
| --- | --- |
| §2 Records and identity: private-key steps | §2 Parsing and keys, §3 Authority signatures |
| §3 Namespace encryption: who epochs are sealed to | §5 Vault and slots (epochs sealed to the vault and members) |
| §4 Storage and authority: root, recovery, handover, recover | §4 Controllers and the keyring, §6 Authority, §7 Members |
| §7.2 The root-only `colophon.importBatch` | §7 `grant.import` |

Everything else in 0.3 is unchanged and normative for 0.4:

- canonical bytes;
- member identities, requests, grants and member kinds;
- HPKE epochs;
- operations, admission and live state;
- modules, views and tools;
- blobs;
- the HTTP exchange.

Operation and request markers stay `/3`, and authority bodies use `colophon/authority/4`.

## What a library is in 0.4

- **A keyring of controllers holds authority.** Controllers are passkeys, security keys,
  device owner keys and recovery kits, each with roles (`approve`, `control`, `recover`) and
  thresholds. No single key is the library.
- **Members write content.** Apps, devices and agents are members with grants. Controllers
  aren't members, and no key serves two principals. Agents can never hold authority.
- **A vault receives every epoch.** Its seed opens through slots: sealed to a device or kit,
  wrapped by a passkey's PRF output, or combined, needing several keys at once.
- **Passkeys authorize; device keys work.** A passkey signs keyring changes, approvals and
  recovery as a WebAuthn assertion. Device and member keys sign everything else without a
  prompt.

## Freeze record

- **Specification:** two independent review rounds (Codex, agy) with every finding resolved
  (`colophon-0.4-keys-review-*.md`).
- **Conformance:** 98 key cases plus a complete library fixture, covering every §10 bullet with
  named outcomes and cryptographic intermediates.
- **Implementation review:** an independent read-only Codex security review. Its two
  medium findings were fixed with regression tests (`tests/route_binding.rs`), and its final
  pass reported "Ready to ship: yes".
- **Platforms:** the same flows pass through Rust, Swift (`ColophonKit`, sessions and
  `ColophonKeys`), Kotlin and Android, and JavaScript/WASM, with identical records.

- **Performance:** WebAuthn verification is about 0.22 ms per signature (budget 1 ms). Cold
  replay of a 200-entry, 20-controller keyring is about 55 ms, against a 20 ms budget. It's
  dominated by pure-Rust P-256 verification, and is recorded as **deviation D-F2-1** in Galley's
  register. Opens through the verified-prefix cache stay incremental.

The interface is frozen: changes need a new spec revision, never a quiet patch.
