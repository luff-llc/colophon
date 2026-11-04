# Core 0.2 handoff

Implemented on branch `core`, entirely in this worktree. Swift sources and 0.1 vectors were not
modified. Nothing was pushed or published.

## Completed

- Exact-pinned Rust workspace: pure `colophon-core` and `colophon-wasm` 0.2.0; wasm-bindgen
  crate and CLI match at 0.2.130. No getrandom dependency or implicit entropy in the core.
- Stored-byte signature verification, canonical writing, P-256 identities, explicit host
  signing/ECDH steps, software/recovery identities, and RFC 9180-tested HPKE.
- Verified authority, pairing requests, narrowed grants, grant-wide budgets, kept revocations,
  atomic rekeying, historical-key handover, and recovery of authority plus every data epoch.
  Root replacement also rotates all namespaces, excluding the former root.
- Signed encrypted operations, admitted/held/refused evidence, authenticated AI attribution,
  all three clean domain modules, unknown-field preservation, specs, tools, and ledger.
- Deterministic `conformance/0.2/` records and expected output; native and wasm replay parity.
- `@colophon/core`, tsc-only build, non-extractable WebCrypto providers, Node 24 smoke,
  protocol spec, dependency documentation, and six portable-core lessons.

## Build and verification

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
cargo test
cargo clippy -- -D warnings
cargo build -p colophon-core --target wasm32-unknown-unknown
npm ci --prefix js
npm --prefix js run build
npm --prefix js test
```

Passed: 12 Rust tests (2 crypto, 9 protocol/domain, 1 conformance), Clippy with warnings denied
(including `--workspace --all-targets`), wasm32 core build, release wasm build, TypeScript
compilation, Node 24.12.0 smoke and fixed-fixture parity, `cargo fmt --check`, and public API
documentation builds. Both crates deny missing public docs and forbid unsafe code. Source checks
found no `unwrap()`, I/O, clocks or OS RNG calls in core/bindings sources. `js/dist/` was built;
build artifacts and caches are ignored.

## Integration notes and remaining boundaries

- Existing JavaScript names and outcome shapes are preserved. Tools retain namespace dots:
  `reading.saved__capture`, `listening.podcasts__episode`, `notes__addNote`.
- After synchronous `merge(records)`, await the additive `ready()` before reading newly shared
  keys. Revocation takes effect synchronously. Async write/approve/call open keys themselves.
- Persist the creation-time `recoveryKeys` independently, or supply a recovery provider to
  `create`. CryptoKey handles can be structured-cloned; private key export remains disabled.
- One immutable grant per member identity is supported; regranting, delegation, recovery-key
  rotation, WebAuthn/keyrings, checkpoints, native FFI and CLI/MCP transports remain follow-ups.
  Storage, sync, authority-fork resolution and globally fresh budget enforcement belong to hosts.
- Signed header reservations count toward write budgets even if their encrypted content cannot
  be opened; invalid content never folds. Expiry cannot prove an author's wall-clock claim.
- Verification exercised Node WebCrypto and wasm compilation, not a real browser UI or mobile
  hardware keystore. No playground files were modified.

## Commit restriction

The first milestone commit was blocked: the linked worktree's Git metadata is outside the
sandbox's writable roots, so Git could not create `index.lock`. No approval escalation is
available in this session. All changes therefore remain uncommitted for the coordinator.

Suggested descriptive commit groups, in dependency order:

1. Add pure Rust protocol engine and wasm host steps (workspace manifests, lockfile, crate sources).
2. Add deterministic conformance and adversarial protocol tests (tests and 0.2 vectors).
3. Add WebCrypto TypeScript package and cross-runtime smoke (js).
4. Document Colophon 0.2 and core integration (README, spec and docs).

End each commit message with:

```
Co-Authored-By: Codex <noreply@openai.com>
```
