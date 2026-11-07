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
- Deterministic `conformance/0.3/` records and expected output; native and wasm replay parity.
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

Initial milestone passed: 12 Rust tests (2 crypto, 9 protocol/domain, 1 conformance), Clippy with warnings denied
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

The review-fix commit attempt failed because Git could not create
`/Users/mikelxc/projects/colophon/.git/worktrees/core/index.lock` (`Operation not permitted`).
All review fixes remain uncommitted, as requested when Git cannot write. Nothing was pushed.
The worktree was clean at the start of this review pass.

Intended separate commit subjects, in review-finding order:

1. Prevent hostile headers from poisoning namespace write clocks
2. Preserve authenticated records across invalid duplicate IDs
3. Round-trip fractional payloads when deriving operation IDs
4. Isolate domain extensions from controlled state
5. Compare and clear temporary ECDH secrets
6. Interleave ledger writes with authority history
7. Tell the library ledger story in plain English
8. Expose authenticated ledger grouping metadata

Each commit should end with `Co-Authored-By: Codex <noreply@openai.com>`.

## Review fixes (November 4)

1. Write clocks now use only admitted, authenticated content. Known scope, expiry and revocation
   precede future-authority holding; admitted headers have a 1,024-step forward-jump bound.
   The hostile-header regression failed before the fix and passes afterward. Spec §5 updated.
2. `kept` now binds full SHA-256 signed-body digests of authenticated operations. Invalid
   copies cannot disqualify originals or spend extra duplicate-ID budget slots. The regression
   failed before the fix, including an earlier-clock duplicate, and passes after it. Authority
   records and conformance expectations were regenerated for this wire-rule change.
3. Enabled `float_roundtrip` on the unchanged serde_json =1.0.145 pin. Both reported fractional
   values now survive writing and replay with their IDs intact; the new regression failed
   before the feature was enabled. Spec §2 defines canonical number encoding.
4. All three modules now project only each kind's defined fields. Unknown fields live in
   `extensions`, including attempted playback, tombstone and attribution overrides. Command
   controls are not persisted as state. The new cross-module regression failed on playback
   overwrite before the fix; existing extension tests now assert the bag shape. Spec §6 and
   conformance projections were updated.
5. WebCrypto key-pair validation compares every ECDH byte with XOR accumulation and clears
   both temporary buffers in `finally`, including mismatch and partial-failure paths. The new
   JS regression observed the original early exit and now checks full reads plus zeroization.
6. Ledger authority and operations now interleave by cited authority, with `(created, author,
   id)` display order inside each sequence and requests before their grants. Dates normalize
   equivalent UTC encodings. The story-order regression failed before the fix and now also
   checks replay after operations arrive before authority. Spec §6 updated.
7. Ledger copy now comes from module display names and kind phrases, uses plain English and
   present tense for standing facts, counts distinct preserved contributions, and combines
   each rotation into one rekey summary. Creation describes sealing instead of epoch-one lines.
   The wording regression failed before the rewrite. Existing grant semantics are unchanged:
   access applies uniformly to every listed namespace, so text accurately says “read and write
   listening and notes” for that scope. Spec §6 documents this boundary.
8. `LedgerEntry` exposes optional `namespace`, `kind` and authenticated `origin` on write
   entries in Rust, TypeScript and docs/js-api.md. Locked content omits kind. The grouping
   regression failed before these fields existed and checks that payload attribution cannot
   spoof them. Ledger conformance expectations were regenerated for ordering, copy and fields.

## Review validation

Each of the eight review findings has a regression that was observed failing before its fix:
seven new Rust protocol tests and a JavaScript key-validation regression. Rust now runs 19 tests
(16 protocol/domain, two crypto, one conformance). The JavaScript smoke additionally writes and
replays both reported fractional values and checks the ledger grouping fields through WASM.

Passed after the fixes:

```sh
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
npm --prefix js run build
npm --prefix js test
```

Regenerated `conformance/0.3/`: revoke/recovery kept digests changed authority records 6–8 and
the aggregate record map; extension projections and ledger ordering, wording and metadata
changed expected output. Operation record bytes and all 0.1 vectors remain unchanged.
