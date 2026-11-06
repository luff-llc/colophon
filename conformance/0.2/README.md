# Colophon 0.2 conformance library

Every identity and entropy seed here is public test material. Never use them for real data.

`library/` contains exact signed records in their storage layout. `library.json` is the same
path-to-record map with standard base64 values, convenient for browser and Node fixtures.
`expected.json` contains the views, ledger, members, pre-revocation budget refusal and local
refusal outcomes. Both native Rust and the Node/WebCrypto wasm smoke test reproduce it.

Generate deterministically from the repository root:

```sh
COLOPHON_UPDATE_VECTORS=1 cargo test -p colophon-core --test conformance
cargo test -p colophon-core --test conformance
```

The generator is `crates/colophon-core/tests/conformance.rs`; shared host-driving helpers are
in `tests/support/mod.rs`. It performs I/O only in the test harness. Normal tests compare all
record bytes to the checked-in library, then open the persisted records and compare views and
ledger. Regeneration is deliberate; normal tests never update expectations.

`SoftwareKeys::from_seed([N; 32])` creates owner 1, device 2, app 3, agent 4, and recovered owner 5.
`SoftwareKeys::recovery([9; 32])` creates the separate recovery identity. The fixed host time is
`2026-11-04T12:00:00.000Z` (later authority actions use `12:01:00.000Z`). Action seeds 10–39 are
specified in the generator. The Node smoke derives the recovered owner's fixture keys with
WebCrypto HKDF and imports the fixed scalars as non-extractable CryptoKeys.

The scenario covers all three namespaces, a narrowed two-write agent grant, local and signed
out-of-scope refusals, budget exhaustion, AI attribution despite a false payload claim,
revocation with kept writes, a held unseen backdated write, epoch rotation excluding the agent,
and recovery of every data epoch followed by root replacement and another complete rotation.
The budget refusal is captured before revocation; after revocation the unkept backdated header
is held according to the precedence in the spec.

The fixture asserts generated outputs and replay equivalence. Independent protocol tests also
assert the invariants directly, including malformed signatures, chain failures, missing recovery
seals, wrong epochs, foreign requests, widened grants, stale edits, and planned handover ordering.

`reading.books/records.json` is an independent synthetic library (base64 signed records),
with bounded query answers in `reading.books/expected.json`. The fixture uses the public
software-key seed 5, exercises all ten books kinds, stale note resolution, rereads,
backwards position, tombstones, orphan rejection and invalid progress. The existing
library vectors are unchanged. The loan write currently produces the intentional
`authenticatedAppOrDeviceRequired` diagnostic because the engine's `OperationView`
does not expose member kind; authorized loan behavior is covered by domain tests.

Regenerate only this vector with:

```sh
COLOPHON_UPDATE_VECTORS=1 cargo test --test domain_books deterministic_books_vector
```

The existing `conformance` test target and the JavaScript smoke test both check these
exact query results from the saved record bytes. No source library data is included.
