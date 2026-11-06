# Domains integration handoff

## Merge dom-reading.saved — 2026-11-06

Resolved all five conflicted files in the working tree. `domains/mod.rs` exports books,
notes and saved; `domain.rs` retains all four namespaces, state constructors, reducer/query
dispatch and module/tool registration, with both books and saved validation hooks. The existing
`lib.rs` public `domains` export already exposes the combined modules and needed no change.
Kept `Saved(Box<SavedState>)` to contain the larger saved projection; books remains inline and
notes retains its internally boxed projection. Removed the shared `create` helper after both
preview reducers stopped using it, fixing the integration's only Clippy error.

`tests/conformance.rs` retains every test from both parents, including separate books, notes
and saved fixture checks. `js/scripts/smoke.mjs` retains all three domain fixtures and existing
checks, including saved's `getPosition` query alias. The conformance README preserves books
and saved descriptions and now also describes notes. Retained saved's deletion precondition
in the protocol test and the JS build's `CARGO_TARGET_DIR` support.

No vector regeneration was necessary: the merged `expected.json` already combines notes and
saved projections, and the shared ledger and signed-record comparisons pass unchanged.
Existing domain handoffs and their integration limitations remain intact.

Final checks passed with the supplied Rust PATH, CARGO_HOME and CARGO_TARGET_DIR:

- `cargo test`: 83 passed; the existing opt-in notes 100k shape test remains ignored.
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- `npm --prefix js ci && npm --prefix js run build && npm --prefix js test`
- `git diff --check`, conflict-marker scan, and conformance-test preservation check.

No Git-writing command was run. Resolved files remain in the working tree; Git's index still
reports unmerged paths because staging/merge completion was intentionally left untouched.
