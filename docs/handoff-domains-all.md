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

## Merge dom-listening.podcasts — 2026-11-06

Resolved all four conflicted files: `domain.rs` now delegates to the dedicated podcast
module alongside books, saved and notes; `domains/mod.rs` exports all four modules;
`tests/conformance.rs` and `js/scripts/smoke.mjs` retain both parents' checks and podcast
query aliases. All 100 Rust test functions and every JS smoke assertion from both parents
are preserved. Removed obsolete preview reducers and their now-unused shared helpers.

Kept all four namespaces, constructors, apply/query dispatch, generated tool/spec registration,
and the books/saved validation hooks. The existing public `lib.rs` domains export needs no
change. Saved and podcasts use boxed state variants; books is now boxed too because it became
the sole large enum variant after podcast integration, triggering Clippy. Notes retains its
internally boxed projection. Boxing preserves serialized state shapes. The root and conformance
READMEs describe all four domains; each original domain handoff and its integration gaps survives.

No vector regeneration was necessary. The incoming shared `expected.json` already combines the
new podcast projection with notes and saved; comparison against HEAD confirms all other views
and the shared ledger are unchanged. Signed-record and native/WASM fixture comparisons pass.
Kept the incoming protocol assertion for the retained passive-playback-regression conflict.

Final checks passed using the supplied Rust PATH, CARGO_HOME and CARGO_TARGET_DIR:

- `cargo test`: 99 passed, 0 failed; the existing opt-in notes scale test remains ignored.
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- `npm --prefix js ci && npm --prefix js run build && npm --prefix js test`
- `git diff HEAD --check`, tracked-file conflict-marker scan, and test-preservation checks.

No Git-writing commands were run. Resolved files remain in the working tree; the index still
reports unmerged paths because staging and merge completion require Git metadata writes.
