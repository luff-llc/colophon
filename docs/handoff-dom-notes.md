# Notes domain handoff — 2026-11-06

Implemented in the `dom-notes` worktree, left uncommitted. No Git metadata was written.
No reducer trait, engine implementation, library admission code, dependency, or other domain
was changed. Stop point: this handoff. This is the domain implementation, not a claim that
end-to-end 0.1 migration or the engine integration requirements below are complete.

## Implementation

The implementation lives under `crates/colophon-core/src/domains/notes/`:

- `mod.rs`: serializable projection, reducer, authenticated-role integration seam, component
  heads, attributed candidates, tombstones, derived output currency and maintained indexes.
- `validation.rs`: all thirteen operation schemas, two preview aliases, and authoritative
  payload validation including UTF-8 byte bounds, Gregorian days, unique tags, SHA-256
  descriptors, source pointers, exact output alternatives and proposal input limits.
- `query.rs`: all ten specified queries, compatibility reads and diagnostic pages.
- `import.rs`: pure verified-source translator, identity/component mapping keys, evidence,
  pending blob writes and explicit missing-context dispositions.

`domain.rs` removes the old notes implementation and re-exports `Notes`/`NotesState` from
this module. Registration continues to use the same types and namespace. `lib.rs` exports
`domains`; `domains/mod.rs` exports `notes`. NotesState boxes its own projection so the
shared State enum need not change. Other workers can add their modules independently.

All thirteen clean kinds are implemented: createNotebook, renameNotebook, archiveNotebook,
putCell, resolveCell, moveCell, deleteCell, recordOutput, putEntry, resolveEntry,
addAttachment, proposeEntry and reviewProposal. Review semantics are tested through the
explicit role-aware entry point; the current engine path fails closed, as explained below.

Metadata, cell text, entry metadata, notebook order and proposal review heads remain separate.
Stale edits retain complete candidates with authenticated attribution, expected/found heads,
unknown fields and original command payload. Resolutions compare the head and exact observed
alternative set. Normal entry edits retain alternatives; explicit resolution clears the active
set, while the conflict audit remains. Tombstones retain the last cell, runs, alternatives and
late edits, including ownership when deletion precedes visible creation. No same-ID recovery.

Cell order is a maintained ordered index with variable-length integer positions, plus parent
and entry indexes; queries do not copy a notebook's entire order. End insertion reserves ample
integer space to avoid growing keys for normal append/prepend. Other indexes cover notebook
archive/touched order, entry touched order, assigned/unassigned materials, proposal parent/status,
source hashes and cached counts. Proposal currency is refreshed on affected entry-cell changes.
No execution, file I/O, blob fetch or permission expansion is performed.

Unknown payload fields merge into extensions only on effective mutations. A literal input
`extensions` stays nested. Blob, source-pointer and output-descriptor extras have their own
bags. Payload attribution cannot replace authenticated attribution.

## Queries and compatibility

The ten new queries are notebooks, notebook, entries, entry, cells, cell, attachments,
proposals, contentDetail and noteCounts. Success is `{revision, value}`. Domain failures are
JSON objects with `outcome` (`notFound`, `deleted`, `invalidArgument`, `staleCursor`, or the
additional `contentTooLarge`). The unchanged Library layer still wraps this value in its
existing Outcome; permission/key failures remain Library failures. SDK callers must inspect
this inner outcome before using value. Domain failures do not become empty collections.

Pages are `{rows, next, total}`. Defaults: cells 30, proposals/contentDetail 20, other pages 50;
maximum 100. Cursor strings bind notes, query, normalized filters, admitted-operation prefix
and last indexed key. Page size may change between pages. Unknown and invalid admitted kinds
also advance the domain prefix. These content-prefix revisions are deterministic strings,
not the engine's device-local revision counter. The engine continues to handle grants and
availability before invoking the reducer query.

Cell/markdown previews contain at most 240 Unicode scalar values and an explicit `truncated`
flag. Full cell input and full run/proposal retrieval are separate. `latestRun` is an immutable
run ID for contentDetail. The 1 MiB response cap shortens pages at row boundaries; an individual
oversize record returns contentTooLarge without modifying or truncating retained data.

Common hot pages use indexed ranges; single-object lookups use maps and counters are cached.
Explicit notebook title search scans the touched index with deterministic Unicode lowercase
matching. Entry touched order reflects effective entry metadata mutations. Proposal rows use ID
order. The conflicts query is a retained audit, including resolved candidates; noteCounts.conflicts
counts active cell/entry alternatives plus retained notebook/order/proposal conflicts and late
attempts. Late edits also have their own counter.

`addNote` and `editNote` remain wire/tool aliases for one markdown cell with an explicit
notebook. Add is create-only; edit requires an existing cell. Alias extras cannot become
canonical cell fields. Existing `read`, `note`, `notes` and the full view's `notes`/`text`
compatibility projection remain. `notes` retains offset/limit and the old items/nextOffset
shape. Compatibility reads are not bounded hot-path APIs. No playground source change was
needed. The JS smoke test now exercises cells/cell and the new signed notes vector.

## Pure 0.1 mapping

`import::translate(&VerifiedOperation, &ImportContext) -> Translation` has no I/O and does
not execute old code. The input retains kind/version, payload JSON, source library/author,
operation ID, author label, exact-signed-body SHA-256 digest, admitted order, claimed-date
representation, admission and actual source-fold disposition. A verified source reader must
supply that disposition: one payload cannot reveal whether a CAS was originally stale or
whether a proposal review was accepted. This additional context is required by the disposition
table, not a guessed reconstruction of 0.1 history.

All twelve 0.1 kinds are mapped and tested. Component heads and nested source references use
explicit persisted mappings. Missing mappings/context produce visible unresolved evidence.
Existing cell language/entry and entry metadata semantics use a complete effective source
value. Missing/self move anchors translate to top with the original retained in evidence;
ignored edit anchors are not used to move cells. Unsupported notebook kinds and oversized
sources remain evidence instead of invented types or truncated content.

Each input produces a manifest/evidence entry, including unknown kinds, malformed payloads,
legacy journal/preview kinds, invalid attempts, rejected admission, no-effect retries and
historical conflicts/late edits. Historical candidates carry separately labelled provenance;
new commands never claim to be signed by the old author. Commands include importSource and
stable child keys derived from the complete source tuple and transform version. Hosts bind
these keys to actual signed destination operation IDs after signing; they are not operation IDs.

Historical output strings over 1 KiB become content-addressed BlobWrite requests, keeping runs
well below the 256 KiB inline cap. Original MIME and exact UTF-8 text are retained. Malformed
source-skipped elements and invalid source digests stay evidence. Accessible legacy attachments
need a verified/re-sealed descriptor supplied by the host; unavailable attachments remain
explicitly unresolved. Library pointers map library, namespace, namespace-qualified artifact
identity and revision independently. No source access is implied by a pointer.

Accepted historical keeps need an app/device source reviewer and explicit confirmation that
translated inputs are current. Otherwise the contribution remains evidence pending repair.
Nonempty historical resolutions likewise wait for the destination conflict adapter's exact
materialized alternative set. They are never emitted as an unconditional edit.

## Exact engine/SDK integration requirements and deviations

1. **Authenticated reviewer kind.** OperationView exposes origin, not MemberKind. `person`
   cannot distinguish device/app from server. The engine must call
   `Notes::apply_with_member_kind(state, operation, Some(verified_kind))` for notes operations
   using authority-derived kind on every replay/suffix path, or extend its admitted-operation
   context equivalently. The existing Reducer::apply passes None; reviewProposal records
   authenticatedAppOrDeviceRequired and does not change status. Payload role claims are ignored.
   No trait or engine changes were made. The signed vector deliberately pins this current
   fail-closed behavior; role-aware tests cover acceptance, dismissal, retry and rejection.

2. **Encrypted import evidence and historical overlay.** Persist Translation.evidence and
   required BlobWrite bytes durably and atomically with child-key/output-ID bindings. Retain
   exact source envelopes in a read-only archive; parsed JSON plus a digest does not replace
   original bytes. Supply the common paged importEvidence query and historical:true overlays
   in conflict/detail UI. ImportContext.alternatives/projected_alternatives are the explicit
   resolution seam: an engine/SDK adapter must materialize/identify the imported candidates
   and make exact-set resolution and overlay invalidation agree. Without that adapter, a
   historical resolution with alternatives remains unresolved evidence. No unsigned legacy
   opcode or sidecar mutation has been added to the normal reducer.

3. **Source reader and import lifecycle.** The verified 0.1 reader must supply actual admission,
   actual fold outcome, complete effective values, verified pre-operation component heads,
   alternative sets and source order. Persist collision/lifecycle identity mappings and
   component revision mappings. After signing commands, check their destination outcomes;
   native 0.2 changes can cause intentional CAS alternatives. Catch-up must compare complete
   source tuples/outcomes, not rerun an unconditional snapshot import. Source archive verification,
   catch-up orchestration and a live Swift-reader comparison are outside this pure translator.

4. **Blob adapter and oversized retained content.** Validate digest/size/media type after host
   storage/re-sealing and report available/missing/inaccessible/invalid separately. The reducer
   handles descriptors only. Large sources above 256 KiB stay evidence until a source-blob editor
   contract exists. Arbitrarily large extension/descriptor records can return contentTooLarge;
   a host/engine lazy-content or streaming retrieval path is still required for these retained
   records. No retained original is replaced with an empty file or disposable cache.

5. **Local preflight validation.** Generated schemas include enums, nullability, cardinality,
   one-of descriptors, formats and byte-limit annotations. The existing shared schema evaluator
   implements only a subset. Every received operation is fully checked by validate_payload
   before indexes change, but some domain-invalid local writes can currently be signed and then
   appear in invalid diagnostics. The engine should call notes::validate_payload at local
   begin_write/begin_call preflight or implement the remaining schema constraints. Do not alter
   the ledger/admission treatment of already signed domain-invalid history.

6. **Checkpoint format coordination.** NotesState requires the new format/projection fields,
   so an old flat-note snapshot cannot deserialize and restore falls back to replay. The engine
   worker must nevertheless bump the global checkpoint version, or introduce a checked per-domain
   schema version, when integrating this semantic change. Future historical overlays must be
   bound into checkpoint validity and query revisions. The engine's current version constant
   was intentionally not edited in this worktree.

These are integration gaps, not permission requests. In particular, default-engine proposal
review and end-to-end historical conflict migration are not production-complete until the
corresponding seams above are connected.

## Conformance and checks

`tests/domain_notes.rs` generates `conformance/0.3/notes.json`: deterministic signed records
plus expected queries covering every named query and all thirteen kinds (including the current
review role diagnostic), tombstones, late edits, output currency, conflicts, resolutions,
archive filtering and nested extras. The existing conformance test independently replays the
checked-in bytes and checks the query results. JS smoke verifies exact WASM parity for the same
vector. The fixture identity seed is public synthetic test material.

Only the notes portions of `conformance/0.3/expected.json` were regenerated: the old preview
notes now have markdown-cell fields and notebooks expose archive/kind/touched/order metadata.
Original library.json and signed library record bytes are unchanged. Other namespaces' expected
results and the ledger are unchanged.

All required checks passed on the final code:

```sh
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
export CARGO_HOME=/Users/mikelxc/projects/colophon-wt/.cargo-shared
export CARGO_TARGET_DIR=/Users/mikelxc/projects/colophon-wt/.target-domains
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
npm --prefix js ci
npm --prefix js run build
npm --prefix js test
git diff --check
```

44 Rust tests passed, with one additional 100k shape test ignored by default and explicitly run
successfully. Notes contributes 16 regular tests and that shape test. Coverage includes all
source kinds and their invalid/rejected/conflict dispositions, deterministic random reducer
orders, serialized state continuation, signed reverse arrival compared with fresh replay,
checkpoint suffix replay, every collection's paging, stale cursors, role fences, nullable fields,
immutable retries, UTF-8 boundaries, nested pointer maps, unavailable blobs and oversize results.

Explicit large-shape command:

```sh
cargo test -p colophon-core --test domain_notes indexed_hundred_thousand_cell_notebook -- --ignored --nocapture
```

Observed in a debug build: 100k-cell projection 7.541 s; two indexed 30-row pages plus counts
2.065 ms. This is a synthetic reducer-only measurement, not a signed-library rebuild, release
benchmark, peak-memory measurement or iPhone proof. The large test is opt-in to avoid repeated
load in the shared target directory. Worst-case adversarial ordering/key growth, very large
proposal sets, real Swift projection parity, host blob durability and mobile performance remain
unmeasured gates.

The JS build script hardcodes `target/` for wasm-bindgen input. A temporary local `target`
symlink to CARGO_TARGET_DIR was used for the successful build/test and removed afterward;
recreate that symlink when repeating the build with this shared target configuration. No
shared caches or other workers' artifacts were deleted. Generated JS output remains ignored.

Vector regeneration commands used deliberately:

```sh
COLOPHON_UPDATE_VECTORS=1 cargo test -p colophon-core --test domain_notes deterministic_notes_conformance_vector
COLOPHON_UPDATE_VECTORS=1 cargo test -p colophon-core --test conformance
```

## Intended commits

1. Implement the notes notebook, cell and entry reducer with bounded indexed queries
2. Add verified notes import mappings and immutable migration evidence interfaces
3. Add signed notes conformance vectors and Rust/WASM regression coverage
4. Document notes engine integration requirements and validation results

No commits were created. Suggested trailer: `Co-Authored-By: Codex <noreply@openai.com>`.

## Engine3 follow-up — November 6, 2026

The engine-facing storage and authenticated-context requests above are superseded by the
[engine3 API contract](engine.md#engine3-authenticated-import-storage-and-blobs) and
[engine3 validation handoff](handoff-engine3.md). Root-signed encrypted batches now bind evidence,
virtual output revisions, reservations and manifests atomically. Historical alternatives and
prefix reconciliation remain separate from effective native state. The Swift migration reader
uses synchronized evidence; unsupported source codecs, automatic correction/UI, typed collision
remapping in that orchestrator, source/anchor verification and real platform acceptance remain
explicit host/app work. Earlier validation counts describe the earlier handoff, not engine3.
