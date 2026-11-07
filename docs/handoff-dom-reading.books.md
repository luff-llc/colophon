# reading.books domain handoff

Implemented in the `dom-reading.books` worktree on 2026-11-06. Changes are uncommitted.
The reducer trait, engine internals, protocol wire types, existing domain implementations,
and existing signed conformance libraries were not changed. There was no books preview to move.

The domain implementation is complete for the interfaces available here, with the integration
limitations below. In particular, **the current Library path cannot apply setCopyLoan**:
it deliberately records an `authenticatedAppOrDeviceRequired` diagnostic until the engine
supplies authenticated member kind. This is not a claim that the migration or app rollout
acceptance gates are complete.

## Implementation

`crates/colophon-core/src/domains/books/` contains:

- `mod.rs`: `ReadingBooks`, serializable `BooksState`, all ten reducers, component heads,
  permanent book/note tombstones, retained readings, attributed alternatives, exact observed
  note resolution, signer-scoped loan receipts, and maintained indexes/counts.
- `specs.rs`: all ten operation specifications and strict validation, including UTF-8 byte
  limits, interoperable integers, IDs, Gregorian days, statuses, nullable fields, and sorted
  unique resolution sets. Unknown properties remain extensions; a property named
  `extensions` remains nested. Authenticated attribution cannot be overwritten.
- `query.rs`: all eight specified queries, plus compatibility `read` and paged `invalid`.
  Book ordering follows immutable addition order, notes support both creation orders, and
  readings are newest first. Metadata, plan, progress, loan, and activity heads are separate.
  Effective note mutations advance the parent activity head; stale attempts do not.
- `import.rs`: a pure verified-source transform and serializable identity/head/idempotency
  state, proposed commands, evidence manifests, and destination-ID binding helpers.

The minimal shared additions are module exports, namespace/state registration, and a dispatch
hook in the existing tool-input validator for schemas carrying `x-colophon-books-kind`.
That hook is needed because the existing schema subset does not enforce nullable unions,
enums, byte limits, or calendar dates. Operation schemas also advertise
`x-colophon-member-kinds`; the current engine does not yet consume that role annotation.
No aliases or playground changes were needed. The JS smoke change only adds books checks.

Exact logical add retries preserve the original occurrence and revision. Other duplicate IDs
become conflicts. Deleted occurrences cannot resurrect. Children of deleted books remain in
history and return `deleted` through ordinary detail queries. Successful note resolution
clears precisely the observed active alternatives and retains the conflict audit rows with
`resolved:true`; unresolved rows carry `resolved:false`. Book conflict counts include child
note conflicts. The namespace conflict count includes retained unresolved tombstone conflicts.

## Queries and bounds

Successful domain queries return `{revision, value}`. Pages are `{rows, next, total}`, with
limit 50 by default and maximum 100. Cursors bind namespace, query, normalized arguments
(including limit), position/order key, and prefix revision. Changed prefixes return
`staleCursor`; malformed or mismatched cursors return `invalidArgument`.

ID lookups use maps; shelf pages use maintained all/status/year/combined status-year ordered
sets, notes use parent/order sets, catalog membership uses key-to-ID sets, and counts are
maintained on mutations. Pages range from their cursor rather than sorting the entire shelf.
Search is a deterministic lowercase substring scan of the selected index over title, creator,
and ISBN; no inverted title/content search index is supplied. Finished-year headings put the
undated group first, followed by descending numeric years. This is a provisional choice for
the specification's open ordering question.

Notes rows preview at most 512 UTF-8 bytes per text/quote, on scalar boundaries, with
`truncated:true`; `note(id)` retrieves the editor value. The `note` member of that editor value
contains authenticated attribution, with text, quote, location, and parent as siblings, avoiding
duplication of up to 512 KiB of text. Alternatives are retrieved separately through `conflicts`.
If a book and note share the same category-scoped ID, `conflicts(object)` includes both histories;
component names distinguish the candidates, since the specified query has no category argument.

Collection pages are also bounded by serialized size. Catalog results return at most 100 IDs
per key and may return fewer to stay within the response budget; `total` and `truncated` make
that explicit. Large conflict candidates become retrieval descriptors naming the operation,
while retaining their attributed conflict metadata. Ordinary query responses cap at 1 MiB.
A single value that cannot fit returns `unavailable` with `detail:responseTooLarge` and an
explicit host-adapter requirement. Compatibility `read` is intentionally a full export.

Additional defensive limits not explicitly assigned in the compact domain table are 4 KiB for
ISBN/catalog keys/search strings, 256 KiB for loan reflection, and query years 1–9999. These
keep metadata queries bounded and match the representable calendar-day range. They are
published in schemas; stricter imported values remain evidence rather than being clamped.

## Pure 0.1 import contract

Call `transform(&ImportState, &SourceOperation)` in verified source fold order. The source
input includes library, author ID/label, operation ID, exact signed-body SHA-256, kind/version,
original payload/date representation, admission disposition, and admitted order. Verification
itself belongs to the existing 0.1 reader. Non-admitted/unverified/unreadable history produces
unresolved evidence only. Legacy-journal/unknown kinds require their separate adapter.
The old fold did not inspect version, so an admitted old books kind is interpreted using its
actual old fold even when its version is not 1; the version remains in evidence.

Before initial import, use `reserve_destination_ids` for existing destination books/notes,
including tombstones. Preserve unambiguous source IDs; collisions, illegal clean IDs, and
remove/recreate occurrences receive deterministic IDs from framed source identity and the
creation signed-body digest. References use these maps. No title or catalog matching occurs.

Each emitted command has a stable output key and child index, and carries `importSource`
as explicitly historical provenance. These output keys are **not signed operation IDs**.
Sign commands sequentially as the importer and call `ImportResult::bind_output` after each
successful destination effect. It updates remaining command expectations, persisted component
maps, and manifest output-operation-ID receipts. Persist all evidence and identity/head maps.
Do not treat a merely signed but conflicted/invalid destination write as an imported baseline.

The mapping covers every old opcode:

- Adds map creator/year/catalog fields, preserve unknown extras (including synthetic Booklist
  shapes), and record ineffective duplicates. Extras that collide with new command fields are
  kept in a nested `legacyExtras` bag rather than accidentally becoming controlled fields.
- Edits translate actual typed changes and merged extras, ignore old ISBN edits as the old
  fold did, and never treat an old edit's extra `expect` as CAS. Typed copyLoan values can emit
  a second `setCopyLoan`. Untyped values remain extra JSON/evidence. A typed `needsReturn`
  without the optional old request ID gets a deterministic import receipt ID; original data
  remains in its historical proposal. Import never claims another person's confirmation.
- Removal uses the imported activity head, retains history, and closes source child lifecycles.
  A later book/note reuse is a distinct destination occurrence.
- Plans translate the separate plan head, emit explicit null dates for old clearing behavior,
  retain ignored intent, and leave stale/unknown-status/invalid-date plans as evidence.
- Progress preserves old backwards reports, explicitly clears absent page, and retains invalid
  historical numerics without clamping. Metadata extras named fraction/page cannot alter the
  source fold's actual progress.
- Notes require a real clean parent. Orphans remain pending; when a matching source parent
  becomes available, their effective history materializes with original source attribution and
  creation ordering. Removal before parent availability closes the pending occurrence.
- Stale edits/resolutions retain full source attribution as historical alternatives. Effective
  edits translate the text head. Effective resolutions record the exact reviewed historical
  evidence keys in `resolvesEvidence`/`importReviewedAlternatives`; native `resolves` is empty
  because those historical alternatives are not native 0.2 conflict revisions.

Every first-seen source tuple gets a manifest disposition and original parsed payload; delayed
materialization adds linking evidence instead of discarding the earlier pending disposition.
Exact source envelopes must remain in the read-only archive. Catch-up is idempotent by the full
source tuple plus transform version, not by a highest clock. Admission changes require a fresh
source-prefix evaluation and reconciliation with prior effects, as described below.

## Required engine and host integration

1. **Authenticated role delivery.** Pass verified `MemberKind` into
   `ReadingBooks::apply_with_member_kind(state, operation, Some(kind))` on both append and
   replay. Only App/Device may apply loans. Do not infer Device from `origin:person`, which
   also includes Server. Use the same authenticated role fence before signing and in tool
   filtering. The existing `Reducer::apply` calls this seam with `None` and fails closed for
   loans. Bump/invalidate books checkpoint semantics when enabling this path, then regenerate
   the books vector's loan outcome. Other domain checkpoint schemas are unchanged here.

2. **Prefix identity, versions, and outcomes.** The current domain token is a deterministic
   rolling hash of authenticated OperationViews, including unknown/invalid domain attempts.
   Supply the engine's admitted signed-body-prefix digest as the authoritative query revision
   when that interface exists. The current trait exposes neither that digest nor operation
   version. The existing engine rejects non-v1 plaintext as invalidPayload; the proposed shared
   contract instead needs retained/skipped unknown versions. Preserve the version and implement
   that decision before dispatch. Domain failures currently travel as `{ok:false,reason,...}`
   inside the existing Library `Outcome::Success` value; lift them into the unified typed query
   outcome in the SDK/engine. Authorization/key failures still use the existing outer outcome.

3. **Durable historical evidence.** Persist `ImportEvidence`, output receipts, and exact source
   archives as encrypted user data under destination access rules. Provide the shared bounded
   `importEvidence(sourceLibrary?, namespace?, object?, cursor?, limit?)` stream and historical
   conflict overlays with `historical:true`. Overlay resolution must honor the reviewed evidence
   keys without pretending they are native operation revisions or old authors' new signatures.
   The normal domain conflict query currently returns native conflicts only. These sidecar data
   structures are implemented; persistence, historical query union, and resolution linking are
   host/SDK responsibilities and are not silently emulated as new legacy opcodes.

4. **Native-aware catch-up.** Compare source replay outcomes and last imported component heads
   against destination heads before emitting catch-up effects. Preserve native edits and changed
   source outcomes as explicit reconciliation alternatives. The pure adapter is a sequential
   baseline transform, not an orchestrator for destination races. In particular, `position` has
   no CAS field in the proposed schema: an engine/host conditional-import facility is needed
   before a late historical progress report can safely coexist with native progress. Do not
   append it unconditionally during catch-up, and do not smuggle an ignored `expect` extension
   into that command. The host must retain unresolved dispositions when this check cannot be made.

5. **Large content retrieval.** Provide an authorized operation/content retrieval adapter for
   truncated conflict candidates and oversized detail extensions. The emitted operation locator
   is a domain-side interface placeholder, not a claim that a blob exists. If using the proposed
   blob descriptors, supply digest/size/media type plus verified availability, encryption, and
   storage resolution in the host. The domain stores catalog references and arbitrary extension
   descriptors; it neither decodes cover bytes nor implements a blob transport.

## Conformance, checks, and remaining proof gaps

`conformance/0.3/reading.books/{records,expected}.json` is a separate 36 KiB synthetic vector.
It contains signed records and expected bounded query results, exercises all ten kinds, and
records the current fail-closed loan outcome. `tests/support/books.rs` supplies its shared
scenario. `domain_books.rs` generates it; the existing `conformance` target checks it; the JS
smoke test replays the same bytes through WASM and compares every query. Existing vectors were
not regenerated or changed. No real-library records or private Booklist data were used.

Regeneration command used only for the new vector:

```sh
COLOPHON_UPDATE_VECTORS=1 cargo test --test domain_books deterministic_books_vector
```

Final checks passed:

```sh
cargo test                                      # 47 tests, including 19 books tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
npm --prefix js ci
npm --prefix js run build
npm --prefix js test
git diff --check
```

Cargo used `/opt/homebrew/opt/rustup/bin`, the supplied shared CARGO_HOME, and shared
CARGO_TARGET_DIR. The existing JS build script hardcodes `target/wasm32-unknown-unknown`;
an ignored local directory/symlink at that path points to the shared WASM target, avoiding a
second build tree without changing the shared build script. No tracked target symlink remains.

Tests cover fixed-seed randomized incremental/full replay and serialized-state restoration;
reverse signed-record arrival and engine checkpoints; component expectations; exact note
resolution; tombstones and parent visibility/activity; loan role fences and signer receipts;
validation boundaries; paging/filter/count/catalog behavior; bounded large text and conflicts;
all nine source kinds, malformed and rejected histories, stale imports, lifecycles, orphans,
collisions, and output binding. A 100,000-operation reducer scenario over 100 books verifies
bounded hot pages and a serialized state under 300 KiB.

That scale test is not a signed 100k-library latency benchmark. No iPhone measurements, true
cold-open target, complete source Swift parity run, real-library migration, encrypted evidence
storage, historical overlay integration, or native-aware catch-up race proof was performed.
Those remain rollout gates; this work adds no claims about engine performance improvements.

## Intended commits

1. `feat(core): add reading.books reducers, indexed queries, and generated tools`
2. `feat(books): transform verified 0.1 history with lifecycle maps and import evidence`
3. `test(books): add replay, import, conformance, and Rust/WASM parity coverage`
4. `docs(books): record domain behavior and engine integration requirements`

No commits were created. Work stopped after writing this handoff, as requested.

## Engine3 follow-up — November 6, 2026

The engine-facing storage and authenticated-context requests above are superseded by the
[engine3 API contract](engine.md#engine3-authenticated-import-storage-and-blobs) and
[engine3 validation handoff](handoff-engine3.md). Root-signed encrypted batches now bind evidence,
virtual output revisions, reservations and manifests atomically. Historical alternatives and
prefix reconciliation remain separate from effective native state. The Swift migration reader
uses synchronized evidence; unsupported source codecs, automatic correction/UI, typed collision
remapping in that orchestrator, source/anchor verification and real platform acceptance remain
explicit host/app work. Earlier validation counts describe the earlier handoff, not engine3.
