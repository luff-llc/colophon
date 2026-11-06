# reading.saved domain handoff

Implemented in the `dom-reading.saved` worktree, November 6, 2026. Changes are uncommitted.
No Git writes, commits, pushes, Cloudflare actions, dependency additions, reducer-trait changes,
or engine-internal changes were made. This implements the domain surface and a conservative
import boundary; the integration and performance gaps below remain acceptance work.

## Implementation

The implementation lives in `crates/colophon-core/src/domains/saved/`:

- `mod.rs`: serializable projection, independent state/metadata/source/position/activity heads,
  permanent item and annotation/view tombstones, retained alternatives, immutable source and
  metadata records, annotation/view/visibility/connection DAGs, dependency reverse edges,
  atomic tags, feed windows, review history and undo, answers, subscriptions and browser
  checkpoints. All 24 proposed command names are registered.
- `validate.rs` and `specs.rs`: structural, identifier, enum, reference, blob, source identity,
  page/range, image, metadata and bounded payload checks; operation and query JSON schemas.
  A small saved-only hook in `domain::validate_input` enforces this domain's richer schemas
  before local signing as well as during reduction. Other domains retain their validator.
- `queries.rs`: all 19 named queries, plus compatibility `read`, diagnostics `invalid`, and
  the tool alias `getPosition`. Results use `{revision,value}`, with `{rows,next,total}` pages,
  default 50/max 100, revision/argument-bound cursors, explicit missing/deleted/stale outcomes,
  UTF-16 previews and a 1 MiB response ceiling outside compatibility `read`.
- `import.rs`: pure `translate(VerifiedLegacyOperation, ImportContext)`, all 36 advertised
  legacy dispositions, stable full-source-tuple/transform keys, per-child provenance,
  complete original parsed payload evidence, dependency binding with `resolve_payload`,
  and publication-barrier requirements. No source signer becomes destination authority.

Shared Rust edits move the preview implementation out of `domain.rs`, re-export its existing
public names, register the `domains` module, box the larger saved state variant, and add the
saved-only schema-validation hook. The other domains and `engine.rs`/`library.rs` are unchanged.
The one existing saved deletion test now supplies the required current activity precondition.

Effective item mutations preserve unknown top-level properties in `extensions`; properties
literally named `extensions` remain nested. Defined nested models have their own bags.
Authenticated attribution always comes from `OperationView`. Invalid commands leave domain
objects unchanged and retain diagnostics. Stale conditional mutations retain complete attributed
candidates. Source descriptors contain plaintext identities, never ciphertext or availability
claims. Identical content can be referenced by independent occurrences without merging items.

The shelf maintains creation/touched/title/creator order indexes, status/tag/collection/kind
buckets, cached counts and note counts. Creation order includes the entire admitted
`(clock,author,operationID)` key; claimed dates do not arbitrate order. Graphs cache touched order
and maintain revision-order indexes and global per-category revision identities. Deferred graph
nodes cannot move item activity backward when prerequisites arrive. Unknown kinds and unresolved
graph closure are visible through compatibility diagnostics and block a complete-export claim.

The pinned Marginalia commit `3503057517a0e14e2f21325403fa1bc3a23e487c` was consulted for
`ReadingViewQuery`, saved views, connection relations, magazine subscription values and retained
image/original limits. The enums use the shipped subscription plans (`unknown`, `digital`,
`print`, `printAndDigital`) and relations (`related`, `supports`, `challenges`, `expands`).
Original descriptors cap at 128,000,000 bytes, image blobs at 8,000,000 and image batches at
40,000,000. Source and image identities use framed, versioned `colophon/reading.saved/.../1`
SHA-256 purposes exposed by `source_id` and `image_candidate_id`.

## Compatibility and explicit choices

- `reading.saved__capture` remains available. For old preview records, a URL may supply a missing
  title; URL-free captures require a title. The old `setState.state` spellings remain accepted and
  also project normalized consumption. New callers should use `consumption` and `retention`.
  This preserves the existing signed conformance history and playground call without editing it.
- `position` is both a proposed write and query name. Rust `query("position", ...)` works;
  generated read tools use `reading.saved__getPosition`, keeping `reading.saved__position` writable.
- Saved queries return the new envelope/page shapes. The optional old numeric `offset` remains
  accepted. Shelf cursors use ordered keys; other page cursors use prefix-bound offsets.
  `read` remains a deliberately unbounded compatibility/background projection.
- Malformed query arguments currently use the existing `Result::Err` channel with an
  `invalidArgument` reason rather than adding a new engine-level outcome variant. Semantic
  missing/deleted/stale/unavailable results are explicit values, not empty successes.
- `sources(kind:"versions")` also exposes tagged immutable source-only metadata records, so
  their raw provenance is retrievable without inventing a `SourceManifest.original`.
- Reader attachment requires matching origin kind, document ID, source-record digest and raw
  digest. These provenance fields live in the manifest's JSON `origin` object.
- A search/source-text filter or `availability:"savedText"` returns `unavailable` with
  `hostSearchIndexRequired` until the host provides the digest-keyed search join. It does not
  interpret missing local search facts as an empty shelf.

## Import boundary and what remains outside Rust

A verified signature plus kind/payload/ID/label/digest/order is insufficient to reproduce the old
stateful fold: it cannot establish whether a CAS was stale, whether an old deletion witness was
accepted, whether a Safari checkpoint advanced selection, or which subscription generation won.
`VerifiedLegacyOperation` therefore also requires the verified source outcome and source identity.
`ImportContext` supplies the old typed projection's lossless semantic decoding, persisted identity
map, last-imported destination component heads, existing occurrences, closure verification and
Safari advancement decision. Use last-imported heads, not heads refreshed from intervening native
edits; native edits must make catch-up imports stale.

Simple shelf commands map directly. Swift-associated-value models, dates, snapshots, graph
archives and custody packets require `ImportContext.decoded` from the original codec. The exact
normalized shapes used by each path are in `map_effect` and the every-kind mapping test. This
change does **not** implement a replacement Swift Codable decoder or reproduce the complete 0.1
admission/fold inside Rust. Missing decoding/closure/component context produces zero commands
and an explicit unresolved evidence entry. Unsupported legacy-journal and source.native kinds
remain evidence-only. This is a conservative integration interface, not proof of source-format
migration parity.

Effective restores expand into bounded clean commands. Restore replacement of an existing live
occurrence requires an explicit new-occurrence mapping when terminal new note semantics cannot
represent it. Deleted-history plans require an atomic publication barrier and finish with delete;
without that barrier they must not be presented as completed imports. Old Safari presence,
completion markers and review enablement stay historical evidence. Historical losers, conflicts,
rejected and invalid history never become unconditional clean effects.

The publisher must persist identity/component maps, exact original envelopes, evidence, blob
verification outcomes and actual signed destination operation IDs. `ImportCommand.key` is a
stable transform-child identity, not a signed operation ID. `resolve_payload` binds prior signed
child IDs to `expect` or deletion's `expectActivity`. Catch-up outcome changes and collisions
require explicit reconciliation; the domain does not rewrite signed destination history.

## Required engine / SDK / host integration

1. **Authenticated member kind on replay.** `OperationView` exposes only person/AI. The reducer
   rejects agents for fenced commands, but cannot distinguish an app/device from a server.
   `protected_kind` and `validate_for_member` provide the domain-side boundary. The engine must
   provide authenticated member kinds and apply equivalent checks during replay, not just hide
   tools. No payload role or historical signer can supply this authority.
2. **Blob and byte verification.** Connect `SourceVerifier`/`validate_with_sources` to verified
   source, image and raw-export bytes. Check digest, length, media parsing, exact quotations,
   UTF-16 boundaries, image candidates and provenance. Preserve missing/inaccessible/invalid
   distinctions. Structural descriptors alone never establish that bytes exist or anchors match.
3. **Durable encrypted import evidence.** Store `ImportResult.evidence` and original envelope
   references with destination namespace access controls. Implement the common paged
   `importEvidence` stream and merge historical alternatives into SDK conflict views with
   `historical:true`; the reducer currently exposes live conflicts only.
4. **Publication and catch-up receipts.** Commit evidence, blobs, identity/head maps and signed
   child-ID bindings before publishing a migration batch. Hide partial snapshot/deleted-history
   imports. Re-evaluate late source history through the source reader and reconcile changed
   outcomes against the last imported component baseline.
5. **Search and passages.** Provide bounded, revision-pinned host search results and source
   passage/PDF retrieval. Bind joined pages to both domain and host-index revisions. No local
   availability, presence lease, credentials, model enablement or download status is replicated.
6. **Checkpoint compatibility.** The saved state schema changed substantially. Old preview
   state fails deserialization, but the integrating engine should explicitly bump/version-bind
   reducer checkpoints. Preserve verified-prefix invalidation and deterministic suffix replay;
   this branch deliberately does not alter engine checkpoint formats.

## Remaining acceptance and performance gaps

- Unfiltered and single-index shelf pages use keyset ranges; common counts are cached. Compound
  filters scan the smallest candidate bucket. Several secondary lists still enumerate/sort
  projected summaries or references, and non-shelf cursors use offsets. They return bounded
  content but do **not** yet meet O(log n + page size) for every query. Full secondary indexes,
  large-library timings and the 100k-operation acceptance measurements remain to be completed.
- Dependency re-evaluation follows affected reverse edges iteratively, avoiding recursive stack
  growth and full-history scans. A large ready dependency cascade can still consume an entire
  reducer call; there is no resumable engine work budget in the current trait.
- Head arrays are capped and report counts/conflict state; there is not yet a dedicated cursor
  over every oversized graph's head set. History/conflict pages retain the underlying revisions.
- Tests cover normalized import effects and evidence disposition for every advertised kind,
  but do not run real Swift-codec parity across all snapshot versions 1–7, annotation versions
  1–5, malformed archive-byte encodings, source custody corpora or historical recovery collisions.
  These are migration proof gaps, not verified capabilities of the decoder interface.
- Complete export, historical conflict overlays, blob resolution and migration atomic visibility
  require the integrations above. The core does no I/O and has not claimed these are operational.

## Conformance and validation

`conformance/0.2/reading.saved.json` contains deterministic synthetic signed records and expected
results for all 19 named queries. `domain_saved::deterministic_saved_vector` generates it;
`conformance::saved_domain_conformance` reopens the checked-in bytes. JavaScript checks the same
fixture through WASM. The old `library.json` and `library/` record bytes are unchanged. Only the
saved projection in `expected.json` was regenerated: defaults, claimed added dates, normalized
preview state and the expanded compatibility projection are intentional new semantics.

There are 18 saved-domain tests, including all 24 command paths, missing-payload rejection for
every command, all 36 successful/contextual import mappings and negative dispositions, stale
component heads, terminal deletion, graph siblings/resolution/dependency arrival, source-only
attachment, images, feed retention, review undo, generated tool validation, cursor binding,
UTF-16 previews, shared content with distinct occurrences, admitted-order ties, fixed-seed replay,
serialization and shuffled-record/checkpoint replay.

Final checks passed:

```sh
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export CARGO_TARGET_DIR=/Users/mikelxc/projects/colophon-wt/.target-domains
export CARGO_HOME=/Users/mikelxc/projects/colophon-wt/.cargo-shared
cargo test                                           # 46 tests passed
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
npm --prefix js ci
npm --prefix js run build
npm --prefix js test
git diff --check
```

`js/scripts/build.sh` has one portability fix to pass `${CARGO_TARGET_DIR:-target}` to
wasm-bindgen; this makes the requested shared-target build reproducible without a worktree
symlink. The temporary symlink used during initial checks was removed. Build artifacts and
npm output remain ignored; no build directories or dependencies were committed.

## Intended commits

1. Implement saved-reading commands, component heads and retained graph projections
2. Add saved-reading schemas, bounded queries and generated-tool validation
3. Add verified legacy saved-reading transforms and import-evidence boundary
4. Test saved-reading replay and Rust/WASM conformance; document integration gaps

Suggested trailer: `Co-Authored-By: Codex <noreply@openai.com>`.
