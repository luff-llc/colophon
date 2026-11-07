# listening.podcasts domain handoff

Implemented in the `dom-listening.podcasts` worktree, 2026-11-06. Changes are uncommitted.
The domain implementation is complete at the interfaces described below. End-to-end app
migration still requires the engine/SDK integrations and verification work listed here.
No reducer trait, admission logic, cryptography, or engine implementation was changed.

## Implementation

`crates/colophon-core/src/domains/listening/` contains:

- `mod.rs`: all 30 proposed command reducers, attributed alternatives, permanent note
  tombstones, independent metadata/position/state heads, atomic preference and playback
  batches, signer-scoped receipts, transcript selection, playlists and structural services.
- `specs.rs`: operation and query descriptions and JSON schemas, including nested models.
- `validation.rs`: received-payload validation, bounds, IDs, credential-free HTTP(S) URLs,
  dates, digests, blobs, discrete preferences, UTF-16 citation limits and nested extensions.
- `query.rs`: all 17 specified queries, deterministic indexes, bounded rows and revision-bound
  cursors. Also supplies compatibility reads and aliases described below.
- `import.rs`: pure verified-operation import planning, all 33 old kinds, typed identity/head
  maps, deterministic occurrence IDs, child indices, baseline classification and manifests.
- `evidence.rs`: immutable sidecar indexing, bounded historical pages and post-signing output
  ID binding. Historical attribution is separate; historical jobs are never executable.

The preview implementation was removed from `domain.rs`, which re-exports the same public
`ListeningPodcasts` and `PodcastsState` names. Registration remains unchanged. Its podcast
state variant is boxed to avoid growing every other domain's enum allocation and to satisfy
clippy. `lib.rs` exports `domains`; `domains/mod.rs` exports `listening`. These are the only
shared implementation changes. No dependency was added.

Unknown payload properties are retained under extensions, including an input property literally
named `extensions`. Known nested models get their own bags. Projection attribution comes from
`OperationView`; payload attribution cannot replace it. Stale operations retain complete
attributed candidates and exact attempted commands. Rejected passive regressions now produce
conflicts instead of disappearing. Successful note resolution requires the current head and
exact sorted observed note/text alternatives; resolved alternatives remain in a receipt.

Playback completion compares queue order/head and every episode position/state head before
changing anything. Batch and event identities remain bound even on stale attempts. Native
positions are not sessions. Imported baselines use a separate trusted application context;
existing native heads block them, and subsequent native progress can replace a baseline.

Transcript descriptors retain every immutable candidate; source/timing rank and fold order
select one. Descriptor availability is separate from byte verification. Segment/chapter
replacement validates the complete list. Authenticated app/device person review protects a
recording from generated replacement. Context proposals and acceptances preserve separate
attributions, including prior accepted versions when a new proposal replaces the current one.

## Queries and compatibility choices

Canonical queries return `{revision,value}`. Pages contain `{rows,next,total}`, default 50,
maximum 100; queue/jobs/contributions default 20. Cursors bind namespace, query, normalized
filters, last sort key and revision. Limits may change between pages. Changed prefixes return
`staleCursor`. Missing objects and tombstones are distinguished. Results have a 1 MiB guard;
page construction reserves overhead and stops before the response bound. Oversized individual
objects report `unavailable` rather than silently dropping their contents.

Indexes are maintained for shows, episode parent/state/publication, note parent/creation/time,
playlists, transcripts, state history, jobs, contributions and source dependencies. Late
transcript descriptors update dependent job/contribution episode filters without resuming work.
Playback history contains state heads, ordered and displayed by their claimed state date;
position updates do not invent history sessions or change that state's claimed date.

Normal indexed pages use ordered range lookup and serialize only page rows. Queue scans are
bounded by 1,024 entries, recording lists by 2,048. Conflict paging scans one object's retained
alternatives. Counts use maintained index lengths/conflict counters except the bounded queue
scan. Historical sidecar insertion recomputes its content revision in background import work;
it is not a player-tick operation.

Deliberate compatibility/additive choices:

- `episode` and `queue` remain write tool names. Rust `Reducer::query` and `Library::query`
  accept those names for the specified reads. Generated tools expose `episodeDetail` for the
  new detail shape and `getQueue` for the new rich queue shape. `getEpisode` retains the old
  raw single-episode result, including null for absence. `read` remains the full compatibility
  projection; it is not intended for hot paths.
- Explicit legacy offset paging retains `items`/`nextOffset` alongside the new page fields and
  the old unwrapped result. New callers should use cursors. `getQueue` now returns the proposed
  head and EpisodeRow page rather than the preview's string-ID page.
- `follow.title`, `episode.show` and `position.show` remain optional for shipped preview callers.
  A supplied parent cannot move an existing episode. Missing follow title defaults to its URL.
  The old `followed` property remains alongside `following`. The playground needs no changes.
- `follow` and `episode` additionally accept optional `expect` on their respective heads. This
  permits conditional catch-up imports without adding legacy wire opcodes.
- Existing malformed-argument API behavior is preserved: `invalidArgument` is a Rust error with
  a stable reason prefix. Domain missing/deleted/stale-cursor/unavailable results are values
  inside the query envelope. A unified typed outer failure envelope needs the engine adapter.
- Known commands have a 1 MiB canonical payload ceiling in addition to model-specific limits.
  Notes use the proposed 256 KiB text limit. Explicit inline transcript/blob byte fields are
  rejected; the preview's bounded `transcriptExcerpt` remains supported only on episode metadata.
- Contribution list pages summarize claim counts with `truncated:true`; the `id` query returns
  the complete bounded contribution. Full history/raw payloads remain available through the
  background compatibility/archive interfaces.

## Import contract and required evaluator input

`import_operation(&VerifiedOperation, &ImportContext) -> ImportPlan` is pure. Its record input
contains kind, version, decoded payload, operation ID, original signer/label, exact signed-body
SHA-256, admitted order, claimed date and source library. Every record yields an evidence
manifest, including rejected/malformed/unknown/unresolved history. The source tuple plus
transform version identifies the entry; old operation IDs alone are never idempotency keys.

A verified operation alone cannot establish whether an old CAS, recovery, service batch or
legacy baseline took effect. Therefore the verified 0.1 reader must supply admission and
`Disposition`, and these additional inputs where applicable:

- `effective_payload` is required for show.follow, show.settings, queue.retain, legacy.bridge.import,
  legacy.podcastState.import and podcast.source.publish. It contains the actual retained first
  show metadata, accepted settings fields, descriptors actually filled, feeds actually added,
  baseline fields actually supplied, or source actions actually applied, respectively.
- For source publication, evaluated actions have `{kind,payload,mode}` where kind is one of
  follow/unfollow/position/setState. Original facts, action receipts, inventory, lineage roots,
  source descriptors and all rejected effects remain unchanged in the source manifest.
- For note.resolve, supply the actual old `expect` and exact `resolves` revisions in the effective
  payload. For natural-end batches, supply only the events actually pending/applied. These cannot
  be reconstructed from one raw operation without the old prefix/service state.
- `identities` and `revisions` use `map_key(category,id)`; revisions are component-specific
  (`position`, `state`, `text`, `queue`, `transcript`, or `preference:<old preference key>`).
  The host persists lifecycle/collision choices. `occurrence_id` supplies deterministic new
  IDs for remove/recreate occurrences; feed/GUID hashes preserve exact original input bytes.
- `destination_heads` supplies prior imported destination heads for catch-up. Its keys use
  `map_key(component,newObjectID)`. For old show-settings speed, use
  `map_key("preference","show:<mapped show ID>:speed")`. Missing required catch-up heads leave
  evidence instead of emitting unconditional overwrites.
- `blobs` maps old plaintext digests to resealed plaintext descriptors. Anchor references also
  require transcript revision and transcript identity mappings. Missing mappings never imply
  verified bytes; missing/invalid anchors and unavailable originals remain explicit evidence.
- `accepted_answer` contains a durably accepted old response and translated-source inputs.
  Persist `emitted_answers` by original response revision to materialize an accepted answer only
  once across question.response/question.admit records.

Queue duplicates collapse in first-occurrence order. Overflow beyond 1,024 and invalid optional
metadata are retained and reported in evidence. Original malformed metadata cannot discard the
valid queue order. Legacy normalized chapters/playlists use explicit defaults and preserve raw
values in the manifest. Invalid stricter values are evidence-only. All transcript candidates
with mapped valid descriptors may be retained, not just the old winner.

Old preparation/question/capture/context work is archived. It does not enroll an agent or
revive a worker request. Imported capture descriptors have no active target agent. Native
saveAnswer imports are signed by the importer; original attribution is historical provenance.

After signing commands, call `evidence::bind_outputs` and atomically persist records, child/output
bindings and manifests. `Command.baseline` must be bound to the resulting operation ID in that
trusted manifest. Do not derive baseline privilege from a payload's `importedBaseline` property.
Exact source envelopes and referenced bytes remain in a read-only source archive. No Swift
signature reader, Date codec, private legacy archive reconstruction or resealing I/O is included
in this pure transformation module.

## Exact engine/SDK integration requirements

1. **Authenticated roles:** call `apply_with_context` with the signer's authority-derived
   `MemberKind` for every operation, including replay and checkpoints. `OperationView` currently
   exposes only origin, which distinguishes agents but not apps/devices from servers. Ordinary
   `Reducer::apply` therefore fails closed for app/device-only service mutations and capture
   delegation (`unavailableRole` conflicts). It cannot mark a person recording edit reviewed.
   Role-bearing direct reducer tests cover all service paths; this is not yet wired through
   `Library` because changing engine internals was explicitly out of scope.
2. **Import provenance:** provide the verified output-ID-to-baseline mapping to `ApplyContext`.
   Persist it access-controlled with the encrypted evidence sidecar and reproduce it on every
   replica/replay. A caller-provided extension is not proof of a baseline or old authorship.
3. **Verified prefix:** call `bind_admitted_prefix` after admission with the engine's verified
   prefix digest, including versions not delivered to the reducer. Until then, the domain uses
   a deterministic rolling hash of delivered OperationViews. That fallback detects delivered
   unknown/invalid operations but is not the exact signed-body-prefix digest.
4. **Checkpoints:** coordinate the new reducer schema with the engine's checkpoint format/version
   migration. The state has required new fields and `schema:2`, so preview state shapes cannot
   deserialize as this state. The shared engine checkpoint version was intentionally untouched.
5. **Historical overlays:** persist `EvidenceIndex`, authorize every read with current namespace
   access, and route/merge its pages for common importEvidence and historical jobs, contributions,
   conflicts and sessions. `insert_historical` accepts normalized rows from the verified old
   evaluator; the evaluator must decode dates and fold PlaybackVisibility by original source
   clock/actor/operation identity. Native `history(importedSession)` explicitly reports
   `unavailable` until this adapter is supplied. It never substitutes an empty native history.
6. **Source verification and execution:** resolve blob descriptors by plaintext digest/size/type,
   distinguish available/missing/inaccessible/invalid bytes, validate exact transcript revision,
   UTF-16 boundaries and quote contents, and supply current source/access/deadline overlays.
   Enforce future deadlines, the old seven-day/pending-request host limits where adopted, current
   worker enrollment and read permissions before delegation/admission. Structural results stay
   `pendingSource`, `respondedPendingVerification` or `acceptedPendingVerification`; no reducer
   action starts a worker, verifies bytes or consults a clock. Implement transcript passage,
   moment and search APIs in the host's digest-keyed blob index.
7. **Bindings:** expose the richer queries/error outcomes and sidecar access in native/SDK
   bindings. Generated JS tools already exercise the available domain queries; no trait or
   engine signature was changed to force the new overlays into the existing API.

## Conformance and checks

New synthetic signed records and expected results:

- `conformance/0.3/listening.podcasts.records.json`
- `conformance/0.3/listening.podcasts.expected.json`

`tests/support/listening_vector.rs` generates the vector, checks stored bytes through a fresh
replica, and is run from both `tests/domain_listening.rs` and the existing conformance test.
The vector exercises all 17 specified query surfaces. JS smoke replays the same records through
WASM and generated tools, including episodeDetail/getQueue aliases.

The existing `conformance/0.3/expected.json` was regenerated only for the richer podcast state
(component heads, availability, claimed update date, following alias and additional collections).
Existing signed library bytes, other namespaces and ledger outputs are unchanged. One existing
protocol assertion now expects the additional passive-regression conflict. Original ledger
phrases and existing write tool names are preserved.

Final checks passed with cargo from `/opt/homebrew/opt/rustup/bin`, the supplied shared
CARGO_HOME and CARGO_TARGET_DIR:

- `cargo test`: 43 integration tests passed, including 15 new domain tests; doctests passed.
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- `npm --prefix js ci`
- `npm --prefix js run build`
- `npm --prefix js test`: key security, smoke, existing fixture parity and new podcast parity.
- `git diff --check`

An overlapping build once removed a shared-target rlib before the final doctest process opened
it; the sequential final run passed. The existing JS build script hardcodes `target/` for
wasm-bindgen input. A temporary local `target` symlink to the supplied shared target directory
was used for those builds and removed afterward; no duplicate build cache or script change was
introduced. Recreate that temporary link when reproducing this exact shared-target JS build.

Tests cover fixed-seed random ordered histories and serialized-prefix replay, explicit conflicts,
tombstones, atomic batches, receipt reuse, role/worker/requester fences, missing blobs, all 33 old
kind dispositions including malformed/rejected/legacy history, catch-up heads, baseline precedence,
source dependency indexes, cursor/filter invalidation, overflow/bounds and signed native/WASM replay.
No real-library migration, Swift differential run, 100k-operation performance measurement,
mobile benchmark, encrypted sidecar storage integration or blob-byte integration was performed.
Those remain release proof gaps, not claims made by these synthetic tests.

## Intended commits

1. `Implement listening.podcasts reducers and bounded indexed queries`
2. `Add verified podcast import planning and historical evidence interfaces`
3. `Add podcast domain conformance vectors and native/WASM coverage`
4. `Document podcast engine integration requirements and migration gaps`

Leave these changes uncommitted for the coordinating worker. No other domain implementation
or playground source was changed.

## Engine3 follow-up — November 6, 2026

The engine-facing storage and authenticated-context requests above are superseded by the
[engine3 API contract](engine.md#engine3-authenticated-import-storage-and-blobs) and
[engine3 validation handoff](handoff-engine3.md). Root-signed encrypted batches now bind evidence,
virtual output revisions, reservations and manifests atomically. Historical alternatives and
prefix reconciliation remain separate from effective native state. The Swift migration reader
uses synchronized evidence; unsupported source codecs, automatic correction/UI, typed collision
remapping in that orchestrator, source/anchor verification and real platform acceptance remain
explicit host/app work. Earlier validation counts describe the earlier handoff, not engine3.
