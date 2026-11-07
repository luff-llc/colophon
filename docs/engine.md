# Colophon engine APIs

The compatible `Library` caches verified operations, admission decisions, and reducer state.
The storage-backed `Engine` adds verified-prefix cold opens and bounded content retention;
see [stage 2 below](#storage-backed-engine-stage-2). Existing `Library` methods and return types
are unchanged. `view` and the `read`
tool still return the full history-bearing `NamespaceView`; use `query` for app rendering.
Operation and authority envelope formats are unchanged. The engine3 extension below adds reserved
engine operations for import publication and blobs. Role-sensitive conformance expectations reflect
authenticated member kinds.

## Reducers

`domain::Reducer` extends the existing metadata/specification interface `DomainModule`:

```rust
pub trait Reducer: DomainModule {
    type State: Default + Clone + Serialize + for<'de> Deserialize<'de>;
    fn apply(&self, state: &mut Self::State, operation: &AdmittedOperation);
    fn query(&self, state: &Self::State, name: &str, args: &Value) -> Result<Value>;
}
```

All four built-in modules are registered: `reading.books`, `reading.saved`, `notes`, and
`listening.podcasts`. Their full reducers, operation validation hooks, named queries and pure
import planners are shared by `Library` and `Engine`; registration does not materialize history.
See [domain contracts](domains/README.md) for the richer query shapes, cursor/revision rules,
validation and host integration seams. The offset/query table below describes the retained
preview compatibility surface; new domain queries use their own bounded result envelopes.

`AdmittedOperation` aliases the existing authenticated `OperationView`. `ReadingSaved`,
`ListeningPodcasts`, and `Notes` own `SavedState`, `PodcastsState`, and `NotesState` respectively.
The engine alone orders admission. Reducers retain attributed conflicts, invalid IDs, tombstones,
extensions, and the previous conflict semantics. Unknown kinds are skipped. `DomainModule::fold`
is retained as a source-compatible from-scratch replay wrapper. A new reducer schema or semantic
change must increment the authenticated `reducer_schema` generation before old snapshots can
be restored. Generation 3 added authority-derived member kinds during append, full replay and checkpoint-suffix
replay. Generation 4 adds full author context and the import/blob sidecar projection. Both cache APIs
reject older generations, whose role-sensitive or import projections may be incomplete.

## Queries

Call `Library::query(namespace, name, args, now) -> Result<Outcome<Value>>`. Grant, expiry,
revocation, and current epoch availability are checked on every call. A missing key or permission
returns the same denial as `view`; an inaccessible namespace never becomes an empty success.
Unknown query names and malformed arguments are errors for built-in domains.

| Namespace | Single object, with `{"id":"..."}` | Paged collection |
| --- | --- | --- |
| `reading.saved` | `item` | `items` |
| `listening.podcasts` | `show`, `getEpisode` | `shows`, `episodes`, `getQueue` |
| `notes` | `notebook`, `note` | `notebooks`, `notes` |
| Every built-in namespace | — | `conflicts`, `invalid` |

Single-object queries return the projected object or JSON `null` for an absent ID. Pages accept
`{"offset":0,"limit":50}`; both fields are optional, integers must be nonnegative, and `limit`
must be 1–200. Results are `{"items":[...],"nextOffset":50}`; `nextOffset` is `null` at the end.
An offset beyond the end returns an empty terminal page. Collections retain the existing
`(clock, author, revision)` order of each object's last applied operation. Conflicts and invalid
IDs retain reducer order. `getQueue` pages the ordered episode ID strings, not the queue metadata.
Saved item pages include tombstones, as the full projection does.

`read` through `query` returns the complete **state** as a compatibility escape hatch. The
existing `namespace__read` tool still returns the complete **NamespaceView**. Other query tools
use `<namespace>__<query>` and return the bounded result directly. The `getEpisode` and `getQueue`
names avoid collisions with the existing `episode` and `queue` write tools. All queries appear
in `DomainModule::queries()` with their JSON input schemas, and in authorized tool lists.

Offsets refer to one namespace revision: discard pagination progress after a revision change.
Single-object lookup is O(log projected objects), without walking history. Paged object queries
currently sort references to the projection in memory, then serialize only the requested page;
they do not clone the entire projection. An ordered collection index is a future optimization
for exceptionally large shelves. Text and extension values inside a single object are not capped.

## Changes and revisions

Additive methods:

- `merge_with_changes(Records) -> Result<ChangeSummary>` performs the merge; `merge` delegates
  to it and discards the summary.
- `finish_with_changes(PendingBatch, signatures) -> Result<ChangeSummary>` completes a prepared
  write or authority action and merges it. Existing `begin_write` and `finish` remain unchanged.
- `changes() -> &ChangeSummary` reports the last successful merge/unlock's changes.
- `revision(namespace) -> u64` returns the current device-local revision (initially zero).
- `applied_operations(namespace) -> u64` counts reducer invocations for diagnostics.

`ChangeSummary.namespaces` maps changed names to their new revisions. A merge increments each
affected namespace at most once, including held/refused evidence changes. Identical records
produce an empty summary. Failed merges do not mutate records, admission, state, or revisions.
Authority changes conservatively invalidate every declared namespace, since access outcomes
can change without a projection change. Unlocks invalidate affected namespaces, and can also
change admission when previously unavailable payloads authenticate. Collect summaries after
both merge and unlock. Revisions are observation tokens within one `Library`, not persisted
content identities; checkpoint validity never depends on them.

An append after a namespace's known header tail advances admission and reduces only the new
admitted content. A capped author's grant-wide budget also requires appending after that author's
tail across namespaces. For a middle insert, duplicate competition, authority change, or key
unlock, the engine reevaluates admission using cached signature/decryption results, compares each
namespace's admitted prefix, and replays the changed suffix from the nearest retained checkpoint.
An unchanged admitted prefix does not replay reducers. Regranting remains the 0.3 protocol's
fresh-identity enrollment; this engine does not introduce same-identity replacement grants.

## Local checkpoints

- `checkpoint(namespace) -> Result<Vec<u8>>` serializes the current state and prefix identity.
- `restore_checkpoint(namespace, bytes) -> Result<bool>` accepts a matching cache and replays
  its suffix, or returns `false` and leaves the already replayed state authoritative.
- `open_with_checkpoints(records, identity, BTreeMap<namespace, bytes>)` stages caches for cold
  open. They are validated as keys unlock. Invalid caches are discarded and ordinary replay wins.
- `set_checkpoint_policy(CheckpointPolicy { every, retain })` controls automatic in-memory
  snapshots. Defaults: every 10,000 admitted operations, at most four per namespace. `every: 0`
  disables creation; `retain: 0` also removes retained snapshots. A host explicitly persists
  `checkpoint()` bytes; the core performs no filesystem I/O.

The version-1 body contains `version`, `reducer_schema`, `library`, `identity`, `namespace`, `epoch`, and `snapshot`.
The snapshot contains serialized reducer `state`, admitted-prefix `position`, and 32-byte `digest`.
`H(0)` is 32 zero bytes. `H(n) = SHA-256(H(n-1) || recordDigest(n))`, concatenating raw 32-byte
values. The operation record digest is SHA-256 of the exact signed **body** bytes, as in `kept`;
it is neither an operation ID nor a digest of the outer JSON envelope.

The outer envelope stores base64 `body` bytes and a base64 32-byte `tag`. Prefix checks alone
cannot detect a modified state, so the tag authenticates the entire body. A recipient-specific
cache key is derived from the successfully authenticated HPKE ECDH result with
HKDF-SHA256, salt `colophon/checkpoint-key/1`, and the epoch's existing `key_info` as info.
The tag uses HKDF-SHA256 with that cache key as salt, the exact body as input key material,
info `colophon/device-checkpoint/1`, and 32 output bytes. Thus another namespace member's
shared AES key is insufficient to forge this device's cache. Tag comparison covers every byte.
No new host secret or dependency is required. These caches are not signed protocol records,
not portable backups, and must not be synced or accepted as shared authority. Their state is
plaintext encoded in base64: hosts should use protected local storage.

Restoration checks authentication, format/reducer version, library, recipient identity,
namespace/state type, prefix length, and the recomputed admitted-prefix digest. Reordered,
revoked, unavailable, or otherwise changed prefixes invalidate the cache. Operations after the
checkpoint always undergo normal signature, authority, budget, payload, and admission checks.
An older valid cache can restore a prefix of a longer current history; the suffix is then reduced.
A mismatching cache falls back to the record-derived state, never to an empty success.

For cold open, obtain `begin_unlock()` steps, perform ECDH through the host, and call:

```rust
library.finish_unlock_many(results)?;
// results: Vec<(String /* namespace */, u64 /* epoch */, Vec<u8> /* shared secret */)>
```

This validates every result before installing any key, then refreshes admission/projections once.
The original `finish_unlock` remains available and source-compatible; sequential unlock also
restores staged caches, but performs more admission passes. For this compatibility API, cold open still verifies and decrypts the signed history. Its
version-1 checkpoints accelerate projection replay. Use the storage-backed `Engine` below for
verified-prefix trust and lazy historical content.

## Storage-backed Engine (stage 2)

Native Swift and Kotlin sessions now use `engine::Engine<S: RecordSource>` through `NativeEngine`. `Library` remains the compatible
in-memory API, with every existing method signature and outcome shape intact. Both paths share
exact-byte verification, payload validation and admission rules. The existing version-1
`Library` checkpoints still replay cryptography; the new version-2 `Engine` checkpoint is a
separate, library-wide cache. `NativeEngine.query` and the compatible `NativeLibrary.query` expose named
reads directly, including names that also identify commands (`episode`, `queue`, `position`),
without preparing writes or constructing history. Swift and Kotlin bindings include it;
WASM export signatures are unchanged.

```rust
use colophon_core::engine::{Engine, EngineOptions, RecordSource};

// Implement read(path) -> Result<Vec<u8>> on a host-owned immutable store.
// listing is a coherent list of all current authority/, requests/ and ops/ paths.
let mut engine = Engine::open(store, listing, identity, EngineOptions {
    library_id,                 // expected ID from creation/enrollment
    checkpoint_key,             // random [u8; 32], protected device-local host secret
    content_cache_bytes: 256 * 1024,
}, checkpoint.as_deref())?;
let tasks = engine.begin_unlock();
// Host performs ECDH and returns (namespace, epoch, raw shared secret) for each task.
engine.finish_unlock_many(results)?;
let episode = engine.query("listening.podcasts", "getEpisode", args, now)?;
let cache_bytes = engine.checkpoint()?; // host atomically persists locally
```

The core never opens a file, enumerates a directory, reads a clock, generates randomness, or
persists a record. `RecordSource::read` runs synchronously on the caller's thread; hosts can
implement it over a database, an immutable file snapshot, or their own cache. `Records` and
`Arc<T: RecordSource>` have adapters. An async app should run engine calls on its worker and
supply a synchronous snapshot reader. The source must give coherent reads, enforce immutable
path writes, and retain all indexed records. It need not implement `Send` or `Sync`: worker
threads receive already-read buffers, never the source. `source()` exposes the owned source
for host integration, without granting the core write access.

Always call `finish_unlock_many`, even with an empty vector, before queries, writes or
checkpointing. A cache restores admission and projections, but contains **no epoch keys**.
Unlock authenticates fresh host ECDH results; access checks still enforce current grants,
revocation, expiry and current-epoch availability. Restoring with a different set of unlocked
epochs requires a full replay, since payload availability affects IDs and projections. Batch all
available unlock tasks to avoid repeated rebuilds. All results authenticate before keys install.
`open_mode()` reports `FullVerification`, `VerifiedPrefix`, or `Invalidated(reason)`.

### Cache identity and invalidation

The format is an authenticated binary container: `COLOENG3`, little-endian u32 JSON-metadata
length, metadata bytes, u32 record count, sorted entries, then a 32-byte tag. Each entry contains
u32 UTF-8 path length, path bytes, 32-byte **SHA-256 of the entire exact envelope**, u16 namespace
index (65535 means none), one byte of flags, the 32-byte author signing-key digest,
u64 epoch, and a length-prefixed UTF-8 provider-version token (zero means none; otherwise length is byte count plus one). This implementation supports fewer than 65,535
namespaces. Flags distinguish signature-verified headers, header budget admission, authenticated
IDs and projected operations. Rejected records/requests are bound as observed bytes, never
promoted to valid operations. The metadata contains:

- Container/storage/layout versions, required `reducer_schema` generation (6), selected namespaces,
  expected library and complete recipient public identity.
- Authenticated authority state, including historical roots, grants, epochs and revocation keeps.
- Reducer states, namespace prefix counts and rolling digests, clocks and revisions.
- Admission tails, capped-author spend sets, unlocked-epoch names and rejection evidence.

The duplicate-ID index is reconstructed from compact path identities and authenticated flags;
it contains no plaintext payload and uses a fixed-key hasher without OS entropy.
Per-namespace prefix digests use the existing rolling
SHA-256 construction over exact signed **body** digests, preserving `kept` semantics. The
checkpoint tag binds those prefixes, reducer states, authority and the entire record index
in one authenticated object. Index envelope digests additionally catch changed signatures,
outer encodings and ciphertext. These two digest purposes are intentionally different.

Authentication is HKDF-SHA256 with the host's device key as salt, the exact container body as
IKM, `colophon/verified-prefix/3` as expansion info and 32 output bytes. Comparison covers all
tag bytes before parsing metadata or index. Container changes must bump version and magic. Reducer schema/semantic changes increment the
required authenticated `reducer_schema` generation in both cache APIs. Missing or mismatching
generations fall back to replay, including caches made before all four full domains were merged.
This preserves the `COLOENG3` layout, exact-envelope index, tag construction and prefix digests.
The key must be random and protected separately from the shared folder. This is an additional
host-supplied device secret, independent of namespace AES keys and the version-1 ECDH-derived
`Library` cache key. Raw checkpoint state is plaintext. Use `checkpoint::PreparedCheckpointKey` to generate a random
cache authentication key sealed to the member using the existing RFC 9180 HPKE implementation.
Sign its exact `signing_body()` with the member key and call `finish(signature)`; the core verifies
that signature before issuing a `CheckpointKey`. Supply `authentication_key()` to the engine.
`CheckpointKey::protect(checkpoint, fresh_entropy)` encrypts the raw checkpoint with AES-256-GCM
under a purpose-derived key and authenticates the exact signed ticket as additional data.

To reopen, `CheckpointOpening::begin(bytes, library_id, member)` verifies the ticket signature,
purpose, library and exact recipient before asking the host for ECDH at `agreement_peer()`.
`finish(shared_secret)` returns the original `CheckpointKey` and authenticated plaintext for
`Engine::open`. Wrong member/library, forged ticket, wrong ECDH and modified ciphertext fail
explicitly. An inaccessible member key must retry; never create a replacement identity or ticket.
The wrapper is private acceleration data, not shared authority or a portable backup, and does not
provide rollback detection against an attacker controlling the private host container.

A provider should implement `RecordSource::content_version(path)` with coherent opaque versions.
A changed token forces signature/decryption/admission checks even for identical bytes; different
bytes at a covered immutable path are equivocation. Without provider versions, run explicit
`verify_batch` audits. Replaceable live slots are fetched and verified on every storage-engine
restore/refresh, including a checkpoint restore; they never become durable reducer state.

A missing, unauthenticated, wrong-library, wrong-recipient or unknown-version cache falls back
to ordinary verification. A missing covered immutable path fails explicitly; a sibling namespace excluded from the
selected listing cannot block it. Authority additions invalidate all admission/projections. A valid cache may have a new suffix; only its new records are fetched,
verified, decrypted and applied. An arrival before a namespace tail or a capped author's global
tail forces full verification/replay. Full replay recomputes duplicates, budgets, held/refused
status and revocation keeps using the same admission rule as `Library`. New key availability
also invalidates cached payload evidence. A successfully authenticated cache retains its exact-envelope expectations even when its
projection is invalidated: changed bytes at surviving covered paths fail with an integrity error
during the rebuild. Missing covered immutable paths in a supplied listing are an explicit error, while a
missing read for a still-listed covered path is an integrity error. The conservative rebuild is explicit and may take
full-rebuild time; the <100 ms target applies to unchanged authority with an appendable 1% suffix.

### Host changes, writes and history

- `refresh(listing) -> Result<ChangeSummary>` compares a complete listing, including removals.
- `apply_paths(paths) -> Result<ChangeSummary>` processes a known persisted delta without a full
  listing scan. Known paths are fetched and digest-checked; a different envelope is an integrity
  error. Authority deltas trigger a full rebuild. New authority may produce new unlock tasks.
- `begin_write(...)` returns the existing `Outcome<PendingBatch>`. Sign with the host and call
  `PendingBatch::finish(signatures)` to obtain records. Persist them atomically, then call
  `apply_paths(record_paths)`. The engine does not write to the source. Do not apply a path
  before its bytes are readable. Existing `Library::finish` remains unchanged.
- `history(namespace, offset, limit, now)` returns `Outcome<HistoryPage { items, next_offset }>`;
  limits are 1–200. It orders admitted original operations, validates the fetched envelope
  digest, and decrypts/validates only the selected payloads. A lazy namespace ordering index
  is built on its first history query and invalidated on record changes. Discard pagination
  offsets when `revision(namespace)` changes.
- History uses LRU eviction by encoded plaintext byte budget. Oversized operations bypass the
  cache; zero disables it. Hits need no source fetch/decryption. Cache accounting excludes
  small path/container overhead, whose entry count is also bounded by cached content size.
- `view(namespace, now)` assembles the compatibility `NamespaceView` on demand. The returned
  full allocation belongs to the caller, not the engine. Prefer `query` and bounded `history`.
- `materialize_library()` explicitly fetches/digest-checks and fully verifies all records,
  returning a caller-owned, unlocked `Library`. Use this compatibility escape hatch for the
  full ledger, member write counts and administrative actions (approve, revoke, handover,
  recovery). It temporarily costs O(history bytes/views); drop it after preparing the action,
  persist the signed batch, and feed its paths back to the engine. Administrative actions are
  not silently delegated to a history-free `Library`, which would lose preservation evidence.

`stats()` exposes fetched-record, verified-operation, decrypted-payload and reducer-application
counts, index length and cached content bytes. Normal rendering retains no operation bodies,
ciphertexts or full `OperationView`s. Memory is O(record/admission indexes + authority + reducer
state + bounded cache + bounded processing batch), **not strictly O(projection state)**: exact
membership, duplicate IDs, ordering and capped budgets require history indexes. Reducer conflicts,
invalid entries, tombstones and authority `kept` sets can also legitimately grow with history.
The engine processes at most 8,192 new records per batch; an individual record is not size-capped.
After ordered global admission, independent namespace projections can reduce concurrently in
native workers. Each namespace's operation order is preserved; workers receive only projection
state, admitted content and its authority-derived member kind. Small deltas, WASM and builds without `parallel` run serially.
Saved-reading caches compact retained items and shelf indexes; derived shelf rows are rebuilt
from projection state during restore (in parallel where available), never from historical records.

### Integrity audits and trusted-folder limits

`verify_batch(limit) -> Result<VerificationProgress { checked, remaining }>` audits at most
`limit` indexed records in path order. After `remaining == 0`, the next call starts another pass;
zero performs no reads. Appends preserve the last-audited path so continuous writes do not
restart the scan; newly inserted paths before that cursor are visited on the next pass. A full
invalidation restarts auditing after the full verification. Hosts schedule calls on a background worker. Every fetched envelope must
match its checkpoint/ingest digest. Verified operations and authority records also undergo
standard RustCrypto signature verification, independent of the optimized foreground verifier
and any host callback. Previously rejected records and requests are checked for byte equality;
they were never trusted as admitted content. No historical payload decryption is needed for
this audit because matching bytes retain the authenticated prior payload decision.

An attacker controlling only the shared folder cannot forge the device-authenticated projection,
admission flags, digests or authority, or admit a new unsigned operation. They can suppress unseen
records, delay updates, or rewrite/delete a covered record while retaining its listed path.
A path-only fast open cannot detect such a rewrite until a history-cache miss or audit reads it;
it serves the previously authenticated local state in the meantime. Cached history hits likewise
use the earlier authenticated bytes. The attacker does not choose replacement projection data.
A listing missing a covered immutable path makes this namespace unavailable; absent unseen suffixes cannot be detected.
Neither signatures nor checkpoints prove global freshness. A valid older local checkpoint can
be rolled back if an attacker also controls local checkpoint storage; use host anti-rollback
storage if that is in the app's threat model. Compromise of the device secret or trusted host
verification provider is outside this optimization's protection.

Mismatch/missing bytes during history loading, materialization, explicit known-path application
or auditing return an `Integrity error` (with the path for history/audits), never an empty page
or silently rebuilt success. The failure is sticky: queries, writes, refresh, unlock and
checkpointing then fail. The host should surface it and reopen only after resolving the storage
problem. Other failed processing/I/O/backend calls also poison the instance so partially applied
batches cannot be exposed. Malformed listings fail before mutation. `authority()` remains an
inspection of previously known authority, not proof that an audit completed.

### Verification backend and portability

`Engine::open_with_verifier(..., Option<Arc<dyn verification::BatchVerifier>>)` optionally routes
operation signature checks to a trusted host. Each borrowed `VerificationTask` supplies the exact
body bytes, raw 64-byte `r || s` signature and authority-selected uncompressed SEC1 public key.
Return one boolean per task, in order. Verify ECDSA P-256 with SHA-256 (including valid high-S
signatures); do not reserialize JSON or hash twice. Wrong result counts or callback errors abort
processing. `false` becomes ordinary invalid-record evidence. The callback runs synchronously
on the calling thread, once per batch; the FFI must copy borrowed data if its provider requires
an asynchronous boundary. The core alone checks path/library/header bindings, decryption, IDs,
epochs, ordering, grants, revocation, clocks and budgets. Authority-chain verification remains
portable Rust. No CryptoKit/Android bridge has been implemented in this worktree.

The default portable verifier reuses fixed-base four-bit tables for the generator and each
validated public key. It computes the usual ECDSA `u1*G + u2*Q` equation with pinned `p256`
scalar/point arithmetic; table lookups depend only on public verification inputs. Secret signing
and ECDH paths are unchanged. Tests compare with the standard verifier across valid/high-S,
modified-message, modified-signature and malformed-scalar cases; background audits intentionally
use the standard path too. The new arithmetic composition remains a review-sensitive crypto
change despite these differential checks.

The default `parallel` feature uses `std::thread::scope`, up to 16 available workers, for
independent verification and payload opening. Parsing occurs once per valid operation and
payload buffers are opened in place. Admission remains ordered on the caller thread; parallel
namespace reduction preserves each namespace's operation order.
`--no-default-features` disables native parallelism. `wasm32` always uses the single-thread path,
even if the feature is enabled. Dependency pins, wire bytes and the size-focused WASM release
profile are unchanged. See [performance.md](performance.md) for measured targets and limits.

## Engine3: authenticated import storage and blobs

Reducer schema **4** adds `AuthorContext { kind, grant, root, library }` and the namespace
import projection. Kind, the immutable grant and root enrollment come from verified authority,
after ordinary admission. Library append, reconciliation, checkpoint suffixes and storage-backed
parallel reduction use the same context. Books loans and notes reviews accept app/device members;
local signing and tool filtering reject other kinds. Saved-reading's protected commands also
check the authenticated kind on replay. Payload role claims never supply context. Schema 3
already delivered member kinds; older local caches are invalidated by the generation change.

### Atomic source units and reservations

`Library::begin_write(ns, "colophon.importBatch", batch, now, entropy)` (or native
`beginImport`) prepares **one** encrypted, signed ordinary operation. Only an admitted root can
publish this engine operation. It uses ordinary namespace epochs, grant checks, signature/ID
validation, ordering, revocation and preservation. There are no plaintext sidecar files and no
unsigned privileged domain opcode. Each source unit has this JSON shape:

```json
{
  "key": "full source tuple plus transform version",
  "evidence": {"sourceLibrary":"old", "authorID":"old-author", "domainOutcome":"applied"},
  "children": [{"key":"stable-output", "kind":"createNotebook", "payload":{"id":"n","title":"Imported"}, "baseline":false}],
  "alternatives": [],
  "identities": {"framed source occurrence": {"category":"notebook", "id":"n"}},
  "blobs": []
}
```

The complete canonical batch is bounded to 1 MiB and 1,024 children/alternatives/manifests.
Structural and reservation validation precedes effects. A complete admitted record exposes its
ordered children, evidence, bindings and reservations together; a missing, truncated, refused or
invalid record exposes none. Normal domain CAS/no-op/conflict semantics still apply to each clean
child. This is atomic **publication**, not a promise that every domain command is effective.

Children are virtual authenticated operations: their author/label/origin/clock/date are the
importer's, and their order is the array order. Their revisions are the first 32 hex SHA-256
characters of canonical `["colophon/import-output/1", destinationLibrary, namespace, batchKey,
childKey]`. `output_id` / `importOutputId` computes them before signing, allowing references
between children. The enclosing signature authenticates every child and its output binding;
children do not have separate envelopes or signatures. Original source authorship remains
labelled evidence. Compatibility history exposes the enclosing batch; query `importReceipt`
for its actual output bindings. The engine supplies podcast `imported_baseline` only from the
root-authenticated child receipt, never from a domain payload extension.

A namespace retains its first accepted batch per key. A byte-equivalent retry cannot repeat its
effects, even with new entropy/signature/clock; changed content under that key is rejected.
`importReceipt({key})` returns the publication, canonical batch digest, importer, evidence,
identity bindings, retained `alternatives`, `baselineOutputs` and `outputOperationIDs`. Native `HostAction.commit` still rejects stale actions.
Hosts durably journal signed bytes before publication and read back the record before advancing
source progress. No multi-file atomic filesystem primitive is required for the publication itself.

`importIdentity({key,category,preferred})` reports a prior reservation and whether the preferred
identity is occupied. Native object attempts and tombstones remain indexed by namespace/category;
reservations commit with the batch. `occurrence_id` / `importOccurrenceId` derives a deterministic
replacement from the destination library/namespace and framed source tuple including the creation
digest. Hosts apply that mapping to typed references before submitting the batch. A conflicting
reservation fails; it never silently reuses a native object. Concurrent proposals are resolved in
normal signed fold order, so hosts must inspect the receipt after refreshed admission.

### Evidence, historical alternatives and reconciliation

All namespace queries perform current grant/expiry/revocation/key checks before accessing the
sidecar. `importEvidence({sourceLibrary?,object?,cursor?,limit?})` and
`historicalAlternatives({sourceLibrary?,object?,component?,cursor?,limit?})` return
`{revision,value:{rows,next,total}}`. Default limit is 50, maximum 100; responses have a 1 MiB
ceiling. Oversize individual rows report `contentTooLarge`; retained history remains available.
Cursors bind the namespace, query, filters, admitted-prefix observation and last key. Any admitted
attempt invalidates old cursors. Namespace pages traverse the retained key index; filtered totals
currently scan metadata, without fetching original operation records. Evidence retains the
importer's complete JSON, including original attribution, original date representations, losing
candidates, exact-body digest purposes, baseline receipts and all output bindings.

`historicalAlternatives` materializes separately attributed candidates with `historical:true`,
a stable alternative ID, source batch, importer and publication. They do not enter native domain
reducers. An app/device may acknowledge an exact set using `colophon.resolveHistorical` with
`{alternatives:[sorted IDs],expectedRevision,object?,component?}`. A stale revision or changed set
leaves the overlay intact and appears in `importInvalid`. Resolution acknowledges the historical
set; changing native content requires an explicit clean domain command with its normal head/CAS
checks. Historical acknowledgments never replay a rejected old write as an unconditional effect.
The native domain `conflicts` query remains native-only; UIs query this labelled overlay alongside it.

`reconcile_prefix(previous,current,imported_heads)` / `reconcileImportPrefix` compares maps keyed
by the complete source identity. Values are the source reader's evaluated outcomes and effective
values. Insertions, removals and changed outcomes produce explicit historical alternatives with
both previous/current candidates and the last imported component heads. It emits no domain writes.
Publish those alternatives in another additive import batch; signed destination history and native
edits remain intact. The verified source reader still owns old admission/fold evaluation.

Swift `ColophonMigration` now publishes each supported source unit atomically and reads evidence
through the engine query. It stages encrypted blob manifests for retry, while exact old envelopes
and migration progress remain protected local archival data. It compares evaluated outcomes after
an earlier-prefix change, publishes bounded reconciliation evidence, then keeps the migration
marker active pending review. Automatic application of historical corrections and app repair UI
remain host work. Native identity collisions likewise require the caller to apply the deterministic
occurrence map; the Swift orchestrator continues to stop safely rather than guess cross-references.

### Blob descriptor and host contract

`BlobDescriptor = {digest,size,mediaType}` names complete plaintext. `begin_blob` / `beginBlob`
checks current write access and returns a streaming writer. Feed at most 64 KiB to `push`; persist
its immutable `(blobs/<ciphertext SHA-256>, ciphertext)` result before publishing. `finish` returns
a manifest containing the plaintext descriptor, epoch, random upload identity and ordered chunk
metadata (plaintext digest/size, nonce, ciphertext path). One manifest supports up to 8,192 chunks;
the publication's 1 MiB metadata bound can impose a smaller limit. Larger assets require multiple
application-level parts. Descriptor media type does not prove parsing or anchor validity.

AES-256-GCM uses the namespace epoch key. Chunk nonces are the first 12 SHA-256 bytes of canonical
`[upload,index]`; upload is SHA-256 of the fresh host seed. Associated data is canonical
`["colophon/blob/1",library,namespace,epoch,upload,index]`. Hosts MUST supply fresh unpredictable
seeds. The signed encrypted manifest binds the chunk order, digests and complete descriptor.

A root can publish manifests in an import batch. Any namespace writer can publish an ordinary
`colophon.blobPublish` operation with `{manifest,reference}`. `colophon.blobReference` with
`{digest,reference,retain:boolean}` adds/removes an idempotent reference. Either may carry
`required: boolean`, a synchronized eager-download hint. `blob({digest})` returns the signed
manifest, live reference count and `required`; `blobs({after?,limit?,required?})` pages manifests
in digest order (`{digest,size,mediaType,chunks,references,required}`, `next`). Reducer schema 5.
Native hosts authenticate fetched ciphertext with `openBlobChunk(namespace,digest,index,ciphertext)`
(no callback) and copy only a write's own records with `recordsAt(paths)`. Zero live references is
**not** permission to delete retained originals or bytes needed by immutable history. The core
runs no garbage collection; the SDK sessions' explicit `collectBlobGarbage` removes only this
device's local copies (see [handoff-blobs.md](handoff-blobs.md)).

`Engine::blob_chunk` fetches one chunk through `RecordSource::read_blob`; default sources may use
`read`, while hosts can return `Missing` or `Inaccessible`. Native `BlobSource` callbacks run outside
the session mutex, with access rechecked after callback reentry. Results distinguish available,
missing, inaccessible and invalid. Successful bytes have verified ciphertext address, AEAD tag,
chunk plaintext digest and size. Complete streaming consumers also use `BlobVerifier` (or an
independent SHA-256 accumulator) to verify the whole descriptor before certifying an original.

Blob paths are outside the authority/operation listing and local history cache. Cold opens and
metadata queries fetch no blob bytes. Hosts must synchronize the chunk directory as user data,
retain referenced chunks, enforce immutable writes and bound reads to 65,552 ciphertext bytes.
Swift `FolderRecordStore` implements separate lazy `BlobStore` methods; snapshots enumerate only
records. Migration persists/read-checks chunks before signing their manifest. Actual iCloud
hydration, format parsing, quotation/UTF-16 anchor verification and mobile acceptance are host gates.
