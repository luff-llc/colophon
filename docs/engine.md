# Colophon engine APIs

The compatible `Library` caches verified operations, admission decisions, and reducer state.
The storage-backed `Engine` adds verified-prefix cold opens and bounded content retention;
see [stage 2 below](#storage-backed-engine-stage-2). Existing `Library` methods and return types
are unchanged. `view` and the `read`
tool still return the full history-bearing `NamespaceView`; use `query` for app rendering.
No protocol records or conformance vectors changed.

## Reducers

`domain::Reducer` extends the existing metadata/specification interface `DomainModule`:

```rust
pub trait Reducer: DomainModule {
    type State: Default + Clone + Serialize + for<'de> Deserialize<'de>;
    fn apply(&self, state: &mut Self::State, operation: &AdmittedOperation);
    fn query(&self, state: &Self::State, name: &str, args: &Value) -> Result<Value>;
}
```

`AdmittedOperation` aliases the existing authenticated `OperationView`. `ReadingSaved`,
`ListeningPodcasts`, and `Notes` own `SavedState`, `PodcastsState`, and `NotesState` respectively.
The engine alone orders admission. Reducers retain attributed conflicts, invalid IDs, tombstones,
extensions, and the previous conflict semantics. Unknown kinds are skipped. `DomainModule::fold`
is retained as a source-compatible from-scratch replay wrapper. A new reducer schema or semantic
change must increment the local checkpoint format version before old snapshots can be restored.

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
An unchanged admitted prefix does not replay reducers. Regranting remains the 0.2 protocol's
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

The version-1 body contains `version`, `library`, `identity`, `namespace`, `epoch`, and `snapshot`.
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

Native hosts should opt into `engine::Engine<S: RecordSource>`. `Library` remains the compatible
in-memory API, with every existing method signature and outcome shape intact. Both paths share
exact-byte verification, payload validation and admission rules. The existing version-1
`Library` checkpoints still replay cryptography; the new version-2 `Engine` checkpoint is a
separate, library-wide cache. No FFI or WASM export was changed.

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

The format is an authenticated binary container: `COLOENG2`, little-endian u32 JSON-metadata
length, metadata bytes, u32 record count, sorted entries, then a 32-byte tag. Each entry contains
u32 UTF-8 path length, path bytes, 32-byte **SHA-256 of the entire exact envelope**, u16 namespace
index (65535 means none), and one byte of flags. This implementation supports fewer than 65,535
namespaces. Flags distinguish signature-verified headers, header budget admission, authenticated
IDs and projected operations. Rejected records/requests are bound as observed bytes, never
promoted to valid operations. The metadata contains:

- Format/reducer version, expected library and complete recipient public identity.
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
IKM, `colophon/verified-prefix/2` as expansion info and 32 output bytes. Comparison covers all
tag bytes before parsing metadata or index. Format/reducer changes must bump version and magic.
The key must be random and protected separately from the shared folder. This is an additional
host-supplied device secret, independent of namespace AES keys and the version-1 ECDH-derived
`Library` cache key. Checkpoint state is plaintext; protect the local cache itself as well.

A missing, unauthenticated, wrong-library, wrong-recipient or unknown-version cache falls back
to ordinary verification. A missing covered path or any authority-listing change invalidates
all admission/projections. A valid cache may have a new suffix; only its new records are fetched,
verified, decrypted and applied. An arrival before a namespace tail or a capped author's global
tail forces full verification/replay. Full replay recomputes duplicates, budgets, held/refused
status and revocation keeps using the same admission rule as `Library`. New key availability
also invalidates cached payload evidence. A successfully authenticated cache retains its exact-envelope expectations even when its
projection is invalidated: changed bytes at surviving covered paths fail with an integrity error
during the rebuild. Missing paths in a supplied listing are an explicit invalidation, while a
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
A listing missing a covered path invalidates the cache; absent unseen suffixes cannot be detected.
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
payload buffers are opened in place. Admission and reducers remain ordered on the caller thread.
`--no-default-features` disables native parallelism. `wasm32` always uses the single-thread path,
even if the feature is enabled. Dependency pins, wire bytes and the size-focused WASM release
profile are unchanged. See [performance.md](performance.md) for measured targets and limits.
