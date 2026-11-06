# Incremental engine API

The Rust engine caches verified operations, admission decisions, and a reducer state per
namespace. Existing `Library` methods and return types are unchanged. `view` and the `read`
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

The version-2 body contains `version`, `library`, `identity`, `namespace`, `epoch`, and `snapshot`.
Version 2 passes authority-derived member kinds to domain reducers during append and replay.
Version-1 caches are discarded because their role-sensitive projections may be incomplete.
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
restores staged caches, but performs more admission passes. Cold open still verifies and decrypts
the signed history. Checkpoints currently accelerate projection replay, not cryptographic record
loading; see [performance measurements](performance.md) for the unmet cold-open and memory targets.
