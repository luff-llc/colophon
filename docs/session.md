# Apple app SDK contracts

`ColophonKitStorage` and `ColophonSession` are additive 0.2 products in the root Swift package.
They have no third-party Swift dependencies and compile in Swift 6 language mode. The 0.1
products remain unchanged. The sample is a starting template, not acceptance evidence from
Later, Taupe, Shelf or Scribenda.

## Storage, restoration and private state

`FolderRecordStore` stores the spec's `authority`, `requests` and `ops` paths unchanged. Each
write batch uses `NSFileCoordinator`; files are staged with mode 0600, synchronized, and linked
into place without replacing an existing record. Equal bytes are idempotent; different bytes
at one path are a conflict. Directory synchronization precedes success. Publication is atomic
per record, **not across a batch**. Partial batches remain retryable; an incomplete authority
chain never produces a ready session. Records are capped at 16 MiB per file in this adapter.

Reads enumerate immutable records off-main. iCloud placeholder files and non-current download
status request hydration and throw `unavailable`; enumeration/read/permission failures are not
absence. Previously observed paths are retained in the private journal, including across
restart, and disappearing records also produce `unavailable`. The first complete observation
cannot prove an unseen remote record exists; there is no remote completeness oracle.

An `NSFilePresenter` on the library directory emits bounded wake-up hints. The session
coalesces bursts into a 75 ms batch and rereads once; duplicate snapshots do not bump revisions.
`flushExternalChanges()` is an explicit completion barrier, useful for tests and host refresh.
Foreground entry should always call `refresh()`; presenter delivery alone is not a guarantee
that a suspended process received every provider notification.

App Group/iCloud resolution is performed for this process, before opening records. Failure
never falls back to a private empty library. `.folder` is for an already accessible, host-owned
location; arbitrary document-picker bookmarks and live profile switching are not implemented.
Private-container mode stores the library in `home/Library`. Keep session state, checkpoints
and identity providers outside the shared library/App Group. iOS private staging uses
`completeUntilFirstUserAuthentication`; macOS uses private POSIX permissions without requesting
unsupported iOS file-protection flags. Existing files remain intact when staging fails.

`KeychainKeys` stores software scalars or opaque Secure Enclave references in a process-private,
ThisDeviceOnly Keychain item. The backend selects initial creation; reopening preserves the
stored identity/backend. No keychain error regenerates keys or silently falls back. Hardware
and protected-data failures propagate. Supply a separate persistent recovery provider when
creating a library. If omitted, ColophonKit creates an ephemeral recovery provider available
through `recoveryKeys()`; the host must protect it before relying on recovery. The sample
supplies a separate persistent provider, but it does not implement recovery-kit export UI.

`CheckpointCache(privateContainer:)` bounds opaque cache bytes and keys them by validated
library ID, sets backup exclusion and can discard/reload them. The current bindings have no
verified-prefix checkpoint API, so the session deliberately does **not** read projections from
this cache. It must be connected only to the new engine's prefix validation, never to an app
revision counter. Cache persistence errors are explicit. No cache is an authority or backup.

## Session and engine boundary

Create one session per app process, shared by windows, intents and feature stores. `restore()`
is a shared completion barrier. The session owns phase, identity, ledger, pairing requests,
global revision and per-namespace revisions. Inaccessible namespaces prevent `ready`; views
are invalidated immediately on loss of readiness. Revocation and expiry are checked on every
refresh and command; an expiry task schedules a recheck even without a file notification.

All storage, signing, FFI and projection work runs on background actors. `SessionWorker` has a
suspension-aware FIFO gate around complete operations: a key-provider suspension cannot let a
second write/rejoin interleave with its persistence. Leave completes preceding operations
before invalidating the context. `ObservedRevision` binds an action to session context and
global revision. The worker refreshes before signing and rejects stale observations. It never
silently retries an unsigned stale command. Cancellation is checked before core signing/commit;
a committed operation must still be persisted. The API does not promise a cross-process CAS:
concurrent authority writers may produce immutable-path conflicts, which stop publication.

`SessionCore` is the one internal engine protocol; `BindingSessionCore` is its current adapter.
The storage-backed engine is documented in `docs/engine.md`; its `RecordSource` and verified-prefix
checkpoint APIs are not yet exposed by the native bindings. Today this adapter still obtains
full record/view snapshots and compares namespace evidence off-main to avoid falsely
invalidating unrelated namespace caches. This is **not** the incremental engine or a 100k-op
performance claim. SwiftUI only reads cached values. `NamespaceStore<Query, Result>` decodes
on a concurrent executor, fences completion by context and namespace revision, bounds query
entries, and publishes cold-load completion separately from journal changes. Cache registrations are removed on deinit; `close()` also allows explicit early disposal.

## Exactly what is automatic

By default: restore the configured location, establish container access, refresh observations,
create/persist this identity's **signed pairing request** when it is ungranted, and recognize
an approved grant. No App Group, member label, folder selection, request kind or transport
credential authorizes approval. Agents and servers always wait for explicit approval.

`EnrollmentPolicy.deviceOnlyAppGroup(starterKeys:)` is an explicit suite-only opt-in, matching
Marginalia's device-only starter-root policy. It applies only to `.app` members at an `.appGroup`
location. The host supplies the actual device-only starter root and must cease supplying it
when protecting/moving the library. Creation makes that starter the root, then the app writes
its own pairing request. Joining also writes a real request. A second core handle using the
starter signs a grant with **exactly the request's namespaces/access**, never all supported
library namespaces. Core authority must still recognize that starter as current root; a
former starter is refused and the app remains in the normal pairing phase. There is no
label allowlist or automatic root-key discovery. The SDK does not copy starter/root secrets
into the App Group or implement the old 0.1 starter-to-protected-root migration.

`leave()` disconnects locally and persists the choice; it neither revokes membership nor
deletes records. `rejoin(keys:)` reconnects. A revoked member must use a fresh independently
persisted identity and request, because requests are immutable. Configure that same new key
provider on subsequent launches. Pending signed publication must be retried before leave or
rejoin. Profile replacement in place and account-selection UI remain host responsibilities.

## Extension inbox and retry

Extensions enqueue `IngressEnvelope` values into `IngressInbox(appGroupContainer:)`. Each
contains a UUID, destination library **and member**, expiration, and a bounded domain command.
They never receive a signing key. Default limits are 128 files, 64 KiB encoded per envelope,
32 KiB command payload and seven-day maximum lifetime. A nonblocking advisory lock bounds
concurrent extension publication; malformed/oversized files stop the bounded scan. Enqueue
returns `.queued`, never `.saved`. Destination-route UI/publication is product policy; use the
foreground session's ready library/member IDs, and remove stale routes when it loses access.

Foreground `drain` refreshes and validates exact destination, expiry, current namespace and
write grant before core signing. Signed records plus the envelope's operation receipt are
atomically journaled in the app's private container before public publication. It retries the
**same bytes**, verifies readback, then acknowledges the queue file. Durable receipt matching
prevents a lost acknowledgement/restart from signing again. A post-commit provider failure
binds its receipt to the core-emitted operation path; retry checks admitted evidence before
acknowledging. An ambiguous publication stays queued for review instead of re-signing. Expired receipt entries are pruned
before accepting new requests; at most 4096 active receipts are retained. Conflicting IDs,
wrong destinations, denied grants and expired unsigned envelopes remain queued for review.
A partial batch or write failure is not a saved receipt. Foreground refresh, external changes
or explicit Retry resume publication. There is no background network scheduler and no promise
of remote iCloud upload completion: saved means durable in the selected local store.

## Acceptance limits

Tests use actual Rust-backed sessions and independent keys/private homes. The two-process-style
folder test uses separate folder-store objects and explicit change barriers. Its internal test
initializer disables coordination because filecoordinationd is inaccessible in this sandbox;
production has no uncoordinated fallback. Actual OS presenter delivery, iCloud hydration,
App Group entitlement/bootstrap, Secure Enclave, Keychain prompts, Share/Safari/widget host
journeys and two real consuming apps still need unrestricted/device acceptance. The sample
uses a private folder and explicit pairing-request import, including agent approval/revocation.

## Named domain queries

The four `Colophon*Kit` domain stores use `NamespaceStore`'s additive async-loader initializer.
`ColophonSession.query(namespace:name:arguments:)` serializes the core read through the worker's
FIFO gate, checks the session context/namespace revision around suspension, and sends no signing
request. `Library.query` calls the core's named query API directly, avoiding tool-name collisions.
The typed decoder runs on a concurrent executor, and only its completed plain value enters the
bounded cache. No compatibility whole-state projection is decoded to answer a domain query.
Closing a store invalidates pending load completions as well as existing cache entries.

This does not replace the existing session snapshot adapter: writes and refreshes still collect
full views off-main as described above. The new stores make no claim that the entire session
pipeline is incremental at 100k operations. The core now supplies authenticated member kinds to
role-sensitive reducers on append/replay. Both checkpoint APIs authenticate the reducer schema
generation, so caches from before those semantics fall back to replay. Named queries must keep
using projection state directly; they must not call `view`, `materialize_library`, or read all
history to reconstruct a result. Storage-backed history remains separately paged and lazy.

## Upgrade barriers, durable import writes and key failures

`SessionPhase.migrating` means “Your library is being upgraded.” Configure every suite app
participating in one migration scope with the same `SessionConfiguration.migrationMarker` URL
outside the destination record tree. Independent scoped migrations use separate markers and
journals; apps still on another 0.1 namespace are not gated by books completion. See
[scoped migration](migration.md) for multi-scope coordination.
An active marker takes precedence over an empty destination, enrollment and ordinary writes.
Foreground `refresh()` observes marker changes; the marker itself is not a new sync protocol or
authority record. The root's dedicated migration session sets `migrationWriter: true`; only
the host’s `LegacyLibrarySource` adapter verifies possession of the existing source root
before `ColophonMigration` imports it. Other app sessions use
normal enrollment, including the existing explicit App Group starter policy where applicable.
Old members are reported as needing to rejoin; no agent or grant is automatically restored.

`performMigration(_:outputKey:)` uses the same serialized session write/publication path as
ordinary commands. A non-expiring receipt binds the full source output key and a command digest
to the signed operation ID. The receipt and exact pending signed bytes are journaled together
before publication, then read back from storage. A restart reuses those bytes and receipts;
a conflicting command for the same key fails. Creation collisions with native objects/tombstones stop with `migrationCollision` before signing;
occurrence remapping requires the engine reservation seam. Payloads are not duplicated as plaintext
in the migration receipt. These receipts currently grow with history and share the 64 MiB session
journal bound; a scalable transactional import receipt API remains an engine integration gap.

Provider failures carry `SessionFailure.keysUnavailable(detail:)`; unrelated failures retain
`.other(detail:)`. The sample displays the actionable reason. `retry()` remembers a failed
create and otherwise refreshes restore/enrollment. It never regenerates an identity in response
to a key failure. The sample's `--demo-key-failure` mode fails the first provider access and
allows Retry using that same identity in a temporary, separate demo library.

## Engine3 migration publication

The migration writer now sends one `colophon.importBatch` command per source unit through the
existing gated signing/outbox/readback path. Only these migration batches receive the engine's
1 MiB ceiling; ordinary session commands keep their 256 KiB ceiling. Permanent local receipts
bind the batch command digest and signed parent operation; synchronized `importReceipt` binds
its virtual children. Migration checks that receipt after refreshed admission before advancing
source progress. Child authorship is the importer; original attribution remains evidence.

`migrationBlob` streams 64 KiB plaintext chunks through the native writer, persists encrypted
chunks through `BlobStore`, reads them back, and returns the manifest for atomic publication.
`FolderRecordStore` implements blob storage separately from record snapshots. Chunks may arrive
before their manifest but have no projected visibility until publication. Failed uploads can
leave unreferenced encrypted chunks; hosts retain them until an explicit archival cleanup policy
can prove removal safe. Sibling apps read evidence through their ordinary namespace grants.
